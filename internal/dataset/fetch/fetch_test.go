// internal/dataset/fetch/fetch_test.go

package fetch

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/dataset/datasettest"
	"github.com/papa0four/orkowatch/internal/elevation"
	"github.com/papa0four/orkowatch/internal/osfingerprint"
)

// origin is a TLS server standing in for the source of a dataset, with the
// client that trusts it and a record of what it was sent.
type origin struct {
	*httptest.Server
	client *Client

	mu       sync.Mutex
	requests []*http.Request
}

// serve starts an origin whose paths answer with handlers.
func serve(t *testing.T, handlers map[string]http.HandlerFunc) *origin {
	t.Helper()
	o := &origin{}
	mux := http.NewServeMux()
	for path, handler := range handlers {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			o.mu.Lock()
			o.requests = append(o.requests, r.Clone(context.Background()))
			o.mu.Unlock()
			handler(w, r)
		})
	}
	o.Server = httptest.NewTLSServer(mux)
	t.Cleanup(o.Close)

	roots := x509.NewCertPool()
	roots.AddCert(o.Certificate())
	o.client = newClient(roots, nil)
	return o
}

// at is the test dataset served at path of the origin.
func (o *origin) at(path string) dataset.Dataset {
	return datasettest.Dataset{Name: "wanted", Applies: true, From: dataset.Origin{URL: o.URL + path}}
}

// received returns the requests the origin has been sent.
func (o *origin) received() []*http.Request {
	o.mu.Lock()
	defer o.mu.Unlock()
	return slices.Clone(o.requests)
}

// send writes body as the answer, stating its length when stated is set.
func send(t *testing.T, body string, stated bool) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if stated {
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		} else {
			w.(http.Flusher).Flush()
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Logf("the test server could not answer: %v", err)
		}
	}
}

// refused reports whether err is a fetch failure that will not clear and
// names what.
func refused(err error, what string) bool {
	var fe *Error
	return errors.As(err, &fe) && !fe.Passing() && strings.Contains(err.Error(), what)
}

// The data is written as served, its size is what the server states, and
// each request carries the fixed client name, asks for no encoding, and
// holds nothing else: no query, no cookie, no other header.
func TestFetchAndWhatItSends(t *testing.T) {
	o := serve(t, map[string]http.HandlerFunc{"/data": send(t, datasettest.Content, true)})
	d := o.at("/data")

	size, known, err := o.client.Size(context.Background(), d)
	if err != nil || !known || size != int64(len(datasettest.Content)) {
		t.Errorf("size %d, %v, %v", size, known, err)
	}
	var got bytes.Buffer
	if err := o.client.Fetch(context.Background(), d, &got); err != nil || got.String() != datasettest.Content {
		t.Fatalf("fetched %q, %v", got.String(), err)
	}

	requests := o.received()
	if len(requests) != 2 || requests[0].Method != http.MethodHead || requests[1].Method != http.MethodGet {
		t.Fatalf("the server received %d requests", len(requests))
	}
	for _, r := range requests {
		var names []string
		for name := range r.Header {
			names = append(names, name)
		}
		slices.Sort(names)
		if !slices.Equal(names, []string{"Accept-Encoding", "User-Agent"}) {
			t.Errorf("%s carried the headers %q", r.Method, names)
		}
		if r.UserAgent() != "owatch" || r.Header.Get("Accept-Encoding") != "identity" || r.URL.RawQuery != "" {
			t.Errorf("%s carried %q, %q, and the query %q", r.Method, r.UserAgent(), r.Header.Get("Accept-Encoding"), r.URL.RawQuery)
		}
	}
}

// A redirect on the same host is followed, and the address it came from is
// not sent on. One to a host the dataset does not list, one to plain HTTP,
// and one too many are each refused, and none is tried again.
func TestRedirects(t *testing.T) {
	var o *origin
	to := func(target func() string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target(), http.StatusFound) }
	}
	o = serve(t, map[string]http.HandlerFunc{
		"/data":      send(t, datasettest.Content, true),
		"/moved":     to(func() string { return "/data" }),
		"/elsewhere": to(func() string { return strings.Replace(o.URL, "127.0.0.1", "localhost", 1) + "/data" }),
		"/plain":     to(func() string { return strings.Replace(o.URL, "https://", "http://", 1) + "/data" }),
		"/loop":      to(func() string { return "/loop" }),
	})

	var got bytes.Buffer
	if err := o.client.Fetch(context.Background(), o.at("/moved"), &got); err != nil || got.String() != datasettest.Content {
		t.Fatalf("a redirect on the same host: %q, %v", got.String(), err)
	}
	requests := o.received()
	if last := requests[len(requests)-1]; last.URL.Path != "/data" || last.Referer() != "" {
		t.Errorf("after the redirect the server received %s with the referer %q", last.URL.Path, last.Referer())
	}

	for path, what := range map[string]string{
		"/elsewhere": "localhost is not a host this dataset is fetched from",
		"/plain":     "is not an HTTPS address",
		"/loop":      "more than 5 redirects",
	} {
		got.Reset()
		if err := o.client.Fetch(context.Background(), o.at(path), &got); !refused(err, what) {
			t.Errorf("%s gave %v, want it refused for good: %s", path, err, what)
		}
		if got.Len() != 0 {
			t.Errorf("%s wrote %q", path, got.String())
		}
	}
}

// A host a dataset lists is one a redirect may lead to, in any case, and no
// other is.
func TestRedirectWithin(t *testing.T) {
	rule := redirectWithin([]string{"data.example", "cdn.example"})
	for address, allowed := range map[string]bool{
		"https://cdn.example/x":      true,
		"https://CDN.Example/x":      true,
		"https://cdn.example:8443/x": true,
		"https://evil.example/x":     false,
		"https://cdn.example.evil/x": false,
		"http://cdn.example/x":       false,
	} {
		u, err := url.Parse(address)
		if err != nil {
			t.Fatal(err)
		}
		req := &http.Request{URL: u, Header: http.Header{"Referer": {"https://data.example/"}}}
		if err := rule(req, nil); (err == nil) != allowed {
			t.Errorf("%s: %v, want allowed %v", address, err, allowed)
		}
		if req.Header.Get("Referer") != "" {
			t.Errorf("%s: the referer was kept", address)
		}
	}
}

// keeping is a dataset that keeps less than its origin serves, whose origin
// may serve twice what it keeps.
type keeping struct{ datasettest.Dataset }

func (keeping) FetchMaxBytes() int64 { return 2 * datasettest.MaxBytes }

func (keeping) Keep(io.ReaderAt, int64, *osfingerprint.OSInfo, io.Writer) error { return nil }

// A dataset that keeps less than its origin serves is fetched up to the
// origin's limit, not its own, and past it is refused.
func TestFetchLimitOfAKeepingDataset(t *testing.T) {
	within := strings.Repeat("x", datasettest.MaxBytes+1)
	past := strings.Repeat("x", 2*datasettest.MaxBytes+1)
	o := serve(t, map[string]http.HandlerFunc{"/within": send(t, within, true), "/past": send(t, past, false)})

	var got bytes.Buffer
	if err := o.client.Fetch(context.Background(), keeping{o.at("/within").(datasettest.Dataset)}, &got); err != nil || got.String() != within {
		t.Errorf("a file within the origin's limit gave %v and %d bytes", err, got.Len())
	}
	if err := o.client.Fetch(context.Background(), keeping{o.at("/past").(datasettest.Dataset)}, &got); !refused(err, "the dataset's origin may serve") {
		t.Errorf("a file past the origin's limit gave %v, want it refused for good", err)
	}
}

// A body over what the dataset's origin may serve is refused, whether the server states
// its length or not, and a download past the time limit is refused. Neither
// is tried again.
func TestLimits(t *testing.T) {
	big := strings.Repeat("x", datasettest.MaxBytes+1)
	release := make(chan struct{})
	o := serve(t, map[string]http.HandlerFunc{
		"/stated":   send(t, big, true),
		"/unstated": send(t, big, false),
		"/slow": func(w http.ResponseWriter, _ *http.Request) {
			w.(http.Flusher).Flush()
			<-release
		},
	})
	t.Cleanup(func() { close(release) })

	var got bytes.Buffer
	for _, path := range []string{"/stated", "/unstated"} {
		if err := o.client.Fetch(context.Background(), o.at(path), &got); !refused(err, "the dataset's origin may serve") {
			t.Errorf("%s gave %v, want it refused for good", path, err)
		}
	}

	o.client.timeout = 200 * time.Millisecond
	started := time.Now()
	if err := o.client.Fetch(context.Background(), o.at("/slow"), &got); !refused(err, "the time limit passed") {
		t.Errorf("a download that never ends gave %v, want it refused for good", err)
	}
	if waited := time.Since(started); waited > 5*time.Second {
		t.Errorf("gave up after %v", waited)
	}
}

// A download is allowed its size at 256 KiB a second, and never less than ten
// minutes: an 838 MB file is allowed the 54 minutes it needs at that rate.
func TestTimeLimit(t *testing.T) {
	c := newClient(nil, nil)
	for size, want := range map[int64]time.Duration{
		0:           10 * time.Minute,
		1 << 20:     10 * time.Minute,
		150 << 20:   10 * time.Minute,
		160 << 20:   640 * time.Second,
		837_827_112: 3197 * time.Second,
		2 << 30:     8192 * time.Second,
	} {
		if got := c.TimeLimit(size); got != want {
			t.Errorf("a download of %d bytes is allowed %v, want %v", size, got, want)
		}
	}
}

// A download that receives nothing for the stall time is ended as a failure
// that may clear, while one that keeps receiving runs past it.
func TestStall(t *testing.T) {
	release := make(chan struct{})
	write := func(w http.ResponseWriter, text string) {
		if _, err := w.Write([]byte(text)); err != nil {
			t.Logf("the test server could not answer: %v", err)
		}
		w.(http.Flusher).Flush()
	}
	o := serve(t, map[string]http.HandlerFunc{
		"/stalls": func(w http.ResponseWriter, _ *http.Request) {
			write(w, "owatch")
			<-release
		},
		"/trickles": func(w http.ResponseWriter, _ *http.Request) {
			for range 6 {
				write(w, "x")
				time.Sleep(50 * time.Millisecond)
			}
		},
	})
	// Released before the server closes, which waits for its handlers.
	t.Cleanup(func() { close(release) })
	o.client.stall = 150 * time.Millisecond

	var got bytes.Buffer
	err := o.client.Fetch(context.Background(), o.at("/stalls"), &got)
	var fetchErr *Error
	if !errors.As(err, &fetchErr) || !fetchErr.Passing() || !strings.Contains(err.Error(), "nothing was received for 150ms") {
		t.Errorf("a stalled download gave %v, want a failure that may clear naming the stall", err)
	}
	got.Reset()
	if err := o.client.Fetch(context.Background(), o.at("/trickles"), &got); err != nil || got.String() != "xxxxxx" {
		t.Errorf("a download that kept receiving gave %v and %q", err, got.String())
	}
}

// wide is a dataset whose origin may serve two seconds' worth at the floor
// rate.
type wide struct{ datasettest.Dataset }

func (wide) FetchMaxBytes() int64 { return 2 * floorRate }

func (wide) Keep(io.ReaderAt, int64, *osfingerprint.OSInfo, io.Writer) error { return nil }

// A download whose size the server does not state is allowed the time the
// most its origin may serve needs, not only the floor.
func TestUnstatedSizeIsAllowedTheMost(t *testing.T) {
	o := serve(t, map[string]http.HandlerFunc{
		"/unstated": func(w http.ResponseWriter, _ *http.Request) {
			for range 8 {
				if _, err := w.Write([]byte("x")); err != nil {
					t.Logf("the test server could not answer: %v", err)
				}
				w.(http.Flusher).Flush()
				time.Sleep(100 * time.Millisecond)
			}
		},
	})
	o.client.timeout = 300 * time.Millisecond

	var got bytes.Buffer
	if err := o.client.Fetch(context.Background(), wide{o.at("/unstated").(datasettest.Dataset)}, &got); err != nil || got.Len() != 8 {
		t.Errorf("a download of unstated size within the most its origin may serve gave %v and %d bytes", err, got.Len())
	}
}

// A server briefly unable to answer is a failure that may clear; a missing
// file, a certificate that does not verify, and an address that is not HTTPS
// are not.
func TestWhichFailuresPass(t *testing.T) {
	status := func(code int) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) }
	}
	o := serve(t, map[string]http.HandlerFunc{
		"/unavailable": status(http.StatusServiceUnavailable),
		"/throttled":   status(http.StatusTooManyRequests),
		"/missing":     status(http.StatusNotFound),
		"/forbidden":   status(http.StatusForbidden),
		"/data":        send(t, datasettest.Content, true),
	})
	var got bytes.Buffer
	for path, passing := range map[string]bool{"/unavailable": true, "/throttled": true, "/missing": false, "/forbidden": false} {
		var fe *Error
		if err := o.client.Fetch(context.Background(), o.at(path), &got); !errors.As(err, &fe) || fe.Passing() != passing {
			t.Errorf("%s gave %v, want a failure with passing %v", path, err, passing)
		}
	}

	untrusting := newClient(x509.NewCertPool(), nil)
	if err := untrusting.Fetch(context.Background(), o.at("/data"), &got); !refused(err, "certificate") {
		t.Errorf("an unverified certificate gave %v, want it refused for good", err)
	}
	plain := datasettest.Dataset{Name: "wanted", From: dataset.Origin{URL: strings.Replace(o.URL, "https://", "http://", 1) + "/data"}}
	if err := o.client.Fetch(context.Background(), plain, &got); !refused(err, "not an HTTPS address") {
		t.Errorf("a plain HTTP origin gave %v, want it refused for good", err)
	}
	if got.Len() != 0 {
		t.Errorf("a failed fetch wrote %q", got.String())
	}
}

// Only HTTPS_PROXY names a proxy, and one that is not an address is refused.
func TestProxyFromEnvironment(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://other.example:1")
	t.Setenv("ALL_PROXY", "http://other.example:1")
	t.Setenv(proxyVariable, "")
	if proxy, err := proxyFromEnvironment(nil); proxy != nil || err != nil {
		t.Errorf("with HTTPS_PROXY unset: %v, %v", proxy, err)
	}
	t.Setenv(proxyVariable, "http://proxy.example:3128")
	if proxy, err := proxyFromEnvironment(nil); err != nil || proxy.Host != "proxy.example:3128" {
		t.Errorf("with HTTPS_PROXY set: %v, %v", proxy, err)
	}
	t.Setenv(proxyVariable, "proxy.example:3128")
	if _, err := proxyFromEnvironment(nil); !errors.Is(err, errProxy) {
		t.Errorf("a proxy that is not an address gave %v", err)
	}
}

// An elevated process is given no client.
func TestNewRefusesElevated(t *testing.T) {
	client, err := New()
	if elevation.Elevated() != errors.Is(err, ErrElevated) || (err == nil) != (client != nil) {
		t.Errorf("elevated %v: %v, %v", elevation.Elevated(), client, err)
	}
}

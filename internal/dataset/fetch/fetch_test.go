// internal/dataset/fetch/fetch_test.go

package fetch

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
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

// fetchDirect fetches d with c from its origin's own address, where Locate
// finds an origin with no index.
func fetchDirect(c *Client, d dataset.Dataset, w io.Writer) error {
	o := d.Origin(nil)
	return c.Fetch(context.Background(), d, Source{Origin: o, URL: o.URL}, w)
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

	src, err := o.client.Locate(context.Background(), d, nil)
	if err != nil || !src.Stated || src.Size != int64(len(datasettest.Content)) || src.URL != o.URL+"/data" || src.SHA256 != "" {
		t.Errorf("located %+v, %v", src, err)
	}
	var got bytes.Buffer
	if err := fetchDirect(o.client, d, &got); err != nil || got.String() != datasettest.Content {
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

// lineIndex reads an index of one line, a relative address, a SHA-256, and a
// size, resolving the address against where the index was fetched from.
func lineIndex(index io.Reader, at *url.URL) (dataset.Location, error) {
	var href, sum string
	var size int64
	if _, err := fmt.Fscan(index, &href, &sum, &size); err != nil {
		return dataset.Location{}, err
	}
	ref, err := url.Parse(href)
	if err != nil {
		return dataset.Location{}, err
	}
	return dataset.Location{URL: at.ResolveReference(ref).String(), SHA256: sum, Size: size}, nil
}

// sumOf is the SHA-256 of text in lower-case hexadecimal.
func sumOf(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

// indexed is the test dataset whose index is at each of places of o, in
// order, read by lineIndex within 1 KiB.
func (o *origin) indexed(places ...string) datasettest.Dataset {
	from := dataset.Origin{URL: o.URL + places[0], Index: &dataset.Index{MaxBytes: 1 << 10, Locate: lineIndex}}
	for _, p := range places[1:] {
		from.Elsewhere = append(from.Elsewhere, dataset.Place{URL: o.URL + p, Standing: "found at " + p})
	}
	return datasettest.Dataset{Name: "wanted", Applies: true, From: from}
}

// status answers with code and nothing else.
func status(code int) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) }
}

// An origin with an index is located by reading it: the data's address is
// the index's, resolved against where the index is, with the checksum and
// size it states, and the data is fetched from there. The index is fetched
// once, and nothing is asked with HEAD.
func TestLocateThroughAnIndex(t *testing.T) {
	o := serve(t, map[string]http.HandlerFunc{
		"/repo/repodata/index":         send(t, fmt.Sprintf("data/file.xml %s %d", sumOf(datasettest.Content), len(datasettest.Content)), true),
		"/repo/repodata/data/file.xml": send(t, datasettest.Content, true),
	})
	d := o.indexed("/repo/repodata/index")

	src, err := o.client.Locate(context.Background(), d, nil)
	want := Source{Origin: d.From, URL: o.URL + "/repo/repodata/data/file.xml", SHA256: sumOf(datasettest.Content), Size: int64(len(datasettest.Content)), Stated: true}
	if err != nil || src.URL != want.URL || src.SHA256 != want.SHA256 || src.Size != want.Size || !src.Stated {
		t.Fatalf("located %+v, %v; want %+v", src, err, want)
	}
	var got bytes.Buffer
	if err := o.client.Fetch(context.Background(), d, src, &got); err != nil || got.String() != datasettest.Content {
		t.Fatalf("fetched %q, %v", got.String(), err)
	}
	var asked []string
	for _, r := range o.received() {
		asked = append(asked, r.Method+" "+r.URL.Path)
	}
	if !slices.Equal(asked, []string{"GET /repo/repodata/index", "GET /repo/repodata/data/file.xml"}) {
		t.Errorf("the server was asked %q", asked)
	}
}

// Data whose checksum is not the one its index states is refused for good,
// naming both.
func TestLocatedChecksum(t *testing.T) {
	stated := sumOf("another file")
	o := serve(t, map[string]http.HandlerFunc{
		"/index": send(t, fmt.Sprintf("file %s %d", stated, len(datasettest.Content)), true),
		"/file":  send(t, datasettest.Content, true),
	})
	d := o.indexed("/index")
	src, err := o.client.Locate(context.Background(), d, nil)
	if err != nil {
		t.Fatal(err)
	}
	var got bytes.Buffer
	if err := o.client.Fetch(context.Background(), d, src, &got); !refused(err, "is not the file its index names") || !strings.Contains(err.Error(), stated) || !strings.Contains(err.Error(), sumOf(datasettest.Content)) {
		t.Errorf("a file that is not the one its index names gave %v, want it refused for good", err)
	}
}

// A place that answers it holds nothing there, 404 or 410, moves the search
// to the next place, with or without an index, and the source found takes
// the standing of the place it was found at, the origin's own having none; any other answer ends it
// there, and the last place's answer is the search's.
func TestLocateMovesOnFromMissing(t *testing.T) {
	index := send(t, fmt.Sprintf("file %s %d", sumOf(datasettest.Content), len(datasettest.Content)), true)
	o := serve(t, map[string]http.HandlerFunc{
		"/gone":        status(http.StatusNotFound),
		"/removed":     status(http.StatusGone),
		"/down":        status(http.StatusServiceUnavailable),
		"/forbidden":   status(http.StatusForbidden),
		"/archive/idx": index,
		"/data":        send(t, datasettest.Content, true),
	})

	if src, err := o.client.Locate(context.Background(), o.indexed("/gone", "/removed", "/archive/idx"), nil); err != nil || src.URL != o.URL+"/archive/file" || src.Standing != "found at /archive/idx" {
		t.Errorf("an index past two missing places: %+v, %v", src, err)
	}
	plain := datasettest.Dataset{Name: "wanted", Applies: true, From: dataset.Origin{URL: o.URL + "/gone", Elsewhere: []dataset.Place{{URL: o.URL + "/data", Standing: "found at /data"}}}}
	if src, err := o.client.Locate(context.Background(), plain, nil); err != nil || src.URL != o.URL+"/data" || !src.Stated || src.Standing != "found at /data" {
		t.Errorf("data past a missing place: %+v, %v", src, err)
	}
	plain.From.URL = o.URL + "/data"
	if src, err := o.client.Locate(context.Background(), plain, nil); err != nil || src.URL != o.URL+"/data" || src.Standing != "" {
		t.Errorf("data at the origin's own address: %+v, %v, want no standing", src, err)
	}
	for _, first := range []string{"/down", "/forbidden"} {
		before := len(o.received())
		_, err := o.client.Locate(context.Background(), o.indexed(first, "/archive/idx"), nil)
		if err == nil || !strings.Contains(err.Error(), first) {
			t.Errorf("%s first gave %v, want its own failure", first, err)
		}
		if asked := len(o.received()) - before; asked != 1 {
			t.Errorf("%s first: the server was asked %d times, want once", first, asked)
		}
	}
	var fe *Error
	if _, err := o.client.Locate(context.Background(), o.indexed("/gone", "/removed"), nil); !errors.As(err, &fe) || fe.Passing() || !strings.Contains(err.Error(), "/removed") {
		t.Errorf("only missing places gave %v, want the last place's failure", err)
	}
}

// What an index gives is held to its origin before anything is fetched: an
// index past its limit, one its reader refuses, an address that is not HTTPS
// or is on another host, a checksum not written in full, and a size outside
// what the dataset's origin may serve are each refused for good. So is an
// index stated without its limit or reader.
func TestLocateRefuses(t *testing.T) {
	sum := sumOf(datasettest.Content)
	o := serve(t, map[string]http.HandlerFunc{
		"/big":       send(t, strings.Repeat("x", 1<<10+1), true),
		"/garbled":   send(t, "file", true),
		"/plain":     send(t, fmt.Sprintf("http://%s/file %s 10", "127.0.0.1", sum), true),
		"/away":      send(t, fmt.Sprintf("https://elsewhere.example/file %s 10", sum), true),
		"/short-sum": send(t, "file abc123 10", true),
		"/upper-sum": send(t, fmt.Sprintf("file %s 10", strings.ToUpper(sum)), true),
		"/empty":     send(t, fmt.Sprintf("file %s 0", sum), true),
		"/huge":      send(t, fmt.Sprintf("file %s %d", sum, datasettest.MaxBytes+1), true),
	})
	for path, what := range map[string]string{
		"/big":       "more than the 1024 bytes it may hold",
		"/garbled":   "the index at",
		"/plain":     "is not an HTTPS address",
		"/away":      "elsewhere.example is not a host this dataset is fetched from",
		"/short-sum": "gives no SHA-256",
		"/upper-sum": "gives no SHA-256",
		"/empty":     "as 0 bytes",
		"/huge":      fmt.Sprintf("as %d bytes", datasettest.MaxBytes+1),
	} {
		before := len(o.received())
		if _, err := o.client.Locate(context.Background(), o.indexed(path), nil); !refused(err, what) {
			t.Errorf("%s gave %v, want it refused for good: %s", path, err, what)
		}
		if asked := len(o.received()) - before; asked != 1 {
			t.Errorf("%s: the server was asked %d times, want only for the index", path, asked)
		}
	}
	for name, index := range map[string]*dataset.Index{
		"no limit":  {Locate: lineIndex},
		"no reader": {MaxBytes: 1 << 10},
	} {
		d := datasettest.Dataset{Name: "wanted", From: dataset.Origin{URL: o.URL + "/big", Index: index}}
		if _, err := o.client.Locate(context.Background(), d, nil); !refused(err, "states an index without its limit and reader") {
			t.Errorf("an index with %s gave %v", name, err)
		}
	}
}

// lineListing reads a listing of one relative address a line, resolving each
// against where the listing was fetched from.
func lineListing(listing io.Reader, at *url.URL) ([]string, error) {
	data, err := io.ReadAll(listing)
	if err != nil {
		return nil, err
	}
	var pages []string
	for _, line := range strings.Fields(string(data)) {
		ref, err := url.Parse(line)
		if err != nil {
			return nil, err
		}
		pages = append(pages, at.ResolveReference(ref).String())
	}
	return pages, nil
}

// paged is the test dataset whose listing is at path of o, read by
// lineListing within 1 KiB and naming at most maxPages pages.
func (o *origin) paged(path string, maxPages int) datasettest.Dataset {
	return datasettest.Dataset{Name: "wanted", Applies: true, From: dataset.Origin{URL: o.URL + path, Pages: &dataset.Pages{MaxBytes: 1 << 10, MaxPages: maxPages, List: lineListing}}}
}

// An origin with pages is located by reading its listing, each page's
// address held to the origin, and fetched one page after another in the
// listing's order, each written after the one before; the size is not
// stated, so the most the dataset's origin may serve is planned for.
func TestPagesAreFetchedInTurn(t *testing.T) {
	o := serve(t, map[string]http.HandlerFunc{
		"/list":   send(t, "p/1\np/2\np/3\n", true),
		"/p/1":    send(t, "one ", true),
		"/p/2":    send(t, "two ", false),
		"/p/3":    send(t, "three", true),
		"/unused": send(t, "never", true),
	})
	d := o.paged("/list", 3)
	src, err := o.client.Locate(context.Background(), d, nil)
	want := []string{o.URL + "/p/1", o.URL + "/p/2", o.URL + "/p/3"}
	if err != nil || !slices.Equal(src.Pages, want) || src.Requests() != 3 || src.Stated || src.Size != dataset.FetchLimit(d) || src.URL != o.URL+"/list" {
		t.Fatalf("located %+v, %v", src, err)
	}
	var got bytes.Buffer
	if err := o.client.Fetch(context.Background(), d, src, &got); err != nil || got.String() != "one two three" {
		t.Fatalf("fetched %q, %v", got.String(), err)
	}
	var asked []string
	for _, r := range o.received() {
		asked = append(asked, r.Method+" "+r.URL.Path)
	}
	if !slices.Equal(asked, []string{"GET /list", "GET /p/1", "GET /p/2", "GET /p/3"}) {
		t.Errorf("the server was asked %q", asked)
	}
	if (Source{}).Requests() != 1 {
		t.Error("a source with no pages is not one request")
	}
}

// A page that cannot be fetched ends the fetch there, naming it, and the
// pages after it are not asked for; pages that together pass what the
// dataset's origin may serve are refused for good.
func TestAPageThatFailsEndsTheFetch(t *testing.T) {
	half := strings.Repeat("x", datasettest.MaxBytes/2+1)
	o := serve(t, map[string]http.HandlerFunc{
		"/list":  send(t, "p/1 p/2 p/3", true),
		"/large": send(t, "big/1 big/2", true),
		"/p/1":   send(t, "one", true),
		"/p/2":   status(http.StatusServiceUnavailable),
		"/p/3":   send(t, "three", true),
		"/big/1": send(t, half, true),
		"/big/2": send(t, half, false),
	})
	d := o.paged("/list", 3)
	src, err := o.client.Locate(context.Background(), d, nil)
	if err != nil {
		t.Fatal(err)
	}
	var fe *Error
	var got bytes.Buffer
	if err := o.client.Fetch(context.Background(), d, src, &got); !errors.As(err, &fe) || !fe.Passing() || !strings.Contains(err.Error(), "/p/2") {
		t.Errorf("a page the server could not answer gave %v", err)
	}
	for _, r := range o.received() {
		if r.URL.Path == "/p/3" {
			t.Error("a page after the one that failed was asked for")
		}
	}

	big := o.paged("/large", 2)
	src, err = o.client.Locate(context.Background(), big, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := o.client.Fetch(context.Background(), big, src, &got); !refused(err, "the dataset's origin may serve") {
		t.Errorf("pages past the limit together gave %v, want them refused for good", err)
	}
}

// A listing past its limit, one that names more pages than the dataset may
// take, one its reader refuses, or a page that is not HTTPS or is on another
// host, is refused for good before any page is fetched; so is an origin with
// both an index and pages, or pages without their limits and reader.
func TestPagesRefuses(t *testing.T) {
	o := serve(t, map[string]http.HandlerFunc{
		"/big":     send(t, strings.Repeat("p/1 ", 1<<9), true),
		"/many":    send(t, "p/1 p/2 p/3", true),
		"/away":    send(t, "p/1 https://elsewhere.example/p/2", true),
		"/plain":   send(t, "http://127.0.0.1/p/1", true),
		"/garbled": send(t, "%zz", true),
	})
	for path, tt := range map[string]struct {
		pages int
		what  string
	}{
		"/big":     {10, "more than the 1024 bytes it may hold"},
		"/many":    {2, "names 3 pages, more than the 2 wanted may take"},
		"/away":    {10, "elsewhere.example is not a host this dataset is fetched from"},
		"/plain":   {10, "is not an HTTPS address"},
		"/garbled": {10, "the listing at"},
	} {
		before := len(o.received())
		if _, err := o.client.Locate(context.Background(), o.paged(path, tt.pages), nil); !refused(err, tt.what) {
			t.Errorf("%s gave %v, want it refused for good: %s", path, err, tt.what)
		}
		if asked := len(o.received()) - before; asked != 1 {
			t.Errorf("%s: the server was asked %d times, want only for the listing", path, asked)
		}
	}
	both := o.paged("/many", 10)
	both.From.Index = &dataset.Index{MaxBytes: 1 << 10, Locate: lineIndex}
	if _, err := o.client.Locate(context.Background(), both, nil); !refused(err, "states both an index and pages") {
		t.Errorf("an origin with an index and pages gave %v", err)
	}
	for name, pages := range map[string]*dataset.Pages{
		"no limit":    {MaxPages: 10, List: lineListing},
		"no page cap": {MaxBytes: 1 << 10, List: lineListing},
		"no reader":   {MaxBytes: 1 << 10, MaxPages: 10},
	} {
		d := datasettest.Dataset{Name: "wanted", From: dataset.Origin{URL: o.URL + "/many", Pages: pages}}
		if _, err := o.client.Locate(context.Background(), d, nil); !refused(err, "states pages without their limits and reader") {
			t.Errorf("pages with %s gave %v", name, err)
		}
	}
}

// gated is the test dataset paged from the listing at /list of o, read after
// the gate at gate, whose answer "inactive" stands the listing down.
func (o *origin) gated(gate string) datasettest.Dataset {
	d := o.paged("/list", 10)
	d.From.Pages.Gate = &dataset.Gate{URL: gate, MaxBytes: 64, Read: func(answer io.Reader) (string, error) {
		text, err := io.ReadAll(answer)
		switch {
		case err != nil:
			return "", err
		case string(text) == "inactive":
			return "the release is not one the tracker files for", nil
		case string(text) == "active":
			return "", nil
		}
		return "", fmt.Errorf("%q is not the gate's answer", text)
	}}
	return d
}

// A gate is read before the listing. One that stands the listing down leaves
// it unread: the source is the gate alone, one request, with the gate's
// standing, and the gate's answer is what is fetched. One that does not opens
// the pages, its answer first.
func TestGateBeforeTheListing(t *testing.T) {
	o := serve(t, map[string]http.HandlerFunc{
		"/inactive": send(t, "inactive", true),
		"/active":   send(t, "active", true),
		"/list":     send(t, "p/1 p/2", true),
		"/p/1":      send(t, " one", true),
		"/p/2":      send(t, " two", true),
	})
	down := o.gated(o.URL + "/inactive")
	src, err := o.client.Locate(context.Background(), down, nil)
	if err != nil || src.Requests() != 1 || src.Standing != "the release is not one the tracker files for" || !slices.Equal(src.Pages, []string{o.URL + "/inactive"}) {
		t.Fatalf("a gate that stands the listing down located %+v, %v", src, err)
	}
	for _, r := range o.received() {
		if r.URL.Path == "/list" {
			t.Error("the listing was read past a gate that stood it down")
		}
	}
	var got bytes.Buffer
	if err := o.client.Fetch(context.Background(), down, src, &got); err != nil || got.String() != "inactive" {
		t.Errorf("fetched %q, %v", got.String(), err)
	}

	up := o.gated(o.URL + "/active")
	src, err = o.client.Locate(context.Background(), up, nil)
	if err != nil || src.Standing != "" || !slices.Equal(src.Pages, []string{o.URL + "/active", o.URL + "/p/1", o.URL + "/p/2"}) {
		t.Fatalf("an open gate located %+v, %v", src, err)
	}
	got.Reset()
	if err := o.client.Fetch(context.Background(), up, src, &got); err != nil || got.String() != "active one two" {
		t.Errorf("fetched %q, %v", got.String(), err)
	}
}

// A gate off the origin's hosts, past its limit, refused by its reader, or
// stated without its address, limit, or reader is refused for good, and the
// listing is not read.
func TestGateRefuses(t *testing.T) {
	o := serve(t, map[string]http.HandlerFunc{
		"/big":   send(t, strings.Repeat("x", 65), true),
		"/other": send(t, "neither", true),
		"/list":  send(t, "p/1", true),
	})
	for name, tt := range map[string]struct {
		gate, what string
	}{
		"off the hosts":       {"https://elsewhere.example/gate", "elsewhere.example is not a host this dataset is fetched from"},
		"past its limit":      {o.URL + "/big", "the gate at " + o.URL + "/big is more than the 64 bytes it may hold"},
		"refused by its read": {o.URL + "/other", `"neither" is not the gate's answer`},
	} {
		_, err := o.client.Locate(context.Background(), o.gated(tt.gate), nil)
		var fe *Error
		if err == nil || !strings.Contains(err.Error(), tt.what) || !errors.As(err, &fe) || fe.Passing() {
			t.Errorf("%s: gave %v, want it refused for good: %s", name, err, tt.what)
		}
	}
	for _, r := range o.received() {
		if r.URL.Path == "/list" {
			t.Error("the listing was read past a gate that was refused")
		}
	}
	d := o.gated(o.URL + "/other")
	d.From.Pages.Gate.Read = nil
	if _, err := o.client.Locate(context.Background(), d, nil); !refused(err, "states a gate without its address, limit, and reader") {
		t.Errorf("a gate with no reader gave %v", err)
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
	if err := fetchDirect(o.client, o.at("/moved"), &got); err != nil || got.String() != datasettest.Content {
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
		if err := fetchDirect(o.client, o.at(path), &got); !refused(err, what) {
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
	rule := redirectWithin(dataset.Origin{URL: "https://data.example/k", RedirectHosts: []string{"cdn.example"}})
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
	if err := fetchDirect(o.client, keeping{o.at("/within").(datasettest.Dataset)}, &got); err != nil || got.String() != within {
		t.Errorf("a file within the origin's limit gave %v and %d bytes", err, got.Len())
	}
	if err := fetchDirect(o.client, keeping{o.at("/past").(datasettest.Dataset)}, &got); !refused(err, "the dataset's origin may serve") {
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
		if err := fetchDirect(o.client, o.at(path), &got); !refused(err, "the dataset's origin may serve") {
			t.Errorf("%s gave %v, want it refused for good", path, err)
		}
	}

	o.client.timeout = 200 * time.Millisecond
	started := time.Now()
	if err := fetchDirect(o.client, o.at("/slow"), &got); !refused(err, "the time limit passed") {
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
	err := fetchDirect(o.client, o.at("/stalls"), &got)
	var fetchErr *Error
	if !errors.As(err, &fetchErr) || !fetchErr.Passing() || !strings.Contains(err.Error(), "nothing was received for 150ms") {
		t.Errorf("a stalled download gave %v, want a failure that may clear naming the stall", err)
	}
	got.Reset()
	if err := fetchDirect(o.client, o.at("/trickles"), &got); err != nil || got.String() != "xxxxxx" {
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
	if err := fetchDirect(o.client, wide{o.at("/unstated").(datasettest.Dataset)}, &got); err != nil || got.Len() != 8 {
		t.Errorf("a download of unstated size within the most its origin may serve gave %v and %d bytes", err, got.Len())
	}
}

// A server briefly unable to answer is a failure that may clear; a missing
// file, a certificate that does not verify, and an address that is not HTTPS
// are not.
func TestWhichFailuresPass(t *testing.T) {
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
		if err := fetchDirect(o.client, o.at(path), &got); !errors.As(err, &fe) || fe.Passing() != passing {
			t.Errorf("%s gave %v, want a failure with passing %v", path, err, passing)
		}
	}

	untrusting := newClient(x509.NewCertPool(), nil)
	if err := fetchDirect(untrusting, o.at("/data"), &got); !refused(err, "certificate") {
		t.Errorf("an unverified certificate gave %v, want it refused for good", err)
	}
	plain := datasettest.Dataset{Name: "wanted", From: dataset.Origin{URL: strings.Replace(o.URL, "https://", "http://", 1) + "/data"}}
	if err := fetchDirect(o.client, plain, &got); !refused(err, "not an HTTPS address") {
		t.Errorf("a plain HTTP origin gave %v, want it refused for good", err)
	}
	if got.Len() != 0 {
		t.Errorf("a failed fetch wrote %q", got.String())
	}
}

// A server nothing answers at, as on a host with no network, is a failure
// that says no connection could be made; one that answers is not.
func TestUnreachable(t *testing.T) {
	o := serve(t, map[string]http.HandlerFunc{"/missing": status(http.StatusNotFound)})
	var got bytes.Buffer
	var fe *Error
	if err := fetchDirect(o.client, o.at("/missing"), &got); !errors.As(err, &fe) || fe.Unreachable() {
		t.Errorf("a server that answered gave %v, want a failure that reached it", err)
	}

	gone := o.at("/missing")
	o.Close()
	err := fetchDirect(o.client, gone, &got)
	if !errors.As(err, &fe) || !fe.Unreachable() || !fe.Passing() || !strings.Contains(err.Error(), "no connection could be made") {
		t.Errorf("a server nothing answers at gave %v, want a failure that says no connection could be made", err)
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

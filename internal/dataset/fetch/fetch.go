// internal/dataset/fetch/fetch.go

// Package fetch brings a dataset's data from its origin over HTTPS. It is the
// only part of owatch that opens a network connection, and it is held to what
// each dataset states of itself: the address its data is at, and the hosts a
// redirect from that address may lead to. It sends nothing about the host it
// runs on, reads no more than the dataset's origin may serve, and gives up
// when a download runs past the time its size allows or stalls. It never runs elevated: a privileged process that reads what a server
// sends puts that server's input in front of everything the process can do.
package fetch

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"time"

	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/elevation"
	"github.com/papa0four/orkowatch/internal/osfingerprint"
)

const (
	// userAgent names the client and nothing else: it is the same on every
	// host and in every version, so a request says only that it is owatch's.
	userAgent = "owatch"

	// downloadTimeout is the least time one download is allowed, and
	// floorRate the slowest a link may carry it at before a large one runs
	// out of time: a download is allowed its size at floorRate, never less
	// than downloadTimeout. sizeTimeout bounds the question of how large one
	// is.
	downloadTimeout = 10 * time.Minute
	floorRate       = 256 << 10
	sizeTimeout     = 30 * time.Second

	// stallTimeout is how long a download may receive nothing before it is
	// given up as stalled, which may clear when it is tried again.
	stallTimeout = 60 * time.Second

	// connectTimeout bounds reaching a server and agreeing on TLS with it,
	// and headerTimeout the wait for its answer to begin.
	connectTimeout = 15 * time.Second
	headerTimeout  = 30 * time.Second

	// maxRedirects is how many redirects one request follows.
	maxRedirects = 5

	// proxyVariable names the proxy requests go through, when it is set. It
	// is the one environment variable owatch reads for where it connects:
	// many networks reach the internet no other way, and TLS still
	// authenticates the origin through a proxy.
	proxyVariable = "HTTPS_PROXY"
)

// ErrElevated means the process is elevated, where nothing is fetched.
var ErrElevated = errors.New("datasets are never fetched by an elevated run")

// Error is a fetch that failed. Passing says whether trying again could
// succeed: a server briefly unable to answer or a dropped connection may
// clear, where a refused redirect, a certificate that does not verify, or a
// body past the limit will not. Unreachable says no connection could be made
// at all, as on a host with no network, where no other dataset can be fetched
// either.
type Error struct {
	err         error
	passing     bool
	unreachable bool
	missing     bool
}

func (e *Error) Error() string { return e.err.Error() }
func (e *Error) Unwrap() error { return e.err }

// Passing reports whether the failure is one that may clear.
func (e *Error) Passing() bool { return e.passing }

// Unreachable reports whether no connection could be made: the server's name
// could not be resolved, or nothing answered where it or the proxy is.
func (e *Error) Unreachable() bool { return e.unreachable }

// lasting is a failure trying again cannot change.
func lasting(format string, args ...any) *Error {
	return &Error{err: fmt.Errorf(format, args...)}
}

// Client fetches datasets.
type Client struct {
	transport http.RoundTripper
	timeout   time.Duration
	stall     time.Duration
}

// errTimeLimit and errStalled are why a download was ended before it
// finished: it ran past the time its size allows, or it received nothing for
// too long.
var (
	errTimeLimit = errors.New("the time limit passed")
	errStalled   = errors.New("the download stalled")
)

// TimeLimit is how long a download of size bytes is allowed: its size at the
// floor rate, and never less than the floor time.
func (c *Client) TimeLimit(size int64) time.Duration {
	return max(c.timeout, time.Duration((size+floorRate-1)/floorRate)*time.Second)
}

// New returns the client owatch fetches with: the system's certificate roots
// and the proxy HTTPS_PROXY names, if any. It refuses in an elevated process.
func New() (*Client, error) {
	if elevation.Elevated() {
		return nil, ErrElevated
	}
	return newClient(nil, proxyFromEnvironment), nil
}

// newClient builds a client that trusts roots, the system's when nil, and
// reaches servers through what proxy returns.
func newClient(roots *x509.CertPool, proxy func(*http.Request) (*url.URL, error)) *Client {
	return &Client{
		timeout: downloadTimeout,
		stall:   stallTimeout,
		transport: &http.Transport{
			Proxy:                 proxy,
			DialContext:           (&net.Dialer{Timeout: connectTimeout}).DialContext,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
			TLSHandshakeTimeout:   connectTimeout,
			ResponseHeaderTimeout: headerTimeout,
			ForceAttemptHTTP2:     true,
			DisableCompression:    true,
		},
	}
}

// proxyFromEnvironment returns the proxy HTTPS_PROXY names, or none. No other
// variable is read, so nothing else in the environment changes where a
// request goes.
func proxyFromEnvironment(*http.Request) (*url.URL, error) {
	value := os.Getenv(proxyVariable)
	if value == "" {
		return nil, nil
	}
	proxy, err := url.Parse(value)
	if err != nil || proxy.Host == "" || (proxy.Scheme != "http" && proxy.Scheme != "https") {
		return nil, fmt.Errorf("%w: %s is not the address of a proxy", errProxy, proxyVariable)
	}
	return proxy, nil
}

// Source is where the data of a dataset is fetched from for one host: the
// origin it was located through, the data's address, the standing of the
// place it was found at, the SHA-256 the origin's index states for it, empty
// when the origin has no index, and its size when Stated. For an origin with
// pages, URL is the listing and Pages the addresses it named, fetched in
// order.
type Source struct {
	Origin   dataset.Origin
	URL      string
	Standing string
	SHA256   string
	Size     int64
	Stated   bool
	Pages    []string
}

// Requests is how many requests fetching the source takes.
func (s Source) Requests() int { return max(1, len(s.Pages)) }

// sumPattern is a SHA-256 written as an index must state one.
var sumPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Locate finds where the data of d is for host, trying the places its origin
// names in order and moving on only from one that answers it holds nothing
// there. An origin with no index is asked how large its data is; one with an
// index has the index read for the data's address, checksum, and size, each
// held to the origin before anything is fetched.
func (c *Client) Locate(ctx context.Context, d dataset.Dataset, host *osfingerprint.OSInfo) (Source, error) {
	origin := d.Origin(host)
	if _, err := origin.Hosts(); err != nil {
		return Source{}, &Error{err: err}
	}
	switch {
	case origin.Index != nil && origin.Pages != nil:
		return Source{}, lasting("%s states both an index and pages", d.ID())
	case origin.Index != nil && (origin.Index.MaxBytes <= 0 || origin.Index.Locate == nil):
		return Source{}, lasting("%s states an index without its limit and reader", d.ID())
	case origin.Pages != nil && (origin.Pages.MaxBytes <= 0 || origin.Pages.MaxPages <= 0 || origin.Pages.List == nil):
		return Source{}, lasting("%s states pages without their limits and reader", d.ID())
	case origin.Pages != nil && origin.Pages.Gate != nil && (origin.Pages.Gate.URL == "" || origin.Pages.Gate.MaxBytes <= 0 || origin.Pages.Gate.Read == nil):
		return Source{}, lasting("%s states a gate without its address, limit, and reader", d.ID())
	}
	ctx, cancel := context.WithTimeout(ctx, sizeTimeout)
	defer cancel()
	places := origin.Places()
	for i, place := range places {
		src, err := c.locateAt(ctx, d, origin, place)
		var fe *Error
		if err == nil || !errors.As(err, &fe) || !fe.missing || i == len(places)-1 {
			return src, err
		}
	}
	return Source{}, lasting("%s names no place to fetch from", d.ID())
}

// locateAt locates the data of d at place, one of origin's places, the
// source taking the place's standing.
func (c *Client) locateAt(ctx context.Context, d dataset.Dataset, origin dataset.Origin, place dataset.Place) (src Source, err error) {
	method := http.MethodHead
	if origin.Index != nil || origin.Pages != nil {
		method = http.MethodGet
	}
	if origin.Pages != nil && origin.Pages.Gate != nil {
		standing, err := c.readGate(ctx, origin)
		if err != nil || standing != "" {
			return Source{Origin: origin, URL: place.URL, Standing: standing, Size: dataset.FetchLimit(d), Pages: []string{origin.Pages.Gate.URL}}, err
		}
	}
	resp, err := c.do(ctx, method, origin, place.URL)
	if err != nil {
		return Source{}, err
	}
	defer func() { err = errors.Join(err, resp.Body.Close()) }()
	switch {
	case origin.Index != nil:
		src, err = c.readIndex(ctx, d, origin, place.URL, resp.Body)
	case origin.Pages != nil:
		src, err = c.readListing(ctx, d, origin, place.URL, resp.Body)
	default:
		return Source{Origin: origin, URL: place.URL, Standing: place.Standing, Size: resp.ContentLength, Stated: resp.ContentLength >= 0}, nil
	}
	src.Standing = place.Standing
	return src, err
}

// readLimited reads body, what place answered, refusing more than limit
// bytes, which what names.
func readLimited(ctx context.Context, body io.Reader, limit int64, place, what string) ([]byte, *url.URL, error) {
	data, err := io.ReadAll(io.LimitReader(body, limit+1))
	switch {
	case err != nil:
		return nil, nil, failure(ctx, fmt.Errorf("read %s: %w", place, err))
	case int64(len(data)) > limit:
		return nil, nil, lasting("the %s at %s is more than the %d bytes it may hold", what, place, limit)
	}
	at, err := url.Parse(place)
	if err != nil {
		return nil, nil, &Error{err: err}
	}
	return data, at, nil
}

// readGate reads origin's gate, held to origin and its limit, and gives the
// standing its reader gives when the listing is not to be read.
func (c *Client) readGate(ctx context.Context, origin dataset.Origin) (string, error) {
	gate := origin.Pages.Gate
	resp, err := c.do(ctx, http.MethodGet, origin, gate.URL)
	if err != nil {
		return "", err
	}
	answer, _, err := readLimited(ctx, resp.Body, gate.MaxBytes, gate.URL, "gate")
	if err = errors.Join(err, resp.Body.Close()); err != nil {
		return "", err
	}
	standing, err := gate.Read(bytes.NewReader(answer))
	if err != nil {
		return "", lasting("the gate at %s: %w", gate.URL, err)
	}
	return standing, nil
}

// readIndex reads the index at place from body for where the data of d is.
func (c *Client) readIndex(ctx context.Context, d dataset.Dataset, origin dataset.Origin, place string, body io.Reader) (Source, error) {
	index, at, err := readLimited(ctx, body, origin.Index.MaxBytes, place, "index")
	if err != nil {
		return Source{}, err
	}
	loc, err := origin.Index.Locate(bytes.NewReader(index), at)
	if err != nil {
		return Source{}, lasting("the index at %s: %w", place, err)
	}
	return located(d, origin, place, loc)
}

// readListing reads the listing at place from body for the pages the data of
// d is in, each held to origin, no more than it may name. The size is not
// stated: the most the dataset's origin may serve is what the pages may hold
// together.
func (c *Client) readListing(ctx context.Context, d dataset.Dataset, origin dataset.Origin, place string, body io.Reader) (Source, error) {
	listing, at, err := readLimited(ctx, body, origin.Pages.MaxBytes, place, "listing")
	if err != nil {
		return Source{}, err
	}
	pages, err := origin.Pages.List(bytes.NewReader(listing), at)
	switch {
	case err != nil:
		return Source{}, lasting("the listing at %s: %w", place, err)
	case len(pages) > origin.Pages.MaxPages:
		return Source{}, lasting("the listing at %s names %d pages, more than the %d %s may take", place, len(pages), origin.Pages.MaxPages, d.ID())
	}
	for _, page := range pages {
		u, err := url.Parse(page)
		if err != nil {
			return Source{}, lasting("the listing at %s names %q, which is not an address", place, dataset.Printable(page))
		}
		if err := origin.Allows(u); err != nil {
			return Source{}, lasting("the listing at %s names a page that is refused: %w", place, err)
		}
	}
	if origin.Pages.Gate != nil {
		pages = append([]string{origin.Pages.Gate.URL}, pages...)
	}
	return Source{Origin: origin, URL: place, Size: dataset.FetchLimit(d), Pages: pages}, nil
}

// located is the source an index at place gives, held to origin: an address
// the origin allows, a SHA-256 written in full, and a size the dataset's
// origin may serve.
func located(d dataset.Dataset, origin dataset.Origin, place string, loc dataset.Location) (Source, error) {
	u, err := url.Parse(loc.URL)
	if err != nil {
		return Source{}, lasting("the index at %s gives %q, which is not an address", place, loc.URL)
	}
	if err := origin.Allows(u); err != nil {
		return Source{}, lasting("the index at %s gives an address that is refused: %w", place, err)
	}
	if !sumPattern.MatchString(loc.SHA256) {
		return Source{}, lasting("the index at %s gives no SHA-256 for %s", place, u.Redacted())
	}
	if limit := dataset.FetchLimit(d); loc.Size <= 0 || loc.Size > limit {
		return Source{}, lasting("the index at %s gives %s as %d bytes, where the dataset's origin may serve 1 to %d", place, u.Redacted(), loc.Size, limit)
	}
	return Source{Origin: origin, URL: loc.URL, SHA256: loc.SHA256, Size: loc.Size, Stated: true}, nil
}

// Fetch writes the data of d to w from src, where Locate found it. It reads
// at most what d's origin may serve, and refuses data whose checksum is not
// the one src's index states. Each download is allowed the time its stated
// size needs, or the most it may serve when the server does not say, and is
// ended when it receives nothing for the stall time. A source in pages has
// each page fetched in turn, never two at once, and written one after
// another; a page that cannot be fetched ends the fetch there.
func (c *Client) Fetch(ctx context.Context, d dataset.Dataset, src Source, w io.Writer) error {
	limit := dataset.FetchLimit(d)
	if len(src.Pages) == 0 {
		_, err := c.fetchOne(ctx, src, src.URL, limit, w)
		return err
	}
	for _, page := range src.Pages {
		if err := ctx.Err(); err != nil {
			return &Error{err: err}
		}
		n, err := c.fetchOne(ctx, Source{Origin: src.Origin}, page, limit, w)
		if err != nil {
			return err
		}
		limit -= n
	}
	return nil
}

// fetchOne writes what address, one of src's, answers to w, reading at most
// limit bytes, and returns how many it wrote.
func (c *Client) fetchOne(ctx context.Context, src Source, address string, limit int64, w io.Writer) (written int64, err error) {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	resp, err := c.do(ctx, http.MethodGet, src.Origin, address)
	if err != nil {
		return 0, err
	}
	defer func() { err = errors.Join(err, resp.Body.Close()) }()

	if resp.ContentLength > limit {
		return 0, lasting("%s is %d bytes, more than the %d the dataset's origin may serve", address, resp.ContentLength, limit)
	}
	size := resp.ContentLength
	if size < 0 {
		size = limit
	}
	allowed := c.TimeLimit(size)
	whole := time.AfterFunc(allowed, func() { cancel(fmt.Errorf("%w: %s", errTimeLimit, allowed)) })
	defer whole.Stop()
	body := &watched{r: resp.Body, every: c.stall, timer: time.AfterFunc(c.stall, func() {
		cancel(fmt.Errorf("%w: nothing was received for %s", errStalled, c.stall))
	})}
	defer body.timer.Stop()

	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(w, hash), io.LimitReader(body, limit+1))
	switch {
	case err != nil:
		return n, failure(ctx, fmt.Errorf("read %s: %w", address, err))
	case n > limit:
		return n, lasting("%s sent more than the %d bytes the dataset's origin may serve", address, limit)
	}
	if sum := hex.EncodeToString(hash.Sum(nil)); src.SHA256 != "" && sum != src.SHA256 {
		return n, lasting("%s is not the file its index names: its SHA-256 is %s, where the index states %s", address, sum, src.SHA256)
	}
	return n, nil
}

// watched reads r and restarts timer, which ends a stalled download, each
// time something is received.
type watched struct {
	r     io.Reader
	every time.Duration
	timer *time.Timer
}

func (w *watched) Read(p []byte) (int, error) {
	n, err := w.r.Read(p)
	if n > 0 {
		w.timer.Reset(w.every)
	}
	return n, err
}

// do sends one request for address, one of origin's, and returns the answer
// when it is 200. The address and every redirect are held to origin's hosts,
// and the request carries the fixed headers and no other that owatch
// chooses. An answer that the server holds nothing there is a failure marked
// missing, so a fetch can look in the origin's next place.
func (c *Client) do(ctx context.Context, method string, origin dataset.Origin, address string) (*http.Response, error) {
	u, err := url.Parse(address)
	if err != nil {
		return nil, &Error{err: err}
	}
	if err := origin.Allows(u); err != nil {
		return nil, &Error{err: err}
	}
	req, err := http.NewRequestWithContext(ctx, method, address, nil)
	if err != nil {
		return nil, &Error{err: err}
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept-Encoding", "identity")

	client := &http.Client{Transport: c.transport, CheckRedirect: redirectWithin(origin)}
	resp, err := client.Do(req)
	if err != nil {
		return nil, failure(ctx, err)
	}
	if resp.StatusCode != http.StatusOK {
		status := &Error{
			err:     fmt.Errorf("%s answered %s", address, resp.Status),
			passing: resp.StatusCode >= http.StatusInternalServerError || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusRequestTimeout,
			missing: resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone,
		}
		return nil, errors.Join(status, resp.Body.Close())
	}
	return resp, nil
}

// errRedirect marks a redirect that was refused, and errProxy a proxy that
// could not be used as named.
var (
	errRedirect = errors.New("redirect refused")
	errProxy    = errors.New("proxy unusable")
)

// redirectWithin returns the rule for following a redirect: only to an
// address origin allows, and only so many times. The address a request was
// redirected from is not sent on.
func redirectWithin(origin dataset.Origin) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		req.Header.Del("Referer")
		if len(via) >= maxRedirects {
			return fmt.Errorf("%w: more than %d redirects", errRedirect, maxRedirects)
		}
		if err := origin.Allows(req.URL); err != nil {
			return fmt.Errorf("%w: %w", errRedirect, err)
		}
		return nil
	}
}

// failure says whether a request that did not complete may clear. A download
// that stalled may; the time limit, a refused redirect, a certificate that
// does not verify, and a run that was canceled will not; a connection that
// could not be made at all may, and says so; anything else on the way to a
// server may.
func failure(ctx context.Context, err error) *Error {
	var (
		unknownAuthority x509.UnknownAuthorityError
		hostname         x509.HostnameError
		invalid          x509.CertificateInvalidError
		verification     *tls.CertificateVerificationError
		lookup           *net.DNSError
		dial             *net.OpError
	)
	cause := context.Cause(ctx)
	switch {
	case errors.Is(cause, errStalled):
		return &Error{err: fmt.Errorf("%w: %w", cause, err), passing: true}
	case errors.Is(cause, errTimeLimit):
		return &Error{err: fmt.Errorf("%w: %w", cause, err)}
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return &Error{err: fmt.Errorf("the time limit passed: %w", err)}
	case errors.Is(err, context.Canceled), errors.Is(err, errRedirect), errors.Is(err, errProxy):
		return &Error{err: err}
	case errors.As(err, &unknownAuthority), errors.As(err, &hostname), errors.As(err, &invalid), errors.As(err, &verification):
		return &Error{err: err}
	case errors.As(err, &lookup), errors.As(err, &dial) && dial.Op == "dial":
		return &Error{err: fmt.Errorf("no connection could be made: %w", err), passing: true, unreachable: true}
	}
	return &Error{err: err, passing: true}
}

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
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/elevation"
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

// Size asks the origin of d how large its data is. It reports false when the
// server does not say.
func (c *Client) Size(ctx context.Context, d dataset.Dataset) (int64, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, sizeTimeout)
	defer cancel()
	resp, err := c.do(ctx, http.MethodHead, d)
	if err != nil {
		return 0, false, err
	}
	if err := resp.Body.Close(); err != nil {
		return 0, false, err
	}
	return resp.ContentLength, resp.ContentLength >= 0, nil
}

// Fetch writes the data of d to w as its origin serves it. It reads at most
// what d's origin may serve. The download is allowed the time its stated
// size needs, or the most it may serve when the server does not say, and is
// ended when it receives nothing for the stall time.
func (c *Client) Fetch(ctx context.Context, d dataset.Dataset, w io.Writer) (err error) {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	resp, err := c.do(ctx, http.MethodGet, d)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, resp.Body.Close()) }()

	limit := dataset.FetchLimit(d)
	if resp.ContentLength > limit {
		return lasting("%s is %d bytes, more than the %d the dataset's origin may serve", d.Origin().URL, resp.ContentLength, limit)
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

	n, err := io.Copy(w, io.LimitReader(body, limit+1))
	switch {
	case err != nil:
		return failure(ctx, fmt.Errorf("read %s: %w", d.Origin().URL, err))
	case n > limit:
		return lasting("%s sent more than the %d bytes the dataset's origin may serve", d.Origin().URL, limit)
	}
	return nil
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

// do sends one request for d and returns the answer when it is 200. Every
// redirect is held to d's own hosts, and the request carries the fixed
// headers and no other that owatch chooses.
func (c *Client) do(ctx context.Context, method string, d dataset.Dataset) (*http.Response, error) {
	origin := d.Origin()
	if _, err := origin.Hosts(); err != nil {
		return nil, &Error{err: err}
	}
	req, err := http.NewRequestWithContext(ctx, method, origin.URL, nil)
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
			err:     fmt.Errorf("%s answered %s", origin.URL, resp.Status),
			passing: resp.StatusCode >= http.StatusInternalServerError || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusRequestTimeout,
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

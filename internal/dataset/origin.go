// internal/dataset/origin.go

package dataset

import (
	"fmt"
	"io"
	"net/url"
	"slices"
	"strings"
)

// Origin is where a dataset's data is fetched from and the terms it comes
// under, as its source states them.
type Origin struct {
	// URL is the HTTPS address of the data, or of its index when Index is
	// set.
	URL string

	// Elsewhere are further addresses of the same thing, tried in order
	// when the one before answers that it holds nothing there, as a release
	// moved to an archive does. Any other failure ends the fetch.
	Elsewhere []string

	// Index is set when the data's address is read from an index at URL,
	// as a repository names a file by its checksum, and is nil when URL is
	// the data itself.
	Index *Index

	// RedirectHosts are the hosts, other than those of URL and Elsewhere,
	// that a redirect may lead to. A redirect anywhere else is refused, so
	// a source lists here only hosts it is known to use.
	RedirectHosts []string

	// License and Attribution are what the source asks to be stated with
	// its data, recorded in the manifest of every copy fetched.
	License     string
	Attribution string
}

// Index is how a dataset finds its data in an index: the most the index may
// hold, and how to read the data's address from it. Locate is given the
// address the index was fetched from, which a relative address in it is
// resolved against.
type Index struct {
	MaxBytes int64
	Locate   func(index io.Reader, at *url.URL) (Location, error)
}

// Location is where an index places the data: its address, the SHA-256 the
// index states for it in lower-case hexadecimal, and its size.
type Location struct {
	URL    string
	SHA256 string
	Size   int64
}

// Places returns the addresses the origin names, in the order they are
// tried: URL, then each of Elsewhere.
func (o Origin) Places() []string {
	return append([]string{o.URL}, o.Elsewhere...)
}

// Hosts returns the hosts a fetch of the data may reach: those of its places
// and the redirect hosts, in lower case, each once. It refuses an origin with
// a place that is not an HTTPS address of a host, or that lists an empty
// redirect host, so a fetch never starts from an origin it could not hold to
// its list.
func (o Origin) Hosts() ([]string, error) {
	var hosts []string
	add := func(h string) {
		if h = strings.ToLower(h); !slices.Contains(hosts, h) {
			hosts = append(hosts, h)
		}
	}
	for _, place := range o.Places() {
		if err := validSource(place); err != nil {
			return nil, err
		}
		u, err := url.Parse(place)
		if err != nil {
			return nil, refuse("the source %q is not an address", place)
		}
		add(u.Hostname())
	}
	for _, h := range o.RedirectHosts {
		if h == "" || strings.ContainsAny(h, "/:@ ") {
			return nil, refuse("%q is not a host a redirect may lead to", h)
		}
		add(h)
	}
	return hosts, nil
}

// Allows refuses an address a fetch of the data may not reach: one that is
// not HTTPS, names a user, or is on a host the origin does not list. A
// redirect and an address an index gives are held to the same rule.
func (o Origin) Allows(u *url.URL) error {
	hosts, err := o.Hosts()
	if err != nil {
		return err
	}
	switch {
	case u.Scheme != "https":
		return fmt.Errorf("%s is not an HTTPS address", u.Redacted())
	case u.User != nil:
		return fmt.Errorf("%s names a user", u.Redacted())
	case !slices.Contains(hosts, strings.ToLower(u.Hostname())):
		return fmt.Errorf("%s is not a host this dataset is fetched from", u.Hostname())
	}
	return nil
}

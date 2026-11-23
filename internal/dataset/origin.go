// internal/dataset/origin.go

package dataset

import (
	"net/url"
	"strings"
)

// Origin is where a dataset's data is fetched from and the terms it comes
// under, as its source states them.
type Origin struct {
	// URL is the HTTPS address of the data.
	URL string

	// RedirectHosts are the hosts, other than the URL's own, that a
	// redirect from the URL may lead to. A redirect anywhere else is
	// refused, so a source lists here only hosts it is known to use.
	RedirectHosts []string

	// License and Attribution are what the source asks to be stated with
	// its data, recorded in the manifest of every copy fetched.
	License     string
	Attribution string
}

// Hosts returns the hosts a fetch of the data may reach: the URL's own and
// the redirect hosts, in lower case. It refuses an origin whose URL is not an
// HTTPS address of a host, or that lists an empty redirect host, so a fetch
// never starts from an origin it could not hold to its list.
func (o Origin) Hosts() ([]string, error) {
	if err := validSource(o.URL); err != nil {
		return nil, err
	}
	u, err := url.Parse(o.URL)
	if err != nil {
		return nil, refuse("the source %q is not an address", o.URL)
	}
	hosts := []string{strings.ToLower(u.Hostname())}
	for _, h := range o.RedirectHosts {
		if h == "" || strings.ContainsAny(h, "/:@ ") {
			return nil, refuse("%q is not a host a redirect may lead to", h)
		}
		hosts = append(hosts, strings.ToLower(h))
	}
	return hosts, nil
}

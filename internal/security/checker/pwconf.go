//go:build linux || freebsd

// internal/security/checker/pwconf.go

package checker

import "strings"

const (
	// pwConfFile configures the range pw(8) assigns to new accounts on
	// FreeBSD. pw.conf(5): "The default values for both user and group ids
	// are 1000 and 32000 as minimum and maximum respectively."
	pwConfFile      = "/etc/pw.conf" // #nosec G101 -- the path of the configuration file of pw(8), not a credential
	pwDefaultMinUID = 1000
	pwDefaultMaxUID = 32000
)

// pwUIDRange returns the range pw assigns to regular accounts, from the
// content of pw.conf. A line is a keyword, an equals sign and its data, as
// pw writes the file; a missing file or keyword leaves the documented
// default in place.
func pwUIDRange(conf []byte) uidRange {
	regular := uidRange{min: pwDefaultMinUID, max: pwDefaultMaxUID}

	for _, line := range strings.Split(string(conf), "\n") {
		keyword, data, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		value, ok := parseUnixID(strings.TrimSpace(data))
		if !ok {
			continue
		}
		switch strings.TrimSpace(keyword) {
		case "minuid":
			regular.min = value
		case "maxuid":
			regular.max = value
		}
	}
	return regular
}

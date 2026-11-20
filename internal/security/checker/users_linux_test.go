//go:build linux

// internal/security/checker/users_linux_test.go

package checker

import "testing"

// The range of regular accounts is the one login.defs sets, key by key, and
// the documented default for a key it does not set or sets to something that
// is not an identifier. A file that could not be read is no content, which
// leaves both defaults.
func TestRegularUIDRange(t *testing.T) {
	for name, tc := range map[string]struct {
		conf string
		want uidRange
	}{
		"no content":   {"", uidRange{min: defaultUIDMin, max: defaultUIDMax}},
		"both set":     {"# comment\nUID_MIN\t\t 500\nUID_MAX 29999\nGID_MIN 100\n", uidRange{min: 500, max: 29999}},
		"one set":      {"UID_MIN 2000\n", uidRange{min: 2000, max: defaultUIDMax}},
		"not a number": {"UID_MIN many\nUID_MAX -1\n", uidRange{min: defaultUIDMin, max: defaultUIDMax}},
		"key alone":    {"UID_MIN\n", uidRange{min: defaultUIDMin, max: defaultUIDMax}},
	} {
		if got := regularUIDRange([]byte(tc.conf)); got != tc.want {
			t.Errorf("%s: %+v, want %+v", name, got, tc.want)
		}
	}
}

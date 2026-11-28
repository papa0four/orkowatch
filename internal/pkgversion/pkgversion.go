// internal/pkgversion/pkgversion.go

// Package pkgversion orders the versions of installed packages as each
// package manager orders its own, and Windows builds as Microsoft orders
// them. Whether a package is affected by a
// vulnerability comes down to whether its version is older than the one that
// fixed it, and every manager has its own rules for that: epochs, release
// suffixes, and marks that sort a version before or after the one it is
// attached to. Each comparison here is written from its manager's own
// specification or source and none by analogy with another, and each is
// tested against the answers the manager's own tool gave.
package pkgversion

import (
	"fmt"
	"strings"
)

// Compare orders two versions of one scheme: negative when a is older than
// b, zero when they are the same version, positive when a is newer. It
// returns an error when either is not a version of the scheme, and a caller
// then has no order to act on: the package is neither affected nor clear.
type Compare func(a, b string) (int, error)

// unusable reports the first of two strings no scheme can order: an empty
// one, since a package with no version has no order to act on whatever its
// manager makes of that, and one holding a NUL, which no package manager can
// be handed and which would otherwise read as the end of a version.
func unusable(scheme, a, b string) error {
	for _, version := range []string{a, b} {
		switch {
		case version == "":
			return notVersion(scheme, version, "it is empty")
		case strings.IndexByte(version, 0) >= 0:
			return notVersion(scheme, version, "it holds a NUL")
		}
	}
	return nil
}

// notVersion is the error for a string a scheme does not accept.
func notVersion(scheme, version, why string) error {
	return fmt.Errorf("%s: %q is not a version: %s", scheme, version, why)
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isLetter(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

// compareNumbers orders two runs of digits by the numbers they write,
// whatever their length: leading zeros are dropped, the longer run is then
// the greater, and runs of one length order as text.
func compareNumbers(a, b string) int {
	a, b = trimZeros(a), trimZeros(b)
	switch {
	case len(a) != len(b):
		return sign(len(a) - len(b))
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func trimZeros(digits string) string {
	for len(digits) > 0 && digits[0] == '0' {
		digits = digits[1:]
	}
	return digits
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}

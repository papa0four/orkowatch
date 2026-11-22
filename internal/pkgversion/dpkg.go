// internal/pkgversion/dpkg.go

package pkgversion

import (
	"strconv"
	"strings"
)

const dpkgScheme = "dpkg"

// dpkgVersion is a version as deb-version(7) divides it: "Version numbers as
// used for Debian binary and source packages consist of three components",
// the epoch, the upstream-version and the debian-revision.
type dpkgVersion struct {
	epoch    string
	upstream string
	revision string
}

// Dpkg orders two versions as dpkg does. deb-version(7): the epoch "is a
// single (generally small) unsigned integer. It may be omitted, in which
// case zero is assumed", and "the absence of a debian-revision compares
// earlier than the presence of one (but note that the debian-revision is the
// least significant part of the version number)".
func Dpkg(a, b string) (int, error) {
	if err := unusable(dpkgScheme, a, b); err != nil {
		return 0, err
	}
	va, err := parseDpkg(a)
	if err != nil {
		return 0, err
	}
	vb, err := parseDpkg(b)
	if err != nil {
		return 0, err
	}

	if order := compareNumbers(va.epoch, vb.epoch); order != 0 {
		return order, nil
	}
	if order := compareDpkgPart(va.upstream, vb.upstream); order != 0 {
		return order, nil
	}
	return compareDpkgPart(va.revision, vb.revision), nil
}

// parseDpkg divides a version. deb-version(7): "Dpkg will break the version
// number apart at the last hyphen in the string (if there is one) to
// determine the upstream-version and debian-revision", and the epoch is what
// stands before the first colon. The strings refused are the ones dpkg
// itself refuses to compare: an empty one, one holding a space, an epoch
// that is empty, not a number or too large, and an epoch, an upstream
// version or a revision with nothing in it. A version dpkg only warns of,
// one that does not start with a digit or holds a character deb-version(7)
// does not allow, dpkg still orders, and so does this.
func parseDpkg(version string) (dpkgVersion, error) {
	var v dpkgVersion
	rest := version
	if strings.ContainsAny(rest, " \t\n") {
		return v, notVersion(dpkgScheme, version, "it holds a space")
	}

	if epoch, after, found := strings.Cut(rest, ":"); found {
		if epoch == "" {
			return v, notVersion(dpkgScheme, version, "its epoch is empty")
		}
		for i := range len(epoch) {
			if !isDigit(epoch[i]) {
				return v, notVersion(dpkgScheme, version, "its epoch is not a number")
			}
		}
		if _, err := strconv.ParseUint(epoch, decimal, dpkgEpochBits); err != nil {
			return v, notVersion(dpkgScheme, version, "its epoch is too large")
		}
		if after == "" {
			return v, notVersion(dpkgScheme, version, "nothing follows its epoch")
		}
		v.epoch, rest = epoch, after
	}

	v.upstream = rest
	if hyphen := strings.LastIndexByte(rest, '-'); hyphen >= 0 {
		v.upstream, v.revision = rest[:hyphen], rest[hyphen+1:]
		if v.revision == "" {
			return v, notVersion(dpkgScheme, version, "its revision is empty")
		}
	}
	if v.upstream == "" {
		return v, notVersion(dpkgScheme, version, "its upstream version is empty")
	}
	return v, nil
}

// compareDpkgPart orders two upstream-versions or two debian-revisions, which
// deb-version(7) says are compared "using the same algorithm": "First the
// initial part of each string consisting entirely of non-digit characters is
// determined. These two parts (one of which may be empty) are compared
// lexically." "Then the initial part of the remainder of each string which
// consists entirely of digit characters is determined. The numerical values
// of these two parts are compared." "These two steps ... are repeated until a
// difference is found or both strings are exhausted."
func compareDpkgPart(a, b string) int {
	for a != "" || b != "" {
		for (a != "" && !isDigit(a[0])) || (b != "" && !isDigit(b[0])) {
			if order := dpkgCharOrder(a) - dpkgCharOrder(b); order != 0 {
				return sign(order)
			}
			a, b = a[1:], b[1:]
		}

		da, db := digitRun(a), digitRun(b)
		if order := compareNumbers(a[:da], b[:db]); order != 0 {
			return order
		}
		a, b = a[da:], b[db:]
	}
	return 0
}

// dpkgCharOrder ranks the first character of a non-digit part for the
// lexical comparison, which deb-version(7) describes as "a comparison of
// ASCII values modified so that all the letters sort earlier than all the
// non-letters and so that a tilde sorts before anything, even the end of a
// part". The end of the part, and a digit, which ends the non-digit part,
// rank between the tilde and the letters.
func dpkgCharOrder(part string) int {
	if part == "" || isDigit(part[0]) {
		return 0
	}
	switch c := part[0]; {
	case c == '~':
		return -1
	case isLetter(c):
		return int(c)
	default:
		return int(c) + dpkgNonLetter
	}
}

// digitRun returns the length of the digits s begins with.
func digitRun(s string) int {
	n := 0
	for n < len(s) && isDigit(s[n]) {
		n++
	}
	return n
}

const (
	// dpkgNonLetter lifts every character that is not a letter above every
	// letter: it is one more than the largest value a byte holds.
	dpkgNonLetter = 256

	// dpkgEpochBits is the size of the largest epoch dpkg accepts,
	// 2147483647: it keeps the epoch in a signed 32-bit integer.
	dpkgEpochBits = 31
)

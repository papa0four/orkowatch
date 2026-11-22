// internal/pkgversion/pacman.go

package pkgversion

import "strings"

const pacmanScheme = "pacman"

// Pacman orders two versions as pacman's vercmp does. vercmp(8) gives the
// form, "epoch:version-rel", and libalpm's alpm_pkg_vercmp the rule: the
// epochs are compared, then the versions, and the releases only when both
// have one, so a version with no release is the same as that version at any
// release. A version with no epoch has epoch zero.
func Pacman(a, b string) (int, error) {
	if err := unusable(pacmanScheme, a, b); err != nil {
		return 0, err
	}

	epochA, versionA, releaseA, hasA := splitPacman(a)
	epochB, versionB, releaseB, hasB := splitPacman(b)
	if order := comparePacmanPart(epochA, epochB); order != 0 {
		return order, nil
	}
	if order := comparePacmanPart(versionA, versionB); order != 0 {
		return order, nil
	}
	if hasA && hasB {
		return comparePacmanPart(releaseA, releaseB), nil
	}
	return 0, nil
}

// splitPacman divides a version as libalpm's parseEVR does: the epoch is the
// digits the string begins with when a colon follows them, zero when there
// are none, and the release is what follows the last hyphen.
func splitPacman(version string) (epoch, upstream, release string, hasRelease bool) {
	epoch, upstream = "0", version
	if digits := digitRun(version); digits < len(version) && version[digits] == ':' {
		if digits > 0 {
			epoch = version[:digits]
		}
		upstream = version[digits+1:]
	}
	if hyphen := strings.LastIndexByte(upstream, '-'); hyphen >= 0 {
		return epoch, upstream[:hyphen], upstream[hyphen+1:], true
	}
	return epoch, upstream, "", false
}

// comparePacmanPart orders two epochs, versions or releases as libalpm's
// rpmvercmp does, which its source says was "adopted from the rpm source"
// and "most recently updated against rpm version 4.8.1": it has none of the
// tilde and caret operators rpm gained later, and it has rules rpm does not.
// Each part is read as segments of digits or of letters with separators
// between. Where the two have separators of different lengths before a
// segment, the one with fewer is older. A numeric segment is newer than an
// alphabetic one. When every segment compares the same, what is left
// decides: a part that goes on with letters is older than one that has
// ended, and one that goes on with anything else is newer.
func comparePacmanPart(a, b string) int {
	if a == b {
		return 0
	}

	for a != "" && b != "" {
		gapA, gapB := separatorRun(a), separatorRun(b)
		a, b = a[gapA:], b[gapB:]
		if a == "" || b == "" {
			break
		}
		if gapA != gapB {
			return sign(gapA - gapB)
		}

		order, usedA, usedB := compareSegment(a, b)
		if order != 0 {
			return order
		}
		a, b = a[usedA:], b[usedB:]
	}

	switch {
	case a == "" && b == "":
		return 0
	case a == "" && !isLetter(b[0]), a != "" && isLetter(a[0]):
		return -1
	}
	return 1
}

// separatorRun returns the length of the characters s begins with that are
// neither letters nor digits.
func separatorRun(s string) int {
	n := 0
	for n < len(s) && !isDigit(s[n]) && !isLetter(s[n]) {
		n++
	}
	return n
}

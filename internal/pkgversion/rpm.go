// internal/pkgversion/rpm.go

package pkgversion

import "strings"

const rpmScheme = "rpm"

// rpmVersion is a version as rpm-version(7) divides it, "[EPOCH:]VERSION
// [-RELEASE]": "Only the VERSION component is mandatory". hasRelease tells
// a version with no release from one whose release is empty.
type rpmVersion struct {
	epoch      string
	version    string
	release    string
	hasRelease bool
}

// RPM orders two versions as rpm does. rpm-version(7): "Two EVRs are
// compared left to right, one component at a time", "an omitted EPOCH has an
// implicit value of zero", and "an EVR with more components is considered
// newer", so a version with a release is newer than the same version with
// none.
func RPM(a, b string) (int, error) {
	if err := unusable(rpmScheme, a, b); err != nil {
		return 0, err
	}
	va, vb := parseRPM(a), parseRPM(b)

	if order := compareRPMPart(va.epoch, vb.epoch); order != 0 {
		return order, nil
	}
	if order := compareRPMPart(va.version, vb.version); order != 0 {
		return order, nil
	}
	switch {
	case va.hasRelease && vb.hasRelease:
		return compareRPMPart(va.release, vb.release), nil
	case va.hasRelease:
		return 1, nil
	case vb.hasRelease:
		return -1, nil
	}
	return 0, nil
}

// parseRPM divides a version the way rpm's parseEVR does: the epoch is the
// digits the string begins with when a colon follows them, and an empty run
// of digits before a colon is epoch zero; the release is what follows the
// last hyphen after that.
func parseRPM(version string) rpmVersion {
	v := rpmVersion{epoch: "0"}
	rest := version
	if digits := digitRun(rest); digits < len(rest) && rest[digits] == ':' {
		if digits > 0 {
			v.epoch = rest[:digits]
		}
		rest = rest[digits+1:]
	}

	v.version = rest
	if hyphen := strings.LastIndexByte(rest, '-'); hyphen >= 0 {
		v.version, v.release, v.hasRelease = rest[:hyphen], rest[hyphen+1:], true
	}
	return v
}

// compareRPMPart orders two epochs, two versions or two releases as
// rpmvercmp does. rpm-version(7): "consecutive alphabetic characters and
// consecutive numbers form implicit segments", "the segment separator
// characters are not compared", "numeric segments are compared numerically
// as integers with leading zeros ignored, otherwise lexicographical
// comparison is used", "numeric segments are considered newer than
// alphabetic segments regardless of the actual content", and "when otherwise
// equal, the component with more segments is considered newer". "The tilde
// operator causes a segment to sort older", and "the caret operator is
// essentially the opposite of tilde".
func compareRPMPart(a, b string) int {
	if a == b {
		return 0
	}

	for a != "" || b != "" {
		a, b = skipRPMSeparators(a), skipRPMSeparators(b)
		if order, operator := compareRPMOperator(a, b); operator {
			if order != 0 {
				return order
			}
			a, b = a[1:], b[1:]
			continue
		}
		if a == "" || b == "" {
			break
		}

		order, usedA, usedB := compareSegment(a, b)
		if order != 0 {
			return order
		}
		a, b = a[usedA:], b[usedB:]
	}

	// Every segment compared the same: the part with something left is
	// the newer.
	switch {
	case a == "" && b == "":
		return 0
	case a == "":
		return -1
	}
	return 1
}

// compareRPMOperator handles a tilde or a caret at the head of either part,
// and reports whether there was one. A tilde sorts before everything, the
// end of the part included. A caret sorts after the end of the part and
// before anything else that could follow. Where both parts have the same
// operator the order is zero and both step past it.
func compareRPMOperator(a, b string) (order int, operator bool) {
	if tildeA, tildeB := strings.HasPrefix(a, "~"), strings.HasPrefix(b, "~"); tildeA || tildeB {
		switch {
		case !tildeA:
			return 1, true
		case !tildeB:
			return -1, true
		}
		return 0, true
	}
	if caretA, caretB := strings.HasPrefix(a, "^"), strings.HasPrefix(b, "^"); caretA || caretB {
		switch {
		case a == "":
			return -1, true
		case b == "":
			return 1, true
		case !caretA:
			return 1, true
		case !caretB:
			return -1, true
		}
		return 0, true
	}
	return 0, false
}

// compareSegment orders the segments two parts begin with and returns how
// much of each it read. It is the step rpm's rpmvercmp and libalpm's copy of
// it share word for word. The first part decides what kind is compared, the
// digits or the letters each begins with. Where the second begins with the
// other kind its segment is empty, and the numeric one is the newer. Digits
// are compared as numbers and letters as text.
func compareSegment(a, b string) (order, usedA, usedB int) {
	numeric := isDigit(a[0])
	run := letterRun
	if numeric {
		run = digitRun
	}
	usedA, usedB = run(a), run(b)
	switch {
	case usedB == 0 && numeric:
		return 1, usedA, usedB
	case usedB == 0:
		return -1, usedA, usedB
	case numeric:
		return compareNumbers(a[:usedA], b[:usedB]), usedA, usedB
	}
	return strings.Compare(a[:usedA], b[:usedB]), usedA, usedB
}

// skipRPMSeparators drops what stands between segments: every character
// that is not a letter or a digit, the tilde and the caret apart, which are
// operators and are compared.
func skipRPMSeparators(part string) string {
	for part != "" && !isDigit(part[0]) && !isLetter(part[0]) && part[0] != '~' && part[0] != '^' {
		part = part[1:]
	}
	return part
}

// letterRun returns the length of the letters s begins with.
func letterRun(s string) int {
	n := 0
	for n < len(s) && isLetter(s[n]) {
		n++
	}
	return n
}

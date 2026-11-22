// internal/pkgversion/apk.go

package pkgversion

import "strings"

const apkScheme = "apk"

// The kinds of token apk-tools 2.14 reads a version as, in the order its
// version.c gives them, which is also the order a version may move through
// them: "{digit}{.digit}...{letter}{_suf{#}}...{-r#}".
const (
	apkInvalid = iota - 1
	apkDigitOrZero
	apkDigit
	apkLetter
	apkSuffix
	apkSuffixNumber
	apkRevision
	apkEnd
)

// apkNumberDigits is the length at which apk refuses a number as too long.
const apkNumberDigits = 18

// apkPreSuffixes mark a version as coming before the one they are attached
// to, and apkPostSuffixes as coming after, each in the order apk ranks them.
var (
	apkPreSuffixes  = []string{"alpha", "beta", "pre", "rc"}
	apkPostSuffixes = []string{"cvs", "svn", "git", "hg", "p"}
)

// apkReader reads one version token by token.
type apkReader struct {
	rest string
	kind int
}

// APK orders two versions as apk-tools 2.14 does, the apk of Alpine 3.20. The
// two are read token by token while their tokens are of one kind and one
// value. A difference in value decides. Where one version ends or changes
// kind first, the one that goes on is newer, unless it goes on with a suffix
// that marks a pre-release, and otherwise the one whose next token is of the
// earlier kind is newer. A string apk does not accept as a version is
// refused.
func APK(a, b string) (int, error) {
	if err := unusable(apkScheme, a, b); err != nil {
		return 0, err
	}
	for _, version := range []string{a, b} {
		if !validAPK(version) {
			return 0, notVersion(apkScheme, version, "apk does not read it as one")
		}
	}

	ra, rb := apkReader{rest: a, kind: apkDigit}, apkReader{rest: b, kind: apkDigit}
	var va, vb int64
	for ra.kind == rb.kind && ra.kind != apkEnd && ra.kind != apkInvalid && va == vb {
		va, vb = ra.token(), rb.token()
	}

	switch {
	case va < vb:
		return -1, nil
	case va > vb:
		return 1, nil
	case ra.kind == rb.kind:
		return 0, nil
	case ra.preRelease():
		return -1, nil
	case rb.preRelease():
		return 1, nil
	}
	return sign(rb.kind - ra.kind), nil
}

// preRelease reports whether the reader stands at a suffix that marks a
// pre-release. It reads from a copy, so the reader stays where it is.
func (r apkReader) preRelease() bool {
	return r.kind == apkSuffix && r.token() < 0
}

// validAPK reports whether apk reads the whole string as tokens of a
// version, which is what its apk_version_validate checks.
func validAPK(version string) bool {
	r := apkReader{rest: version, kind: apkDigit}
	for r.kind != apkEnd && r.kind != apkInvalid {
		r.token()
	}
	return r.kind == apkEnd
}

// token reads the token the reader stands at, returns its value and moves to
// the next. A number's value is the number; a letter's is the letter; a
// suffix's is its rank, below zero for one that marks a pre-release. The
// zeros a number after a full stop begins with are a token of their own,
// whose value falls as their count rises, so that 1.01 is older than 1.1.
func (r *apkReader) token() int64 {
	if r.rest == "" {
		r.kind = apkEnd
		return 0
	}

	var value int64
	var used int
	next := apkInvalid
	switch {
	case r.kind == apkDigitOrZero && r.rest[0] == '0':
		for used+1 < len(r.rest) && r.rest[used+1] == '0' {
			used++
		}
		next, value = apkDigit, int64(-used)
	case r.kind == apkDigitOrZero, r.kind == apkDigit, r.kind == apkSuffixNumber, r.kind == apkRevision:
		used = digitRun(r.rest)
		if used >= apkNumberDigits {
			r.kind = apkInvalid
			return -1
		}
		for i := range used {
			value = value*decimal + int64(r.rest[i]-'0')
		}
	case r.kind == apkLetter:
		value, used = int64(r.rest[0]), 1
	case r.kind == apkSuffix:
		rank, length, found := apkSuffixRank(r.rest)
		if !found {
			r.kind = apkInvalid
			return -1
		}
		value, used = rank, length
	default:
		r.kind = apkInvalid
		return -1
	}

	r.rest = r.rest[used:]
	switch {
	case r.rest == "":
		r.kind = apkEnd
	case next != apkInvalid:
		r.kind = next
	default:
		r.advance()
	}
	return value
}

// apkSuffixRank finds the suffix s begins with. A pre-release suffix ranks
// below zero, the earliest lowest; the others from zero up.
func apkSuffixRank(s string) (rank int64, length int, found bool) {
	for i, suffix := range apkPreSuffixes {
		if strings.HasPrefix(s, suffix) {
			return int64(i - len(apkPreSuffixes)), len(suffix), true
		}
	}
	for i, suffix := range apkPostSuffixes {
		if strings.HasPrefix(s, suffix) {
			return int64(i), len(suffix), true
		}
	}
	return 0, 0, false
}

// advance decides the kind of the token that follows, from the kind just
// read and the character the rest begins with, and steps over the character
// that introduces it. A kind may only follow one that comes before it in the
// order above, three steps back apart: a number after a full stop, a suffix
// after a suffix's number, and a number after a letter.
func (r *apkReader) advance() {
	before, next := r.kind, apkInvalid
	c := r.rest[0]
	switch {
	case (before == apkDigit || before == apkDigitOrZero) && c >= 'a' && c <= 'z':
		next = apkLetter
	case before == apkLetter && isDigit(c):
		next = apkDigit
	case before == apkSuffix && isDigit(c):
		next = apkSuffixNumber
	default:
		switch {
		case c == '.':
			next = apkDigitOrZero
		case c == '_':
			next = apkSuffix
		case c == '-' && len(r.rest) > 1 && r.rest[1] == 'r':
			next = apkRevision
			r.rest = r.rest[1:]
		}
		r.rest = r.rest[1:]
	}

	if next < before {
		back := (next == apkDigitOrZero && before == apkDigit) ||
			(next == apkSuffix && before == apkSuffixNumber) ||
			(next == apkDigit && before == apkLetter)
		if !back {
			next = apkInvalid
		}
	}
	r.kind = next
}

// decimal is the base version numbers are written in.
const decimal = 10

// internal/pkgversion/pkg.go

package pkgversion

import (
	"math"
	"strings"
)

const pkgScheme = "pkg"

// pkgLetterBase is the rank of the letter a within a component. The ranks
// below it are a component with no letter, at zero, and the stages libpkg
// sorts ahead of every letter.
const pkgLetterBase = 2

// The values libpkg gives a component with no number of its own.
const (
	pkgNoNumber = -1
	pkgWildcard = -2
)

type (
	// pkgParts is a version as libpkg's split_version divides it:
	// "${PORTVERSION}[_${PORTREVISION}][,${PORTEPOCH}]". text is the
	// version from its start, and end is where the port version stops in
	// it.
	pkgParts struct {
		text     string
		end      int
		epoch    uint64
		revision uint64
	}

	// pkgComponent is one component of a port version, which libpkg
	// describes as "a version number, a letter and a patchlevel number".
	pkgComponent struct {
		number int64
		letter int
		patch  int64
	}

	// pkgReader reads the components of one port version in turn.
	pkgReader struct {
		text string
		pos  int
		end  int
	}

	// pkgStage is a word libpkg reads as one stage and not as a letter
	// followed by more letters. atEnd is set for a word read so only
	// where it ends the version.
	pkgStage struct {
		name  string
		rank  int
		atEnd bool
	}
)

// pkgStages are the stage words with the rank each takes: alpha, beta, pre
// and rc rank as their first letters do, and pl ranks before any letter.
//
// snap is read as pkg 2.6 reads it, the pkg of FreeBSD 15.1: it ranks
// between pl and the letters, and only where it ends the version. Followed
// by anything it is the letter s like any other word. pkg's later source
// ranks snap as the letter s and reads it wherever no letter follows; no
// version in FreeBSD's vulnerability data holds the word.
var pkgStages = []pkgStage{
	{name: "pl", rank: 0},
	{name: "snap", rank: 1, atEnd: true},
	{name: "alpha", rank: pkgLetterRank('a')},
	{name: "beta", rank: pkgLetterRank('b')},
	{name: "pre", rank: pkgLetterRank('p')},
	{name: "rc", rank: pkgLetterRank('r')},
}

// Pkg orders two versions as FreeBSD's pkg does. libpkg's pkg_version_cmp:
// "${PORTEPOCH} supersedes ${PORTVERSION} supersedes ${PORTREVISION}".
func Pkg(a, b string) (int, error) {
	if err := unusable(pkgScheme, a, b); err != nil {
		return 0, err
	}

	va, vb := splitPkg(a), splitPkg(b)
	if va.epoch != vb.epoch {
		return compareUnsigned(va.epoch, vb.epoch), nil
	}
	if order := comparePortVersions(va, vb); order != 0 {
		return order, nil
	}
	return compareUnsigned(va.revision, vb.revision), nil
}

// comparePortVersions orders two port versions a component at a time. A
// component one version lacks counts as zero, so 10, 10.0 and 10.0.0 are one
// version. A plus sign ends a block of components: each version is read up
// to its own, and the two step over them together.
func comparePortVersions(va, vb pkgParts) int {
	if va.end == vb.end && strings.EqualFold(va.text[:va.end], vb.text[:vb.end]) {
		return 0
	}

	ra, rb := pkgReader{text: va.text, end: va.end}, pkgReader{text: vb.text, end: vb.end}
	for !ra.done() || !rb.done() {
		blockedA, blockedB := ra.blocked(), rb.blocked()
		if blockedA && blockedB {
			ra.step()
			rb.step()
			continue
		}

		var ca, cb pkgComponent
		if !blockedA {
			ca = ra.component()
		}
		if !blockedB {
			cb = rb.component()
		}
		switch {
		case ca.number != cb.number:
			return compareSigned(ca.number, cb.number)
		case ca.letter != cb.letter:
			return sign(ca.letter - cb.letter)
		case ca.patch != cb.patch:
			return compareSigned(ca.patch, cb.patch)
		}
	}
	return 0
}

// splitPkg divides a version as split_version does. What follows the last
// hyphen is the version, since the function is also given package names.
// The revision follows the last underscore in that, and the epoch the last
// comma after the revision; the port version stops at whichever of the two
// comes first.
func splitPkg(version string) pkgParts {
	p := pkgParts{text: version}
	if hyphen := strings.LastIndexByte(version, '-'); hyphen >= 0 {
		p.text = version[hyphen+1:]
	}
	p.end = len(p.text)

	afterRevision := 0
	if underscore := strings.LastIndexByte(p.text, '_'); underscore >= 0 {
		p.revision = leadingNumber(p.text[underscore+1:])
		p.end = underscore
		afterRevision = underscore + 1
	}
	if comma := strings.LastIndexByte(p.text[afterRevision:], ','); comma >= 0 {
		p.epoch = leadingNumber(p.text[afterRevision+comma+1:])
		if afterRevision == 0 {
			p.end = comma
		}
	}
	return p
}

// done reports whether the reader has passed the end of the port version.
func (r *pkgReader) done() bool { return r.pos >= r.end }

// blocked reports whether the reader stands at the end of a block of
// components: the end of the port version, or a plus sign.
func (r *pkgReader) blocked() bool { return r.done() || r.text[r.pos] == '+' }

// step moves a reader that is not done over the plus sign it stands at.
func (r *pkgReader) step() {
	if !r.done() {
		r.pos++
	}
}

// at returns the character at i, or zero past the end of the text. A version
// holds no NUL, so zero is the end and nothing else.
func (r *pkgReader) at(i int) byte {
	if i < len(r.text) {
		return r.text[i]
	}
	return 0
}

// component reads the component the reader stands at and moves to the next,
// as libpkg's get_component does: "missing version numbers (in components
// starting with a letter) sort as -1", "the special component `*' is
// guaranteed to be the smallest possible component", and after the number
// come a letter and a patch level, where there is a letter.
func (r *pkgReader) component() pkgComponent {
	var c pkgComponent
	numberless := false
	switch {
	case isDigit(r.at(r.pos)):
		c.number = r.number()
	case r.at(r.pos) == '*':
		c.number = pkgWildcard
		r.pos++
		for r.at(r.pos) != 0 && r.at(r.pos) != '+' {
			r.pos++
		}
	default:
		c.number = pkgNoNumber
		numberless = true
	}

	var hasPatch bool
	c.letter, hasPatch = r.letter(numberless)
	if hasPatch {
		c.patch = pkgNoNumber
		if isDigit(r.at(r.pos)) {
			c.patch = r.number()
		}
	}

	for ch := r.at(r.pos); ch != 0 && !isDigit(ch) && !isLetter(ch) && ch != '+' && ch != '*'; ch = r.at(r.pos) {
		r.pos++
	}
	return c
}

// number reads the digits the reader stands at.
func (r *pkgReader) number() int64 {
	digits := digitRun(r.text[r.pos:])
	n := saturatingNumber(r.text[r.pos : r.pos+digits])
	r.pos += digits
	return n
}

// letter reads the letter part of a component and reports its rank and
// whether a patch level may follow it. libpkg: "other strings use only the
// first letter for sorting, case is ignored", and "a separator is inserted
// before the special strings": a stage word is read as a stage only in a
// component with no number, so after a number it is left to start a
// component of its own, and this one has neither a letter nor a patch level.
func (r *pkgReader) letter(numberless bool) (rank int, hasPatch bool) {
	if !isLetter(r.at(r.pos)) {
		return 0, false
	}
	if stage, found := r.stage(); found {
		if !numberless {
			return 0, false
		}
		r.pos += len(stage.name)
		return stage.rank, true
	}

	rank = pkgLetterRank(r.at(r.pos) | caseBit)
	for isLetter(r.at(r.pos)) {
		r.pos++
	}
	return rank, true
}

// stage finds the stage word the reader stands at: one of pkgStages, of at
// least two letters, with no letter after it.
func (r *pkgReader) stage() (pkgStage, bool) {
	if !isLetter(r.at(r.pos + 1)) {
		return pkgStage{}, false
	}
	for _, s := range pkgStages {
		after := r.pos + len(s.name)
		if after > len(r.text) || !strings.EqualFold(r.text[r.pos:after], s.name) || isLetter(r.at(after)) {
			continue
		}
		if s.atEnd && after != len(r.text) {
			continue
		}
		return s, true
	}
	return pkgStage{}, false
}

// pkgLetterRank returns the rank of a lower-case letter within a component.
func pkgLetterRank(letter byte) int {
	return int(letter-'a') + pkgLetterBase
}

// caseBit is the bit that sets an ASCII letter to lower case.
const caseBit = 0x20

// leadingNumber returns the number s begins with, zero when it begins with
// none, as strtoul reads a revision or an epoch.
func leadingNumber(s string) uint64 {
	var n uint64
	for i := 0; i < len(s) && isDigit(s[i]); i++ {
		digit := uint64(s[i] - '0')
		if n > (math.MaxUint64-digit)/decimal {
			return math.MaxUint64
		}
		n = n*decimal + digit
	}
	return n
}

// saturatingNumber returns the number a run of digits writes, or the largest
// a component can hold when it is larger, as strtoll does.
func saturatingNumber(digits string) int64 {
	var n int64
	for i := range len(digits) {
		digit := int64(digits[i] - '0')
		if n > (math.MaxInt64-digit)/decimal {
			return math.MaxInt64
		}
		n = n*decimal + digit
	}
	return n
}

func compareSigned(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func compareUnsigned(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

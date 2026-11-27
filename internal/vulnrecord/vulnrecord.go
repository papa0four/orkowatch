// internal/vulnrecord/vulnrecord.go

// Package vulnrecord is what a source of vulnerability records gives the
// matcher of installed packages: a record, the packages it affects, and the
// ranges of their versions, in one form whatever the source. Each source
// converts its own records to it, so the matcher, and the commands that give
// it a source's records, name no source. It holds the types alone and
// imports nothing of owatch, so a dataset can give records without importing
// the matcher.
package vulnrecord

type (
	// Record is one record of vulnerabilities: its identifier, the CVEs it
	// covers, when it was published and last modified, the advisory it
	// names, the source's own rating of it, its scores, and the packages it
	// affects. An Open record says a vulnerability is tracked against its
	// packages, as a tracking bug does, and not that their versions are
	// affected: a fix another record gives clears it, and with none it is
	// shown as tracked.
	Record struct {
		ID        string
		CVEs      []string
		Published string
		Modified  string
		Advisory  string
		Rating    string
		Scores    []Score
		Affected  []Affected
		Open      bool
	}

	// Affected is a package a record affects, the ecosystem it names the
	// package in, and the ranges of its versions that are affected. A version
	// in any one range is affected. Source says Package names a source
	// package, as a tracker files against, where the manager's records name
	// binary packages: each installed package built from it is affected.
	Affected struct {
		Package   string
		Ecosystem string
		Ranges    [][]Bound
		Source    bool
	}

	// Bound is one bound of a range: what it says of versions, and the
	// version it says it of.
	Bound struct {
		Kind    Kind
		Version string
	}

	// Kind is what a bound says of the versions of its range.
	Kind string

	// Score is a score a record carries, of the type it names, as a CVSS
	// vector or a distribution's own word. Its keys are those a view of a
	// match serializes a score with.
	Score struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	}
)

// The bounds a range is made of. A range is judged by walking its bounds in
// the order of their versions: From and After enter it, Before and UpTo leave
// it, Exactly is inside at its version alone, and a version at or past a
// Limit is in no part of the range. A range with no bound that enters it
// affects no version, so a source whose range names no lower bound gives From
// First.
const (
	// From is at or after Version.
	From Kind = "from"

	// After is strictly after Version.
	After Kind = "after"

	// Before is strictly before Version, which is the version that fixes
	// the range.
	Before Kind = "before"

	// UpTo is at or before Version, the last version affected, with no fix
	// stated.
	UpTo Kind = "up to"

	// Exactly is Version alone.
	Exactly Kind = "exactly"

	// Limit ends the range: no version at or past Version is in it.
	Limit Kind = "limit"
)

// Combining is how the records of one source that name one vulnerability
// combine for an installed version: a source's records may overlap, and
// sources overlap differently, so each states its own.
type Combining int

const (
	// FixClears settles a version a record's range has passed as not
	// affected, whatever another record says: a distribution's data can
	// hold one record with the fix beside a stale one that still states
	// none, and the fix is what holds.
	FixClears Combining = iota

	// AnyRange settles a version any record's range holds as affected, as
	// pkg audit judges VuXML: a later entry widens what an earlier one
	// covered rather than being cleared by it.
	AnyRange
)

// The two versions a bound gives a meaning of its own, as OSV gives them: the
// version that sorts before any other, and the one that sorts after any
// other.
const (
	First    = "0"
	Infinity = "*"
)

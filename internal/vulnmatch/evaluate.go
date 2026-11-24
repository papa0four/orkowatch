// internal/vulnmatch/evaluate.go

package vulnmatch

import (
	"slices"

	"github.com/papa0four/orkowatch/internal/dataset/osv"
	"github.com/papa0four/orkowatch/internal/pkgversion"
)

// The events of a range, as the OSV schema names them, and the two versions
// it gives a meaning of its own: "introduced allows a version of the value
// "0" to represent a version that sorts before any other version", and "limit
// allows versions containing the string "*" to represent "infinity"".
const (
	eventIntroduced   = "introduced"
	eventFixed        = "fixed"
	eventLastAffected = "last_affected"
	eventLimit        = "limit"
	versionFirst      = "0"
	versionInfinity   = "*"
)

// verdict is what one record's ranges say of an installed version.
type verdict int

const (
	// outside: the version is in no range of the record, which is for
	// versions it does not have, such as another module stream's.
	outside verdict = iota

	// cleared: the version entered a range and has passed a fixed or last
	// affected event of it, so the record's fix is installed.
	cleared

	// inside: the version is in a range of the record.
	inside
)

// judgment is one record's verdict on an installed version, with the fixed
// versions its ranges give above the installed one, the lowest of which is
// the update that clears it.
type judgment struct {
	verdict verdict
	above   []string
}

// judge evaluates the ranges of one package of a record against an installed
// version, ordering versions by compare. It follows the evaluation the OSV
// schema gives: a range applies when the version is below one of its limits,
// or it has none; its events are sorted, and walked with one flag, which an
// introduced event the version reaches sets, and a fixed event it reaches, or
// a last affected event it passes, clears. "A version is considered affected
// if it lies within any one of the ranges." A version that entered a range
// and was cleared is the record's fix installed, which the schema's flag does
// not tell from a version that never entered one, and which matching needs.
// A version that cannot be ordered is an error.
func judge(installed string, ranges [][]osv.Event, compare pkgversion.Compare) (judgment, error) {
	var j judgment
	for _, events := range ranges {
		within, err := beforeLimits(installed, events, compare)
		if err != nil {
			return judgment{}, err
		}
		if !within {
			continue
		}
		sorted, err := sortEvents(events, compare)
		if err != nil {
			return judgment{}, err
		}
		vulnerable, entered, above, err := walk(installed, sorted, compare)
		if err != nil {
			return judgment{}, err
		}
		switch {
		case vulnerable:
			j.verdict = inside
			j.above = append(j.above, above...)
		case entered && j.verdict == outside:
			j.verdict = cleared
		}
	}
	return j, nil
}

// walk runs the schema's flag over one range's sorted events: whether
// installed ends in the range, whether it entered it at all, and the fixed
// versions above it, which are what would clear it.
func walk(installed string, sorted []event, compare pkgversion.Compare) (vulnerable, entered bool, above []string, err error) {
	for _, e := range sorted {
		at, err := order(installed, e.version, compare)
		if err != nil {
			return false, false, nil, err
		}
		switch e.kind {
		case eventIntroduced:
			if at >= 0 {
				vulnerable, entered = true, true
			}
		case eventFixed:
			if at >= 0 {
				vulnerable = false
			} else {
				above = append(above, e.version)
			}
		case eventLastAffected:
			if at > 0 {
				vulnerable = false
			}
		}
	}
	return vulnerable, entered, above, nil
}

// event is one event of a range, its kind and version.
type event struct {
	kind    string
	version string
}

// sortEvents orders a range's events by their versions, the first version
// before every other and an event of no version a range reads, a limit, left
// out. Events of one version keep the order the record gives them.
func sortEvents(events []osv.Event, compare pkgversion.Compare) ([]event, error) {
	var out []event
	for _, e := range events {
		for kind, version := range e {
			if kind != eventLimit {
				out = append(out, event{kind: kind, version: version})
			}
		}
	}
	var failed error
	slices.SortStableFunc(out, func(a, b event) int {
		at, err := order(a.version, b.version, compare)
		if err != nil && failed == nil {
			failed = err
		}
		return at
	})
	return out, failed
}

// beforeLimits reports whether installed is below one of the range's limits,
// or the range has none, which the schema reads as an implicit limit of
// infinity.
func beforeLimits(installed string, events []osv.Event, compare pkgversion.Compare) (bool, error) {
	limited := false
	for _, e := range events {
		limit, ok := e[eventLimit]
		if !ok {
			continue
		}
		limited = true
		at, err := order(installed, limit, compare)
		if err != nil {
			return false, err
		}
		if at < 0 {
			return true, nil
		}
	}
	return !limited, nil
}

// order compares two versions of a range by compare, with the two versions the
// schema gives a meaning: the first version before every other, and infinity
// after every other.
func order(a, b string, compare pkgversion.Compare) (int, error) {
	switch {
	case a == b:
		return 0, nil
	case a == versionFirst || b == versionInfinity:
		return -1, nil
	case b == versionFirst || a == versionInfinity:
		return 1, nil
	}
	return compare(a, b)
}

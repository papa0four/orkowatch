// internal/vulnmatch/evaluate.go

package vulnmatch

import (
	"slices"

	"github.com/papa0four/orkowatch/internal/pkgversion"
	"github.com/papa0four/orkowatch/internal/vulnrecord"
)

// verdict is what one record's ranges say of an installed version.
type verdict int

const (
	// outside: the version is in no range of the record, which is for
	// versions it does not have, such as another module stream's.
	outside verdict = iota

	// cleared: the version entered a range and has reached a Before bound
	// of it or passed an UpTo or Exactly bound, so the record's fix is
	// installed.
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
	open    bool
}

// judge evaluates the ranges of one package of a record against an installed
// version, ordering versions by compare. It follows the evaluation the OSV
// schema gives, over bounds of every kind a source states: a range applies
// when the version is below one of its limits, or it has none; its bounds are
// sorted, and walked with one flag, which a From bound the version reaches or
// an After bound it passes sets, an Exactly bound sets at its version alone,
// and a Before bound it reaches or an UpTo bound it passes clears. "A version
// is considered affected if it lies within any one of the ranges." A version
// that entered a range and was cleared is the record's fix installed, which
// the schema's flag does not tell from a version that never entered one, and
// which matching needs. A version that cannot be ordered is an error.
func judge(installed string, ranges [][]vulnrecord.Bound, compare pkgversion.Compare) (judgment, error) {
	var j judgment
	for _, bounds := range ranges {
		within, err := beforeLimits(installed, bounds, compare)
		if err != nil {
			return judgment{}, err
		}
		if !within {
			continue
		}
		sorted, err := sortBounds(bounds, compare)
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

// walk runs the schema's flag over one range's sorted bounds: whether
// installed ends in the range, whether it entered it at all, and the fixed
// versions above it, which are what would clear it. An Exactly bound the
// version is past has entered and cleared it, as a fix installed does.
func walk(installed string, sorted []vulnrecord.Bound, compare pkgversion.Compare) (vulnerable, entered bool, above []string, err error) {
	for _, b := range sorted {
		at, err := order(installed, b.Version, compare)
		if err != nil {
			return false, false, nil, err
		}
		vulnerable, entered = step(b.Kind, at, vulnerable, entered)
		if b.Kind == vulnrecord.Before && at < 0 {
			above = append(above, b.Version)
		}
	}
	return vulnerable, entered, above, nil
}

// step is the flag, and whether the version has entered the range, after a
// bound of kind, at says where the installed version is against the bound's:
// below it, at it, or past it.
func step(kind vulnrecord.Kind, at int, vulnerable, entered bool) (bool, bool) {
	switch {
	case kind == vulnrecord.From && at >= 0, kind == vulnrecord.After && at > 0, kind == vulnrecord.Exactly && at == 0:
		return true, true
	case kind == vulnrecord.Exactly && at > 0:
		return false, true
	case kind == vulnrecord.Before && at >= 0, kind == vulnrecord.UpTo && at > 0:
		return false, entered
	}
	return vulnerable, entered
}

// sortBounds orders a range's bounds by their versions, the first version
// before every other and a bound the walk does not read, a limit, left out.
// Bounds of one version keep the order the record gives them.
func sortBounds(bounds []vulnrecord.Bound, compare pkgversion.Compare) ([]vulnrecord.Bound, error) {
	var out []vulnrecord.Bound
	for _, b := range bounds {
		if b.Kind != vulnrecord.Limit {
			out = append(out, b)
		}
	}
	var failed error
	slices.SortStableFunc(out, func(a, b vulnrecord.Bound) int {
		at, err := order(a.Version, b.Version, compare)
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
func beforeLimits(installed string, bounds []vulnrecord.Bound, compare pkgversion.Compare) (bool, error) {
	limited := false
	for _, b := range bounds {
		if b.Kind != vulnrecord.Limit {
			continue
		}
		limited = true
		at, err := order(installed, b.Version, compare)
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
	case a == vulnrecord.First || b == vulnrecord.Infinity:
		return -1, nil
	case b == vulnrecord.First || a == vulnrecord.Infinity:
		return 1, nil
	}
	return compare(a, b)
}

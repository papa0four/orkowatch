// internal/cvss/cvss.go

// Package cvss computes a CVSS v3.1 or v3.0 base score from a vector string and maps
// a score to its qualitative severity band, following the equations in the
// FIRST CVSS v3.1 specification. The registry's baselines are CVSS v4.0 and are
// scored by internal/cvss/v4; this package remains for the v3.x scores NVD
// publishes for a CVE, which the matching of software to NVD's CVEs is to
// check against their vectors, and for the severity bands both versions share.
//
// Only the base metrics are supported. A vector that carries temporal or
// environmental metrics is refused rather than scored as though it did not.
package cvss

import (
	"fmt"
	"math"
	"strings"

	"github.com/papa0four/orkowatch/internal/security/finding"
)

// The constants of the base score equations, as the specification defines
// them in section 7.1.
const (
	version    = "CVSS:3.1"
	versionOld = "CVSS:3.0"

	unchangedImpactScale = 6.42
	changedImpactScale   = 7.52
	changedImpactOffset  = 0.029
	changedImpactPenalty = 3.25
	changedPenaltyOffset = 0.02
	changedPenaltyPower  = 15
	exploitabilityScale  = 8.22
	changedScopeFactor   = 1.08
	maxScore             = 10.0

	// roundScale and roundStep are the integer arithmetic of the
	// specification's Roundup function, which avoids the floating point
	// error that rounding a decimal up directly would introduce. tenths turns
	// the result back into a score with one decimal.
	roundScale = 100000
	roundStep  = 10000
	tenths     = 10.0

	// The score at which each severity band starts, from the specification's
	// qualitative severity rating scale.
	mediumFloor   = 4.0
	highFloor     = 7.0
	criticalFloor = 9.0

	scopeChanged = 'C'
)

type (
	// Vector is a parsed CVSS v3.1 or v3.0 base vector, each metric held as
	// the letter it is written with, and the version it states.
	Vector struct {
		version                                                                                            string
		attackVector, complexity, privileges, interaction, scope, confidentiality, integrity, availability byte
	}

	// metric is one base metric: its abbreviation, the values it may take,
	// and where the parsed value is kept.
	metric struct {
		key    string
		values string
		set    func(v *Vector, value byte)
	}
)

var (
	// metrics lists the eight base metrics in the order the specification
	// gives them. A vector must state each exactly once.
	metrics = []metric{
		{"AV", "NALP", func(v *Vector, b byte) { v.attackVector = b }},
		{"AC", "LH", func(v *Vector, b byte) { v.complexity = b }},
		{"PR", "NLH", func(v *Vector, b byte) { v.privileges = b }},
		{"UI", "NR", func(v *Vector, b byte) { v.interaction = b }},
		{"S", "UC", func(v *Vector, b byte) { v.scope = b }},
		{"C", "NLH", func(v *Vector, b byte) { v.confidentiality = b }},
		{"I", "NLH", func(v *Vector, b byte) { v.integrity = b }},
		{"A", "NLH", func(v *Vector, b byte) { v.availability = b }},
	}

	// Metric weights from the specification, keyed by the metric's letter.
	attackVectorWeight = map[byte]float64{'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2}
	complexityWeight   = map[byte]float64{'L': 0.77, 'H': 0.44}
	interactionWeight  = map[byte]float64{'N': 0.85, 'R': 0.62}
	impactWeight       = map[byte]float64{'H': 0.56, 'L': 0.22, 'N': 0}

	// The privileges required weight depends on whether the scope changes.
	privilegesUnchangedWeight = map[byte]float64{'N': 0.85, 'L': 0.62, 'H': 0.27}
	privilegesChangedWeight   = map[byte]float64{'N': 0.85, 'L': 0.68, 'H': 0.5}
)

// Parse reads a CVSS v3.1 base vector such as
// "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", or a v3.0 one, which has
// the same metrics and values. It refuses a vector of another version, one
// that omits or repeats a metric, one with a value the metric does not
// allow, and one carrying a metric outside the base set.
//
// A v3.0 vector is scored with the v3.1 base equations. FIRST's v3.1 user
// guide says v3.1 was made "without introducing new metrics or metric
// values, and without making major changes to existing formulas", that its
// restructuring of the formulas is "purely clarifications and do not alter
// the scoring", and that the rounding function "is now defined more
// precisely"; the scores it names as changed are Temporal and Environmental.
func Parse(vector string) (Vector, error) {
	var v Vector
	parts := strings.Split(vector, "/")
	if parts[0] != version && parts[0] != versionOld {
		return v, fmt.Errorf("%q does not begin with %s or %s", vector, version, versionOld)
	}
	v.version = strings.TrimPrefix(parts[0], "CVSS:")

	seen := make(map[string]bool, len(metrics))
	for _, part := range parts[1:] {
		key, value, ok := strings.Cut(part, ":")
		if !ok || len(value) != 1 {
			return v, fmt.Errorf("%q: %q is not a metric written KEY:V", vector, part)
		}
		m, known := lookup(key)
		switch {
		case !known:
			return v, fmt.Errorf("%q: %s is not a base metric", vector, key)
		case seen[key]:
			return v, fmt.Errorf("%q: %s is stated twice", vector, key)
		case !strings.Contains(m.values, value):
			return v, fmt.Errorf("%q: %s:%s is not a value %s allows (%s)", vector, key, value, key, m.values)
		}
		seen[key] = true
		m.set(&v, value[0])
	}

	for _, m := range metrics {
		if !seen[m.key] {
			return v, fmt.Errorf("%q does not state %s", vector, m.key)
		}
	}
	return v, nil
}

// Version is the version the vector states, 3.1 or 3.0.
func (v Vector) Version() string { return v.version }

func lookup(key string) (metric, bool) {
	for _, m := range metrics {
		if m.key == key {
			return m, true
		}
	}
	return metric{}, false
}

// BaseScore returns the base score the vector's metrics give, from 0.0 to
// 10.0 with one decimal.
func (v Vector) BaseScore() float64 {
	changed := v.scope == scopeChanged

	iss := 1 - (1-impactWeight[v.confidentiality])*(1-impactWeight[v.integrity])*(1-impactWeight[v.availability])
	var impact float64
	if changed {
		impact = changedImpactScale*(iss-changedImpactOffset) -
			changedImpactPenalty*math.Pow(iss-changedPenaltyOffset, changedPenaltyPower)
	} else {
		impact = unchangedImpactScale * iss
	}
	if impact <= 0 {
		return 0
	}

	privileges := privilegesUnchangedWeight[v.privileges]
	if changed {
		privileges = privilegesChangedWeight[v.privileges]
	}
	exploitability := exploitabilityScale * attackVectorWeight[v.attackVector] * complexityWeight[v.complexity] *
		privileges * interactionWeight[v.interaction]

	total := impact + exploitability
	if changed {
		total *= changedScopeFactor
	}
	return roundUp(math.Min(total, maxScore))
}

// roundUp is the specification's Roundup: the smallest number with one decimal
// that is not less than x, computed in integers.
func roundUp(x float64) float64 {
	n := int(math.Round(x * roundScale))
	if n%roundStep == 0 {
		return float64(n) / roundScale
	}
	return float64(n/roundStep+1) / tenths
}

// Band returns the severity a score falls in: NONE for 0.0, LOW below 4.0,
// MEDIUM below 7.0, HIGH below 9.0, and CRITICAL from 9.0, as the
// specification's qualitative scale defines them.
func Band(score float64) string {
	switch {
	case score <= 0:
		return finding.SeverityNone
	case score < mediumFloor:
		return finding.SeverityLow
	case score < highFloor:
		return finding.SeverityMedium
	case score < criticalFloor:
		return finding.SeverityHigh
	default:
		return finding.SeverityCritical
	}
}

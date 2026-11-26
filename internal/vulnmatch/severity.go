// internal/vulnmatch/severity.go

package vulnmatch

import (
	"fmt"
	"slices"
	"strings"

	"github.com/papa0four/orkowatch/internal/cvss"
	v4 "github.com/papa0four/orkowatch/internal/cvss/v4"
	"github.com/papa0four/orkowatch/internal/security/finding"
	"github.com/papa0four/orkowatch/internal/vulnrecord"
)

// The levels of the one scale every severity is placed on, most severe first,
// and the place of a vulnerability whose records state nothing to place it
// by.
const (
	LevelCritical   = "critical"
	LevelHigh       = "high"
	LevelMedium     = "medium"
	LevelLow        = "low"
	LevelNegligible = "negligible"
	LevelNone       = "none stated"
)

// The bases a severity can have.
const (
	basisPriority = "Ubuntu priority"
	basisRating   = "advisory rating"

	// ubuntuScore is the type of the score that carries Ubuntu's priority.
	ubuntuScore = "Ubuntu"

	// cvssV3 and cvssV4 open the vectors that are scored.
	cvssV3 = "CVSS:3."
	cvssV4 = "CVSS:4.0"
)

// levels is the scale, most severe first.
var levels = []string{LevelCritical, LevelHigh, LevelMedium, LevelLow, LevelNegligible, LevelNone}

// ratingLevels places the ratings of an advisory on the scale: Red Hat's
// Important is the level below Critical, and its Moderate the one below that.
var ratingLevels = map[string]string{"Critical": LevelCritical, "Important": LevelHigh, "Moderate": LevelMedium, "Low": LevelLow}

// Severity is how severe a vulnerability is, and on what basis: the label as
// its source words it, the level of the scale that label is placed at, and
// where it came from, the distribution's own priority or its advisory's
// rating, or the CVSS version and base score a band was computed from. An
// advisory's rating is the advisory's, so each vulnerability it names
// carries it.
type Severity struct {
	Label string `json:"label,omitempty" yaml:"label,omitempty"`
	Level string `json:"level" yaml:"level"`
	Basis string `json:"basis,omitempty" yaml:"basis,omitempty"`
}

// Levels is the scale severities are placed on, most severe first, ending
// with the place of those with none stated.
func Levels() []string { return slices.Clone(levels) }

// Worse reports whether s is placed higher on the scale than other.
func (s Severity) Worse(other Severity) bool { return rank(s.Level) < rank(other.Level) }

// rank is the place of level on the scale, the most severe first.
func rank(level string) int {
	if at := slices.Index(levels, level); at >= 0 {
		return at
	}
	return len(levels)
}

// severityOf is the severity the records of one vulnerability give it. The
// distribution's own label is used where the records state one, the most
// severe of them: an Ubuntu priority, or the rating of an advisory. Where
// they state none, it is the band of the highest base score among the CVSS
// vectors they give, which the detail shows as computed. Where they give
// nothing that can be read, none is stated.
func severityOf(scores []vulnrecord.Score, ratings []string) Severity {
	best := Severity{Level: LevelNone}
	take := func(s Severity) {
		if rank(s.Level) < rank(best.Level) {
			best = s
		}
	}
	for _, s := range scores {
		if level := strings.ToLower(s.Score); s.Type == ubuntuScore && slices.Contains(levels[:len(levels)-1], level) {
			take(Severity{Label: level, Level: level, Basis: basisPriority})
		}
	}
	for _, rating := range ratings {
		if level, ok := ratingLevels[rating]; ok {
			take(Severity{Label: rating, Level: level, Basis: basisRating})
		}
	}
	if best.Level != LevelNone {
		return best
	}

	highest, basis := -1.0, ""
	for _, s := range scores {
		if score, version, ok := baseScore(s.Score); ok && score > highest {
			highest, basis = score, fmt.Sprintf("CVSS v%s base %.1f", version, score)
		}
	}
	if highest < 0 {
		return best
	}
	// A base score of 0.0, which the CVSS scale calls None, is placed at
	// the least level of this one.
	band := strings.ToLower(cvss.Band(highest))
	level := band
	if cvss.Band(highest) == finding.SeverityNone {
		level = LevelNegligible
	}
	return Severity{Label: band, Level: level, Basis: basis}
}

// baseScore scores a CVSS v3.1, v3.0, or v4.0 vector, and says which version
// it states. A vector of another version, or one that is not a base vector,
// is not scored.
func baseScore(vector string) (score float64, version string, ok bool) {
	switch {
	case strings.HasPrefix(vector, cvssV3):
		v, err := cvss.Parse(vector)
		if err != nil {
			return 0, "", false
		}
		return v.BaseScore(), v.Version(), true
	case strings.HasPrefix(vector, cvssV4):
		v, err := v4.Parse(vector)
		if err != nil {
			return 0, "", false
		}
		return v.Score(), "4.0", true
	}
	return 0, "", false
}

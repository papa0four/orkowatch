// internal/tone/tone_test.go

package tone

import (
	"fmt"
	"strings"
	"testing"

	"github.com/papa0four/orkowatch/internal/security/finding"
	"github.com/papa0four/orkowatch/internal/vulnmatch"
)

// Every word of both severity scales has its tone, and a vulnerability whose
// records state none, or a word owatch does not know, is plain.
func TestForSeverity(t *testing.T) {
	want := map[string]Tone{
		finding.SeverityCritical: Critical, finding.SeverityHigh: High, finding.SeverityMedium: Medium,
		finding.SeverityLow: Low, finding.SeverityNone: None,
		vulnmatch.LevelCritical: Critical, vulnmatch.LevelHigh: High, vulnmatch.LevelMedium: Medium,
		vulnmatch.LevelLow: Low, vulnmatch.LevelNegligible: Negligible, vulnmatch.LevelNone: Plain,
		"Important": Plain, "": Plain,
	}
	for name, tone := range want {
		if got := ForSeverity(name); got != tone {
			t.Errorf("%q is %d, want %d", name, got, tone)
		}
	}
	for _, name := range append(strings.Split(finding.SeverityNames(), ", "), vulnmatch.Levels()...) {
		if _, ok := want[name]; !ok {
			t.Errorf("the severity %q has no tone stated in this test", name)
		}
	}
}

// A pass is clean, a check that could not run or be read is an error, and a
// failure takes its tone from what it found.
func TestForResult(t *testing.T) {
	for r, want := range map[finding.Result]Tone{
		finding.ResultPass: None, finding.ResultError: Error, finding.ResultUnknown: Error,
		finding.ResultFail: Plain, finding.ResultNotApplicable: Plain,
	} {
		if got := ForResult(r); got != want {
			t.Errorf("%s is %d, want %d", r, got, want)
		}
	}
}

// No color stands for two meanings, every tone but Plain has one, and only
// what needs the operator now is bold.
func TestEachToneItsOwnColor(t *testing.T) {
	seen := map[string]Tone{}
	for tone := KnownExploited; tone <= Error; tone++ {
		c := tone.Color()
		if c == nil {
			t.Errorf("tone %d has no color", tone)
			continue
		}
		key := fmt.Sprint(c.RGBA())
		if other, ok := seen[key]; ok {
			t.Errorf("tones %d and %d share a color", other, tone)
		}
		seen[key] = tone
	}
	if Plain.Color() != nil || Plain.Render("text") != "text" {
		t.Error("plain text is colored")
	}
	for tone, want := range map[Tone]bool{KnownExploited: true, Critical: true, Error: true, High: false, None: false} {
		if got := tone.Style().GetBold(); got != want {
			t.Errorf("tone %d bold %v, want %v", tone, got, want)
		}
	}
}

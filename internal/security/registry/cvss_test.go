// internal/security/registry/cvss_test.go

package registry

import (
	"strings"
	"testing"

	"github.com/papa0four/orkowatch/internal/security/finding"
)

// A definition's baseline is a CVSS v4.0 vector of Base metrics, the score its
// vector computes and the band of that score, and the registry refuses a
// definition in which they disagree or which states a modified score.
func TestBaselineMustBeAConsistentV4BaseVector(t *testing.T) {
	const vector = "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
	good := FindingDefinition{Severity: "HIGH", CVSSScore: 8.4, CVSSVector: vector}
	if err := good.validateCVSS(); err != nil {
		t.Fatalf("a consistent baseline was refused: %v", err)
	}
	cases := map[string]struct {
		mutate  func(d *FindingDefinition)
		wantErr string
	}{
		"a v3.1 vector":                    {func(d *FindingDefinition) { d.CVSSVector = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N" }, "does not begin with CVSS:4.0"},
		"a score its vector does not give": {func(d *FindingDefinition) { d.CVSSScore = 8.7 }, "that its cvss_vector computes"},
		"a severity that is not the band":  {func(d *FindingDefinition) { d.Severity = "CRITICAL" }, "is not the HIGH band"},
		"a Threat metric":                  {func(d *FindingDefinition) { d.CVSSVector = vector + "/E:P" }, "CVSS-BT"},
		"an Environmental metric":          {func(d *FindingDefinition) { d.CVSSVector = vector + "/MAV:A" }, "CVSS-BE"},
		"a missing Base metric":            {func(d *FindingDefinition) { d.CVSSVector = "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N" }, "missing the Base metric"},
		"no vector":                        {func(d *FindingDefinition) { d.CVSSVector = "" }, "does not begin with"},
	}
	for name, c := range cases {
		d := good
		c.mutate(&d)
		if err := d.validateCVSS(); err == nil || !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("%s: error %v, want one containing %q", name, err, c.wantErr)
		}
	}
}

// Every shipped baseline is labelled as a CVSS-B v4.0 score with a link that
// opens FIRST's calculator on its vector.
func TestShippedBaselinesCarryTheCalculatorLink(t *testing.T) {
	for label, d := range allDefinitions() {
		f := d.Finding()
		want := "https://www.first.org/cvss/calculator/4.0#" + d.CVSSVector
		if f.CVSS == nil || f.CVSS.CalculatorURL != want {
			t.Errorf("%s: calculator link %v, want %s", label, f.CVSS, want)
		}
		if f.CVSS != nil && f.CVSS.Severity != d.Severity {
			t.Errorf("%s: severity %s differs from the definition's %s", label, f.CVSS.Severity, d.Severity)
		}
		if d.Result == finding.ResultFail && f.CVSS != nil && f.CVSS.BaseScore <= 0 {
			t.Errorf("%s: a finding that can fail has a baseline of %.1f", label, f.CVSS.BaseScore)
		}
	}
}

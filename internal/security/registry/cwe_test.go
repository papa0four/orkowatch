// internal/security/registry/cwe_test.go

package registry

import (
	"strings"
	"testing"

	"github.com/papa0four/orkowatch/internal/security/finding"
)

// A definition names a weakness in the bundled dataset or says why none fits,
// never both and never neither when it can fail.
func TestDefinitionStatesItsWeakness(t *testing.T) {
	cases := map[string]struct {
		def     FindingDefinition
		wantErr string
	}{
		"a weakness in the dataset":  {def: FindingDefinition{Result: finding.ResultFail, CWE: "CWE-732"}},
		"no weakness, with a reason": {def: FindingDefinition{Result: finding.ResultFail, NoWeakness: "No entry describes this."}},
		"cannot fail, names neither": {def: FindingDefinition{Result: finding.ResultNotApplicable}},
		"names both":                 {def: FindingDefinition{Result: finding.ResultFail, CWE: "CWE-732", NoWeakness: "x"}, wantErr: "also says no weakness"},
		"can fail, names neither":    {def: FindingDefinition{Result: finding.ResultFail}, wantErr: "does not say why"},
		"not in the dataset":         {def: FindingDefinition{Result: finding.ResultFail, CWE: "CWE-284"}, wantErr: "not in the bundled CWE dataset"},
		"malformed identifier":       {def: FindingDefinition{Result: finding.ResultFail, CWE: "284"}, wantErr: "invalid CWE identifier"},
		"a blank reason":             {def: FindingDefinition{Result: finding.ResultFail, NoWeakness: "  "}, wantErr: "does not say why"},
	}
	for name, c := range cases {
		_, err := c.def.validateWeakness()
		switch {
		case c.wantErr == "" && err != nil:
			t.Errorf("%s: refused: %v", name, err)
		case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
			t.Errorf("%s: error %v, want one containing %q", name, err, c.wantErr)
		}
	}
}

// The dataset refuses a weakness MITRE advises against mapping to.
func TestDatasetRefusesDiscouragedWeakness(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("a Discouraged weakness loaded")
		}
	}()
	mustLoadWeaknesses([]byte(`version: "5.0"
verified: "2026-11-15"
weaknesses:
  "CWE-284":
    name: "Improper Access Control"
    abstraction: "Pillar"
    usage: "Discouraged"
    description: "x"
`))
}

// Every shipped finding carries its weakness's name from the dataset, or the
// reason none applies, and a CVSS score labelled as the baseline it is.
func TestShippedFindingsCarryWeaknessAndLabelledCVSS(t *testing.T) {
	for label, d := range allDefinitions() {
		f := d.Finding()
		switch {
		case d.Result == finding.ResultNotApplicable:
		case d.CWE != "" && (f.Weakness == nil || f.Weakness.Name == "" || f.Weakness.Description == ""):
			t.Errorf("%s: names %s but carries no weakness", label, d.CWE)
		case d.CWE == "" && f.NoWeakness == "":
			t.Errorf("%s: carries neither a weakness nor a reason", label)
		}
		if f.CVSS == nil || f.CVSS.Nomenclature != "CVSS-B" || f.CVSS.Version != "3.1" || f.CVSS.Source != "registry" || f.CVSS.BaseScore != d.CVSSScore {
			t.Errorf("%s: CVSS %+v is not the registry's labelled baseline", label, f.CVSS)
		}
	}
}

// A weakness MITRE discourages is not one a definition maps to.
func TestNoDefinitionMapsToADiscouragedWeakness(t *testing.T) {
	for label, d := range allDefinitions() {
		if w := d.weakness(); w != nil && !cweUsable[w.Usage] {
			t.Errorf("%s maps to %s, which MITRE marks %s", label, w.ID, w.Usage)
		}
	}
}

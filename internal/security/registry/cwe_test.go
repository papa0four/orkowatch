// internal/security/registry/cwe_test.go

package registry

import (
	"strings"
	"testing"

	"github.com/papa0four/orkowatch/internal/security/finding"
)

// A definition names a weakness MITRE allows, or says why none fits, never both
// and never neither when it can fail.
func TestDefinitionStatesItsWeakness(t *testing.T) {
	cases := map[string]struct {
		def     FindingDefinition
		wantErr string
	}{
		"a weakness MITRE allows":    {def: FindingDefinition{Result: finding.ResultFail, CWE: "CWE-732"}},
		"no weakness, with a reason": {def: FindingDefinition{Result: finding.ResultFail, NoWeakness: "No entry describes this."}},
		"cannot fail, names neither": {def: FindingDefinition{Result: finding.ResultNotApplicable}},
		"names both":                 {def: FindingDefinition{Result: finding.ResultFail, CWE: "CWE-732", NoWeakness: "x"}, wantErr: "also says no weakness"},
		"can fail, names neither":    {def: FindingDefinition{Result: finding.ResultFail}, wantErr: "does not say why"},
		"a blank reason":             {def: FindingDefinition{Result: finding.ResultFail, NoWeakness: "  "}, wantErr: "does not say why"},
		"malformed identifier":       {def: FindingDefinition{Result: finding.ResultFail, CWE: "284"}, wantErr: "invalid CWE identifier"},
		"not in the catalog":         {def: FindingDefinition{Result: finding.ResultFail, CWE: "CWE-9999999"}, wantErr: "not a weakness in the bundled CWE catalog"},
		"MITRE discourages it":       {def: FindingDefinition{Result: finding.ResultFail, CWE: "CWE-284"}, wantErr: "Discouraged for mapping"},
		"allowed but not described":  {def: FindingDefinition{Result: finding.ResultFail, CWE: "CWE-79"}, wantErr: "no description"},
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

// Every weakness MITRE marks Discouraged or Prohibited is refused when a
// definition names it, whichever it is.
func TestEveryUnusableWeaknessIsRefused(t *testing.T) {
	var refused int
	for id, rec := range weaknesses {
		if cweUsable[rec.usage] {
			continue
		}
		refused++
		if _, err := (FindingDefinition{Result: finding.ResultFail, CWE: id}).validateWeakness(); err == nil {
			t.Errorf("%s, which MITRE marks %s, was accepted", id, rec.usage)
		}
	}
	if refused == 0 {
		t.Fatal("the catalog holds no weakness MITRE marks unusable")
	}
}

// The catalog holds MITRE's weaknesses with their usage, including the ones
// MITRE discourages or prohibits, so a mapping to one is recognised and refused
// and not mistaken for a typo. Groupings such as CWE-16 are not weaknesses and
// are absent.
func TestCatalogCarriesMITREsUsage(t *testing.T) {
	if len(weaknesses) < 900 {
		t.Fatalf("the bundled catalog holds %d weaknesses", len(weaknesses))
	}
	for id, want := range map[finding.CWE]string{"CWE-284": "Discouraged", "CWE-269": "Discouraged", "CWE-287": "Discouraged", "CWE-732": "Allowed-with-Review", "CWE-266": "Allowed"} {
		if got := weaknesses[id].usage; got != want {
			t.Errorf("%s has usage %q, want %q", id, got, want)
		}
	}
	if _, ok := weaknesses["CWE-16"]; ok {
		t.Error("CWE-16, a grouping, is in the catalog of weaknesses")
	}
	// A child names its parent, so a mapping can be walked up or down.
	if parents := weaknesses["CWE-266"].parents; len(parents) == 0 || parents[0] != "CWE-269" {
		t.Errorf("CWE-266 has parents %v, want CWE-269", parents)
	}
}

// A damaged catalog stops startup: an unknown usage, a parent the catalog lacks
// and a cycle are each refused.
func TestCatalogLoaderRefusesDamage(t *testing.T) {
	const head = "version: \"5.0\"\nverified: \"2026-11-15\"\nweaknesses:\n"
	entry := func(id, usage, parents string) string {
		return "  \"" + id + "\":\n    name: \"n\"\n    abstraction: \"Base\"\n    usage: \"" + usage + "\"\n    parents: [" + parents + "]\n"
	}
	cases := map[string]string{
		"an unknown usage":   head + entry("CWE-1", "Maybe", ""),
		"a missing parent":   head + entry("CWE-1", "Allowed", `"CWE-2"`),
		"a cycle":            head + entry("CWE-1", "Allowed", `"CWE-2"`) + entry("CWE-2", "Allowed", `"CWE-1"`),
		"an unknown field":   head + entry("CWE-1", "Allowed", "") + "    colour: red\n",
		"no version":         "weaknesses:\n" + entry("CWE-1", "Allowed", ""),
		"a malformed id":     head + entry("1", "Allowed", ""),
		"an unknown kind":    strings.Replace(head+entry("CWE-1", "Allowed", ""), `"Base"`, `"Galaxy"`, 1),
		"a parent of itself": head + entry("CWE-1", "Allowed", `"CWE-1"`),
	}
	for name, data := range cases {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s was accepted", name)
				}
			}()
			mustLoadWeaknesses([]byte(data))
		}()
	}
}

// Every shipped finding carries its weakness's name and MITRE's description
// from the catalog, or the reason none applies, and a CVSS score labelled as
// the baseline it is.
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

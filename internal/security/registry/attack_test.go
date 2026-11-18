// internal/security/registry/attack_test.go

package registry

import (
	"strings"
	"testing"

	"github.com/papa0four/orkowatch/internal/security/finding"
)

// A bundled technique is cited by a definition or reserved; one that is
// neither, or cited and still reserved, is refused.
func TestTechniqueUse(t *testing.T) {
	known := map[string]finding.Technique{"T1000": {ID: "T1000"}, "T2000": {ID: "T2000"}}
	citing := map[FindingKey]FindingDefinition{"x.cites": {AttackTechniques: []AttackLink{{ID: "T1000", Basis: []string{"b"}}}}}

	cases := map[string]struct {
		reserved map[string]bool
		want     string
	}{
		"cited, and uncited but reserved": {reserved: map[string]bool{"T2000": true}},
		"neither cited nor reserved":      {want: "none reserves: T2000"},
		"cited and still reserved":        {reserved: map[string]bool{"T1000": true, "T2000": true}, want: "already references: T1000"},
	}
	for name, c := range cases {
		err := techniqueUse(known, c.reserved, citing)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: refused: %v", name, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: got %v, want an error containing %q", name, err, c.want)
		}
	}
}

// The bundled dataset reserves exactly the techniques kept for the directory
// client rules, and the loader reads the mark.
func TestReservedTechniques(t *testing.T) {
	if len(reservedTechniques) != 2 || !reservedTechniques["T1003.005"] || !reservedTechniques["T1558.005"] {
		t.Errorf("the bundled dataset reserves %v", reservedTechniques)
	}
	_, reserved := mustLoadTechniques([]byte("version: \"20.1\"\nmitigations:\n  M1000: \"m\"\ntechniques:\n  T1000:\n    name: \"t\"\n    tactics: [\"x\"]\n    mitigations: [\"M1000\"]\n    reserved: true\n"))
	if !reserved["T1000"] {
		t.Errorf("a reserved technique was not read as reserved: %v", reserved)
	}
}

// internal/security/registry/attack_test.go

package registry

import (
	"strings"
	"testing"

	"github.com/papa0four/orkowatch/internal/security/finding"
)

// A bundled technique no definition cites is refused.
func TestTechniqueUse(t *testing.T) {
	citing := map[FindingKey]FindingDefinition{"x.cites": {AttackTechniques: []AttackLink{{ID: "T1000", Basis: []string{"b"}}}}}

	if err := techniqueUse(map[string]finding.Technique{"T1000": {ID: "T1000"}}, citing); err != nil {
		t.Errorf("every technique cited: refused: %v", err)
	}
	err := techniqueUse(map[string]finding.Technique{"T1000": {ID: "T1000"}, "T2000": {ID: "T2000"}}, citing)
	if err == nil || !strings.Contains(err.Error(), "no definition references: T2000") {
		t.Errorf("one technique uncited: got %v", err)
	}
}

// A technique cannot be kept without a definition citing it: the loader has no
// mark for one, and refuses a field it does not know.
func TestNoTechniqueIsReserved(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("a technique marked reserved was loaded")
		}
	}()
	mustLoadTechniques([]byte("version: \"20.1\"\nmitigations:\n  M1000: \"m\"\ntechniques:\n  T1000:\n    name: \"t\"\n    tactics: [\"x\"]\n    mitigations: [\"M1000\"]\n    reserved: true\n"))
}

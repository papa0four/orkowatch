// internal/security/registry/attack_test.go

package registry

import (
	"strings"
	"testing"

	"github.com/papa0four/orkowatch/internal/security/finding"
)

// A bundled technique is cited by a definition or kept for a named issue; one
// that is neither, or cited and still kept, is refused.
func TestTechniqueUse(t *testing.T) {
	known := map[string]finding.Technique{"T1000": {ID: "T1000"}, "T2000": {ID: "T2000"}}
	citing := map[FindingKey]FindingDefinition{"x.cites": {AttackTechniques: []AttackLink{{ID: "T1000", Basis: []string{"b"}}}}}

	cases := map[string]struct {
		consumers map[string]string
		want      string
	}{
		"cited and kept for an issue": {consumers: map[string]string{"T2000": "#186"}},
		"neither cited nor kept":      {want: "no issue is named to: T2000"},
		"cited and still kept":        {consumers: map[string]string{"T1000": "#186", "T2000": "#186"}, want: "already references: T1000 (#186)"},
	}
	for name, c := range cases {
		err := techniqueUse(known, c.consumers, citing)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: refused: %v", name, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: got %v, want an error containing %q", name, err, c.want)
		}
	}
}

// A consumer is an issue reference, and only the techniques the bundled
// dataset keeps for #186 name one.
func TestTechniqueConsumers(t *testing.T) {
	defer func() {
		if r := recover(); r == nil || !strings.Contains(r.(string), "not an issue reference") {
			t.Errorf("a malformed consumer was accepted: %v", r)
		}
	}()
	for id, consumer := range techniqueConsumers {
		if id != "T1003.005" && id != "T1558.005" || consumer != "#186" {
			t.Errorf("%s is kept for %s", id, consumer)
		}
	}
	mustLoadTechniques([]byte("version: \"20.1\"\nmitigations:\n  M1000: \"m\"\ntechniques:\n  T1000:\n    name: \"t\"\n    tactics: [\"x\"]\n    mitigations: [\"M1000\"]\n    consumer: \"186\"\n"))
}

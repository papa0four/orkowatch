// internal/selection/checks_test.go

package selection

import "testing"

// The datasets module is named and coded as a status report file needs, and
// a mask of the modules all runs is coded as it always was.
func TestDatasetsModule(t *testing.T) {
	if got := Codes(ModuleDatasets); got != "m.d" {
		t.Errorf("Codes(ModuleDatasets) = %q, want m.d", got)
	}
	if mask, err := MaskFromNames([]string{NameDatasets}, CategoryModule); err != nil || mask != ModuleDatasets {
		t.Errorf("datasets resolves to %b, %v", mask, err)
	}
	if got := Codes(ModuleOS | ModuleSoftware | ModuleListeners | CheckFirewall | CheckSSH); got != "m.nos-c.fs" {
		t.Errorf("all's modules and two checks are coded %q, want m.nos-c.fs", got)
	}
}

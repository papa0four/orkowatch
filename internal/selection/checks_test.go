// internal/selection/checks_test.go

package selection

import (
	"strings"
	"testing"
)

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

// The names a category accepts are its canonical names and the flag names
// that differ, and every one resolves.
func TestAcceptedNames(t *testing.T) {
	want := []string{"firewall", "fwall", "permissions", "fperms", "ssh", "users"}
	got := AcceptedNames(CategoryCheck)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("AcceptedNames(CategoryCheck) = %v, want %v", got, want)
	}
	for _, category := range []CheckCategory{CategoryCheck, CategoryModule} {
		if _, err := MaskFromNames(AcceptedNames(category), category); err != nil {
			t.Errorf("%s: %v", category, err)
		}
	}
}

// A name is read without the spaces around it, as a list quoted with a space
// after each comma gives it, and a name of only spaces is still refused.
func TestMaskFromNamesTrimsSpaces(t *testing.T) {
	if mask, err := MaskFromNames([]string{"firewall", " permissions"}, CategoryCheck); err != nil || mask != CheckFirewall|CheckPerms {
		t.Errorf("firewall and \" permissions\" resolve to %b, %v", mask, err)
	}
	if mask, err := MaskFromNames([]string{" audit ", "software"}, CategoryModule); err != nil || mask != ModuleAudit|ModuleSoftware {
		t.Errorf("\" audit \" and software resolve to %b, %v", mask, err)
	}
	if _, err := MaskFromNames([]string{"firewall", "  "}, CategoryCheck); err == nil {
		t.Error("a name of only spaces was accepted")
	}
}

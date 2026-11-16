// cmd/commands/security/browse_test.go

package security

import (
	"testing"

	"github.com/papa0four/orkowatch/internal/security/finding"
	"github.com/papa0four/orkowatch/internal/tui"
)

// A run of one module opens on what it produced; the audit, several modules or
// all of them open on the findings.
func TestLandingTab(t *testing.T) {
	ran := func(name string) ModuleNote { return ModuleNote{Name: name, Result: finding.ResultInformational} }
	skipped := func(name string) ModuleNote { return ModuleNote{Name: name, Result: finding.ResultNotSelected} }
	cases := []struct {
		name    string
		modules []ModuleNote
		want    string
	}{
		{"audit command, no module record", nil, tui.TabFindings},
		{"osinfo alone", []ModuleNote{ran("osinfo")}, tui.TabSystem},
		{"software alone", []ModuleNote{ran("software")}, tui.TabSoftware},
		{"all with audit and software skipped", []ModuleNote{ran("osinfo"), skipped("software"), skipped("audit")}, tui.TabSystem},
		{"all with osinfo and audit skipped", []ModuleNote{skipped("osinfo"), ran("software"), skipped("audit")}, tui.TabSoftware},
		{"all with osinfo and software skipped", []ModuleNote{skipped("osinfo"), skipped("software"), ran("audit")}, tui.TabFindings},
		{"all", []ModuleNote{ran("osinfo"), ran("software"), ran("audit")}, tui.TabFindings},
		{"all with audit skipped", []ModuleNote{ran("osinfo"), ran("software"), skipped("audit")}, tui.TabFindings},
	}
	for _, c := range cases {
		if got := landingTab(c.modules); got != c.want {
			t.Errorf("%s: landed on %q, want %q", c.name, got, c.want)
		}
	}
}

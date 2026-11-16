// cmd/commands/security/browse_test.go

package security

import (
	"strings"
	"testing"

	"github.com/papa0four/orkowatch/internal/security/audit"
	"github.com/papa0four/orkowatch/internal/security/finding"
	"github.com/papa0four/orkowatch/internal/tui"
)

// A run opens on the findings when the audit ran, and otherwise on the first
// module that did.
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
		{"all with audit skipped", []ModuleNote{ran("osinfo"), ran("software"), skipped("audit")}, tui.TabSystem},
		{"all with osinfo skipped, audit absent", []ModuleNote{skipped("osinfo"), ran("software"), skipped("audit")}, tui.TabSoftware},
		{"osinfo and audit", []ModuleNote{ran("osinfo"), skipped("software"), ran("audit")}, tui.TabFindings},
		{"module that ran and failed", []ModuleNote{{Name: "software", Result: finding.ResultError}, skipped("osinfo"), skipped("audit")}, tui.TabSoftware},
	}
	for _, c := range cases {
		if got := landingTab(c.modules); got != c.want {
			t.Errorf("%s: landed on %q, want %q", c.name, got, c.want)
		}
	}
}

// A technique's record names each finding that made it available: its
// severity and title, the rule that failed, what it found and the evidence.
func TestAttackTabTracesTechniqueToFinding(t *testing.T) {
	var evidence []finding.Evidence
	for _, who := range []string{"alice", "bob", "carol", "dave"} {
		evidence = append(evidence, finding.Evidence{Kind: "account", Subject: who})
	}
	view := &audit.View{Results: []audit.CheckView{{Conditions: []audit.ConditionView{{
		Key: "users.no_password_required", Result: finding.ResultFail, Reason: "blank password permitted",
		Evidence: evidence,
		Finding: &audit.FindingView{Title: "Account may have a blank password", Severity: "HIGH",
			Attack: []finding.Technique{{ID: "T1078.003", Name: "Local Accounts", Tactics: []string{"Persistence"}}}},
	}}}}}
	tab, ok := attackTab(view)
	if !ok || len(tab.Records) != 1 {
		t.Fatalf("no technique record: ok=%v tab=%+v", ok, tab)
	}
	var shown string
	for _, f := range tab.Records[0].Fields {
		if strings.HasPrefix(f.Label, "triggered by") {
			shown = f.Value
		}
	}
	for _, want := range []string{"HIGH  Account may have a blank password", "rule: users.no_password_required",
		"found: blank password permitted", "alice", "and 1 more evidence entries"} {
		if !strings.Contains(shown, want) {
			t.Errorf("the triggering finding is missing %q:\n%s", want, shown)
		}
	}
	if strings.Contains(shown, "dave") {
		t.Errorf("a fourth evidence entry is listed, not counted:\n%s", shown)
	}
}

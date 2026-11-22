// cmd/commands/security/browse_test.go

package security

import (
	"strings"
	"testing"

	"github.com/papa0four/orkowatch/internal/security/audit"
	"github.com/papa0four/orkowatch/internal/security/finding"
	"github.com/papa0four/orkowatch/internal/softwarelist"
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

// A technique's record says why each finding is associated with it.
func TestAttackTabStatesTheBasis(t *testing.T) {
	view := &audit.View{Results: []audit.CheckView{{Conditions: []audit.ConditionView{{
		Key: "firewall.ufw_inactive", Result: finding.ResultFail,
		Finding: &audit.FindingView{Title: "Firewall is inactive", Severity: "HIGH",
			Attack: []finding.Technique{{ID: "T1686", Name: "Disable or Modify System Firewall",
				Basis: []string{"CWE-284 relates to CAPEC-1, which CAPEC 3.9 maps to this technique"}}}},
	}}}}}
	tab, ok := attackTab(view)
	if !ok {
		t.Fatal("no technique record")
	}
	var shown string
	for _, f := range tab.Records[0].Fields {
		if strings.HasPrefix(f.Label, "triggered by") {
			shown = f.Value
		}
	}
	if !strings.Contains(shown, "associated because: CWE-284 relates to CAPEC-1") {
		t.Errorf("the basis is not shown:\n%s", shown)
	}
}

// The browser's finding detail carries the weakness with MITRE's description
// and the labelled CVSS, or the reason no weakness applies.
func TestBrowserItemCarriesWeaknessAndCVSS(t *testing.T) {
	cond := audit.ConditionView{Key: "permissions.world_writable_file", Result: finding.ResultFail,
		Finding: &audit.FindingView{Title: "World-writable file", Severity: "HIGH",
			Weakness: &finding.Weakness{ID: "CWE-732", Name: "Incorrect Permission Assignment for Critical Resource",
				Description: "The product specifies permissions for a security-critical resource in a way that allows it to be read or modified by unintended actors.",
				Usage:       "Allowed-with-Review", URL: "https://cwe.mitre.org/data/definitions/732.html"},
			CVSS: &finding.CVSSScore{Version: "4.0", Vector: "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N", Score: 8.4, Severity: "HIGH",
				Source: "registry", Nomenclature: "CVSS-B", Basis: "baseline for the condition, not measured on this host"}}}
	item := browserItem(cond)
	for _, want := range []string{"CWE-732 Incorrect Permission Assignment", "Allowed-with-Review"} {
		if !strings.Contains(item.Weakness, want) {
			t.Errorf("weakness %q lacks %q", item.Weakness, want)
		}
	}
	if !strings.Contains(item.WeaknessAbout, "unintended actors") || !strings.Contains(item.WeaknessAbout, "cwe.mitre.org") {
		t.Errorf("weakness detail %q lacks MITRE's description or the link", item.WeaknessAbout)
	}
	if !strings.Contains(item.CVSS, "8.4 HIGH") || !strings.Contains(item.CVSS, "CVSS-B v4.0") || !strings.Contains(item.CVSS, "not measured on this host") {
		t.Errorf("CVSS %q is not shown with its label", item.CVSS)
	}
	if !strings.Contains(item.HostCVSS, "no rule of this finding reads the host") || item.SeverityBasis != "the registry's rating for this rule" {
		t.Errorf("a finding with no rule shows host score %q and severity basis %q", item.HostCVSS, item.SeverityBasis)
	}

	cond.Finding.Host = &finding.HostScore{
		CVSS: &finding.CVSSScore{Version: "4.0", Vector: "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/MPR:H", Score: 6.9,
			Severity: "MEDIUM", Source: "host evidence", Nomenclature: "CVSS-BE", Basis: "Modified Base metrics derived from evidence recorded on this host"},
		Modified: []finding.ModifiedMetric{{Metric: "MPR", Value: "H", Fact: finding.Fact{Name: "reach", Value: "root-only"},
			Because: "only root can reach the file", Carried: 2, Subjects: 2}},
	}
	cond.Finding.Severity = "MEDIUM"
	item = browserItem(cond)
	for _, want := range []string{"6.9 MEDIUM  CVSS-BE v4.0", "MPR:H from reach root-only on 2 of 2 subjects: only root can reach the file"} {
		if !strings.Contains(item.HostCVSS, want) {
			t.Errorf("host score %q lacks %q", item.HostCVSS, want)
		}
	}
	if item.SeverityBasis != "the CVSS-BE severity on this host; the registry rates the rule HIGH" {
		t.Errorf("a modified finding's severity basis: %q", item.SeverityBasis)
	}
	cond.Finding.Host = nil
	cond.Finding.Severity = "HIGH"

	cond.Finding.Weakness = nil
	cond.Finding.NoWeakness = "No entry describes this."
	item = browserItem(cond)
	if item.Weakness != "none" || item.WeaknessAbout != "No entry describes this." {
		t.Errorf("a finding with no weakness shows %q / %q", item.Weakness, item.WeaknessAbout)
	}
}

// The Software tab shows what a package's manager states of it, and for an
// entry with a name and a version alone shows only those.
func TestSoftwareTabShowsWhatTheManagerStates(t *testing.T) {
	tab := softwareTab(softwarelist.SoftwareView{Packages: []softwarelist.SoftwareEntry{
		{Name: "bash", Version: "5.2.15-2+b13", Manager: softwarelist.ManagerDpkg, Architecture: "amd64", Source: "bash", SourceVersion: "5.2.15-2"},
		{Name: "Some Application", Version: "1.2"},
	}})
	if len(tab.Records) != 2 {
		t.Fatalf("%d records, want 2", len(tab.Records))
	}

	labels := func(r tui.Record) string {
		var out []string
		for _, f := range r.Fields {
			out = append(out, f.Label+"="+f.Value)
		}
		return strings.Join(out, "; ")
	}
	wantPackage := "name=bash; version=5.2.15-2+b13; architecture=amd64; package manager=dpkg; source package=bash; source version=5.2.15-2"
	if got := labels(tab.Records[0]); got != wantPackage {
		t.Errorf("a package's fields are %q, want %q", got, wantPackage)
	}
	if got := labels(tab.Records[1]); got != "name=Some Application; version=1.2" {
		t.Errorf("an application's fields are %q, want its name and version alone", got)
	}
}

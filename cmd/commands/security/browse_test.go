// cmd/commands/security/browse_test.go

package security

import (
	"slices"
	"strings"
	"testing"

	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/security/audit"
	"github.com/papa0four/orkowatch/internal/security/finding"
	"github.com/papa0four/orkowatch/internal/selection"
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
// and the labeled CVSS, or the reason no weakness applies.
func TestBrowserItemCarriesWeaknessAndCVSS(t *testing.T) {
	cond := audit.ConditionView{Key: "permissions.world_writable_file", Result: finding.ResultFail,
		Finding: &audit.FindingView{Title: "World-writable file", Severity: "HIGH",
			Weakness: &finding.Weakness{ID: "CWE-732", Name: "Incorrect Permission Assignment for Critical Resource",
				Description: "The product specifies permissions for a security-critical resource in a way that allows it to be read or modified by unintended actors.",
				Usage:       "Allowed-with-Review", URL: "https://cwe.mitre.org/data/definitions/732.html",
				Lineage: []finding.WeaknessAncestor{
					{ID: "CWE-284", Name: "Improper Access Control", Abstraction: "Pillar"},
					{ID: "CWE-285", Name: "Improper Authorization", Abstraction: "Class"},
				}},
			CVSS: &finding.CVSSScore{Version: "4.0", Vector: "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N", Score: 8.4, Severity: "HIGH",
				Source: "registry", Nomenclature: "CVSS-B", Basis: "baseline for the condition, not measured on this host"}}}
	item := browserItem(cond)
	for _, want := range []string{"CWE-732 Incorrect Permission Assignment", "Allowed-with-Review",
		"\nCWE-284 Improper Access Control (Pillar)\n> CWE-285 Improper Authorization (Class)\n> CWE-732 Incorrect Permission Assignment for Critical Resource"} {
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
	if item.ClassExploited != "" {
		t.Errorf("a finding whose class has no count shows %q", item.ClassExploited)
	}
	cond.Finding.KnownExploitedInClass = 3
	if item = browserItem(cond); item.ClassExploited != audit.ClassExploitedText(*cond.Finding) || !strings.Contains(item.ClassExploited, "3 vulnerabilities known to be exploited are of CWE-732") {
		t.Errorf("a finding whose class counts 3 shows %q", item.ClassExploited)
	}
	cond.Finding.KnownExploitedInClass = 0

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

// The summary names the data the counts of known-exploited vulnerabilities by
// weakness class were read from, or why they were not read, and nothing for
// an audit not given them.
func TestSummaryNamesTheCatalog(t *testing.T) {
	value := func(view audit.View) string {
		for _, line := range summaryLines(&view) {
			if line.Label == "known exploited" {
				return line.Value
			}
		}
		return ""
	}
	read := dataset.Use{Provenance: dataset.Provenance{ID: "kev", Version: "2026.11.21", DataDate: "2026-11-21", State: dataset.StateCurrent}}
	notRead := dataset.Use{Provenance: dataset.Provenance{ID: "kev"}, NotDone: "kev is not held"}
	for want, view := range map[string]audit.View{
		"kev, 2026.11.21, data of 2026-11-21, current": {KnownExploited: &read},
		"not read: kev is not held":                    {KnownExploited: &notRead},
		"":                                             {},
	} {
		if got := value(view); got != want {
			t.Errorf("the summary says %q, want %q", got, want)
		}
	}
}

// The Software tab shows what a package's manager states of it, and for an
// entry with a name and a version alone shows only those.
func TestSoftwareTabShowsWhatTheManagerStates(t *testing.T) {
	tab := softwareTab(softwarelist.SoftwareView{Packages: []softwarelist.SoftwareEntry{
		{Name: "bash", Version: "5.2.15-2+b13", Manager: softwarelist.ManagerDpkg, Architecture: "amd64", Source: "bash", SourceVersion: "5.2.15-2"},
		{Name: "Some Application", Version: "1.2"},
	}}, nil)
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

// A report that holds no datasets offers no Datasets tab, so every report but
// owatch data status's opens as it did; one that does offers it, and a run
// of that module alone opens on it.
func TestDatasetsTabOnlyWhenHeld(t *testing.T) {
	for _, src := range []BrowserSource{{Title: "audit"}, {Title: "all", Modules: []ModuleNote{{Name: selection.NameOS}}}} {
		for _, tab := range BrowserReport(src).Tabs {
			if tab.ID == tui.TabDatasets {
				t.Errorf("%s offers a Datasets tab", src.Title)
			}
		}
	}
	report := BrowserReport(BrowserSource{
		Datasets: &dataset.View{Store: "/store", Datasets: []dataset.Row{{Provenance: dataset.Provenance{ID: "kev", State: dataset.StateNotHeld}}}},
		Modules:  []ModuleNote{{Name: selection.NameDatasets, Result: finding.ResultInformational}},
	})
	if report.Start != tui.TabDatasets {
		t.Errorf("opens on %q, want the datasets", report.Start)
	}
	empty := datasetsTab(dataset.View{Store: "/store"})
	if len(empty.Records) != 0 || !strings.Contains(empty.Note, "/store holds none") {
		t.Errorf("an empty store gave %+v", empty)
	}
}

// What an elevated run installed from the operator's store is the first
// record, with the same sentences the text report prints.
func TestDatasetsTabSaysWhatWasInstalled(t *testing.T) {
	operator := &dataset.Operator{Store: "/home/a/store", Installed: []string{"kev"}, Refused: []dataset.Refusal{{ID: "epss", Reason: "it is a link"}}, Advice: "run import"}
	tab := datasetsTab(dataset.View{Store: "/store", Operator: operator, Datasets: []dataset.Row{{Provenance: dataset.Provenance{ID: "kev", State: dataset.StateCurrent}}}})
	if len(tab.Records) != 2 || tab.Records[0].Title != "from the operator" || tab.Records[1].Title != "kev" {
		t.Fatalf("records %+v, want the operator's ahead of the dataset's", tab.Records)
	}
	var got []string
	for _, f := range tab.Records[0].Fields {
		got = append(got, f.Value)
	}
	if !slices.Equal(got, operator.Lines()) {
		t.Errorf("the record says %q, want %q", got, operator.Lines())
	}
	if plain := datasetsTab(dataset.View{Store: "/store", Datasets: []dataset.Row{{Provenance: dataset.Provenance{ID: "kev", State: dataset.StateCurrent}}}}); len(plain.Records) != 1 {
		t.Errorf("with nothing from an operator: %+v", plain.Records)
	}
}

// A held dataset's record gives the date of its data and, after it, the
// version its source gives the data.
func TestDatasetsTabShowsTheVersion(t *testing.T) {
	tab := datasetsTab(dataset.View{Store: "/store", Datasets: []dataset.Row{
		{Provenance: dataset.Provenance{ID: "kev", State: dataset.StateCurrent, DataDate: "2026-11-23", Version: "2026.11.23"}},
	}})
	var got []string
	for _, f := range tab.Records[0].Fields {
		got = append(got, f.Label+"="+f.Value)
	}
	if want := "state=current; date of the data=2026-11-23; version=2026.11.23; store=/store"; strings.Join(got, "; ") != want {
		t.Errorf("the record's fields are %q, want %q", strings.Join(got, "; "), want)
	}
}

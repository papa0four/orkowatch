// cmd/commands/refresh_browser_test.go

package cmd

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/papa0four/orkowatch/cmd/commands/delivery"
	"github.com/papa0four/orkowatch/cmd/commands/held"
	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/dataset/datasettest"
	"github.com/papa0four/orkowatch/internal/security/audit"
	"github.com/papa0four/orkowatch/internal/selection"
	"github.com/papa0four/orkowatch/internal/tui"
)

// textOut is output flags resolved to the text format.
func textOut(t *testing.T) *delivery.Flags {
	t.Helper()
	cmd := &cobra.Command{Use: "probe"}
	out := delivery.Bind(cmd)
	if err := out.Resolve(cmd); err != nil {
		t.Fatal(err)
	}
	return out
}

// unmatched is a run on Debian whose inventory was not matched, its records
// not held, with the audit's counts read from no catalog.
func unmatched() *ScanResult {
	v := notDone("records", "records is not held; fetch it with owatch data refresh, or install it with owatch data import")
	return &ScanResult{
		Timestamp:     dataNow,
		OSInfo:        debian,
		Software:      installed("3.0.11-1"),
		Vulns:         v,
		Modules:       []moduleRun{softwareModule(v)},
		SecurityAudit: &audit.Result{},
	}
}

// browsing is the refresh of result's browser over a data command that
// fetches the test records into a store in a temporary directory.
func browsing(t *testing.T, result *ScanResult) (*liveRefresh, *served) {
	t.Helper()
	d, s, origins := refreshing(t, false, "")
	m, _, _ := matching(t)
	m.matched = []dataset.Dataset{testRecords{datasettest.Dataset{Name: "records", Applies: true, From: at("records")}}}
	origins.sizes["records"] = int64(len(datasettest.Content))
	d.known = m.matched
	d.run = func() *held.Run { return heldIn(s, m.matched...) }
	refresh := liveRefreshFor(d, m, heldIn(s, m.matched...), result, "owatch all", "", textOut(t))
	l, ok := refresh.(*liveRefresh)
	if !ok {
		t.Fatalf("no refresh for %+v", result.Vulns)
	}
	return l, origins
}

// A run whose inventory was matched against a dataset offers the refresh;
// one no dataset covers, or with no inventory matched, does not.
func TestLiveRefreshOffered(t *testing.T) {
	d, _, _ := refreshing(t, false, "")
	m, data, _ := matching(t)
	if liveRefreshFor(d, m, data, unmatched(), "owatch all", "", textOut(t)) == nil {
		t.Error("a run matched against records offers no refresh")
	}
	uncovered := unmatched()
	uncovered.Vulns = notDone("", "no dataset owatch knows covers this host's packages")
	for name, result := range map[string]*ScanResult{"no dataset covers it": uncovered, "no inventory matched": {}} {
		if liveRefreshFor(d, m, data, result, "owatch all", "", textOut(t)) != nil {
			t.Errorf("%s: a refresh is offered", name)
		}
	}
}

// The plan names each dataset to fetch with its download; the fetch brings
// them into the store, matches the inventory again, recounts the audit from
// the catalog, and gives the report matched again, which offers r again. The
// run's own result is left as it was.
func TestLiveRefreshMatchesAgain(t *testing.T) {
	result := unmatched()
	l, origins := browsing(t, result)
	lines, err := l.Plan(context.Background())
	if err != nil || len(lines) != 1 || lines[0] != "records: 39 B from https://data.example/records, allowed 10m0s" {
		t.Fatalf("plan %q, %v", lines, err)
	}
	var progress []string
	report, err := l.Fetch(context.Background(), func(line string) { progress = append(progress, line) })
	if err != nil || report.Refresh == nil || !strings.Contains(report.Text, "CVE-2026-0001") {
		t.Fatalf("fetch: %v, refresh %v, text\n%s", err, report.Refresh != nil, report.Text)
	}
	if !fetchedOnly(origins.fetched, "records") || len(progress) == 0 {
		t.Errorf("fetched %q, progress %q", origins.fetched, progress)
	}
	matched := l.result
	if matched.Vulns.NotDone != "" || len(matched.Vulns.Packages) != 1 || matched.Vulns.Packages[0].Vulnerabilities[0].ID != "CVE-2026-0001" {
		t.Errorf("matched again: %+v", matched.Vulns)
	}
	if len(matched.Modules) != 1 || !strings.Contains(matched.Modules[0].Reason, "matched against records") {
		t.Errorf("the software row is %+v", matched.Modules)
	}
	if matched.SecurityAudit.KnownExploited == nil || !strings.HasPrefix(matched.SecurityAudit.KnownExploited.NotDone, "kev is not held") {
		t.Errorf("the audit was not recounted: %+v", matched.SecurityAudit.KnownExploited)
	}
	if result.Vulns.NotDone == "" || result.SecurityAudit.KnownExploited != nil || !strings.Contains(result.Modules[0].Reason, "not done") {
		t.Errorf("the run's own result changed: %+v, %+v", result.Vulns, result.Modules)
	}
}

// A refresh that does not bring every dataset fails with what happened to
// each, and keeps the result it had.
func TestLiveRefreshFails(t *testing.T) {
	l, origins := browsing(t, unmatched())
	origins.fails["records"] = errors.New("https://data.example/records answered 404 Not Found")
	if _, err := l.Plan(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, err := l.Fetch(context.Background(), func(string) {})
	if err == nil || !strings.Contains(err.Error(), "1 of 1 dataset not refreshed") || !strings.Contains(err.Error(), "404 Not Found") {
		t.Errorf("a failed fetch gave %v", err)
	}
	if l.result.Vulns.NotDone == "" {
		t.Errorf("a failed refresh matched again: %+v", l.result.Vulns)
	}

	origins.fails["records"] = unreachable{}
	if _, err := l.Fetch(context.Background(), func(string) {}); err == nil || !strings.Contains(err.Error(), "owatch data import <directory> here") {
		t.Errorf("with no network the fetch gave %v", err)
	}
}

// Elevated, the refresh fetches nothing and builds no fetcher: it leaves the
// browser with what to run, the commands a run that does not hold its
// datasets prints, and then this command again.
func TestLiveRefreshElevated(t *testing.T) {
	l, _ := browsing(t, unmatched())
	l.data.elevated = func() bool { return true }
	l.data.fetcher = func() (fetcher, error) {
		t.Error("an elevated refresh asked for a fetcher")
		return nil, errors.New("not built")
	}
	_, err := l.Plan(context.Background())
	var leave tui.Leave
	if !errors.As(err, &leave) || !strings.HasPrefix(leave.Text, "Run owatch data refresh. ") || !strings.HasSuffix(leave.Text, "Then run this command again.") {
		t.Errorf("elevated: %v", err)
	}
}

// The software row a match records replaces the one an earlier match
// recorded, and is added where there was none.
func TestMatchSoftwareRecordsItsRow(t *testing.T) {
	m, data, _ := matching(t)
	result := &ScanResult{OSInfo: debian, Software: installed("3.0.11-1"), Modules: []moduleRun{
		{Name: selection.NameOS, Result: "informational"}, {Name: selection.NameSoftware, Result: "informational", Reason: "before"}}}
	matchSoftware(context.Background(), m, data, result)
	if len(result.Modules) != 2 || result.Modules[1].Reason == "before" || result.Vulns == nil {
		t.Errorf("modules %+v", result.Modules)
	}
	result.Modules = result.Modules[:1]
	matchSoftware(context.Background(), m, data, result)
	if len(result.Modules) != 2 || result.Modules[1].Name != selection.NameSoftware {
		t.Errorf("with no row before: %+v", result.Modules)
	}
}

// cmd/commands/refresh_browser_test.go

package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/papa0four/orkowatch/cmd/commands/delivery"
	"github.com/papa0four/orkowatch/cmd/commands/held"
	"github.com/papa0four/orkowatch/internal/dataset/datasettest"
	"github.com/papa0four/orkowatch/internal/dataset/store"
	"github.com/papa0four/orkowatch/internal/osfingerprint"
	"github.com/papa0four/orkowatch/internal/security/audit"
	"github.com/papa0four/orkowatch/internal/security/finding"
	"github.com/papa0four/orkowatch/internal/selection"
	"github.com/papa0four/orkowatch/internal/softwarelist"
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
func browsing(t *testing.T, result *ScanResult) (*browserRefresh, *liveRun, *served) {
	t.Helper()
	d, s, origins := refreshing(t, false, "")
	m, _, _ := matching(t)
	m.matched = []held.Source{testRecords{datasettest.Dataset{Name: "records", Applies: true, From: at("records")}}}
	origins.sizes["records"] = int64(len(datasettest.Content))
	d.known = held.Datasets(m.matched)
	d.run = func() *held.Run { return heldIn(s, held.Datasets(m.matched)...) }
	refresh, live := newLiveRefresh(d, m, heldIn(s, held.Datasets(m.matched)...), result, "owatch all", "", textOut(t))
	if refresh == nil {
		t.Fatalf("no refresh for %+v", result.Vulns)
	}
	return refresh, live, origins
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
	l, live, origins := browsing(t, result)
	lines, err := l.Plan(context.Background())
	if err != nil || len(lines) != 1 || lines[0] != "records: 39 B, allowed 10m0s" {
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
	matched := live.result
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
	l, live, origins := browsing(t, unmatched())
	origins.fails["records"] = errors.New("https://data.example/records answered 404 Not Found")
	if _, err := l.Plan(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, err := l.Fetch(context.Background(), func(string) {})
	if err == nil || !strings.Contains(err.Error(), "1 of 1 dataset not refreshed") || !strings.Contains(err.Error(), "404 Not Found") {
		t.Errorf("a failed fetch gave %v", err)
	}
	if live.result.Vulns.NotDone == "" {
		t.Errorf("a failed refresh matched again: %+v", live.result.Vulns)
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
	l, _, _ := browsing(t, unmatched())
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

// savedFile is an all report saved on a Debian host whose packages were
// matched against the test records, with the catalog not held, and one
// finding of CWE-306: written to a file in a temporary directory, with the
// data command and store a refresh of it reads, and the origins it fetches
// from.
func savedFile(t *testing.T, version string) (path string, d *dataCmd, m inventoryMatching, s store.Store, origins *served) {
	t.Helper()
	d, s, origins = refreshing(t, false, "")
	m, _, _ = matching(t)
	m.matched = []held.Source{testRecords{datasettest.Dataset{Name: "records", Applies: true, From: at("records")}}}
	origins.sizes["records"] = int64(len(datasettest.Content))
	d.known = held.Datasets(m.matched)
	d.host = func() (*osfingerprint.OSInfo, error) { return debian, nil }
	d.run = func() *held.Run { return heldIn(s, held.Datasets(m.matched)...) }

	datasettest.Put(t, s.Root(), datasettest.Dataset{Name: "records"}, datasettest.Content, dataNow.Add(-time.Hour), nil)
	v := m.run(context.Background(), heldIn(s, held.Datasets(m.matched)...), debian, installed("3.0.11-1"))
	v.Version = version
	view := softwarelist.View(installed("3.0.11-1"))
	all := allResult{
		Timestamp: "2026-11-25T12:00:00Z",
		Modules:   []moduleRun{softwareModule(v)},
		Software:  &view,
		Vulns:     v,
		Security: &audit.View{Results: []audit.CheckView{{Key: "ssh", Name: "SSH", Result: finding.ResultFail, Conditions: []audit.ConditionView{{
			Key: "ssh.a", Result: finding.ResultFail,
			Finding: &audit.FindingView{Title: "a finding", Severity: finding.SeverityHigh, Weakness: &finding.Weakness{ID: "CWE-306", Name: "a weakness"}},
		}}}}},
	}
	data, err := delivery.Encode(all, delivery.FormatJSON)
	if err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(t.TempDir(), "owatch-saved.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, d, m, s, origins
}

// openedRefresh is the refresh owatch browse offers on the saved report at
// path, or nil.
func openedRefresh(t *testing.T, path string, d *dataCmd, m inventoryMatching, s store.Store) tui.Refresher {
	t.Helper()
	data, err := os.ReadFile(path) // #nosec G304 -- a file the test wrote
	if err != nil {
		t.Fatal(err)
	}
	saved, err := readSaved(path, delivery.FormatJSON, data)
	if err != nil || !saved.isAll() {
		t.Fatalf("read %v, all %v", err, saved.isAll())
	}
	return savedRefreshFor(d, m, heldIn(s, held.Datasets(m.matched)...), path, saved.all(), delivery.FormatText)
}

// A saved report matched against this host's dataset and release is matched
// again after a refresh, from its saved inventory, with no system section to
// say which host it was: the catalog held since is read, the finding's class
// count recounted from it, and the banner says the screen was matched again
// and the file is unchanged, which it is, byte for byte.
func TestSavedRefreshMatchesAgain(t *testing.T) {
	path, d, m, s, origins := savedFile(t, "Debian:12")
	before, err := os.ReadFile(path) // #nosec G304 -- a file the test wrote
	if err != nil {
		t.Fatal(err)
	}
	datasettest.PutCatalog(t, s.Root(), dataNow.Add(-time.Hour), `{"cveID": "CVE-2026-0001", "dateAdded": "2026-11-20", "knownRansomwareCampaignUse": "Known", "cwes": ["CWE-306"]}`)

	refresh := openedRefresh(t, path, d, m, s)
	if refresh == nil {
		t.Fatal("a saved report of this host's release offers no refresh")
	}
	if lines, err := refresh.Plan(context.Background()); err != nil || len(lines) != 1 {
		t.Fatalf("plan %q, %v", lines, err)
	}
	report, err := refresh.Fetch(context.Background(), func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(report.Title, "owatch-saved.json, matched again ") || !strings.HasSuffix(report.Title, "; the file is unchanged") || report.Refresh == nil {
		t.Errorf("title %q, refresh %v", report.Title, report.Refresh != nil)
	}
	if !strings.Contains(report.Text, "1 vulnerability known to be exploited") || !fetchedOnly(origins.fetched, "records") {
		t.Errorf("fetched %q; the text does not mark the CVE known exploited:\n%s", origins.fetched, report.Text)
	}
	var recounted bool
	for _, item := range report.Items {
		recounted = recounted || strings.Contains(item.ClassExploited, "1 vulnerability known to be exploited")
	}
	if !recounted {
		t.Errorf("the finding was not recounted: %+v", report.Items)
	}
	if after, err := os.ReadFile(path); err != nil || !bytes.Equal(before, after) { // #nosec G304 -- a file the test wrote
		t.Errorf("the file changed: %v", err)
	}
}

// A saved report matched against another release fetches nothing and says
// where it can be matched again; one never matched, and a report with no
// inventory, offer no refresh.
func TestSavedRefreshOfAnotherRelease(t *testing.T) {
	path, d, m, s, origins := savedFile(t, "Debian:11")
	built := false
	d.fetcher = func() (fetcher, error) { built = true; return origins, nil }
	refresh := openedRefresh(t, path, d, m, s)
	if refresh == nil {
		t.Fatal("a matched report offers no refresh")
	}
	_, err := refresh.Plan(context.Background())
	if err == nil || err.Error() != "This report was matched against records Debian:11; this host's packages are matched against records Debian:12, so the report can be matched again only on a host of Debian:11: open it there with owatch browse" || built || len(origins.fetched) != 0 {
		t.Errorf("another release: %v, a fetcher built %v, fetched %q", err, built, origins.fetched)
	}

	unmatchedAll := allResult{Software: &softwarelist.SoftwareView{}, Vulns: notDone("records", "records is not held")}
	if savedRefreshFor(d, m, heldIn(s), path, unmatchedAll, delivery.FormatText) != nil {
		t.Error("a report never matched offers a refresh")
	}
	if savedRefreshFor(d, m, heldIn(s), path, allResult{Vulns: unmatchedAll.Vulns}, delivery.FormatText) != nil {
		t.Error("a report with no inventory offers a refresh")
	}
}

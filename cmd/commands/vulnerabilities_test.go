// cmd/commands/vulnerabilities_test.go

package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/papa0four/orkowatch/cmd/commands/delivery"
	"github.com/papa0four/orkowatch/cmd/commands/held"
	"github.com/papa0four/orkowatch/cmd/commands/security"
	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/dataset/datasettest"
	"github.com/papa0four/orkowatch/internal/dataset/epss"
	"github.com/papa0four/orkowatch/internal/dataset/store"
	"github.com/papa0four/orkowatch/internal/osfingerprint"
	"github.com/papa0four/orkowatch/internal/security/finding"
	"github.com/papa0four/orkowatch/internal/selection"
	"github.com/papa0four/orkowatch/internal/softwarelist"
	"github.com/papa0four/orkowatch/internal/tui"
	"github.com/papa0four/orkowatch/internal/vulnmatch"
	"github.com/papa0four/orkowatch/internal/vulnrecord"
)

// testRecords is the test dataset as a source of records for Debian hosts:
// its data checked as the test dataset's, and one record of openssl given.
type testRecords struct{ datasettest.Dataset }

func (testRecords) AppliesTo(host *osfingerprint.OSInfo) bool { return host.Platform == "debian" }
func (testRecords) Manager() string                           { return softwarelist.ManagerDpkg }

// Combining is how the test records combine, as a distribution's do.
func (testRecords) Combining() vulnrecord.Combining { return vulnrecord.FixClears }

// Release is the release the test records are of, the Version a match of
// them carries.
func (testRecords) Release(*osfingerprint.OSInfo) (string, error) { return "Debian:12", nil }

func (r testRecords) Records(data io.Reader, host *osfingerprint.OSInfo, each func(vulnrecord.Record) error) (dataset.Facts, error) {
	facts, err := r.Check(data, host)
	if err != nil {
		return facts, err
	}
	facts.Version = "Debian:12"
	return facts, each(vulnrecord.Record{ID: "DSA-1", CVEs: []string{"CVE-2026-0001"}, Modified: "2026-11-20T00:00:00Z",
		Affected: []vulnrecord.Affected{{Package: "openssl", Ecosystem: "Debian:12", Ranges: [][]vulnrecord.Bound{{{Kind: vulnrecord.From, Version: vulnrecord.First}, {Kind: vulnrecord.Before, Version: "3.0.15-1"}}}}}})
}

var debian = &osfingerprint.OSInfo{OS: "linux", Platform: "debian", PlatformVersion: "12"}

// matching is inventoryMatching that knows the test records, with a run's
// data over a store in a temporary directory, read at dataNow.
func matching(t *testing.T) (inventoryMatching, *held.Run, store.Store) {
	t.Helper()
	s := store.At(filepath.Join(t.TempDir(), "store"))
	records := testRecords{datasettest.Dataset{Name: "records", Applies: true}}
	return inventoryMatching{
		host:     func() (*osfingerprint.OSInfo, error) { return debian, nil },
		matched:  []dataset.Dataset{records},
		coverage: "Debian",
	}, heldIn(s, records), s
}

// heldIn is a run's data that reads s, knowing known, at dataNow.
func heldIn(s store.Store, known ...dataset.Dataset) *held.Run {
	return held.New(func(context.Context, []dataset.Dataset, *osfingerprint.OSInfo, time.Time) (store.Store, store.Adoption, error) {
		return s, store.Adoption{}, nil
	}, known, dataNow)
}

// installed is a host with openssl at version installed.
func installed(version string) []softwarelist.SoftwareEntry {
	return []softwarelist.SoftwareEntry{{Name: "libssl3", Version: version, Manager: "dpkg", Source: "openssl", SourceVersion: version}}
}

// With the dataset held, the inventory is matched and the view names the
// dataset, its release, its date, and its state; read when the run did not
// read the host.
func TestMatchingHeld(t *testing.T) {
	m, data, s := matching(t)
	datasettest.Put(t, s.Root(), datasettest.Dataset{Name: "records"}, datasettest.Content, dataNow.Add(-9*24*time.Hour), nil)

	v := m.run(context.Background(), data, nil, installed("3.0.11-1"))
	if v.NotDone != "" || v.ID != "records" || v.Version != "Debian:12" || v.DataDate != "2026-11-20" || v.State != dataset.StateOutOfSync || v.Source == "" {
		t.Fatalf("view %+v", v)
	}
	if len(v.Packages) != 1 || len(v.Packages[0].Vulnerabilities) != 1 || v.Packages[0].Vulnerabilities[0].ID != "CVE-2026-0001" || v.Packages[0].Vulnerabilities[0].Fixed != "3.0.15-1" {
		t.Errorf("packages %+v", v.Packages)
	}
	if v := m.run(context.Background(), data, debian, installed("3.0.15-1")); v.NotDone != "" || len(v.Packages) != 0 {
		t.Errorf("the fixed version gave %+v", v)
	}
	if v.KnownExploited == nil || !strings.HasPrefix(v.KnownExploited.NotDone, "kev is not held") || v.Packages[0].Vulnerabilities[0].KnownExploited != nil {
		t.Errorf("with no catalog held the match says %+v", v.KnownExploited)
	}
}

// A match is marked from the catalog of known-exploited vulnerabilities the
// run's data holds.
func TestMatchingMarksKnownExploited(t *testing.T) {
	m, data, s := matching(t)
	datasettest.Put(t, s.Root(), datasettest.Dataset{Name: "records"}, datasettest.Content, dataNow.Add(-time.Hour), nil)
	datasettest.PutCatalog(t, s.Root(), dataNow.Add(-time.Hour), `{"cveID": "CVE-2026-0001", "dateAdded": "2026-11-20", "knownRansomwareCampaignUse": "Known"}`)

	v := m.run(context.Background(), data, debian, installed("3.0.11-1"))
	found := v.Packages[0].Vulnerabilities[0]
	if found.KnownExploited == nil || found.KnownExploited.Added != "2026-11-20" || v.KnownExploited == nil || v.KnownExploited.ID != "kev" || v.Counts.KnownExploited != 1 {
		t.Errorf("the match is marked %+v, from %+v", found.KnownExploited, v.KnownExploited)
	}
}

// A match is scored from the EPSS scores file the run's data holds, keeping
// the scores of what it matched; with none held it says why and what to run.
func TestMatchingScoresFromEPSS(t *testing.T) {
	m, data, s := matching(t)
	datasettest.Put(t, s.Root(), datasettest.Dataset{Name: "records"}, datasettest.Content, dataNow.Add(-time.Hour), nil)

	v := m.run(context.Background(), data, debian, installed("3.0.11-1"))
	if v.ExploitPrediction == nil || !strings.HasPrefix(v.ExploitPrediction.NotDone, "epss is not held; fetch it with owatch data refresh") || v.Packages[0].Vulnerabilities[0].ExploitPrediction != nil {
		t.Errorf("with no scores held the match says %+v", v.ExploitPrediction)
	}

	datasettest.PutScores(t, s.Root(), dataNow.Add(-time.Hour), "CVE-1999-0001,0.04753,0.921", "CVE-2026-0001,0.41012,0.9721")
	v = m.run(context.Background(), data, debian, installed("3.0.11-1"))
	found := v.Packages[0].Vulnerabilities[0]
	if found.ExploitPrediction == nil || *found.ExploitPrediction != (epss.Prediction{Score: 0.41012, Percentile: 0.9721}) {
		t.Errorf("CVE-2026-0001 is scored %+v", found.ExploitPrediction)
	}
	if v.ExploitPrediction == nil || v.ExploitPrediction.ID != "epss" || v.ExploitPrediction.Version != "v2026.06.15" || v.ExploitPrediction.NotDone != "" {
		t.Errorf("the match names the scores as %+v", v.ExploitPrediction)
	}
	if x, _ := predicted(context.Background(), data, debian, *v); !has(x, "CVE-2026-0001") || has(x, "CVE-1999-0001") {
		t.Error("the run kept the score of a CVE it did not match, or not of one it did")
	}
}

// has reports whether x holds a prediction for cve.
func has(x epss.Index, cve string) bool {
	_, ok := x.Prediction(cve)
	return ok
}

// A match that cannot be made says why and what to do: no dataset for the
// host, a dataset not held, one that cannot be used, a host that cannot be
// read, and a store that cannot be read.
func TestMatchingNotDone(t *testing.T) {
	for name, tt := range map[string]struct {
		change func(*inventoryMatching, **held.Run, store.Store)
		host   *osfingerprint.OSInfo
		reason string
	}{
		"no dataset for the host": {nil, &osfingerprint.OSInfo{OS: "linux", Platform: "arch"}, "matching covers Debian"},
		"not held":                {nil, debian, "records is not held; fetch it with owatch data refresh"},
		"unusable": {func(_ *inventoryMatching, _ **held.Run, s store.Store) {
			datasettest.Put(t, s.Root(), datasettest.Dataset{Name: "records"}, "not the test dataset\n", dataNow.Add(-time.Hour), nil)
		}, debian, "records cannot be used"},
		"no host": {func(m *inventoryMatching, _ **held.Run, _ store.Store) {
			m.host = func() (*osfingerprint.OSInfo, error) { return nil, errors.New("no host") }
		}, nil, "the host could not be identified: no host"},
		"no store": {func(_ *inventoryMatching, data **held.Run, _ store.Store) {
			*data = held.New(func(context.Context, []dataset.Dataset, *osfingerprint.OSInfo, time.Time) (store.Store, store.Adoption, error) {
				return store.Store{}, store.Adoption{}, errors.New("locked")
			}, nil, dataNow)
		}, debian, "the dataset store could not be read: locked"},
	} {
		m, data, s := matching(t)
		if tt.change != nil {
			tt.change(&m, &data, s)
		}
		v := m.run(context.Background(), data, tt.host, installed("3.0.11-1"))
		if !strings.Contains(v.NotDone, tt.reason) || len(v.Packages) != 0 || v.Packages == nil {
			t.Errorf("%s: %+v, want not done naming %q", name, v, tt.reason)
		}
	}
}

// The view is the software module's section of every report: JSON and YAML
// carry it under vulnerabilities, the text of all and of software alone show
// it, and a saved report reads it back.
func TestVulnerabilitiesInTheReports(t *testing.T) {
	m, reads, s := matching(t)
	datasettest.Put(t, s.Root(), datasettest.Dataset{Name: "records"}, datasettest.Content, dataNow.Add(-time.Hour), nil)
	result := &ScanResult{
		Timestamp: dataNow,
		Modules:   []moduleRun{{Name: selection.NameSoftware, Result: finding.ResultInformational}},
		Software:  installed("3.0.11-1"),
		Vulns:     m.run(context.Background(), reads, debian, installed("3.0.11-1")),
	}
	view := toAllResult(result, "")
	data, err := json.Marshal(view)
	if err != nil || !bytes.Contains(data, []byte(`"vulnerabilities":{"id":"records","state":"current","source":"https://data.example/records","data_date":"2026-11-20","version":"Debian:12"`)) {
		t.Fatalf("JSON %s, %v", data, err)
	}
	if data, err := delivery.Encode(view, delivery.FormatYAML); err != nil || !bytes.Contains(data, []byte("vulnerabilities:\n    id: records\n    state: current\n")) {
		t.Fatalf("YAML %s, %v", data, err)
	}

	var text bytes.Buffer
	if err := writeAllText(&text, view); err != nil || !strings.Contains(text.String(), "\nVulnerabilities\nMatched against records, Debian:12") ||
		!strings.Contains(text.String(), "-           CVE-2026-0001        openssl 3.0.11-1, fixed in 3.0.15-1") {
		t.Errorf("software alone wrote %q, %v", text.String(), err)
	}
	if strings.Contains(text.String(), "\x1b") {
		t.Errorf("the text report is colored: %q", text.String())
	}
	view.Modules = append(view.Modules, moduleRun{Name: selection.NameOS, Result: finding.ResultInformational})
	text.Reset()
	if err := writeAllText(&text, view); err != nil || !strings.Contains(text.String(), "\nVulnerabilities\nMatched against records") {
		t.Errorf("all wrote %q, %v", text.String(), err)
	}

	data, err = json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	report, err := decodeReport("saved.json", delivery.FormatJSON, delivery.FormatText, data)
	if err != nil || !strings.Contains(report.Text, "fixed in 3.0.15-1") {
		t.Errorf("a saved report read back %q, %v", report.Text, err)
	}

	// The saved report opens to the Vulnerabilities tab the live run showed.
	tabOf := func(r tui.Report) tui.Tab {
		for _, tab := range r.Tabs {
			if tab.ID == tui.TabVulnerabilities {
				return tab
			}
		}
		return tui.Tab{}
	}
	live := tabOf(security.BrowserReport(allSource("live", view, "")))
	if saved := tabOf(report); len(live.Records) != 1 || !reflect.DeepEqual(live.Records, saved.Records) || !reflect.DeepEqual(live.Filters, saved.Filters) {
		t.Errorf("the live tab %+v and the saved one %+v differ", live, saved)
	}
}

// The software module matches what it lists: on any host whose inventory can
// be read, the run carries a vulnerabilities section, a match or why none was
// made.
func TestSoftwareModuleMatches(t *testing.T) {
	result := &ScanResult{}
	collectSoftware(context.Background(), held.ForHost(), result)
	if ran := result.Modules[len(result.Modules)-1]; ran.Result == finding.ResultError {
		t.Skipf("this host's inventory cannot be read: %s", ran.Reason)
	}
	if result.Vulns == nil || (result.Vulns.NotDone == "" && result.Vulns.ID == "") {
		t.Errorf("the software module's run carries %+v", result.Vulns)
	}
}

// The software module's row is an inventory's, neither passing nor failing,
// and says what the match of it found, or why no match was made, as the
// match states itself.
func TestSoftwareModuleStatesTheMatch(t *testing.T) {
	m, reads, s := matching(t)
	datasettest.Put(t, s.Root(), datasettest.Dataset{Name: "records"}, datasettest.Content, dataNow.Add(-time.Hour), nil)
	matched := m.run(context.Background(), reads, debian, installed("3.0.11-1"))
	for _, v := range []*vulnmatch.View{matched, notDone("records", "records is not held")} {
		row := softwareModule(v)
		if row.Name != selection.NameSoftware || row.Result != finding.ResultInformational || row.Reason != "inventory, "+v.Summary() {
			t.Errorf("the row is %+v for the match %q", row, v.Summary())
		}
	}
	if !strings.HasPrefix(matched.Summary(), "matched against records: ") {
		t.Errorf("the match states itself as %q", matched.Summary())
	}
}

// A FreeBSD host's packages are matched against VuXML, which owatch knows, a
// match of it carries VuXML's one release, and the coverage a match not made
// names FreeBSD among the systems matching covers.
func TestMatchingCoversFreeBSD(t *testing.T) {
	host := &osfingerprint.OSInfo{OS: "freebsd", Platform: "freebsd", PlatformVersion: "15.1-RELEASE"}
	m := hostMatching()
	if source := m.source(host); source == nil || source.ID() != "vuxml" {
		t.Fatalf("a FreeBSD host is matched against %v", source)
	}
	if id, release, err := m.release(host); err != nil || id != "vuxml" || release != "FreeBSD ports" {
		t.Errorf("release %q %q, %v", id, release, err)
	}
	if !strings.Contains(m.coverage, "FreeBSD") {
		t.Errorf("the coverage %q leaves FreeBSD out", m.coverage)
	}
	if !slices.ContainsFunc(held.Known(), func(d dataset.Dataset) bool { return d.ID() == "vuxml" }) {
		t.Error("owatch does not know VuXML")
	}
}

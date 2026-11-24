// cmd/commands/vulnerabilities_test.go

package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/papa0four/orkowatch/cmd/commands/delivery"
	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/dataset/datasettest"
	"github.com/papa0four/orkowatch/internal/dataset/osv"
	"github.com/papa0four/orkowatch/internal/dataset/store"
	"github.com/papa0four/orkowatch/internal/osfingerprint"
	"github.com/papa0four/orkowatch/internal/security/finding"
	"github.com/papa0four/orkowatch/internal/selection"
	"github.com/papa0four/orkowatch/internal/softwarelist"
)

// testRecords is the test dataset as a source of records for Debian hosts:
// its data checked as the test dataset's, and one record of openssl given.
type testRecords struct{ datasettest.Dataset }

func (testRecords) AppliesTo(host *osfingerprint.OSInfo) bool { return host.Platform == "debian" }
func (testRecords) Manager() string                           { return softwarelist.ManagerDpkg }

func (r testRecords) Records(data io.Reader, host *osfingerprint.OSInfo, each func(osv.Record) error) (dataset.Facts, error) {
	facts, err := r.Check(data, host)
	if err != nil {
		return facts, err
	}
	facts.Version = "Debian:12"
	return facts, each(osv.Record{ID: "DSA-1", CVEs: []string{"CVE-2026-1"}, Modified: "2026-11-20T00:00:00Z",
		Affected: []osv.Affected{{Package: "openssl", Ecosystem: "Debian:12", Ranges: [][]osv.Event{{{"introduced": "0"}, {"fixed": "3.0.15-1"}}}}}})
}

var debian = &osfingerprint.OSInfo{OS: "linux", Platform: "debian", PlatformVersion: "12"}

// matching is inventoryMatching over a store in a temporary directory that
// knows the test records, at dataNow.
func matching(t *testing.T) (inventoryMatching, store.Store) {
	t.Helper()
	s := store.At(filepath.Join(t.TempDir(), "store"))
	records := testRecords{datasettest.Dataset{Name: "records", Applies: true}}
	return inventoryMatching{
		host: func() (*osfingerprint.OSInfo, error) { return debian, nil },
		read: func(context.Context, []dataset.Dataset, *osfingerprint.OSInfo, time.Time) (store.Store, store.Adoption, error) {
			return s, store.Adoption{}, nil
		},
		now:      func() time.Time { return dataNow },
		matched:  []dataset.Dataset{records},
		known:    []dataset.Dataset{records},
		coverage: "Debian",
	}, s
}

// installed is a host with openssl at version installed.
func installed(version string) []softwarelist.SoftwareEntry {
	return []softwarelist.SoftwareEntry{{Name: "libssl3", Version: version, Manager: "dpkg", Source: "openssl", SourceVersion: version}}
}

// With the dataset held, the inventory is matched and the view names the
// dataset, its release, its date, and its state; read when the run did not
// read the host.
func TestMatchingHeld(t *testing.T) {
	m, s := matching(t)
	datasettest.Put(t, s.Root(), datasettest.Dataset{Name: "records"}, datasettest.Content, dataNow.Add(-9*24*time.Hour), nil)

	v := m.run(context.Background(), nil, installed("3.0.11-1"))
	if v.NotDone != "" || v.Dataset != "records" || v.Release != "Debian:12" || v.DataDate != "2026-11-20" || v.State != string(dataset.StateOutOfSync) || v.Source == "" {
		t.Fatalf("view %+v", v)
	}
	if len(v.Packages) != 1 || len(v.Packages[0].Vulnerabilities) != 1 || v.Packages[0].Vulnerabilities[0].ID != "CVE-2026-1" || v.Packages[0].Vulnerabilities[0].Fixed != "3.0.15-1" {
		t.Errorf("packages %+v", v.Packages)
	}
	if v := m.run(context.Background(), debian, installed("3.0.15-1")); v.NotDone != "" || len(v.Packages) != 0 {
		t.Errorf("the fixed version gave %+v", v)
	}
}

// A match that cannot be made says why and what to do: no dataset for the
// host, a dataset not held, one that cannot be used, a host that cannot be
// read, and a store that cannot be read.
func TestMatchingNotDone(t *testing.T) {
	for name, tt := range map[string]struct {
		change func(*inventoryMatching, store.Store)
		host   *osfingerprint.OSInfo
		reason string
	}{
		"no dataset for the host": {nil, &osfingerprint.OSInfo{OS: "linux", Platform: "arch"}, "matching covers Debian"},
		"not held":                {nil, debian, "records is not held; fetch it with owatch data refresh"},
		"unusable": {func(_ *inventoryMatching, s store.Store) {
			datasettest.Put(t, s.Root(), datasettest.Dataset{Name: "records"}, "not the test dataset\n", dataNow.Add(-time.Hour), nil)
		}, debian, "records cannot be used"},
		"no host": {func(m *inventoryMatching, _ store.Store) {
			m.host = func() (*osfingerprint.OSInfo, error) { return nil, errors.New("no host") }
		}, nil, "the host could not be identified: no host"},
		"no store": {func(m *inventoryMatching, _ store.Store) {
			m.read = func(context.Context, []dataset.Dataset, *osfingerprint.OSInfo, time.Time) (store.Store, store.Adoption, error) {
				return store.Store{}, store.Adoption{}, errors.New("locked")
			}
		}, debian, "the dataset store could not be read: locked"},
	} {
		m, s := matching(t)
		if tt.change != nil {
			tt.change(&m, s)
		}
		v := m.run(context.Background(), tt.host, installed("3.0.11-1"))
		if !strings.Contains(v.NotDone, tt.reason) || len(v.Packages) != 0 || v.Packages == nil {
			t.Errorf("%s: %+v, want not done naming %q", name, v, tt.reason)
		}
	}
}

// The view is the software module's section of every report: JSON and YAML
// carry it under vulnerabilities, the text of all and of software alone show
// it, and a saved report reads it back.
func TestVulnerabilitiesInTheReports(t *testing.T) {
	m, s := matching(t)
	datasettest.Put(t, s.Root(), datasettest.Dataset{Name: "records"}, datasettest.Content, dataNow.Add(-time.Hour), nil)
	result := &ScanResult{
		Timestamp: dataNow,
		Modules:   []moduleRun{{Name: selection.NameSoftware, Result: finding.ResultInformational}},
		Software:  installed("3.0.11-1"),
		Vulns:     m.run(context.Background(), debian, installed("3.0.11-1")),
	}
	view := toAllResult(result, "")
	data, err := json.Marshal(view)
	if err != nil || !bytes.Contains(data, []byte(`"vulnerabilities":{"dataset":"records"`)) {
		t.Fatalf("JSON %s, %v", data, err)
	}

	var text bytes.Buffer
	if err := writeAllText(&text, view); err != nil || !strings.Contains(text.String(), "\nVulnerabilities\nMatched against records, Debian:12") ||
		!strings.Contains(text.String(), "CVE-2026-1           openssl 3.0.11-1, fixed in 3.0.15-1") {
		t.Errorf("software alone wrote %q, %v", text.String(), err)
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
}

// The software module matches what it lists: on any host whose inventory can
// be read, the run carries a vulnerabilities section, a match or why none was
// made.
func TestSoftwareModuleMatches(t *testing.T) {
	result := &ScanResult{}
	collectSoftware(context.Background(), result)
	if ran := result.Modules[len(result.Modules)-1]; ran.Result == finding.ResultError {
		t.Skipf("this host's inventory cannot be read: %s", ran.Reason)
	}
	if result.Vulns == nil || (result.Vulns.NotDone == "" && result.Vulns.Dataset == "") {
		t.Errorf("the software module's run carries %+v", result.Vulns)
	}
}

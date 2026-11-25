// cmd/commands/held/held_test.go

package held

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/dataset/datasettest"
	"github.com/papa0four/orkowatch/internal/dataset/kev"
	"github.com/papa0four/orkowatch/internal/dataset/store"
	"github.com/papa0four/orkowatch/internal/osfingerprint"
)

var (
	now     = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	held    = datasettest.Dataset{Name: "held", Applies: true}
	missing = datasettest.Dataset{Name: "missing", Applies: true}
	host    = &osfingerprint.OSInfo{OS: "linux"}
)

// counted is a run over s whose opener counts how often it is called and
// fails with err when err is not nil.
func counted(s store.Store, err error) (*Run, *int) {
	opens := new(int)
	return New(func(context.Context, []dataset.Dataset, *osfingerprint.OSInfo, time.Time) (store.Store, store.Adoption, error) {
		*opens++
		return s, store.Adoption{}, err
	}, []dataset.Dataset{held, missing}, now), opens
}

// check reads data as the dataset d's own check does.
func check(d dataset.Dataset) func(io.Reader) (dataset.Facts, error) {
	return func(data io.Reader) (dataset.Facts, error) { return d.Check(data, host) }
}

// A run opens its store once, however many datasets it reads and whether or
// not each is held, and a held dataset reads as its provenance.
func TestReadOpensTheStoreOnce(t *testing.T) {
	s := store.At(filepath.Join(t.TempDir(), "store"))
	datasettest.Put(t, s.Root(), held, datasettest.Content, now.Add(-time.Hour), nil)
	run, opens := counted(s, nil)

	use := run.Read(context.Background(), held, host, check(held))
	want := dataset.Provenance{ID: "held", State: dataset.StateCurrent, Source: "https://data.example/held", DataDate: "2026-11-20",
		Version: datasettest.Version, Fetched: "2026-11-22T11:00:00Z", License: "CC0 1.0", Attribution: "Made for the tests"}
	if use.NotDone != "" || use.Provenance != want {
		t.Errorf("a held dataset read as %+v, want %+v", use, want)
	}
	run.Read(context.Background(), missing, host, check(missing))
	run.Read(context.Background(), held, host, check(held))
	if *opens != 1 {
		t.Errorf("three reads opened the store %d times, want once", *opens)
	}
}

// The catalog of known-exploited vulnerabilities is read once a run, however
// often the run asks for it, with its index and its provenance; one not held
// gives an empty index and the reason.
func TestExploitedIsReadOnce(t *testing.T) {
	s := store.At(filepath.Join(t.TempDir(), "store"))
	catalog := kev.Catalog{}
	datasettest.PutCatalog(t, s.Root(), now.Add(-time.Hour),
		`{"cveID": "CVE-2026-0001", "dateAdded": "2026-11-20", "dueDate": "2026-12-11", "knownRansomwareCampaignUse": "Known", "cwes": ["CWE-306"]}`)
	run, _ := counted(s, nil)

	x, use := run.Exploited(context.Background(), host)
	entry, listed := x.Entry("CVE-2026-0001")
	if use.NotDone != "" || use.ID != "kev" || use.Version != "2026.11.21" || use.Attribution != catalog.Origin().Attribution ||
		!listed || entry.Ransomware != "Known" || x.ClassCount("CWE-306") != 1 {
		t.Fatalf("the catalog read as %+v, %+v, %v", use, entry, listed)
	}
	if err := os.RemoveAll(filepath.Join(s.Root(), "kev")); err != nil {
		t.Fatal(err)
	}
	if again, use := run.Exploited(context.Background(), host); again.ClassCount("CWE-306") != 1 || use.NotDone != "" {
		t.Errorf("asked again, the run read the catalog again: %+v", use)
	}

	other, _ := counted(store.At(filepath.Join(t.TempDir(), "store")), nil)
	x, use = other.Exploited(context.Background(), host)
	if _, listed := x.Entry("CVE-2026-0001"); listed || x.ClassCount("CWE-306") != 0 || use.NotDone != "kev is not held; fetch it with owatch data refresh, or install it with owatch data import" {
		t.Errorf("a catalog not held gave %+v", use)
	}
}

// A catalog that reads as a catalog but is not the file its manifest
// describes gives nothing it read: the store refuses it only after it was
// read.
func TestExploitedRefusedAfterReading(t *testing.T) {
	s := store.At(filepath.Join(t.TempDir(), "store"))
	datasettest.PutCatalog(t, s.Root(), now.Add(-time.Hour), `{"cveID": "CVE-2026-0001", "knownRansomwareCampaignUse": "Known", "cwes": ["CWE-306"]}`)
	files, err := filepath.Glob(filepath.Join(s.Root(), "kev", "*.data"))
	if err != nil || len(files) != 1 {
		t.Fatalf("data files %v, %v", files, err)
	}
	data, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(files[0], bytes.Replace(data, []byte(`"Known"`), []byte(`"Knowx"`), 1), 0o600); err != nil {
		t.Fatal(err)
	}

	run, _ := counted(s, nil)
	x, use := run.Exploited(context.Background(), host)
	if _, listed := x.Entry("CVE-2026-0001"); listed || x.ClassCount("CWE-306") != 0 || !strings.HasPrefix(use.NotDone, "kev cannot be used") {
		t.Errorf("a catalog its checksum refuses gave %v listed, %d of CWE-306, %+v", listed, x.ClassCount("CWE-306"), use)
	}
}

// A run says what it installed from the operator's store once it has opened
// its store, and nothing before; a read is what opens it.
func TestOperatorIsWhatOpeningInstalled(t *testing.T) {
	s := store.At(filepath.Join(t.TempDir(), "store"))
	run := New(func(context.Context, []dataset.Dataset, *osfingerprint.OSInfo, time.Time) (store.Store, store.Adoption, error) {
		return s, store.Adoption{From: "/home/a/store", Outcomes: []store.Outcome{
			{ID: "held", Result: store.Installed},
			{ID: "missing", Result: store.Refused, Reason: "it is a link"},
		}}, nil
	}, []dataset.Dataset{held, missing}, now)

	if o := run.Operator(); o != nil {
		t.Fatalf("before opening, the run says %+v", o)
	}
	run.Read(context.Background(), missing, host, check(missing))
	o := run.Operator()
	if o == nil || o.Store != "/home/a/store" || len(o.Installed) != 1 || o.Installed[0] != "held" ||
		len(o.Refused) != 1 || o.Refused[0] != (dataset.Refusal{ID: "missing", Reason: "it is a link"}) ||
		o.Advice != "To install what was not installed, as a deliberate act, run owatch data import /home/a/store" {
		t.Errorf("after reading, the run says %+v", o)
	}
}

// What cannot be read says why and what to run: a dataset not held, one its
// reader refuses, and every dataset of a run whose store cannot be opened,
// which is tried once.
func TestReadNotDone(t *testing.T) {
	s := store.At(filepath.Join(t.TempDir(), "store"))
	datasettest.Put(t, s.Root(), held, datasettest.Content, now.Add(-time.Hour), nil)
	run, _ := counted(s, nil)

	for name, c := range map[string]struct {
		use      dataset.Use
		id, want string
	}{
		"not held": {run.Read(context.Background(), missing, host, check(missing)), "missing",
			"missing is not held; fetch it with owatch data refresh, or install it with owatch data import"},
		"refused": {run.Read(context.Background(), held, host, func(io.Reader) (dataset.Facts, error) { return dataset.Facts{}, errors.New("not records") }), "held",
			"held cannot be used: dataset unusable: not records; fetch it again with owatch data refresh"},
	} {
		if c.use.NotDone != c.want || c.use.ID != c.id || c.use.DataDate != "" {
			t.Errorf("%s: %+v, want not done saying %q", name, c.use, c.want)
		}
	}

	locked, opens := counted(store.Store{}, errors.New("locked"))
	for _, d := range []dataset.Dataset{held, missing} {
		if use := locked.Read(context.Background(), d, host, check(d)); use.NotDone != "the dataset store could not be read: locked" || use.ID != d.ID() {
			t.Errorf("%s with no store: %+v", d.ID(), use)
		}
	}
	if *opens != 1 {
		t.Errorf("a store that cannot be opened was tried %d times, want once", *opens)
	}
}

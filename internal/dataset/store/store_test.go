// internal/dataset/store/store_test.go

package store

import (
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
	"github.com/papa0four/orkowatch/internal/elevation"
	"github.com/papa0four/orkowatch/internal/osfingerprint"
)

var now = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

// testDataset is the dataset made for the tests, and content a sound file of
// it.
type testDataset = datasettest.Dataset

const content = datasettest.Content

// put holds data in s as the dataset d, with the manifest that describes it
// changed by edit when edit is not nil.
func put(t *testing.T, s Store, d dataset.Dataset, data string, fetched time.Time, edit func(*dataset.Manifest)) {
	t.Helper()
	datasettest.Put(t, s.root, d, data, fetched, edit)
}

// dataFile is the path of the file holding data for d in s.
func dataFile(s Store, d dataset.Dataset, data string) string {
	return filepath.Join(s.dir(d.ID()), datasettest.DataName(data))
}

// rowOf returns the status row of id.
func rowOf(t *testing.T, s Store, known []dataset.Dataset, id string) dataset.Row {
	t.Helper()
	view, err := s.Status(known, &osfingerprint.OSInfo{}, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range view.Datasets {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("status has no row for %s: %+v", id, view.Datasets)
	return dataset.Row{}
}

// A sound dataset is read, and status gives what its manifest and its data
// say.
func TestStatusOfAHeldDataset(t *testing.T) {
	s := Store{root: t.TempDir()}
	d := testDataset{Name: "test-data", Applies: true}
	put(t, s, d, content, now.Add(-time.Hour), nil)

	got := rowOf(t, s, []dataset.Dataset{d}, d.Name)
	want := dataset.Row{
		ID:          d.Name,
		State:       dataset.StateCurrent,
		Source:      "https://data.example/test-data",
		DataDate:    "2026-11-20",
		Version:     datasettest.Version,
		Fetched:     "2026-11-22T11:00:00Z",
		Size:        int64(len(content)),
		License:     "CC0 1.0",
		Attribution: "Made for the tests",
	}
	if got != want {
		t.Errorf("row %+v, want %+v", got, want)
	}
}

// unversioned is the test dataset with a check that states no version.
type unversioned struct{ testDataset }

func (u unversioned) Check(data io.Reader, host *osfingerprint.OSInfo) (dataset.Facts, error) {
	facts, err := u.testDataset.Check(data, host)
	facts.Version = ""
	return facts, err
}

// A dataset whose check states no version is unusable, so no row shows a
// dataset without one.
func TestStatusRefusesADatasetWithNoVersion(t *testing.T) {
	s := Store{root: t.TempDir()}
	d := unversioned{testDataset{Name: "test-data", Applies: true}}
	put(t, s, d, content, now.Add(-time.Hour), nil)
	if got := rowOf(t, s, []dataset.Dataset{d}, "test-data"); got.State != dataset.StateUnusable || !strings.Contains(got.Reason, "no version") {
		t.Errorf("row %+v, want unusable for want of a version", got)
	}
}

// A held dataset is out of sync more than 7 days after its fetch and stale
// more than 14 after.
func TestStatusAge(t *testing.T) {
	for age, want := range map[time.Duration]dataset.State{
		8 * 24 * time.Hour:  dataset.StateOutOfSync,
		15 * 24 * time.Hour: dataset.StateStale,
	} {
		s := Store{root: t.TempDir()}
		d := testDataset{Name: "test-data", Applies: true}
		put(t, s, d, content, now.Add(-age), nil)
		if got := rowOf(t, s, []dataset.Dataset{d}, d.Name).State; got != want {
			t.Errorf("fetched %v ago: %q, want %q", age, got, want)
		}
	}
}

// A dataset whose data is truncated, longer than its manifest says, changed,
// not the expected format, or missing, or whose manifest is wrong or is not a
// regular file, is reported as unusable with the reason, and nothing it says
// is shown.
func TestStatusRefusesADamagedDataset(t *testing.T) {
	d := testDataset{Name: "test-data", Applies: true}
	for _, tt := range []struct {
		name   string
		damage func(t *testing.T, s Store, d dataset.Dataset)
		reason string
	}{
		{"truncated", rewriteData(content[:len(content)-3]), "the data holds"},
		{"longer", rewriteData(content + "more\n"), "the data holds"},
		{"changed", rewriteData(strings.Replace(content, "entries", "entriez", 1)), "checksum"},
		{"not the format", holdInstead(strings.Replace(content, "owatch-test-dataset", "owatch-other-format", 1), nil), "not the test dataset"},
		{"data missing", removeData, dataSuffix},
		{"a manifest for another dataset", holdInstead(content, func(m *dataset.Manifest) { m.ID = "other-data" }), "manifest refused"},
		{"a manifest that is a directory", replaceWithDir(func(s Store, d dataset.Dataset) string {
			return filepath.Join(s.dir(d.ID()), manifestName)
		}), "not a regular file"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := Store{root: t.TempDir()}
			put(t, s, d, content, now.Add(-time.Hour), nil)
			tt.damage(t, s, d)

			got := rowOf(t, s, []dataset.Dataset{d}, d.Name)
			if got.State != dataset.StateUnusable || !strings.Contains(got.Reason, tt.reason) {
				t.Errorf("row %+v, want unusable for a reason naming %q", got, tt.reason)
			}
			if got.Source != "" || got.DataDate != "" || got.Size != 0 {
				t.Errorf("an unusable dataset shows what it says: %+v", got)
			}
		})
	}
}

// rewriteData puts data where the held dataset's data file is, leaving its
// manifest as it was.
func rewriteData(data string) func(*testing.T, Store, dataset.Dataset) {
	return func(t *testing.T, s Store, d dataset.Dataset) {
		if err := os.WriteFile(dataFile(s, d, content), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// holdInstead holds data in place of the dataset, with its manifest changed
// by edit.
func holdInstead(data string, edit func(*dataset.Manifest)) func(*testing.T, Store, dataset.Dataset) {
	return func(t *testing.T, s Store, d dataset.Dataset) {
		if err := os.RemoveAll(s.dir(d.ID())); err != nil {
			t.Fatal(err)
		}
		put(t, s, d, data, now.Add(-time.Hour), edit)
	}
}

// removeData deletes the held dataset's data file, leaving its manifest.
func removeData(t *testing.T, s Store, d dataset.Dataset) {
	if err := os.Remove(dataFile(s, d, content)); err != nil {
		t.Fatal(err)
	}
}

// replaceWithDir puts a directory where the file path names is, so the file
// is missing and something that is not a regular file is in its place.
func replaceWithDir(path func(Store, dataset.Dataset) string) func(*testing.T, Store, dataset.Dataset) {
	return func(t *testing.T, s Store, d dataset.Dataset) {
		p := path(s, d)
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
}

// A manifest that is a link is refused, so the file a dataset is judged by
// cannot be swapped for one elsewhere.
func TestStatusRefusesALinkedManifest(t *testing.T) {
	s := Store{root: t.TempDir()}
	d := testDataset{Name: "test-data", Applies: true}
	put(t, s, d, content, now.Add(-time.Hour), nil)
	path := filepath.Join(s.dir(d.Name), manifestName)
	elsewhere := filepath.Join(t.TempDir(), manifestName)
	if err := os.Rename(path, elsewhere); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, path); err != nil {
		t.Skipf("this account cannot make a link: %v", err)
	}
	if got := rowOf(t, s, []dataset.Dataset{d}, d.Name); got.State != dataset.StateUnusable || !strings.Contains(got.Reason, "not a regular file") {
		t.Errorf("row %+v, want unusable as not a regular file", got)
	}
}

// Status lists a dataset that applies and is not held, one held that no
// longer applies and one the version does not know, each with its size, and
// nothing for a dataset that neither applies nor is held. A store that does
// not exist yet holds nothing.
func TestStatusRows(t *testing.T) {
	s := Store{root: filepath.Join(t.TempDir(), "store")}
	wanted := testDataset{Name: "wanted", Applies: true}
	former := testDataset{Name: "former", Applies: false}
	elsewhere := testDataset{Name: "elsewhere", Applies: false}
	known := []dataset.Dataset{wanted, former, elsewhere}

	view, err := s.Status(known, &osfingerprint.OSInfo{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Datasets) != 1 || view.Datasets[0] != (dataset.Row{ID: "wanted", State: dataset.StateNotHeld}) {
		t.Errorf("a missing store gave %+v, want wanted as not held", view.Datasets)
	}

	put(t, s, former, content, now.Add(-time.Hour), nil)
	put(t, s, testDataset{Name: "retired"}, content, now.Add(-time.Hour), nil)
	// A directory of the store's own, where a fetch is staged, is not listed.
	if err := os.Mkdir(filepath.Join(s.root, ".staging"), 0o700); err != nil {
		t.Fatal(err)
	}

	view, err = s.Status(known, &osfingerprint.OSInfo{}, now)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, r := range view.Datasets {
		ids = append(ids, r.ID+"="+string(r.State))
	}
	if got := strings.Join(ids, " "); got != "wanted=not held former=no longer applies retired=unknown to this version" {
		t.Errorf("rows %s", got)
	}
	for _, r := range view.Datasets[1:] {
		if r.Size <= int64(len(content)) {
			t.Errorf("%s gives the size %d, want the data and its manifest", r.ID, r.Size)
		}
	}
}

// The process's store is under the home the system records for its account,
// and an elevated process's is the protected one in the system's data
// directory.
func TestForProcess(t *testing.T) {
	s, err := ForProcess(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if elevation.Elevated() {
		base, err := systemData()
		if err != nil {
			t.Fatal(err)
		}
		if want := filepath.Join(base, "owatch", "datasets"); s.Root() != want || s.protect == nil {
			t.Errorf("an elevated process's store is %s, protected %v; want %s, protected", s.Root(), s.protect != nil, want)
		}
		return
	}
	if s.protect != nil {
		t.Error("the account's own store is protected")
	}
	want, err := accountRoot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if s.Root() != want || !strings.HasSuffix(s.Root(), filepath.Join("owatch", "datasets")) {
		t.Errorf("the store is %s, want %s", s.Root(), want)
	}
}

// Read gives a run the data of a held dataset, checked as it is given: a
// dataset not held is ErrNotHeld, and one whose data is not what its manifest
// says is ErrUnusable even though consume saw it.
func TestRead(t *testing.T) {
	s := Store{root: t.TempDir()}
	d := testDataset{Name: "test-data", Applies: true}
	var got strings.Builder
	consume := func(data io.Reader) error {
		got.Reset()
		_, err := io.Copy(&got, data)
		return err
	}

	if _, err := s.Read(d, now, consume); !errors.Is(err, ErrNotHeld) {
		t.Errorf("a dataset not held gave %v, want ErrNotHeld", err)
	}
	put(t, s, d, content, now.Add(-time.Hour), nil)
	if m, err := s.Read(d, now, consume); err != nil || got.String() != content || m.ID != d.Name {
		t.Errorf("a held dataset gave %q, %+v, %v", got.String(), m, err)
	}
	if err := os.WriteFile(dataFile(s, d, content), []byte(strings.ToUpper(content)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Read(d, now, consume); !errors.Is(err, ErrUnusable) || got.Len() == 0 {
		t.Errorf("damaged data gave %v after consume saw %d bytes, want ErrUnusable", err, got.Len())
	}
}

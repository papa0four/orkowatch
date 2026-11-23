// internal/dataset/store/store_test.go

package store

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/elevation"
	"github.com/papa0four/orkowatch/internal/osfingerprint"
)

// testHeader opens every file of the test dataset; the line after it is the
// date of its data.
const testHeader = "owatch-test-dataset\n"

var now = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

// testDataset is a dataset made for the tests: a header line, the date of its
// data, and anything after.
type testDataset struct {
	id      string
	applies bool
}

func (d testDataset) ID() string                           { return d.id }
func (d testDataset) AppliesTo(*osfingerprint.OSInfo) bool { return d.applies }
func (testDataset) MaxBytes() int64                        { return 1 << 10 }

func (testDataset) Check(data io.Reader) (dataset.Facts, error) {
	r := bufio.NewReader(data)
	header, err := r.ReadString('\n')
	if err != nil || header != testHeader {
		return dataset.Facts{}, errors.New("not the test dataset")
	}
	line, err := r.ReadString('\n')
	if err != nil {
		return dataset.Facts{}, errors.New("no date")
	}
	date, err := time.Parse(time.DateOnly, strings.TrimSpace(line))
	if err != nil {
		return dataset.Facts{}, errors.New("no date")
	}
	return dataset.Facts{Date: date}, nil
}

// content is a sound file of the test dataset.
const content = testHeader + "2026-11-20\nentries\n"

// put holds content in s as the dataset d, with the manifest that describes
// it changed by edit when edit is not nil.
func put(t *testing.T, s Store, d dataset.Dataset, data string, fetched time.Time, edit func(*dataset.Manifest)) {
	t.Helper()
	sum := sha256.Sum256([]byte(data))
	m := dataset.Manifest{
		Format:      dataset.ManifestFormat,
		ID:          d.ID(),
		Source:      "https://data.example/" + d.ID(),
		Fetched:     fetched,
		SHA256:      hex.EncodeToString(sum[:]),
		Size:        int64(len(data)),
		License:     "CC0 1.0",
		Attribution: "Made for the tests",
	}
	if edit != nil {
		edit(&m)
	}
	dir := s.dir(d.ID())
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, hex.EncodeToString(sum[:])+dataSuffix), []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(dir, manifestName))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Encode(f); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// dataFile is the path of the data file held for d.
func dataFile(s Store, d dataset.Dataset, data string) string {
	sum := sha256.Sum256([]byte(data))
	return filepath.Join(s.dir(d.ID()), hex.EncodeToString(sum[:])+dataSuffix)
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
	d := testDataset{id: "test-data", applies: true}
	put(t, s, d, content, now.Add(-time.Hour), nil)

	got := rowOf(t, s, []dataset.Dataset{d}, d.id)
	want := dataset.Row{
		ID:          d.id,
		State:       dataset.StateCurrent,
		Source:      "https://data.example/test-data",
		DataDate:    "2026-11-20",
		Fetched:     "2026-11-22T11:00:00Z",
		Size:        int64(len(content)),
		License:     "CC0 1.0",
		Attribution: "Made for the tests",
	}
	if got != want {
		t.Errorf("row %+v, want %+v", got, want)
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
		d := testDataset{id: "test-data", applies: true}
		put(t, s, d, content, now.Add(-age), nil)
		if got := rowOf(t, s, []dataset.Dataset{d}, d.id).State; got != want {
			t.Errorf("fetched %v ago: %q, want %q", age, got, want)
		}
	}
}

// A dataset whose data is truncated, longer than its manifest says, changed,
// not the expected format, or missing, or whose manifest is wrong or is not a
// regular file, is reported as unusable with the reason, and nothing it says
// is shown.
func TestStatusRefusesADamagedDataset(t *testing.T) {
	d := testDataset{id: "test-data", applies: true}
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

			got := rowOf(t, s, []dataset.Dataset{d}, d.id)
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
	d := testDataset{id: "test-data", applies: true}
	put(t, s, d, content, now.Add(-time.Hour), nil)
	path := filepath.Join(s.dir(d.id), manifestName)
	elsewhere := filepath.Join(t.TempDir(), manifestName)
	if err := os.Rename(path, elsewhere); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, path); err != nil {
		t.Skipf("this account cannot make a link: %v", err)
	}
	if got := rowOf(t, s, []dataset.Dataset{d}, d.id); got.State != dataset.StateUnusable || !strings.Contains(got.Reason, "not a regular file") {
		t.Errorf("row %+v, want unusable as not a regular file", got)
	}
}

// Status lists a dataset that applies and is not held, one held that no
// longer applies and one the version does not know, each with its size, and
// nothing for a dataset that neither applies nor is held. A store that does
// not exist yet holds nothing.
func TestStatusRows(t *testing.T) {
	s := Store{root: filepath.Join(t.TempDir(), "store")}
	wanted := testDataset{id: "wanted", applies: true}
	former := testDataset{id: "former", applies: false}
	elsewhere := testDataset{id: "elsewhere", applies: false}
	known := []dataset.Dataset{wanted, former, elsewhere}

	view, err := s.Status(known, &osfingerprint.OSInfo{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Datasets) != 1 || view.Datasets[0] != (dataset.Row{ID: "wanted", State: dataset.StateNotHeld}) {
		t.Errorf("a missing store gave %+v, want wanted as not held", view.Datasets)
	}

	put(t, s, former, content, now.Add(-time.Hour), nil)
	put(t, s, testDataset{id: "retired"}, content, now.Add(-time.Hour), nil)

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
// and an elevated process has none.
func TestForProcess(t *testing.T) {
	s, err := ForProcess(context.Background())
	if elevation.Elevated() {
		if !errors.Is(err, ErrElevated) {
			t.Errorf("an elevated process gave %v, want ErrElevated", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	want, err := accountRoot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if s.Root() != want || !strings.HasSuffix(s.Root(), filepath.Join("owatch", "datasets")) {
		t.Errorf("the store is %s, want %s", s.Root(), want)
	}
}

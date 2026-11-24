// internal/dataset/store/adopt_test.go

package store

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/dataset/datasettest"
	"github.com/papa0four/orkowatch/internal/osfingerprint"
)

// ownerOf is an Owner a test decides: it owns the files whose names it is
// not told to disown.
type ownerOf struct{ disowned string }

func (o ownerOf) Owns(f *os.File) (bool, error) {
	return o.disowned == "" || !strings.HasSuffix(f.Name(), o.disowned), nil
}

// adopt installs into s what the account's store in from holds newer, owned
// as owner says.
func adopt(t *testing.T, s, from Store, owner Owner) []Outcome {
	t.Helper()
	outcomes, err := s.Adopt(context.Background(), from.root, owner, known, &osfingerprint.OSInfo{}, now)
	if err != nil {
		t.Fatal(err)
	}
	return outcomes
}

// staged lists what the store's staging directories hold, which is nothing
// once an adoption has ended.
func staged(t *testing.T, s Store) []string {
	t.Helper()
	left, err := filepath.Glob(filepath.Join(s.root, stagingPrefix+"*"))
	if err != nil {
		t.Fatal(err)
	}
	return left
}

// A dataset the account holds and the store does not is installed; one the
// account holds newer replaces the copy held; one no newer, and one the
// account does not hold, are left with no outcome and nothing copied.
func TestAdoptInstallsWhatIsNewer(t *testing.T) {
	s, from := stores(t)
	if got := adopt(t, s, from, ownerOf{}); len(got) != 0 {
		t.Errorf("an account holding nothing gave %+v", got)
	}

	// A dataset that does not apply to this host is not copied to be told so.
	put(t, from, testDataset{Name: "elsewhere"}, content, now.Add(-time.Hour), nil)
	if got := adopt(t, s, from, ownerOf{}); len(got) != 0 {
		t.Errorf("a dataset that does not apply here gave %+v", got)
	}

	put(t, from, wanted, content, now.Add(-2*time.Hour), nil)
	if got := adopt(t, s, from, ownerOf{}); len(got) != 1 || got[0] != (Outcome{ID: "wanted", Result: Installed, Attempts: 1}) {
		t.Fatalf("a dataset the store lacks: %+v", got)
	}
	if row := rowOf(t, s, known, "wanted"); row.State != dataset.StateCurrent || row.DataDate != "2026-11-20" {
		t.Errorf("row %+v, want the dataset current", row)
	}

	if got := adopt(t, s, from, ownerOf{}); len(got) != 0 {
		t.Errorf("a dataset no newer than the copy held gave %+v", got)
	}

	newer := strings.Replace(content, "2026-11-20", "2026-11-21", 1)
	put(t, from, wanted, newer, now.Add(-time.Hour), nil)
	if got := adopt(t, s, from, ownerOf{}); len(got) != 1 || got[0].Result != Installed {
		t.Fatalf("a newer dataset: %+v", got)
	}
	if row := rowOf(t, s, known, "wanted"); row.DataDate != "2026-11-21" {
		t.Errorf("row %+v, want the newer data", row)
	}
	if left := staged(t, s); len(left) != 0 {
		t.Errorf("staging left behind: %q", left)
	}
}

// What the account's store holds is refused, and the copy held left as it
// was, when its manifest or its data is owned by another account, when
// either is larger than it may be, when the manifest names its data by
// something that is not a checksum, and when the data is not what the
// manifest says.
func TestAdoptRefuses(t *testing.T) {
	newer := strings.Replace(content, "2026-11-20", "2026-11-21", 1)
	dataName := datasettest.DataName(newer)

	for _, tt := range []struct {
		name   string
		owner  Owner
		edit   func(*dataset.Manifest)
		damage func(t *testing.T, dir string)
		reason string
	}{
		{"a manifest owned by another", ownerOf{disowned: manifestName}, nil, nil, "manifest.json: it is not owned by the account"},
		{"data owned by another", ownerOf{disowned: dataSuffix}, nil, nil, dataSuffix + ": it is not owned by the account"},
		{"a manifest too large", ownerOf{}, nil, func(t *testing.T, dir string) {
			grow(t, filepath.Join(dir, manifestName), 1<<20)
		}, "manifest"},
		{"a size over the dataset's limit", ownerOf{}, func(m *dataset.Manifest) { m.Size = wanted.MaxBytes() + 1 }, nil, "more than wanted may hold"},
		{"data longer than its manifest says", ownerOf{}, nil, func(t *testing.T, dir string) {
			grow(t, filepath.Join(dir, dataName), 16)
		}, "bytes when copied"},
		{"a checksum that is a path", ownerOf{}, func(m *dataset.Manifest) { m.SHA256 = "../../../escape" }, nil, "manifest refused"},
		{"data that is not what the manifest says", ownerOf{}, func(m *dataset.Manifest) { m.SHA256 = strings.Repeat("ab", 32) }, func(t *testing.T, dir string) {
			if err := os.Rename(filepath.Join(dir, dataName), filepath.Join(dir, strings.Repeat("ab", 32)+dataSuffix)); err != nil {
				t.Fatal(err)
			}
		}, "checksum"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s, from := stores(t)
			put(t, s, wanted, content, now.Add(-48*time.Hour), nil)
			put(t, from, wanted, newer, now.Add(-time.Hour), tt.edit)
			if tt.damage != nil {
				tt.damage(t, from.dir("wanted"))
			}

			got := adopt(t, s, from, tt.owner)
			if len(got) != 1 || got[0].Result != Refused || !strings.Contains(got[0].Reason, tt.reason) {
				t.Fatalf("outcomes %+v, want one refused for a reason naming %q", got, tt.reason)
			}
			if row := rowOf(t, s, known, "wanted"); row.DataDate != "2026-11-20" || row.Attention != "" {
				t.Errorf("row %+v, want the copy held unchanged and nothing recorded", row)
			}
			if left := staged(t, s); len(left) != 0 {
				t.Errorf("staging left behind: %q", left)
			}
		})
	}
}

// A manifest or data file that is a link is refused, whatever it leads to. A
// host that will not let the test make a link says so and the case is
// skipped.
func TestAdoptRefusesALink(t *testing.T) {
	newer := strings.Replace(content, "2026-11-20", "2026-11-21", 1)
	for _, name := range []string{manifestName, datasettest.DataName(newer)} {
		s, from := stores(t)
		put(t, s, wanted, content, now.Add(-48*time.Hour), nil)
		put(t, from, wanted, newer, now.Add(-time.Hour), nil)

		path := filepath.Join(from.dir("wanted"), name)
		real := path + ".real"
		if err := os.Rename(path, real); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(real, path); err != nil {
			t.Skipf("this host would not make a link: %v", err)
		}

		got := adopt(t, s, from, ownerOf{})
		if len(got) != 1 || got[0].Result != Refused {
			t.Fatalf("with %s a link: %+v, want it refused", name, got)
		}
		if row := rowOf(t, s, known, "wanted"); row.DataDate != "2026-11-20" {
			t.Errorf("with %s a link: row %+v, want the copy held unchanged", name, row)
		}
	}
}

// grow appends n bytes to the file at path.
func grow(t *testing.T, path string, n int) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(make([]byte, n)); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

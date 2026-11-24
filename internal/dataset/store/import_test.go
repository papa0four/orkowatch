// internal/dataset/store/import_test.go

package store

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/osfingerprint"
)

var (
	wanted = testDataset{Name: "wanted", Applies: true}
	known  = []dataset.Dataset{wanted, testDataset{Name: "elsewhere", Applies: false}}
)

// importFrom imports the directory src into s and returns the outcomes.
func importFrom(t *testing.T, s, src Store) []Outcome {
	t.Helper()
	outcomes, err := s.Import(context.Background(), src.root, known, &osfingerprint.OSInfo{}, now)
	if err != nil {
		t.Fatal(err)
	}
	return outcomes
}

// stores returns an empty store and an empty directory to import from.
func stores(t *testing.T) (Store, Store) {
	t.Helper()
	return Store{root: filepath.Join(t.TempDir(), "store")}, Store{root: t.TempDir()}
}

// names lists what the dataset id's directory holds.
func names(t *testing.T, s Store, id string) []string {
	t.Helper()
	entries, err := os.ReadDir(s.dir(id))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

// A dataset that passes every check is installed, and the store then holds
// its manifest and its data and nothing else.
func TestImportInstalls(t *testing.T) {
	s, src := stores(t)
	put(t, src, wanted, content, now.Add(-time.Hour), nil)

	got := importFrom(t, s, src)
	if len(got) != 1 || got[0] != (Outcome{ID: "wanted", Result: Installed, Attempts: 1}) {
		t.Fatalf("outcomes %+v", got)
	}
	if row := rowOf(t, s, known, "wanted"); row.State != dataset.StateCurrent || row.DataDate != "2026-11-20" || row.Attention != "" {
		t.Errorf("row %+v", row)
	}
	want := []string{filepath.Base(dataFile(s, wanted, content)), manifestName}
	if got := names(t, s, "wanted"); !slices.Equal(got, want) {
		t.Errorf("the dataset holds %q, want %q", got, want)
	}
}

// What is not a known dataset, or does not pass its checks, is refused with
// the reason, and nothing of it reaches the store.
func TestImportRefuses(t *testing.T) {
	s, src := stores(t)
	put(t, src, testDataset{Name: "retired"}, content, now.Add(-time.Hour), nil)
	if err := os.Mkdir(filepath.Join(src.root, "Not_A_Name"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src.root, "loose.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	put(t, src, wanted, content, now.Add(-time.Hour), nil)
	if err := os.WriteFile(dataFile(src, wanted, content), []byte(strings.Replace(content, "entries", "entriez", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src.root, ".hidden"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	reasons := map[string]string{}
	for _, o := range importFrom(t, s, src) {
		if o.Result != Refused || !o.NeedsAttention() {
			t.Errorf("%s: %s, want refused", o.ID, o.Result)
		}
		reasons[o.ID] = o.Reason
	}
	for id, want := range map[string]string{
		"Not_A_Name": "cannot name a dataset",
		"loose.json": "not a dataset directory",
		"retired":    "does not know",
		"wanted":     "checksum",
	} {
		if !strings.Contains(reasons[id], want) {
			t.Errorf("%s: reason %q, want one naming %q", id, reasons[id], want)
		}
	}
	if _, found := reasons[".hidden"]; found || len(reasons) != 4 {
		t.Errorf("outcomes for %v, want the four entries and not the hidden one", reasons)
	}
	if entries, err := os.ReadDir(s.root); err != nil || len(entries) != 1 || entries[0].Name() != lockName {
		t.Errorf("the store holds %v, %v, want only its lock", entries, err)
	}
}

// A held copy fetched no earlier than the one offered is kept, a dataset for
// another host is skipped, and neither needs attention.
func TestImportKeepsAndSkips(t *testing.T) {
	s, src := stores(t)
	put(t, s, wanted, content, now.Add(-time.Hour), nil)
	put(t, src, wanted, strings.Replace(content, "entries", "older", 1), now.Add(-2*time.Hour), nil)
	put(t, src, testDataset{Name: "elsewhere"}, content, now.Add(-time.Hour), nil)

	got := importFrom(t, s, src)
	if len(got) != 2 || got[0].ID != "elsewhere" || got[0].Result != Skipped || got[1].ID != "wanted" || got[1].Result != Kept {
		t.Fatalf("outcomes %+v, want elsewhere skipped and wanted kept", got)
	}
	for _, o := range got {
		if o.NeedsAttention() {
			t.Errorf("%s needs attention: %+v", o.ID, o)
		}
	}
	if _, err := os.Stat(s.dir("elsewhere")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the skipped dataset reached the store: %v", err)
	}
	if got := names(t, s, "wanted"); !slices.Contains(got, filepath.Base(dataFile(s, wanted, content))) {
		t.Errorf("the held copy was replaced: %q", got)
	}
}

// A newer copy replaces the one held, and the data it replaces, a partial
// file, and data no manifest names, which an interrupted install leaves, are
// deleted.
func TestImportReplacesAndSweeps(t *testing.T) {
	s, src := stores(t)
	put(t, s, wanted, content, now.Add(-48*time.Hour), nil)
	for _, stray := range []string{manifestName + partialSuffix, strings.Repeat("0", 64) + dataSuffix} {
		if err := os.WriteFile(filepath.Join(s.dir("wanted"), stray), []byte("left"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if row := rowOf(t, s, known, "wanted"); row.State != dataset.StateCurrent || !strings.Contains(row.Attention, "did not finish") {
		t.Errorf("an interrupted install gave %+v, want the held copy current and the install named", row)
	}

	newer := strings.Replace(content, "2026-11-20", "2026-11-21", 1)
	put(t, src, wanted, newer, now.Add(-time.Hour), nil)
	if got := importFrom(t, s, src); len(got) != 1 || got[0].Result != Installed {
		t.Fatalf("outcomes %+v", got)
	}
	want := []string{filepath.Base(dataFile(s, wanted, newer)), manifestName}
	slices.Sort(want)
	if got := names(t, s, "wanted"); !slices.Equal(got, want) {
		t.Errorf("the dataset holds %q, want %q", got, want)
	}
	if row := rowOf(t, s, known, "wanted"); row.DataDate != "2026-11-21" || row.Attention != "" {
		t.Errorf("row %+v, want the newer data and nothing to attend to", row)
	}
}

// An install that fails for a lasting reason is tried once, leaves the held
// copy readable, and is recorded, so status names it until an install of the
// dataset succeeds.
func TestImportRecordsAFailure(t *testing.T) {
	s, src := stores(t)
	put(t, s, wanted, content, now.Add(-48*time.Hour), nil)
	newer := strings.Replace(content, "2026-11-20", "2026-11-21", 1)
	put(t, src, wanted, newer, now.Add(-time.Hour), nil)
	blocker := dataFile(s, wanted, newer)
	if err := os.MkdirAll(filepath.Join(blocker, "inside"), 0o700); err != nil {
		t.Fatal(err)
	}

	got := importFrom(t, s, src)
	if len(got) != 1 || got[0].Result != Failed || got[0].Attempts != 1 || !got[0].NeedsAttention() {
		t.Fatalf("outcomes %+v, want one failed attempt", got)
	}
	row := rowOf(t, s, known, "wanted")
	if row.State != dataset.StateCurrent || row.DataDate != "2026-11-20" {
		t.Errorf("the held copy is %+v, want it current and unchanged", row)
	}
	if !strings.Contains(row.Attention, "failed after 1 attempt:") || !strings.Contains(row.Attention, "2026-11-22T12:00:00Z") {
		t.Errorf("attention %q, want the failure with its time and attempts", row.Attention)
	}
	wantFailureOf(t, row.Attention, opImport)

	if err := os.RemoveAll(blocker); err != nil {
		t.Fatal(err)
	}
	if got := importFrom(t, s, src); len(got) != 1 || got[0].Result != Installed {
		t.Fatalf("after the cause was removed: %+v", got)
	}
	if row := rowOf(t, s, known, "wanted"); row.Attention != "" || row.DataDate != "2026-11-21" {
		t.Errorf("row %+v, want the failure cleared", row)
	}
}

// wantFailureOf checks that attention names a failure of op and the command
// that runs op again.
func wantFailureOf(t *testing.T, attention string, op operation) {
	t.Helper()
	if !strings.HasPrefix(attention, "the "+string(op)+" at ") || !strings.HasSuffix(attention, "run owatch data "+string(op)+" again") {
		t.Errorf("attention %q, want the %s that failed and the command to run it again", attention, op)
	}
}

// A reason that ends in a period, as Windows writes its errors, is shown
// without it where the sentence goes on.
func TestFailureReasonEndingInAPeriod(t *testing.T) {
	s, _ := stores(t)
	put(t, s, wanted, content, now.Add(-48*time.Hour), nil)
	record := `{"operation":"refresh","attempts":3,"reason":"the target machine actively refused it.","at":"2026-11-22T12:00:00Z"}`
	if err := os.WriteFile(filepath.Join(s.dir("wanted"), failureName), []byte(record), 0o600); err != nil {
		t.Fatal(err)
	}
	if row := rowOf(t, s, known, "wanted"); !strings.Contains(row.Attention, "actively refused it; resolve the cause") {
		t.Errorf("attention %q, want the reason's period dropped before the advice", row.Attention)
	}
}

// A record that names an operation owatch does not know is refused as any
// unreadable record is, and status says to run either command.
func TestFailureRecordWithAnUnknownOperation(t *testing.T) {
	s, _ := stores(t)
	put(t, s, wanted, content, now.Add(-48*time.Hour), nil)
	record := `{"operation":"fetch","attempts":1,"reason":"for the test","at":"2026-11-22T12:00:00Z"}`
	if err := os.WriteFile(filepath.Join(s.dir("wanted"), failureName), []byte(record), 0o600); err != nil {
		t.Fatal(err)
	}
	row := rowOf(t, s, known, "wanted")
	if !strings.Contains(row.Attention, `cannot be read (it names the operation "fetch", which is neither import nor refresh)`) ||
		!strings.HasSuffix(row.Attention, "run owatch data refresh or owatch data import again") {
		t.Errorf("attention %q, want the record refused and both commands named", row.Attention)
	}
}

// A step that fails for a reason that passes is tried again and succeeds when
// the reason passes in time; one that keeps failing is given up after the
// attempts; one that fails for a lasting reason is not tried again.
func TestRetry(t *testing.T) {
	failing := func(times int, err error) func() error {
		return func() error {
			if times > 0 {
				times--
				return err
			}
			return nil
		}
	}
	for _, tt := range []struct {
		name     string
		step     func() error
		attempts int
		fails    bool
	}{
		{"passes on the third", failing(2, errPassing), 3, false},
		{"never passes", failing(maxAttempts, errPassing), maxAttempts, true},
		{"lasting", failing(1, fs.ErrPermission), 1, true},
		{"at once", failing(0, nil), 1, false},
	} {
		attempts, err := retry(context.Background(), tt.step)
		if attempts != tt.attempts || (err != nil) != tt.fails {
			t.Errorf("%s: %d attempts, %v; want %d, failing %v", tt.name, attempts, err, tt.attempts, tt.fails)
		}
	}
}

// Data that changed after it was checked is not copied into place, and no
// partial file is left.
func TestCopyRefusesChangedData(t *testing.T) {
	_, src := stores(t)
	put(t, src, wanted, content, now.Add(-time.Hour), nil)
	m, err := src.read(wanted, now, checkWith(wanted))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dataFile(src, wanted, content), []byte(strings.Replace(content, "entries", "entriez", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	to := filepath.Join(t.TempDir(), "copy")
	if err := copyVerified(dataFile(src, wanted, content), to, m); err == nil || !strings.Contains(err.Error(), "changed after it was checked") {
		t.Errorf("a changed file gave %v", err)
	}
	for _, path := range []string{to, to + partialSuffix} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s is there: %v", filepath.Base(path), err)
		}
	}
}

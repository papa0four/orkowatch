// cmd/commands/data_test.go

package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/papa0four/orkowatch/cmd/commands/delivery"
	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/dataset/datasettest"
	"github.com/papa0four/orkowatch/internal/dataset/store"
	"github.com/papa0four/orkowatch/internal/osfingerprint"
	"github.com/papa0four/orkowatch/internal/tui"
)

var dataNow = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

// testData is the data command over a store in a temporary directory that
// knows the test dataset, answering any question with answer.
func testData(t *testing.T, interactive bool, answer string) (*dataCmd, store.Store) {
	t.Helper()
	s := store.At(filepath.Join(t.TempDir(), "store"))
	return &dataCmd{
		known:       []dataset.Dataset{datasettest.Dataset{Name: "wanted", Applies: true}},
		open:        func(context.Context) (store.Store, error) { return s, nil },
		host:        func() (*osfingerprint.OSInfo, error) { return &osfingerprint.OSInfo{}, nil },
		now:         func() time.Time { return dataNow },
		interactive: func() bool { return interactive },
		in:          strings.NewReader(answer),
	}, s
}

// run executes owatch data with args over d and returns what it printed.
func run(d *dataCmd, args ...string) (string, error) {
	cmd := dataCommand(d)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

// A directory of sound datasets is imported with a line for each and no
// error; one with a refused dataset ends in an error naming how many; an
// empty one is an error.
func TestDataImport(t *testing.T) {
	d, _ := testData(t, false, "")
	src := t.TempDir()
	datasettest.Put(t, src, datasettest.Dataset{Name: "wanted"}, datasettest.Content, dataNow.Add(-time.Hour), nil)

	out, err := run(d, "import", src)
	if err != nil || out != "wanted: installed\n" {
		t.Errorf("import printed %q, %v", out, err)
	}

	datasettest.Put(t, src, datasettest.Dataset{Name: "retired"}, datasettest.Content, dataNow.Add(-time.Hour), nil)
	out, err = run(d, "import", src)
	if err == nil || !strings.Contains(err.Error(), "1 of the 2 datasets") {
		t.Errorf("a refused dataset gave %v", err)
	}
	if !strings.Contains(out, "retired: refused: this version of owatch does not know the dataset") ||
		!strings.Contains(out, "wanted: kept") {
		t.Errorf("import printed %q", out)
	}

	if _, err := run(d, "import", t.TempDir()); err == nil || !strings.Contains(err.Error(), "no dataset found") {
		t.Errorf("an empty directory gave %v", err)
	}
}

// A dataset is deleted with --yes, or when the operator says yes; it is kept
// when the answer is no, and when no one is at the terminal to ask.
func TestDataRemove(t *testing.T) {
	for _, tt := range []struct {
		name        string
		args        []string
		interactive bool
		answer      string
		deleted     bool
		fails       bool
	}{
		{"with --yes", []string{"remove", "--yes", "wanted"}, false, "", true, false},
		{"answered yes", []string{"remove", "wanted"}, true, "y\n", true, false},
		{"answered no", []string{"remove", "wanted"}, true, "n\n", false, false},
		{"no one to ask", []string{"remove", "wanted"}, false, "", false, true},
		{"not held", []string{"remove", "--yes", "absent"}, false, "", false, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			d, s := testData(t, tt.interactive, tt.answer)
			datasettest.Put(t, s.Root(), datasettest.Dataset{Name: "wanted"}, datasettest.Content, dataNow.Add(-time.Hour), nil)

			out, err := run(d, tt.args...)
			if (err != nil) != tt.fails {
				t.Errorf("printed %q, error %v", out, err)
			}
			_, statErr := os.Stat(filepath.Join(s.Root(), "wanted"))
			if deleted := errors.Is(statErr, os.ErrNotExist); deleted != tt.deleted {
				t.Errorf("deleted %v, want %v (%q)", deleted, tt.deleted, out)
			}
		})
	}
}

// An elevated run has no store, and import and remove say so.
func TestDataElevated(t *testing.T) {
	d, _ := testData(t, false, "")
	d.open = func(context.Context) (store.Store, error) { return store.Store{}, store.ErrElevated }
	for _, args := range [][]string{{"import", t.TempDir()}, {"remove", "--yes", "wanted"}} {
		if _, err := run(d, args...); !errors.Is(err, store.ErrElevated) {
			t.Errorf("%v gave %v, want ErrElevated", args, err)
		}
	}
}

// owatch data status saves a report named for the datasets module, which
// owatch browse reads back to the rows status found, in its own tab, opened
// first; its text is the store's own text.
func TestDataStatusReport(t *testing.T) {
	d, s := testData(t, false, "")
	datasettest.Put(t, s.Root(), datasettest.Dataset{Name: "wanted"}, datasettest.Content, dataNow.Add(-8*24*time.Hour), nil)
	dir := t.TempDir()

	for _, format := range []string{"json", "yaml"} {
		if _, err := run(d, "status", "-o", format, "--report-file", dir); err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		saved, err := filepath.Glob(filepath.Join(dir, "owatch-*-m.d-*."+format))
		if err != nil || len(saved) != 1 {
			t.Fatalf("%s: saved %v, %v", format, saved, err)
		}
		data, err := os.ReadFile(saved[0])
		if err != nil {
			t.Fatal(err)
		}
		f, _ := delivery.ParseFormat(format)
		report, err := decodeReport(saved[0], f, delivery.FormatText, data)
		if err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		if report.Start != tui.TabDatasets {
			t.Errorf("%s: opens on %q, want the datasets", format, report.Start)
		}
		at := slices.IndexFunc(report.Tabs, func(tab tui.Tab) bool { return tab.ID == tui.TabDatasets })
		if at < 0 || len(report.Tabs[at].Records) != 1 || report.Tabs[at].Records[0].Subtitle != string(dataset.StateOutOfSync) {
			t.Errorf("%s: tabs %+v, want the dataset out of sync", format, report.Tabs)
		}
		if !strings.HasPrefix(report.Text, "Store: "+s.Root()) || !strings.Contains(report.Text, "wanted  out of sync: data of 2026-11-20") {
			t.Errorf("%s: text %q", format, report.Text)
		}
		if err := os.Remove(saved[0]); err != nil {
			t.Fatal(err)
		}
	}
}

// An elevated run has no store, and status says so.
func TestDataStatusElevated(t *testing.T) {
	d, _ := testData(t, false, "")
	d.open = func(context.Context) (store.Store, error) { return store.Store{}, store.ErrElevated }
	if _, err := run(d, "status", "--plain"); err == nil || !strings.Contains(err.Error(), store.ErrElevated.Error()) {
		t.Errorf("status gave %v, want the elevated refusal", err)
	}
}

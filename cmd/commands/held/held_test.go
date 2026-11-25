// cmd/commands/held/held_test.go

package held

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/dataset/datasettest"
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

// internal/dataset/store/refresh_test.go

package store

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/osfingerprint"
)

// served is the test dataset with an origin, as a fetch needs.
var served = testDataset{Name: "wanted", Applies: true, From: dataset.Origin{
	URL: "https://data.example/wanted", License: "CC0 1.0", Attribution: "Served for the tests",
}}

// errBrief is a failure that says it passes, as a fetch says of a timeout.
type errBrief struct{}

func (errBrief) Error() string { return "the server is briefly unable to answer" }
func (errBrief) Passing() bool { return true }

// serving returns a fetch that fails with each of fails in turn and then
// writes data, and a count of how many times it ran.
func serving(data string, fails ...error) (Fetch, *int) {
	calls := new(int)
	return func(_ context.Context, _ dataset.Dataset, w io.Writer) error {
		*calls++
		if *calls <= len(fails) {
			// A failed fetch may have written part of the data first.
			if _, err := io.WriteString(w, data[:len(data)/2]); err != nil {
				return err
			}
			return fails[*calls-1]
		}
		_, err := io.WriteString(w, data)
		return err
	}, calls
}

// refresh runs a refresh of served with fetch and returns its one outcome.
func refresh(t *testing.T, s Store, fetch Fetch) Outcome {
	t.Helper()
	outcomes, err := s.Refresh(context.Background(), fetch, []dataset.Dataset{served}, &osfingerprint.OSInfo{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(outcomes) != 1 {
		t.Fatalf("outcomes %+v, want one", outcomes)
	}
	entries, err := os.ReadDir(s.root)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), stagingPrefix) {
			t.Errorf("the refresh left %s", e.Name())
		}
	}
	return outcomes[0]
}

// What is fetched is installed with a manifest recording its origin, the
// time, and the terms its source states, and staging an earlier refresh left
// is removed.
func TestRefreshInstalls(t *testing.T) {
	s, _ := stores(t)
	if err := os.MkdirAll(s.dir(stagingPrefix+"left"), 0o700); err != nil {
		t.Fatal(err)
	}
	fetch, calls := serving(content)

	if got := refresh(t, s, fetch); got != (Outcome{ID: "wanted", Result: Installed, Attempts: 1}) || *calls != 1 {
		t.Fatalf("outcome %+v after %d fetches", got, *calls)
	}
	row := rowOf(t, s, []dataset.Dataset{served}, "wanted")
	want := dataset.Row{
		ID: "wanted", State: dataset.StateCurrent, Source: "https://data.example/wanted", DataDate: "2026-11-20",
		Fetched: "2026-11-22T12:00:00Z", Size: int64(len(content)), License: "CC0 1.0", Attribution: "Served for the tests",
	}
	if row != want {
		t.Errorf("row %+v, want %+v", row, want)
	}
}

// A fetch that fails for a reason that passes is tried again, and what it
// serves once it clears is installed.
func TestRefreshRetriesAPassingFailure(t *testing.T) {
	s, _ := stores(t)
	put(t, s, served, content, now.Add(-48*time.Hour), nil)
	fetch, calls := serving(strings.Replace(content, "2026-11-20", "2026-11-21", 1), errBrief{}, errBrief{})

	if got := refresh(t, s, fetch); got.Result != Installed || *calls != 3 {
		t.Fatalf("outcome %+v after %d fetches, want it installed on the third", got, *calls)
	}
	if row := rowOf(t, s, []dataset.Dataset{served}, "wanted"); row.DataDate != "2026-11-21" || row.Attention != "" {
		t.Errorf("row %+v, want the newer data", row)
	}
}

// A fetch that never clears fails after three attempts, and one that fails
// for a lasting reason after one. Either leaves the copy held as it was and
// is recorded for status.
func TestRefreshRecordsAFailure(t *testing.T) {
	for name, fails := range map[string][]error{
		"never clears": {errBrief{}, errBrief{}, errBrief{}},
		"lasting":      {errors.New("the server answered 404")},
	} {
		t.Run(name, func(t *testing.T) {
			s, _ := stores(t)
			put(t, s, served, content, now.Add(-48*time.Hour), nil)
			fetch, calls := serving(content, fails...)

			got := refresh(t, s, fetch)
			if got.Result != Failed || *calls != len(fails) || got.Attempts != len(fails) || !got.NeedsAttention() {
				t.Fatalf("outcome %+v after %d fetches, want it failed after %d", got, *calls, len(fails))
			}
			row := rowOf(t, s, []dataset.Dataset{served}, "wanted")
			if row.State != dataset.StateCurrent || row.DataDate != "2026-11-20" || !strings.Contains(row.Attention, "failed after") {
				t.Errorf("row %+v, want the held copy current and the failure named", row)
			}
		})
	}
}

// Data that is not what the source publishes, and data past the dataset's
// limit, are not installed: the copy held stays and the refresh is recorded
// as failed.
func TestRefreshRefusesBadData(t *testing.T) {
	for name, data := range map[string]string{
		"not the format": strings.Replace(content, "owatch-test-dataset", "owatch-other-format", 1),
		"over the limit": content + strings.Repeat("x", int(served.MaxBytes())),
	} {
		t.Run(name, func(t *testing.T) {
			s, _ := stores(t)
			put(t, s, served, content, now.Add(-48*time.Hour), nil)
			fetch, _ := serving(data)

			if got := refresh(t, s, fetch); got.Result != Failed || got.Attempts != 1 {
				t.Fatalf("outcome %+v, want one failed attempt", got)
			}
			row := rowOf(t, s, []dataset.Dataset{served}, "wanted")
			if row.State != dataset.StateCurrent || row.DataDate != "2026-11-20" || row.Attention == "" {
				t.Errorf("row %+v, want the held copy current and the failure named", row)
			}
		})
	}
}

// A directory refreshed to carry is one import reads on another host.
func TestRefreshToADirectoryThenImport(t *testing.T) {
	carried, _ := stores(t)
	fetch, _ := serving(content)
	if got := refresh(t, carried, fetch); got.Result != Installed {
		t.Fatalf("refresh into the directory: %+v", got)
	}

	s, _ := stores(t)
	outcomes, err := s.Import(context.Background(), carried.root, []dataset.Dataset{served}, &osfingerprint.OSInfo{}, now)
	if err != nil || len(outcomes) != 1 || outcomes[0].Result != Installed {
		t.Fatalf("import of the directory: %+v, %v", outcomes, err)
	}
	if row := rowOf(t, s, []dataset.Dataset{served}, "wanted"); row.State != dataset.StateCurrent || row.Source != "https://data.example/wanted" {
		t.Errorf("row %+v", row)
	}
}

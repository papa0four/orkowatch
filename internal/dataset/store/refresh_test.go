// internal/dataset/store/refresh_test.go

package store

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/dataset/datasettest"
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
	return func(_ context.Context, d dataset.Dataset, w io.Writer) (dataset.Place, error) {
		*calls++
		source := dataset.Place{URL: d.Origin(nil).URL}
		if *calls <= len(fails) {
			// A failed fetch may have written part of the data first.
			if _, err := io.WriteString(w, data[:len(data)/2]); err != nil {
				return source, err
			}
			return source, fails[*calls-1]
		}
		_, err := io.WriteString(w, data)
		return source, err
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

	if got := refresh(t, s, fetch); !installedWanted(got) || *calls < 1 || *calls > maxAttempts {
		t.Fatalf("outcome %+v after %d fetches", got, *calls)
	}
	row := rowOf(t, s, []dataset.Dataset{served}, "wanted")
	want := dataset.Row{Provenance: dataset.Provenance{
		ID: "wanted", State: dataset.StateCurrent, Source: "https://data.example/wanted", DataDate: "2026-11-20", Version: datasettest.Version,
		Fetched: "2026-11-22T12:00:00Z", License: "CC0 1.0", Attribution: "Served for the tests",
	}, Size: int64(len(content))}
	if row != want {
		t.Errorf("row %+v, want %+v", row, want)
	}
}

// The manifest's source and standing are those of the place the fetch says
// it fetched from, which for an origin with more than one place or an index
// is not the origin's own address; a fetch that gives no address is refused at the check, as a
// manifest with no source is.
func TestRefreshRecordsWhereItFetched(t *testing.T) {
	s, _ := stores(t)
	from := func(address, standing string) Fetch {
		return func(_ context.Context, _ dataset.Dataset, w io.Writer) (dataset.Place, error) {
			_, err := io.WriteString(w, content)
			return dataset.Place{URL: address, Standing: standing}, err
		}
	}
	const mirror = "https://mirror.example/repodata/0123-wanted.zst"
	if got := refresh(t, s, from(mirror, "archived")); got.Result != Installed {
		t.Fatalf("outcome %+v", got)
	}
	if row := rowOf(t, s, []dataset.Dataset{served}, "wanted"); row.Source != mirror || row.Standing != "archived" || row.License != "CC0 1.0" {
		t.Errorf("row %+v, want the source %s, its standing, and the origin's terms", row, mirror)
	}
	plain, _ := stores(t)
	if got := refresh(t, plain, from(mirror, "")); got.Result != Installed {
		t.Fatalf("outcome %+v", got)
	}
	if row := rowOf(t, plain, []dataset.Dataset{served}, "wanted"); row.Standing != "" {
		t.Errorf("a refresh from a place with no standing kept %q", row.Standing)
	}
	if got := refresh(t, s, from("", "")); got.Result == Installed {
		t.Errorf("a fetch that gave no address was installed: %+v", got)
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
			wantFailureOf(t, row.Attention, opRefresh)
		})
	}
}

// An install that fails after the fetch succeeded is a failed refresh, and
// status names the refresh and the command to run again.
func TestRefreshRecordsAFailedInstall(t *testing.T) {
	s, _ := stores(t)
	put(t, s, served, content, now.Add(-48*time.Hour), nil)
	newer := strings.Replace(content, "2026-11-20", "2026-11-21", 1)
	blocker := dataFile(s, served, newer)
	if err := os.MkdirAll(filepath.Join(blocker, "inside"), 0o700); err != nil {
		t.Fatal(err)
	}
	fetch, _ := serving(newer)

	if got := refresh(t, s, fetch); got.Result != Failed {
		t.Fatalf("outcome %+v, want the install failed", got)
	}
	row := rowOf(t, s, []dataset.Dataset{served}, "wanted")
	if row.DataDate != "2026-11-20" {
		t.Errorf("row %+v, want the held copy unchanged", row)
	}
	wantFailureOf(t, row.Attention, opRefresh)
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
			wantFailureOf(t, row.Attention, opRefresh)
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

// keeping is the served test dataset keeping less than its origin serves:
// the origin may serve 4 KiB, and what is kept is the fetched file's first
// keep bytes, or an error when keep is negative.
type keeping struct {
	testDataset
	keep int
}

func (keeping) FetchMaxBytes() int64 { return 4 << 10 }

func (k keeping) Keep(fetched io.ReaderAt, size int64, _ *osfingerprint.OSInfo, kept io.Writer) error {
	if k.keep < 0 {
		return errors.New("not what the source publishes")
	}
	_, err := io.Copy(kept, io.NewSectionReader(fetched, 0, min(size, int64(k.keep))))
	return err
}

// A dataset that keeps less than its origin serves is fetched up to the
// origin's limit and holds only what it keeps, under that data's checksum,
// with the fetched file recorded beside it and not held. A file past the
// origin's limit, kept data past the dataset's own, and a file the dataset
// will not keep from are each refused, leaving the copy held.
func TestRefreshKeepsLessThanItFetches(t *testing.T) {
	fetched := content + strings.Repeat("x", 2<<10)
	refreshWith := func(t *testing.T, d keeping, data string) (Store, Outcome) {
		t.Helper()
		s, _ := stores(t)
		put(t, s, d, content, now.Add(-48*time.Hour), nil)
		fetch, _ := serving(data)
		outcomes, err := s.Refresh(context.Background(), fetch, []dataset.Dataset{d}, &osfingerprint.OSInfo{}, now)
		if err != nil || len(outcomes) != 1 {
			t.Fatalf("outcomes %+v, %v", outcomes, err)
		}
		return s, outcomes[0]
	}

	d := keeping{testDataset: served, keep: len(content)}
	s, got := refreshWith(t, d, fetched)
	if got.Result != Installed {
		t.Fatalf("outcome %+v, want it installed", got)
	}
	m, err := readManifest(filepath.Join(s.dir("wanted"), manifestName))
	if err != nil {
		t.Fatal(err)
	}
	if want := datasettest.DataName(content); m.SHA256+dataSuffix != want || m.Size != int64(len(content)) ||
		m.OriginSHA256+dataSuffix != datasettest.DataName(fetched) || m.OriginSize != int64(len(fetched)) {
		t.Errorf("manifest %+v, want the kept data's checksum and size and the fetched file's beside them", m)
	}
	if held := names(t, s, "wanted"); len(held) != 2 || !slices.Contains(held, datasettest.DataName(content)) {
		t.Errorf("the dataset holds %q, want its manifest and the kept data only", held)
	}

	// Each is refused as it is written, before anything is installed.
	for name, tt := range map[string]struct {
		d      keeping
		data   string
		reason string
	}{
		"a file past the origin's limit":   {d, content + strings.Repeat("x", 4<<10), "more than 4096 bytes"},
		"kept data past the dataset's":     {keeping{testDataset: served, keep: datasettest.MaxBytes + 1}, content + strings.Repeat("x", 2<<10), "more than 1024 bytes"},
		"a file the dataset will not keep": {keeping{testDataset: served, keep: -1}, fetched, "not what the source publishes"},
	} {
		t.Run(name, func(t *testing.T) {
			s, got := refreshWith(t, tt.d, tt.data)
			if got.Result != Failed || !strings.Contains(got.Reason, tt.reason) {
				t.Fatalf("outcome %+v, want it failed naming %q", got, tt.reason)
			}
			if row := rowOf(t, s, []dataset.Dataset{tt.d}, "wanted"); row.DataDate != "2026-11-20" || row.Fetched != "2026-11-20T12:00:00Z" {
				t.Errorf("row %+v, want the copy held", row)
			}
		})
	}
}

// errAway is a fetch that could make no connection at all, as on a host with
// no network.
type errAway struct{}

func (errAway) Error() string     { return "no connection could be made" }
func (errAway) Passing() bool     { return true }
func (errAway) Unreachable() bool { return true }

// A fetch that can make no connection stops the refresh there: the datasets
// after it are not fetched, the one that failed is recorded, and the refresh
// says the network could not be reached.
func TestRefreshStopsWhenUnreachable(t *testing.T) {
	s, _ := stores(t)
	other := testDataset{Name: "other", Applies: true, From: served.From}
	var fetched []string
	fetch := func(_ context.Context, d dataset.Dataset, _ io.Writer) (dataset.Place, error) {
		fetched = append(fetched, d.ID())
		return dataset.Place{}, errAway{}
	}
	outcomes, err := s.Refresh(context.Background(), fetch, []dataset.Dataset{served, other}, &osfingerprint.OSInfo{}, now)
	if !errors.Is(err, ErrUnreachable) || !strings.Contains(err.Error(), "no connection could be made") {
		t.Errorf("the refresh ended with %v, want the network unreachable", err)
	}
	if slices.Contains(fetched, "other") {
		t.Errorf("fetched %q after the network could not be reached", fetched)
	}
	if len(outcomes) != 1 || outcomes[0].ID != "wanted" || outcomes[0].Result != Failed {
		t.Errorf("outcomes %+v, want the one that failed", outcomes)
	}
}

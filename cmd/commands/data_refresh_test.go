// cmd/commands/data_refresh_test.go

package cmd

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
	"github.com/papa0four/orkowatch/internal/dataset/store"
	"github.com/papa0four/orkowatch/internal/osfingerprint"
)

// served stands in for the datasets' origins: the size each states, what
// each sends, and a record of which were fetched.
type served struct {
	sizes   map[string]int64
	fails   map[string]error
	fetched []string
}

func (s *served) Size(_ context.Context, d dataset.Dataset) (int64, bool, error) {
	size, stated := s.sizes[d.ID()]
	return size, stated, nil
}

// TimeLimit allows every download ten minutes.
func (*served) TimeLimit(int64) time.Duration { return 10 * time.Minute }

func (s *served) Fetch(_ context.Context, d dataset.Dataset, w io.Writer) error {
	s.fetched = append(s.fetched, d.ID())
	if err := s.fails[d.ID()]; err != nil {
		return err
	}
	_, err := io.WriteString(w, datasettest.Content)
	return err
}

// forDebian is a test dataset that applies to Debian hosts alone.
type forDebian struct{ datasettest.Dataset }

func (forDebian) AppliesTo(host *osfingerprint.OSInfo) bool { return host.Platform == "debian" }

// at is the origin of the test dataset named id.
func at(id string) dataset.Origin {
	return dataset.Origin{URL: "https://data.example/" + id, License: "CC0 1.0", Attribution: "Served for the tests"}
}

// refreshing is the data command over a store in a temporary directory that
// knows one dataset for every host and one for Debian, fetched from origins.
func refreshing(t *testing.T, interactive bool, answer string) (*dataCmd, store.Store, *served) {
	t.Helper()
	d, s := testData(t, interactive, answer)
	origins := &served{sizes: map[string]int64{"wanted": int64(len(datasettest.Content))}, fails: map[string]error{}}
	d.known = []dataset.Dataset{
		datasettest.Dataset{Name: "wanted", Applies: true, From: at("wanted")},
		forDebian{datasettest.Dataset{Name: "debian-data", From: at("debian-data")}},
	}
	d.fetcher = func() (fetcher, error) { return origins, nil }
	return d, s, origins
}

// holds reports whether the store in root holds the dataset id.
func holds(root, id string) bool {
	_, err := os.Stat(filepath.Join(root, id, "manifest.json"))
	return err == nil
}

// refresh fetches the datasets that apply to the host, and no other, prints
// each one's size and where it comes from, shows each step as it begins and
// ends, and installs what it fetched.
func TestDataRefresh(t *testing.T) {
	d, s, origins := refreshing(t, false, "")
	out, err := run(d, "refresh")
	if err != nil || out != "wanted: 39 B from https://data.example/wanted, allowed 10m0s\n"+
		"wanted: downloading 39 B\nwanted: downloaded 39 B in 0s\nwanted: checking\nwanted: checked in 0s\n"+
		"wanted: installing\nwanted: installed in 0s\nwanted: installed\n" {
		t.Errorf("refresh printed %q, %v", out, err)
	}
	if !slices.Equal(origins.fetched, []string{"wanted"}) || !holds(s.Root(), "wanted") || holds(s.Root(), "debian-data") {
		t.Errorf("fetched %q; the store holds wanted %v", origins.fetched, holds(s.Root(), "wanted"))
	}

	d.known = nil
	out, err = run(d, "refresh")
	if err != nil || !strings.Contains(out, "knows no dataset for this host") {
		t.Errorf("with no dataset known: %q, %v", out, err)
	}
}

// A dataset that could not be fetched is reported with the reason, and the
// command ends in an error.
func TestDataRefreshReportsAFailure(t *testing.T) {
	d, s, origins := refreshing(t, false, "")
	origins.fails["wanted"] = errors.New("https://data.example/wanted answered 404 Not Found")
	out, err := run(d, "refresh")
	if err == nil || !strings.Contains(err.Error(), "1 of 1 dataset not refreshed") {
		t.Errorf("a failed fetch gave %v", err)
	}
	if !strings.Contains(out, "wanted: failed after 1 attempt: https://data.example/wanted answered 404 Not Found") || holds(s.Root(), "wanted") {
		t.Errorf("refresh printed %q", out)
	}
}

// A dataset larger than 100 MiB is fetched with --yes, or when the operator
// agrees; it is not fetched when the operator declines, or when no one is at
// the terminal, and the command then ends in an error. A server that does not
// state a size is taken at the most the dataset may hold, which is small.
func TestDataRefreshAsksBeforeALargeDownload(t *testing.T) {
	for _, tt := range []struct {
		name        string
		args        []string
		interactive bool
		answer      string
		fetched     bool
	}{
		{"with --yes", []string{"refresh", "--yes"}, false, "", true},
		{"agreed to", []string{"refresh"}, true, "y\n", true},
		{"declined", []string{"refresh"}, true, "n\n", false},
		{"no one to ask", []string{"refresh"}, false, "", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			d, s, origins := refreshing(t, tt.interactive, tt.answer)
			origins.sizes["wanted"] = largeDownload + 1

			out, err := run(d, tt.args...)
			if (err == nil) != tt.fetched || holds(s.Root(), "wanted") != tt.fetched || (len(origins.fetched) == 1) != tt.fetched {
				t.Errorf("printed %q, error %v, fetched %q", out, err, origins.fetched)
			}
			if !strings.Contains(out, "wanted: 100.0 MiB from") {
				t.Errorf("the size was not stated: %q", out)
			}
		})
	}

	d, s, origins := refreshing(t, false, "")
	delete(origins.sizes, "wanted")
	out, err := run(d, "refresh")
	if err != nil || !holds(s.Root(), "wanted") || !strings.Contains(out, "wanted: up to 1.0 KiB from") {
		t.Errorf("with no size stated: %q, %v", out, err)
	}
}

// --to with --for fetches the datasets of the host named into a directory,
// which import then installs on that host; --for alone, and a host that is
// not one, are refused before anything is fetched.
func TestDataRefreshForAnotherHost(t *testing.T) {
	d, s, origins := refreshing(t, false, "")
	origins.sizes["debian-data"] = int64(len(datasettest.Content))
	carried := filepath.Join(t.TempDir(), "carried")

	out, err := run(d, "refresh", "--to", carried, "--for", "linux/debian/12.8")
	if err != nil || !holds(carried, "wanted") || !holds(carried, "debian-data") || holds(s.Root(), "wanted") {
		t.Fatalf("refresh --to --for printed %q, %v", out, err)
	}

	d.host = func() (*osfingerprint.OSInfo, error) {
		return &osfingerprint.OSInfo{OS: "linux", Platform: "debian"}, nil
	}
	out, err = run(d, "import", carried)
	if err != nil || !holds(s.Root(), "wanted") || !holds(s.Root(), "debian-data") {
		t.Errorf("import of the directory printed %q, %v", out, err)
	}

	fetched := len(origins.fetched)
	for _, args := range [][]string{
		{"refresh", "--for", "linux/debian/12"},
		{"refresh", "--to", carried, "--for", "plan9"},
		{"refresh", "--to", carried, "--for", "linux/debian/12/extra"},
		{"refresh", "--to", carried, "--for", "/debian"},
	} {
		if _, err := run(d, args...); err == nil {
			t.Errorf("%v was accepted", args)
		}
	}
	if len(origins.fetched) != fetched {
		t.Errorf("a refused refresh fetched: %q", origins.fetched)
	}
}

// refresh refuses in an elevated process, with or without --to and whatever
// else is given, says what to do instead, and builds nothing that connects.
func TestDataRefreshRefusesElevated(t *testing.T) {
	d, s, origins := refreshing(t, true, "y\n")
	d.elevated = func() bool { return true }
	d.fetcher = func() (fetcher, error) {
		t.Error("an elevated refresh asked for a fetcher")
		return origins, nil
	}
	for _, args := range [][]string{{"refresh"}, {"refresh", "--yes"}, {"refresh", "--to", t.TempDir(), "--for", "windows"}} {
		_, err := run(d, args...)
		if !errors.Is(err, errRefreshElevated) || !strings.Contains(err.Error(), "owatch data import") {
			t.Errorf("%v gave %v, want the elevated refusal", args, err)
		}
	}
	if len(origins.fetched) != 0 || holds(s.Root(), "wanted") {
		t.Errorf("an elevated refresh fetched %q", origins.fetched)
	}
}

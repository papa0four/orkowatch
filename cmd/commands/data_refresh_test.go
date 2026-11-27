// cmd/commands/data_refresh_test.go

package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/dataset/datasettest"
	"github.com/papa0four/orkowatch/internal/dataset/fetch"
	"github.com/papa0four/orkowatch/internal/dataset/store"
	"github.com/papa0four/orkowatch/internal/osfingerprint"
)

// served stands in for the datasets' origins: the size each states, the
// address each is found at when it is not its origin's own, or the error
// locating it gives; what each sends; and a record of which were located and
// which fetched, and from where.
type served struct {
	sizes      map[string]int64
	addresses  map[string]string
	locateErrs map[string]error
	fails      map[string]error
	located    []string
	fetched    []string
	from       []string
}

func (s *served) Locate(_ context.Context, d dataset.Dataset, host *osfingerprint.OSInfo) (fetch.Source, error) {
	s.located = append(s.located, d.ID())
	if err := s.locateErrs[d.ID()]; err != nil {
		return fetch.Source{}, err
	}
	origin := d.Origin(host)
	address, ok := s.addresses[d.ID()]
	if !ok {
		address = origin.URL
	}
	size, stated := s.sizes[d.ID()]
	return fetch.Source{Origin: origin, URL: address, Size: size, Stated: stated}, nil
}

// TimeLimit allows every download ten minutes.
func (*served) TimeLimit(int64) time.Duration { return 10 * time.Minute }

func (s *served) Fetch(_ context.Context, d dataset.Dataset, src fetch.Source, w io.Writer) error {
	s.fetched = append(s.fetched, d.ID())
	s.from = append(s.from, src.URL)
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
	if err != nil || !matchesWhole(regexp.QuoteMeta("wanted: 39 B from https://data.example/wanted, allowed 10m0s\n")+
		downloadedLines("wanted", "39 B", "39 B")+regexp.QuoteMeta("wanted: checking\nwanted: checked in 0s\n")+installedLines("wanted"), out) {
		t.Errorf("refresh printed %q, %v", out, err)
	}
	if !fetchedOnly(origins.fetched, "wanted") || !holds(s.Root(), "wanted") || holds(s.Root(), "debian-data") {
		t.Errorf("fetched %q; the store holds wanted %v", origins.fetched, holds(s.Root(), "wanted"))
	}

	d.known = nil
	out, err = run(d, "refresh")
	if err != nil || !strings.Contains(out, "knows no dataset for this host") {
		t.Errorf("with no dataset known: %q, %v", out, err)
	}
}

// unreachable is a fetch that could make no connection at all, as the fetch
// package reports one on a host with no network.
type unreachable struct{}

func (unreachable) Error() string     { return "no connection could be made" }
func (unreachable) Unreachable() bool { return true }

// With no network, refresh stops at the first dataset it cannot reach, prints
// what happened to it, says the network could not be reached, and names the
// route for a host with no network, with this host's target for --for.
func TestDataRefreshWithNoNetwork(t *testing.T) {
	d, _, origins := refreshing(t, false, "")
	d.host = func() (*osfingerprint.OSInfo, error) {
		return &osfingerprint.OSInfo{OS: "linux", Platform: "debian", PlatformVersion: "12"}, nil
	}
	origins.fails["wanted"] = unreachable{}
	out, err := run(d, "refresh")
	if !strings.Contains(out, "wanted: failed after 1 attempt: no connection could be made") {
		t.Errorf("refresh printed %q", out)
	}
	if slices.Contains(origins.fetched, "debian-data") {
		t.Errorf("fetched %q after the network could not be reached", origins.fetched)
	}
	if err == nil || !errors.Is(err, store.ErrUnreachable) ||
		!strings.Contains(err.Error(), `owatch data refresh --to <directory> --for "linux/debian/12" on a host with one, and owatch data import <directory> here`) {
		t.Errorf("with no network refresh ended with %v", err)
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
			if (err == nil) != tt.fetched || holds(s.Root(), "wanted") != tt.fetched || fetchedOnly(origins.fetched, "wanted") != tt.fetched {
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

// A plan holds each dataset that applies to the host with its download as its
// origin states it, or the most a fetch may read when it states none, and
// whether it is large; it fetches nothing, builds no fetcher when nothing
// applies, and refuses an elevated process before building one.
func TestPlanRefresh(t *testing.T) {
	debian := &osfingerprint.OSInfo{OS: "linux", Platform: "debian", PlatformVersion: "12"}
	d, _, origins := refreshing(t, false, "")
	origins.sizes["debian-data"] = largeDownload + 1
	plan, err := d.planRefresh(context.Background(), debian)
	if err != nil || len(plan.datasets) != 2 || plan.host != debian {
		t.Fatalf("plan %+v, %v", plan, err)
	}
	wanted, debianData := plan.datasets[0], plan.datasets[1]
	if wanted.dataset.ID() != "wanted" || wanted.size != int64(len(datasettest.Content)) || !wanted.stated || wanted.allowed != 10*time.Minute || wanted.large() {
		t.Errorf("wanted planned as %+v", wanted)
	}
	if debianData.dataset.ID() != "debian-data" || !debianData.large() {
		t.Errorf("debian-data planned as %+v", debianData)
	}
	if got, want := wanted.String(), "wanted: 39 B from https://data.example/wanted, allowed 10m0s"; got != want {
		t.Errorf("the line is %q, want %q", got, want)
	}
	if got, want := wanted.brief(), "wanted: 39 B, allowed 10m0s"; got != want {
		t.Errorf("the brief line is %q, want %q", got, want)
	}

	delete(origins.sizes, "wanted")
	plan, err = d.planRefresh(context.Background(), &osfingerprint.OSInfo{OS: "linux", Platform: "ubuntu"})
	if err != nil || len(plan.datasets) != 1 || plan.datasets[0].stated || plan.datasets[0].size != dataset.FetchLimit(plan.datasets[0].dataset) ||
		!strings.HasPrefix(plan.datasets[0].String(), "wanted: up to ") {
		t.Errorf("with no size stated, on a host only wanted applies to: %+v, %v", plan, err)
	}

	built := false
	d.fetcher = func() (fetcher, error) { built = true; return origins, nil }
	d.known = nil
	if plan, err := d.planRefresh(context.Background(), debian); err != nil || len(plan.datasets) != 0 || built {
		t.Errorf("with nothing known: %+v, %v, a fetcher built %v", plan, err, built)
	}
	d.known = []dataset.Dataset{datasettest.Dataset{Name: "wanted", Applies: true}}
	d.elevated = func() bool { return true }
	if _, err := d.planRefresh(context.Background(), debian); !errors.Is(err, errRefreshElevated) || built {
		t.Errorf("elevated: %v, a fetcher built %v", err, built)
	}
	if len(origins.fetched) != 0 {
		t.Errorf("planning fetched %q", origins.fetched)
	}
}

// steps records the steps a store reports, as id and step.
type steps []string

func (s *steps) Began(id string, step store.Step, _ int) { *s = append(*s, id+" "+string(step)) }
func (*steps) Received(string, int64)                    {}
func (*steps) Ended(string, store.Step, error)           {}

// A plan fetches what was chosen of it and no other, telling the progress it
// is given each step, and a fetch that can make no connection ends the
// refresh as unreachable.
func TestRefreshPlanFetch(t *testing.T) {
	debian := &osfingerprint.OSInfo{OS: "linux", Platform: "debian", PlatformVersion: "12"}
	d, s, origins := refreshing(t, false, "")
	plan, err := d.planRefresh(context.Background(), debian)
	if err != nil || len(plan.datasets) != 2 {
		t.Fatalf("plan %+v, %v", plan, err)
	}
	var told steps
	outcomes, err := plan.fetch(context.Background(), s, plan.datasets[:1], dataNow, &told)
	if err != nil || len(outcomes) != 1 || outcomes[0].ID != "wanted" || outcomes[0].Result != store.Installed {
		t.Errorf("outcomes %+v, %v", outcomes, err)
	}
	if !fetchedOnly(origins.fetched, "wanted") || !holds(s.Root(), "wanted") || holds(s.Root(), "debian-data") {
		t.Errorf("fetched %q", origins.fetched)
	}
	if !slices.Contains(told, "wanted download") || !slices.Contains(told, "wanted check") || !slices.Contains(told, "wanted install") {
		t.Errorf("the progress was told %q", told)
	}

	origins.fails["debian-data"] = unreachable{}
	if _, err := plan.fetch(context.Background(), s, plan.datasets[1:], dataNow, &told); !errors.Is(err, store.ErrUnreachable) {
		t.Errorf("with no network the fetch ended with %v", err)
	}
}

// A download of exactly 100 MiB is not large: it is planned as not large and
// fetched without a question, where one byte more is asked about.
func TestDataRefreshAtTheLargeLimit(t *testing.T) {
	d, s, origins := refreshing(t, false, "")
	origins.sizes["wanted"] = largeDownload
	plan, err := d.planRefresh(context.Background(), &osfingerprint.OSInfo{})
	if err != nil || len(plan.datasets) != 1 || plan.datasets[0].large() {
		t.Fatalf("at the limit planned %+v, %v", plan, err)
	}
	if out, err := run(d, "refresh"); err != nil || !holds(s.Root(), "wanted") || strings.Contains(out, "not fetched") {
		t.Errorf("at the limit refresh printed %q, %v", out, err)
	}
}

// A dataset that could not be located is taken as no size stated: the most
// the dataset may hold, named as up to that from its origin's own address.
// It is located again when it is fetched, and fetched from where it is then
// found.
func TestPlanRefreshWithALocateThatFails(t *testing.T) {
	d, s, origins := refreshing(t, false, "")
	origins.locateErrs = map[string]error{"wanted": errors.New("HEAD answered 500")}
	plan, err := d.planRefresh(context.Background(), &osfingerprint.OSInfo{})
	if err != nil || len(plan.datasets) != 1 {
		t.Fatalf("plan %+v, %v", plan, err)
	}
	p := plan.datasets[0]
	if p.stated || p.size != dataset.FetchLimit(p.dataset) || p.String() != fmt.Sprintf("wanted: up to %s from https://data.example/wanted, allowed 10m0s", dataset.Size(p.size)) {
		t.Errorf("with locating failing, planned %+v as %q", p, p.String())
	}

	delete(origins.locateErrs, "wanted")
	origins.addresses = map[string]string{"wanted": "https://mirror.example/wanted"}
	if _, err := plan.fetch(context.Background(), s, plan.datasets, dataNow, &steps{}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(origins.located, []string{"wanted", "wanted"}) || !slices.Equal(origins.from, []string{"https://mirror.example/wanted"}) {
		t.Errorf("located %q and fetched from %q", origins.located, origins.from)
	}
}

// A dataset found somewhere other than its origin's own address is named by
// where it was found, and fetched from there without being located again.
func TestPlanRefreshNamesWhereItWasFound(t *testing.T) {
	d, s, origins := refreshing(t, false, "")
	origins.addresses = map[string]string{"wanted": "https://mirror.example/repodata/0123-wanted.zst"}
	plan, err := d.planRefresh(context.Background(), &osfingerprint.OSInfo{})
	if err != nil || len(plan.datasets) != 1 {
		t.Fatalf("plan %+v, %v", plan, err)
	}
	if got, want := plan.datasets[0].String(), "wanted: 39 B from https://mirror.example/repodata/0123-wanted.zst, allowed 10m0s"; got != want {
		t.Errorf("the line is %q, want %q", got, want)
	}
	if _, err := plan.fetch(context.Background(), s, plan.datasets, dataNow, &steps{}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(origins.located, []string{"wanted"}) || !slices.Equal(origins.from, []string{"https://mirror.example/repodata/0123-wanted.zst"}) {
		t.Errorf("located %q and fetched from %q", origins.located, origins.from)
	}
	view, err := s.Status(d.known, &osfingerprint.OSInfo{}, dataNow)
	if err != nil || len(view.Datasets) != 1 || view.Datasets[0].Source != "https://mirror.example/repodata/0123-wanted.zst" {
		t.Errorf("the store holds %+v, %v, want the source where it was found", view, err)
	}
}

// A fetcher that cannot be built ends the plan with its error and plans
// nothing.
func TestPlanRefreshWithNoFetcher(t *testing.T) {
	d, _, _ := refreshing(t, false, "")
	broken := errors.New("no trusted roots")
	d.fetcher = func() (fetcher, error) { return nil, broken }
	if plan, err := d.planRefresh(context.Background(), &osfingerprint.OSInfo{}); !errors.Is(err, broken) || len(plan.datasets) != 0 || plan.f != nil {
		t.Errorf("with no fetcher: %+v, %v", plan, err)
	}
}

// A refresh for a host --for names that no dataset applies to says so, by
// that host's name, and fetches nothing.
func TestDataRefreshForAHostNoDatasetCovers(t *testing.T) {
	d, _, origins := refreshing(t, false, "")
	d.known = d.known[1:]
	out, err := run(d, "refresh", "--to", t.TempDir(), "--for", "linux/ubuntu/26.04")
	if err != nil || !strings.Contains(out, "knows no dataset for the host linux/ubuntu/26.04; nothing was fetched") || len(origins.fetched) != 0 {
		t.Errorf("printed %q, %v, fetched %q", out, err, origins.fetched)
	}
}

// A plan of which nothing is chosen fetches nothing, as when every large
// dataset is declined.
func TestRefreshPlanFetchesNothingChosen(t *testing.T) {
	d, s, origins := refreshing(t, false, "")
	plan, err := d.planRefresh(context.Background(), &osfingerprint.OSInfo{})
	if err != nil {
		t.Fatal(err)
	}
	var told steps
	outcomes, err := plan.fetch(context.Background(), s, nil, dataNow, &told)
	if err != nil || len(outcomes) != 0 || len(origins.fetched) != 0 || len(told) != 0 || holds(s.Root(), "wanted") {
		t.Errorf("outcomes %+v, %v, fetched %q, told %q", outcomes, err, origins.fetched, told)
	}
}

// In an elevated process, a malformed --for, or --for without --to, is
// refused for what is wrong with it, before anything is planned: no fetcher
// is built and no store is opened.
func TestDataRefreshElevatedWithAMalformedFor(t *testing.T) {
	d, _, _ := refreshing(t, false, "")
	d.elevated = func() bool { return true }
	d.fetcher = func() (fetcher, error) {
		t.Error("an elevated refresh asked for a fetcher")
		return nil, errors.New("not built")
	}
	d.open = func(context.Context) (store.Store, error) {
		t.Error("an elevated refresh opened a store")
		return store.Store{}, errors.New("not opened")
	}
	for _, args := range [][]string{
		{"refresh", "--for", "linux/debian/12"},
		{"refresh", "--to", t.TempDir(), "--for", "plan9"},
	} {
		if _, err := run(d, args...); err == nil || errors.Is(err, errRefreshElevated) || !strings.Contains(err.Error(), "--for") {
			t.Errorf("%v gave %v, want the --for refusal", args, err)
		}
	}
}

// cmd/commands/held/held_test.go

package held

import (
	"bytes"
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
	"github.com/papa0four/orkowatch/internal/dataset/kev"
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

// Every dataset owatch knows says what a run lacks without it: matching for
// each distribution's records, known exploitation for the catalog, and
// exploit prediction for the scores.
func TestKnownGive(t *testing.T) {
	for _, d := range Known() {
		want := "matching of the installed packages"
		switch d.ID() {
		case "kev":
			want = "known exploitation"
		case "epss":
			want = "exploit prediction"
		case "fedora-tracking-bugs":
			want = "the open tracking bugs of the installed packages"
		}
		if got := d.Gives(); got != want {
			t.Errorf("%s gives %q, want %q", d.ID(), got, want)
		}
	}
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

// The catalog of known-exploited vulnerabilities is read once a run, however
// often the run asks for it, with its index and its provenance; one not held
// gives an empty index and the reason.
func TestExploitedIsReadOnce(t *testing.T) {
	s := store.At(filepath.Join(t.TempDir(), "store"))
	catalog := kev.Catalog{}
	datasettest.PutCatalog(t, s.Root(), now.Add(-time.Hour),
		`{"cveID": "CVE-2026-0001", "dateAdded": "2026-11-20", "dueDate": "2026-12-11", "knownRansomwareCampaignUse": "Known", "cwes": ["CWE-306"]}`)
	run, _ := counted(s, nil)

	x, use := run.Exploited(context.Background(), host)
	entry, listed := x.Entry("CVE-2026-0001")
	if use.NotDone != "" || use.ID != "kev" || use.Version != "2026.11.21" || use.Attribution != catalog.Origin(nil).Attribution ||
		!listed || entry.Ransomware != "Known" || x.ClassCount("CWE-306") != 1 {
		t.Fatalf("the catalog read as %+v, %+v, %v", use, entry, listed)
	}
	if err := os.RemoveAll(filepath.Join(s.Root(), "kev")); err != nil {
		t.Fatal(err)
	}
	if again, use := run.Exploited(context.Background(), host); again.ClassCount("CWE-306") != 1 || use.NotDone != "" {
		t.Errorf("asked again, the run read the catalog again: %+v", use)
	}

	other, _ := counted(store.At(filepath.Join(t.TempDir(), "store")), nil)
	x, use = other.Exploited(context.Background(), host)
	if _, listed := x.Entry("CVE-2026-0001"); listed || x.ClassCount("CWE-306") != 0 || use.NotDone != "kev is not held; fetch it with owatch data refresh, or install it with owatch data import" {
		t.Errorf("a catalog not held gave %+v", use)
	}
}

// A catalog that reads as a catalog but is not the file its manifest
// describes gives nothing it read: the store refuses it only after it was
// read.
func TestExploitedRefusedAfterReading(t *testing.T) {
	s := store.At(filepath.Join(t.TempDir(), "store"))
	datasettest.PutCatalog(t, s.Root(), now.Add(-time.Hour), `{"cveID": "CVE-2026-0001", "knownRansomwareCampaignUse": "Known", "cwes": ["CWE-306"]}`)
	files, err := filepath.Glob(filepath.Join(s.Root(), "kev", "*.data"))
	if err != nil || len(files) != 1 {
		t.Fatalf("data files %v, %v", files, err)
	}
	data, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(files[0], bytes.Replace(data, []byte(`"Known"`), []byte(`"Knowx"`), 1), 0o600); err != nil {
		t.Fatal(err)
	}

	run, _ := counted(s, nil)
	x, use := run.Exploited(context.Background(), host)
	if _, listed := x.Entry("CVE-2026-0001"); listed || x.ClassCount("CWE-306") != 0 || !strings.HasPrefix(use.NotDone, "kev cannot be used") {
		t.Errorf("a catalog its checksum refuses gave %v listed, %d of CWE-306, %+v", listed, x.ClassCount("CWE-306"), use)
	}
}

// A run says what it installed from the operator's store once it has opened
// its store, and nothing before; a read is what opens it.
func TestOperatorIsWhatOpeningInstalled(t *testing.T) {
	s := store.At(filepath.Join(t.TempDir(), "store"))
	run := New(func(context.Context, []dataset.Dataset, *osfingerprint.OSInfo, time.Time) (store.Store, store.Adoption, error) {
		return s, store.Adoption{From: "/home/a/store", Outcomes: []store.Outcome{
			{ID: "held", Result: store.Installed},
			{ID: "missing", Result: store.Refused, Reason: "it is a link"},
		}}, nil
	}, []dataset.Dataset{held, missing}, now)

	if o := run.Operator(); o != nil {
		t.Fatalf("before opening, the run says %+v", o)
	}
	run.Read(context.Background(), missing, host, check(missing))
	o := run.Operator()
	if o == nil || o.Store != "/home/a/store" || len(o.Installed) != 1 || o.Installed[0] != "held" ||
		len(o.Refused) != 1 || o.Refused[0] != (dataset.Refusal{ID: "missing", Reason: "it is a link"}) ||
		o.Advice != "To install what was not installed, as a deliberate act, run owatch data import /home/a/store" {
		t.Errorf("after reading, the run says %+v", o)
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

// The route for a host with no network names the host by its target, and a
// host not identified, or one its target cannot name, by the line that gives
// it.
func TestCarried(t *testing.T) {
	const unnamed = "<the Target line owatch osinfo prints here>"
	for name, c := range map[string]struct {
		host *osfingerprint.OSInfo
		want string
	}{
		"named":           {&osfingerprint.OSInfo{OS: "linux", Platform: "ubuntu", PlatformVersion: "22.04"}, `"linux/ubuntu/22.04"`},
		"not identified":  {nil, unnamed},
		"cannot be named": {&osfingerprint.OSInfo{OS: "plan9"}, unnamed},
	} {
		want := "On a host with no network, run owatch data refresh --to <directory> --for " + c.want +
			" on a host with one, and owatch data import <directory> here"
		if got := Carried(c.host); got != want {
			t.Errorf("%s: %q, want %q", name, got, want)
		}
	}
}

// missing names, once each and in the order needed gives them, the datasets
// that apply to the host and cannot be read: one not held, and one whose data
// is not the size its manifest says; a held dataset that is sound, and one
// that does not apply, are not gaps. A store that cannot be opened is a gap of
// every dataset, and is tried once.
func TestMissing(t *testing.T) {
	s := store.At(filepath.Join(t.TempDir(), "store"))
	datasettest.Put(t, s.Root(), held, datasettest.Content, now.Add(-time.Hour), nil)
	damaged := datasettest.Dataset{Name: "damaged", Applies: true}
	datasettest.Put(t, s.Root(), damaged, datasettest.Content, now.Add(-time.Hour), nil)
	if err := os.WriteFile(filepath.Join(s.Root(), "damaged", datasettest.DataName(datasettest.Content)), []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	elsewhere := datasettest.Dataset{Name: "elsewhere"}
	run, _ := counted(s, nil)

	got := run.missing(context.Background(), host, []dataset.Dataset{held, missing, elsewhere, damaged, missing})
	if len(got) != 2 || got[0] != (Gap{ID: "missing", Gives: "what missing gives", Reason: "not held"}) ||
		got[1].ID != "damaged" || !strings.HasPrefix(got[1].Reason, "cannot be used: dataset unusable: the data holds 5 bytes") {
		t.Errorf("gaps %+v", got)
	}

	locked, opens := counted(store.Store{}, errors.New("locked"))
	got = locked.missing(context.Background(), host, []dataset.Dataset{held, missing})
	if len(got) != 2 || got[0].Reason != "the dataset store could not be read: locked" || got[1].Reason != got[0].Reason || *opens != 1 {
		t.Errorf("with no store, gaps %+v after %d opens", got, *opens)
	}
}

// Ask for a run that reads nothing goes on and judges nothing, not even
// opening the store; otherwise it judges the datasets the run reads and
// settles on what it cannot.
func TestAsk(t *testing.T) {
	s := store.At(filepath.Join(t.TempDir(), "store"))
	datasettest.Put(t, s.Root(), held, datasettest.Content, now.Add(-time.Hour), nil)
	run, opens := counted(s, nil)
	var out strings.Builder
	reads := func(*osfingerprint.OSInfo) []dataset.Dataset { return []dataset.Dataset{held, missing} }
	if err := run.Ask(context.Background(), nil, true, strings.NewReader(""), &out); err != nil || out.Len() > 0 || *opens != 0 {
		t.Errorf("reading nothing: %v, said %q, opened the store %d times", err, out.String(), *opens)
	}
	err := run.Ask(context.Background(), reads, false, strings.NewReader(""), &out)
	if want := "This run goes without missing (what missing gives): not held; its report says what was not read.\n"; err != nil || out.String() != want {
		t.Errorf("with no terminal: %v, said %q, want %q", err, out.String(), want)
	}
}

// settle goes on with no gaps, saying nothing; with no one at the terminal it
// goes on and says in one line what the run goes without; at a terminal it
// names each gap and asks, goes on at yes, and at anything else is ErrDeclined
// with what to run: a refresh by an ordinary account, a refresh by the account
// behind an elevated run and an install, or how datasets reach a host with no
// account behind the run.
func TestSettle(t *testing.T) {
	gaps := []Gap{{ID: "osv-ubuntu", Gives: "matching of the installed packages", Reason: "not held"}, {ID: "kev", Gives: "known exploitation", Reason: "not held"}}
	ubuntu := &osfingerprint.OSInfo{OS: "linux", Platform: "ubuntu", PlatformVersion: "22.04"}
	opened := func(a store.Adoption) *Run {
		run := New(func(context.Context, []dataset.Dataset, *osfingerprint.OSInfo, time.Time) (store.Store, store.Adoption, error) {
			return store.At(t.TempDir()), a, nil
		}, nil, now)
		if _, err := run.Open(context.Background(), ubuntu); err != nil {
			t.Fatal(err)
		}
		return run
	}
	const carried = `On a host with no network, run owatch data refresh --to <directory> --for "linux/ubuntu/22.04" on a host with one, and owatch data import <directory> here.`

	for name, c := range map[string]struct {
		run         *Run
		gaps        []Gap
		interactive bool
		answer      string
		asked       bool
		said        string
		err         string
	}{
		"no gaps": {opened(store.Adoption{}), nil, true, "", false, "", ""},
		"no terminal": {opened(store.Adoption{}), gaps, false, "", false,
			"This run goes without osv-ubuntu (matching of the installed packages): not held; kev (known exploitation): not held; its report says what was not read.\n", ""},
		"answered yes": {opened(store.Adoption{}), gaps, true, "y\n", true, "Continue without them? [y/N] ", ""},
		"answered no": {opened(store.Adoption{}), gaps, true, "\n", true, "Continue without them? [y/N] ",
			"run canceled: datasets it reads are not held. Run owatch data refresh. " + carried},
		"elevated": {opened(store.Adoption{From: "/home/a/store"}), gaps, true, "n\n", true, "Continue without them? [y/N] ",
			"run canceled: datasets it reads are not held. As the account whose store is /home/a/store, not elevated, run owatch data refresh, then run owatch data status elevated to install what it fetched. " + carried},
		"no account behind it": {opened(store.Adoption{NoOperator: true}), gaps, true, "", true, "Continue without them? [y/N] ",
			"run canceled: datasets it reads are not held. " + noOperatorAdvice},
	} {
		var out strings.Builder
		err := c.run.settle(context.Background(), c.gaps, ubuntu, c.interactive, strings.NewReader(c.answer), &out)
		switch {
		case c.err == "" && err != nil, c.err != "" && (!errors.Is(err, ErrDeclined) || err.Error() != c.err):
			t.Errorf("%s: %v, want %q", name, err, c.err)
		case !strings.HasSuffix(out.String(), c.said):
			t.Errorf("%s: said %q, want it to end %q", name, out.String(), c.said)
		case c.said == "" && out.Len() > 0:
			t.Errorf("%s: said %q, want nothing", name, out.String())
		}
		const question = "This run reads datasets it cannot read here, and would go without what they give:\n" +
			"  osv-ubuntu (matching of the installed packages): not held\n  kev (known exploitation): not held\n"
		if c.asked && !strings.HasPrefix(out.String(), question) {
			t.Errorf("%s: asked %q", name, out.String())
		}
	}
}

// ToFetch opens the run's store when nothing has, so a run asked before it
// has read a dataset still words what to run from what opening the store did:
// as the account behind an elevated run, or as this account.
func TestToFetchOpensTheStore(t *testing.T) {
	ubuntu := &osfingerprint.OSInfo{OS: "linux", Platform: "ubuntu", PlatformVersion: "22.04"}
	for _, c := range []struct {
		adoption store.Adoption
		want     string
	}{
		{store.Adoption{From: "/home/a/store"}, "As the account whose store is /home/a/store, not elevated, run owatch data refresh, then run owatch data status elevated to install what it fetched. "},
		{store.Adoption{}, "Run owatch data refresh. "},
	} {
		adoption, want := c.adoption, c.want
		opens := 0
		run := New(func(context.Context, []dataset.Dataset, *osfingerprint.OSInfo, time.Time) (store.Store, store.Adoption, error) {
			opens++
			return store.At(t.TempDir()), adoption, nil
		}, nil, now)
		if got := run.ToFetch(context.Background(), ubuntu); !strings.HasPrefix(got, want) || opens != 1 {
			t.Errorf("with %+v: %q after %d opens, want it to begin %q", adoption, got, opens, want)
		}
		if run.ToFetch(context.Background(), ubuntu); opens != 1 {
			t.Errorf("asked again, the store was opened %d times", opens)
		}
	}
}

// ToFetch with a store that cannot be opened names it before what to run.
func TestToFetchWithNoStore(t *testing.T) {
	run, _ := counted(store.Store{}, errors.New("locked"))
	if got := run.ToFetch(context.Background(), host); !strings.HasPrefix(got, "The dataset store could not be read: locked. Run owatch data refresh. ") {
		t.Errorf("with no store: %q", got)
	}
}

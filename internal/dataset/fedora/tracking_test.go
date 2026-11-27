// internal/dataset/fedora/tracking_test.go

package fedora

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/softwarelist"
	"github.com/papa0four/orkowatch/internal/vulnmatch"
	"github.com/papa0four/orkowatch/internal/vulnrecord"
)

// The pages below are written for the tests in the form Bugzilla answers a
// request for bugs by identifier; none is a copy of a real bug.

// testBug is a bug as a page gives it, public and open unless changed.
func testBug(id int, version, summary string, components ...string) bug {
	return bug{ID: id, Component: components, Version: []string{version}, Status: "NEW", Summary: summary,
		DataCategory: "Public", Changed: fmt.Sprintf("2026-11-%02dT10:00:00Z", 10+id%10)}
}

// versionsOf is Bugzilla's answer of Fedora's versions, as the gate answers
// it: 42 inactive, and 43, 44, and rawhide active.
const versionsOf = `{"products":[{"versions":[{"name":"42","is_active":false,"sort_key":0,"id":1},` +
	`{"name":"43","is_active":true,"sort_key":0,"id":2},{"name":"44","is_active":true,"sort_key":0,"id":3},` +
	`{"name":"rawhide","is_active":true,"sort_key":0,"id":4}]}]}`

// pagesOf is the pages as a fetch writes them, the gate's answer and then one
// answer after another.
func pagesOf(t *testing.T, pages ...[]bug) []byte {
	t.Helper()
	b := bytes.NewBufferString(versionsOf + "\n")
	for _, p := range pages {
		if err := json.NewEncoder(b).Encode(map[string]any{"limit": "20", "offset": 0, "total_matches": len(p), "bugs": p}); err != nil {
			t.Fatal(err)
		}
	}
	return b.Bytes()
}

// keptBugs is what Keep keeps of fetched for Fedora 44.
func keptBugs(fetched []byte) ([]byte, error) {
	var kept bytes.Buffer
	err := TrackingBugs{}.Keep(bytes.NewReader(fetched), int64(len(fetched)), f44, &kept)
	return kept.Bytes(), err
}

// sample is two pages of bugs of every kind Keep sorts.
func sample(t *testing.T) []byte {
	return pagesOf(t, []bug{
		testBug(101, "44", "CVE-2026-1001 zstd: zstd: an overflow [fedora-44]", "zstd"),
		testBug(102, "rawhide", "CVE-2026-1002 CVE-2026-1003 CVE-2026-1002 openclaw: body-parser: a crash [fedora-all]", "openclaw"),
		testBug(103, "rawhide", "CVE-2026-1004 rust-foo: a flaw [fedora-rawhide]", "rust-foo"),
		testBug(104, "43", "CVE-2026-1005 bar: a flaw [fedora-43]", "bar"),
	}, []bug{
		func() bug {
			b := testBug(105, "44", "CVE-2026-1006 baz: a flaw [fedora-44]", "baz")
			b.Status = "CLOSED"
			return b
		}(),
		testBug(106, "44", "perl-XML-Twig: expand_external_ents fails [fedora-44]", "perl-XML-Twig"),
		testBug(107, "44", "CVE-2026-1007 python-a: a flaw [fedora-44]", "python-a", "python-b"),
		testBug(108, "44", "CVE-2026-1008 qux: a regression of the fix for CVE-2025-9999 [fedora-44]", "qux"),
	})
}

// The dataset applies to a Fedora host as its updates do, combines its
// records as they do so the two are matched together, keeps less than it
// fetches, and is fetched from Bugzilla's listing of the identifiers of the
// open tracking bugs of the host's release and of rawhide, in pages.
func TestTrackingBugsStatesItself(t *testing.T) {
	tb := TrackingBugs{}
	var _ dataset.Keeper = tb
	if tb.ID() != "fedora-tracking-bugs" || !dataset.ValidID(tb.ID()) || !tb.AppliesTo(f44) || tb.AppliesTo(nil) || tb.Manager() != softwarelist.ManagerRPM || tb.Combining() != (Updates{}).Combining() {
		t.Errorf("states %q, %q, %v", tb.ID(), tb.Manager(), tb.Combining())
	}
	if rel, err := tb.Release(f44); err != nil || rel != "Fedora 44" {
		t.Errorf("release %q, %v", rel, err)
	}
	o := tb.Origin(f44)
	u, err := url.Parse(o.URL)
	if err != nil || u.Host != "bugzilla.redhat.com" || u.Path != "/rest/bug" || o.Pages == nil || o.Index != nil || o.Pages.MaxPages != 2000 {
		t.Fatalf("origin %+v, %v", o, err)
	}
	q := u.Query()
	if !slices.Equal(q["version"], []string{"44", "rawhide"}) || q.Get("ids_only") != "1" || q.Get("keywords") != "SecurityTracking" || q.Get("product") != "Fedora" || q.Get("bug_status") != "__open__" {
		t.Errorf("the listing is %s", o.URL)
	}
	if !strings.Contains(o.License, "No license stated") || !strings.Contains(o.Attribution, "Red Hat Bugzilla") {
		t.Errorf("terms %q, %q", o.License, o.Attribution)
	}
}

// The listing gives a page of 20 identifiers at a time, each asking for the
// fields the dataset needs and no other, none of which names a person; a
// listing that holds an error, is not one, or names an identifier that is
// not one, is refused.
func TestListingGivesThePages(t *testing.T) {
	var ids []string
	for i := 1; i <= 45; i++ {
		ids = append(ids, fmt.Sprintf(`{"id":%d}`, 1000+i))
	}
	pages, err := list(strings.NewReader(`{"bugs":[`+strings.Join(ids, ",")+`],"limit":"20","total_matches":45}`), nil)
	if err != nil || len(pages) != 3 {
		t.Fatalf("pages %q, %v", pages, err)
	}
	for i, p := range pages {
		u, err := url.Parse(p)
		if err != nil || u.Host != "bugzilla.redhat.com" {
			t.Fatalf("page %q, %v", p, err)
		}
		want := []int{20, 20, 5}[i]
		if got := strings.Split(u.Query().Get("id"), ","); len(got) != want || got[0] != fmt.Sprint(1001+20*i) {
			t.Errorf("page %d asks for %q", i, got)
		}
		if fields := u.Query().Get("include_fields"); fields != "id,component,version,status,summary,data_category,last_change_time" {
			t.Errorf("page %d asks for the fields %q", i, fields)
		}
	}
	for name, listing := range map[string]string{
		"an error":      `{"error":true,"message":"x"}`,
		"not JSON":      `not json`,
		"a bad id":      `{"bugs":[{"id":0}]}`,
		"a negative id": `{"bugs":[{"id":-5}]}`,
	} {
		if _, err := list(strings.NewReader(listing), nil); err == nil {
			t.Errorf("%s was listed", name)
		}
	}
}

// What is kept is each open bug of the release, and each of rawhide filed
// for every release, once for each component, with the CVEs its summary opens
// with given once; a bug of another release, closed since it was listed, or
// naming no CVE is left out, and no summary is kept. Each is given as an open
// record of its component as a source package, with its page, and the data
// is dated by the latest change.
func TestKeepsTheOpenTrackingBugs(t *testing.T) {
	kept, err := keptBugs(sample(t))
	if err != nil {
		t.Fatal(err)
	}
	gz, err := gzip.NewReader(bytes.NewReader(kept))
	if err != nil {
		t.Fatal(err)
	}
	text, err := io.ReadAll(gz)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(text), "overflow") || strings.Contains(string(text), "body-parser") {
		t.Errorf("a summary was kept:\n%s", text)
	}

	var records []vulnrecord.Record
	facts, err := TrackingBugs{}.Records(bytes.NewReader(kept), f44, func(r vulnrecord.Record) error {
		records = append(records, r)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range records {
		a := r.Affected[0]
		if !r.Open || !a.Source || len(r.Affected) != 1 || r.Advisory != "https://bugzilla.redhat.com/show_bug.cgi?id="+strings.TrimPrefix(r.ID, "rhbz#") || len(a.Ranges) != 1 || len(a.Ranges[0]) != 1 {
			t.Errorf("record %+v", r)
		}
		got = append(got, r.ID+" "+a.Package+" "+strings.Join(r.CVEs, ","))
	}
	want := []string{"rhbz#101 zstd CVE-2026-1001", "rhbz#102 openclaw CVE-2026-1002,CVE-2026-1003", "rhbz#107 python-a CVE-2026-1007", "rhbz#107 python-b CVE-2026-1007", "rhbz#108 qux CVE-2026-1008"}
	if !slices.Equal(got, want) {
		t.Errorf("records %q, want %q", got, want)
	}
	if wantDate := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC); facts.Version != "Fedora 44" || !facts.Date.Equal(wantDate) {
		t.Errorf("facts %+v", facts)
	}
}

// A kept tracking bug of a source package is open for each installed package
// built from it.
func TestTrackingBugsMatchBySource(t *testing.T) {
	kept, err := keptBugs(sample(t))
	if err != nil {
		t.Fatal(err)
	}
	m, err := vulnmatch.New(softwarelist.ManagerRPM, TrackingBugs{}.Combining(), []softwarelist.SoftwareEntry{
		{Name: "libzstd", Version: "1.5.7-1.fc44", Manager: softwarelist.ManagerRPM, Source: "zstd"},
		{Name: "zstd-extra", Version: "1.0-1.fc44", Manager: softwarelist.ManagerRPM, Source: "zstd-extra"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (TrackingBugs{}).Records(bytes.NewReader(kept), f44, m.Add); err != nil {
		t.Fatal(err)
	}
	v := m.Result()
	if len(v.Packages) != 1 || v.Packages[0].Package != "libzstd" || v.Packages[0].Vulnerabilities[0].Status != vulnmatch.StatusTracked ||
		!slices.Equal(v.Packages[0].Vulnerabilities[0].Records, []string{"rhbz#101"}) {
		t.Errorf("matched %+v", v.Packages)
	}
}

// Pages that hold an error, are not Bugzilla's answer, hold a bug that is not
// public, a time that is not one, or a component a terminal would act on,
// or keep no open tracking bug, are refused whole.
func TestKeepRefuses(t *testing.T) {
	notPublic := testBug(201, "44", "CVE-2026-2001 a: b", "a")
	notPublic.DataCategory = "Private"
	badTime := testBug(202, "44", "CVE-2026-2002 a: b", "a")
	badTime.Changed = "yesterday"
	escaped := testBug(203, "44", "CVE-2026-2003 a: b", "a\u009b2J")
	for name, tt := range map[string]struct {
		fetched []byte
		what    string
	}{
		"an error":     {[]byte(versionsOf + `{"error":true,"message":"x"}`), "holds an error from Bugzilla"},
		"not JSON":     {[]byte(versionsOf + `<html>`), "is not Bugzilla's answer"},
		"not public":   {pagesOf(t, []bug{notPublic}), "it is not a public bug"},
		"a bad time":   {pagesOf(t, []bug{badTime}), `"yesterday" is not a time`},
		"an escape":    {pagesOf(t, []bug{escaped}), "holds a control character"},
		"nothing kept": {pagesOf(t, []bug{testBug(204, "43", "CVE-2026-2004 a: b", "a")}), "no open tracking bug of Fedora 44"},
		"no pages":     {[]byte(versionsOf), "no open tracking bug of Fedora 44"},
	} {
		if _, err := keptBugs(tt.fetched); err == nil || !strings.Contains(err.Error(), tt.what) {
			t.Errorf("%s: gave %v, want it refused: %s", name, err, tt.what)
		}
	}
}

// What was kept is refused when it is not gzip, was kept for another
// release, counts more or fewer bugs than follow, holds a field it does not
// write, or has anything after it.
func TestTrackingRecordsRefuse(t *testing.T) {
	kept, err := keptBugs(sample(t))
	if err != nil {
		t.Fatal(err)
	}
	gzipped := func(lines ...string) []byte {
		var b bytes.Buffer
		z := gzip.NewWriter(&b)
		if _, err := io.WriteString(z, strings.Join(lines, "\n")+"\n"); err != nil {
			t.Fatal(err)
		}
		if err := z.Close(); err != nil {
			t.Fatal(err)
		}
		return b.Bytes()
	}
	one := `{"id":1,"component":"a","status":"NEW","changed":"2026-11-27T00:00:00Z","cves":["CVE-2026-1001"]}`
	for name, tt := range map[string]struct {
		data []byte
		host string
		what string
	}{
		"the pages as fetched": {sample(t), "44", "not the tracking bugs kept"},
		"another release":      {kept, "42", "kept for Fedora 44, not Fedora 42"},
		"fewer than counted":   {gzipped(`{"release":"Fedora 44","active":true,"bugs":2}`, one), "44", "bug 2 of 2 cannot be read"},
		"more than counted":    {gzipped(`{"release":"Fedora 44","active":true,"bugs":1}`, one, one), "44", "text follows the tracking bugs the header counts"},
		"a field not written":  {gzipped(`{"release":"Fedora 44","active":true,"bugs":1}`, strings.Replace(one, `"status"`, `"summary":"x","status"`, 1)), "44", "cannot be read"},
		"no CVE":               {gzipped(`{"release":"Fedora 44","active":true,"bugs":1}`, strings.Replace(one, `["CVE-2026-1001"]`, `[]`, 1)), "44", "names no CVE"},
		"none":                 {gzipped(`{"release":"Fedora 44","active":true,"bugs":0}`), "44", "no open tracking bug of Fedora 44 is kept"},
		"data after the gzip":  {append(slices.Clone(kept), "trailing"...), "44", "data follows the tracking bugs kept"},
	} {
		host := f44
		if tt.host == "42" {
			host = f42
		}
		if _, err := (TrackingBugs{}).Check(bytes.NewReader(tt.data), host); err == nil || !strings.Contains(err.Error(), tt.what) {
			t.Errorf("%s: gave %v, want it refused: %s", name, err, tt.what)
		}
	}
}

// Bugzilla's answer of Fedora's versions says whether a release is one it
// files tracking bugs for; an answer that is not Bugzilla's, holds an error,
// or does not name the release is refused. The origin's gate gives an
// inactive release its standing and an active one none.
func TestActiveVersion(t *testing.T) {
	for release, want := range map[string]bool{"44": true, "43": true, "42": false} {
		if got, err := activeVersion(strings.NewReader(versionsOf), release); err != nil || got != want {
			t.Errorf("%s: active %v, %v; want %v", release, got, err, want)
		}
	}
	for name, tt := range map[string]struct{ answer, what string }{
		"unlisted": {versionsOf, "no Fedora version 41 is named in Red Hat Bugzilla"},
		"an error": {`{"error":true}`, "not Bugzilla's answer of Fedora's versions"},
		"none":     {`{"products":[]}`, "not Bugzilla's answer of Fedora's versions"},
		"not JSON": {`<html>`, "not Bugzilla's answer of Fedora's versions"},
	} {
		if _, err := activeVersion(strings.NewReader(tt.answer), "41"); err == nil || !strings.Contains(err.Error(), tt.what) {
			t.Errorf("%s: gave %v, want it refused: %s", name, err, tt.what)
		}
	}
	gate := (TrackingBugs{}).Origin(f42).Pages.Gate
	if gate == nil || gate.URL != "https://bugzilla.redhat.com/rest/product?names=Fedora&include_fields=versions" {
		t.Fatalf("gate %+v", gate)
	}
	if standing, err := gate.Read(strings.NewReader(versionsOf)); err != nil || standing != "Fedora 42 is not an active version in Red Hat Bugzilla; no tracking bugs are filed for it" {
		t.Errorf("an inactive release stands %q, %v", standing, err)
	}
	if standing, err := (TrackingBugs{}).Origin(f44).Pages.Gate.Read(strings.NewReader(versionsOf)); err != nil || standing != "" {
		t.Errorf("an active release stands %q, %v", standing, err)
	}
}

// A release that is not an active version keeps no bug, which is all that
// was fetched for it, and what was kept reads as none with no date of its
// own; pages after the answer that it is not active are refused.
func TestKeepsNoneOnAnInactiveRelease(t *testing.T) {
	var kept bytes.Buffer
	fetched := []byte(versionsOf)
	if err := (TrackingBugs{}).Keep(bytes.NewReader(fetched), int64(len(fetched)), f42, &kept); err != nil {
		t.Fatal(err)
	}
	given := 0
	facts, err := TrackingBugs{}.Records(bytes.NewReader(kept.Bytes()), f42, func(vulnrecord.Record) error { given++; return nil })
	if err != nil || given != 0 || facts.Version != "Fedora 42" || !facts.Date.IsZero() {
		t.Errorf("an inactive release gave %d records, %+v, %v", given, facts, err)
	}
	withPages := pagesOf(t, []bug{testBug(301, "rawhide", "CVE-2026-3001 a: b [fedora-all]", "a")})
	kept.Reset()
	if err := (TrackingBugs{}).Keep(bytes.NewReader(withPages), int64(len(withPages)), f42, &kept); err == nil || !strings.Contains(err.Error(), "pages follow the answer that Fedora 42 is not an active version") {
		t.Errorf("pages after an inactive answer gave %v", err)
	}
}

// What was kept is refused when it does not say whether the release is an
// active version, or keeps bugs for one that is not.
func TestTrackingRecordsRefuseWhatContradictsActive(t *testing.T) {
	gzipped := func(lines ...string) []byte {
		var b bytes.Buffer
		z := gzip.NewWriter(&b)
		if _, err := io.WriteString(z, strings.Join(lines, "\n")+"\n"); err != nil {
			t.Fatal(err)
		}
		if err := z.Close(); err != nil {
			t.Fatal(err)
		}
		return b.Bytes()
	}
	one := `{"id":1,"component":"a","status":"NEW","changed":"2026-11-27T00:00:00Z","cves":["CVE-2026-1001"]}`
	for name, tt := range map[string]struct {
		data []byte
		what string
	}{
		"not saying":          {gzipped(`{"release":"Fedora 42","bugs":0}`), "do not say whether the release is an active version"},
		"bugs of an inactive": {gzipped(`{"release":"Fedora 42","active":false,"bugs":1}`, one), "1 tracking bugs are kept for Fedora 42, which is not an active version"},
	} {
		if _, err := (TrackingBugs{}).Check(bytes.NewReader(tt.data), f42); err == nil || !strings.Contains(err.Error(), tt.what) {
			t.Errorf("%s: gave %v, want it refused: %s", name, err, tt.what)
		}
	}
}

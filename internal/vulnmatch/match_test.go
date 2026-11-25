// internal/vulnmatch/match_test.go

package vulnmatch

import (
	"slices"
	"strings"
	"testing"

	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/dataset/kev"
	"github.com/papa0four/orkowatch/internal/dataset/osv"
	"github.com/papa0four/orkowatch/internal/pkgversion"
	"github.com/papa0four/orkowatch/internal/softwarelist"
)

// events is a range of the events given, kind and version in turn.
func events(pairs ...string) []osv.Event {
	var out []osv.Event
	for i := 0; i+1 < len(pairs); i += 2 {
		out = append(out, osv.Event{pairs[i]: pairs[i+1]})
	}
	return out
}

// A range is evaluated as the OSV schema's evaluation states: a version an
// introduced event reaches is in the range until a fixed event it reaches, or
// a last affected event it passes; a range applies below its limits; events
// are taken in version order whatever order they are given in. A version that
// entered and left a range has the fix installed; one that never entered it
// is outside the record.
func TestJudge(t *testing.T) {
	for _, tt := range []struct {
		name      string
		installed string
		ranges    [][]osv.Event
		want      verdict
		above     []string
	}{
		{"below the fix", "1.0-1", [][]osv.Event{events("introduced", "0", "fixed", "2.0-1")}, inside, []string{"2.0-1"}},
		{"at the fix", "2.0-1", [][]osv.Event{events("introduced", "0", "fixed", "2.0-1")}, cleared, nil},
		{"above the fix", "3.0-1", [][]osv.Event{events("introduced", "0", "fixed", "2.0-1")}, cleared, nil},
		{"no fix", "9.0-1", [][]osv.Event{events("introduced", "0")}, inside, nil},
		{"several fixes, below all", "1.0-1", [][]osv.Event{events("introduced", "0", "fixed", "2.0-1", "fixed", "3.0-1")}, inside, []string{"2.0-1", "3.0-1"}},
		{"several fixes, between", "2.5-1", [][]osv.Event{events("introduced", "0", "fixed", "2.0-1", "fixed", "3.0-1")}, cleared, nil},
		{"between two ranges", "2.0-1", [][]osv.Event{events("introduced", "1.0-1", "fixed", "1.2-1", "introduced", "3.0-1", "fixed", "3.5-1")}, cleared, nil},
		{"in the second range", "3.1-1", [][]osv.Event{events("introduced", "1.0-1", "fixed", "1.2-1", "introduced", "3.0-1", "fixed", "3.5-1")}, inside, []string{"3.5-1"}},
		{"before any range", "0.5-1", [][]osv.Event{events("introduced", "1.0-1", "fixed", "1.2-1")}, outside, nil},
		{"at the last affected", "2.0-1", [][]osv.Event{events("introduced", "0", "last_affected", "2.0-1")}, inside, nil},
		{"past the last affected", "2.1-1", [][]osv.Event{events("introduced", "0", "last_affected", "2.0-1")}, cleared, nil},
		{"past a limit", "3.0-1", [][]osv.Event{events("introduced", "0", "limit", "2.0-1")}, outside, nil},
		{"below a limit", "1.0-1", [][]osv.Event{events("introduced", "0", "limit", "2.0-1")}, inside, nil},
		{"an infinite limit", "9.0-1", [][]osv.Event{events("introduced", "0", "limit", "*")}, inside, nil},
		{"events out of order", "1.0-1", [][]osv.Event{events("fixed", "2.0-1", "introduced", "0")}, inside, []string{"2.0-1"}},
		{"events out of order, above the fix", "3.0-1", [][]osv.Event{events("fixed", "2.0-1", "introduced", "0")}, cleared, nil},
		{"one range of two", "1.0-1", [][]osv.Event{events("introduced", "5.0-1", "fixed", "6.0-1"), events("introduced", "0", "fixed", "2.0-1")}, inside, []string{"2.0-1"}},
		{"an epoch orders first", "1:1.0-1", [][]osv.Event{events("introduced", "0", "fixed", "9.0-1")}, cleared, nil},
	} {
		got, err := judge(tt.installed, tt.ranges, pkgversion.Dpkg)
		if err != nil || got.verdict != tt.want || !slices.Equal(got.above, tt.above) {
			t.Errorf("%s: %+v, %v; want verdict %d above %q", tt.name, got, err, tt.want, tt.above)
		}
	}
	if _, err := judge("1:", [][]osv.Event{events("introduced", "0", "fixed", "2.0-1")}, pkgversion.Dpkg); err == nil {
		t.Error("a version that cannot be ordered was judged")
	}
}

// record is an OSV record naming cves, affecting package with ranges.
func record(id string, cves []string, pkg string, ranges ...[]osv.Event) osv.Record {
	return osv.Record{ID: id, CVEs: cves, Modified: "2026-11-23T10:00:00Z",
		Severity: []osv.Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
		Affected: []osv.Affected{{Package: pkg, Ecosystem: "Test:1", Ranges: ranges}}}
}

// match is one vulnerability with the package it is under, as the tests read
// a view.
type match struct {
	ID, Package, Installed, Status, Fixed string
	Binaries, Records                     []string
	Severity                              []osv.Severity
}

// flatten lists the vulnerabilities of v, each with its package, in the order
// the view holds them.
func flatten(v View) []match {
	var out []match
	for _, pkg := range v.Packages {
		for _, found := range pkg.Vulnerabilities {
			out = append(out, match{ID: found.ID, Package: pkg.Package, Installed: pkg.Installed, Status: found.Status, Fixed: found.Fixed,
				Binaries: pkg.Binaries, Records: found.Records, Severity: found.Scores})
		}
	}
	return out
}

// matched runs a matcher of manager's entries over records.
func matched(t *testing.T, manager string, entries []softwarelist.SoftwareEntry, records ...osv.Record) View {
	t.Helper()
	m, err := New(manager, entries)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range records {
		if err := m.Add(r); err != nil {
			t.Fatal(err)
		}
	}
	return m.Result()
}

// A dpkg package is matched by its source and the source's version, and the
// binaries built from it are named; a vulnerability below its fix is one with
// a fix available, one with no fix unfixed, and a record naming no CVE is
// matched by its own identifier.
func TestMatchDpkgBySource(t *testing.T) {
	entries := []softwarelist.SoftwareEntry{
		{Name: "libssl3", Version: "3.0.2-0ubuntu1.10", Manager: "dpkg", Source: "openssl", SourceVersion: "3.0.2-0ubuntu1.10"},
		{Name: "openssl", Version: "3.0.2-0ubuntu1.10", Manager: "dpkg", Source: "openssl", SourceVersion: "3.0.2-0ubuntu1.10"},
		{Name: "bash", Version: "5.1-6ubuntu1", Manager: "dpkg", Source: "bash", SourceVersion: "5.1-6ubuntu1"},
		{Name: "openssl", Version: "3.0.2-1", Manager: "rpm"},
	}
	v := matched(t, "dpkg", entries,
		record("UBUNTU-CVE-2026-1", []string{"CVE-2026-1"}, "openssl", events("introduced", "0", "fixed", "3.0.2-0ubuntu1.12")),
		record("UBUNTU-CVE-2026-2", []string{"CVE-2026-2"}, "openssl", events("introduced", "0")),
		record("USN-1-1", nil, "openssl", events("introduced", "0", "fixed", "3.0.2-0ubuntu1.11")),
		record("UBUNTU-CVE-2026-3", []string{"CVE-2026-3"}, "libssl3", events("introduced", "0")),
	)
	// The three are under one package, given once, those with a fix
	// available first.
	want := []match{
		{ID: "CVE-2026-1", Package: "openssl", Installed: "3.0.2-0ubuntu1.10", Status: StatusFixAvailable, Fixed: "3.0.2-0ubuntu1.12"},
		{ID: "USN-1-1", Package: "openssl", Installed: "3.0.2-0ubuntu1.10", Status: StatusFixAvailable, Fixed: "3.0.2-0ubuntu1.11"},
		{ID: "CVE-2026-2", Package: "openssl", Installed: "3.0.2-0ubuntu1.10", Status: StatusUnfixed},
	}
	if got := flatten(v); len(v.Packages) != 1 || len(got) != len(want) {
		t.Fatalf("packages %+v, want one holding %d", v.Packages, len(want))
	}
	for i, w := range want {
		got := flatten(v)[i]
		if got.ID != w.ID || got.Package != w.Package || got.Installed != w.Installed || got.Status != w.Status || got.Fixed != w.Fixed ||
			!slices.Equal(got.Binaries, []string{"libssl3", "openssl"}) || len(got.Severity) != 1 {
			t.Errorf("match %d: %+v, want %+v", i, got, w)
		}
	}
	c := v.Counts
	if c.Packages != 2 || c.NotCovered != 1 || c.FixAvailable != 2 || c.Unfixed != 1 || c.PackagesWithFix != 1 || c.PackagesWithUnfixed != 1 || v.Order != "dpkg" {
		t.Errorf("counts %+v, order %q", c, v.Order)
	}
}

// One vulnerability of one package in several advisories, as Red Hat's minor
// releases give it, is fixed at the lowest fixed version any of them gives: a
// package at the 9.3 update's fix is not affected though the 9.4 advisory's
// fix is higher, and one below both is affected with the lower fix. An
// advisory whose range the package never entered does not clear it.
func TestMatchAcrossAdvisories(t *testing.T) {
	advisories := []osv.Record{
		record("RHSA-2023:1", []string{"CVE-2023-45803"}, "fence-agents", events("introduced", "0", "fixed", "0:4.10.0-55.el9_3.3")),
		record("RHSA-2024:2", []string{"CVE-2023-45803"}, "fence-agents", events("introduced", "0", "fixed", "0:4.10.0-62.el9")),
	}
	for installed, fixed := range map[string]string{
		"4.10.0-55.el9_3.3": "",
		"4.10.0-60.el9":     "",
		"4.10.0-62.el9":     "",
		"4.10.0-50.el9":     "0:4.10.0-55.el9_3.3",
	} {
		v := matched(t, "rpm", []softwarelist.SoftwareEntry{{Name: "fence-agents", Version: installed, Manager: "rpm"}}, advisories...)
		switch {
		case fixed == "" && len(flatten(v)) != 0:
			t.Errorf("%s: %+v, want it not affected", installed, flatten(v))
		case fixed != "" && (len(flatten(v)) != 1 || flatten(v)[0].Fixed != fixed || !slices.Equal(flatten(v)[0].Records, []string{"RHSA-2023:1", "RHSA-2024:2"})):
			t.Errorf("%s: %+v, want it affected and fixed in %s", installed, flatten(v), fixed)
		}
	}

	other := record("RHSA-2024:3", []string{"CVE-2023-45803"}, "fence-agents", events("introduced", "5.0", "fixed", "5.1"))
	v := matched(t, "rpm", []softwarelist.SoftwareEntry{{Name: "fence-agents", Version: "4.10.0-50.el9", Manager: "rpm"}}, advisories[0], other)
	if len(flatten(v)) != 1 || flatten(v)[0].Fixed != "0:4.10.0-55.el9_3.3" {
		t.Errorf("an advisory the package never entered cleared it: %+v", flatten(v))
	}
}

// A module build whose records give more than one fixed version is not
// matched, with the reason, since the records do not say which stream each
// fix is for; with one fixed version it is judged as any package is.
func TestMatchModuleBuild(t *testing.T) {
	nodejs := softwarelist.SoftwareEntry{Name: "nodejs", Version: "1:20.20.2-1.module_el9.7.0+226+88d36870", Manager: "rpm"}
	streams := []osv.Record{
		record("ALSA-2025:1", []string{"CVE-2025-1"}, "nodejs", events("introduced", "0", "fixed", "1:18.20.9-1.module_el9.6.0+1+aaaa")),
		record("ALSA-2025:2", []string{"CVE-2025-1"}, "nodejs", events("introduced", "0", "fixed", "1:20.20.9-1.module_el9.6.0+1+aaaa")),
	}
	v := matched(t, "rpm", []softwarelist.SoftwareEntry{nodejs}, streams...)
	if len(flatten(v)) != 0 || len(v.NotMatched) != 1 || !strings.Contains(v.NotMatched[0].Reason, "module build") || v.Counts.NotMatched != 1 {
		t.Errorf("a module build with two streams' fixes: %+v, %+v", flatten(v), v.NotMatched)
	}
	v = matched(t, "rpm", []softwarelist.SoftwareEntry{nodejs}, streams[1])
	if len(flatten(v)) != 1 || flatten(v)[0].Status != StatusFixAvailable || len(v.NotMatched) != 0 {
		t.Errorf("a module build with one fix: %+v, %+v", flatten(v), v.NotMatched)
	}
}

// A version that cannot be ordered is not matched, with the reason, and is
// never called affected or clean; a manager with no known order is refused.
func TestMatchCannotCompare(t *testing.T) {
	v := matched(t, "apk", []softwarelist.SoftwareEntry{{Name: "busybox", Version: "", Manager: "apk", Source: "busybox"}},
		record("ALPINE-CVE-2026-1", []string{"CVE-2026-1"}, "busybox", events("introduced", "0", "fixed", "1.36.1-r20")))
	if len(flatten(v)) != 0 || len(v.NotMatched) != 1 || !strings.Contains(v.NotMatched[0].Reason, "cannot be compared") {
		t.Errorf("an empty version: %+v, %+v", flatten(v), v.NotMatched)
	}
	if _, err := New("pacman", nil); err == nil {
		t.Error("a manager with no known order was matched")
	}
}

// The text section gives the counts, each vulnerability with a fix available,
// the unfixed counted by package, and those not matched; with no match made,
// why.
func TestWriteText(t *testing.T) {
	v := View{Use: dataset.Use{Provenance: dataset.Provenance{ID: "osv-ubuntu", Version: "Ubuntu:22.04", DataDate: "2026-11-24", State: dataset.StateCurrent}}, Order: "dpkg",
		Packages: []PackageMatches{{Package: "openssl", Installed: "3.0.2-1", Vulnerabilities: []Vulnerability{
			{ID: "CVE-2026-1", Status: StatusFixAvailable, Fixed: "3.0.2-2", Severity: Severity{Label: "medium", Level: LevelMedium, Basis: "Ubuntu priority"}},
			{ID: "CVE-2026-2", Status: StatusUnfixed},
			{ID: "CVE-2026-3", Status: StatusUnfixed},
		}}},
		NotMatched: []NotMatched{{ID: "CVE-2026-4", Package: "nodejs", Installed: "x", Reason: "a module build"}},
		Installed:  3, NotCovered: 1}
	v.count()
	var b strings.Builder
	if err := WriteText(&b, v); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Matched against osv-ubuntu, Ubuntu:22.04, data of 2026-11-24, current",
		"3 packages matched: 1 vulnerability with a fix available in 1 package, 2 unfixed in 1 package, 1 pair not matched, 1 package no record covers",
		"medium      CVE-2026-1           openssl 3.0.2-1, fixed in 3.0.2-2",
		"openssl 3.0.2-1: 2 unfixed",
		"CVE-2026-4           nodejs x: a module build",
	} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("the text lacks %q:\n%s", want, b.String())
		}
	}
	if strings.Contains(b.String(), "CVE-2026-2") {
		t.Errorf("an unfixed vulnerability was listed:\n%s", b.String())
	}

	b.Reset()
	if err := WriteText(&b, View{Use: dataset.Use{NotDone: "no OSV dataset is held for this host; run owatch data refresh"}}); err != nil || !strings.HasPrefix(b.String(), "Matching was not done: no OSV dataset") {
		t.Errorf("a match not made wrote %q, %v", b.String(), err)
	}
}

// catalog is a catalog of known-exploited vulnerabilities listing the
// identifiers it holds.
type catalog map[string]kev.Entry

func (c catalog) Entry(id string) (kev.Entry, bool) {
	e, ok := c[id]
	return e, ok
}

// kevData is the provenance of a catalog read at its date.
var kevData = dataset.Use{Provenance: dataset.Provenance{ID: "kev", Version: "2026.11.23", DataDate: "2026-11-23", State: dataset.StateCurrent, Attribution: "Attributed as the catalog asks."}}

// exploitedView is a match of two packages, openssl with a low fix, a high
// fix, and a critical unfixed, and bash with a medium fix, before any is
// marked.
func exploitedView() View {
	sev := func(level string) Severity { return Severity{Label: level, Level: level, Basis: "Ubuntu priority"} }
	v := View{Use: dataset.Use{Provenance: dataset.Provenance{ID: "osv-ubuntu", Version: "Ubuntu:22.04"}}, Packages: []PackageMatches{
		{Package: "bash", Installed: "5.1", Vulnerabilities: []Vulnerability{
			{ID: "CVE-2026-10", Status: StatusFixAvailable, Fixed: "5.2", Severity: sev(LevelMedium)},
		}},
		{Package: "openssl", Installed: "3.0.2-1", Vulnerabilities: []Vulnerability{
			{ID: "CVE-2026-1", Status: StatusFixAvailable, Fixed: "3.0.2-2", Severity: sev(LevelHigh)},
			{ID: "CVE-2026-2", Status: StatusFixAvailable, Fixed: "3.0.2-2", Severity: sev(LevelLow)},
			{ID: "CVE-2026-3", Status: StatusUnfixed, Severity: sev(LevelCritical)},
		}},
	}, Installed: 2}
	v.count()
	return v
}

// The catalog marks what it lists and nothing else, and a package's
// vulnerabilities known to be exploited come first, the most severe first,
// then the rest in their order: a fix available ahead of the unfixed, the
// most severe first within each. The counts include those known exploited.
func TestMarkExploited(t *testing.T) {
	v := exploitedView()
	v.MarkExploited(catalog{
		"CVE-2026-2": {Added: "2026-11-20", Due: "2026-12-11", Ransomware: "Known"},
		"CVE-2026-3": {Added: "2026-11-21", Due: "2026-12-12", Ransomware: "Unknown"},
	}, kevData)

	var order []string
	for _, found := range v.Packages[1].Vulnerabilities {
		order = append(order, found.ID)
	}
	if got := strings.Join(order, ","); got != "CVE-2026-3,CVE-2026-2,CVE-2026-1" {
		t.Errorf("openssl's vulnerabilities are in the order %s, want the critical and the low known exploited, then the high", got)
	}
	if e := v.Packages[1].Vulnerabilities[1].KnownExploited; e == nil || e.Added != "2026-11-20" || e.Ransomware != "Known" {
		t.Errorf("CVE-2026-2 is marked %+v", e)
	}
	if v.Packages[1].Vulnerabilities[2].KnownExploited != nil || v.Packages[0].Vulnerabilities[0].KnownExploited != nil {
		t.Error("a vulnerability the catalog does not list was marked")
	}
	if v.Counts.KnownExploited != 2 || v.Counts.FixAvailable != 3 || v.Counts.Unfixed != 1 {
		t.Errorf("counts %+v", v.Counts)
	}
	if v.KnownExploited == nil || *v.KnownExploited != kevData {
		t.Errorf("the view names the catalog's data as %+v", v.KnownExploited)
	}
}

// The text lists every vulnerability known to be exploited first and apart,
// fixed or not, the most severe first, with the catalog's data and
// attribution, and leaves them out of the list of the rest with a fix
// available. With none listed, or the catalog not read, it says so.
func TestWriteTextKnownExploited(t *testing.T) {
	v := exploitedView()
	v.MarkExploited(catalog{
		"CVE-2026-2":  {Added: "2026-11-20", Ransomware: "Known"},
		"CVE-2026-3":  {Added: "2026-11-21", Ransomware: "Unknown"},
		"CVE-2026-10": {Added: "2026-11-19", Ransomware: "Unknown"},
	}, kevData)
	var b strings.Builder
	if err := WriteText(&b, v); err != nil {
		t.Fatal(err)
	}
	text := b.String()
	want := "\n3 vulnerabilities known to be exploited, by kev, 2026.11.23, data of 2026-11-23, current:\n" +
		"  critical    CVE-2026-3           openssl 3.0.2-1, unfixed; added 2026-11-21, ransomware use Unknown\n" +
		"  medium      CVE-2026-10          bash 5.1, fixed in 5.2; added 2026-11-19, ransomware use Unknown\n" +
		"  low         CVE-2026-2           openssl 3.0.2-1, fixed in 3.0.2-2; added 2026-11-20, ransomware use Known\n" +
		"  Attributed as the catalog asks.\n" +
		"\nFix available:\n" +
		"  high        CVE-2026-1           openssl 3.0.2-1, fixed in 3.0.2-2\n"
	if !strings.Contains(text, want) {
		t.Errorf("the text lacks\n%s\nin\n%s", want, text)
	}

	for name, c := range map[string]struct {
		catalog catalog
		use     dataset.Use
		want    string
	}{
		"none listed": {catalog{}, kevData, "\nNone is known to be exploited, by kev, 2026.11.23, data of 2026-11-23, current.\n"},
		"not read":    {catalog{}, dataset.Use{Provenance: dataset.Provenance{ID: "kev"}, NotDone: "kev is not held"}, "\nKnown exploitation was not read: kev is not held\n"},
	} {
		v := exploitedView()
		v.MarkExploited(c.catalog, c.use)
		b.Reset()
		if err := WriteText(&b, v); err != nil || !strings.Contains(b.String(), c.want) || !strings.Contains(b.String(), "high        CVE-2026-1") {
			t.Errorf("%s: wrote %q, %v, want %q", name, b.String(), err, c.want)
		}
	}
}

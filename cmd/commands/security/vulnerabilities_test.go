// cmd/commands/security/vulnerabilities_test.go

package security

import (
	"slices"
	"strings"
	"testing"

	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/dataset/epss"
	"github.com/papa0four/orkowatch/internal/dataset/kev"
	"github.com/papa0four/orkowatch/internal/dataset/osv"
	"github.com/papa0four/orkowatch/internal/tone"
	"github.com/papa0four/orkowatch/internal/tui"
	"github.com/papa0four/orkowatch/internal/vulnmatch"
)

// matchedView is a match of two packages: openssl with one vulnerability
// fixable and labeled high by its records and one unfixed labeled low, bash
// with one unfixed that states only a CVSS vector, and one pair not matched.
func matchedView() vulnmatch.View {
	v := vulnmatch.View{Use: dataset.Use{Provenance: dataset.Provenance{ID: "osv-ubuntu", Version: "Ubuntu:22.04", DataDate: "2026-11-24", State: dataset.StateCurrent}},
		Packages: []vulnmatch.PackageMatches{
			{Package: "bash", Installed: "5.1-6ubuntu1", Vulnerabilities: []vulnmatch.Vulnerability{
				{ID: "CVE-2026-3", Status: vulnmatch.StatusUnfixed, Severity: vulnmatch.Severity{Level: vulnmatch.LevelNone}, Records: []string{"UBUNTU-CVE-2026-3"}},
			}},
			{Package: "openssl", Installed: "3.0.2-1", Binaries: []string{"libssl3", "openssl"}, Vulnerabilities: []vulnmatch.Vulnerability{
				{ID: "CVE-2026-1", Status: vulnmatch.StatusFixAvailable, Fixed: "3.0.2-2", Severity: vulnmatch.Severity{Label: "Important", Level: vulnmatch.LevelHigh, Basis: "advisory rating"},
					Scores: []osv.Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N"}}, Records: []string{"UBUNTU-CVE-2026-1", "USN-1-1"}},
				{ID: "CVE-2026-2", Status: vulnmatch.StatusUnfixed, Severity: vulnmatch.Severity{Label: "low", Level: vulnmatch.LevelLow, Basis: "CVSS v3.1 base 3.1"}, Records: []string{"UBUNTU-CVE-2026-2"}},
			}},
		},
		NotMatched: []vulnmatch.NotMatched{{ID: "CVE-2026-4", Package: "nodejs", Installed: "1:20.1-1.module+el9", Reason: "a module build"}},
		Counts:     vulnmatch.Counts{FixAvailable: 1, Unfixed: 2, NotMatched: 1},
	}
	return v
}

// field returns the value of the field labeled label in r.
func field(r tui.Record, label string) string {
	for _, f := range r.Fields {
		if f.Label == label {
			return f.Value
		}
	}
	return ""
}

// The tab lists each vulnerability of each package in the match's order, the
// most severe first, then not matched; each record falls under its status and its
// records' severity label; it opens on those with a fix available; and its
// detail gives the package, what was built from it, the versions, the scores
// as the records give them, the records, and the dataset.
func TestVulnerabilitiesTab(t *testing.T) {
	tab := vulnerabilitiesTab(matchedView())
	if tab.ID != tui.TabVulnerabilities || tab.Note != "" {
		t.Fatalf("tab %q, note %q", tab.ID, tab.Note)
	}
	var rows []string
	for _, r := range tab.Records {
		rows = append(rows, r.Title+" | "+r.Subtitle.String()+" | "+r.Filters[0][0]+","+r.Filters[1][0])
	}
	want := []string{
		"CVE-2026-1  openssl | Important  fix 3.0.2-2 | fix available,high",
		"CVE-2026-2  openssl | low  unfixed | unfixed,low",
		"CVE-2026-3  bash | unfixed | unfixed,none stated",
		"CVE-2026-4  nodejs | not matched | not matched,none stated",
	}
	if !slices.Equal(rows, want) {
		t.Errorf("rows\n%s\nwant\n%s", strings.Join(rows, "\n"), strings.Join(want, "\n"))
	}
	if len(tab.Filters) != 2 || tab.Filters[0].Start != vulnmatch.StatusFixAvailable ||
		!slices.Equal(tab.Filters[0].Options, []string{tui.All, "fix available", "unfixed", "not matched"}) ||
		!slices.Equal(tab.Filters[1].Options, []string{tui.All, "high", "low", "none stated"}) {
		t.Errorf("filters %+v", tab.Filters)
	}

	fixable := tab.Records[0]
	for label, value := range map[string]string{
		"package":                          "openssl",
		"installed packages built from it": "libssl3, openssl",
		"installed":                        "3.0.2-1",
		"fixed in":                         "3.0.2-2",
		"severity":                         "Important, placed with high (advisory rating)",
		"scores, as the records give them": "CVSS_V3: CVSS:3.1/AV:N",
		"records":                          "UBUNTU-CVE-2026-1, USN-1-1",
		"matched against":                  "osv-ubuntu, Ubuntu:22.04, data of 2026-11-24, current",
	} {
		if got := field(fixable, label); got != value {
			t.Errorf("%s: %q, want %q", label, got, value)
		}
	}
	if got := field(tab.Records[3], "not matched"); got != "a module build" {
		t.Errorf("the pair not matched gives %q", got)
	}
}

// With the catalog read, the vulnerabilities it lists come first under their
// own band, the most severe first and whether fixed or not, marked on the row
// with the entry and the catalog in the detail; the rest follow under theirs;
// and the tab filters by it. With the catalog not read there
// are no bands and no filter, and the detail says why.
func TestVulnerabilitiesTabKnownExploited(t *testing.T) {
	v := matchedView()
	v.Packages[1].Vulnerabilities[0].KnownExploited = &kev.Entry{Added: "2026-11-20", Due: "2026-12-11", Ransomware: "Known"}
	v.Packages[0].Vulnerabilities[0].KnownExploited = &kev.Entry{Added: "2026-11-19", Due: "2026-12-10", Ransomware: "Unknown"}
	v.KnownExploited = &dataset.Use{Provenance: dataset.Provenance{ID: "kev", Version: "2026.11.21", DataDate: "2026-11-21", State: dataset.StateCurrent, Attribution: "As the catalog asks."}}
	tab := vulnerabilitiesTab(v)

	var rows []string
	for _, r := range tab.Records {
		rows = append(rows, r.Band+" | "+r.Title+" | "+r.Subtitle.String()+" | "+r.Filters[2][0])
	}
	want := []string{
		"known exploited | CVE-2026-1  openssl | exploited  Important  fix 3.0.2-2 | known exploited",
		"known exploited | CVE-2026-3  bash | exploited  unfixed | known exploited",
		"not in the catalog | CVE-2026-2  openssl | low  unfixed | not in the catalog",
		"not in the catalog | CVE-2026-4  nodejs | not matched | not in the catalog",
	}
	if !slices.Equal(rows, want) {
		t.Errorf("rows\n%s\nwant\n%s", strings.Join(rows, "\n"), strings.Join(want, "\n"))
	}
	if len(tab.Filters) != 3 || !slices.Equal(tab.Filters[2].Options, []string{tui.All, "known exploited", "not in the catalog"}) || tab.Filters[2].Start != tui.All {
		t.Errorf("filters %+v", tab.Filters)
	}
	if tab.Alert != "known exploited" || tab.Filters[0].Spares != "known exploited" || tab.Filters[1].Spares != "" || tab.Filters[2].Spares != "" {
		t.Errorf("the tab sets apart %q, and its filters spare %q, %q, %q; want the status filter alone to spare the known exploited",
			tab.Alert, tab.Filters[0].Spares, tab.Filters[1].Spares, tab.Filters[2].Spares)
	}
	if got := field(tab.Records[0], "known to be exploited"); got != "added to the catalog 2026-11-20\ndue date 2026-12-11\nransomware use Known" {
		t.Errorf("the entry reads %q", got)
	}
	if got := field(tab.Records[2], "known exploitation"); got != "kev, 2026.11.21, data of 2026-11-21, current\nAs the catalog asks." || field(tab.Records[2], "known to be exploited") != "" {
		t.Errorf("a vulnerability the catalog does not list reads %q", got)
	}

	v = matchedView()
	v.KnownExploited = &dataset.Use{Provenance: dataset.Provenance{ID: "kev"}, NotDone: "kev is not held"}
	tab = vulnerabilitiesTab(v)
	if len(tab.Filters) != 2 || tab.Records[0].Band != "" || tab.Alert != "" || tab.Filters[0].Spares != "" || field(tab.Records[0], "known exploitation") != "not read: kev is not held" {
		t.Errorf("with the catalog not read: filters %+v, band %q, detail %q", tab.Filters, tab.Records[0].Band, field(tab.Records[0], "known exploitation"))
	}
}

// With the scores read, each row carries its EPSS score after its severity,
// or a dash where the file gives none, and the detail gives a scored
// vulnerability's score and percentile as FIRST defines them, and every
// record names the file. With the scores not read no row carries a score and
// the detail says why.
func TestVulnerabilitiesTabPredicted(t *testing.T) {
	v := matchedView()
	v.Packages[1].Vulnerabilities[0].ExploitPrediction = &epss.Prediction{Score: 0.00043, Percentile: 0.12345}
	v.ExploitPrediction = &dataset.Use{Provenance: dataset.Provenance{ID: "epss", Version: "v2026.06.15", DataDate: "2026-11-23", State: dataset.StateCurrent, Attribution: "As FIRST asks."}}
	tab := vulnerabilitiesTab(v)

	var rows []string
	for _, r := range tab.Records {
		rows = append(rows, r.Title+" | "+r.Subtitle.String())
	}
	want := []string{
		"CVE-2026-1  openssl | Important  EPSS 0.043%  fix 3.0.2-2",
		"CVE-2026-2  openssl | low  EPSS -  unfixed",
		"CVE-2026-3  bash | EPSS -  unfixed",
		"CVE-2026-4  nodejs | not matched",
	}
	if !slices.Equal(rows, want) {
		t.Errorf("rows\n%s\nwant\n%s", strings.Join(rows, "\n"), strings.Join(want, "\n"))
	}
	if got := field(tab.Records[0], "exploit prediction"); got != "score 0.043%, the probability that it will be exploited in the wild in the next 30 days\n"+
		"percentile 12.3%, the proportion of all scored vulnerabilities with the same score or lower" {
		t.Errorf("the prediction reads %q", got)
	}
	if got := field(tab.Records[1], "exploit prediction data"); got != "epss, v2026.06.15, data of 2026-11-23, current\nAs FIRST asks." || field(tab.Records[1], "exploit prediction") != "" {
		t.Errorf("a vulnerability the file does not score reads %q", got)
	}

	v = matchedView()
	v.ExploitPrediction = &dataset.Use{Provenance: dataset.Provenance{ID: "epss"}, NotDone: "epss is not held"}
	tab = vulnerabilitiesTab(v)
	if strings.Contains(tab.Records[0].Subtitle.String(), "EPSS") || field(tab.Records[0], "exploit prediction data") != "not read: epss is not held" {
		t.Errorf("with the scores not read: subtitle %q, detail %q", tab.Records[0].Subtitle.String(), field(tab.Records[0], "exploit prediction data"))
	}
}

// With nothing fixable the tab opens on all; with no match made it says why.
func TestVulnerabilitiesTabOpensAndNotes(t *testing.T) {
	v := matchedView()
	v.Packages = v.Packages[:1]
	v.Counts.FixAvailable = 0
	if tab := vulnerabilitiesTab(v); tab.Filters[0].Start != tui.All {
		t.Errorf("with nothing fixable the tab opens on %q", tab.Filters[0].Start)
	}
	tab := vulnerabilitiesTab(vulnmatch.View{Use: dataset.Use{NotDone: "osv-ubuntu is not held; fetch it with owatch data refresh"}})
	if tab.Note != "Matching was not done: osv-ubuntu is not held; fetch it with owatch data refresh" || len(tab.Records) != 0 {
		t.Errorf("a match not made: %+v", tab)
	}
}

// A severity is shown with what it rests on, and with the level it is placed
// at when the source's word is another; with none stated it says so.
func TestSeverityText(t *testing.T) {
	for want, s := range map[string]vulnmatch.Severity{
		"medium (Ubuntu priority)":                       {Label: "medium", Level: vulnmatch.LevelMedium, Basis: "Ubuntu priority"},
		"Moderate, placed with medium (advisory rating)": {Label: "Moderate", Level: vulnmatch.LevelMedium, Basis: "advisory rating"},
		"high (CVSS v3.1 base 7.1)":                      {Label: "high", Level: vulnmatch.LevelHigh, Basis: "CVSS v3.1 base 7.1"},
		"none stated":                                    {Level: vulnmatch.LevelNone},
	} {
		if got := severityText(s); got != want {
			t.Errorf("%+v: %q, want %q", s, got, want)
		}
	}
}

// The tab is offered after Software by a report that holds a match, and by
// no other, so a report from before matching opens as it did.
func TestVulnerabilitiesTabOffered(t *testing.T) {
	ids := func(src BrowserSource) []string {
		var out []string
		for _, tab := range BrowserReport(src).Tabs {
			out = append(out, tab.ID)
		}
		return out
	}
	v := matchedView()
	if got := ids(BrowserSource{Vulns: &v}); !slices.Equal(got[:3], []string{tui.TabSystem, tui.TabSoftware, tui.TabVulnerabilities}) {
		t.Errorf("with a match the tabs are %q", got)
	}
	if got := ids(BrowserSource{}); slices.Contains(got, tui.TabVulnerabilities) {
		t.Errorf("without a match the tabs are %q", got)
	}
}

// A vulnerability's subtitle colors known exploitation and the severity, each
// in its own tone, and nothing else; its severity field is in the severity's
// tone.
func TestVulnerabilityRecordTones(t *testing.T) {
	v := matchedView()
	v.Packages[1].Vulnerabilities[0].KnownExploited = &kev.Entry{Added: "2026-11-20"}
	v.KnownExploited = &dataset.Use{Provenance: dataset.Provenance{ID: "kev"}}
	r := vulnerabilitiesTab(v).Records[0]
	var toned []tui.Span
	for _, s := range r.Subtitle {
		if s.Tone != tone.Plain {
			toned = append(toned, s)
		}
	}
	want := []tui.Span{{Text: "exploited", Tone: tone.KnownExploited}, {Text: "Important", Tone: tone.High}}
	if !slices.Equal(toned, want) {
		t.Errorf("the toned words are %+v, want %+v", toned, want)
	}
	for _, f := range r.Fields {
		if f.Label == "severity" && f.Tone != tone.High {
			t.Errorf("the severity field is in tone %d", f.Tone)
		}
	}
}

// The severity filter tones each level it offers, and the status filter none.
func TestVulnerabilityFilterTones(t *testing.T) {
	tab := vulnerabilitiesTab(matchedView())
	if tab.Filters[0].Tones != nil {
		t.Errorf("the status filter has tones %v", tab.Filters[0].Tones)
	}
	if got := tab.Filters[1].Tones; got["high"] != tone.High || got["low"] != tone.Low || got["none stated"] != tone.Plain {
		t.Errorf("the severity filter's tones are %v", got)
	}
}

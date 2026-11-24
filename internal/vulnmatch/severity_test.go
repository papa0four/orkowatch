// internal/vulnmatch/severity_test.go

package vulnmatch

import (
	"slices"
	"testing"

	"github.com/papa0four/orkowatch/internal/dataset/osv"
	"github.com/papa0four/orkowatch/internal/softwarelist"
)

// The vectors are ones OSV's records carried on 2026-11-24, with the base
// score Ubuntu's page for the CVE gave: 6.1, 9.0, and 7.1.
const (
	vector61 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
	vector90 = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H"
	vector71 = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
)

// A severity is the distribution's own label where the records state one,
// and the most severe of them: Ubuntu's priority, or an advisory's rating,
// placed on the one scale and kept in the source's word. Where they state
// none it is the band of the highest base score among the vectors that can
// be scored, named with its version and score. Where there is nothing to read
// it is none stated.
func TestSeverityOf(t *testing.T) {
	for name, tt := range map[string]struct {
		scores  []osv.Severity
		ratings []string
		want    Severity
	}{
		"an Ubuntu priority beside a vector": {[]osv.Severity{{Type: "CVSS_V3", Score: vector90}, {Type: "Ubuntu", Score: "medium"}}, nil,
			Severity{Label: "medium", Level: LevelMedium, Basis: "Ubuntu priority"}},
		"an Ubuntu priority of negligible": {[]osv.Severity{{Type: "Ubuntu", Score: "negligible"}}, nil,
			Severity{Label: "negligible", Level: LevelNegligible, Basis: "Ubuntu priority"}},
		"a rating": {nil, []string{"Important"},
			Severity{Label: "Important", Level: LevelHigh, Basis: "advisory rating"}},
		"a rating beside a vector": {[]osv.Severity{{Type: "CVSS_V3", Score: vector90}}, []string{"Moderate"},
			Severity{Label: "Moderate", Level: LevelMedium, Basis: "advisory rating"}},
		"two advisories' ratings": {nil, []string{"Low", "Critical", "Moderate"},
			Severity{Label: "Critical", Level: LevelCritical, Basis: "advisory rating"}},
		"a v3.1 vector alone": {[]osv.Severity{{Type: "CVSS_V3", Score: vector71}}, nil,
			Severity{Label: "high", Level: LevelHigh, Basis: "CVSS v3.1 base 7.1"}},
		"a v3.0 vector alone": {[]osv.Severity{{Type: "CVSS_V3", Score: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}}, nil,
			Severity{Label: "medium", Level: LevelMedium, Basis: "CVSS v3.0 base 6.1"}},
		"two vectors, the higher": {[]osv.Severity{{Type: "CVSS_V3", Score: vector61}, {Type: "CVSS_V3", Score: vector90}}, nil,
			Severity{Label: "critical", Level: LevelCritical, Basis: "CVSS v3.1 base 9.0"}},
		"a base score of zero": {[]osv.Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"}}, nil,
			Severity{Label: "none", Level: LevelNegligible, Basis: "CVSS v3.1 base 0.0"}},
		"a vector that is not scored": {[]osv.Severity{{Type: "CVSS_V2", Score: "AV:N/AC:L/Au:N/C:P/I:P/A:P"}}, nil,
			Severity{Level: LevelNone}},
		"a damaged vector":           {[]osv.Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N"}}, nil, Severity{Level: LevelNone}},
		"a word that is no priority": {[]osv.Severity{{Type: "Ubuntu", Score: "untriaged"}}, nil, Severity{Level: LevelNone}},
		"a rating that is none":      {nil, []string{"Severe"}, Severity{Level: LevelNone}},
		"nothing":                    {nil, nil, Severity{Level: LevelNone}},
	} {
		if got := severityOf(tt.scores, tt.ratings); got != tt.want {
			t.Errorf("%s: %+v, want %+v", name, got, tt.want)
		}
	}
}

// A v4.0 vector is scored by the v4.0 code and named as v4.0: a vector with
// every impact high, reached from the network with nothing required, is
// critical.
func TestSeverityOfV4(t *testing.T) {
	got := severityOf([]osv.Severity{{Type: "CVSS_V4", Score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"}}, nil)
	if got.Level != LevelCritical || got.Basis != "CVSS v4.0 base 10.0" {
		t.Errorf("a v4.0 vector gave %+v", got)
	}
}

// The scale runs from critical to none stated, and a match carries each
// vulnerability's severity with the raw scores beside it, a package's
// vulnerabilities ordered by it after those with a fix come first. Ratings
// reach the match from the records.
func TestMatchCarriesSeverity(t *testing.T) {
	if want := []string{"critical", "high", "medium", "low", "negligible", "none stated"}; !slices.Equal(Levels(), want) {
		t.Fatalf("levels %q", Levels())
	}
	rated := func(id, cve, rating, vector string) osv.Record {
		r := record(id, []string{cve}, "kernel", events("introduced", "0"))
		r.Rating, r.Severity = rating, nil
		if vector != "" {
			r.Severity = []osv.Severity{{Type: "CVSS_V3", Score: vector}}
		}
		return r
	}
	v := matched(t, "rpm", []softwarelist.SoftwareEntry{{Name: "kernel", Version: "5.14.0-1.el9", Manager: "rpm"}},
		rated("RLSA-1", "CVE-2026-1", "Moderate", vector90),
		rated("RLSA-2", "CVE-2026-2", "Critical", ""),
		rated("RLSA-3", "CVE-2026-3", "", vector71),
		rated("RLSA-4", "CVE-2026-4", "", ""),
	)
	var got []string
	for _, found := range v.Packages[0].Vulnerabilities {
		got = append(got, found.ID+" "+found.Severity.Level+" "+found.Severity.Basis)
	}
	want := []string{
		"CVE-2026-2 critical advisory rating",
		"CVE-2026-3 high CVSS v3.1 base 7.1",
		"CVE-2026-1 medium advisory rating",
		"CVE-2026-4 none stated ",
	}
	if !slices.Equal(got, want) {
		t.Errorf("severities %q, want %q", got, want)
	}
	if scores := v.Packages[0].Vulnerabilities[2].Scores; len(scores) != 1 || scores[0].Score != vector90 {
		t.Errorf("the raw scores of CVE-2026-1 are %+v", scores)
	}
}

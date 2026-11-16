// internal/cvss/v4/v4_test.go

package v4

import (
	"encoding/json"
	"math"
	"os"
	"strings"
	"testing"
)

func mustParse(t *testing.T, vector string) Vector {
	t.Helper()
	v, err := Parse(vector)
	if err != nil {
		t.Fatalf("%s: %v", vector, err)
	}
	return v
}

// The vectors the specification (section on vector strings) gives as valid are
// accepted, and the ones it gives as invalid are refused, each for the reason it
// states.
func TestParseSpecificationExamples(t *testing.T) {
	valid := []string{
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/E:A",
		"CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:P",
		"CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:A/VC:N/VI:N/VA:L/SC:H/SI:H/SA:H/CR:H/IR:H/AR:M/MAV:N/MAC:L/MAT:P/MPR:L/MUI:A/MVC:N/MVI:H/MVA:L/MSC:L/MSI:S/MSA:H",
		"CVSS:4.0/AV:P/AC:H/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:A/S:P/AU:Y/R:A/V:D/RE:L/U:Red",
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/E:U/CR:L/IR:X/AR:L/MAV:A/MAC:H/MAT:N/MPR:N/MUI:P/MVC:X/MVI:N/MVA:H/MSC:N/MSI:L/MSA:S/S:N/AU:N/R:I/V:C/RE:H/U:Green",
	}
	for _, vector := range valid {
		if _, err := Parse(vector); err != nil {
			t.Errorf("valid vector refused: %v", err)
		}
	}

	invalid := map[string]string{
		"CVSS:4.0/AV:F/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N":                      "not one of",
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N/E:A/E:X":              "unknown, repeated or out of the specified order",
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/ui:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N":                      "unknown, repeated or out of the specified order",
		"AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N":                               "does not begin with CVSS:4.0",
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/SC:N/SI:N/SA:N":                           "missing the Base metric VA",
		"CVSS:4.0/AC:L/AV:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/CR:L/IR:X/AR:L/RE:H/MAV:A": "missing the Base metric AV",
	}
	for vector, want := range invalid {
		_, err := Parse(vector)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: error %v, want one containing %q", vector, err, want)
		}
	}
}

// More ways a vector is malformed.
func TestParseRefusals(t *testing.T) {
	const base = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
	for vector, want := range map[string]string{
		"": "does not begin with",
		"CVSS:3.1/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N": "does not begin with",
		base + "/E":         "where a metric:value pair belongs",
		base + "/E:A:B":     "where a metric:value pair belongs",
		base + "/E:Z":       "not one of",
		base + "/e:A":       "unknown, repeated or out of the specified order",
		base + "/MSC:S":     "not one of",
		base + "/U:red":     "not one of",
		base + "/MAV:A/E:A": "unknown, repeated or out of the specified order",
	} {
		if _, err := Parse(vector); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: error %v, want one containing %q", vector, err, want)
		}
	}
}

// The scores FIRST prints in its Implementation Guide (Tables 2 to 6 and the
// worked examples that follow) and its User Guide, for the vectors printed with
// them. B is the guide's base vector, a network device with high impact on the
// vulnerable system and none on a subsequent one.
func TestScoresMatchFIRSTGuides(t *testing.T) {
	const b = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
	cases := []struct {
		vector string
		want   float64
	}{
		// Implementation Guide.
		{b, 9.3},
		{b + "/MAV:A", 8.7},
		{b + "/MAV:L", 8.6},
		{b + "/MAV:A/MAC:H", 7.7},
		{b + "/MAV:A/MAC:H/MAT:P", 7.7},
		{b + "/MAV:A/MAC:H/MAT:P/MPR:H", 7.3},
		{b + "/E:P/MAV:A/MAC:H/MAT:P/MPR:H", 6.4},
		{b + "/MAV:A/MAC:H/MPR:H/MUI:A", 5.4},
		{b + "/E:U/MAV:A/MAC:H/MPR:H/MUI:A", 2.0},
		{b + "/MAV:A/MAC:H/MPR:H/MUI:A/MVC:L", 4.6},
		{b + "/E:U/MAV:A/MAC:H/MPR:H/MUI:A/MVC:N", 0.7},
		{b + "/MAV:A/MAC:H/MPR:H/MUI:A/MVC:L/MVI:L", 4.4},
		{b + "/MAV:A/MAC:H/MPR:H/MUI:A/MVA:L", 5.3},
		{b + "/E:U/MAV:A/MAC:H/MPR:H/MUI:A/MVA:L", 1.9},
		{b + "/MAV:A/MAC:H/MPR:H/MUI:A/MVC:L/MVI:L/MVA:L", 1.0},
		{b + "/E:U/MAV:A/MAC:H/MPR:H/MUI:A/MVC:L/MVI:L/MVA:L", 0.1},
		// User Guide. Its MySQL example (CVE-2013-0375) prints CVSS-B 5.1 and
		// CVSS-BE 4.9 for AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N, and
		// FIRST's calculator scores that vector 5.3 and with MAV:A 5.1. The guide
		// is the outlier: the calculator agrees with every other FIRST example below
		// and with NVD, so the two guide figures are not used.
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", 8.7},
		{"CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 8.5},
	}
	for _, c := range cases {
		if got := mustParse(t, c.vector).Score(); math.Abs(got-c.want) > 1e-9 {
			t.Errorf("%s scores %.1f, FIRST prints %.1f", c.vector, got, c.want)
		}
	}
}

// scoresFile is a list of vectors with the scores a source publishes for them.
type scoresFile struct {
	Entries []struct {
		Vector   string  `json:"vector"`
		Score    float64 `json:"score"`
		Severity string  `json:"severity"`
		CVE      string  `json:"cve"`
	} `json:"entries"`
}

func loadScores(t *testing.T, path string) scoresFile {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var file scoresFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	return file
}

// The vectors FIRST prints with a score on its Examples page, which are real
// vulnerabilities scored by the people who maintain the standard, score here as
// FIRST prints them.
func TestScoresMatchFIRSTExamples(t *testing.T) {
	file := loadScores(t, "testdata/first_examples.json")
	if len(file.Entries) < 50 {
		t.Fatalf("the sample holds %d vectors", len(file.Entries))
	}
	for _, e := range file.Entries {
		if got := mustParse(t, e.Vector).Score(); math.Abs(got-e.Score) > 1e-9 {
			t.Errorf("%s scores %.1f, FIRST prints %.1f", e.Vector, got, e.Score)
		}
	}
}

// Every vector in a sample of 372 distinct ones taken from the NVD CVE API scores
// here as NVD scores it, with one kind of exception: where the unrounded score
// sits on a rounding tie, FIRST's calculator, whose arithmetic this follows, can
// land a hair under the tie and round down while NVD rounds up. The two vectors
// of that kind in the sample are 5.65 to within floating-point error; owatch
// scores them as FIRST's calculator does, because that is the score a reader can
// reproduce there.
func TestScoresMatchNVD(t *testing.T) {
	file := loadScores(t, "testdata/nvd_scores.json")
	if len(file.Entries) < 300 {
		t.Fatalf("the NVD sample holds %d vectors", len(file.Entries))
	}
	var ties int
	for _, e := range file.Entries {
		v, err := Parse(e.Vector)
		if err != nil {
			t.Errorf("%s (%s): NVD's own vector is refused: %v", e.CVE, e.Vector, err)
			continue
		}
		got := v.Score()
		if math.Abs(got-e.Score) > 1e-9 {
			tenths := v.raw() * 10
			onTie := math.Abs(tenths-math.Floor(tenths)-0.5) < 1e-9
			nvdRoundsUp := math.Abs(e.Score*10-(math.Floor(tenths)+1)) < 1e-9
			if !onTie || !nvdRoundsUp {
				t.Errorf("%s: %s scores %.1f (unrounded %.12f), NVD publishes %.1f", e.CVE, e.Vector, got, v.raw(), e.Score)
				continue
			}
			ties++
		}
		if sev := Severity(e.Score); !strings.EqualFold(sev, e.Severity) {
			t.Errorf("%s: NVD's score %.1f is %s, NVD rates it %s", e.CVE, e.Score, sev, e.Severity)
		}
	}
	if ties > 2 {
		t.Errorf("%d vectors differ from NVD on a rounding tie, where the sample has 2", ties)
	}
}

// A vector with no impact on any system scores 0.0, whatever its exploitability.
func TestNoImpactScoresZero(t *testing.T) {
	v := mustParse(t, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N")
	if got := v.Score(); got != 0 {
		t.Errorf("a vector with no impact scores %.1f", got)
	}
	// A Modified Base metric can remove all impact too.
	v = mustParse(t, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/MVC:N")
	if got := v.Score(); got != 0 {
		t.Errorf("a Modified Base metric that removes the impact leaves %.1f", got)
	}
}

// Every combination of Base metrics belongs to a MacroVector FIRST's table scores,
// and scores within 0.0 to 10.0, so no vector a person can write falls outside the
// table. Threat and Environmental metrics choose among the same MacroVectors.
func TestEveryBaseVectorHasAScore(t *testing.T) {
	var count int
	var walk func(i int, parts []string)
	walk = func(i int, parts []string) {
		if i == baseCount {
			v, err := Parse(prefix + "/" + strings.Join(parts, "/"))
			if err != nil {
				t.Fatal(err)
			}
			count++
			if s := v.Score(); math.IsNaN(s) || s < 0 || s > 10 {
				t.Fatalf("%s scores %v", v, s)
			}
			return
		}
		for _, value := range metrics[i].values {
			walk(i+1, append(parts[:i:i], metrics[i].name+":"+value))
		}
	}
	walk(0, nil)
	const want = 4 * 2 * 2 * 3 * 3 * 3 * 3 * 3 * 3 * 3 * 3
	if count != want {
		t.Fatalf("walked %d base vectors, want %d", count, want)
	}
}

// The label says which metrics a score was made from, as the specification
// requires wherever a score is displayed.
func TestNomenclature(t *testing.T) {
	const b = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
	for suffix, want := range map[string]string{
		"":                 "CVSS-B",
		"/E:X":             "CVSS-B",
		"/E:P":             "CVSS-BT",
		"/MAV:A":           "CVSS-BE",
		"/CR:H":            "CVSS-BE",
		"/MSA:S":           "CVSS-BE",
		"/E:P/MAV:A":       "CVSS-BTE",
		"/S:P/AU:Y":        "CVSS-B",
		"/E:A/MAV:X/S:P":   "CVSS-BT",
		"/MAV:A/S:P/U:Red": "CVSS-BE",
	} {
		if got := mustParse(t, b+suffix).Nomenclature(); got != want {
			t.Errorf("%s: label %s, want %s", suffix, got, want)
		}
	}
}

// The qualitative scale of the specification's Table 22.
func TestSeverityBands(t *testing.T) {
	for score, want := range map[float64]string{0: "NONE", 0.1: "LOW", 3.9: "LOW", 4.0: "MEDIUM", 6.9: "MEDIUM", 7.0: "HIGH", 8.9: "HIGH", 9.0: "CRITICAL", 10.0: "CRITICAL"} {
		if got := Severity(score); got != want {
			t.Errorf("Severity(%.1f) = %s, want %s", score, got, want)
		}
	}
}

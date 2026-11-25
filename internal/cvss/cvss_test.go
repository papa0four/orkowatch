// internal/cvss/cvss_test.go

package cvss

import (
	"strings"
	"testing"

	"github.com/papa0four/orkowatch/internal/security/finding"
)

// The base score of a vector is the one its publisher states. The first three
// pairs are vectors OSV's records carried on 2026-11-24 with the base score
// Ubuntu's page for the CVE gave: CVE-2026-49264, 6.1; CVE-2026-11386, 9.0;
// and CVE-2026-54369, 7.1. A vector with no impact scores 0.0, as the
// specification's equations give. A v3.0 vector has the same metrics and is
// scored by the same equations, and says which version it is.
func TestBaseScore(t *testing.T) {
	for vector, want := range map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
		"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H": 9.0,
		"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N": 7.1,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0.0,
		"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
	} {
		v, err := Parse(vector)
		if err != nil {
			t.Errorf("%s: %v", vector, err)
			continue
		}
		if got := v.BaseScore(); got != want {
			t.Errorf("%s scores %.1f, want %.1f", vector, got, want)
		}
		if got, want := v.Version(), vector[len("CVSS:"):len("CVSS:3.1")]; got != want {
			t.Errorf("%s: version %q, want %q", vector, got, want)
		}
	}
}

// A vector of another version, one missing or repeating a metric, one with a
// value its metric does not allow, and one with a metric outside the base
// set are refused.
func TestParseRefuses(t *testing.T) {
	for name, vector := range map[string]string{
		"version 2":           "AV:N/AC:L/Au:N/C:P/I:P/A:P",
		"version 4":           "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
		"a missing metric":    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",
		"a repeated metric":   "CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"a value not allowed": "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"a temporal metric":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:H",
		"empty":               "",
	} {
		if _, err := Parse(vector); err == nil {
			t.Errorf("%s: %q was read", name, vector)
		}
	}
	if _, err := Parse("CVSS:2.0/AV:N"); err == nil || !strings.Contains(err.Error(), "CVSS:3.1 or CVSS:3.0") {
		t.Errorf("another version gave %v", err)
	}
}

// A score falls in the band the specification's qualitative scale gives it.
func TestBand(t *testing.T) {
	for score, want := range map[float64]string{
		0.0: finding.SeverityNone, 0.1: finding.SeverityLow, 3.9: finding.SeverityLow, 4.0: finding.SeverityMedium,
		6.9: finding.SeverityMedium, 7.0: finding.SeverityHigh, 8.9: finding.SeverityHigh, 9.0: finding.SeverityCritical, 10.0: finding.SeverityCritical,
	} {
		if got := Band(score); got != want {
			t.Errorf("%.1f is %s, want %s", score, got, want)
		}
	}
}

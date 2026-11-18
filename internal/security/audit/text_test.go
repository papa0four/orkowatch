// internal/security/audit/text_test.go

package audit

import (
	"strings"
	"testing"

	"github.com/papa0four/orkowatch/internal/render"
	"github.com/papa0four/orkowatch/internal/security/finding"
)

// hostScored is a finding whose baseline is the Implementation Guide's 9.3 web
// server and whose host score is the guide's localhost example, 8.6 with MAV:L.
func hostScored() *FindingView {
	return &FindingView{
		Title:    "service exposed",
		Severity: finding.SeverityHigh,
		CVSS: &finding.CVSSScore{Version: "4.0", Vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
			Score: 9.3, Severity: finding.SeverityCritical, Source: "registry", Nomenclature: "CVSS-B",
			Basis: "baseline for the condition, not measured on this host", CalculatorURL: "https://www.first.org/cvss/calculator/4.0#baseline"},
		Host: &finding.HostScore{
			CVSS: &finding.CVSSScore{Version: "4.0", Vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/MAV:L",
				Score: 8.6, Severity: finding.SeverityHigh, Source: "host evidence", Nomenclature: "CVSS-BE",
				Basis: "Modified Base metrics derived from evidence recorded on this host", CalculatorURL: "https://www.first.org/cvss/calculator/4.0#host"},
			Modified: []finding.ModifiedMetric{{Metric: "MAV", Value: "L", Fact: finding.Fact{Name: "listening", Value: "loopback-only"},
				Because: "sshd listens only on loopback addresses", Section: "Modified Attack Vector (MAV)",
				Quote: "the service is exposed locally", Carried: 1, Subjects: 1}},
			Unmodified: []finding.UnmodifiedMetric{{Metric: "MPR", Reason: "no file evidence was recorded, so PR:N stands"}},
		},
	}
}

func findingText(t *testing.T, def *FindingView) string {
	t.Helper()
	var out strings.Builder
	ew := render.NewErrWriter(&out)
	if err := writeFinding(ew, ConditionView{Key: "ssh.exposed", Result: finding.ResultFail, Finding: def}); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

// The text report shows the baseline and the score on this host, each
// labelled, and traces the host score to the fact and passage behind it.
func TestTextShowsBothScores(t *testing.T) {
	text := findingText(t, hostScored())
	for _, want := range []string{
		"  CVSS baseline: 9.3 CRITICAL  CVSS-B v4.0, baseline for the condition, not measured on this host  CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
		"    calculator: https://www.first.org/cvss/calculator/4.0#baseline",
		"  CVSS on this host: 8.6 HIGH  CVSS-BE v4.0, Modified Base metrics derived from evidence recorded on this host  CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/MAV:L",
		"    calculator: https://www.first.org/cvss/calculator/4.0#host",
		"    MAV:L from listening loopback-only on 1 of 1 subjects: sshd listens only on loopback addresses",
		"      Implementation Guide, Modified Attack Vector (MAV): \"the service is exposed locally\"",
		"    MPR not modified: no file evidence was recorded, so PR:N stands",
	} {
		if !strings.Contains(text, want+"\n") {
			t.Errorf("the text lacks %q:\n%s", want, text)
		}
	}
}

// A finding the host's evidence did not modify, and one with no rule, each say
// that the baseline is the score and why.
func TestTextStatesWhenTheBaselineStands(t *testing.T) {
	kept := hostScored()
	kept.Host.CVSS, kept.Host.Modified = nil, nil
	text := findingText(t, kept)
	for _, want := range []string{
		"  CVSS on this host: none; the evidence recorded on this host modified no metric, so the CVSS-B baseline stands\n",
		"    MPR not modified: no file evidence was recorded, so PR:N stands\n",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("an unmodified finding's text lacks %q:\n%s", want, text)
		}
	}

	norule := hostScored()
	norule.Host = nil
	want := "  CVSS on this host: none; no rule of this finding reads the host, so the CVSS-B baseline is its only score\n"
	if text := findingText(t, norule); !strings.Contains(text, want) {
		t.Errorf("a finding with no rule lacks %q:\n%s", want, text)
	}
}

// A fact value read from the host is written safely, as evidence is.
func TestHostScoreQuotesHostText(t *testing.T) {
	def := hostScored()
	def.Host.Modified[0].Fact.Value = "loopback\x1b[31m"
	if text := findingText(t, def); strings.Contains(text, "\x1b") {
		t.Errorf("a control sequence from the host reached the text:\n%q", text)
	}
}

// The severity's basis names the host score only when the host's evidence set
// it, with the registry's rating beside it.
func TestSeverityBasis(t *testing.T) {
	if got := SeverityBasis(hostScored()); got != "the CVSS-BE severity on this host; the registry rates the rule CRITICAL" {
		t.Errorf("a modified finding's basis: %q", got)
	}
	kept := hostScored()
	kept.Host.CVSS = nil
	if got := SeverityBasis(kept); got != "the registry's rating for this rule" {
		t.Errorf("an unmodified finding's basis: %q", got)
	}
}

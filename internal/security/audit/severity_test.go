// internal/security/audit/severity_test.go

package audit

import (
	"testing"

	"github.com/papa0four/orkowatch/internal/security/finding"
)

// A finding the host's evidence moved to another severity is counted, filtered
// and shown at that severity, and one it did not move keeps the registry's.
func TestHostSeverityGovernsTheRun(t *testing.T) {
	moved := finding.Condition{Key: "ssh.moved", Result: finding.ResultFail, Finding: &finding.Finding{
		Title:    "moved",
		Severity: finding.SeverityCritical,
		Host:     &finding.HostScore{CVSS: &finding.CVSSScore{Score: 8.6, Severity: finding.SeverityHigh, Nomenclature: "CVSS-BE"}},
	}}
	kept := finding.Condition{Key: "ssh.kept", Result: finding.ResultFail, Finding: &finding.Finding{
		Title:    "kept",
		Severity: finding.SeverityCritical,
		Host:     &finding.HostScore{Unmodified: []finding.UnmodifiedMetric{{Metric: "MAV", Reason: "listening: network"}}},
	}}
	result := Result{Results: []finding.AuditResult{{Key: "ssh", Result: finding.ResultFail, Conditions: []finding.Condition{moved, kept}}}}
	result.Summary = summarize(result.Results)

	if got := result.Summary.Findings; got[finding.SeverityHigh] != 1 || got[finding.SeverityCritical] != 1 {
		t.Errorf("summary counts %v", got)
	}

	view := result.View(finding.SeverityCritical)
	if view.FindingsSuppressed != 1 || len(view.Results[0].Conditions) != 1 || view.Results[0].Conditions[0].Key != "ssh.kept" {
		t.Errorf("at CRITICAL: %d suppressed, shown %+v", view.FindingsSuppressed, view.Results[0].Conditions)
	}

	view = result.View(finding.SeverityHigh)
	for _, c := range view.Results[0].Conditions {
		want := map[string]string{"ssh.moved": finding.SeverityHigh, "ssh.kept": finding.SeverityCritical}[c.Key]
		if c.Finding.Severity != want || c.Finding.Host == nil {
			t.Errorf("%s shown at %s with host score %+v, want %s", c.Key, c.Finding.Severity, c.Finding.Host, want)
		}
	}
}

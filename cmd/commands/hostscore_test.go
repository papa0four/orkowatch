// cmd/commands/hostscore_test.go

package cmd

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/papa0four/orkowatch/cmd/commands/delivery"
	"github.com/papa0four/orkowatch/cmd/commands/security"
	"github.com/papa0four/orkowatch/internal/security/audit"
	"github.com/papa0four/orkowatch/internal/security/finding"
)

// hostScoredAudit is an audit run with one finding the host's evidence moved,
// the Implementation Guide's localhost example: 9.3 baseline, 8.6 with MAV:L.
func hostScoredAudit() audit.View {
	def := &audit.FindingView{
		Title:    "Root login over SSH is permitted",
		Severity: finding.SeverityHigh,
		CVSS: &finding.CVSSScore{Version: "4.0", Vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
			Score: 9.3, Severity: finding.SeverityCritical, Source: "registry", Nomenclature: "CVSS-B",
			Basis: "baseline for the condition, not measured on this host"},
		Host: &finding.HostScore{
			CVSS: &finding.CVSSScore{Version: "4.0", Vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/MAV:L",
				Score: 8.6, Severity: finding.SeverityHigh, Source: "host evidence", Nomenclature: "CVSS-BE",
				Basis: "Modified Base metrics derived from evidence recorded on this host"},
			Modified: []finding.ModifiedMetric{{Metric: "MAV", Value: "L", Fact: finding.Fact{Name: "listening", Value: "loopback-only"},
				Because: "sshd listens only on loopback addresses", Section: "Modified Attack Vector (MAV)",
				Quote: "the service is exposed locally", Carried: 1, Subjects: 1}},
		},
	}
	return audit.View{
		Timestamp: "2026-11-17T12:00:00Z",
		Duration:  "1s",
		Results: []audit.CheckView{{Key: "ssh", Name: "SSH Configuration", Result: finding.ResultFail, Conditions: []audit.ConditionView{{
			Key: "ssh.root_login_permitted", Result: finding.ResultFail, Finding: def,
			Evidence: []finding.Evidence{{Kind: "listening", Subject: "sshd", Facts: []finding.Fact{{Name: "listening", Value: "loopback-only"}}}},
		}}}},
	}
}

// A saved audit report, JSON or YAML, opens to the findings a live run showed,
// the score on this host and what the severity rests on included, and each
// format labels both scores.
func TestHostScoreBrowseParity(t *testing.T) {
	view := hostScoredAudit()
	var text strings.Builder
	if err := security.WriteAuditText(&text, view); err != nil {
		t.Fatal(err)
	}
	live := security.BrowserReport(security.AuditSource("owatch audit", view, text.String()))
	if len(live.Items) != 1 || !strings.Contains(live.Items[0].HostCVSS, "8.6 HIGH  CVSS-BE") ||
		!strings.Contains(live.Items[0].SeverityBasis, "CVSS-BE severity on this host") {
		t.Fatalf("the live item does not carry the host score: %+v", live.Items)
	}

	for _, format := range []delivery.Format{delivery.FormatJSON, delivery.FormatYAML} {
		data := encodedHostScore(t, view, format)
		saved, err := decodeReport("saved."+format.Extension(), format, delivery.FormatText, data)
		if err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		if !reflect.DeepEqual(saved.Items, live.Items) {
			t.Errorf("%s: the saved report's findings differ from the live run's\n got  %+v\n want %+v", format, saved.Items, live.Items)
		}
		if saved.Text != live.Text {
			t.Errorf("%s: the saved report's text differs from the live run's", format)
		}
	}
}

// encodedHostScore encodes view as a command delivers it in format, checks the
// encoding labels both scores and decodes to the same host score, and returns
// it.
func encodedHostScore(t *testing.T, view audit.View, format delivery.Format) []byte {
	t.Helper()
	data, err := delivery.Encode(view, format)
	if err != nil {
		t.Fatal(err)
	}
	for _, label := range []string{"CVSS-B", "CVSS-BE", "host_score"} {
		if !strings.Contains(string(data), label) {
			t.Errorf("%s lacks %q:\n%s", format, label, data)
		}
	}
	var decoded audit.View
	if format == delivery.FormatJSON {
		err = json.Unmarshal(data, &decoded)
	} else {
		err = yaml.Unmarshal(data, &decoded)
	}
	if err != nil {
		t.Fatal(err)
	}
	want := view.Results[0].Conditions[0].Finding.Host
	if got := decoded.Results[0].Conditions[0].Finding.Host; !reflect.DeepEqual(got, want) {
		t.Errorf("%s does not carry the host score whole:\n got  %+v\n want %+v", format, got, want)
	}
	return data
}

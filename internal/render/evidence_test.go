// internal/render/evidence_test.go

package render

import (
	"strings"
	"testing"

	"github.com/papa0four/orkowatch/internal/security/finding"
)

// An evidence entry occupies one line whatever it holds. A saved report is a
// file, so its fact names are as untrusted as the subjects and values a host
// supplies, and none of the three may carry a control character to the
// terminal.
func TestEvidenceTextEscapesEveryPart(t *testing.T) {
	plain := finding.Evidence{Kind: finding.KindFile, Subject: `C:\Users\a b`, Facts: []finding.Fact{
		{Name: finding.FactMode, Value: "-rw-r--r--"},
	}}
	if got, want := EvidenceText(plain), `- C:\Users\a b  mode=-rw-r--r--`; got != want {
		t.Errorf("printable text: %q, want %q", got, want)
	}

	const escape = "\x1b[2J"
	for part, entry := range map[string]finding.Evidence{
		"subject": {Subject: "a" + escape},
		"name":    {Subject: "a", Facts: []finding.Fact{{Name: finding.FactName("mode" + escape), Value: "x"}}},
		"value":   {Subject: "a", Facts: []finding.Fact{{Name: finding.FactMode, Value: "x\n" + escape}}},
	} {
		got := EvidenceText(entry)
		if strings.ContainsAny(got, "\x1b\n") {
			t.Errorf("a control character in the %s reached the line: %q", part, got)
		}
	}
}

// internal/security/audit/view_test.go

package audit

import (
	"encoding/json"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// A report states what the audit found. It has no key saying whether CVE
// data was asked for, since nothing asks.
func TestViewCarriesNoEnrichmentKey(t *testing.T) {
	view := (&Result{}).View("")

	asJSON, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	asYAML, err := yaml.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	for format, data := range map[string][]byte{"json": asJSON, "yaml": asYAML} {
		if strings.Contains(string(data), "enrich") {
			t.Errorf("%s names enrichment:\n%s", format, data)
		}
	}
}

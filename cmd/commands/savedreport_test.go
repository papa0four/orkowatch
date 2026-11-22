// cmd/commands/savedreport_test.go

package cmd

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/papa0four/orkowatch/cmd/commands/delivery"
)

// A report saved while the audit still wrote enrichment_requested opens to
// the same findings as one written without it: a key no longer in the
// projection is passed over, not refused.
func TestSavedReportWithEnrichmentKeyOpens(t *testing.T) {
	view := hostScoredAudit()
	older := map[delivery.Format]func([]byte) []byte{
		delivery.FormatJSON: func(data []byte) []byte {
			return bytes.Replace(data, []byte("{"), []byte(`{"enrichment_requested": false,`), 1)
		},
		delivery.FormatYAML: func(data []byte) []byte {
			return append([]byte("enrichment_requested: false\n"), data...)
		},
	}

	for format, withKey := range older {
		data, err := delivery.Encode(view, format)
		if err != nil {
			t.Fatal(err)
		}
		current, err := decodeReport("saved."+format.Extension(), format, delivery.FormatText, data)
		if err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		saved, err := decodeReport("older."+format.Extension(), format, delivery.FormatText, withKey(data))
		if err != nil {
			t.Fatalf("%s with the key: %v", format, err)
		}
		if !reflect.DeepEqual(saved.Items, current.Items) {
			t.Errorf("%s: the findings differ with the key present\n got  %+v\n want %+v", format, saved.Items, current.Items)
		}
	}
}

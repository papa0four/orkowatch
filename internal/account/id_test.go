// internal/account/id_test.go

package account

import "testing"

// An identifier is unsigned and 32 bits wide; anything else is a malformed
// record, and an identifier is written back as it was read.
func TestParseID(t *testing.T) {
	for field, want := range map[string]bool{
		"0":          true,
		"1000":       true,
		"4294967295": true,
		"4294967296": false,
		"-1":         false,
		"":           false,
		"10a":        false,
		" 10":        false,
	} {
		id, ok := ParseID(field)
		if ok != want {
			t.Errorf("ParseID(%q) reports %v, want %v", field, ok, want)
		}
		if ok && FormatID(id) != field {
			t.Errorf("FormatID(ParseID(%q)) = %q", field, FormatID(id))
		}
	}
}

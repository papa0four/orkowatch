// internal/render/confirm_test.go

package render

import (
	"strings"
	"testing"
)

// Only y or yes, in any case and with space around it, is yes; the question
// is written with [y/N] after it.
func TestConfirm(t *testing.T) {
	for answer, want := range map[string]bool{
		"y\n":     true,
		"YES\n":   true,
		"  yes  ": true,
		"n\n":     false,
		"\n":      false,
		"":        false,
		"yep\n":   false,
	} {
		var out strings.Builder
		got, err := Confirm(strings.NewReader(answer), &out, "Remove it?")
		if err != nil || got != want {
			t.Errorf("answer %q gave %v, %v, want %v", answer, got, err, want)
		}
		if out.String() != "Remove it? [y/N] " {
			t.Errorf("asked %q", out.String())
		}
	}
}

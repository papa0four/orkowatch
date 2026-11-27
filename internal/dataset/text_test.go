// internal/dataset/text_test.go

package dataset

import (
	"strings"
	"testing"
)

// Text kept from a source is refused when it is empty, longer than MaxText,
// or holds a character a terminal would act on, and is kept otherwise.
func TestCheckText(t *testing.T) {
	if err := CheckText("a name", "curl"); err != nil {
		t.Errorf("a plain name was refused: %v", err)
	}
	if err := CheckText("a name", strings.Repeat("a", MaxText)); err != nil {
		t.Errorf("a name of the most a text may hold was refused: %v", err)
	}
	for value, want := range map[string]string{
		"":                             "a name is empty",
		strings.Repeat("a", MaxText+1): "a name is longer than 1024 bytes",
		"cu\x1b[2Jrl":                  "a name holds a control character",
		"line\nbreak":                  "a name holds a control character",
	} {
		if err := CheckText("a name", value); err == nil || err.Error() != want {
			t.Errorf("%q gave %v, want %q", value, err, want)
		}
	}
}

// Text a refusal quotes from a source is shown with each control character
// as a question mark and cut at MaxText, so a refusal cannot act on the
// terminal that shows it or run on without end.
func TestPrintable(t *testing.T) {
	if got := Printable("cu\x1b[2Jrl\n"); got != "cu?[2Jrl?" {
		t.Errorf("control characters shown as %q", got)
	}
	if got := Printable(strings.Repeat("a", MaxText+5)); got != strings.Repeat("a", MaxText)+"..." {
		t.Errorf("a long text shown as %d bytes", len(got))
	}
	if got := Printable("curl"); got != "curl" {
		t.Errorf("plain text shown as %q", got)
	}
}

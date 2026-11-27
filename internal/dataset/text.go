// internal/dataset/text.go

package dataset

import (
	"fmt"
	"strings"
	"unicode"
)

// MaxText bounds a string a dataset keeps from its source: an identifier, a
// package name, a version, a score, or an address.
const MaxText = 1 << 10

// CheckText refuses text kept from a source that is empty, too long, or holds
// a character a terminal would act on, naming it as what. Every dataset that
// keeps its source's text judges it by CheckText, as it judges CVEs by
// ValidCVE, so the same text is kept or refused alike whatever its source.
func CheckText(what, value string) error {
	switch {
	case value == "":
		return fmt.Errorf("%s is empty", what)
	case len(value) > MaxText:
		return fmt.Errorf("%s is longer than %d bytes", what, MaxText)
	case strings.IndexFunc(value, unicode.IsControl) >= 0:
		return fmt.Errorf("%s holds a control character", what)
	}
	return nil
}

// Printable is text a refusal quotes from a source, each control character
// shown as a question mark and the text cut at MaxText, so a refusal of
// untrusted data cannot act on the terminal that shows it.
func Printable(text string) string {
	text = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '?'
		}
		return r
	}, text)
	if len(text) > MaxText {
		text = text[:MaxText] + "..."
	}
	return text
}

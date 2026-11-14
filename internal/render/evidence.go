// internal/render/evidence.go

package render

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/papa0four/orkowatch/internal/security/finding"
)

// HostText returns text read from the host in a form that occupies exactly
// one line of a text report. A file name may hold any byte but NUL and the
// path separator, so one carrying a newline or a terminal escape sequence
// would otherwise forge report lines or rewrite the operator's screen. Text
// made only of printable characters is returned unchanged, backslashes and
// all, so a Windows path reads as it is written; anything else comes back as
// a quoted Go string literal, whose quotes mark it as escaped. Text that
// already opens with a quote is quoted too, so it cannot pass for the escaped
// form of something else. Structured encoders escape for themselves, so this
// is the text renderer's concern alone.
func HostText(text string) string {
	plain := utf8.ValidString(text) &&
		!strings.HasPrefix(text, `"`) &&
		!strings.ContainsFunc(text, func(r rune) bool { return !strconv.IsPrint(r) })
	if plain {
		return text
	}
	return strconv.Quote(text)
}

// EvidenceLine writes one evidence entry as its subject followed by its
// facts in recorded order, prefixed by indent. Subject and values come from
// the host and pass through HostText.
func EvidenceLine(w io.Writer, indent string, evidence finding.Evidence) error {
	var line strings.Builder
	line.WriteString(indent)
	line.WriteString("- ")
	line.WriteString(HostText(evidence.Subject))
	for _, fact := range evidence.Facts {
		line.WriteString("  ")
		line.WriteString(fact.Name)
		line.WriteString("=")
		line.WriteString(HostText(fact.Value))
	}
	_, err := fmt.Fprintln(w, line.String())
	return err
}

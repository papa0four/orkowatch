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

// EvidenceLine writes one evidence entry as EvidenceText renders it,
// prefixed by indent.
func EvidenceLine(w io.Writer, indent string, evidence finding.Evidence) error {
	_, err := fmt.Fprintln(w, indent+EvidenceText(evidence))
	return err
}

// EvidenceText renders one evidence entry as its subject followed by its
// facts in recorded order. Subject and values come from the host, and a fact
// name comes from a file when a saved report is shown, so all three pass
// through HostText. The text report and the results browser both render
// evidence through it, so the two show an entry alike.
func EvidenceText(evidence finding.Evidence) string {
	var line strings.Builder
	line.WriteString("- ")
	line.WriteString(HostText(evidence.Subject))
	for _, fact := range evidence.Facts {
		line.WriteString("  ")
		line.WriteString(HostText(string(fact.Name)))
		line.WriteString("=")
		line.WriteString(HostText(fact.Value))
	}
	return line.String()
}

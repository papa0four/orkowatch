// internal/render/finding.go

package render

import (
	"fmt"
	"io"

	"github.com/papa0four/orkowatch/internal/security/finding"
)

// FindingLine writes a single finding as symbol, fixed-width severity
// label, and title, prefixed by indent. Severity symbol and label come
// from finding.SeverityFormat so every command renders findings identically.
func FindingLine(w io.Writer, indent, severity, title string) error {
	symbol, label := finding.SeverityFormat(severity)
	_, err := fmt.Fprintf(w, "%s%s %s  %s\n", indent, symbol, label, title)
	return err
}

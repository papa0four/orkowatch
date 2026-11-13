// internal/render/summary.go

package render

import (
	"fmt"
	"io"
	"strings"
)

// SuppressionNotice writes the min-severity suppression disclosure, or
// nothing when no findings were suppressed.
func SuppressionNotice(w io.Writer, suppressed, total int, minSeverity string) error {
	if suppressed <= 0 {
		return nil
	}
	_, err := fmt.Fprintf(w, "%d of %d findings suppressed by --min-severity %s. "+
		"Rerun with a lower threshold or without --min-severity to see all findings.\n\n",
		suppressed, total, strings.ToUpper(minSeverity))
	return err
}

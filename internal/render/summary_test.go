// internal/render/summary_test.go

package render

import (
	"strings"
	"testing"
)

// The notice counts the findings so the noun agrees with one, and says
// nothing when none was suppressed.
func TestSuppressionNotice(t *testing.T) {
	for total, want := range map[int]string{1: "1 of 1 finding suppressed by --min-severity HIGH.", 3: "1 of 3 findings suppressed by --min-severity HIGH."} {
		var out strings.Builder
		if err := SuppressionNotice(&out, 1, total, "high"); err != nil || !strings.HasPrefix(out.String(), want) {
			t.Errorf("total %d: %q, %v; want it to begin %q", total, out.String(), err, want)
		}
	}
	var out strings.Builder
	if err := SuppressionNotice(&out, 0, 3, "high"); err != nil || out.Len() != 0 {
		t.Errorf("nothing suppressed: %q, %v", out.String(), err)
	}
}

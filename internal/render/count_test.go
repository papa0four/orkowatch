// internal/render/count_test.go

package render

import "testing"

// One takes the singular, and every other number the plural, zero included.
func TestCount(t *testing.T) {
	for n, want := range map[int]string{0: "0 datasets", 1: "1 dataset", 2: "2 datasets", 12: "12 datasets"} {
		if got := Count(n, "dataset", "datasets"); got != want {
			t.Errorf("Count(%d) = %q, want %q", n, got, want)
		}
	}
}

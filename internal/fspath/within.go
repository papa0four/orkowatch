// internal/fspath/within.go

package fspath

import (
	"path/filepath"
	"strings"
)

// Within reports whether target lies at or beneath base, comparing on path
// boundaries so a sibling is not mistaken for a child. On Windows the
// comparison ignores case, as the filesystem does.
func Within(target, base string) bool {
	target, base = fold(target), fold(base)
	if target == base {
		return true
	}
	rel, err := filepath.Rel(base, target)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

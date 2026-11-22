// internal/fspath/within_test.go

package fspath

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A path is within itself and within any directory above it, and a sibling
// whose name begins with the base's is not.
func TestWithin(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "var", "lib")
	cases := map[string]struct {
		target string
		want   bool
	}{
		"the base itself":            {base, true},
		"a child":                    {filepath.Join(base, "owatch"), true},
		"a grandchild":               {filepath.Join(base, "owatch", "kev.json"), true},
		"a sibling sharing a prefix": {base + "rary", false},
		"the parent":                 {filepath.Dir(base), false},
		"an unrelated path":          {filepath.Join(root, "etc"), false},
		"a child named with dots":    {filepath.Join(base, "..data"), true},
	}
	for name, c := range cases {
		if got := Within(c.target, base); got != c.want {
			t.Errorf("%s: Within(%q, %q) = %v, want %v", name, c.target, base, got, c.want)
		}
	}
}

// Case separates names on Unix and does not on Windows.
func TestWithinCase(t *testing.T) {
	base := filepath.Join(t.TempDir(), "Data")
	target := filepath.Join(strings.ToUpper(base), "file")
	if got, want := Within(target, base), runtime.GOOS == "windows"; got != want {
		t.Errorf("Within(%q, %q) = %v, want %v", target, base, got, want)
	}
}

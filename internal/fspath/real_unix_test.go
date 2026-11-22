//go:build linux || darwin || freebsd || openbsd || netbsd

// internal/fspath/real_unix_test.go

package fspath

import (
	"os"
	"path/filepath"
	"testing"
)

// A link to a directory, and a path through one, resolve to where they lead.
func TestRealFollowsLinks(t *testing.T) {
	root, err := Real(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target", "inner")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(filepath.Join(root, "target"), link); err != nil {
		t.Fatal(err)
	}

	for path, want := range map[string]string{
		link:                         filepath.Join(root, "target"),
		filepath.Join(link, "inner"): target,
	} {
		if got, err := Real(path); err != nil || got != want {
			t.Errorf("Real(%q) = %q, %v, want %q", path, got, err, want)
		}
	}
}

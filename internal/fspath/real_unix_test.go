//go:build linux || darwin || freebsd || openbsd || netbsd

// internal/fspath/real_unix_test.go

package fspath

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// A directory the process may not search is reported with that reason, and
// the error reads as the system states it.
func TestRealKeepsTheReason(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root may search any directory")
	}
	closed := filepath.Join(t.TempDir(), "closed")
	if err := os.MkdirAll(filepath.Join(closed, "inner"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(closed, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(closed, 0o700); err != nil {
			t.Errorf("the test directory could not be reopened for removal: %v", err)
		}
	})

	inner := filepath.Join(closed, "inner")
	_, err := Real(inner)
	if !errors.Is(err, ErrMissing) || !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("an unsearchable directory gave %v, want ErrMissing carrying a refused permission", err)
	}
	_, want := filepath.EvalSymlinks(inner)
	if err.Error() != want.Error() {
		t.Errorf("the error reads %q, want the system's %q", err, want)
	}
}

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

//go:build linux || darwin || freebsd || openbsd || netbsd

// internal/fspath/create_unix_test.go

package fspath

import (
	"os"
	"path/filepath"
	"testing"
)

// The file is created with the mode asked for.
func TestCreateNewMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "new")
	f, err := CreateNew(path, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("the mode of the file is %o, want 600", got)
	}
}

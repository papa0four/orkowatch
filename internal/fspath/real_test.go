// internal/fspath/real_test.go

package fspath

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// The real path of a directory names that directory, and a directory that
// does not exist is reported as missing.
func TestReal(t *testing.T) {
	dir := t.TempDir()
	real, err := Real(dir)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.Stat(real)
	if err != nil {
		t.Fatalf("the real path %q cannot be read: %v", real, err)
	}
	if !os.SameFile(want, got) {
		t.Errorf("Real(%q) = %q, which is another directory", dir, real)
	}

	_, err = Real(filepath.Join(dir, "absent", "below"))
	if !errors.Is(err, ErrMissing) {
		t.Errorf("a missing directory gave %v, want ErrMissing", err)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a missing directory gave %v, which does not carry the system's reason", err)
	}
}

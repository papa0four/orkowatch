// internal/fspath/create_test.go

package fspath

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// A file is created where nothing is and holds what is written to it. Where a
// file already is, nothing is created and the file is left as it was.
func TestCreateNew(t *testing.T) {
	path := filepath.Join(t.TempDir(), "new")
	f, err := CreateNew(path, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := CreateNew(path, 0o600); !errors.Is(err, fs.ErrExist) {
		t.Errorf("creating over a file gave %v, want fs.ErrExist", err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "first" {
		t.Errorf("the file holds %q, %v, want it untouched", got, err)
	}
}

// A link planted where the file is to be made is refused, and what it points
// to is not created.
func TestCreateNewRefusesALink(t *testing.T) {
	dir := t.TempDir()
	elsewhere := filepath.Join(dir, "elsewhere")
	planted := filepath.Join(dir, "planted")
	if err := os.Symlink(elsewhere, planted); err != nil {
		t.Skipf("this account cannot make a link: %v", err)
	}

	if _, err := CreateNew(planted, 0o600); !errors.Is(err, fs.ErrExist) {
		t.Errorf("creating over a link gave %v, want fs.ErrExist", err)
	}
	if _, err := os.Lstat(elsewhere); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the target of the link was created: %v", err)
	}
}

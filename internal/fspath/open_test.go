// internal/fspath/open_test.go

package fspath

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// A regular file is opened and read. A directory, a link to a regular file
// and a link to nothing are each refused as not regular, and a path with
// nothing at it is reported as missing.
func TestOpenRegular(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("held"), 0o600); err != nil {
		t.Fatal(err)
	}

	f, err := OpenRegular(file)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(f)
	if cerr := f.Close(); err != nil || cerr != nil || string(got) != "held" {
		t.Fatalf("the file read as %q, %v, %v", got, err, cerr)
	}

	if _, err := OpenRegular(dir); !errors.Is(err, ErrNotRegular) {
		t.Errorf("a directory gave %v, want ErrNotRegular", err)
	}
	if _, err := OpenRegular(filepath.Join(dir, "absent")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a missing file gave %v, want fs.ErrNotExist", err)
	}

	link := filepath.Join(dir, "link")
	if err := os.Symlink(file, link); err != nil {
		t.Skipf("this account cannot make a link: %v", err)
	}
	dangling := filepath.Join(dir, "dangling")
	if err := os.Symlink(filepath.Join(dir, "absent"), dangling); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{link, dangling} {
		if _, err := OpenRegular(path); !errors.Is(err, ErrNotRegular) {
			t.Errorf("the link %s gave %v, want ErrNotRegular", filepath.Base(path), err)
		}
	}
}

// internal/report/write_test.go

package report

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A report is never written over what is already there: the write is refused
// and the file is left as it was.
func TestWriteRefusesExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, []byte("kept"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := Write(path, []byte("{}"), Options{AllowElevatedWrite: true})
	if !errors.Is(err, fs.ErrExist) || !strings.HasPrefix(err.Error(), "create destination: ") {
		t.Errorf("writing over a file gave %v, want a refused creation", err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "kept" {
		t.Errorf("the file holds %q, %v, want it untouched", got, err)
	}
}

// A report whose directory does not exist is refused as that, naming the
// directory asked for, and nothing is created.
func TestWriteRefusesMissingDirectory(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "absent")
	err := Write(filepath.Join(parent, "report.json"), []byte("{}"), Options{})
	if !errors.Is(err, ErrParentMissing) || !strings.Contains(err.Error(), parent) {
		t.Errorf("a missing directory gave %v, want ErrParentMissing naming %s", err, parent)
	}
	if _, statErr := os.Stat(parent); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("the directory was created: %v", statErr)
	}
}

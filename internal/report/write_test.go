// internal/report/write_test.go

package report

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

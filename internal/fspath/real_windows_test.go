//go:build windows

// internal/fspath/real_windows_test.go

package fspath

import (
	"errors"
	"strings"
	"testing"
)

// A path in extended-length or device form is refused before it is opened,
// and a path with a trailing dot or in another case resolves to the directory
// Windows records.
func TestRealOnWindows(t *testing.T) {
	dir, err := Real(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{`\\?\` + dir, `\\.\` + dir} {
		if _, err := Real(path); !errors.Is(err, ErrDevicePath) {
			t.Errorf("Real(%q) gave %v, want ErrDevicePath", path, err)
		}
	}
	for _, path := range []string{dir + ".", strings.ToUpper(dir), strings.ToLower(dir)} {
		if got, err := Real(path); err != nil || got != dir {
			t.Errorf("Real(%q) = %q, %v, want %q", path, got, err, dir)
		}
	}
}

//go:build windows

// internal/dataset/store/protect_windows_test.go

package store

import (
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// A directory of the protected store is made with a list of its own that
// nothing above it adds to, now or when inheritance is applied again: the
// list is marked protected and holds the two entries stated, for the system
// and the administrators.
func TestMakeProtectedStatesItsOwnList(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "owatch")
	if err := makeProtected(dir); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := sd.Control()
	if err != nil {
		t.Fatal(err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Error("the list is not protected from what the directory above passes down")
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("the list could not be read: %v", err)
	}
	if dacl.AceCount != 2 {
		t.Errorf("the list holds %d entries, want the system's and the administrators'", dacl.AceCount)
	}
	if err := makeProtected(dir); err == nil {
		t.Error("a directory that exists was made again")
	}
}

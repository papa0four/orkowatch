//go:build windows

// internal/dataset/store/adopt_windows_test.go

package store

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/papa0four/orkowatch/internal/elevation"
	"github.com/papa0four/orkowatch/internal/winfolder"
)

// With the host's own operator, a file owned by the account running the
// process is opened, and one given to the administrators is refused as
// another's. Giving a file away takes an elevated process; where the test is
// not one, that part is skipped and says so.
func TestOpenOwnedByTheOperatorOnThisHost(t *testing.T) {
	const administratorsSID = "S-1-5-32-544"
	operator, ok := elevation.InvokingOperator()
	if !ok {
		t.Fatal("no operator")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	icacls, err := winfolder.System.Path("icacls.exe")
	if err != nil {
		t.Fatal(err)
	}
	setOwner := func(path, sid string) ([]byte, error) {
		return exec.Command(icacls, path, "/setowner", "*"+sid).CombinedOutput()
	}

	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := setOwner(path, user.User.Sid.String()); err != nil {
		t.Fatalf("icacls: %v: %s", err, out)
	}
	f, err := openOwned(path, operator)
	if err != nil {
		t.Fatalf("a file of the operator's own: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	if out, err := setOwner(path, administratorsSID); err != nil {
		t.Skipf("the file could not be given to the administrators, which takes an elevated process: %v: %s", err, out)
	}
	if _, err := openOwned(path, operator); !errors.Is(err, errNotOwned) {
		t.Errorf("a file of the administrators' gave %v, want it refused as not the operator's", err)
	}
}

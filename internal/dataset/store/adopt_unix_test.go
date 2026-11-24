//go:build linux || darwin || freebsd || openbsd || netbsd

// internal/dataset/store/adopt_unix_test.go

package store

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"testing"

	"github.com/papa0four/orkowatch/internal/account"
	"github.com/papa0four/orkowatch/internal/elevation"
)

// With the host's own operator, a file the operator's account made is opened
// and the system's account file, which is root's, is refused as another's. As
// root every file made is root's, so the second part is skipped there.
func TestOpenOwnedByTheOperatorOnThisHost(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SUDO_USER", me.Username)
	operator, ok := elevation.InvokingOperator()
	if !ok {
		t.Fatal("no operator")
	}

	mine := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(mine, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := openOwned(mine, operator)
	if err != nil {
		t.Fatalf("a file of the operator's own: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	if os.Getuid() == 0 {
		t.Skip("as root the system's account file is the operator's own")
	}
	if _, err := openOwned(account.PasswdFile, operator); !errors.Is(err, errNotOwned) {
		t.Errorf("root's %s gave %v, want it refused as not the operator's", account.PasswdFile, err)
	}
}

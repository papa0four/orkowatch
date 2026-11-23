//go:build linux || darwin || freebsd || openbsd || netbsd

// internal/dataset/store/root_test.go

package store

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/papa0four/orkowatch/internal/account"
)

// The store is under the home the account database records, wherever HOME
// points.
func TestAccountRootIgnoresHome(t *testing.T) {
	uid, ok := account.ParseID(strconv.Itoa(os.Getuid()))
	if !ok {
		t.Fatal("the process has no user identifier")
	}
	a, err := account.ByID(context.Background(), uid)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_DATA_HOME", t.TempDir())

	root, err := accountRoot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(root, a.Home+string(filepath.Separator)) {
		t.Errorf("the store %s is not under the recorded home %s", root, a.Home)
	}
}

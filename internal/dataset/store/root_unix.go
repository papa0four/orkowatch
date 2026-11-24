//go:build linux || darwin || freebsd || openbsd || netbsd

// internal/dataset/store/root_unix.go

package store

import (
	"context"
	"os"
	"path/filepath"
	"strconv"

	"github.com/papa0four/orkowatch/internal/account"
)

// accountRoot is the store of the account running the process, at
// underHome in the home the system records for the account. No environment
// variable is read, since a run started with another environment would then
// use another store.
func accountRoot(ctx context.Context) (string, error) {
	uid, ok := account.ParseID(strconv.Itoa(os.Getuid()))
	if !ok {
		return "", account.ErrNotFound
	}
	a, err := account.ByID(ctx, uid)
	if err != nil {
		return "", err
	}
	return RootOf(a.Home), nil
}

// RootOf is the store of the account whose home is home, as the system
// records it for the account.
func RootOf(home string) string {
	return filepath.Join(append([]string{home}, underHome...)...)
}

//go:build windows

// internal/dataset/store/root_windows.go

package store

import (
	"context"
	"path/filepath"

	"github.com/papa0four/orkowatch/internal/winfolder"
)

// accountRoot is the store of the account running the process: in the local
// application data folder of the profile Windows records for the account.
// LOCALAPPDATA is not read, since a run started with another environment
// would then use another store.
func accountRoot(context.Context) (string, error) {
	profile, err := winfolder.Profile()
	if err != nil {
		return "", err
	}
	return filepath.Join(profile, "AppData", "Local", "owatch", "datasets"), nil
}

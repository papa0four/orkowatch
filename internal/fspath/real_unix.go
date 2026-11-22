//go:build linux || darwin || freebsd || openbsd || netbsd

// internal/fspath/real_unix.go

package fspath

import (
	"fmt"
	"path/filepath"
)

// Real returns dir with every link in its path resolved, so a rule about
// where a directory is judges where it leads.
func Real(dir string) (string, error) {
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrMissing, dir)
	}
	return real, nil
}

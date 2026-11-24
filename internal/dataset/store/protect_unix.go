//go:build linux || darwin || freebsd || openbsd || netbsd

// internal/dataset/store/protect_unix.go

package store

import "os"

// makeProtected makes dir for its owner alone. An elevated process is root,
// so the directory is root's.
func makeProtected(dir string) error {
	return os.Mkdir(dir, dirMode)
}

// beginProtected does nothing: what root creates is root's.
func beginProtected() (func() error, error) {
	return func() error { return nil }, nil
}

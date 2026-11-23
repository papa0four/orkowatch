//go:build linux || darwin || freebsd || openbsd || netbsd

// internal/fspath/create_unix.go

package fspath

import "os"

// CreateNew creates path with mode and opens it for writing, and fails with
// fs.ErrExist when anything is already there. A link counts as something
// there, so one planted to redirect the write is refused, where an open that
// tolerated an existing entry would follow it or truncate its target.
func CreateNew(path string, mode os.FileMode) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode) // #nosec G304 -- the caller's path, created only where nothing is
}

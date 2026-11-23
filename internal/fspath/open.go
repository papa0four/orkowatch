// internal/fspath/open.go

package fspath

import (
	"errors"
	"io/fs"
	"os"
)

// ErrNotRegular means the path names something other than a regular file: a
// link, a directory, a FIFO or a device.
var ErrNotRegular = errors.New("not a regular file")

// refused states that path is not a regular file.
func refused(path string) error {
	return &fs.PathError{Op: "open", Path: path, Err: ErrNotRegular}
}

// classify turns the failure to open path into ErrNotRegular when what is
// there is not a regular file, since the system reports a refused link or
// directory in words that differ by platform. It decides only how the failure
// reads; the open has already refused.
func classify(path string, err error) error {
	if info, lerr := os.Lstat(path); lerr == nil && !info.Mode().IsRegular() {
		return refused(path)
	}
	return err
}

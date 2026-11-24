//go:build linux || darwin || freebsd || openbsd || netbsd

// internal/fspath/open_unix.go

package fspath

import (
	"errors"
	"os"
	"syscall"
)

// OpenRegular opens path for reading when it is a regular file, and fails
// with ErrNotRegular when it is anything else. A link is not followed, so a
// file a reader trusts cannot be swapped for a pointer to another, and the
// open does not wait on a FIFO. What was opened is what is judged: the type
// is read from the open file, not from the path a second time.
func OpenRegular(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) // #nosec G304 -- the caller's path, opened without following a link and judged below
	if err != nil {
		return nil, classify(path, err)
	}
	info, err := f.Stat()
	if err == nil && info.Mode().IsRegular() {
		return f, nil
	}
	if err == nil {
		err = refused(path)
	}
	return nil, errors.Join(err, f.Close())
}

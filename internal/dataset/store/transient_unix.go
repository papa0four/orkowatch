//go:build linux || darwin || freebsd || openbsd || netbsd

// internal/dataset/store/transient_unix.go

package store

import (
	"errors"
	"syscall"
)

// transient reports whether err is a failure that passes: an interrupted
// call, a resource busy for the moment, or a file in use. A refused
// permission, a full disk, or a missing file is not, and trying again would
// only fail again.
func transient(err error) bool {
	return errors.Is(err, syscall.EINTR) || errors.Is(err, syscall.EAGAIN) ||
		errors.Is(err, syscall.EBUSY) || errors.Is(err, syscall.ETXTBSY)
}

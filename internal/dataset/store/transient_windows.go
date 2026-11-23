//go:build windows

// internal/dataset/store/transient_windows.go

package store

import (
	"errors"

	"golang.org/x/sys/windows"
)

// transient reports whether err is a failure that passes: a file another
// process holds open or has locked, as a virus scanner does while it reads a
// new file. A refused permission, a full disk, or a missing file is not, and
// trying again would only fail again.
func transient(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_LOCK_VIOLATION)
}

//go:build linux || darwin || freebsd || openbsd || netbsd

// internal/dataset/store/lock_unix.go

package store

import (
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// lockFileMode keeps the lock file to the account the store belongs to.
const lockFileMode os.FileMode = 0o600

// openLockFile opens the lock file, creating it if it is not there, and does
// not follow a link in its place.
func openLockFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, lockFileMode) // #nosec G304 -- the store's own lock file, opened without following a link
}

// tryLock takes an exclusive flock on f, reporting false when another
// process holds one.
func tryLock(f *os.File) (bool, error) {
	err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) // #nosec G115 -- a file descriptor fits an int
	if errors.Is(err, unix.EWOULDBLOCK) {
		return false, nil
	}
	return err == nil, err
}

// unlock releases the flock on f.
func unlock(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_UN) // #nosec G115 -- a file descriptor fits an int
}

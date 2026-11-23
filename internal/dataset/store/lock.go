// internal/dataset/store/lock.go

package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	// lockName is the file in the store that a process changing the store
	// holds a lock on. Its name cannot name a dataset.
	lockName = ".lock"

	// lockPoll is how often a waiting process tries the lock again.
	lockPoll = 100 * time.Millisecond

	// dirMode keeps the store and its datasets to the account they belong
	// to.
	dirMode os.FileMode = 0o700
)

// ErrBusy means another process is changing the store.
var ErrBusy = errors.New("another owatch data command is changing the dataset store")

// lock takes the store's lock, creating the store when it does not exist, and
// returns the function that releases it. The lock is one the system holds for
// the process and releases when the process ends, however it ends, so a
// process that is killed leaves nothing to clear by hand. Another process
// holding it is waited for until wait has passed, and then ErrBusy is
// returned.
func (s Store) lock(ctx context.Context, wait time.Duration) (func() error, error) {
	if err := os.MkdirAll(s.root, dirMode); err != nil {
		return nil, fmt.Errorf("create the dataset store: %w", err)
	}
	f, err := openLockFile(filepath.Join(s.root, lockName))
	if err != nil {
		return nil, fmt.Errorf("open the store's lock: %w", err)
	}

	deadline := time.Now().Add(wait)
	for {
		held, err := tryLock(f)
		switch {
		case err != nil:
			return nil, errors.Join(fmt.Errorf("lock the dataset store: %w", err), f.Close())
		case held:
			return func() error { return errors.Join(unlock(f), f.Close()) }, nil
		case !time.Now().Before(deadline):
			return nil, errors.Join(ErrBusy, f.Close())
		}
		select {
		case <-ctx.Done():
			return nil, errors.Join(ctx.Err(), f.Close())
		case <-time.After(lockPoll):
		}
	}
}

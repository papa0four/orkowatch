// internal/dataset/store/remove.go

package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
)

// ErrNotHeld means the store holds no dataset of the name given.
var ErrNotHeld = errors.New("the dataset store holds no dataset of that name")

// Remove deletes the dataset named id from the store, with the record of any
// failed import of it, and nothing else. It is the only way a dataset leaves
// the store: nothing is removed for being old, for no longer applying to the
// host, or for being unknown to this version, since a host without a network
// cannot fetch it again. id may be any name status lists, an unknown one
// included, but not a path or a name beginning with a dot.
func (s Store) Remove(ctx context.Context, id string) (err error) {
	if id == "" || strings.HasPrefix(id, ".") || strings.ContainsAny(id, `/\`) {
		return fmt.Errorf("%w: %q", ErrNotHeld, id)
	}
	if held, err := s.held(id); err != nil || !held {
		return errors.Join(fmt.Errorf("%w: %q", ErrNotHeld, id), err)
	}

	release, err := s.lock(ctx, lockWait)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, release()) }()

	held, err := s.held(id)
	if err != nil {
		return err
	}
	if !held {
		return fmt.Errorf("%w: %q", ErrNotHeld, id)
	}
	return os.RemoveAll(s.dir(id))
}

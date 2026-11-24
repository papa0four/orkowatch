// internal/dataset/store/protected.go

package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/papa0four/orkowatch/internal/elevation"
)

const (
	// appDir is the directory owatch makes for itself in the system's data
	// directory, and datasetsDir the protected store in it.
	appDir      = "owatch"
	datasetsDir = "datasets"
)

// ErrOpen means a directory of the protected store can be changed by someone
// who is not an administrator, so an elevated run does not use the store. The
// error that carries it names the directory and what opens it.
var ErrOpen = errors.New("the protected dataset store is open to an account that is not an administrator")

// protection is what makes a store one only administrators may change: what
// is done before the store is changed and undone after, how a directory of it
// is made, and the rule its directories are judged by. A test gives its own,
// since the host's needs an elevated process.
type protection struct {
	begin func() (end func() error, err error)
	make  func(dir string) error
	judge func(dir string) (reason string, err error)
}

// protectedStore is the store an elevated process uses, in the system's
// directory for an application's data.
func protectedStore() (Store, error) {
	base, err := systemData()
	if err != nil {
		return Store{}, err
	}
	return Store{
		root:    filepath.Join(base, appDir, datasetsDir),
		protect: &protection{begin: beginProtected, make: makeProtected, judge: elevation.OpenBeyondAdmins},
	}, nil
}

// own lists the directories owatch makes for a protected store, outermost
// first: its own in the system's data directory, and the store in that.
func (s Store) own() []string {
	return []string{filepath.Dir(s.root), s.root}
}

// ensure makes the store's directory when it does not exist. A protected
// store's directories are each made protected, and then judged, so one that
// was already there and is open to others is refused and not written into;
// the refusal is returned as judged gives it, since nothing was being made.
func (s Store) ensure() error {
	if s.protect == nil {
		if err := os.MkdirAll(s.root, dirMode); err != nil {
			return fmt.Errorf("create the dataset store: %w", err)
		}
		return nil
	}
	for _, dir := range s.own() {
		_, err := os.Lstat(dir)
		if errors.Is(err, os.ErrNotExist) {
			err = s.protect.make(dir)
		}
		if err != nil {
			return fmt.Errorf("create the dataset store: %w", err)
		}
	}
	return s.judged()
}

// judged refuses a protected store when one of its directories, or of more,
// can be changed by anyone but the system and its administrators. It is asked
// each time the store is read or changed, since a directory that was sound
// when it was made may not be now. A directory that does not exist yet has
// nothing to trust, and one of a store that is not protected is not judged.
func (s Store) judged(more ...string) error {
	if s.protect == nil {
		return nil
	}
	for _, dir := range append(s.own(), more...) {
		reason, err := s.protect.judge(dir)
		switch {
		case errors.Is(err, os.ErrNotExist):
		case err != nil:
			return fmt.Errorf("judge %s: %w", dir, err)
		case reason != "":
			return fmt.Errorf("%w: %s is %s", ErrOpen, dir, reason)
		}
	}
	return nil
}

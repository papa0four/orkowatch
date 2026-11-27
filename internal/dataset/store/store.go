// internal/dataset/store/store.go

// Package store holds vulnerability datasets on the host: one directory per
// dataset, holding the data and the manifest that describes it. It is the one
// place a dataset is read from, and every read checks the dataset again, since
// a file on disk is untrusted however it got there.
//
// A store lives in the account of the process that uses it, at a fixed path
// under the home the system records for that account. An elevated process
// uses another, the protected store in the system's data directory, which
// only the system and its administrators may change: a store in an ordinary
// account's home is a directory that account can change, and a privileged run
// must not trust it.
package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/elevation"
	"github.com/papa0four/orkowatch/internal/fspath"
)

const (
	// manifestName is the name of a dataset's manifest in its directory.
	manifestName = "manifest.json"

	// dataSuffix ends the name of a dataset's data file, which is the
	// checksum the manifest records, so replacing the manifest is the whole
	// of replacing the data a reader is pointed at.
	dataSuffix = ".data"

	// maxEntries bounds the entries read from the store or from one of its
	// directories, so a directory filled to exhaust a run is refused.
	maxEntries = 256
)

// ErrUnusable means a held dataset failed a check and is not read. The error
// that carries it says why.
var ErrUnusable = errors.New("dataset unusable")

// Store is a directory of datasets. A protected one is made and judged as
// protect says; any other is the account's own, or a directory to carry.
// progress, when it is set, is told what a change of the store does with each
// dataset.
type Store struct {
	root     string
	protect  *protection
	progress Progress
}

// ForProcess returns the store the process uses: the protected store when it
// is elevated, and otherwise the store of the account running it.
func ForProcess(ctx context.Context) (Store, error) {
	if elevation.Elevated() {
		s, err := protectedStore()
		if err != nil {
			return Store{}, fmt.Errorf("locate the protected dataset store: %w", err)
		}
		return s, nil
	}
	root, err := accountRoot(ctx)
	if err != nil {
		return Store{}, fmt.Errorf("locate the dataset store: %w", err)
	}
	return At(root), nil
}

// At returns the store in the directory root, which need not exist yet: a
// directory written in the store's layout to carry to another host is one,
// as is the store ForProcess finds.
func At(root string) Store {
	return Store{root: root}
}

// Root is the store's directory.
func (s Store) Root() string {
	return s.root
}

// dir is the directory of the dataset named id.
func (s Store) dir(id string) string {
	return filepath.Join(s.root, id)
}

// Read gives the data of the dataset d, as held, to consume, for a run that
// uses what the data holds. It reads as every read of the store does, so the
// data is checked as it is given: nothing consume learned may be used unless
// Read returns nil. A dataset the store does not hold is ErrNotHeld, and one
// held that cannot be used is ErrUnusable with the reason.
func (s Store) Read(d dataset.Dataset, now time.Time, consume func(io.Reader) error) (dataset.Manifest, error) {
	if err := s.holds(d); err != nil {
		return dataset.Manifest{}, err
	}
	return s.read(d, now, consume)
}

// Usable reports whether the dataset d can be read at now, as Read would
// judge it before reading its data: ErrNotHeld when the store does not hold
// it, and ErrUnusable with the reason when its directory, its manifest, or
// the size of its data file refuses it. It reads none of the data, so a run
// can learn before it starts what it cannot read without reading anything
// twice; data whose content is damaged is refused only when Read reads it.
func (s Store) Usable(d dataset.Dataset, now time.Time) error {
	if err := s.holds(d); err != nil {
		return err
	}
	m, err := s.manifest(d, now)
	if err != nil {
		return err
	}
	f, err := openData(s.dataPath(d, m), m)
	if err != nil {
		return unusable(err)
	}
	return f.Close()
}

// holds is ErrNotHeld when the store has no directory for d.
func (s Store) holds(d dataset.Dataset) error {
	held, err := s.held(d.ID())
	switch {
	case err != nil:
		return err
	case !held:
		return fmt.Errorf("%w: %q", ErrNotHeld, d.ID())
	}
	return nil
}

// read checks the dataset d held in the store and passes its data to consume.
// The manifest is read and validated first; the data file it names is then
// read through consume and hashed as it is read, and whatever consume does not
// read is read too, so the checksum covers every byte. Nothing consume
// learned may be used unless read returns nil: a file that is truncated, that
// is longer than its manifest says, or whose checksum disagrees is refused
// after consume has seen it.
func (s Store) read(d dataset.Dataset, now time.Time, consume func(io.Reader) error) (dataset.Manifest, error) {
	m, err := s.manifest(d, now)
	if err != nil {
		return dataset.Manifest{}, err
	}
	if err := readData(s.dataPath(d, m), m, consume); err != nil {
		return dataset.Manifest{}, unusable(err)
	}
	return m, nil
}

// manifest is the manifest of the dataset d held in the store, validated for
// d at now. In a protected store the dataset's directory is judged first, with
// the store's own, so nothing is read from a directory someone who is not an
// administrator can change. Whatever refuses it is ErrUnusable.
func (s Store) manifest(d dataset.Dataset, now time.Time) (dataset.Manifest, error) {
	if err := s.judged(s.dir(d.ID())); err != nil {
		return dataset.Manifest{}, unusable(err)
	}
	m, err := readManifest(filepath.Join(s.dir(d.ID()), manifestName))
	if err != nil {
		return dataset.Manifest{}, unusable(err)
	}
	if err := m.Validate(d, now); err != nil {
		return dataset.Manifest{}, unusable(err)
	}
	return m, nil
}

// dataPath is the data file the manifest m of the dataset d names.
func (s Store) dataPath(d dataset.Dataset, m dataset.Manifest) string {
	return filepath.Join(s.dir(d.ID()), m.SHA256+dataSuffix)
}

// readManifest opens and decodes a manifest, refusing anything but a regular
// file.
func readManifest(path string) (m dataset.Manifest, err error) {
	f, err := fspath.OpenRegular(path)
	if err != nil {
		return dataset.Manifest{}, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	return dataset.DecodeManifest(f)
}

// openData opens the data file at path, refusing anything but a regular file
// of the size m records.
func openData(path string, m dataset.Manifest) (*os.File, error) {
	f, err := fspath.OpenRegular(path)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err == nil && info.Size() != m.Size {
		err = fmt.Errorf("the data holds %d bytes where the manifest says %d", info.Size(), m.Size)
	}
	if err != nil {
		return nil, errors.Join(err, f.Close())
	}
	return f, nil
}

// readData reads the data file at path through consume, holding it to the
// size and checksum m records.
func readData(path string, m dataset.Manifest, consume func(io.Reader) error) (err error) {
	f, err := openData(path, m)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, f.Close()) }()

	hash := sha256.New()
	counted := dataset.Limited(io.TeeReader(f, hash), m.Size)
	consumeErr := consume(counted)
	if _, err := io.Copy(io.Discard, counted); err != nil {
		return err
	}
	switch {
	case counted.N() != m.Size:
		return fmt.Errorf("the data held %d bytes when read, where the manifest says %d", counted.N(), m.Size)
	case hex.EncodeToString(hash.Sum(nil)) != m.SHA256:
		return errors.New("the data does not match the checksum in its manifest")
	case consumeErr != nil:
		return consumeErr
	}
	return nil
}

// unusable states err as the reason a dataset is not used.
func unusable(err error) error {
	return fmt.Errorf("%w: %w", ErrUnusable, err)
}

// held reports whether the store has a directory for the dataset named id.
// A missing store holds nothing.
func (s Store) held(id string) (bool, error) {
	info, err := os.Lstat(s.dir(id))
	switch {
	case errors.Is(err, os.ErrNotExist):
		return false, nil
	case err != nil:
		return false, err
	}
	return info.IsDir(), nil
}

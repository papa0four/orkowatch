// internal/dataset/store/adopt.go

package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/fspath"
	"github.com/papa0four/orkowatch/internal/osfingerprint"
)

// Owner answers whether an open file belongs to the account whose datasets
// are adopted. elevation.Operator is one.
type Owner interface {
	Owns(f *os.File) (bool, error)
}

// errNotOwned means a file in the operator's store belongs to another
// account, and is left alone.
var errNotOwned = errors.New("it is not owned by the account the run is elevated for")

// Adopt installs into the store each dataset of known that applies to host
// and that the store in from, an account's own, holds a newer copy of. It is
// how an elevated run comes by what the operator refreshed, and from is a
// directory the operator can change, so nothing in it is trusted: a manifest
// and its data are read only through open files that are regular, not a link
// or a reparse point, and owner's, and within what a manifest and the dataset
// may hold. Nothing else in from is listed or opened. What passes is copied
// into a staging directory of the store and checked there as an import is,
// so nothing is judged in a place the operator can change after the copy.
//
// One outcome is returned for each dataset installed, refused, or failed, in
// name order. A dataset the operator does not hold, or holds no newer than
// the store does, has none and nothing of it is copied.
func (s Store) Adopt(ctx context.Context, from string, owner Owner, known []dataset.Dataset, host *osfingerprint.OSInfo, now time.Time) (outcomes []Outcome, err error) {
	release, err := s.lock(ctx, lockWait)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, release()) }()

	if err := s.clearStaging(); err != nil {
		return nil, err
	}
	staging, err := os.MkdirTemp(s.root, stagingPrefix)
	if err != nil {
		return nil, fmt.Errorf("stage the datasets: %w", err)
	}
	defer func() { err = errors.Join(err, os.RemoveAll(staging)) }()

	for _, d := range known {
		if !d.AppliesTo(host) {
			continue
		}
		if err := s.stageOwned(from, staging, owner, d, now); err != nil {
			outcomes = append(outcomes, Outcome{ID: d.ID(), Result: Refused, Reason: err.Error()})
		}
	}

	entries, err := readDirBounded(staging)
	if err != nil {
		return nil, err
	}
	outcomes = append(outcomes, s.importEntries(ctx, opImport, staging, entries, known, host, now)...)
	slices.SortFunc(outcomes, func(a, b Outcome) int { return strings.Compare(a.ID, b.ID) })
	return outcomes, nil
}

// stageOwned copies the dataset d from the account's store in from into
// staging, when the account holds a copy fetched later than the one held. A
// dataset the account does not hold, or holds no newer, is not an error and
// leaves nothing staged.
func (s Store) stageOwned(from, staging string, owner Owner, d dataset.Dataset, now time.Time) error {
	source := filepath.Join(from, d.ID())
	mf, err := openOwned(filepath.Join(source, manifestName), owner)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	m, err := dataset.DecodeManifest(mf)
	if err = errors.Join(err, mf.Close()); err != nil {
		return err
	}
	// The checksum names the data file, so the manifest is held to its form
	// before any of it becomes part of a path.
	if err := m.Validate(d, now); err != nil {
		return err
	}
	if held, err := readManifest(filepath.Join(s.dir(d.ID()), manifestName)); err == nil && !m.Fetched.After(held.Fetched) {
		return nil
	}

	dir := filepath.Join(staging, d.ID())
	if err := os.Mkdir(dir, dirMode); err != nil {
		return err
	}
	dataName := m.SHA256 + dataSuffix
	in, err := openOwned(filepath.Join(source, dataName), owner)
	if err != nil {
		return errors.Join(err, os.RemoveAll(dir))
	}
	err = writeNew(filepath.Join(dir, dataName), func(out io.Writer) error {
		n, err := io.Copy(out, io.LimitReader(in, m.Size+1))
		if err == nil && n != m.Size {
			err = fmt.Errorf("the data held %d bytes when copied, where its manifest says %d", n, m.Size)
		}
		return err
	})
	if err = errors.Join(err, in.Close()); err != nil {
		return errors.Join(err, os.RemoveAll(dir))
	}

	var manifest bytes.Buffer
	if err := m.Encode(&manifest); err != nil {
		return errors.Join(err, os.RemoveAll(dir))
	}
	if err := writeReplacing(filepath.Join(dir, manifestName), manifest.Bytes()); err != nil {
		return errors.Join(err, os.RemoveAll(dir))
	}
	return nil
}

// openOwned opens the file at path when it is a regular file that owner
// owns. Both are judged on the open file, so what is read is what was judged
// whatever the path comes to name afterward.
func openOwned(path string, owner Owner) (*os.File, error) {
	f, err := fspath.OpenRegular(path)
	if err != nil {
		return nil, err
	}
	owned, err := owner.Owns(f)
	if err == nil && !owned {
		err = fmt.Errorf("%s: %w", filepath.Base(path), errNotOwned)
	}
	if err != nil {
		return nil, errors.Join(err, f.Close())
	}
	return f, nil
}

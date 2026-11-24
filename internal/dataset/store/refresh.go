// internal/dataset/store/refresh.go

package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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

const (
	// stagingPrefix begins the name of the directory a refresh stages what
	// it fetches in. The dot keeps it from being read as a dataset.
	stagingPrefix = ".staging-"

	// downloadName is the file a fetch is written to before its checksum,
	// which names it, is known.
	downloadName = "download" + partialSuffix
)

// Fetch writes the data of d, as its origin serves it, to w. The store does
// not know how data is fetched, and what fetches it does not know how the
// store keeps it.
type Fetch func(ctx context.Context, d dataset.Dataset, w io.Writer) error

// Refresh fetches each of datasets and brings it into the store, one outcome
// per dataset in name order. What is fetched is staged in the store's own
// layout, with a manifest recording its origin, the time now, and its
// checksum, and then enters the store by the path an imported dataset does:
// checked, installed over the copy held only when it passes, and recorded
// when it does not. A fetch that fails for a reason that passes is tried
// again; a dataset that cannot be fetched leaves the copy held in place and is
// recorded beside it. The store is locked for the whole refresh, and staging
// an earlier refresh left behind is removed first.
func (s Store) Refresh(ctx context.Context, fetch Fetch, datasets []dataset.Dataset, host *osfingerprint.OSInfo, now time.Time) (outcomes []Outcome, err error) {
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
		return nil, fmt.Errorf("stage the refresh: %w", err)
	}
	defer func() { err = errors.Join(err, os.RemoveAll(staging)) }()

	outcomes, err = s.stageAll(ctx, fetch, datasets, staging, now)
	if err != nil {
		return nil, err
	}
	installed, err := s.installStaged(ctx, staging, datasets, host, now)
	if err != nil {
		return nil, err
	}
	outcomes = append(outcomes, installed...)
	slices.SortFunc(outcomes, func(a, b Outcome) int { return strings.Compare(a.ID, b.ID) })
	return outcomes, nil
}

// stageAll fetches each of datasets into staging, trying again a fetch that
// fails for a reason that passes, and returns the outcome of each that could
// not be fetched. What a failed fetch staged is removed, so only whole
// datasets are left to install.
func (s Store) stageAll(ctx context.Context, fetch Fetch, datasets []dataset.Dataset, staging string, now time.Time) ([]Outcome, error) {
	var failed []Outcome
	for _, d := range datasets {
		dir := filepath.Join(staging, d.ID())
		attempts, ferr := retry(ctx, func() error { return stage(ctx, fetch, d, dir, now) })
		if ferr == nil {
			continue
		}
		if err := os.RemoveAll(dir); err != nil {
			return nil, err
		}
		failed = append(failed, s.failed(d.ID(), opRefresh, attempts, ferr, now))
	}
	return failed, nil
}

// installStaged brings what was staged into the store by the path an import
// takes.
func (s Store) installStaged(ctx context.Context, staging string, datasets []dataset.Dataset, host *osfingerprint.OSInfo, now time.Time) ([]Outcome, error) {
	entries, err := readDirBounded(staging)
	if err != nil {
		return nil, err
	}
	var outcomes []Outcome
	for _, o := range s.importEntries(ctx, opRefresh, staging, entries, datasets, host, now) {
		// What was fetched and then refused is a failed refresh of that
		// dataset, to be shown until one succeeds, where a refused entry
		// of an import is only a file the operator offered.
		if o.Result == Refused {
			o = s.failed(o.ID, opRefresh, 1, errors.New(o.Reason), now)
		}
		outcomes = append(outcomes, o)
	}
	return outcomes, nil
}

// clearStaging removes the staging directories in the store, which only a
// refresh that did not finish leaves.
func (s Store) clearStaging() error {
	entries, err := readDirBounded(s.root)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), stagingPrefix) {
			if err := os.RemoveAll(filepath.Join(s.root, e.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

// stage fetches d into dir as a dataset in the store's layout. Whatever an
// earlier attempt left in dir is removed first. The data is counted and
// hashed as it is written, and refused past the dataset's limit whatever the
// fetch itself allows, since the limit is the store's to keep.
func stage(ctx context.Context, fetch Fetch, d dataset.Dataset, dir string, now time.Time) error {
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return err
	}

	hash := sha256.New()
	limited := &limitedWriter{limit: d.MaxBytes()}
	download := filepath.Join(dir, downloadName)
	if err := writeNew(download, func(out io.Writer) error {
		limited.w = io.MultiWriter(out, hash)
		return fetch(ctx, d, limited)
	}); err != nil {
		return err
	}

	origin := d.Origin()
	m := dataset.Manifest{
		Format:      dataset.ManifestFormat,
		ID:          d.ID(),
		Source:      origin.URL,
		Fetched:     now,
		SHA256:      hex.EncodeToString(hash.Sum(nil)),
		Size:        limited.n,
		License:     origin.License,
		Attribution: origin.Attribution,
	}
	if err := os.Rename(download, filepath.Join(dir, m.SHA256+dataSuffix)); err != nil {
		return err
	}
	var manifest bytes.Buffer
	if err := m.Encode(&manifest); err != nil {
		return err
	}
	return writeReplacing(filepath.Join(dir, manifestName), manifest.Bytes())
}

// writeNew creates the file at path, which must not exist, and writes it
// with write, flushed to disk.
func writeNew(path string, write func(io.Writer) error) error {
	f, err := fspath.CreateNew(path, fileMode)
	if err != nil {
		return err
	}
	if err := write(f); err != nil {
		return errors.Join(err, f.Close())
	}
	if err := f.Sync(); err != nil {
		return errors.Join(err, f.Close())
	}
	return f.Close()
}

// errOverLimit means a fetch wrote more than the dataset may hold.
var errOverLimit = errors.New("the data is larger than the dataset may hold")

// limitedWriter writes to w and counts, and refuses the write that would
// pass limit.
type limitedWriter struct {
	w     io.Writer
	limit int64
	n     int64
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if l.n+int64(len(p)) > l.limit {
		return 0, fmt.Errorf("%w: more than %d bytes", errOverLimit, l.limit)
	}
	n, err := l.w.Write(p)
	l.n += int64(n)
	return n, err
}

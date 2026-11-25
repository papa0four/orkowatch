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
	// which names it, is known, and keptName the file a dataset that keeps
	// less than it fetches writes what it keeps to.
	downloadName = "download" + partialSuffix
	keptName     = "kept" + partialSuffix
)

// Fetch writes the data of d, as its origin serves it, to w. The store does
// not know how data is fetched, and what fetches it does not know how the
// store keeps it. A failure that says it is Unreachable means no connection
// could be made at all.
type Fetch func(ctx context.Context, d dataset.Dataset, w io.Writer) error

// ErrUnreachable means a refresh stopped because no connection could be made,
// as on a host with no network, and fetched none of the datasets after the
// one that could not be reached.
var ErrUnreachable = errors.New("the network could not be reached")

// Refresh fetches each of datasets and brings it into the store, one outcome
// per dataset in name order. What is fetched is staged in the store's own
// layout, with a manifest recording its origin, the time now, and its
// checksum, and then enters the store by the path an imported dataset does:
// checked, installed over the copy held only when it passes, and recorded
// when it does not. A fetch that fails for a reason that passes is tried
// again; a dataset that cannot be fetched leaves the copy held in place and is
// recorded beside it. A fetch that could make no connection at all stops the
// refresh there: what was fetched before it is still brought in, its outcomes
// are returned, and the error is ErrUnreachable with the fetch's reason. The
// store is locked for the whole refresh, and staging an earlier refresh left
// behind is removed first.
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

	outcomes, unreached, err := s.stageAll(ctx, fetch, datasets, staging, host, now)
	if err != nil {
		return nil, err
	}
	installed, err := s.installStaged(ctx, staging, datasets, host, now)
	if err != nil {
		return nil, err
	}
	outcomes = append(outcomes, installed...)
	slices.SortFunc(outcomes, func(a, b Outcome) int { return strings.Compare(a.ID, b.ID) })
	return outcomes, unreached
}

// stageAll fetches each of datasets into staging, trying again a fetch that
// fails for a reason that passes, and returns the outcome of each that could
// not be fetched. What a failed fetch staged is removed, so only whole
// datasets are left to install. A dataset that keeps less than it fetches
// keeps what host needs. A fetch that could make no connection at all stops
// the staging, and unreached is ErrUnreachable with its reason.
func (s Store) stageAll(ctx context.Context, fetch Fetch, datasets []dataset.Dataset, staging string, host *osfingerprint.OSInfo, now time.Time) (failed []Outcome, unreached, err error) {
	for _, d := range datasets {
		dir := filepath.Join(staging, d.ID())
		attempt := 0
		attempts, ferr := retry(ctx, func() error {
			attempt++
			return stage(ctx, s.report(), attempt, fetch, d, dir, host, now)
		})
		if ferr == nil {
			continue
		}
		if err := os.RemoveAll(dir); err != nil {
			return nil, nil, err
		}
		failed = append(failed, s.failed(d.ID(), opRefresh, attempts, ferr, now))
		var away interface{ Unreachable() bool }
		if errors.As(ferr, &away) && away.Unreachable() {
			return failed, fmt.Errorf("%w: %w", ErrUnreachable, ferr), nil
		}
	}
	return failed, nil, nil
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

// stage fetches d into dir as a dataset in the store's layout, as the
// attempt-th try, telling p of the download and of what is kept. Whatever an
// earlier attempt left in dir is removed first. The download is counted and
// hashed as it is written, and refused past what d's origin may serve
// whatever the fetch itself allows, since the limit is the store's to keep.
// A dataset that keeps less than it fetches has what it keeps for host
// written from the download, which is then deleted, and the manifest records
// the download beside what was kept.
func stage(ctx context.Context, p Progress, attempt int, fetch Fetch, d dataset.Dataset, dir string, host *osfingerprint.OSInfo, now time.Time) error {
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return err
	}

	download := filepath.Join(dir, downloadName)
	var (
		sum  string
		size int64
	)
	if err := step(p, d.ID(), StepDownload, attempt, func() (err error) {
		sum, size, err = writeCounted(download, dataset.FetchLimit(d), func(out io.Writer) error {
			return fetch(ctx, d, &receiving{w: out, p: p, id: d.ID()})
		})
		return err
	}); err != nil {
		return err
	}

	origin := d.Origin()
	m := dataset.Manifest{
		Format:      dataset.ManifestFormat,
		ID:          d.ID(),
		Source:      origin.URL,
		Fetched:     now,
		SHA256:      sum,
		Size:        size,
		License:     origin.License,
		Attribution: origin.Attribution,
	}
	data := download
	if k, ok := d.(dataset.Keeper); ok {
		m.OriginSHA256, m.OriginSize = sum, size
		data = filepath.Join(dir, keptName)
		if err := step(p, d.ID(), StepKeep, 1, func() (err error) {
			m.SHA256, m.Size, err = keep(k, download, data, host)
			return err
		}); err != nil {
			return err
		}
		if err := os.Remove(download); err != nil {
			return err
		}
	}
	if err := os.Rename(data, filepath.Join(dir, m.SHA256+dataSuffix)); err != nil {
		return err
	}
	var manifest bytes.Buffer
	if err := m.Encode(&manifest); err != nil {
		return err
	}
	return writeReplacing(filepath.Join(dir, manifestName), manifest.Bytes())
}

// writeCounted creates the file at path, which must not exist, and writes it
// with write, refusing the write that would pass limit. It returns the
// checksum of what was written, in lower-case hexadecimal, and its size.
func writeCounted(path string, limit int64, write func(io.Writer) error) (string, int64, error) {
	hash := sha256.New()
	limited := &limitedWriter{limit: limit}
	if err := writeNew(path, func(out io.Writer) error {
		limited.w = io.MultiWriter(out, hash)
		return write(limited)
	}); err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hash.Sum(nil)), limited.n, nil
}

// keep writes to the file at to what k keeps for host from the fetched file
// at from, held to what k may keep. It returns the checksum and size of what
// was kept.
func keep(k dataset.Keeper, from, to string, host *osfingerprint.OSInfo) (sum string, size int64, err error) {
	fetched, err := fspath.OpenRegular(from)
	if err != nil {
		return "", 0, err
	}
	defer func() { err = errors.Join(err, fetched.Close()) }()
	info, err := fetched.Stat()
	if err != nil {
		return "", 0, err
	}
	return writeCounted(to, k.MaxBytes(), func(out io.Writer) error {
		return k.Keep(fetched, info.Size(), host, out)
	})
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

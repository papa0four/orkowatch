// internal/dataset/store/import.go

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

// Result is what an import did with one dataset.
type Result string

// The results of importing a dataset.
const (
	// Installed is a dataset now held.
	Installed Result = "installed"

	// Kept is a dataset whose held copy was fetched no earlier than the one
	// offered, and is left as it is.
	Kept Result = "kept"

	// Skipped is a dataset that does not apply to this host, and is not
	// installed.
	Skipped Result = "skipped"

	// Refused is a dataset the import would not take: unknown, damaged, or
	// not what its manifest says.
	Refused Result = "refused"

	// Failed is a dataset that passed every check and could not be installed.
	Failed Result = "failed"
)

const (
	// lockWait is how long an import or a removal waits for another to
	// finish changing the store before it gives up.
	lockWait = 10 * time.Second

	// maxAttempts is how many times an install step that fails for a reason
	// that passes is tried before the import of the dataset fails.
	maxAttempts = 3

	// partialSuffix ends the name of a file while it is written. It is
	// renamed into place once it is whole, so a reader never sees it.
	partialSuffix = ".partial"

	// fileMode keeps a dataset's files to the account the store belongs to.
	fileMode os.FileMode = 0o600
)

// retryWaits are the waits before the second and third attempts.
var retryWaits = [maxAttempts - 1]time.Duration{100 * time.Millisecond, 500 * time.Millisecond}

// Outcome is what an import did with one entry of the directory it read.
type Outcome struct {
	ID       string
	Result   Result
	Reason   string
	Attempts int
}

// NeedsAttention reports whether the outcome is one the operator must deal
// with: a dataset refused or one that failed to install.
func (o Outcome) NeedsAttention() bool {
	return o.Result == Refused || o.Result == Failed
}

// Import installs the datasets in the directory from, which is written in the
// store's own layout, one outcome per entry in name order. Each is checked as
// a held dataset is before anything is written, and installed only when it is
// one known names, it applies to host, and it was fetched later than the copy
// held. Entries whose names begin with a dot are passed over, since none can
// name a dataset. The store is locked for the whole import.
func (s Store) Import(ctx context.Context, from string, known []dataset.Dataset, host *osfingerprint.OSInfo, now time.Time) (outcomes []Outcome, err error) {
	entries, err := readDirBounded(from)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", from, err)
	}
	slices.SortFunc(entries, func(a, b os.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })

	release, err := s.lock(ctx, lockWait)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, release()) }()
	return s.importEntries(ctx, opImport, from, entries, known, host, now), nil
}

// importEntries imports the entries of the directory from, under the store's
// lock, which the caller holds. op is the operation an install that fails is
// recorded under, since a refresh installs by this path too.
func (s Store) importEntries(ctx context.Context, op operation, from string, entries []os.DirEntry, known []dataset.Dataset, host *osfingerprint.OSInfo, now time.Time) []Outcome {
	var outcomes []Outcome
	byID := make(map[string]dataset.Dataset, len(known))
	for _, d := range known {
		byID[d.ID()] = d
	}
	src := Store{root: from}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			continue
		}
		outcomes = append(outcomes, s.importOne(ctx, op, src, e, byID, host, now))
	}
	return outcomes
}

// importOne imports one entry of the directory src, recording an install
// that fails under op.
func (s Store) importOne(ctx context.Context, op operation, src Store, e os.DirEntry, byID map[string]dataset.Dataset, host *osfingerprint.OSInfo, now time.Time) Outcome {
	id := e.Name()
	d, known := byID[id]
	refuse := func(reason string) Outcome { return Outcome{ID: id, Result: Refused, Reason: reason} }
	switch {
	case !e.IsDir():
		return refuse("not a dataset directory")
	case !dataset.ValidID(id):
		return refuse("the name cannot name a dataset")
	case !known:
		return refuse("this version of owatch does not know the dataset")
	case !d.AppliesTo(host):
		return Outcome{ID: id, Result: Skipped, Reason: "it does not apply to this host"}
	}

	p := s.report()
	var (
		m    dataset.Manifest
		held string
	)
	if err := step(p, id, StepCheck, 1, func() (err error) {
		if m, err = src.read(d, now, checkWith(d, host)); err != nil {
			return err
		}
		if h, err := s.read(d, now, checkWith(d, host)); err == nil && !m.Fetched.After(h.Fetched) {
			held = h.Fetched.UTC().Format(time.RFC3339)
		}
		return nil
	}); err != nil {
		return refuse(err.Error())
	}
	if held != "" {
		return Outcome{ID: id, Result: Kept, Reason: fmt.Sprintf("the copy held was fetched at %s, no earlier than this one, fetched at %s",
			held, m.Fetched.UTC().Format(time.RFC3339))}
	}

	attempt := 0
	attempts, err := retry(ctx, func() error {
		attempt++
		return step(p, id, StepInstall, attempt, func() error { return s.install(src, d, m) })
	})
	if err != nil {
		return s.failed(id, op, attempts, err, now)
	}
	return Outcome{ID: id, Result: Installed, Attempts: attempts}
}

// failed is the outcome of a dataset op could not bring into the store,
// recorded beside the copy held so status shows it, and the command to run
// again, until an install of the dataset succeeds.
func (s Store) failed(id string, op operation, attempts int, err error, now time.Time) Outcome {
	reason := err.Error()
	if rerr := s.recordFailure(id, failure{Operation: op, Attempts: attempts, Reason: reason, At: now}); rerr != nil {
		reason += "; the failure could not be recorded: " + rerr.Error()
	}
	return Outcome{ID: id, Result: Failed, Reason: reason, Attempts: attempts}
}

// checkWith is the read of a dataset that runs its own check of the content,
// for host.
func checkWith(d dataset.Dataset, host *osfingerprint.OSInfo) func(io.Reader) error {
	return func(data io.Reader) error {
		_, err := d.Check(data, host)
		return err
	}
}

// passes reports whether err is a failure worth trying again: one the system
// reports as passing, or one that says so itself, as a fetch does of a
// timeout or of a server that is briefly unable to answer.
func passes(err error) bool {
	var self interface{ Passing() bool }
	return transient(err) || (errors.As(err, &self) && self.Passing())
}

// retry runs step until it succeeds, fails for a reason that does not pass,
// or has been tried maxAttempts times, and says how many times it ran.
func retry(ctx context.Context, step func() error) (int, error) {
	for attempt := 1; ; attempt++ {
		err := step()
		if err == nil || attempt == maxAttempts || !passes(err) {
			return attempt, err
		}
		select {
		case <-ctx.Done():
			return attempt, errors.Join(err, ctx.Err())
		case <-time.After(retryWaits[attempt-1]):
		}
	}
}

// install copies the dataset d, described by m, from src into the store. The
// data is written under its checksum and checked again as it is copied, the
// manifest is then moved onto the one held, which is the moment the new copy
// becomes the one read, and every other file in the dataset's directory is
// deleted: the data replaced, the record of an earlier failure, and anything
// an interrupted install left.
func (s Store) install(src Store, d dataset.Dataset, m dataset.Manifest) error {
	dir := s.dir(d.ID())
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return err
	}
	dataName := m.SHA256 + dataSuffix
	if err := copyVerified(filepath.Join(src.dir(d.ID()), dataName), filepath.Join(dir, dataName), m); err != nil {
		return err
	}
	var manifest bytes.Buffer
	if err := m.Encode(&manifest); err != nil {
		return err
	}
	if err := writeReplacing(filepath.Join(dir, manifestName), manifest.Bytes()); err != nil {
		return err
	}
	return sweep(dir, manifestName, dataName)
}

// copyVerified copies the data file at from to to, holding what is copied to
// the size and checksum m records, since the file read when the dataset was
// checked may have been changed since.
func copyVerified(from, to string, m dataset.Manifest) (err error) {
	in, err := fspath.OpenRegular(from)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, in.Close()) }()

	return writeFile(to, func(out io.Writer) error {
		hash := sha256.New()
		n, err := io.Copy(io.MultiWriter(out, hash), io.LimitReader(in, m.Size+1))
		switch {
		case err != nil:
			return err
		case n != m.Size:
			return fmt.Errorf("the data held %d bytes when copied, where the manifest says %d", n, m.Size)
		case hex.EncodeToString(hash.Sum(nil)) != m.SHA256:
			return errors.New("the data changed after it was checked")
		}
		return nil
	})
}

// writeReplacing writes data to path, replacing what is there in one step.
func writeReplacing(path string, data []byte) error {
	return writeFile(path, func(out io.Writer) error {
		_, err := out.Write(data)
		return err
	})
}

// writeFile writes a file under a partial name, flushes it to disk, and
// renames it onto path, so path holds either what it held or the whole of the
// new file and never part of it. A partial file an earlier write left is
// removed first, and this one is removed when the write fails.
func writeFile(path string, write func(io.Writer) error) (err error) {
	partial := path + partialSuffix
	if err := os.Remove(partial); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := fspath.CreateNew(partial, fileMode)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, os.Remove(partial))
		}
	}()

	if err := write(f); err != nil {
		return errors.Join(err, f.Close())
	}
	if err := f.Sync(); err != nil {
		return errors.Join(err, f.Close())
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(partial, path)
}

// sweep deletes every entry of dir but those named keep.
func sweep(dir string, keep ...string) error {
	entries, err := readDirBounded(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if slices.Contains(keep, e.Name()) {
			continue
		}
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

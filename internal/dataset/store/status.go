// internal/dataset/store/status.go

package store

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/osfingerprint"
)

// Status returns what the store holds of the datasets in known, at now: one
// row for each dataset that applies to host, held or not, and one for each
// directory in the store that holds a dataset not applying to host or one
// known does not name. A held dataset is checked as any read checks it, so a
// row that says current says the data was read and found sound, and a row
// says what needs attention: an import that failed, or an install that did
// not finish.
func (s Store) Status(known []dataset.Dataset, host *osfingerprint.OSInfo, now time.Time) (dataset.View, error) {
	view := dataset.View{Store: s.root, Datasets: []dataset.Row{}}
	named := make(map[string]bool, len(known))

	for _, d := range known {
		named[d.ID()] = true
		held, err := s.held(d.ID())
		if err != nil {
			return dataset.View{}, err
		}
		switch applies := d.AppliesTo(host); {
		case applies && !held:
			view.Datasets = append(view.Datasets, dataset.Row{ID: d.ID(), State: dataset.StateNotHeld})
		case applies:
			row := s.heldRow(d, now)
			row.Attention = attention(s.dir(d.ID()))
			view.Datasets = append(view.Datasets, row)
		case held:
			view.Datasets = append(view.Datasets, s.sizedRow(d.ID(), dataset.StateNotApplicable))
		}
	}

	others, err := s.unknownDirs(named)
	if err != nil {
		return dataset.View{}, err
	}
	for _, id := range others {
		view.Datasets = append(view.Datasets, s.sizedRow(id, dataset.StateUnknown))
	}
	return view, nil
}

// heldRow reads a held dataset with its own check and says what was found.
func (s Store) heldRow(d dataset.Dataset, now time.Time) dataset.Row {
	var facts dataset.Facts
	m, err := s.read(d, now, func(data io.Reader) error {
		var checkErr error
		facts, checkErr = d.Check(data)
		return checkErr
	})
	if err == nil && facts.Version == "" {
		err = errors.New("its check states no version of the data")
	}
	if err != nil {
		return dataset.Row{ID: d.ID(), State: dataset.StateUnusable, Reason: err.Error()}
	}
	return dataset.Row{
		ID:          d.ID(),
		State:       dataset.StateAt(m.Fetched, now),
		Source:      m.Source,
		DataDate:    facts.Date.UTC().Format(time.DateOnly),
		Version:     facts.Version,
		Fetched:     m.Fetched.UTC().Format(time.RFC3339),
		Size:        m.Size,
		License:     m.License,
		Attribution: m.Attribution,
	}
}

// sizedRow is a dataset directory that is not read, with the size of what it
// holds, so the operator can see what removing it would free.
func (s Store) sizedRow(id string, state dataset.State) dataset.Row {
	size, err := dirSize(s.dir(id))
	if err != nil {
		return dataset.Row{ID: id, State: state, Reason: err.Error()}
	}
	return dataset.Row{ID: id, State: state, Size: size}
}

// unknownDirs lists the directories in the store that named does not hold, in
// name order. A missing store has none. One whose name begins with a dot is
// the store's own, where a fetch is staged, and is passed over as Import
// passes over it.
func (s Store) unknownDirs(named map[string]bool) ([]string, error) {
	entries, err := readDirBounded(s.root)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, e := range entries {
		if e.IsDir() && !named[e.Name()] && !strings.HasPrefix(e.Name(), ".") {
			ids = append(ids, e.Name())
		}
	}
	slices.Sort(ids)
	return ids, nil
}

// dirSize adds up the regular files directly in dir. Nothing is followed and
// nothing below dir is entered, since a dataset directory holds files only.
func dirSize(dir string) (int64, error) {
	entries, err := readDirBounded(dir)
	if err != nil {
		return 0, err
	}
	var total int64
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return 0, err
		}
		total += info.Size()
	}
	return total, nil
}

// readDirBounded lists dir, refusing one that holds more than maxEntries.
func readDirBounded(dir string) ([]os.DirEntry, error) {
	f, err := os.Open(filepath.Clean(dir))
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // a directory opened to be listed; the listing is what was wanted

	entries, err := f.ReadDir(maxEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(entries) > maxEntries {
		return nil, fmt.Errorf("%s holds more than %d entries", dir, maxEntries)
	}
	return entries, nil
}

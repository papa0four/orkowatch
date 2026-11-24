// internal/dataset/datasettest/datasettest.go

// Package datasettest holds a dataset made for tests and writes it in the
// store's layout, so the store's tests and the commands' tests judge one
// dataset by one set of files. Nothing outside a test imports it.
package datasettest

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/osfingerprint"
)

const (
	// Header opens every file of the test dataset; the line after it is
	// the date of its data.
	Header = "owatch-test-dataset\n"

	// Content is a sound file of the test dataset, with data of 2026-11-20.
	Content = Header + "2026-11-20\nentries\n"

	// MaxBytes is the most a file of the test dataset may hold.
	MaxBytes = 1 << 10

	// Version is the version every sound file of the test dataset reports.
	Version = "test-1"
)

// Dataset is a dataset made for tests: a header line, the date of its data,
// and anything after. Applies says whether it applies to every host or to
// none, and From is where a test serves it. For, when set, is the only
// platform its data is for, as a dataset kept for one release is.
type Dataset struct {
	Name    string
	Applies bool
	From    dataset.Origin
	For     string
}

// ID names the dataset.
func (d Dataset) ID() string { return d.Name }

// AppliesTo reports Applies whatever the host.
func (d Dataset) AppliesTo(*osfingerprint.OSInfo) bool { return d.Applies }

// Origin is From.
func (d Dataset) Origin() dataset.Origin { return d.From }

// MaxBytes is MaxBytes.
func (Dataset) MaxBytes() int64 { return MaxBytes }

// Check refuses data that does not open with Header and a date, and, when For
// is set, data read for a host of another platform.
func (d Dataset) Check(data io.Reader, host *osfingerprint.OSInfo) (dataset.Facts, error) {
	if d.For != "" && (host == nil || host.Platform != d.For) {
		return dataset.Facts{}, errors.New("the data is for " + d.For + ", not this host")
	}
	r := bufio.NewReader(data)
	header, err := r.ReadString('\n')
	if err != nil || header != Header {
		return dataset.Facts{}, errors.New("not the test dataset")
	}
	line, err := r.ReadString('\n')
	if err != nil {
		return dataset.Facts{}, errors.New("no date")
	}
	date, err := time.Parse(time.DateOnly, strings.TrimSpace(line))
	if err != nil {
		return dataset.Facts{}, errors.New("no date")
	}
	return dataset.Facts{Date: date, Version: Version}, nil
}

// DataName is the name the store gives the file holding data.
func DataName(data string) string {
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:]) + ".data"
}

// Put writes data as the dataset d in the directory root, which is in the
// store's layout, with the manifest that describes it, changed by edit when
// edit is not nil.
func Put(t *testing.T, root string, d dataset.Dataset, data string, fetched time.Time, edit func(*dataset.Manifest)) {
	t.Helper()
	sum := sha256.Sum256([]byte(data))
	m := dataset.Manifest{
		Format:      dataset.ManifestFormat,
		ID:          d.ID(),
		Source:      "https://data.example/" + d.ID(),
		Fetched:     fetched,
		SHA256:      hex.EncodeToString(sum[:]),
		Size:        int64(len(data)),
		License:     "CC0 1.0",
		Attribution: "Made for the tests",
	}
	if edit != nil {
		edit(&m)
	}
	dir := filepath.Join(root, d.ID())
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, DataName(data)), []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(dir, "manifest.json")) // #nosec G304 -- a test's own directory
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Encode(f); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

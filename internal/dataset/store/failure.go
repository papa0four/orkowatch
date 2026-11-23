// internal/dataset/store/failure.go

package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/papa0four/orkowatch/internal/fspath"
)

const (
	// failureName is the record, in a dataset's directory, of an import of
	// it that failed. It stays until an install of the dataset succeeds or
	// the dataset is removed, so status says what went wrong until it is
	// dealt with.
	failureName = "failure.json"

	// maxFailureBytes bounds the record, which is a reason and two fields.
	maxFailureBytes = 64 << 10
)

// failure is what is recorded of a failed import.
type failure struct {
	Attempts int       `json:"attempts"`
	Reason   string    `json:"reason"`
	At       time.Time `json:"at"`
}

// recordFailure writes the record of a failed import of the dataset id,
// replacing any earlier one.
func (s Store) recordFailure(id string, f failure) error {
	dir := s.dir(id)
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return err
	}
	data, err := json.Marshal(f)
	if err != nil {
		return err
	}
	return writeReplacing(filepath.Join(dir, failureName), data)
}

// readFailure reads the record of a failed import in dir, reporting false
// when there is none. The record is read as untrusted as anything else in the
// store: it is bounded, refused with a field it does not know, and refused
// when its reason holds a control character, since it is shown on a terminal.
func readFailure(dir string) (rec failure, found bool, err error) {
	f, err := fspath.OpenRegular(filepath.Join(dir, failureName))
	if errors.Is(err, os.ErrNotExist) {
		return failure{}, false, nil
	}
	if err != nil {
		return failure{}, false, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()

	data, err := io.ReadAll(io.LimitReader(f, maxFailureBytes+1))
	if err != nil {
		return failure{}, false, err
	}
	if len(data) > maxFailureBytes {
		return failure{}, false, fmt.Errorf("larger than %d KiB", maxFailureBytes>>10)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rec); err != nil {
		return failure{}, false, err
	}
	if strings.IndexFunc(rec.Reason, unicode.IsControl) >= 0 {
		return failure{}, false, errors.New("its reason holds a control character")
	}
	return rec, true, nil
}

// attention says what about the dataset in dir needs the operator, or returns
// the empty string when nothing does: an import that failed, as its record
// says, or an install that did not finish, which leaves a file the dataset's
// manifest does not name.
func attention(dir string) string {
	rec, found, err := readFailure(dir)
	switch {
	case err != nil:
		return "the record of a failed import cannot be read (" + err.Error() + "); resolve it and run owatch data import again"
	case found:
		return fmt.Sprintf("the import at %s failed after %d attempts: %s; resolve the cause and run owatch data import again",
			rec.At.UTC().Format(time.RFC3339), rec.Attempts, rec.Reason)
	}
	if strays(dir) {
		return "an install of this dataset did not finish; run owatch data import again to complete it"
	}
	return ""
}

// strays reports whether dir holds a file an install leaves only when it does
// not finish: one being written, or data the manifest does not name.
func strays(dir string) bool {
	entries, err := readDirBounded(dir)
	if err != nil {
		return false
	}
	named := ""
	if m, err := readManifest(filepath.Join(dir, manifestName)); err == nil {
		named = m.SHA256 + dataSuffix
	}
	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, partialSuffix) || (strings.HasSuffix(name, dataSuffix) && name != named) {
			return true
		}
	}
	return false
}

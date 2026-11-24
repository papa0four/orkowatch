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
	"github.com/papa0four/orkowatch/internal/render"
)

const (
	// failureName is the record, in a dataset's directory, of an import or
	// a refresh of it that failed. It stays until an install of the dataset
	// succeeds or the dataset is removed, so status says what went wrong
	// until it is dealt with.
	failureName = "failure.json"

	// maxFailureBytes bounds the record, which is a reason and three fields.
	maxFailureBytes = 64 << 10

	// opImport and opRefresh are the operations that can fail to bring a
	// dataset into the store. Each is also the owatch data command that
	// runs it, so the record names what to run again.
	opImport  operation = "import"
	opRefresh operation = "refresh"
)

type (
	// operation is what failed to bring a dataset into the store.
	operation string

	// failure is what is recorded of a failed import or refresh.
	failure struct {
		Operation operation `json:"operation"`
		Attempts  int       `json:"attempts"`
		Reason    string    `json:"reason"`
		At        time.Time `json:"at"`
	}
)

// recordFailure writes the record of a failed import or refresh of the
// dataset id, replacing any earlier one.
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

// readFailure reads the record of a failed import or refresh in dir,
// reporting false when there is none. The record is read as untrusted as
// anything else in the store: it is bounded, refused with a field it does not
// know or an operation that is neither, and refused when its reason holds a
// control character, since it is shown on a terminal.
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
	if rec.Operation != opImport && rec.Operation != opRefresh {
		return failure{}, false, fmt.Errorf("it names the operation %q, which is neither %s nor %s", rec.Operation, opImport, opRefresh)
	}
	if strings.IndexFunc(rec.Reason, unicode.IsControl) >= 0 {
		return failure{}, false, errors.New("its reason holds a control character")
	}
	return rec, true, nil
}

// attention says what about the dataset in dir needs the operator, or returns
// the empty string when nothing does: an import or a refresh that failed, as
// its record says, with the command to run again, or an install that did not
// finish, which leaves a file the dataset's manifest does not name. Either
// command installs, so where the record cannot say which one ran, both are
// named. A reason that ends a sentence of its own, as Windows writes its
// errors, loses that period here, where the sentence goes on.
func attention(dir string) string {
	rec, found, err := readFailure(dir)
	switch {
	case err != nil:
		return "the record of a failed import or refresh cannot be read (" + err.Error() + "); resolve it and run owatch data refresh or owatch data import again"
	case found:
		return fmt.Sprintf("the %s at %s failed after %s: %s; resolve the cause and run owatch data %s again",
			rec.Operation, rec.At.UTC().Format(time.RFC3339), render.Count(rec.Attempts, "attempt", "attempts"), strings.TrimSuffix(rec.Reason, "."), rec.Operation)
	}
	if strays(dir) {
		return "an install of this dataset did not finish; run owatch data refresh or owatch data import again to complete it"
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

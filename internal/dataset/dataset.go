// internal/dataset/dataset.go

package dataset

import (
	"io"
	"regexp"
	"time"

	"github.com/papa0four/orkowatch/internal/osfingerprint"
)

type (
	// Dataset is what a source states about one of its datasets.
	Dataset interface {
		// ID names the dataset. It is the name of the dataset's directory in
		// the store and must satisfy ValidID.
		ID() string

		// AppliesTo reports whether the dataset holds anything about host,
		// so that a host holds only what it can use.
		AppliesTo(host *osfingerprint.OSInfo) bool

		// MaxBytes is the most the dataset's data may hold. A larger file is
		// refused before it is read.
		MaxBytes() int64

		// Check reads the data and refuses it when it is not what the source
		// publishes. It reads no further than it needs to decide, and the
		// caller bounds what it can read to MaxBytes.
		Check(data io.Reader) (Facts, error)
	}

	// Facts is what Check learns from the data itself, which no manifest can
	// claim on the data's behalf.
	Facts struct {
		// Date is the date the source gave its data.
		Date time.Time
	}
)

// maxIDLen bounds a dataset's name, which is also a directory's.
const maxIDLen = 64

// idPattern admits lower-case letters and digits in words joined by single
// hyphens: nothing that is a path separator, a relative step or a name a
// filesystem treats specially.
var idPattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// ValidID reports whether id can name a dataset, and so a directory in the
// store, on every platform.
func ValidID(id string) bool {
	return len(id) <= maxIDLen && idPattern.MatchString(id)
}

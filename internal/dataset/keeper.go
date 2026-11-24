// internal/dataset/keeper.go

package dataset

import (
	"io"

	"github.com/papa0four/orkowatch/internal/osfingerprint"
)

// Keeper is a dataset that keeps less than its origin serves: a source that
// publishes every release of a system in one file, of which a host needs one.
// A refresh writes what Keep keeps from the fetched file, and the store holds
// that, judged by Check as any data is. MaxBytes bounds what is kept.
type Keeper interface {
	Dataset

	// FetchMaxBytes is the most the file the origin serves may hold. A
	// larger file is refused before it is read.
	FetchMaxBytes() int64

	// Keep reads the fetched file, size bytes, and writes to kept what host
	// needs of it. It refuses a file that is not what the source publishes,
	// as Check refuses data, so nothing is kept from a file that would not
	// pass.
	Keep(fetched io.ReaderAt, size int64, host *osfingerprint.OSInfo, kept io.Writer) error
}

// FetchLimit is the most the file d's origin serves may hold: what d keeps
// when it keeps the file whole, and what it states apart when it keeps less.
// Every bound on a download is taken from here, so none is set by a caller
// choosing between the two.
func FetchLimit(d Dataset) int64 {
	if k, ok := d.(Keeper); ok {
		return k.FetchMaxBytes()
	}
	return d.MaxBytes()
}

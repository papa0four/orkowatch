// internal/dataset/view.go

package dataset

import (
	"fmt"
	"io"
	"strconv"

	"github.com/papa0four/orkowatch/internal/render"
)

// The states of a dataset that is not held and current, out of sync, or
// stale.
const (
	// StateNotHeld is a dataset that applies to the host and is not in the
	// store.
	StateNotHeld State = "not held"

	// StateUnusable is a dataset in the store that failed a check, and so
	// is not read.
	StateUnusable State = "unusable"

	// StateNotApplicable is a dataset in the store that no longer applies
	// to the host, such as one for a release the host was upgraded from.
	StateNotApplicable State = "no longer applies"

	// StateUnknown is a directory in the store that this version of owatch
	// does not know as a dataset.
	StateUnknown State = "unknown to this version"
)

// View is the serializable projection of a store: where it is and what it
// holds, one row per dataset.
type View struct {
	Store    string `json:"store" yaml:"store"`
	Datasets []Row  `json:"datasets" yaml:"datasets"`
}

// Row is one dataset as status shows it. A held dataset carries what its
// manifest and its data say, the date of its data as time.DateOnly writes it,
// the version its source gives the data, and its fetch time as time.RFC3339
// writes it; any other carries its state and, where there is one, the reason
// or its size.
type Row struct {
	ID          string `json:"id" yaml:"id"`
	State       State  `json:"state" yaml:"state"`
	Reason      string `json:"reason,omitempty" yaml:"reason,omitempty"`
	Source      string `json:"source,omitempty" yaml:"source,omitempty"`
	DataDate    string `json:"data_date,omitempty" yaml:"data_date,omitempty"`
	Version     string `json:"version,omitempty" yaml:"version,omitempty"`
	Fetched     string `json:"fetched,omitempty" yaml:"fetched,omitempty"`
	Size        int64  `json:"size,omitempty" yaml:"size,omitempty"`
	License     string `json:"license,omitempty" yaml:"license,omitempty"`
	Attribution string `json:"attribution,omitempty" yaml:"attribution,omitempty"`

	// Attention is what about the dataset the operator must deal with,
	// whatever its state: an import of it that failed, with the reason, or
	// an install of it that did not finish.
	Attention string `json:"attention,omitempty" yaml:"attention,omitempty"`
}

const (
	// unitBytes is the step between the units sizes are written in.
	unitBytes = 1 << 10

	// decimalBase and floatBits describe how a size is written: base-10
	// digits, from a 64-bit float.
	decimalBase = 10
	floatBits   = 64
)

// WriteText writes v as status prints it: the store, then one line per
// dataset with its state and what bears on it, and under it, for a held
// dataset, the source, license, and attribution, and what needs attention.
// This is the one text renderer
// of a store, used by status and by a saved status report alike.
func WriteText(w io.Writer, v View) error {
	ew := render.NewErrWriter(w)
	ew.Printf("Store: %s\n\n", render.HostText(v.Store))
	if len(v.Datasets) == 0 {
		ew.Printf("No dataset applies to this host, and the store holds none.\n")
		return ew.Err()
	}

	width := 0
	for _, r := range v.Datasets {
		width = max(width, len(render.HostText(r.ID)))
	}
	for _, r := range v.Datasets {
		ew.Printf("%-*s  %s\n", width, render.HostText(r.ID), rowDetail(r))
		if r.Source != "" {
			ew.Printf("%-*s  source %s\n", width, "", render.HostText(r.Source))
		}
		if r.License != "" || r.Attribution != "" {
			ew.Printf("%-*s  license %s\n", width, "", render.HostText(r.License+"; "+r.Attribution))
		}
		if r.Attention != "" {
			ew.Printf("%-*s  needs attention: %s\n", width, "", render.HostText(r.Attention))
		}
	}
	return ew.Err()
}

// rowDetail is what follows a dataset's name on its line. A row comes from
// the store, or from a saved report when one is shown, so what it says goes
// through render.HostText before it reaches a terminal.
func rowDetail(r Row) string {
	var detail string
	switch r.State {
	case StateCurrent, StateOutOfSync, StateStale:
		detail = fmt.Sprintf("%s: data of %s, version %s, fetched %s, %s", r.State, r.DataDate, r.Version, r.Fetched, Size(r.Size))
	case StateUnusable:
		detail = fmt.Sprintf("%s: %s", r.State, r.Reason)
	case StateNotApplicable, StateUnknown:
		detail = fmt.Sprintf("%s, %s", r.State, Size(r.Size))
	default:
		detail = string(r.State)
	}
	return render.HostText(detail)
}

// Size writes a size in bytes in the largest unit that keeps it at least 1.
func Size(n int64) string {
	if n < unitBytes {
		return strconv.FormatInt(n, decimalBase) + " B"
	}
	value, unit := float64(n), 0
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	for value >= unitBytes && unit < len(units)-1 {
		value /= unitBytes
		unit++
	}
	return strconv.FormatFloat(value, 'f', 1, floatBits) + " " + units[unit]
}

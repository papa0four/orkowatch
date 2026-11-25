// internal/dataset/view.go

package dataset

import (
	"fmt"
	"io"
	"strconv"
	"time"

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
// holds, one row per dataset, and, for an elevated run, what it installed
// from the operator's store before reading its own.
type View struct {
	Store    string    `json:"store" yaml:"store"`
	Operator *Operator `json:"operator,omitempty" yaml:"operator,omitempty"`
	Datasets []Row     `json:"datasets" yaml:"datasets"`
}

// Operator is what an elevated run did with the datasets of the operator
// behind it. Store is the operator's store, and is empty when no one is
// behind the run, as with a direct root login; Advice then says how datasets
// reach this host. Installed names the datasets installed from Store, and
// Refused those left alone, each with the reason.
type Operator struct {
	Store     string    `json:"store,omitempty" yaml:"store,omitempty"`
	Installed []string  `json:"installed,omitempty" yaml:"installed,omitempty"`
	Refused   []Refusal `json:"refused,omitempty" yaml:"refused,omitempty"`
	Advice    string    `json:"advice,omitempty" yaml:"advice,omitempty"`
}

// Refusal is a dataset in the operator's store that was not installed.
type Refusal struct {
	ID     string `json:"id" yaml:"id"`
	Reason string `json:"reason" yaml:"reason"`
}

// Lines are what a report says of the operator's datasets, one sentence a
// line: what was installed, what was refused and why, and the advice. They
// are the same in the text report and the results browser.
func (o Operator) Lines() []string {
	var lines []string
	if len(o.Installed) > 0 {
		lines = append(lines, fmt.Sprintf("Installed from %s: %s", o.Store, render.List(o.Installed)))
	}
	for _, r := range o.Refused {
		lines = append(lines, fmt.Sprintf("Not installed from %s: %s: %s", o.Store, r.ID, r.Reason))
	}
	if o.Advice != "" {
		lines = append(lines, o.Advice)
	}
	return lines
}

// Provenance is what a dataset read was: the dataset and its state then and,
// for one that was held, what its manifest and its data say, the date of its
// data as time.DateOnly writes it, the version its source gives the data, its
// fetch time as time.RFC3339 writes it, and the terms its data comes under.
// The store's status and every result read from a dataset state it in this
// one form, so a report names its data as status does.
type Provenance struct {
	ID          string `json:"id,omitempty" yaml:"id,omitempty"`
	State       State  `json:"state,omitempty" yaml:"state,omitempty"`
	Source      string `json:"source,omitempty" yaml:"source,omitempty"`
	DataDate    string `json:"data_date,omitempty" yaml:"data_date,omitempty"`
	Version     string `json:"version,omitempty" yaml:"version,omitempty"`
	Fetched     string `json:"fetched,omitempty" yaml:"fetched,omitempty"`
	License     string `json:"license,omitempty" yaml:"license,omitempty"`
	Attribution string `json:"attribution,omitempty" yaml:"attribution,omitempty"`
}

// About names the data on one line as every report names the data a result
// was read from: the dataset, the version of its data, the date of its data,
// and its state.
func (p Provenance) About() string {
	return fmt.Sprintf("%s, %s, data of %s, %s", p.ID, p.Version, p.DataDate, p.State)
}

// ProvenanceOf is the provenance of the dataset id held under m, whose data
// its check gave facts of, read at now.
func ProvenanceOf(id string, m Manifest, facts Facts, now time.Time) Provenance {
	return Provenance{
		ID:          id,
		State:       StateAt(m.Fetched, now),
		Source:      m.Source,
		DataDate:    facts.Date.UTC().Format(time.DateOnly),
		Version:     facts.Version,
		Fetched:     m.Fetched.UTC().Format(time.RFC3339),
		License:     m.License,
		Attribution: m.Attribution,
	}
}

// Use is what a result was read from, or why it read nothing: the dataset
// named, its provenance when it was read, and otherwise the reason and what
// to run. A use with NotDone has nothing of a reading but the dataset's name,
// and that only when one was chosen.
type Use struct {
	Provenance `yaml:",inline"`

	NotDone string `json:"not_done,omitempty" yaml:"not_done,omitempty"`
}

// Row is one dataset as status shows it: its provenance and, for one that is
// not read, the reason or its size.
type Row struct {
	Provenance `yaml:",inline"`

	Reason string `json:"reason,omitempty" yaml:"reason,omitempty"`
	Size   int64  `json:"size,omitempty" yaml:"size,omitempty"`

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

// WriteText writes v as status prints it: the store, what an elevated run
// installed from the operator's, then one line per dataset with its state and
// what bears on it, and under it, for a held dataset, the source, license,
// and attribution, and what needs attention. This is the one text renderer of
// a store, used by status and by a saved status report alike.
func WriteText(w io.Writer, v View) error {
	ew := render.NewErrWriter(w)
	ew.Printf("Store: %s\n", render.HostText(v.Store))
	if v.Operator != nil {
		for _, line := range v.Operator.Lines() {
			ew.Printf("%s\n", render.HostText(line))
		}
	}
	ew.Printf("\n")
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

// internal/dataset/store/progress.go

package store

import "io"

// Step is a stage of bringing one dataset into the store.
type Step string

// The steps a refresh, an import, and an adoption take with a dataset, in the
// order they come. A refresh downloads and, for a dataset that keeps less than
// it fetches, keeps what the host needs; every path then checks and installs.
const (
	StepDownload Step = "download"
	StepKeep     Step = "keep"
	StepCheck    Step = "check"
	StepInstall  Step = "install"
)

// Progress is told what the store is doing with each dataset as it does it,
// so a large download or a long check is not taken for a hang. Received is
// called from inside a download, with the bytes received so far in the attempt
// under way.
type Progress interface {
	Began(id string, step Step, attempt int)
	Received(id string, bytes int64)
	Ended(id string, step Step, err error)
}

// Reporting returns the store, telling p what it does with each dataset.
func (s Store) Reporting(p Progress) Store {
	s.progress = p
	return s
}

// report is what the store tells of its progress: its Progress, or one that
// is told nothing when none was given.
func (s Store) report() Progress {
	if s.progress == nil {
		return quiet{}
	}
	return s.progress
}

// quiet is the Progress of a store no one watches.
type quiet struct{}

func (quiet) Began(string, Step, int)   {}
func (quiet) Received(string, int64)    {}
func (quiet) Ended(string, Step, error) {}

// step runs do as the step of id, telling p as it begins and ends.
func step(p Progress, id string, s Step, attempt int, do func() error) error {
	p.Began(id, s, attempt)
	err := do()
	p.Ended(id, s, err)
	return err
}

// receiving writes to w and tells its Progress how much of the dataset id has
// been received.
type receiving struct {
	w    io.Writer
	p    Progress
	id   string
	seen int64
}

func (r *receiving) Write(b []byte) (int, error) {
	n, err := r.w.Write(b)
	r.seen += int64(n)
	r.p.Received(r.id, r.seen)
	return n, err
}

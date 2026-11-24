// internal/dataset/store/reading.go

package store

import (
	"context"
	"time"

	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/elevation"
	"github.com/papa0four/orkowatch/internal/osfingerprint"
)

// Adoption is what an elevated process did with the operator's datasets
// before it read its own store. It is empty for a process that is not
// elevated, which reads the store its account refreshes.
type Adoption struct {
	// From is the operator's store, which Outcomes are of.
	From     string
	Outcomes []Outcome

	// NoOperator is an elevated process with no one behind it, as a direct
	// root login is: there is no store to install from.
	NoOperator bool
}

// ForReading returns the store the process uses, ready to be read. An
// elevated process first installs into its protected store what the operator
// behind it holds newer, since the operator refreshes and an elevated run
// never does. Every command that reads datasets opens the store here, so each
// reads what the operator last fetched.
func ForReading(ctx context.Context, known []dataset.Dataset, host *osfingerprint.OSInfo, now time.Time) (Store, Adoption, error) {
	s, err := ForProcess(ctx)
	if err != nil || !elevation.Elevated() {
		return s, Adoption{}, err
	}
	operator, ok := elevation.InvokingOperator()
	adoption, err := s.adoptFrom(ctx, operator, ok, RootOf(operator.Home), known, host, now)
	return s, adoption, err
}

// adoptFrom installs what the store in from holds newer, as owner's, or says
// there is no operator when there is none.
func (s Store) adoptFrom(ctx context.Context, owner Owner, ok bool, from string, known []dataset.Dataset, host *osfingerprint.OSInfo, now time.Time) (Adoption, error) {
	if !ok {
		return Adoption{NoOperator: true}, nil
	}
	outcomes, err := s.Adopt(ctx, from, owner, known, host, now)
	if err != nil {
		return Adoption{}, err
	}
	return Adoption{From: from, Outcomes: outcomes}, nil
}

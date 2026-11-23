// internal/dataset/state.go

package dataset

import "time"

// State is how current a held dataset is.
type State string

// The states of a held dataset, as status and every place its data is shown
// name them.
const (
	StateCurrent   State = "current"
	StateOutOfSync State = "out of sync"
	StateStale     State = "stale"
)

const (
	// OutOfSyncAfter is how long after it was fetched a dataset is out of
	// sync: old enough that a refresh is due.
	OutOfSyncAfter = 7 * 24 * time.Hour

	// StaleAfter is how long after it was fetched a dataset is stale: old
	// enough that what it says about the host should not be relied on.
	StaleAfter = 14 * 24 * time.Hour
)

// StateAt returns the state at now of a dataset fetched at fetched. Age is
// measured from the fetch and not from the date of the data, since a source
// that publishes rarely would otherwise read as stale straight after a fetch,
// with nothing the operator could do to clear it.
func StateAt(fetched, now time.Time) State {
	switch age := now.Sub(fetched); {
	case age > StaleAfter:
		return StateStale
	case age > OutOfSyncAfter:
		return StateOutOfSync
	default:
		return StateCurrent
	}
}

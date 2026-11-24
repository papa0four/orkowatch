// internal/fspath/real.go

package fspath

import "errors"

// Errors Real returns, for a caller to state in its own terms.
var (
	// ErrMissing means the directory, or one its path passes through, does
	// not exist or cannot be opened. The error that carries it reads as the
	// system's reason and unwraps to it.
	ErrMissing = errors.New("directory does not exist")

	// ErrDevicePath means the path is in a Windows extended-length or device
	// form, which names an entry without the normalization the comparison
	// rules rely on. No other platform returns it.
	ErrDevicePath = errors.New("extended-length or device path")
)

// missing is a directory that could not be resolved. It is ErrMissing to
// errors.Is and in every other respect the system's own error, so a caller
// that shows it shows why: that the directory is absent, or that the process
// may not read it.
type missing struct{ cause error }

func (m missing) Error() string        { return m.cause.Error() }
func (m missing) Unwrap() error        { return m.cause }
func (m missing) Is(target error) bool { return target == ErrMissing }

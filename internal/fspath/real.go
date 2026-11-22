// internal/fspath/real.go

package fspath

import "errors"

// Errors Real returns, for a caller to state in its own terms.
var (
	// ErrMissing means the directory, or one its path passes through, does
	// not exist or cannot be opened.
	ErrMissing = errors.New("directory does not exist")

	// ErrDevicePath means the path is in a Windows extended-length or device
	// form, which names an entry without the normalisation the comparison
	// rules rely on. No other platform returns it.
	ErrDevicePath = errors.New("extended-length or device path")
)

// internal/render/errwriter.go

package render

import (
	"fmt"
	"io"
)

// ErrWriter wraps an io.Writer and remembers the first write error, letting
// rendering code write unconditionally and report the error once. This is
// the same pattern bufio.Writer and text/tabwriter use internally. Exported
// so any package that owns a text renderer, not only this one, can share one
// implementation of the accumulate-first-error pattern.
type ErrWriter struct {
	w   io.Writer
	err error
}

// NewErrWriter returns an ErrWriter wrapping w.
func NewErrWriter(w io.Writer) *ErrWriter {
	return &ErrWriter{w: w}
}

// Write forwards p to the underlying writer unless a previous write failed,
// in which case it returns that error and writes nothing. It makes an
// ErrWriter usable wherever a renderer takes an io.Writer, so a caller that
// tracks the first error through ew can hand ew itself to such a renderer
// instead of writing around it.
func (ew *ErrWriter) Write(p []byte) (int, error) {
	if ew.err != nil {
		return 0, ew.err
	}
	n, err := ew.w.Write(p)
	ew.err = err
	return n, err
}

// Printf formats to the underlying writer unless a previous write failed,
// in which case it is a no-op.
func (ew *ErrWriter) Printf(format string, args ...any) {
	if ew.err != nil {
		return
	}
	_, ew.err = fmt.Fprintf(ew.w, format, args...)
}

// Err returns the first write error encountered, or nil if every write
// succeeded.
func (ew *ErrWriter) Err() error {
	return ew.err
}

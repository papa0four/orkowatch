// internal/render/tty.go

package render

import "os"

// StdoutIsTerminal reports whether standard output is attached to a
// character device. It is the single TTY detection point in the tree;
// commands combine it with their own verbose and report-file state to
// gate progress headers, and #35's progress display consumes this same
// seam.
func StdoutIsTerminal() bool {
	fileInfo, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fileInfo.Mode() & os.ModeCharDevice) != 0
}

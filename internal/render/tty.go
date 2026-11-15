// internal/render/tty.go

package render

import (
	"os"

	"github.com/charmbracelet/x/term"
)

// StdoutIsTerminal reports whether standard output is attached to a
// terminal. This file is the single TTY detection point in the tree;
// commands use it to choose between the live progress display, the results
// browser and plain output.
func StdoutIsTerminal() bool {
	return isTerminal(os.Stdout)
}

// StdinIsTerminal reports whether standard input is attached to a terminal,
// which is what makes it possible to ask the operator a question.
func StdinIsTerminal() bool {
	return isTerminal(os.Stdin)
}

// isTerminal asks the console or the terminal driver rather than testing for
// a character device, because the null device is one on every platform: a
// run redirected to it would otherwise open an interface that no key press
// can ever leave.
func isTerminal(f *os.File) bool {
	return term.IsTerminal(f.Fd())
}

// internal/render/tty.go

package render

import "os"

// StdoutIsTerminal reports whether standard output is attached to a
// character device. This file is the single TTY detection point in the
// tree; commands use it to choose between the live progress display and
// plain output.
func StdoutIsTerminal() bool {
	return isTerminal(os.Stdout)
}

// StdinIsTerminal reports whether standard input is attached to a character
// device, which is what makes it possible to ask the operator a question.
func StdinIsTerminal() bool {
	return isTerminal(os.Stdin)
}

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

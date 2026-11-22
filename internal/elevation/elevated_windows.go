//go:build windows

// internal/elevation/elevated_windows.go

package elevation

import "golang.org/x/sys/windows"

// Elevated reports whether the process holds an elevated token, where it can
// write anywhere and a mistake in what it trusts is a privileged one. It is
// the question for guarding a write, and errs toward yes: a token restricted
// from an elevated one still reports elevated.
func Elevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

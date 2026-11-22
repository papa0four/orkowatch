//go:build linux || darwin || freebsd || openbsd || netbsd

// internal/elevation/elevated_unix.go

package elevation

import "os"

// Elevated reports whether the process runs as root, where it can read and
// write anything and a mistake in what it trusts is a privileged one.
func Elevated() bool {
	return os.Geteuid() == rootID
}

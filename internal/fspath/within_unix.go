//go:build linux || darwin || freebsd || openbsd || netbsd

// internal/fspath/within_unix.go

package fspath

// fold returns path as it is compared: unchanged, since names differing in
// case are different names.
func fold(path string) string { return path }

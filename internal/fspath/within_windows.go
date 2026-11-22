//go:build windows

// internal/fspath/within_windows.go

package fspath

import (
	"path/filepath"
	"strings"
)

// fold returns path as it is compared: cleaned and in lower case, since
// Windows paths differing only in case name the same entry.
func fold(path string) string { return strings.ToLower(filepath.Clean(path)) }

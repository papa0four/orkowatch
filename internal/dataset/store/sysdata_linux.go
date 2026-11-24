//go:build linux

// internal/dataset/store/sysdata_linux.go

package store

// systemData is where Linux keeps the state of its programs, which hier(7)
// gives as /var/lib.
func systemData() (string, error) { return "/var/lib", nil }

//go:build darwin

// internal/dataset/store/sysdata_darwin.go

package store

// systemData is where macOS keeps what an application shares between users:
// Application Support in the Library of the system, not of an account.
func systemData() (string, error) { return "/Library/Application Support", nil }

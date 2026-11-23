//go:build darwin

// internal/dataset/store/root_darwin.go

package store

// underHome is the account's Application Support folder, where macOS puts an
// application's data.
var underHome = []string{"Library", "Application Support", "owatch", "datasets"}

//go:build linux || freebsd || openbsd || netbsd

// internal/dataset/store/root_xdg.go

package store

// underHome is where the XDG base directory layout puts an application's
// data, without the XDG_DATA_HOME that would move it.
var underHome = []string{".local", "share", "owatch", "datasets"}

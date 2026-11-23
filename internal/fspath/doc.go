// internal/fspath/doc.go

// Package fspath holds the rules more than one part of owatch applies to a
// path it does not trust: the real path of a directory, whether one path lies
// within another, creating a file only where nothing is, and opening one only
// when it is a regular file. They are kept in one place so a guard on where a
// file may be written and a check of what a scan covers cannot disagree about
// the same two paths, and so a link planted in the way of a write or a read
// is refused the same way wherever it is made.
package fspath

// internal/fspath/doc.go

// Package fspath holds the rules for comparing filesystem paths that more than
// one part of owatch judges by: the real path of a directory, and whether one
// path lies within another. They are kept in one place so a guard on where a
// file may be written and a check of what a scan covers cannot disagree about
// the same two paths.
package fspath

// internal/report/doc.go

// Package report writes scan and audit output to disk behind a guard pipeline:
// the destination is resolved against the real filesystem, protected locations
// are refused, and an elevated write into a directory other users can modify is
// refused unless the operator overrides it. It also generates report filenames and resolves a
// filename-safe host identifier.
package report

// internal/render/doc.go

// Package render provides the shared output machinery for owatch commands:
// parameterized text rendering for the blocks that appear in more than one
// command's output (finding lines, suppression disclosure, and summaries),
// and the single TTY detection helper. ErrWriter is exported so any package
// that owns a text renderer, not only this one, can share one implementation
// of the accumulate-first-error write pattern.
//
// Text rendering functions take data and an io.Writer only; the package has
// no dependency on cobra or on the audit engine. It defines no serialization
// types of its own -- a package that owns domain data (internal/osfingerprint,
// internal/security/enrichment) owns that data's serializable projection and
// its text renderer together, and calls into this package only for the
// generic verbs above.
package render

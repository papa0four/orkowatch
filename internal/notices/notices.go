// internal/notices/notices.go

// Package notices carries the third-party license notices for the data owatch
// bundles. MITRE's terms for ATT&CK and CWE grant a royalty-free license on
// the condition that any copy reproduces MITRE's copyright designation and the
// license, so the notices are embedded in the binary: a bare copy of the
// binary carries them, and owatch notices prints them. NIST's catalog is in the
// public domain and is credited alongside.
package notices

import _ "embed"

//go:embed THIRD_PARTY_NOTICES.md
var text string

// Text returns the third-party notices as published in the repository.
func Text() string {
	return text
}

// internal/security/checker/doc.go

// Package checker implements the individual security checks -- firewall, file
// permissions, SSH configuration, and user accounts -- with a Unix and a
// Windows variant of each. Checks emit findings by key against the registry
// rather than constructing finding text themselves, keeping detection logic
// separable from finding content.
package checker

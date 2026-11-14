// internal/security/checker/identity.go

package checker

import "github.com/papa0four/orkowatch/internal/security/registry"

// checkIdentity names a check for display, deriving the platform label from
// the host context. Embedding it satisfies the Name and Description methods
// of the checker interfaces
type checkIdentity struct {
	domain   string
	analyzes string
	osCtx    registry.OSContext
}

// Name returns the check's platform-qualified display name.
func (c checkIdentity) Name() string {
	return c.osCtx.DisplayLabel() + " " + c.domain
}

// Description returns what the check analyzes.
func (c checkIdentity) Description() string {
	return "Analyzing " + c.osCtx.DisplayLabel() + " " + c.analyzes
}

// internal/security/checker/users.go

package checker

import (
	"context"

	"github.com/papa0four/orkowatch/internal/security/types"
)

// UserChecker is the user account check as the audit sees it. Each platform
// supplies NewUserChecker under its own build constraint.
type UserChecker interface {
	Name() string
	Description() string
	Check(ctx context.Context) types.AuditResult
}

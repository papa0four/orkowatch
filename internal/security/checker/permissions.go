// internal/security/checker/permissions.go

package checker

import (
	"context"

	"github.com/papa0four/orkowatch/internal/security/types"
)

// PermissionChecker is the file permission check as the audit sees it. Each
// platform supplies NewPermissionChecker under its own build constraint.
// Check honors ctx cancellation: exec invocations and filesystem walks stop
// when the caller's deadline expires.
type PermissionChecker interface {
	Name() string
	Description() string
	Check(ctx context.Context) types.AuditResult
}

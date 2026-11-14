// internal/security/checker/permissions.go

package checker

import (
	"context"

	"github.com/papa0four/orkowatch/internal/security/finding"
)

// scanWorkers is how many directories a filesystem scan reads at once. The
// scan waits on the operating system far more than it computes, so the gain
// comes from overlapping those waits and not from using every core: measured
// on both reference machines, four to eight workers cut the scan to about a
// third of its single-worker time, and more than eight made it slower again.
const scanWorkers = 8

// PermissionChecker is the file permission check as the audit sees it. Each
// platform supplies NewPermissionChecker under its own build constraint.
// Check honors ctx cancellation: exec invocations and filesystem walks stop
// when the caller's deadline expires.
type PermissionChecker interface {
	Name() string
	Description() string
	Check(ctx context.Context) finding.AuditResult
}

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

// progressStep is how many entries a filesystem scan reads between progress
// reports: often enough to show a long scan is alive, rarely enough that
// reporting costs nothing against the scan itself.
const progressStep = 25000

// ScanProgress is told how many entries a filesystem scan has read so far.
// It is called from one goroutine at a time.
type ScanProgress func(scanned int)

// scanCounter counts the entries a scan reads and reports the running total
// each time it crosses another progressStep, and once more at the end.
type scanCounter struct {
	report   ScanProgress
	scanned  int
	reported int
}

// add counts n more entries. It is called from the traversal's collector,
// which runs on one goroutine at a time.
func (c *scanCounter) add(n int) {
	c.scanned += n
	if c.report != nil && c.scanned-c.reported >= progressStep {
		c.reported = c.scanned
		c.report(c.scanned)
	}
}

// finish reports the final total.
func (c *scanCounter) finish() {
	if c.report != nil {
		c.report(c.scanned)
	}
}

// PermissionChecker is the file permission check as the audit sees it. Each
// platform supplies NewPermissionChecker under its own build constraint.
// Check honors ctx cancellation: exec invocations and filesystem walks stop
// when the caller's deadline expires.
type PermissionChecker interface {
	Name() string
	Description() string
	Check(ctx context.Context) finding.AuditResult
}

//go:build darwin

// internal/security/checker/permissions_darwin.go

package checker

import (
	"bytes"
	"context"
	"os/exec"
	"strconv"
)

// platformCriticalPaths lists the paths macOS adds to the common set.
func platformCriticalPaths() []criticalPath {
	return []criticalPath{
		{"/private/etc", "System configuration directory", permStandardDir},
		{"/System", "System directory", permStandardDir},
		{"/usr/local/bin", "User-installed binaries", permStandardDir},
	}
}

// nameServiceKnows asks Directory Services about a single identifier.
// dscacheutil reports absence through empty output rather than its exit
// status, so both conditions are treated as unresolved.
func nameServiceKnows(ctx context.Context, kind identityKind, id uint32) bool {
	value := strconv.FormatUint(uint64(id), decimalBase)
	cmd := exec.CommandContext(ctx, "dscacheutil", "-q", string(kind), "-a", string(kind)+"id", value) // #nosec G204 -- command is fixed and the sole variable argument is a numeric identifier read from the filesystem
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	return len(bytes.TrimSpace(out)) > 0
}

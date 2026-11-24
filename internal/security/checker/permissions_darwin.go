//go:build darwin

// internal/security/checker/permissions_darwin.go

package checker

import (
	"bytes"
	"context"
	"os/exec"

	"github.com/papa0four/orkowatch/internal/account"
)

// platformLocations adds none: macOS keeps home directories under /Users and
// temporary files under /private, which have not been verified on a macOS
// host here.
func platformLocations() []pathLocation { return nil }

// criticalPaths lists the common paths and the ones macOS adds.
func criticalPaths() []criticalPath {
	return append(commonCriticalPaths(),
		criticalPath{"/private/etc", "System configuration directory", permStandardDir},
		criticalPath{"/System", "System directory", permStandardDir},
		criticalPath{"/usr/local/bin", "User-installed binaries", permStandardDir},
	)
}

// nameServiceKnows asks Directory Services about a single identifier.
// dscacheutil reports absence through empty output rather than its exit
// status, so both conditions are treated as unresolved.
func nameServiceKnows(ctx context.Context, kind identityKind, id uint32) bool {
	cmd := exec.CommandContext(ctx, "dscacheutil", "-q", string(kind), "-a", string(kind)+"id", account.FormatID(id)) // #nosec G204 -- command is fixed and the sole variable argument is a numeric identifier read from the filesystem
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	return len(bytes.TrimSpace(out)) > 0
}

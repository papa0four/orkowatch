//go:build windows

// internal/security/checker/permissions_windows.go

package checker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/papa0four/orkowatch/internal/security/registry"
	"github.com/papa0four/orkowatch/internal/security/types"
)

type (
	// WindowsPermissionChecker implements PermissionChecker for Windows systems
	WindowsPermissionChecker struct {
		checkIdentity
		Paths    []string
		scanRoot string
	}
)

// appendSkippedNote annotates the number of paths find could not read
func appendSkippedNote(result *types.AuditResult, scan string, skipped int) {
	if skipped <= 0 {
		return
	}
	result.Details = append(result.Details,
		fmt.Sprintf("%s %s: %d unreadable paths skipped (run with elevated privileges for complete coverage)",
			types.SymbolInfo, scan, skipped))
}

// NewPermissionChecker returns the file permission checker for Windows
// hosts. scanRoot narrows the ACL traversal to one tree; empty means the
// default system paths and the share listing.
func NewPermissionChecker(osCtx registry.OSContext, scanRoot string) *WindowsPermissionChecker {
	return &WindowsPermissionChecker{
		checkIdentity: checkIdentity{
			domain:   "File Permissions Security",
			analyzes: "file and directory permissions",
			osCtx:    osCtx,
		},
		Paths: []string{
			"C:\\Windows\\System32",
			"C:\\Program Files",
			"C:\\Program Files (x86)",
			"C:\\ProgramData",
			"C:\\Users",
		},
		scanRoot: scanRoot,
	}
}

// Check implements PermissionChecker interface for Windows systems
func (p *WindowsPermissionChecker) Check(ctx context.Context) types.AuditResult {
	result := types.AuditResult{
		Name:        p.Name(),
		Status:      types.StatusChecking,
		Description: p.Description(),
		Details:     make([]string, 0),
		Findings:    make([]types.Finding, 0),
	}

	seen := make(map[registry.FindingKey]struct{})

	if p.scanRoot != "" {
		result.Details = append(result.Details,
			fmt.Sprintf("%s Scanning %s", types.SymbolInfo, p.scanRoot))
		if err := p.checkWindowsPermissions(ctx, p.scanRoot, true, &result, seen); err != nil {
			result.Details = append(result.Details,
				fmt.Sprintf("%s Error checking %s: %v",
					types.SymbolError, p.scanRoot, err))
		}
	} else {
		result.Details = append(result.Details,
			fmt.Sprintf("%s Scanning %d default system paths",
				types.SymbolInfo, len(p.Paths)))
		for _, path := range p.Paths {
			if err := p.checkWindowsPermissions(ctx, path, false, &result, seen); err != nil {
				result.Details = append(result.Details,
					fmt.Sprintf("%s Error checking %s: %v",
						types.SymbolError, path, err))
			}
		}
	}

	// Shares are a host-wide condition rather than a property of the scanned
	// tree, so they are enumerated whether or not a path narrowed the run.
	p.checkNetworkShares(ctx, &result, seen)

	result.Status = types.StatusCompleted
	return result
}


// checkWindowsPermissions reports the ACL grants on one path. seen spans the
// whole check rather than one path, because a definition describes the
// condition rather than the path that carries it, so a grant found on several
// paths is one finding with several detail lines.
func (p *WindowsPermissionChecker) checkWindowsPermissions(ctx context.Context, path string, recursive bool, result *types.AuditResult, seen map[registry.FindingKey]struct{}) error {
	const scan string = "ACL traversal"
	output, skipped, err := runICACLS(ctx, path, recursive)
	if err != nil {
		return fmt.Errorf("failed to check permissions: %w", err)
	}

	// Analyze permissions
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.Contains(line, "Everyone:(OI)(CI)(F)") ||
			strings.Contains(line, "Everyone:(F)") {
			result.Details = append(result.Details,
				fmt.Sprintf("%s WARNING: Full control granted to Everyone group on %s",
					types.SymbolWarning, line))
			emitFindingOnce(result, p.osCtx, "permissions.everyone_full_control", seen)
		} else if strings.Contains(line, "Users:(OI)(CI)(F)") ||
			strings.Contains(line, "Users:(F)") {
			result.Details = append(result.Details,
				fmt.Sprintf("%s WARNING: Full control granted to Users group on %s",
					types.SymbolWarning, line))
			emitFindingOnce(result, p.osCtx, "permissions.users_full_control", seen)
		} else {
			result.Details = append(result.Details,
				fmt.Sprintf("%s %s", types.SymbolInfo, line))
		}
	}

	appendSkippedNote(result, scan, skipped)
	return nil
}

func (p *WindowsPermissionChecker) checkNetworkShares(ctx context.Context, result *types.AuditResult, seen map[registry.FindingKey]struct{}) {
	cmd := exec.CommandContext(ctx, "net", "share")
	output, err := cmd.Output()
	if err != nil {
		result.Details = append(result.Details,
			fmt.Sprintf("%s Error checking network shares: %v",
				types.SymbolError, err))
		return
	}

	shares := strings.Split(string(output), "\n")
	result.Details = append(result.Details, "", "Network Shares:")

	for _, share := range shares {
		share = strings.TrimSpace(share)
		if share == "" || strings.HasPrefix(share, "Share name") ||
			strings.HasPrefix(share, "---") {
			continue
		}

		shareName := strings.Fields(share)[0]
		if shareName == "ADMIN$" || shareName == "C$" || shareName == "IPC$" {
			result.Details = append(result.Details,
				fmt.Sprintf("%s Administrative share: %s",
					types.SymbolWarning, share))
			emitFindingOnce(result, p.osCtx, "permissions.admin_share_present", seen)
		} else {
			result.Details = append(result.Details,
				fmt.Sprintf("%s %s", types.SymbolInfo, share))
		}
	}
}

// runICACLS executes against the given path with optional recursion for tree
// traversal. ctx bounds the invocation; icacls /T over a large tree is the
// slowest operation in the Windows permission path.
func runICACLS(ctx context.Context, path string, recursive bool) (output []byte, skipped int, err error) {
	args := []string{path}
	if recursive {
		args = append(args, "/T")
	}
	cmd := exec.CommandContext(ctx, "icacls", args...) // #nosec G204 -- path validated by caller; flags are fixed literals

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()

	// icacls exits nonzero when any subtree entry is denied while still
	// emitting valid ACL lines for everything it could read. An ExitError is
	// therefore deliberately tolerated: partial output plus the denied-path
	// count is the correct result, and only non-exit failures (binary
	// missing, ctx kill) abort.
	var exitErr *exec.ExitError
	if runErr != nil && !errors.As(runErr, &exitErr) {
		return nil, 0, runErr
	}

	return stdout.Bytes(), countDeniedPaths(stderr.Bytes()), nil
}

// countDeniedPaths counts the paths icacls could not access
func countDeniedPaths(stderr []byte) int {
	if len(stderr) == 0 {
		return 0
	}
	count := 0
	for _, line := range strings.Split(string(stderr), "\n") {
		if strings.Contains(line, "Access is denied") {
			count++
		}
	}
	return count
}

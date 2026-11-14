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

	"github.com/papa0four/orkowatch/internal/security/finding"
	"github.com/papa0four/orkowatch/internal/security/registry"
)

type (
	// WindowsPermissionChecker implements PermissionChecker for Windows systems
	WindowsPermissionChecker struct {
		checkIdentity
		paths    []string
		scanRoot string
	}
)

// The rules this check concludes: two judged on access control entries, one
// on the share listing.
const (
	ruleEveryoneFull registry.FindingKey = "permissions.everyone_full_control"
	ruleUsersFull    registry.FindingKey = "permissions.users_full_control"
	ruleAdminShare   registry.FindingKey = "permissions.admin_share_present"
)

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
		paths: []string{
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
func (p *WindowsPermissionChecker) Check(ctx context.Context) finding.AuditResult {
	r := newReport(p.checkIdentity)

	paths, recursive := p.paths, false
	if p.scanRoot != "" {
		paths, recursive = []string{p.scanRoot}, true
		r.note(finding.SymbolInfo, "Scanning %s", p.scanRoot)
	} else {
		r.note(finding.SymbolInfo, "Scanning %d default system paths", len(p.paths))
	}

	for _, path := range paths {
		p.checkWindowsPermissions(ctx, path, recursive, r)
	}
	r.pass(ruleEveryoneFull, ruleUsersFull)

	// Shares are a host-wide condition rather than a property of the scanned
	// tree, so they are enumerated whether or not a path narrowed the run.
	p.checkNetworkShares(ctx, r)

	return r.finish()
}

// checkWindowsPermissions records the full-control grants on one path. A
// grant found on several paths is one failed rule with several pieces of
// evidence, because a definition describes the condition rather than the
// path that carries it. A path that could not be read, in whole or in part,
// leaves both rules in error unless something already failed them: entries
// nobody examined prove nothing.
func (p *WindowsPermissionChecker) checkWindowsPermissions(ctx context.Context, path string, recursive bool, r *report) {
	output, skipped, err := runICACLS(ctx, path, recursive)
	if err != nil {
		r.inconclusive(finding.ResultError, fmt.Sprintf("permissions on %s could not be read: %v", path, err),
			ruleEveryoneFull, ruleUsersFull)
		return
	}

	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "":
		case strings.Contains(line, "Everyone:(OI)(CI)(F)"), strings.Contains(line, "Everyone:(F)"):
			r.observed(ruleEveryoneFull, evidence(kindACL, line, "principal", "Everyone", "access", "full control"))
		case strings.Contains(line, "Users:(OI)(CI)(F)"), strings.Contains(line, "Users:(F)"):
			r.observed(ruleUsersFull, evidence(kindACL, line, "principal", "Users", "access", "full control"))
		default:
			r.note(finding.SymbolInfo, "%s", line)
		}
	}

	if skipped > 0 {
		reason := fmt.Sprintf("%d paths under %s were unreadable and went unscanned; rerun with elevated privileges for complete coverage",
			skipped, path)
		r.inconclusive(finding.ResultError, reason, ruleEveryoneFull, ruleUsersFull)
		r.note(finding.SymbolWarning, "%s", reason)
	}
}

// checkNetworkShares concludes the administrative share rule and narrates
// the other shares the host exports.
func (p *WindowsPermissionChecker) checkNetworkShares(ctx context.Context, r *report) {
	output, err := exec.CommandContext(ctx, "net", "share").Output()
	if err != nil {
		r.inconclusive(finding.ResultError,
			fmt.Sprintf("network shares could not be listed: %v", execError(err)), ruleAdminShare)
		return
	}

	r.section("Network Shares:")
	for _, share := range strings.Split(string(output), "\n") {
		share = strings.TrimSpace(share)
		if share == "" || strings.HasPrefix(share, "Share name") ||
			strings.HasPrefix(share, "---") {
			continue
		}

		switch name := strings.Fields(share)[0]; name {
		case "ADMIN$", "C$", "IPC$":
			r.observed(ruleAdminShare, evidence(kindShare, name, "listing", share))
		default:
			r.note(finding.SymbolInfo, "%s", share)
		}
	}
	r.pass(ruleAdminShare)
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

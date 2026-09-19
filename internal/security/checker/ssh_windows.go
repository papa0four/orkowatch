//go:build windows

// internal/security/checker/ssh_windows.go

package checker

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/papa0four/orkowatch/internal/security/registry"
	"github.com/papa0four/orkowatch/internal/security/types"
)

// sshdCOnfigPath is where the OpenSSH Server feature reads its configuration.
const sshdConfigPath = `C:\ProgramData\ssh\sshd_config`

// WindowsSSHChecker implements SSHChecker for Windows systems
type WindowsSSHChecker struct {
	checkIdentity
}

// NewSSHChecker returns the SSH Configuration checker for Windows hosts.
func NewSSHChecker(osCtx registry.OSContext) *WindowsSSHChecker {
	return &WindowsSSHChecker{checkIdentity: checkIdentity{
		domain:   "SSH Configuration",
		analyzes: "SSH configuration and security settings",
		osCtx:    osCtx,
	}}
}

// Check implements SSHChecker interface for Windows systems. A configuration
// that cannot be read is recorded but does not end the check: the server's
// presence and PuTTY's are still worth reporting, and Windows defines no
// finding for an unset directive, so the zero sshdAbsentKeys is passed.
func (s *WindowsSSHChecker) Check(ctx context.Context) types.AuditResult {
	result := types.AuditResult{
		Name:        s.Name(),
		Status:      types.StatusChecking,
		Description: s.Description(),
		Details:     make([]string, 0),
		Findings:    make([]types.Finding, 0),
	}

	if s.reportSSHDPresence(ctx, &result) {
		_ = checkSSHDConfig(&result, s.osCtx, sshdConfigPath, sshdAbsentKeys{}) //nolint:errcheck // the failure is already recorded in result and does not end the check
	}
	s.checkPuTTY(ctx, &result)

	result.Status = types.StatusCompleted
	return result
}

// reportSSHDPresence records whether the OpenSSH server is present and, when a
// service is registered, its state. The binary isa fallback for hosts where
// the server is installed but the service is not registered. It reports whether
// the configuration is worth reading.
func (s *WindowsSSHChecker) reportSSHDPresence(ctx context.Context, result *types.AuditResult) bool {
	const sshdBinaryPath = `C:\Windows\System32\OpenSSH\sshd.exe`

	output, err := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		"(Get-Service -Name sshd -ErrorAction SilentlyContinue).Status").Output()
	if serviceStatus := strings.TrimSpace(string(output)); err == nil && serviceStatus != "" {
		switch serviceStatus {
		case "Running":
			result.Details = append(result.Details,
				fmt.Sprintf("%s OpenSSH Server is installed and running", types.SymbolOK))
		case "Stopped":
			result.Details = append(result.Details,
				fmt.Sprintf("%s OpenSSH Server is installed but not running", types.SymbolWarning))
			emitFinding(result, s.osCtx, "ssh.server_not_ruinning")
		default:
			result.Details = append(result.Details,
				fmt.Sprintf("%s OpenSSH Server service state: %s", types.SymbolInfo, serviceStatus))
		}
		return true
	}

	if _, err := os.Stat(sshdBinaryPath); err == nil {
		result.Details = append(result.Details,
			fmt.Sprintf("%s OpenSSH binary found (service not detected)", types.SymbolInfo))
		return true
	}

	result.Details = append(result.Details,
		fmt.Sprintf("%s OpenSSH Server is not installed", types.SymbolInfo))
	return false
}

// checkPuTTY records PuTTY's presence and any saved sessions. Both are
// informational context for an operator rather than findings.
func (s *WindowsSSHChecker) checkPuTTY(ctx context.Context, result *types.AuditResult) {
	const (
		puttyBinaryPath  = `C:\Program Files\PuTTY\putty.exe`
		puttySessionsKey = `HKCU\Software\SimonTatham\PuTTY\Sessions`
	)

	if _, err := os.Stat(puttyBinaryPath); err != nil {
		return
	}

	result.Details = append(result.Details,
		fmt.Sprintf("%s PuTTY is installed", types.SymbolInfo))

	output, err := exec.CommandContext(ctx, "reg", "query", puttySessionsKey).Output()
	if err != nil || len(output) == 0 {
		return
	}

	result.Details = append(result.Details,
		fmt.Sprintf("%s PuTTY configured sessions:", types.SymbolInfo))
	for _, session := range strings.Split(string(output), "\n") {
		if name := strings.TrimSpace(session); name != "" {
			result.Details = append(result.Details, fmt.Sprintf(" - %s", name))
		}
	}
}

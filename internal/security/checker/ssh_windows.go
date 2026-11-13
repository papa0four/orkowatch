//go:build windows

// internal/security/checker/ssh_windows.go

package checker

import (
	"context"
	"os"
	"os/exec"
	"strings"

	"github.com/papa0four/orkowatch/internal/security/registry"
	"github.com/papa0four/orkowatch/internal/security/types"
)

// sshdConfigPath is where the OpenSSH Server feature reads its configuration.
const sshdConfigPath = `C:\ProgramData\ssh\sshd_config`

// WindowsSSHChecker implements SSHChecker for Windows systems
type WindowsSSHChecker struct {
	checkIdentity
}

// NewSSHChecker returns the SSH configuration checker for Windows hosts.
func NewSSHChecker(osCtx registry.OSContext) *WindowsSSHChecker {
	return &WindowsSSHChecker{checkIdentity: checkIdentity{
		domain:   "SSH Configuration",
		analyzes: "SSH configuration and security settings",
		osCtx:    osCtx,
	}}
}

// Check implements SSHChecker interface for Windows systems. A host without
// the OpenSSH server has nothing for the server rules to apply to. Windows
// defines no rule for an unset directive, so the zero sshdAbsentKeys is
// passed.
func (s *WindowsSSHChecker) Check(ctx context.Context) types.AuditResult {
	r := newReport(s.checkIdentity)

	if s.reportSSHDPresence(ctx, r) {
		checkSSHDConfig(r, sshdConfigPath, sshdAbsentKeys{})
	} else {
		r.inconclusive(types.ResultNotApplicable, "OpenSSH Server is not installed",
			"ssh.server_not_running", "ssh.config_not_found",
			"ssh.root_login_permitted", "ssh.password_auth_enabled")
	}
	s.checkPuTTY(ctx, r)

	return r.finish()
}

// reportSSHDPresence concludes whether the OpenSSH server is running and
// reports whether it is present at all, which is whether the configuration is
// worth reading. The binary is a fallback for hosts where the server is
// installed but the service is not registered.
func (s *WindowsSSHChecker) reportSSHDPresence(ctx context.Context, r *report) bool {
	const (
		sshdBinaryPath = `C:\Windows\System32\OpenSSH\sshd.exe`
		serviceRule    = "ssh.server_not_running"
	)

	output, err := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		"(Get-Service -Name sshd -ErrorAction SilentlyContinue).Status").Output()
	if serviceStatus := strings.TrimSpace(string(output)); err == nil && serviceStatus != "" {
		switch serviceStatus {
		case "Running":
			r.pass(serviceRule)
		case "Stopped":
			r.observed(serviceRule, evidence(kindService, "sshd", "status", serviceStatus))
		default:
			r.inconclusive(types.ResultUnknown, "OpenSSH Server service state is "+serviceStatus, serviceRule)
		}
		return true
	}

	if _, err := os.Stat(sshdBinaryPath); err == nil {
		r.inconclusive(types.ResultNotChecked,
			"OpenSSH Server binary found but no sshd service is registered", serviceRule)
		return true
	}

	return false
}

// checkPuTTY records PuTTY presence and any saved sessions. Both are context
// for an operator rather than the outcome of a rule.
func (s *WindowsSSHChecker) checkPuTTY(ctx context.Context, r *report) {
	const (
		puttyBinaryPath  = `C:\Program Files\PuTTY\putty.exe`
		puttySessionsKey = `HKCU\Software\SimonTatham\PuTTY\Sessions`
	)

	if _, err := os.Stat(puttyBinaryPath); err != nil {
		return
	}

	r.note(types.SymbolInfo, "PuTTY is installed")

	output, err := exec.CommandContext(ctx, "reg", "query", puttySessionsKey).Output()
	if err != nil || len(output) == 0 {
		return
	}

	r.note(types.SymbolInfo, "PuTTY configured sessions:")
	for _, session := range strings.Split(string(output), "\n") {
		if name := strings.TrimSpace(session); name != "" {
			r.lines(" - " + name)
		}
	}
}

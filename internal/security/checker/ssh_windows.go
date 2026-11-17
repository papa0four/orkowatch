//go:build windows

// internal/security/checker/ssh_windows.go

package checker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/papa0four/orkowatch/internal/security/finding"
	"github.com/papa0four/orkowatch/internal/security/registry"
	"github.com/papa0four/orkowatch/internal/winfolder"
)

// The rules the Windows SSH check concludes.
const (
	ruleSSHDNotRunning registry.FindingKey = "ssh.server_not_running"
	ruleSSHDNoConfig   registry.FindingKey = "ssh.config_not_found"
	ruleSSHRootLogin   registry.FindingKey = "ssh.root_login_permitted"
	ruleSSHPassword    registry.FindingKey = "ssh.password_auth_enabled"
)

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
// the OpenSSH server has nothing for the server rules to apply to, and one
// whose server could not be looked for is not said to lack it. The server
// reads its configuration from the ssh folder under ProgramData, wherever
// Windows has put that folder. Windows defines no rule for an unset
// directive, so the zero sshdAbsentKeys is passed.
func (s *WindowsSSHChecker) Check(ctx context.Context) finding.AuditResult {
	r := newReport(s.checkIdentity)

	present, err := s.reportSSHDPresence(ctx, r)
	switch {
	case err != nil:
		r.inconclusive(finding.ResultError, err.Error(), ruleSSHDNotRunning, ruleSSHDNoConfig, ruleSSHRootLogin, ruleSSHPassword)
	case !present:
		r.inconclusive(finding.ResultNotApplicable, "OpenSSH Server is not installed",
			ruleSSHDNotRunning, ruleSSHDNoConfig, ruleSSHRootLogin, ruleSSHPassword)
	default:
		if config, err := winfolder.ProgramData.Path("ssh", "sshd_config"); err != nil {
			r.inconclusive(finding.ResultError, "OpenSSH configuration could not be located: "+err.Error(),
				ruleSSHDNoConfig, ruleSSHRootLogin, ruleSSHPassword)
		} else {
			checkSSHDConfig(r, config, sshdAbsentKeys{})
		}
	}
	s.checkPuTTY(ctx, r)

	return r.finish()
}

// reportSSHDPresence concludes whether the OpenSSH server is running and
// reports whether it is present at all, which is whether the configuration is
// worth reading. The binary, in the OpenSSH folder under System, is a fallback
// for hosts where the server is installed but the service is not registered.
// An error means neither could be looked for.
func (s *WindowsSSHChecker) reportSSHDPresence(ctx context.Context, r *report) (bool, error) {
	output, err := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		"(Get-Service -Name sshd -ErrorAction SilentlyContinue).Status").Output()
	if serviceStatus := strings.TrimSpace(string(output)); err == nil && serviceStatus != "" {
		switch serviceStatus {
		case "Running":
			r.pass(ruleSSHDNotRunning)
		case "Stopped":
			r.observed(ruleSSHDNotRunning, evidence(finding.KindService, "sshd", fact(finding.FactStatus, serviceStatus)))
		default:
			r.inconclusive(finding.ResultUnknown, "OpenSSH Server service state is "+serviceStatus, ruleSSHDNotRunning)
		}
		return true, nil
	}

	binary, pathErr := winfolder.System.Path("OpenSSH", "sshd.exe")
	if pathErr != nil {
		return false, fmt.Errorf("OpenSSH Server presence could not be determined: %w", pathErr)
	}
	switch _, err := os.Stat(binary); {
	case err == nil:
		r.inconclusive(finding.ResultNotChecked,
			"OpenSSH Server binary found but no sshd service is registered", ruleSSHDNotRunning)
		return true, nil
	case errors.Is(err, os.ErrNotExist):
		return false, nil
	default:
		return false, fmt.Errorf("OpenSSH Server presence could not be determined: %w", err)
	}
}

// checkPuTTY records PuTTY presence and any saved sessions. Both are context
// for an operator rather than the outcome of a rule. PuTTY is looked for in
// both program folders, because its 32-bit installer uses the x86 one.
func (s *WindowsSSHChecker) checkPuTTY(ctx context.Context, r *report) {
	const puttySessionsKey = `HKCU\Software\SimonTatham\PuTTY\Sessions`

	installed := false
	for _, folder := range []winfolder.Folder{winfolder.ProgramFiles, winfolder.ProgramFilesX86} {
		binary, err := folder.Path("PuTTY", "putty.exe")
		if err != nil {
			r.note(finding.SymbolWarning, "PuTTY was not looked for in %s: %v", folder.Name(), err)
			continue
		}
		if _, err := os.Stat(binary); err == nil {
			installed = true
		}
	}
	if !installed {
		return
	}

	r.note(finding.SymbolInfo, "PuTTY is installed")

	output, err := exec.CommandContext(ctx, "reg", "query", puttySessionsKey).Output()
	if err != nil || len(output) == 0 {
		return
	}

	r.note(finding.SymbolInfo, "PuTTY configured sessions:")
	for _, session := range strings.Split(string(output), "\n") {
		if name := strings.TrimSpace(session); name != "" {
			r.lines(" - " + name)
		}
	}
}

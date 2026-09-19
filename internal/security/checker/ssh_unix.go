//go:build linux || darwin || freebsd || openbsd || netbsd

// internal/security/checker/ssh_unix.go

package checker

import (
	"context"

	"github.com/papa0four/orkowatch/internal/security/registry"
	"github.com/papa0four/orkowatch/internal/security/types"
)

// sshdConfigPath is where OpenSSH reads its server configuration on every
// Unix-like platform; macOS resolves it through the /private symlink.
const sshdConfigPath = "/etc/ssh/sshd_config"

// UnixSSHChecker implements SSHChecker for Unix-like systems
type UnixSSHChecker struct {
	checkIdentity
}

// NewSSHChecker returns the SSH configuration checker for Unix-Like hosts.
func NewSSHChecker(osCtx registry.OSContext) *UnixSSHChecker {
	return &UnixSSHChecker{checkIdentity: checkIdentity{
		domain:   "SSH Configuration",
		analyzes: "SSH configuration and security settings",
		osCtx:    osCtx,
	}}
}

// Check implements SSHChecker interface for Unix systems
func (s *UnixSSHChecker) Check(_ context.Context) types.AuditResult {
	result := types.AuditResult{
		Name:        s.Name(),
		Status:      types.StatusChecking,
		Description: s.Description(),
		Details:     make([]string, 0),
		Findings:    make([]types.Finding, 0),
	}

	absent := sshdAbsentKeys{
		rootLogin:    "ssh.permit_root_login_not_set",
		passwordAuth: "ssh.password_auth_not_set",
	}
	if err := checkSSHDConfig(&result, s.osCtx, sshdConfigPath, absent); err != nil {
		result.Status = types.StatusError
		result.Description = err.Error()
		return result
	}

	result.Status = types.StatusCompleted
	return result
}

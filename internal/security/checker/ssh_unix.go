//go:build linux || darwin || freebsd || openbsd || netbsd

// internal/security/checker/ssh_unix.go

package checker

import (
	"context"

	"github.com/papa0four/orkowatch/internal/security/finding"
	"github.com/papa0four/orkowatch/internal/security/registry"
)

// sshdConfigPath is where OpenSSH reads its server configuration on every
// Unix-like platform; macOS resolves it through the /private symlink.
const sshdConfigPath = "/etc/ssh/sshd_config"

// UnixSSHChecker implements SSHChecker for Unix-like systems. listeners
// returns the host's sockets, from which where sshd listens is recorded.
type UnixSSHChecker struct {
	checkIdentity
	listeners ListenersFunc
}

// NewSSHChecker returns the SSH configuration checker for Unix-like hosts.
func NewSSHChecker(osCtx registry.OSContext, listeners ListenersFunc) *UnixSSHChecker {
	return &UnixSSHChecker{
		checkIdentity: checkIdentity{
			domain:   "SSH Configuration",
			analyzes: "SSH configuration and security settings",
			osCtx:    osCtx,
		},
		listeners: listeners,
	}
}

// Check implements SSHChecker interface for Unix systems
func (s *UnixSSHChecker) Check(ctx context.Context) finding.AuditResult {
	r := newReport(s.checkIdentity)
	checkSSHDConfig(ctx, r, sshdConfigPath, sshdAbsentKeys{
		rootLogin:    "ssh.permit_root_login_not_set",
		passwordAuth: "ssh.password_auth_not_set",
	}, s.listeners(ctx))
	return r.finish()
}

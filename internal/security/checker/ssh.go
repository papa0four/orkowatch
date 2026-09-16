// internal/security/checker/ssh.go

package checker

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/papa0four/orkowatch/internal/security/registry"
	"github.com/papa0four/orkowatch/internal/security/types"
)

type (
	// SSHChecker defines interface for SSH configuration checking
	SSHChecker interface {
		Name() string
		Description() string
		Check(ctx context.Context) types.AuditResult
	}

	// UnixSSHChecker implements SSHChecker for Unix-like systems
	UnixSSHChecker struct {
		checkIdentity
		ConfigPaths []string
	}

	// WindowsSSHChecker implements SSHChecker for Windows systems
	WindowsSSHChecker struct {
		checkIdentity
		ConfigPath string
	}

	// sshConfig holds parsed SSH configuration settings
	sshConfig struct {
		rootLogin         bool
		passwordAuth      bool
		permRootFound     bool
		permPasswordFound bool
	}

	// sshDirective describes one boolean sshd_config directive for reporting.
	//absentDetail and absentKey are empty on platforms with no finding defined
	// for the directive being unset, in which case its absence is not reported.
	sshDirective struct {
		found        bool
		unsafe       bool
		unsafeDetail string
		safeDetail   string
		absentDetail string
		unsafeKey    registry.FindingKey
		absentKey    registry.FindingKey
	}
)

// sshDirectiveField is the minimum whitespace-separated fields in a usable
// sshd_config  line: the directive and its value.
const sshDirectiveField = 2

// parseSSHDConfig reads an sshd_config stream, recording the two directives the
// audit evaluates. Comments, blank lines, and every other directive are ignored.
// The found flags let a caller distinguish an explicit setting from an absent
// one, which warrant different findings because sshd applies its own defaults
// to what the file does not say. Partial results are returned alongside a read
// error so a truncated file still reports what it did contain.
func parseSSHDConfig(r io.Reader) (sshConfig, error) {
	var config sshConfig

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < sshDirectiveField {
			continue
		}

		switch fields[0] {
		case "PermitRootLogin":
			config.permRootFound = true
			config.rootLogin = fields[1] != "no"
		case "PasswordAuthentication":
			config.permPasswordFound = true
			config.passwordAuth = fields[1] == "yes"
		}
	}

	return config, scanner.Err()
}

// reportSSHDirective records a directive's state and emit the matching
// finding. An absent directive is a third condition rather than a variant of
// either value, because sshd applies its own default to what the file does not
// say, and that default is not visible in the configuration being audited.
func reportSSHDirective(result *types.AuditResult, osCtx registry.OSContext, d sshDirective) {
	switch {
	case !d.found:
		if d.absentDetail == "" {
			return
		}
		result.Details = append(result.Details,
			fmt.Sprintf("%s %s", types.SymbolWarning, d.absentDetail))
		emitFinding(result, osCtx, d.absentKey)
	case d.unsafe:
		result.Details = append(result.Details,
			fmt.Sprintf("%s %s", types.SymbolWarning, d.unsafeDetail))
		emitFinding(result, osCtx, d.unsafeKey)
	default:
		result.Details = append(result.Details,
			fmt.Sprintf("%s %s", types.SymbolOK, d.safeDetail))
	}
}

// NewUnixSSHChecker creates a new Unix SSH checker with default paths
func NewUnixSSHChecker(osCtx registry.OSContext) *UnixSSHChecker {
	return &UnixSSHChecker{
		checkIdentity: checkIdentity{
			domain:   "SSH Configuration",
			analyzes: "SSH configuration and security settings",
			osCtx:    osCtx,
		},
		ConfigPaths: []string{
			"/etc/ssh/sshd_config",
			"/private/etc/ssh/sshd_config", // macOS path
		},
	}
}

// NewWindowsSSHChecker creates a new Windows SSH checker
func NewWindowsSSHChecker(osCtx registry.OSContext) *WindowsSSHChecker {
	return &WindowsSSHChecker{
		checkIdentity: checkIdentity{
			domain:   "SSH Configuration",
			analyzes: "SSH configuration and security settings",
			osCtx:    osCtx,
		},
		ConfigPath: "C:\\ProgramData\\ssh\\sshd_config",
	}
}

// Check implements SSHChecker interface for Unix systems
func (s *UnixSSHChecker) Check(ctx context.Context) types.AuditResult {
	result := types.AuditResult{
		Name:        s.Name(),
		Status:      types.StatusChecking,
		Description: s.Description(),
		Details:     make([]string, 0),
		Findings:    make([]types.Finding, 0),
	}

	var file *os.File
	var err error
	var configPath string

	// Try each possible config path
	for _, path := range s.ConfigPaths {
		if file, err = os.Open(path); err == nil { // #nosec G304 -- paths hardcoded in NewUnixSSHChecker; file contents parsed defensively for two known fields only
			configPath = path
			defer file.Close() //nolint:errcheck // read-only file; close error does not affect scan results
			break
		}
	}

	if file == nil {
		result.Status = types.StatusError
		result.Description = fmt.Sprintf("SSH configuration file not found in any of: %v", s.ConfigPaths)
		result.Details = append(result.Details,
			fmt.Sprintf("%s ERROR: No SSH configuration file found", types.SymbolError))
		emitFinding(&result, s.osCtx, "ssh.config_not_found")
		return result
	}

	// Parse SSH Configuration
	config, err := parseSSHDConfig(file)
	if err != nil {
		result.Status = types.StatusError
		result.Description = fmt.Sprintf("Error reading SSH configuration: %v", err)
		result.Details = append(result.Details,
			fmt.Sprintf("%s ERROR: Failed to read configuration", types.SymbolError))
		return result
	}

	// Build detailed results
	result.Details = append(result.Details,
		fmt.Sprintf("%s Configuration file: %s", types.SymbolInfo, configPath))

	reportSSHDirective(&result, s.osCtx, sshDirective{
		found:        config.permRootFound,
		unsafe:       config.rootLogin,
		unsafeDetail: "WARNING: Root login is permitted",
		safeDetail:   "Root login is disabled",
		absentDetail: "WARNING: PermitRootLogin setting not found (defaults may apply)",
		unsafeKey:    "ssh.root_login_permitted",
		absentKey:    "ssh.permit_root_login_not_set",
	})

	reportSSHDirective(&result, s.osCtx, sshDirective{
		found:        config.permPasswordFound,
		unsafe:       config.passwordAuth,
		unsafeDetail: "WARNING: Password authentication is enabled",
		safeDetail:   "Password authentication is disabled",
		absentDetail: "WARNING: PasswordAuthentication setting not found (defaults may apply)",
		unsafeKey:    "ssh.password_auth_enabled",
		absentKey:    "ssh.password_auth_not_set",
	})

	result.Status = types.StatusCompleted
	return result
}

// Check implements SSHChecker interface for Windows systems
func (s *WindowsSSHChecker) Check(ctx context.Context) types.AuditResult {
	result := types.AuditResult{
		Name:        s.Name(),
		Status:      types.StatusChecking,
		Description: s.Description(),
		Details:     make([]string, 0),
		Findings:    make([]types.Finding, 0),
	}

	if s.reportSSHDPresence(ctx, &result) {
		s.checkSSHDConfig(&result)
	}
	s.checkPuTTY(ctx, &result)

	result.Status = types.StatusCompleted
	return result
}

// reportSSHDPresence records whether the OpenSSH server is present and, when a
// service ius registered, its state. The binary is a fallback for hosts where
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
			emitFinding(result, s.osCtx, "ssh.server_not_running")
		default:
			result.Details = append(result.Details,
				fmt.Sprintf("%s OpenSSH Server service state: %s", types.SymbolInfo, serviceStatus))
		}
		return true
	}

	if _, err := os.Stat(sshdBinaryPath); err == nil {
		result.Details = append(result.Details,
			fmt.Sprintf("%s OpenSSH Server binary found (service not detected)", types.SymbolInfo))
		return true
	}

	result.Details = append(result.Details,
		fmt.Sprintf("%s OpenSSH Server is not installed", types.SymbolInfo))
	return false
}

// checkSSHDConfig reads and evaluates the OpenSSH server configuration. It
// opens the file directly rather than stat-then-open: the two-call form leaves
// a window in which the file change between the check and the use, and one
// error already distinguishes "absent" from "unreadable".
func (s *WindowsSSHChecker) checkSSHDConfig(result *types.AuditResult) {
	file, err := os.Open(s.ConfigPath) // #nosec G304 -- path set in NewWindowsSSHChecker to a hardcoded system location
	switch {
	case errors.Is(err, os.ErrNotExist):
		result.Details = append(result.Details,
			fmt.Sprintf("%s WARNING: OpenSSH configuration file not found", types.SymbolWarning))
		emitFinding(result, s.osCtx, "ssh.config_missing")
		return
	case err != nil:
		result.Details = append(result.Details,
			fmt.Sprintf("%s ERROR: Cannot read OpenSSH configuration: %v", types.SymbolError, err))
		return
	}
	defer file.Close() //nolint:errcheck // read-only file; close error does not affect scan results

	config, err := parseSSHDConfig(file)
	if err != nil {
		result.Details = append(result.Details,
			fmt.Sprintf("%s ERROR: Failed to read OpenSSH configuration: %v",
				types.SymbolError, err))
	}

	reportSSHDirective(result, s.osCtx, sshDirective{
		found:        config.permRootFound,
		unsafe:       config.rootLogin,
		unsafeDetail: "WARNING: Root login is permitted",
		safeDetail:   "Root login is disabled",
		unsafeKey:    "ssh.root_login_permitted",
	})

	reportSSHDirective(result, s.osCtx, sshDirective{
		found:        config.permPasswordFound,
		unsafe:       config.passwordAuth,
		unsafeDetail: "WARNING: Password authentication is enabled",
		safeDetail:   "Password authentication is disabled",
		unsafeKey:    "ssh.password_auth_enabled",
	})
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

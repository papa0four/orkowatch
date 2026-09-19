// internal/security/checker/ssh.go

package checker

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
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

	// sshdAbsentKeys names the findings a platform defines for the two
	// evaluated directives being unset. A zero value means the platform has
	// no such definitions and an unset directive is not reported.
	sshdAbsentKeys struct {
		rootLogin    registry.FindingKey
		passwordAuth registry.FindingKey
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

// checkSSHDConfig reads the OpenSSH server configuration at path and reports the
// directives the audit evaluates. It opens the file directly rather than
// stat-then-open: the two-call form leaves a window in which the file can
// change between the check and the use, and one error already distinguishes
// absent from unreadable. An absent file is a finding; an unreadable or
// unparseable one is an error, returned after recording what could be read
// so the caller decides whether it ends the check.
func checkSSHDConfig(result *types.AuditResult, osCtx registry.OSContext, path string, absent sshdAbsentKeys) error {
	file, err := os.Open(path) // #nosec G304 -- path is a platform constant naming the sshd configuration
	switch {
	case errors.Is(err, os.ErrNotExist):
		result.Details = append(result.Details,
			fmt.Sprintf("%s WARNING: OpenSSH configuration file not found: %s", types.SymbolWarning, path))
		emitFinding(result, osCtx, "ssh.config_not_found")
		return fmt.Errorf("OpenSSH configuration file not found: %s", path)
	case err != nil:
		result.Details = append(result.Details,
			fmt.Sprintf("%s ERROR: Cannot read OpenSSH configuration: %v", types.SymbolError, err))
		return fmt.Errorf("error reading SSH configuration: %w", err)
	}
	defer file.Close() //nolint:errcheck // read-only file; close error does not affect scan results

	result.Details = append(result.Details,
		fmt.Sprintf("%s Configuration file: %s", types.SymbolOK, path))

	config, err := parseSSHDConfig(file)
	if err != nil {
		result.Details = append(result.Details,
			fmt.Sprintf("%s ERROR: Failed to read OpenSSH configuration: %v", types.SymbolError, err))
	}

	reportSSHDirective(result, osCtx, sshDirective{
		found:        config.permRootFound,
		unsafe:       config.rootLogin,
		unsafeDetail: "WARNING: Root login is permitted",
		safeDetail:   "Root login is disabled",
		absentDetail: "WARNING: PermitRootLogin setting not found (defaults may apply)",
		unsafeKey:    "ssh.root_login_permitted",
		absentKey:    absent.rootLogin,
	})

	reportSSHDirective(result, osCtx, sshDirective{
		found:        config.permPasswordFound,
		unsafe:       config.passwordAuth,
		unsafeDetail: "WARNING: Password authentication is enabled",
		safeDetail:   "Password authentication is disabled",
		absentDetail: "WARNING: PasswordAuthentication setting not found (defaults may apply)",
		unsafeKey:    "ssh.password_auth_enabled",
		absentKey:    absent.passwordAuth,
	})

	if err != nil {
		return fmt.Errorf("error reading SSH configuration: %w", err)
	}
	return nil
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

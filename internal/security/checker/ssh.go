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
	// SSHChecker is the SSH configuration check as the audit sees it. Each
	// platform supplies NewSSHChecker under its own build constraint.
	SSHChecker interface {
		Name() string
		Description() string
		Check(ctx context.Context) types.AuditResult
	}

	// sshConfig holds the sshd_config directives the audit evaluates.
	sshConfig struct {
		rootLogin    sshSetting
		passwordAuth sshSetting
	}

	// sshSetting is one directive as the file states it. found distinguishes
	// an explicit setting from an absent one, which warrant different
	// conclusions because sshd applies its own default to what the file does
	// not say.
	sshSetting struct {
		value string
		found bool
	}

	// sshRule pairs a directive with the rules it decides. absentKey is empty
	// on platforms with no rule defined for the directive being unset.
	sshRule struct {
		name      string
		setting   sshSetting
		unsafe    func(value string) bool
		unsafeKey registry.FindingKey
		absentKey registry.FindingKey
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
// sshd_config line: the directive and its value.
const sshDirectiveField = 2

// parseSSHDConfig reads an sshd_config stream, recording the two directives the
// audit evaluates. Comments, blank lines, and every other directive are ignored.
// Partial results are returned alongside a read error so a truncated file still
// reports what it did contain.
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
			config.rootLogin = sshSetting{value: fields[1], found: true}
		case "PasswordAuthentication":
			config.passwordAuth = sshSetting{value: fields[1], found: true}
		}
	}

	return config, scanner.Err()
}

// checkSSHDConfig reads the OpenSSH server configuration at path and concludes
// the rules its directives decide. It opens the file directly rather than
// stat-then-open: the two-call form leaves a window in which the file can
// change between the check and the use, and one error already distinguishes
// absent from unreadable. An absent file fails its own rule and leaves the
// directive rules unchecked; an unreadable one is an error on all of them.
func checkSSHDConfig(r *report, path string, absent sshdAbsentKeys) {
	directives := []registry.FindingKey{
		"ssh.root_login_permitted", "ssh.password_auth_enabled",
		absent.rootLogin, absent.passwordAuth,
	}

	file, err := os.Open(path) // #nosec G304 -- path is a platform constant naming the sshd configuration
	switch {
	case errors.Is(err, os.ErrNotExist):
		r.observed("ssh.config_not_found", evidence(kindFile, path))
		r.inconclusive(types.ResultNotChecked, "OpenSSH configuration file not found: "+path, directives...)
		return
	case err != nil:
		r.inconclusive(types.ResultError, fmt.Sprintf("cannot read OpenSSH configuration: %v", err),
			append(directives, "ssh.config_not_found")...)
		return
	}
	defer file.Close() //nolint:errcheck // read-only file; close error does not affect scan results

	r.pass("ssh.config_not_found")
	r.note(types.SymbolInfo, "Configuration file: %s", path)

	config, readErr := parseSSHDConfig(file)

	reportSSHDirective(r, readErr, sshRule{
		name:      "PermitRootLogin",
		setting:   config.rootLogin,
		unsafe:    func(value string) bool { return value != "no" },
		unsafeKey: "ssh.root_login_permitted",
		absentKey: absent.rootLogin,
	})

	reportSSHDirective(r, readErr, sshRule{
		name:      "PasswordAuthentication",
		setting:   config.passwordAuth,
		unsafe:    func(value string) bool { return value == "yes" },
		unsafeKey: "ssh.password_auth_enabled",
		absentKey: absent.passwordAuth,
	})
}

// reportSSHDirective concludes the rules one directive decides. An absent
// directive is a third condition rather than a variant of either value,
// because sshd applies its own default to what the file does not say, and
// that default is not visible in the configuration being audited. A directive
// not found in a file that could not be read to the end is an error rather
// than an absence: the part that was not read may have set it.
func reportSSHDirective(r *report, readErr error, rule sshRule) {
	switch {
	case !rule.setting.found && readErr != nil:
		r.inconclusive(types.ResultError,
			fmt.Sprintf("OpenSSH configuration could not be read in full: %v", readErr),
			rule.unsafeKey, rule.absentKey)
	case !rule.setting.found:
		r.inconclusive(types.ResultNotChecked,
			rule.name+" is not set; the sshd default applies and is not read", rule.unsafeKey)
		if rule.absentKey != "" {
			r.observed(rule.absentKey, evidence(kindDirective, rule.name, "state", "not set"))
		}
	case rule.unsafe(rule.setting.value):
		r.observed(rule.unsafeKey, evidence(kindDirective, rule.name, "value", rule.setting.value))
		r.pass(rule.absentKey)
	default:
		r.pass(rule.unsafeKey, rule.absentKey)
	}
}

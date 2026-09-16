//go:build linux || darwin || freebsd || openbsd || netbsd

// internal/security/checker/users_unix.go

package checker

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"strings"

	"github.com/papa0four/orkowatch/internal/security/registry"
	"github.com/papa0four/orkowatch/internal/security/types"
)

type (
	// UnixUserChecker implements UserChecker for Unix-like systems. The
	// platform reader supplies getUsers under its own build constraint.
	// shadowReadable is set when the reader could open the credential store;
	// it gates the no-password findings and surfaces a diagnostic when the
	// check runs without sufficient privileges. adminLookupErr is set when no
	// privileged group could be read at all; analyzeUsers reports that rather
	// than presenting every account as unprivileged.
	UnixUserChecker struct {
		checkIdentity
		shadowReadable bool
		adminLookupErr error
	}

	// userAccount is a parsed account from the platform's user database.
	// isSystem is true when the UID falls below the platform minimum for
	// regular accounts. password and state stay at their unknown zero values
	// unless the reader could inspect the credential store or the account's
	// directory record, so a reader that cannot see either never reports an
	// account as credential-less or judges a disabled one as live.
	userAccount struct {
		username string
		uid      uint32
		gid      uint32
		homeDir  string
		shell    string
		isSystem bool
		isAdmin  bool
		password passwordState
		state    accountState
	}

	// passwordState is what the credential store says about an account.
	passwordState uint8

	// accountState is whether the directory record allows the account to
	// authenticate at all, independent of its credential.
	accountState uint8
)

const (
	// passwordUnknown is the zero value: the credential store was not
	// readable or has no entry for the account. It never produces a finding.
	passwordUnknown passwordState = iota
	passwordEmpty
	passwordLocked
	passwordSet
)

const (
	// accountUnknown is the zero value: the reader did not or could not
	// inspect the record. Judgments that need a live account treat it as
	// live, so a reader that cannot see the state does not hide findings.
	accountUnknown accountState = iota
	accountEnabled
	accountDisabled
)

// rootUID is the superuser identity on every POSIX platform.
const rootUID = 0

// NewUserChecker returns the user account checker for Unix-like hosts.
func NewUserChecker(osCtx registry.OSContext) *UnixUserChecker {
	return &UnixUserChecker{checkIdentity: checkIdentity{
		domain:   "User Account Security",
		analyzes: "user accounts and security settings",
		osCtx:    osCtx,
	}}
}

// Check implements UserChecker interface for Unix systems
func (u *UnixUserChecker) Check(ctx context.Context) types.AuditResult {
	result := types.AuditResult{
		Name:        u.Name(),
		Status:      types.StatusChecking,
		Description: u.Description(),
		Details:     make([]string, 0),
		Findings:    make([]types.Finding, 0),
	}

	u.checkAuthConfig(&result)

	users, err := u.getUsers(ctx)
	if err != nil {
		result.Status = types.StatusError
		result.Description = fmt.Sprintf("Failed to analyze users: %v", err)
		return result
	}

	u.analyzeUsers(users, &result)

	result.Status = types.StatusCompleted
	return result
}

func (u *UnixUserChecker) analyzeUsers(users []userAccount, result *types.AuditResult) {
	var (
		regularUsers    []string
		adminUsers      []string
		suspiciousUsers []string
	)

	seen := make(map[registry.FindingKey]struct{})
	for _, user := range users {
		details := fmt.Sprintf("%s (UID: %d, Shell: %s)", user.username, user.uid, user.shell)
		if user.state == accountDisabled {
			details += " (disabled)"
		}

		switch {
		case user.isAdmin:
			adminUsers = append(adminUsers, details)
		case isSuspiciousUser(user):
			suspiciousUsers = append(suspiciousUsers, details)
		case !user.isSystem:
			regularUsers = append(regularUsers, details)
		}

		u.judgeAccount(user, result, seen)
	}

	if !u.shadowReadable {
		result.Details = append(result.Details,
			fmt.Sprintf("%s No-password check skipped: /etc/shadow is not readable without elevated privileges",
				types.SymbolInfo))
	}

	if u.adminLookupErr != nil {
		result.Details = append(result.Details,
			fmt.Sprintf("%s Privileged group membership could not be determined; accounts above are not marked administrative: %v",
				types.SymbolWarning, u.adminLookupErr))
	}

	appendAccountSection(result, "Administrative Users:", types.SymbolWarning, adminUsers)
	appendAccountSection(result, "Regular Users:", types.SymbolOK, regularUsers)
	appendAccountSection(result, "Suspicious Users:", types.SymbolWarning, suspiciousUsers)
}

// judgeAccount emits the findings a single account can produce. UID 0 is
// judged before the disabled check because a duplicate root identity is a
// defect in the account database whether or not the record is live; the
// remaining conditions describe how the account can be used, which a
// disabled account cannot be. root's credential is judged from the same
// parsed entry as every other account, which is what passwd -S reports
// without the subprocess or the privilege it demands.
func (u *UnixUserChecker) judgeAccount(user userAccount, result *types.AuditResult, seen map[registry.FindingKey]struct{}) {
	if user.uid == rootUID && user.username != "root" {
		result.Details = append(result.Details,
			fmt.Sprintf("%s CRITICAL: Account %s has UID 0 (root-equivalent)",
				types.SymbolCritical, user.username))
		emitFindingOnce(result, u.osCtx, "users.uid_zero_non_root", seen)
	}

	if user.state == accountDisabled {
		return
	}

	switch {
	case user.username == "root" && user.password == passwordLocked:
		result.Details = append(result.Details,
			fmt.Sprintf("%s Root account password is locked", types.SymbolOK))
	case user.username == "root" && user.password == passwordSet:
		result.Details = append(result.Details,
			fmt.Sprintf("%s WARNING: Root account is unlocked", types.SymbolWarning))
		emitFindingOnce(result, u.osCtx, "users.root_account_unlocked", seen)
	}

	// An empty credential field admits anyone who reaches a login prompt
	// or su for the account. An interactive shell turns that into a
	// session and is reported on top.
	if user.password == passwordEmpty {
		result.Details = append(result.Details,
			fmt.Sprintf("%s CRITICAL: Account %s has no password set",
				types.SymbolCritical, user.username))
		emitFindingOnce(result, u.osCtx, "users.empty_password_hash", seen)
	}

	if user.password == passwordEmpty && isInteractiveShell(user.shell) {
		result.Details = append(result.Details,
			fmt.Sprintf("%s WARNING: Account %s has no password and an interactive login shell",
				types.SymbolWarning, user.username))
		emitFindingOnce(result, u.osCtx, "users.no_password_login_shell", seen)
	}

	if user.isAdmin && !user.isSystem {
		result.Details = append(result.Details,
			fmt.Sprintf("%s WARNING: Regular user %s has administrative privileges",
				types.SymbolWarning, user.username))
		emitFindingOnce(result, u.osCtx, "users.regular_user_admin_privileges", seen)
	}

	if isInteractiveShell(user.shell) && !user.isSystem {
		result.Details = append(result.Details,
			fmt.Sprintf("%s User %s has an interactive login shell: %s",
				types.SymbolWarning, user.username, user.shell))
		emitFindingOnce(result, u.osCtx, "users.login_shell_present", seen)
	}
}

// appendAccountSection appends a titled list of account lines, each carrying
// symbol, and nothing at all when entries is empty.
func appendAccountSection(result *types.AuditResult, title string, symbol string, entries []string) {
	if len(entries) == 0 {
		return
	}

	result.Details = append(result.Details, "", title)
	for _, entry := range entries {
		result.Details = append(result.Details, fmt.Sprintf("%s %s", symbol, entry))
	}
}

// checkAuthConfig reports the authentication sources configured on the host:
// the PAM modules referenced under /etc/pam.d and the network directories
// whose configuration files are present. A file whose presence cannot be
// determined is reported as such, because the directory holding sssd.conf is
// unreadable to an unprivileged caller and a stat failure there is not
// evidence of absence.
func (u *UnixUserChecker) checkAuthConfig(result *types.AuditResult) {
	u.reportPAMModules(result)

	sources := []struct {
		path  string
		label string
		key   registry.FindingKey
	}{
		{"/etc/ldap.conf", "LDAP", "users.ldap_configured"},
		{"/etc/krb5.conf", "Kerberos", "users.kerberos_configured"},
		{"/etc/sssd/sssd.conf", "SSSD", "users.sssd_configured"},
	}

	for _, source := range sources {
		_, err := os.Stat(source.path)
		switch {
		case err == nil:
			result.Details = append(result.Details,
				fmt.Sprintf("%s %s authentication is configured", types.SymbolWarning, source.label))
			emitFinding(result, u.osCtx, source.key)
		case !errors.Is(err, fs.ErrNotExist):
			result.Details = append(result.Details,
				fmt.Sprintf("%s %s configuration could not be checked: %v", types.SymbolWarning, source.label, err))
		}
	}
}

// reportPAMModules reports which of the well-known authentication modules
// /etc/pam.d references. The tree is read once and every file is inspected,
// with unreadable files counted and reported so that reduced coverage is
// visible rather than read as absence. The walk is scoped through os.DirFS
// so a symlink under /etc/pam.d cannot lead it elsewhere (CWE-367).
func (u *UnixUserChecker) reportPAMModules(result *types.AuditResult) {
	modules := []string{"pam_unix.so", "pam_ldap.so", "pam_sss.so"}
	found := make(map[string]bool, len(modules))
	for _, module := range modules {
		found[module] = false
	}

	pamFS := os.DirFS("/etc/pam.d")
	var unreadable int
	err := fs.WalkDir(pamFS, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			if name == "." {
				return err
			}
			unreadable++
			return nil
		}
		if d.IsDir() {
			return nil
		}

		data, err := fs.ReadFile(pamFS, name)
		if err != nil {
			unreadable++
			return nil
		}
		markPAMModules(data, found)
		return nil
	})

	switch {
	case errors.Is(err, fs.ErrNotExist):
		return
	case err != nil:
		result.Details = append(result.Details,
			fmt.Sprintf("%s PAM configuration could not be checked: %v", types.SymbolWarning, err))
		return
	}

	result.Details = append(result.Details,
		fmt.Sprintf("%s PAM authentication is configured", types.SymbolInfo))
	for _, module := range modules {
		if found[module] {
			result.Details = append(result.Details,
				fmt.Sprintf("%s Found authentication module: %s", types.SymbolInfo, module))
		}
	}
	if unreadable > 0 {
		result.Details = append(result.Details,
			fmt.Sprintf("%s %d PAM configuration files could not be read; module detection is incomplete",
				types.SymbolWarning, unreadable))
	}
}

// markPAMModules sets found[module] for every module a PAM configuration
// file references. Only active directives count: a commented-out line is
// not a reference, and a module may be named by bare file name or by path.
func markPAMModules(data []byte, found map[string]bool) {
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		for _, field := range strings.Fields(line) {
			module := path.Base(field)
			if _, tracked := found[module]; tracked {
				found[module] = true
			}
		}
	}
}

func isSuspiciousUser(user userAccount) bool {
	return strings.HasPrefix(user.username, ".") ||
		strings.Contains(user.username, "$") ||
		strings.Contains(user.username, "tmp") ||
		strings.Contains(user.username, "temp") ||
		strings.Contains(user.username, "test")
}

// isInteractiveShell reports whether shell allows interactive login. Shells
// that do not appear in the nologin/false/sync family are considered
// interactive regardless of whether they are considered "secure" -- the
// analyst decides whether the assignment is intentional.
func isInteractiveShell(shell string) bool {
	nonInteractive := []string{
		"nologin",
		"/bin/false",
		"/usr/bin/false",
		"/bin/sync",
		"/usr/bin/sync",
		"/sbin/halt",
		"/sbin/shutdown",
	}
	for _, s := range nonInteractive {
		if strings.HasSuffix(shell, s) {
			return false
		}
	}
	// empty shell field defaults to /bin/sh which is interactive
	return true
}

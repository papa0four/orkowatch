//go:build linux || darwin || freebsd || openbsd || netbsd

// internal/security/checker/users_unix.go

package checker

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/papa0four/orkowatch/internal/security/finding"
	"github.com/papa0four/orkowatch/internal/security/registry"
)

type (
	// UnixUserChecker implements UserChecker for Unix-like systems. The
	// platform reader supplies getUsers under its own build constraint.
	// shadowReadable is set when the reader could open the credential store;
	// it gates the no-password findings and surfaces a diagnostic when the
	// check runs without sufficient privileges. unjudged holds the rules on
	// administrative access the reader could not decide; analyzeUsers reports
	// them rather than presenting every account as unprivileged. adminHeading
	// titles the list of administrative accounts by how the reader decided
	// them. readWarnings holds what else the reader could not see, so reduced
	// coverage is stated in the report rather than read as a complete account
	// list.
	UnixUserChecker struct {
		checkIdentity
		shadowReadable bool
		unjudged       []unjudged
		adminHeading   string
		readWarnings   []string
	}

	// unjudged is why rules on administrative access have no judgment, with
	// what the reader did see that bears on them.
	unjudged struct {
		rules    []registry.FindingKey
		result   finding.Result
		reason   string
		evidence []finding.Evidence
	}

	// userAccount is a parsed account from the platform's user database.
	// isSystem is true when the UID falls outside the range the platform
	// assigns to regular accounts. password and state stay at their unknown zero values
	// unless the reader could inspect the credential store or the account's
	// directory record, so a reader that cannot see either never reports an
	// account as credential-less or judges a disabled one as live. grants,
	// unprompted and borrowed are what sudo said of the account where the
	// reader asked it: the entries behind isAdmin, the entries that ask for no
	// password, and the setting under which sudo asks for a password that is
	// not the account's.
	userAccount struct {
		username   string
		uid        uint32
		gid        uint32
		homeDir    string
		shell      string
		isSystem   bool
		isAdmin    bool
		password   passwordState
		state      accountState
		grants     []string
		unprompted []string
		borrowed   string
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

// rootUID and rootGID are the superuser identity on every POSIX platform.
const (
	rootUID = 0
	rootGID = 0
)

// The rules on administrative access. Each platform's reader names the ones
// it judges in privilegeRules.
const (
	ruleAdminAccount   registry.FindingKey = "users.regular_user_admin_privileges"
	ruleSudoUnprompted registry.FindingKey = "users.sudo_nopasswd"
)

// defaultAdminHeading titles the administrative accounts of a reader that
// decides them by group.
const defaultAdminHeading = "Administrative Users:"

// grantDivider separates the entries sudo lists for one account in a fact.
const grantDivider = "; "

// accountRules are the rules judged per account whatever the reader could
// see of administrative access. credentialRules are the subset that needs
// the credential store to be readable.
var (
	accountRules = []registry.FindingKey{
		"users.uid_zero_non_root",
		"users.root_account_unlocked",
		"users.empty_password_hash",
		"users.no_password_login_shell",
		"users.login_shell_present",
	}

	credentialRules = []registry.FindingKey{
		"users.root_account_unlocked",
		"users.empty_password_hash",
		"users.no_password_login_shell",
	}
)

// NewUserChecker returns the user account checker for Unix-like hosts.
func NewUserChecker(osCtx registry.OSContext) *UnixUserChecker {
	return &UnixUserChecker{checkIdentity: checkIdentity{
		domain:   "User Account Security",
		analyzes: "user accounts and security settings",
		osCtx:    osCtx,
	}}
}

// Check implements UserChecker interface for Unix systems
func (u *UnixUserChecker) Check(ctx context.Context) finding.AuditResult {
	r := newReport(u.checkIdentity)

	u.checkDirectoryClients(ctx, r)

	users, err := u.getUsers(ctx)
	if err != nil {
		reason := fmt.Sprintf("user accounts could not be read: %v", err)
		r.inconclusive(finding.ResultError, reason, accountRules...)
		r.inconclusive(finding.ResultError, reason, privilegeRules...)
		return r.finish()
	}

	u.analyzeUsers(users, r)
	return r.finish()
}

// analyzeUsers judges every account, then concludes the rules no account
// tripped. A rule the reader could not see enough to judge is an error
// rather than a pass: an unreadable credential store proves nothing about
// the credentials in it.
func (u *UnixUserChecker) analyzeUsers(users []userAccount, r *report) {
	var (
		regularUsers    []string
		adminUsers      []string
		suspiciousUsers []string
	)

	for _, user := range users {
		details := fmt.Sprintf("%s (UID: %d, Shell: %s)", user.username, user.uid, user.shell)
		if user.state == accountDisabled {
			details += " (disabled)"
		}
		if user.borrowed != "" {
			details += fmt.Sprintf(" (sudo asks for another account's password: %s)", user.borrowed)
		}

		switch {
		case user.isAdmin:
			adminUsers = append(adminUsers, details)
		case isSuspiciousUser(user):
			suspiciousUsers = append(suspiciousUsers, details)
		case !user.isSystem:
			regularUsers = append(regularUsers, details)
		}

		judgeAccount(user, r)
	}

	if !u.shadowReadable {
		r.inconclusive(finding.ResultError,
			"/etc/shadow is not readable without elevated privileges", credentialRules...)
	}
	r.pass(accountRules...)
	u.concludePrivilege(r)

	for _, warning := range u.readWarnings {
		r.note(finding.SymbolWarning, "%s", warning)
	}

	appendAccountSection(r, cmp.Or(u.adminHeading, defaultAdminHeading), finding.SymbolWarning, adminUsers)
	appendAccountSection(r, "Regular Users:", finding.SymbolOK, regularUsers)
	appendAccountSection(r, "Suspicious Users:", finding.SymbolWarning, suspiciousUsers)
}

// concludePrivilege concludes the rules on administrative access no account
// tripped. A rule the reader could not judge takes the reader's result, which
// pass must not follow: pass outranks a rule that does not apply.
func (u *UnixUserChecker) concludePrivilege(r *report) {
	var undecided []registry.FindingKey
	for _, gap := range u.unjudged {
		for _, key := range gap.rules {
			r.record(key, finding.Condition{Key: string(key), Result: gap.result, Reason: gap.reason, Evidence: gap.evidence})
		}
		undecided = append(undecided, gap.rules...)
	}

	for _, key := range privilegeRules {
		if !slices.Contains(undecided, key) {
			r.pass(key)
		}
	}
}

// judgeAccount records the rules a single account trips. UID 0 is judged
// before the disabled check because a duplicate root identity is a defect in
// the account database whether or not the record is live; the remaining
// conditions describe how the account can be used, which a disabled account
// cannot be. root's credential is judged from the same parsed entry as every
// other account, which is what passwd -S reports without the subprocess or
// the privilege it demands.
func judgeAccount(user userAccount, r *report) {
	account := accountEvidence(user)

	if user.uid == rootUID && user.username != "root" {
		r.observed("users.uid_zero_non_root", account)
	}

	if user.state == accountDisabled {
		return
	}

	if user.username == "root" && user.password == passwordSet {
		r.observed("users.root_account_unlocked", account)
	}

	// An empty credential field admits anyone who reaches a login prompt
	// or su for the account. An interactive shell turns that into a
	// session and is reported on top.
	if user.password == passwordEmpty {
		r.observed("users.empty_password_hash", account)
		if isInteractiveShell(user.shell) {
			r.observed("users.no_password_login_shell", account)
		}
	}

	if user.isAdmin && !user.isSystem {
		r.observed(ruleAdminAccount, accountEvidence(user, fact(finding.FactGrant, strings.Join(user.grants, grantDivider))))
	}
	if len(user.unprompted) > 0 {
		r.observed(ruleSudoUnprompted, accountEvidence(user, fact(finding.FactGrant, strings.Join(user.unprompted, grantDivider))))
	}

	if isInteractiveShell(user.shell) && !user.isSystem {
		r.observed("users.login_shell_present", account)
	}
}

// accountEvidence is the evidence of one account: its identifier and shell,
// then what else was observed of it.
func accountEvidence(user userAccount, facts ...finding.Fact) finding.Evidence {
	return evidence(finding.KindAccount, user.username, append([]finding.Fact{
		fact(finding.FactUID, strconv.FormatUint(uint64(user.uid), decimalBase)),
		fact(finding.FactShell, user.shell),
	}, facts...)...)
}

// appendAccountSection narrates a titled list of accounts, each carrying
// symbol, and nothing at all when entries is empty.
func appendAccountSection(r *report, title string, symbol string, entries []string) {
	if len(entries) == 0 {
		return
	}

	r.section(title)
	for _, entry := range entries {
		r.note(symbol, "%s", entry)
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

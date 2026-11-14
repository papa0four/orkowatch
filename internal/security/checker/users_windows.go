//go:build windows

// internal/security/checker/users_windows.go

package checker

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/papa0four/orkowatch/internal/security/finding"
	"github.com/papa0four/orkowatch/internal/security/registry"
)

// The rules this check concludes.
const (
	ruleAdminActive      registry.FindingKey = "users.administrator_account_active"
	ruleBlankPermitted   registry.FindingKey = "users.no_password_required"
	ruleMicrosoftAccount registry.FindingKey = "users.microsoft_account_no_local_password"
	ruleMinLengthZero    registry.FindingKey = "users.password_min_length_zero"
	ruleLockoutDisabled  registry.FindingKey = "users.lockout_threshold_disabled"
	ruleUACDisabled      registry.FindingKey = "users.uac_disabled"
)

// WindowsUserChecker implements UserChecker for Windows systems.
type WindowsUserChecker struct {
	checkIdentity
}

// NewUserChecker returns the user account checker for Windows hosts.
func NewUserChecker(osCtx registry.OSContext) *WindowsUserChecker {
	return &WindowsUserChecker{checkIdentity: checkIdentity{
		domain:   "User Account Security",
		analyzes: "user accounts and security settings",
		osCtx:    osCtx,
	}}
}

// Check implements UserChecker interface for Windows systems. Accounts,
// group membership and policy are read through the Network Management API
// rather than parsed from command output, so nothing here depends on the
// display language or on a tool's formatting.
func (u *WindowsUserChecker) Check(_ context.Context) finding.AuditResult {
	r := newReport(u.checkIdentity)

	accounts, err := localAccounts()
	if err != nil {
		r.inconclusive(finding.ResultError,
			fmt.Sprintf("user accounts could not be read: %v", err), ruleAdminActive, ruleBlankPermitted)
	} else {
		analyzeAccounts(accounts, r)
	}

	checkPasswordPolicy(r)
	checkUAC(r)

	return r.finish()
}

// analyzeAccounts judges every enabled account, then concludes the rules no
// account tripped. Administrator membership and the password requirement are
// independent, so each is its own rule. A disabled account cannot be logged
// into and is listed without being judged.
func analyzeAccounts(accounts []windowsAccount, r *report) {
	admins, adminErr := administratorSIDs()
	if adminErr != nil {
		r.inconclusive(finding.ResultError,
			fmt.Sprintf("Administrators group membership could not be read: %v", adminErr), ruleAdminActive)
	}

	r.section("Local Accounts:")
	for _, account := range accounts {
		if !account.enabled {
			r.note(finding.SymbolInfo, "%s (Disabled)", account.name)
			continue
		}
		r.note(finding.SymbolInfo, "%s", account.name)
		judgeWindowsAccount(account, admins, r)
	}

	r.pass(ruleAdminActive, ruleBlankPermitted)
}

// judgeWindowsAccount records the rules one enabled account trips. An account
// whose identity record could not be read is not guessed at: without it the
// account can be tied neither to the Administrators group nor to a Microsoft
// identity, so both rules report that they could not be evaluated for it.
func judgeWindowsAccount(account windowsAccount, admins map[string]bool, r *report) {
	if account.identityErr != nil {
		r.inconclusive(finding.ResultError,
			fmt.Sprintf("account type of %s could not be determined: %v", account.name, account.identityErr),
			ruleAdminActive, ruleBlankPermitted)
		return
	}

	subject := evidence(kindAccount, account.name,
		"sid", account.sid,
		"password_required", strconv.FormatBool(account.passwordRequired),
		"internet_identity", strconv.FormatBool(account.internetIdentity))

	if admins[account.sid] {
		r.observed(ruleAdminActive, subject)
	}

	// The flag says a blank password is permitted, not that one is set: the
	// stored credential cannot be read. An account Windows records as
	// connected to an Internet identity is validated by that provider, which
	// is why its local record requires no password.
	switch {
	case account.passwordRequired:
	case account.internetIdentity:
		r.observed(ruleMicrosoftAccount, subject)
	default:
		r.observed(ruleBlankPermitted, subject)
	}
}

// checkPasswordPolicy reports the local password and lockout policy and
// concludes the two rules a value of zero decides on its own: no minimum
// length, and no limit on failed logon attempts. The remaining values are
// narrated; judging them needs a baseline, which is tracked separately.
func checkPasswordPolicy(r *report) {
	policy, err := passwordPolicy()
	if err != nil {
		r.inconclusive(finding.ResultError, err.Error(), ruleMinLengthZero, ruleLockoutDisabled)
		return
	}

	r.section("Password Policy:")
	r.note(finding.SymbolInfo, "Minimum password length: %d", policy.minLength)
	r.note(finding.SymbolInfo, "Password history length: %d", policy.historyLength)
	r.note(finding.SymbolInfo, "Maximum password age: %s", policyAge(policy.maxAge))
	r.note(finding.SymbolInfo, "Minimum password age: %s", policyAge(policy.minAge))
	r.note(finding.SymbolInfo, "Lockout threshold: %d", policy.lockoutThreshold)
	r.note(finding.SymbolInfo, "Lockout duration: %s", policyAge(policy.lockoutDuration))
	r.note(finding.SymbolInfo, "Lockout observation window: %s", policyAge(policy.lockoutWindow))

	if policy.minLength == 0 {
		r.observed(ruleMinLengthZero, evidence(kindSetting, "minimum password length", "value", "0"))
	} else {
		r.pass(ruleMinLengthZero)
	}

	if policy.lockoutThreshold == 0 {
		r.observed(ruleLockoutDisabled, evidence(kindSetting, "lockout threshold", "value", "0"))
	} else {
		r.pass(ruleLockoutDisabled)
	}
}

// policyAge renders a policy duration, naming the case where no limit is set.
// Password ages are whole days, and are shown as such.
func policyAge(d time.Duration) string {
	const day = 24 * time.Hour
	switch {
	case d == 0:
		return "not set"
	case d%day == 0:
		return fmt.Sprintf("%d days", d/day)
	default:
		return d.String()
	}
}

// checkUAC concludes the User Account Control rule. An unreadable setting is
// an error rather than a failure: failing the rule on a failed read would
// assert a weakness the check never observed.
func checkUAC(r *report) {
	enabled, err := uacEnabled()
	switch {
	case err != nil:
		r.inconclusive(finding.ResultError,
			fmt.Sprintf("User Account Control state could not be determined: %v", err), ruleUACDisabled)
	case enabled:
		r.pass(ruleUACDisabled)
	default:
		r.observed(ruleUACDisabled, evidence(kindSetting, uacPolicyValue, "value", "0"))
	}
}

//go:build windows

// internal/security/checker/users_windows.go

package checker

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/papa0four/orkowatch/internal/security/finding"
	"github.com/papa0four/orkowatch/internal/security/registry"
)

const (
	// windowsUserCSVFields is the number of columns produced by Get-LocalUser
	windowsUserCSVFields = 8

	// windowsAdminCSVFields is the number of columns produced by
	// Get-LocalGroupMember
	windowsAdminCSVFields = 1
)

type (
	// WindowsUserChecker implements UserChecker for Windows systems.
	// adminLookupErr is set when Administrators group membership could not be
	// read; analyzeWindowsUsers reports the condition rather than presenting
	// every account as non-administrative.
	WindowsUserChecker struct {
		checkIdentity
		adminLookupErr error
	}

	// windowsUserInfo holds parsed Windows user account data
	windowsUserInfo struct {
		Name             string
		Enabled          bool
		PasswordRequired bool
		PasswordLastSet  string
		LastLogon        string
		AccountExpires   string
		Description      string
		PrincipalSource  string
		IsAdmin          bool
	}
)

// windowsAccountRules are the per-account rules that report fail. The rules
// for accounts authenticated off the host are not among them: they describe
// a state the local password rule does not apply to, and are recorded only
// when such an account is seen.
var windowsAccountRules = []registry.FindingKey{
	"users.administrator_account_active",
	"users.no_password_required",
	"users.unknown_principal_no_local_password",
}

// NewUserChecker returns the user account checker for Windows hosts.
func NewUserChecker(osCtx registry.OSContext) *WindowsUserChecker {
	return &WindowsUserChecker{checkIdentity: checkIdentity{
		domain:   "User Account Security",
		analyzes: "user accounts and security settings",
		osCtx:    osCtx,
	}}
}

// Check implements UserChecker interface for Windows systems
func (u *WindowsUserChecker) Check(ctx context.Context) finding.AuditResult {
	r := newReport(u.checkIdentity)

	users, err := u.getWindowsUsers(ctx)
	if err != nil {
		r.inconclusive(finding.ResultError,
			fmt.Sprintf("user accounts could not be read: %v", err), windowsAccountRules...)
	} else {
		u.analyzeWindowsUsers(users, r)
	}

	u.checkPasswordPolicy(ctx, r)
	u.checkUAC(r)

	return r.finish()
}

func (u *WindowsUserChecker) getWindowsUsers(ctx context.Context) ([]windowsUserInfo, error) {
	psCmd := `Get-LocalUser | ` +
		`Select-Object Name,Enabled,PasswordRequired,PasswordLastSet,LastLogon,AccountExpires,Description,PrincipalSource | ` +
		`ConvertTo-Csv -NoTypeInformation`
	output, err := exec.CommandContext(ctx, "powershell", "-Command", psCmd).Output()
	if err != nil {
		return nil, fmt.Errorf("enumerate local users: %w", execError(err))
	}

	records, err := parsePowershellCSV(output, windowsUserCSVFields)
	if err != nil {
		return nil, fmt.Errorf("enumerate local users: %w", err)
	}

	// A failed membership lookup leaves admins nil, which reads as "no
	// administrators" at every index. analyzeWindowsUsers reports the
	// condition so the run cannot pass that off as a clean result.
	admins, err := u.getWindowsAdmins(ctx)
	if err != nil {
		u.adminLookupErr = err
	}

	users := make([]windowsUserInfo, 0, len(records))
	for _, rec := range records {
		users = append(users, windowsUserInfo{
			Name:             rec[0],
			Enabled:          rec[1] == "True",
			PasswordRequired: rec[2] == "True",
			PasswordLastSet:  rec[3],
			LastLogon:        rec[4],
			AccountExpires:   rec[5],
			Description:      rec[6],
			PrincipalSource:  rec[7],
			IsAdmin:          admins[rec[0]],
		})
	}

	return users, nil
}

// getWindowsAdmins returns local Administrators group membership keyed by bare
// account name. An error means membership could not be determined, which is
// distinct from an empty group, and callers must not report accounts as
// non-administrative on the strength of it.
func (u *WindowsUserChecker) getWindowsAdmins(ctx context.Context) (map[string]bool, error) {
	output, err := exec.CommandContext(ctx, "powershell", "-Command",
		`Get-LocalGroupMember -Group "Administrators" | Select-Object Name | ConvertTo-CSV -NoTypeInformation`).Output()
	if err != nil {
		return nil, execError(err)
	}

	records, err := parsePowershellCSV(output, windowsAdminCSVFields)
	if err != nil {
		return nil, execError(err)
	}

	// Names arrive qualified as SOURCE\account, where SOURCE is the machine,
	// a domain, or AzureAD. An unqualified name is kept as-is rather than
	// dropped, so a member that cannot be split is still counted.
	admins := make(map[string]bool, len(records))
	for _, rec := range records {
		name := rec[0]
		if idx := strings.LastIndex(name, `\`); idx >= 0 {
			name = name[idx+1:]
		}
		if name != "" {
			admins[name] = true
		}
	}

	return admins, nil
}

// passwordlessRule maps a principal source to the rule for an account that
// requires no local password. A source that validates credentials off the
// host explains the missing local hash, and its rule is defined as not
// applicable; a local or unrecognized source does not, and its rule fails.
//
// Get-LocalUser reports PrincipalSource Local for a Microsoft account signed
// into a local profile, so the MicrosoftAccount case does not fire for that
// configuration and such an account is reported as a local account with no
// password.
func passwordlessRule(source string) registry.FindingKey {
	switch source {
	case "MicrosoftAccount":
		return "users.microsoft_account_no_local_password"
	case "AzureAD":
		return "users.azure_ad_account_no_local_password"
	case "ActiveDirectory":
		return "users.domain_account_no_local_password"
	case "Unknown":
		return "users.unknown_principal_no_local_password"
	default:
		return "users.no_password_required"
	}
}

// analyzeWindowsUsers judges every account, then concludes the rules no
// account tripped. Administrator membership is independent of whether the
// account requires a local password, so each is its own rule. Both are judged
// only for enabled accounts: a disabled account cannot be logged into.
func (u *WindowsUserChecker) analyzeWindowsUsers(users []windowsUserInfo, r *report) {
	r.section("Local Accounts:")
	for _, user := range users {
		account := evidence(kindAccount, user.Name,
			"enabled", strconv.FormatBool(user.Enabled), "source", user.PrincipalSource)

		if !user.Enabled {
			r.note(finding.SymbolInfo, "%s (Disabled)", user.Name)
			continue
		}
		r.note(finding.SymbolInfo, "%s", user.Name)

		if user.IsAdmin {
			r.observed("users.administrator_account_active", account)
		}
		if !user.PasswordRequired {
			r.observed(passwordlessRule(user.PrincipalSource), account)
		}
	}

	if u.adminLookupErr != nil {
		r.inconclusive(finding.ResultError,
			fmt.Sprintf("Administrator membership could not be determined: %v", u.adminLookupErr),
			"users.administrator_account_active")
	}
	r.pass(windowsAccountRules...)
}

// checkPasswordPolicy lists the local password policy. The values are reported
// but not yet judged against a baseline; evaluating them is tracked separately.
// A failed query is reported rather than skipped, so an absent policy section
// cannot be mistaken for a host with nothing to report.
func (u *WindowsUserChecker) checkPasswordPolicy(ctx context.Context, r *report) {
	output, err := exec.CommandContext(ctx, "net", "accounts").Output()
	if err != nil {
		r.note(finding.SymbolWarning, "Password policy could not be read: %v", execError(err))
		return
	}

	r.section("Password Policies:")
	for _, policy := range strings.Split(string(output), "\n") {
		policy = strings.TrimSpace(policy)
		if policy != "" && !strings.HasPrefix(policy, "The command completed") {
			r.note(finding.SymbolInfo, "%s", policy)
		}
	}
}

// checkUAC concludes the User Account Control rule. An unreadable setting is
// an error rather than a failure: failing the rule on a failed read would
// assert a weakness the check never observed.
func (u *WindowsUserChecker) checkUAC(r *report) {
	const rule registry.FindingKey = "users.uac_disabled"

	enabled, err := uacEnabled()
	switch {
	case err != nil:
		r.inconclusive(finding.ResultError,
			fmt.Sprintf("User Account Control state could not be determined: %v", err), rule)
	case enabled:
		r.pass(rule)
	default:
		r.observed(rule, evidence(kindSetting, uacPolicyValue, "value", "0"))
	}
}

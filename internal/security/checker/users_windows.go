//go:build windows

// internal/security/checker/users_windows.go

package checker

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/papa0four/orkowatch/internal/security/registry"
	"github.com/papa0four/orkowatch/internal/security/types"
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

// NewUserChecker returns the user account checker for Windows hosts.
func NewUserChecker(osCtx registry.OSContext) *WindowsUserChecker {
	return &WindowsUserChecker{checkIdentity: checkIdentity{
		domain:   "User Account Security",
		analyzes: "user accounts and security settings",
		osCtx:    osCtx,
	}}
}

// Check implements UserChecker interface for Windows systems
func (u *WindowsUserChecker) Check(ctx context.Context) types.AuditResult {
	result := types.AuditResult{
		Name:        u.Name(),
		Status:      types.StatusChecking,
		Description: u.Description(),
		Details:     make([]string, 0),
		Findings:    make([]types.Finding, 0),
	}

	users, err := u.getWindowsUsers(ctx)
	if err != nil {
		result.Status = types.StatusError
		result.Description = fmt.Sprintf("Failed to get user information: %v", err)
		return result
	}

	u.analyzeWindowsUsers(users, &result)
	u.checkPasswordPolicy(ctx, &result)
	u.checkUAC(&result)

	result.Status = types.StatusCompleted
	return result
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

// passwordlessAccount maps a principal source to the annotation, finding key
// and severity for an account that requires no local password. A source that
// validates credentials off the host explains the missing local hash; a local
// or unrecognized source does not.
//
// Get-LocalUser reports PrincipalSource Local for a Microsoft account signed
// into a local profile, so the MicrosoftAccount case does not fire for that
// configuration and such an account is reported as a local account with no
// password.
func passwordlessAccount(source string) (note string, key registry.FindingKey, severe bool) {
	switch source {
	case "MicrosoftAccount":
		return "Microsoft Account -- no local password hash",
			"users.microsoft_account_no_local_password", false
	case "AzureAD":
		return "Azure AD -- no local password hash",
			"users.azure_ad_account_no_local_password", false
	case "ActiveDirectory":
		return "Active Directory -- no local password hash",
			"users.domain_account_no_local_password", false
	case "Unknown":
		return "Unknown principal source -- no local password hash",
			"users.unknown_principal_no_local_password", true
	default:
		return "No local password required", "users.no_password_required", true
	}
}

func (u *WindowsUserChecker) analyzeWindowsUsers(users []windowsUserInfo, result *types.AuditResult) {
	seen := make(map[registry.FindingKey]struct{})
	for _, user := range users {
		notes := make([]string, 0, 2)
		symbol := types.SymbolOK

		// Administrator membership is independent of whether the account is
		// enabled or requires a local password, so it annotates the entry
		// instead of replacing its other state. The finding is emitted only
		// for enabled members, matching the key's claim that the account is
		// active; a disabled member is still annotated so the membership
		// stays visible.
		if user.IsAdmin {
			notes = append(notes, "Administrator")
			symbol = types.SymbolWarning
			if user.Enabled {
				emitFindingOnce(result, u.osCtx, "users.administrator_account_active", seen)
			}
		}

		switch {
		case !user.Enabled:
			// A disabled account cannot be logged into, so its password state
			// is recorded but not judged.
			notes = append(notes, "Disabled")
			if !user.IsAdmin {
				symbol = types.SymbolInfo
			}
		case !user.PasswordRequired:
			note, key, severe := passwordlessAccount(user.PrincipalSource)
			notes = append(notes, note)
			if severe {
				symbol = types.SymbolWarning
			} else if !user.IsAdmin {
				symbol = types.SymbolInfo
			}
			emitFindingOnce(result, u.osCtx, key, seen)
		}

		details := user.Name
		if len(notes) > 0 {
			details += " (" + strings.Join(notes, ", ") + ")"
		}
		result.Details = append(result.Details,
			fmt.Sprintf("%s %s", symbol, details))
	}

	if u.adminLookupErr != nil {
		result.Details = append(result.Details,
			fmt.Sprintf("%s Administrator membership could not be determined; accounts above are not marked administrative: %v",
				types.SymbolWarning, u.adminLookupErr))
	}
}

// checkPasswordPolicy lists the local password policy. The values are reported
// but not yet judged against a baseline; evaluating them is tracked separately.
// A failed query is reported rather than skipped, so an absent policy section
// cannot be mistaken for a host with nothing to report.
func (u *WindowsUserChecker) checkPasswordPolicy(ctx context.Context, result *types.AuditResult) {
	output, err := exec.CommandContext(ctx, "net", "accounts").Output()
	if err != nil {
		result.Details = append(result.Details,
			fmt.Sprintf("%s Password policy could not be read: %v",
				types.SymbolWarning, execError(err)))
		return
	}

	result.Details = append(result.Details, "", "Password Policies:")
	for _, policy := range strings.Split(string(output), "\n") {
		policy = strings.TrimSpace(policy)
		if policy != "" && !strings.HasPrefix(policy, "The command completed") {
			result.Details = append(result.Details,
				fmt.Sprintf("%s %s", types.SymbolInfo, policy))
		}
	}
}

// checkUAC reports User Account control state. An unreadable setting is
// reported as unknown rather than as disabled: emitting the finding on a
// failed read would assert a weakness the check never observed.
func (u *WindowsUserChecker) checkUAC(result *types.AuditResult) {
	enabled, err := uacEnabled()
	switch {
	case err != nil:
		result.Details = append(result.Details,
			fmt.Sprintf("%s User Account Control state could not be determined: %v",
				types.SymbolWarning, err))
	case enabled:
		result.Details = append(result.Details,
			fmt.Sprintf("%s User Account Control (UAC) is enabled", types.SymbolOK))
	default:
		result.Details = append(result.Details,
			fmt.Sprintf("%s WARNING: User Account Control (UAC) is disabled", types.SymbolWarning))
		emitFinding(result, u.osCtx, "users.uac_disabled")
	}
}

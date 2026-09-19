//go:build windows

// internal/security/checker/firewall_windows.go

package checker

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/papa0four/orkowatch/internal/security/registry"
	"github.com/papa0four/orkowatch/internal/security/types"
)

type (
	// WindowsFirewallChecker implements FirewallChecker for Windows systems
	WindowsFirewallChecker struct {
		checkIdentity
	}

	// firewallProfile is holds the name of one Windows Firewall profile and
	// determines whether it is on.
	firewallProfile struct {
		name   string
		active bool
	}
)

// firewallProfileNames lists the profiles netsh reports, in the order it
// reports them, so output is stable across runs.
var firewallProfileNames = []string{"Domain", "Private", "Public"}

// NewFirewallChecker returns the firewall checker for Windows hosts.
func NewFirewallChecker(osCtx registry.OSContext) *WindowsFirewallChecker {
	return &WindowsFirewallChecker{checkIdentity: checkIdentity{
		domain:   "Firewall COnfiguration",
		analyzes: "firewall configuration and rules",
		osCtx:    osCtx,
	}}
}

// Check implements FirewallChecker interface for Windows systems
func (f *WindowsFirewallChecker) Check(ctx context.Context) types.AuditResult {
	result := types.AuditResult{
		Name:        f.Name(),
		Status:      types.StatusChecking,
		Description: f.Description(),
		Details:     make([]string, 0),
		Findings:    make([]types.Finding, 0),
	}

	// Check firewall status for all profiles
	cmd := exec.CommandContext(ctx, "netsh", "advfirewall", "show", "allprofiles", "state")
	output, err := cmd.Output()
	if err != nil {
		result.Status = types.StatusError
		result.Description = "Failed to check Windows Firewall status"
		result.Details = append(result.Details,
			fmt.Sprintf("%s Error checking firewall status: %v", types.SymbolError, err))
		return result
	}

	activeProfiles := 0
	inactiveProfiles := 0
	for _, profile := range parseWindowsFirewallStatus(string(output)) {
		if profile.active {
			activeProfiles++
			result.Details = append(result.Details,
				fmt.Sprintf("%s %s profile is active", types.SymbolOK, profile.name))
		} else {
			inactiveProfiles++
			result.Details = append(result.Details,
				fmt.Sprintf("%s WARNING: %s profile is inactive", types.SymbolWarning, profile.name))
		}
	}

	// One finding per inactive profile
	if inactiveProfiles > 0 && activeProfiles > 0 {
		emitFinding(&result, f.osCtx, "firewall.profile_inactive")
	}

	// Check firewall rules if at least one profile is active
	if activeProfiles > 0 {
		cmd = exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "show", "rule", "name=all", "verbose")
		output, err := cmd.Output()
		if err != nil {
			result.Details = append(result.Details,
				fmt.Sprintf("%s Error enumerating firewall rules: %v", types.SymbolError, err))
		} else {
			rules := parseWindowsFirewallRules(output)
			result.Details = append(result.Details, "", "Active Firewall Rules:")
			for _, rule := range rules {
				result.Details = append(result.Details,
					fmt.Sprintf(" %s", rule))
			}
		}
	}

	// Set final status
	if activeProfiles == 0 {
		result.Status = types.StatusWarning
		result.Details = append(result.Details,
			fmt.Sprintf("%s CRITICAL: Windows Firewall is completely disabled", types.SymbolCritical))
		emitFinding(&result, f.osCtx, "firewall.all_profiles_disabled")
	} else {
		result.Status = types.StatusCompleted
	}

	return result
}

// parseWindowsFirewallStatus reads the per-profile state from netsh output.
// Each profile's section is headed "<Name> Profile Settings:" and carries a
// "State ON|OFF" line; the state is read from that line's value field rather
// than searched for as a substring. Profiles are returned in the fixed order
// of firewallProfileNames. The headings are English literals, so a localized
// netsh reports no profiles at all rather than wrong ones.
func parseWindowsFirewallStatus(output string) []firewallProfile {
	active := make(map[string]bool, len(firewallProfileNames))
	seen := make(map[string]bool, len(firewallProfileNames))

	current := ""
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		for _, name := range firewallProfileNames {
			if strings.HasPrefix(line, name+" Profile") {
				current = name
			}
		}

		fields := strings.Fields(line)
		if current != "" && len(fields) == 2 && fields[0] == "State" {
			seen[current] = true
			active[current] = strings.EqualFold(fields[1], "ON")
		}
	}

	profiles := make([]firewallProfile, 0, len(firewallProfileNames))
	for _, name := range firewallProfileNames {
		if seen[name] {
			profiles = append(profiles, firewallProfile{name: name, active: active[name]})
		}
	}
	return profiles
}

// parseWindowsFirewallRules keeps each rule's name, enabled state, and
// direction from the verbose rule listing.
func parseWindowsFirewallRules(output []byte) []string {
	return filterLines(output, func(line string) bool {
		return strings.HasPrefix(line, "Rule Name:") ||
			strings.HasPrefix(line, "Enabled:") ||
			strings.HasPrefix(line, "Direction:")
	})
}

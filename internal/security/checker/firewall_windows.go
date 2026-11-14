//go:build windows

// internal/security/checker/firewall_windows.go

package checker

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/papa0four/orkowatch/internal/security/finding"
	"github.com/papa0four/orkowatch/internal/security/registry"
)

type (
	// WindowsFirewallChecker implements FirewallChecker for Windows systems
	WindowsFirewallChecker struct {
		checkIdentity
	}

	// firewallProfile is one Windows Firewall profile and whether it is on.
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
		domain:   "Firewall Configuration",
		analyzes: "firewall configuration and rules",
		osCtx:    osCtx,
	}}
}

// Check implements FirewallChecker interface for Windows systems. Output in
// which no profile state is recognized is concluded as unknown: netsh prints
// localized headings, and reading none of them is not the same as reading
// every profile off.
func (f *WindowsFirewallChecker) Check(ctx context.Context) finding.AuditResult {
	const (
		partialRule registry.FindingKey = "firewall.profile_inactive"
		totalRule   registry.FindingKey = "firewall.all_profiles_disabled"
	)

	r := newReport(f.checkIdentity)

	output, err := exec.CommandContext(ctx, "netsh", "advfirewall", "show", "allprofiles", "state").Output()
	if err != nil {
		r.inconclusive(finding.ResultError,
			fmt.Sprintf("Windows Firewall status could not be read: %v", execError(err)), partialRule, totalRule)
		return r.finish()
	}

	profiles := parseWindowsFirewallStatus(string(output))
	if len(profiles) == 0 {
		r.inconclusive(finding.ResultUnknown,
			"no profile state was recognized in the netsh output", partialRule, totalRule)
		return r.finish()
	}

	var inactive []finding.Evidence
	for _, profile := range profiles {
		if profile.active {
			r.note(finding.SymbolOK, "%s profile is active", profile.name)
			continue
		}
		inactive = append(inactive, evidence(kindProfile, profile.name, "state", "OFF"))
	}

	switch {
	case len(inactive) == 0:
		r.pass(partialRule, totalRule)
	case len(inactive) == len(profiles):
		r.observed(totalRule, inactive...)
		r.inconclusive(finding.ResultNotChecked, "superseded by "+string(totalRule), partialRule)
		return r.finish()
	default:
		r.observed(partialRule, inactive...)
		r.pass(totalRule)
	}

	f.reportRules(ctx, r)
	return r.finish()
}

// reportRules lists the rules the firewall holds, which is worth doing only
// when at least one profile is enforcing them.
func (f *WindowsFirewallChecker) reportRules(ctx context.Context, r *report) {
	output, err := exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "show", "rule", "name=all", "verbose").Output()
	if err != nil {
		r.note(finding.SymbolError, "Error enumerating firewall rules: %v", execError(err))
		return
	}

	r.section("Active Firewall Rules:")
	for _, rule := range parseWindowsFirewallRules(output) {
		r.lines(" " + rule)
	}
}

// parseWindowsFirewallStatus reads the per-profile state from netsh output.
// Each profile's section is headed "<Name> Profile Settings:" and carries a
// "State  ON|OFF" line; the state is read from that line's value field rather
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

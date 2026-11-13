//go:build linux || darwin || freebsd || openbsd || netbsd

// internal/security/checker/firewall_unix.go

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
	// UnixFirewallChecker implements FirewallChecker for Unix-like systems
	UnixFirewallChecker struct {
		checkIdentity
	}

	// firewallState is what a manager reported about its own enforcement.
	// The zero value is firewallUnknown, so a state parser that does not
	// recognize its input reports that it could not tell rather than
	// producing a clean result the host does not support.
	firewallState uint8

	// firewallBackend is the packet filter a manager programs. Two managers
	// that program the same backend are two views of one enforcement point
	// rather than two firewalls, which is why the host is judged by distinct
	// backends rather than by how many commands answered.
	firewallBackend string

	// firewallTool is one firewall manager: the backend it programs, the
	// command that reports whether it is enforcing, the parser for that
	// report, the finding emitted when it is installed but not enforcing, and
	// how to list the rules it holds. rulesArgs is empty for a manager whose
	// state query already lists them, in which case the same output is parsed
	// twice. disabledKey is empty on platforms with no definition for the
	// condition, in which case the state is reported and no finding fires.
	firewallTool struct {
		name        string
		backend     firewallBackend
		stateArgs   []string
		parseState  func([]byte) firewallState
		rulesArgs   []string
		parseRules  func([]byte) []string
		disabledKey registry.FindingKey
	}
)

const (
	firewallUnknown firewallState = iota
	firewallEnforcing
	firewallDisabled
)

// The packet filters a manager can program. ufw(8) manages a netfilter
// firewall and iptables(8) sets up the kernel's packet filter rules, so a host
// running both has one enforcement point reported by two commands; firewalld
// is the same relationship on RHEL-family hosts.
const (
	backendNetfilter firewallBackend = "netfilter"
	backendPF        firewallBackend = "pf"
)

// NewFirewallChecker returns the firewall checker for Unix-like hosts.
func NewFirewallChecker(osCtx registry.OSContext) *UnixFirewallChecker {
	return &UnixFirewallChecker{checkIdentity: checkIdentity{
		domain:   "Firewall Configuration",
		analyzes: "firewall configuration and rules",
		osCtx:    osCtx,
	}}
}

// unixFirewallTools lists the managers the check recognizes. nftables is not
// queried separately: iptables on a modern host is the nf_tables backend
// reached through the legacy command, so asking both reports one rule set
// twice.
func unixFirewallTools() []firewallTool {
	return []firewallTool{
		{
			name:        "iptables",
			backend:     backendNetfilter,
			stateArgs:   []string{"iptables", "-S"},
			parseState:  parseIptablesState,
			parseRules:  parseIptablesRules,
			disabledKey: "firewall.iptables_default_accept",
		},
		{
			name:        "ufw",
			backend:     backendNetfilter,
			stateArgs:   []string{"ufw", "status", "verbose"},
			parseState:  parseUfwState,
			parseRules:  parseUfwRules,
			disabledKey: "firewall.ufw_inactive",
		},
		{
			name:        "firewalld",
			backend:     backendNetfilter,
			stateArgs:   []string{"firewall-cmd", "--state"},
			parseState:  parseFirewalldState,
			rulesArgs:   []string{"firewall-cmd", "--list-all"},
			parseRules:  parseFirewalldRules,
			disabledKey: "firewall.firewalld_not_running",
		},
		{
			name:       "pf",
			backend:    backendPF,
			stateArgs:  []string{"pfctl", "-si"},
			parseState: parsePfState,
			rulesArgs:  []string{"pfctl", "-sr"},
			parseRules: parsePfRules,
		},
	}
}

// Check implements FirewallChecker interface for Unix systems. A manager is
// counted as protecting the host only when it reports that it is enforcing,
// and the host is judged by the distinct backends those managers program
// rather than by how many of them answered, so ufw reporting active over the
// same netfilter rule set iptables reports on is one enforcing firewall.
// A query that fails, or output no parser recognizes, is counted as
// undetermined and reported as such: it is not evidence of protection and
// not evidence of its absence.
func (f *UnixFirewallChecker) Check(ctx context.Context) types.AuditResult {
	result := types.AuditResult{
		Name:        f.Name(),
		Status:      types.StatusChecking,
		Description: f.Description(),
		Details:     make([]string, 0),
		Findings:    make([]types.Finding, 0),
	}

	enforcing := make(map[firewallBackend]struct{})
	var undetermined int
	seen := make(map[registry.FindingKey]struct{})

	for _, tool := range unixFirewallTools() {
		if _, err := exec.LookPath(tool.stateArgs[0]); err != nil {
			continue
		}
		switch f.reportTool(ctx, tool, &result, seen) {
		case firewallEnforcing:
			enforcing[tool.backend] = struct{}{}
		case firewallUnknown:
			undetermined++
		}
	}

	switch {
	case len(enforcing) > 0:
		result.Status = types.StatusCompleted
		if len(enforcing) > 1 {
			result.Details = append(result.Details,
				fmt.Sprintf("%s NOTE: %d independent packet filters are enforcing - verify their rule sets do not conflict",
					types.SymbolInfo, len(enforcing)))
		}
	case undetermined > 0:
		result.Status = types.StatusWarning
		result.Description = "Firewall state could not be fully determined"
		result.Details = append(result.Details,
			fmt.Sprintf("%s Firewall state undetermined: rerun with elevated privileges for a definitive result",
				types.SymbolInfo))
	default:
		result.Status = types.StatusWarning
		result.Description = "No firewall is enforcing on this host"
		result.Details = append(result.Details,
			fmt.Sprintf("%s WARNING: No enforcing firewall detected", types.SymbolWarning))
		emitFindingOnce(&result, f.osCtx, "firewall.no_active_manager", seen)
	}

	return result
}

// reportTool queries one manager and records what it reported, returning the
// state so the caller can judge the host as a whole.
func (f *UnixFirewallChecker) reportTool(ctx context.Context, tool firewallTool, result *types.AuditResult, seen map[registry.FindingKey]struct{}) firewallState {
	output, err := exec.CommandContext(ctx, tool.stateArgs[0], tool.stateArgs[1:]...).Output() // #nosec G204 -- command and arguments are hardcoded literals in unixFirewallTools
	if err != nil {
		result.Details = append(result.Details,
			fmt.Sprintf("%s %s is installed but its state could not be determined: %v",
				types.SymbolWarning, tool.name, execError(err)))
		return firewallUnknown
	}

	state := tool.parseState(output)
	switch state {
	case firewallEnforcing:
		result.Details = append(result.Details,
			fmt.Sprintf("%s %s is enforcing", types.SymbolOK, tool.name))
		f.reportRules(ctx, tool, output, result)
	case firewallDisabled:
		result.Details = append(result.Details,
			fmt.Sprintf("%s WARNING: %s is installed but not enforcing", types.SymbolWarning, tool.name))
		if tool.disabledKey != "" {
			emitFindingOnce(result, f.osCtx, tool.disabledKey, seen)
		}
	default:
		result.Details = append(result.Details,
			fmt.Sprintf("%s %s state could not be determined from its output", types.SymbolWarning, tool.name))
	}

	return state
}

// reportRules lists what an enforcing manager holds. A manager whose state
// query already produced the listing is not queried twice.
func (f *UnixFirewallChecker) reportRules(ctx context.Context, tool firewallTool, stateOutput []byte, result *types.AuditResult) {
	output := stateOutput
	if len(tool.rulesArgs) > 0 {
		listed, err := exec.CommandContext(ctx, tool.rulesArgs[0], tool.rulesArgs[1:]...).Output() // #nosec G204 -- command and arguments are hardcoded literals in unixFirewallTools
		if err != nil {
			result.Details = append(result.Details,
				fmt.Sprintf("%s %s rules could not be listed: %v", types.SymbolInfo, tool.name, execError(err)))
			return
		}
		output = listed
	}

	rules := tool.parseRules(output)
	if len(rules) == 0 {
		result.Details = append(result.Details,
			fmt.Sprintf("%s %s reported no rules", types.SymbolInfo, tool.name))
		return
	}
	result.Details = append(result.Details, rules...)
}

// parseIptablesState judges ingress filtering from iptables -S, whose output
// states every chain policy and every rule one per line. A default ACCEPT
// policy on INPUT with no INPUT rules admits all ingress traffic, which is
// the absence of a host firewall however many rules other chains hold.
func parseIptablesState(output []byte) firewallState {
	var policy string
	var inputRules int

	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[1] != "INPUT" {
			continue
		}
		switch {
		case fields[0] == "-P" && len(fields) == 3:
			policy = fields[2]
		case fields[0] == "-A":
			inputRules++
		}
	}

	switch {
	case policy == "":
		return firewallUnknown
	case policy == "DROP" || policy == "REJECT", inputRules > 0:
		return firewallEnforcing
	default:
		return firewallDisabled
	}
}

// parseIptablesRules keeps the policy and rule lines of iptables -S. Each
// already names its chain, so the listing needs no reassembly and carries no
// column headers to discard.
func parseIptablesRules(output []byte) []string {
	return filterLines(output, func(line string) bool {
		return strings.HasPrefix(line, "-")
	})
}

// parseUfwState reads the Status field ufw reports, measured on Ubuntu
// 22.04 as the single line "Status: inactive" when ufw is off.
func parseUfwState(output []byte) firewallState {
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] != "Status:" {
			continue
		}
		switch strings.ToLower(fields[1]) {
		case "active":
			return firewallEnforcing
		case "inactive":
			return firewallDisabled
		}
	}
	return firewallUnknown
}

// parseUfwRules keeps the lines that state a rule's action. All four ufw
// actions are matched: a REJECT or LIMIT rule is a rule.
func parseUfwRules(output []byte) []string {
	return filterLines(output, func(line string) bool {
		return strings.Contains(line, "ALLOW") || strings.Contains(line, "DENY") ||
			strings.Contains(line, "REJECT") || strings.Contains(line, "LIMIT")
	})
}

// parseFirewalldState reads firewall-cmd --state. Not verified against a
// live firewalld host, so anything but the documented running reply is
// reported as undetermined rather than guessed at; the command also exits
// nonzero when the daemon is stopped, which the caller reports before this
// parser is reached.
func parseFirewalldState(output []byte) firewallState {
	switch strings.TrimSpace(string(output)) {
	case "running":
		return firewallEnforcing
	case "not running":
		return firewallDisabled
	default:
		return firewallUnknown
	}
}

// parseFirewalldRules keeps the zone's service and port lists.
func parseFirewalldRules(output []byte) []string {
	return filterLines(output, func(line string) bool {
		return strings.Contains(line, "services:") || strings.Contains(line, "ports:")
	})
}

// parsePfState reads the status pfctl -si reports. Not verified against a
// live BSD or macOS host, so anything that does not match is reported as
// undetermined rather than guessed at.
func parsePfState(output []byte) firewallState {
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "Status:" {
			continue
		}
		switch strings.ToLower(fields[1]) {
		case "enabled":
			return firewallEnforcing
		case "disabled":
			return firewallDisabled
		}
	}
	return firewallUnknown
}

// parsePfRules keeps rule lines, dropping blanks and comments.
func parsePfRules(output []byte) []string {
	return filterLines(output, func(line string) bool {
		return line != "" && !strings.HasPrefix(line, "#")
	})
}

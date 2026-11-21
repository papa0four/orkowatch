//go:build linux

// internal/security/checker/firewall_linux.go

package checker

import "strings"

// The packet filter a Linux manager programs. ufw(8) manages a netfilter
// firewall and iptables(8) sets up the kernel's packet filter rules, so a host
// running both has one enforcement point reported by two commands; firewalld
// is the same relationship on RHEL-family hosts.
const backendNetfilter firewallBackend = "netfilter"

// firewallTools lists the managers the check recognizes on Linux. nftables is
// not queried separately: iptables on a modern host is the nf_tables backend
// reached through the legacy command, so asking both reports one rule set
// twice.
func firewallTools() []firewallTool {
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
	}
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

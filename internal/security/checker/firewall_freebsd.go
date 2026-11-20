//go:build freebsd

// internal/security/checker/firewall_freebsd.go

package checker

import "strings"

// The packet filter a FreeBSD manager programs.
const backendPF firewallBackend = "pf"

// firewallTools lists the managers the check recognizes on FreeBSD.
func firewallTools() []firewallTool {
	return []firewallTool{
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

//go:build freebsd

// internal/security/checker/firewall_freebsd.go

package checker

import (
	"errors"
	"io/fs"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// The packet filters FreeBSD ships, each its own enforcement point.
const (
	backendPF       firewallBackend = "pf"
	backendIPFW     firewallBackend = "ipfw"
	backendIPFilter firewallBackend = "ipfilter"
)

// ipfwEnable and ipfwDefaultToAccept are the sysctls that say whether ipfw
// filters and what its default rule does; any account can read them, where
// only root can list its rules. ipfwDefaultRule is the number ipfw(8)
// reserves for the default rule, which every listing ends with.
const (
	ipfwEnable          = "net.inet.ip.fw.enable"
	ipfwDefaultToAccept = "net.inet.ip.fw.default_to_accept"
	ipfwDefaultRule     = "65535"
)

// firewallTools lists the managers the check recognizes on FreeBSD. Each is a
// kernel module, so each says how to tell it is loaded.
func firewallTools() []firewallTool {
	return []firewallTool{
		{
			name:       "pf",
			backend:    backendPF,
			loaded:     deviceLoaded("/dev/pf"),
			stateArgs:  []string{"pfctl", "-si"},
			parseState: parsePfState,
			rulesArgs:  []string{"pfctl", "-sr"},
			parseRules: parseListedRules,
		},
		{
			name:       "ipfw",
			backend:    backendIPFW,
			loaded:     ipfwLoaded,
			stateArgs:  []string{"sysctl", ipfwEnable, ipfwDefaultToAccept},
			parseState: parseIpfwState,
			rulesArgs:  []string{"ipfw", "list"},
			parseRules: parseIpfwRules,
		},
		{
			name:       "ipfilter",
			backend:    backendIPFilter,
			loaded:     deviceLoaded("/dev/ipl"),
			stateArgs:  []string{"ipf", "-V"},
			parseState: parseIpfState,
			rulesArgs:  []string{"ipfstat", "-io"},
			parseRules: parseListedRules,
		},
	}
}

// deviceLoaded reports a filter loaded while its device node exists: the
// module creates it on load and removes it on unload. A node that cannot be
// examined for another reason is taken as present, so the filter's own
// commands decide.
func deviceLoaded(path string) func() bool {
	return func() bool {
		_, err := os.Stat(path)
		return !errors.Is(err, fs.ErrNotExist)
	}
}

// ipfwLoaded reports ipfw loaded while its sysctl exists. ipfw has no device
// node, and its sysctl names are unknown until the module loads.
func ipfwLoaded() bool {
	_, err := unix.SysctlUint32(ipfwEnable)
	return !errors.Is(err, unix.ENOENT)
}

// parsePfState reads the status pfctl -si reports. An enabled pf filters only
// by its rules: with none, every packet passes.
func parsePfState(output []byte) firewallState {
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "Status:" {
			continue
		}
		switch fields[1] {
		case "Enabled":
			return firewallEnabled
		case "Disabled":
			return firewallDisabled
		}
	}
	return firewallUnknown
}

// parseListedRules keeps the rules of a listing that prints nothing else, one
// per line. pfctl -sr and ipfstat -io both do: ipfstat prints an empty list's
// notice on stderr, which is not read.
func parseListedRules(output []byte) []string {
	return filterLines(output, func(line string) bool { return line != "" })
}

// parseIpfwState reads the two sysctls. An enabled ipfw whose default rule
// denies filters without other rules; one whose default rule accepts filters
// only by the rules ahead of it.
func parseIpfwState(output []byte) firewallState {
	values := make(map[string]string)
	for _, line := range strings.Split(string(output), "\n") {
		if name, value, ok := strings.Cut(line, ":"); ok {
			values[strings.TrimSpace(name)] = strings.TrimSpace(value)
		}
	}
	switch {
	case values[ipfwEnable] == "0":
		return firewallDisabled
	case values[ipfwEnable] != "1":
		return firewallUnknown
	case values[ipfwDefaultToAccept] == "0":
		return firewallEnforcing
	case values[ipfwDefaultToAccept] == "1":
		return firewallEnabled
	}
	return firewallUnknown
}

// parseIpfwRules keeps the rules ipfw list shows ahead of the default rule.
// The default rule's action is read from its sysctl, and the counter ipfw
// lists under the same number is not a rule anyone wrote.
func parseIpfwRules(output []byte) []string {
	return filterLines(output, func(line string) bool {
		return line != "" && !strings.HasPrefix(line, ipfwDefaultRule+" ")
	})
}

// parseIpfState reads whether ipf -V reports the filter running. A running
// ipfilter filters only by its rules: its default passes all.
func parseIpfState(output []byte) firewallState {
	for _, line := range strings.Split(string(output), "\n") {
		name, value, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(name) != "Running" {
			continue
		}
		switch strings.TrimSpace(value) {
		case "yes":
			return firewallEnabled
		case "no":
			return firewallDisabled
		}
	}
	return firewallUnknown
}

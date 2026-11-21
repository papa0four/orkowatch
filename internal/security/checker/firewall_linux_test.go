//go:build linux

// internal/security/checker/firewall_linux_test.go

package checker

import (
	"slices"
	"testing"

	"github.com/papa0four/orkowatch/internal/security/registry"
)

// What iptables 1.8.7 and ufw 0.36.1 printed on Ubuntu 22.04 in each state.
const (
	iptablesNoRules     = "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n"
	iptablesDropPolicy  = "-P INPUT DROP\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n"
	iptablesInputRule   = "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n-A INPUT -p tcp -m tcp --dport 22 -j DROP\n"
	iptablesForwardRule = "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n-A FORWARD -j DROP\n"

	ufwInactive = "Status: inactive\n"
	ufwActive   = `Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), deny (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
23/tcp                     DENY IN     Anywhere
25/tcp                     REJECT IN   Anywhere
2222/tcp                   LIMIT IN    Anywhere
22/tcp (v6)                ALLOW IN    Anywhere (v6)

`
)

// iptables enforces with a policy that drops or with a rule on INPUT, and a
// rule on another chain is not one; ufw says so itself. The firewalld replies
// are the two its parser names, not captured from a host.
func TestLinuxFirewallStates(t *testing.T) {
	for _, tc := range []struct {
		name   string
		parse  func([]byte) firewallState
		output string
		want   firewallState
	}{
		{"iptables no rules", parseIptablesState, iptablesNoRules, firewallDisabled},
		{"iptables drop policy", parseIptablesState, iptablesDropPolicy, firewallEnforcing},
		{"iptables input rule", parseIptablesState, iptablesInputRule, firewallEnforcing},
		{"iptables forward rule only", parseIptablesState, iptablesForwardRule, firewallDisabled},
		{"iptables no policy", parseIptablesState, "", firewallUnknown},
		{"ufw inactive", parseUfwState, ufwInactive, firewallDisabled},
		{"ufw active", parseUfwState, ufwActive, firewallEnforcing},
		{"ufw no status", parseUfwState, "", firewallUnknown},
		{"firewalld running", parseFirewalldState, "running\n", firewallEnforcing},
		{"firewalld not running", parseFirewalldState, "not running\n", firewallDisabled},
		{"firewalld other", parseFirewalldState, "", firewallUnknown},
	} {
		if got := tc.parse([]byte(tc.output)); got != tc.want {
			t.Errorf("%s: state %d, want %d", tc.name, got, tc.want)
		}
	}
}

// The rules kept are iptables' policy and rule lines and ufw's lines that
// state an action: its Default line states policies in lower case and is not
// one.
func TestLinuxFirewallRules(t *testing.T) {
	for _, tc := range []struct {
		name   string
		parse  func([]byte) []string
		output string
		want   []string
	}{
		{"iptables", parseIptablesRules, iptablesDropPolicy, []string{
			"-P INPUT DROP", "-P FORWARD ACCEPT", "-P OUTPUT ACCEPT", "-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT",
		}},
		{"ufw inactive", parseUfwRules, ufwInactive, []string{}},
		{"ufw active", parseUfwRules, ufwActive, []string{
			"22/tcp                     ALLOW IN    Anywhere",
			"23/tcp                     DENY IN     Anywhere",
			"25/tcp                     REJECT IN   Anywhere",
			"2222/tcp                   LIMIT IN    Anywhere",
			"22/tcp (v6)                ALLOW IN    Anywhere (v6)",
		}},
	} {
		if got := tc.parse([]byte(tc.output)); !slices.Equal(got, tc.want) {
			t.Errorf("%s: rules %q, want %q", tc.name, got, tc.want)
		}
	}
}

// Every Linux manager names the rule it is judged by, and Linux defines it:
// a result recorded against an undefined key panics.
func TestLinuxFirewallToolKeysAreDefined(t *testing.T) {
	linux := registry.OSContext{Platform: registry.PlatformLinux, Families: []registry.Distro{registry.DistroGeneric}}
	for _, tool := range firewallTools() {
		if _, ok := registry.Lookup(linux, tool.disabledKey); !ok {
			t.Errorf("%s: rule key %q is not defined for Linux", tool.name, tool.disabledKey)
		}
	}
}

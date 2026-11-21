//go:build freebsd

// internal/security/checker/firewall_freebsd_test.go

package checker

import (
	"slices"
	"testing"
)

// Each FreeBSD filter's state is read from what its query printed on
// FreeBSD 15.1, and an enabled pf or a running ipfilter is enabled, not
// enforcing, since with no rules each passed every packet.
func TestFreeBSDFirewallStates(t *testing.T) {
	for _, tc := range []struct {
		name   string
		parse  func([]byte) firewallState
		output string
		want   firewallState
	}{
		{"pf enabled", parsePfState, "Status: Enabled for 0 days 00:00:00           Debug: Urgent\n\nState Table                          Total             Rate\n", firewallEnabled},
		{"pf disabled", parsePfState, "Status: Disabled for 0 days 00:02:08          Debug: Urgent\n\n", firewallDisabled},
		{"pf no status", parsePfState, "", firewallUnknown},
		{"ipfw default denies", parseIpfwState, "net.inet.ip.fw.enable: 1\nnet.inet.ip.fw.default_to_accept: 0\n", firewallEnforcing},
		{"ipfw default accepts", parseIpfwState, "net.inet.ip.fw.enable: 1\nnet.inet.ip.fw.default_to_accept: 1\n", firewallEnabled},
		{"ipfw disabled", parseIpfwState, "net.inet.ip.fw.enable: 0\nnet.inet.ip.fw.default_to_accept: 0\n", firewallDisabled},
		{"ipfw enable only", parseIpfwState, "net.inet.ip.fw.enable: 1\n", firewallUnknown},
		{"ipf running", parseIpfState, "ipf: IP Filter: v5.1.2 (584)\nKernel: IP Filter: v5.1.2               \nRunning: yes\nLog Flags: 0 = none set\nDefault: pass all, Logging: available\n", firewallEnabled},
		{"ipf not running", parseIpfState, "ipf: IP Filter: v5.1.2 (584)\nKernel: IP Filter: v5.1.2               \nRunning: no\nLog Flags: 0 = none set\n", firewallDisabled},
		{"ipf no kernel", parseIpfState, "ipf: IP Filter: v5.1.2 (584)\n", firewallUnknown},
	} {
		if got := tc.parse([]byte(tc.output)); got != tc.want {
			t.Errorf("%s: state %d, want %d", tc.name, got, tc.want)
		}
	}
}

// Each FreeBSD filter's rules are the lines its listing printed on FreeBSD
// 15.1, and ipfw's default rule and the counter numbered with it are not
// among them.
func TestFreeBSDFirewallRules(t *testing.T) {
	for _, tc := range []struct {
		name   string
		parse  func([]byte) []string
		output string
		want   []string
	}{
		{"pf none", parsePfRules, "", []string{}},
		{"pf rules", parsePfRules, "block drop in all\npass out all flags S/SA keep state\n", []string{"block drop in all", "pass out all flags S/SA keep state"}},
		{"ipfw default only", parseIpfwRules, "65535 count ip from any to any not // orphaned dynamic states counter\n65535 deny ip from any to any\n", []string{}},
		{"ipfw a rule ahead", parseIpfwRules, "00100 allow ip from any to any\n65535 count ip from any to any not // orphaned dynamic states counter\n65535 deny ip from any to any\n", []string{"00100 allow ip from any to any"}},
		{"ipf none", parseIpfRules, "", []string{}},
		{"ipf rules", parseIpfRules, "pass out all\nblock in quick proto tcp from any to any port = ssh\npass in all\n", []string{"pass out all", "block in quick proto tcp from any to any port = ssh", "pass in all"}},
	} {
		if got := tc.parse([]byte(tc.output)); !slices.Equal(got, tc.want) {
			t.Errorf("%s: rules %q, want %q", tc.name, got, tc.want)
		}
	}
}

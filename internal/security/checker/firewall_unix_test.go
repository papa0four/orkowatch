//go:build linux || darwin || freebsd || openbsd || netbsd

// internal/security/checker/firewall_unix_test.go

package checker

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/papa0four/orkowatch/internal/security/finding"
)

// A filter not loaded is absent, and an enabled filter is enforcing only when
// it holds rules: with none it is not enforcing, and with rules that cannot be
// listed it is undetermined. A tool with no rule of its own narrates each.
func TestReportToolEnabledAndNotLoaded(t *testing.T) {
	enabled := func([]byte) firewallState { return firewallEnabled }
	lines := func(out []byte) []string { return strings.Fields(string(out)) }

	for _, tc := range []struct {
		name      string
		tool      firewallTool
		wantState firewallState
		wantLine  string
	}{
		{
			name:      "not loaded",
			tool:      firewallTool{name: "x", loaded: func() bool { return false }, stateArgs: []string{"printf", "on"}, parseState: enabled},
			wantState: firewallAbsent,
			wantLine:  finding.SymbolInfo + " x is not loaded",
		},
		{
			name:      "enabled, no rules",
			tool:      firewallTool{name: "x", stateArgs: []string{"printf", "on"}, parseState: enabled, rulesArgs: []string{"printf", ""}, parseRules: lines},
			wantState: firewallDisabled,
			wantLine:  finding.SymbolWarning + " x: enabled, no rules",
		},
		{
			name:      "enabled with a rule",
			tool:      firewallTool{name: "x", stateArgs: []string{"printf", "on"}, parseState: enabled, rulesArgs: []string{"printf", "block"}, parseRules: lines},
			wantState: firewallEnforcing,
			wantLine:  "block",
		},
		{
			name:      "enabled, rules not listed",
			tool:      firewallTool{name: "x", stateArgs: []string{"printf", "on"}, parseState: enabled, rulesArgs: []string{"false"}, parseRules: lines},
			wantState: firewallUnknown,
			wantLine:  finding.SymbolInfo + " x is enabled but its rules could not be listed: exit status 1",
		},
	} {
		r := newReport(checkIdentity{})
		got := (&UnixFirewallChecker{}).reportTool(context.Background(), tc.tool, finding.Evidence{}, r)
		if got.state != tc.wantState {
			t.Errorf("%s: state %d, want %d", tc.name, got.state, tc.wantState)
		}
		if !slices.Contains(r.result.Details, tc.wantLine) {
			t.Errorf("%s: details %q lack %q", tc.name, r.result.Details, tc.wantLine)
		}
	}
}

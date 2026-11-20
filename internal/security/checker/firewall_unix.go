//go:build linux || darwin || freebsd || openbsd || netbsd

// internal/security/checker/firewall_unix.go

package checker

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/papa0four/orkowatch/internal/security/finding"
	"github.com/papa0four/orkowatch/internal/security/registry"
)

type (
	// UnixFirewallChecker implements FirewallChecker for Unix-like systems.
	// listeners returns the host's sockets, from which where the host
	// listens is recorded.
	UnixFirewallChecker struct {
		checkIdentity
		listeners ListenersFunc
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

	// toolOutcome is what querying one manager established. state is
	// firewallUnknown when the query failed or its output was not
	// recognized, in which case result and reason say which.
	toolOutcome struct {
		state  firewallState
		result finding.Result
		reason string
	}
)

const (
	firewallUnknown firewallState = iota
	firewallEnforcing
	firewallDisabled
)

// NewFirewallChecker returns the firewall checker for Unix-like hosts.
func NewFirewallChecker(osCtx registry.OSContext, listeners ListenersFunc) *UnixFirewallChecker {
	return &UnixFirewallChecker{
		checkIdentity: checkIdentity{
			domain:   "Firewall Configuration",
			analyzes: "firewall configuration and rules",
			osCtx:    osCtx,
		},
		listeners: listeners,
	}
}

// Check implements FirewallChecker interface for Unix systems. A manager is
// counted as protecting the host only when it reports that it is enforcing,
// and the host is judged by the distinct backends those managers program
// rather than by how many of them answered, so ufw reporting active over the
// same netfilter rule set iptables reports on is one enforcing firewall.
// A query that fails, or output no parser recognizes, is concluded as such:
// it is not evidence of protection and not evidence of its absence.
func (f *UnixFirewallChecker) Check(ctx context.Context) finding.AuditResult {
	const hostRule registry.FindingKey = "firewall.no_active_manager"

	r := newReport(f.checkIdentity)
	enforcing := make(map[firewallBackend]struct{})
	var undetermined toolOutcome
	reach := hostListening(r, f.listeners(ctx))

	for _, tool := range firewallTools() {
		if _, err := exec.LookPath(tool.stateArgs[0]); err != nil {
			r.inconclusive(finding.ResultNotApplicable, tool.name+" is not installed", tool.disabledKey)
			continue
		}
		outcome := f.reportTool(ctx, tool, reach, r)
		switch {
		case outcome.state == firewallEnforcing:
			enforcing[tool.backend] = struct{}{}
		case outcome.state == firewallUnknown && undetermined.reason == "":
			undetermined = outcome
		}
	}

	switch {
	case len(enforcing) > 0:
		r.pass(hostRule)
		if len(enforcing) > 1 {
			r.note(finding.SymbolInfo, "NOTE: %d independent packet filters are enforcing - verify their rule sets do not conflict",
				len(enforcing))
		}
	case undetermined.reason != "":
		r.inconclusive(undetermined.result,
			undetermined.reason+"; rerun with elevated privileges for a definitive result", hostRule)
	default:
		r.observed(hostRule, reach)
	}

	return r.finish()
}

// reportTool queries one manager and concludes its rule, returning what it
// learned so the caller can judge the host as a whole. A failed query is an
// error and unrecognized output is unknown: the first could not look, the
// second looked and could not tell. A manager not enforcing is recorded with
// reach, where the host listens.
func (f *UnixFirewallChecker) reportTool(ctx context.Context, tool firewallTool, reach finding.Evidence, r *report) toolOutcome {
	output, err := exec.CommandContext(ctx, tool.stateArgs[0], tool.stateArgs[1:]...).Output() // #nosec G204 -- command and arguments are hardcoded literals in each platform's firewallTools
	if err != nil {
		outcome := toolOutcome{
			result: finding.ResultError,
			reason: fmt.Sprintf("%s is installed but its state could not be determined: %v", tool.name, execError(err)),
		}
		r.inconclusive(outcome.result, outcome.reason, tool.disabledKey)
		return outcome
	}

	switch state := tool.parseState(output); state {
	case firewallEnforcing:
		r.pass(tool.disabledKey)
		r.note(finding.SymbolOK, "%s is enforcing", tool.name)
		f.reportRules(ctx, tool, output, r)
		return toolOutcome{state: state}
	case firewallDisabled:
		if tool.disabledKey == "" {
			r.note(finding.SymbolWarning, "%s is installed but not enforcing", tool.name)
			return toolOutcome{state: state}
		}
		r.observed(tool.disabledKey, evidence(finding.KindManager, tool.name, fact(finding.FactState, "installed, not enforcing")), reach)
		return toolOutcome{state: state}
	default:
		outcome := toolOutcome{
			result: finding.ResultUnknown,
			reason: tool.name + " state could not be determined from its output",
		}
		r.inconclusive(outcome.result, outcome.reason, tool.disabledKey)
		return outcome
	}
}

// reportRules lists what an enforcing manager holds. A manager whose state
// query already produced the listing is not queried twice.
func (f *UnixFirewallChecker) reportRules(ctx context.Context, tool firewallTool, stateOutput []byte, r *report) {
	output := stateOutput
	if len(tool.rulesArgs) > 0 {
		listed, err := exec.CommandContext(ctx, tool.rulesArgs[0], tool.rulesArgs[1:]...).Output() // #nosec G204 -- command and arguments are hardcoded literals in each platform's firewallTools
		if err != nil {
			r.note(finding.SymbolInfo, "%s rules could not be listed: %v", tool.name, execError(err))
			return
		}
		output = listed
	}

	rules := tool.parseRules(output)
	if len(rules) == 0 {
		r.note(finding.SymbolInfo, "%s reported no rules", tool.name)
		return
	}
	r.lines(rules...)
}

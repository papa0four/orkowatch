//go:build linux || freebsd

// internal/security/checker/suaccess.go

// Who su admits to root, set on the accounts from what the su service's
// policy requires and who the group it names holds.

package checker

import (
	"context"
	"fmt"
	"strings"

	"github.com/papa0four/orkowatch/internal/account"
	"github.com/papa0four/orkowatch/internal/security/finding"
	"github.com/papa0four/orkowatch/internal/security/registry"
)

// ruleSUOpen is the rule a su service with no group requirement trips.
const ruleSUOpen registry.FindingKey = "users.su_unrestricted"

// groupLookup returns one group's entry from the group database, and no
// entry for a group the database does not hold.
type groupLookup func(ctx context.Context, group string) ([]byte, error)

// suRules are the rules decided by what the su service requires.
func suRules() []registry.FindingKey {
	return []registry.FindingKey{platformRules.suMember, ruleSUOpen}
}

// applySUGate sets on each account the group by which su admits it to root,
// and records what the policy in file leaves without a judgment. A group the
// policy names and the host does not have is left unknown: who su admits
// then was not observed.
func (h *hostAccounts) applySUGate(ctx context.Context, file string, gate suGate, lookup groupLookup) {
	unknown := func(reason string) {
		h.unjudged = append(h.unjudged, unjudged{rules: suRules(), result: finding.ResultUnknown, reason: reason})
	}

	switch {
	case gate.undecided != "":
		unknown(gate.undecided)
		return
	case gate.open:
		h.hostwide = append(h.hostwide, observation{rule: ruleSUOpen, evidence: evidence(finding.KindFile, file)})
		h.unjudged = append(h.unjudged, unjudged{
			rules:  []registry.FindingKey{platformRules.suMember},
			result: finding.ResultNotApplicable,
			reason: file + " requires no group of an account that asks for root",
		})
		return
	case !isSafeUsername(gate.group) || strings.HasPrefix(gate.group, "-"):
		unknown(fmt.Sprintf("the group %q that %s names is not a name passed to %s", gate.group, file, account.GetentProgram))
		return
	}

	entry, err := lookup(ctx, gate.group)
	switch {
	case err != nil:
		h.unjudged = append(h.unjudged, unjudged{rules: suRules(), result: finding.ResultError, reason: err.Error()})
		return
	case entry == nil:
		unknown(fmt.Sprintf("the group %s that %s names does not exist", gate.group, file))
		return
	}

	groups := newPrivilegedGroups()
	groups.add(entry)
	for i := range h.accounts {
		h.accounts[i].suGroup = groups.groupOf(h.accounts[i])
	}
}

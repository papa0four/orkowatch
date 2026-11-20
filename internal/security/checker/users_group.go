//go:build darwin || openbsd || netbsd

// internal/security/checker/users_group.go

// What the readers that decide administrative accounts by group membership
// share: macOS by the admin group, OpenBSD and NetBSD by wheel.

package checker

import (
	"fmt"

	"github.com/papa0four/orkowatch/internal/security/finding"
	"github.com/papa0four/orkowatch/internal/security/registry"
)

// privilegeRules are the rules on administrative access these readers judge.
var privilegeRules = []registry.FindingKey{ruleAdminAccount}

// platformRules names no rule: these platforms define none yet, and a rule
// is named here when a platform's definitions gain it.
var platformRules platformRuleSet

// groupLookupFailed is the gap left when the membership could not be read.
func groupLookupFailed(err error) unjudged {
	return unjudged{
		rules:  privilegeRules,
		result: finding.ResultError,
		reason: fmt.Sprintf("privileged group membership could not be determined: %v", err),
	}
}

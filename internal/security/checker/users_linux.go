//go:build linux

// internal/security/checker/users_linux.go

package checker

import (
	"context"
	"strings"
)

const (
	// uidRangeFile configures the range useradd assigns to regular accounts.
	// The defaults are the ones login.defs(5) documents for a missing key.
	uidRangeFile  = "/etc/login.defs"
	defaultUIDMin = 1000
	defaultUIDMax = 60000

	// loginDefsFields is the key and value a login.defs setting consists of.
	loginDefsFields = 2

	// credentialStore holds the password field of every local account.
	credentialStore = "/etc/shadow"
)

// privilegeRules are the rules on administrative access the Linux reader
// judges.
var privilegeRules = sudoRules

// platformRules are the rules of platformRuleSet Linux defines.
var platformRules = platformRuleSet{rootUnlocked: ruleRootUnlocked}

// unusablePrefixes begin a shadow password field that passwd -l locked or
// that was never assigned.
var unusablePrefixes = []string{"!", "*"}

// regularUIDRange returns the range login.defs assigns to regular accounts,
// from the content of the file. An account above UID_MAX is as much a system
// account as one below UID_MIN: nobody and the identifiers services allocate
// for themselves sit there. A missing file or key leaves the documented
// default in place.
func regularUIDRange(conf []byte) uidRange {
	regular := uidRange{min: defaultUIDMin, max: defaultUIDMax}

	for _, line := range strings.Split(string(conf), "\n") {
		fields := strings.Fields(line)
		if len(fields) < loginDefsFields {
			continue
		}
		value, ok := parseUnixID(fields[1])
		if !ok {
			continue
		}
		switch fields[0] {
		case "UID_MIN":
			regular.min = value
		case "UID_MAX":
			regular.max = value
		}
	}
	return regular
}

// readHostAccounts reads /etc/passwd and, when readable, /etc/shadow, and
// resolves who is administrative from what the host lets this run see.
func readHostAccounts(ctx context.Context) (hostAccounts, error) {
	return readStoredAccounts(ctx)
}

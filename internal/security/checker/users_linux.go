//go:build linux

// internal/security/checker/users_linux.go

package checker

import (
	"context"
	"os"
	"strings"
)

const (
	// loginDefsFile configures the range useradd assigns to regular accounts.
	// The defaults are the ones login.defs(5) documents for a missing key.
	loginDefsFile = "/etc/login.defs"
	defaultUIDMin = 1000
	defaultUIDMax = 60000

	// loginDefsFields is the key and value a login.defs setting consists of.
	loginDefsFields = 2

	// credentialStore holds the password field of every local account.
	credentialStore = "/etc/shadow"

	// credentialsUnread is why the credential rules have no judgment when
	// the store could not be opened.
	credentialsUnread = credentialStore + " is not readable without elevated privileges"
)

// privilegeRules are the rules on administrative access the Linux reader
// judges.
var privilegeRules = sudoRules

// platformRules are the rules of platformRuleSet Linux defines.
var platformRules = platformRuleSet{rootUnlocked: "users.root_account_unlocked"}

// unusablePrefixes begin a shadow password field that passwd -l locked or
// that was never assigned.
var unusablePrefixes = []string{"!", "*"}

// regularUIDRange returns the range login.defs assigns to regular accounts.
// An account above UID_MAX is as much a system account as one below UID_MIN:
// nobody and the identifiers services allocate for themselves sit there. A
// missing file or key leaves the documented default in place.
func regularUIDRange() uidRange {
	regular := uidRange{min: defaultUIDMin, max: defaultUIDMax}

	data, err := os.ReadFile(loginDefsFile)
	if err != nil {
		return regular
	}

	for _, line := range strings.Split(string(data), "\n") {
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

// getUsers reads /etc/passwd and, when readable, /etc/shadow, and resolves
// who is administrative from what the host lets this run see.
func (u *UnixUserChecker) getUsers(ctx context.Context) ([]userAccount, error) {
	users, err := localAccounts()
	if err != nil {
		return nil, err
	}

	credentials, read, err := readCredentials(credentialStore)
	if err != nil {
		return nil, err
	}
	u.credentialsRead = read

	regular := regularUIDRange()
	for i := range users {
		account := &users[i]
		account.isSystem = !regular.contains(account.uid)

		if field, ok := credentials[account.username]; ok {
			account.password = credentialState(field)
		}
	}

	u.readPrivilege(ctx, hostPrivilegeSources(), users)
	return users, nil
}

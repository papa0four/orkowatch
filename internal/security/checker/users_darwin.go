//go:build darwin

// internal/security/checker/users_darwin.go

package checker

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

const (
	// minRegularUID is the first UID Directory Services assigns to a regular
	// account.
	minRegularUID = 500

	// dsclFields is the attribute name and value a dscl read line consists of.
	dsclFields = 2
)

// getUsers enumerates accounts through Directory Services, resolving
// administrative membership from the admin group and account state from
// each record's AuthenticationAuthority. An account whose record or state
// cannot be read is counted and reported rather than dropped in silence.
func (u *UnixUserChecker) getUsers(ctx context.Context) ([]userAccount, error) {
	output, err := exec.CommandContext(ctx, "dscl", ".", "list", "/Users").Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get macOS users: %w", execError(err))
	}

	admins := u.adminMembers(ctx)

	var users []userAccount
	var unread, stateUnread int
	for _, username := range strings.Split(string(output), "\n") {
		username = strings.TrimSpace(username)
		if username == "" || username[0] == '_' {
			continue
		}

		account, err := readAccount(ctx, username)
		if err != nil {
			unread++
			continue
		}
		account.isSystem = account.uid < minRegularUID
		account.isAdmin = admins[username]

		if state, err := readAccountState(ctx, username); err != nil {
			stateUnread++
		} else {
			account.state = state
		}

		users = append(users, account)
	}

	if unread > 0 {
		u.readWarnings = append(u.readWarnings,
			fmt.Sprintf("%d account records could not be read and are missing from this report", unread))
	}
	if stateUnread > 0 {
		u.readWarnings = append(u.readWarnings,
			fmt.Sprintf("%d accounts have an unreadable authentication state; a disabled account among them is not marked", stateUnread))
	}

	return users, nil
}

// adminMembers returns the members of the admin group. A failed lookup is
// recorded on the checker so the report says membership is unknown rather
// than presenting every account as unprivileged.
func (u *UnixUserChecker) adminMembers(ctx context.Context) map[string]bool {
	members := make(map[string]bool)

	output, err := exec.CommandContext(ctx, "dscacheutil", "-q", "group", "-a", "name", "admin").Output()
	if err != nil {
		u.adminLookupErr = execError(err)
		return members
	}

	for _, line := range strings.Split(string(output), "\n") {
		if list, ok := strings.CutPrefix(line, "users:"); ok {
			for _, member := range strings.Fields(list) {
				members[member] = true
			}
		}
	}
	return members
}

// readAccount reads one account's identity from its directory record.
func readAccount(ctx context.Context, username string) (userAccount, error) {
	if !isSafeUsername(username) {
		return userAccount{}, fmt.Errorf("account %q: name is not safe to pass to dscl", username)
	}

	output, err := exec.CommandContext(ctx, "dscl", ".", "read", "/Users/"+username, // #nosec G204 -- username validated by isSafeUsername above
		"UniqueID", "PrimaryGroupID", "NFSHomeDirectory", "UserShell").Output()
	if err != nil {
		return userAccount{}, execError(err)
	}

	account := userAccount{username: username}
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) < dsclFields {
			continue
		}

		switch fields[0] {
		case "UniqueID:":
			if uid, ok := parseUnixID(fields[1]); ok {
				account.uid = uid
			}
		case "PrimaryGroupID:":
			if gid, ok := parseUnixID(fields[1]); ok {
				account.gid = gid
			}
		case "NFSHomeDirectory:":
			account.homeDir = fields[1]
		case "UserShell:":
			account.shell = fields[1]
		}
	}
	return account, nil
}

// readAccountState reports whether the account's directory record allows it
// to authenticate. The caller has already validated username through
// readAccount.
func readAccountState(ctx context.Context, username string) (accountState, error) {
	output, err := exec.CommandContext(ctx, "dscl", ".", "read", "/Users/"+username, "AuthenticationAuthority").Output() // #nosec G204 -- username validated by isSafeUsername in readAccount
	if err != nil {
		return accountUnknown, execError(err)
	}
	if strings.Contains(string(output), "DisabledUser") {
		return accountDisabled, nil
	}
	return accountEnabled, nil
}

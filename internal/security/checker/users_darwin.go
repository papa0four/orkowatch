//go:build darwin

// internal/security/checker/users_darwin.go

package checker

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// minRegularUID is the first UID Directory Services assigns to a regular
// account.
const minRegularUID = 500

// getUsers enumerates accounts through Directory Services, resolving
// administrative membership from the admin group and account state from
// each record's AuthenticationAuthority.
func (u *UnixUserChecker) getUsers(ctx context.Context) ([]userAccount, error) {
	var users []userAccount

	cmd := exec.CommandContext(ctx, "dscl", ".", "list", "/Users")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get macOS users: %v", err)
	}

	adminUsers := make(map[string]bool)
	adminCmd := exec.CommandContext(ctx, "dscacheutil", "-q", "group", "-a", "name", "admin")
	adminOutput, err := adminCmd.Output()
	if err != nil {
		u.adminLookupErr = execError(err)
	} else {
		for _, line := range strings.Split(string(adminOutput), "\n") {
			if strings.HasPrefix(line, "users:") {
				members := strings.TrimPrefix(line, "users:")
				for _, user := range strings.Fields(members) {
					adminUsers[user] = true
				}
			}
		}
	}

	for _, username := range strings.Split(string(output), "\n") {
		username = strings.TrimSpace(username)
		if username == "" || username[0] == '_' {
			continue
		}

		if !isSafeUsername(username) {
			continue
		}

		infoCmd := exec.CommandContext(ctx, "dscl", ".", "read", "/Users/"+username, // #nosec G204 -- username validated by isSafeUsername before use
			"UniqueID", "PrimaryGroupID", "NFSHomeDirectory", "UserShell")
		infoOutput, err := infoCmd.Output()
		if err != nil {
			continue
		}

		account := userAccount{username: username}

		for _, line := range strings.Split(string(infoOutput), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
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

		account.isSystem = account.uid < minRegularUID
		account.isAdmin = adminUsers[username]

		authCmd := exec.CommandContext(ctx, "dscl", ".", "read", "/Users/"+username, "AuthenticationAuthority") // #nosec G204 -- username validated by isSafeUsername before use
		if authOutput, err := authCmd.Output(); err == nil {
			account.state = accountEnabled
			if strings.Contains(string(authOutput), "DisabledUser") {
				account.state = accountDisabled
			}
		}

		users = append(users, account)
	}

	return users, nil
}

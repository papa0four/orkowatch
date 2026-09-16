//go:build linux

// internal/security/checker/users_linux.go

package checker

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const (
	// minRegularUID is the first UID login.defs assigns to a regular account.
	minRegularUID = 1000

	// shadowMinFields is the fewest fields a usable /etc/shadow line has:
	// the account name and its password field.
	shadowMinFields = 2

	// /etc/group field indices and minimum field count as defined by POSIX.
	groupFieldMembers = 3
	groupFieldCount   = 4
)

// shadowPasswordState classifies the password field of a shadow entry. A
// field beginning with ! or * was locked by passwd -l or never assigned; an
// empty field admits a login with no credential at all.
func shadowPasswordState(field string) passwordState {
	switch {
	case field == "":
		return passwordEmpty
	case strings.HasPrefix(field, "!"), strings.HasPrefix(field, "*"):
		return passwordLocked
	default:
		return passwordSet
	}
}

// addGroupMembers records the members listed in POSIX group-database entries
// into members. An entry is name:password:gid:comma-separated-members; a line
// with fewer fields is skipped rather than treated as a group with no members.
func addGroupMembers(output []byte, members map[string]bool) {
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < groupFieldCount {
			continue
		}
		for _, member := range strings.Split(fields[groupFieldMembers], ",") {
			if name := strings.TrimSpace(member); name != "" {
				members[name] = true
			}
		}
	}
}

// privilegedGroupMembers returns the union of the members of the groups that
// confer administrative access. Each group is queried independently so one
// that does not exist on this distribution does not discard the members of the
// ones that do. The error is non-nil only when no group could be read at all,
// which is the case a caller must not mistake for a host with no
// administrators.
func (u *UnixUserChecker) privilegedGroupMembers(ctx context.Context) (map[string]bool, error) {
	members := make(map[string]bool)
	var read int
	var lastErr error

	for _, group := range []string{"sudo", "wheel", "admin"} {
		output, err := exec.CommandContext(ctx, "getent", "group", group).Output() // #nosec G204 -- group names are hardcoded literals, not user input
		if err != nil {
			lastErr = execError(err)
			continue
		}
		read++
		addGroupMembers(output, members)
	}

	if read == 0 {
		return members, lastErr
	}

	return members, nil
}

// getUsers reads /etc/passwd and, when readable, /etc/shadow, and resolves
// administrative membership through the privileged groups.
func (u *UnixUserChecker) getUsers(ctx context.Context) ([]userAccount, error) {
	var users []userAccount

	passwdFile, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, err
	}
	defer passwdFile.Close() //nolint:errcheck // read-only passwd file; close error does not affect scan results

	shadowEntries := make(map[string]string)
	if shadow, err := os.Open("/etc/shadow"); err == nil {
		u.shadowReadable = true
		defer shadow.Close() //nolint:errcheck // read-only shadow file; close error does not affect scan results
		scanner := bufio.NewScanner(shadow)
		for scanner.Scan() {
			fields := strings.Split(scanner.Text(), ":")
			if len(fields) >= shadowMinFields {
				shadowEntries[fields[passwdFieldUsername]] = fields[passwdFieldPassword]
			}
		}

		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("error reading /etc/shadow: %w", err)
		}
	}

	sudoers, err := u.privilegedGroupMembers(ctx)
	if err != nil {
		u.adminLookupErr = err
	}

	scanner := bufio.NewScanner(passwdFile)
	for scanner.Scan() {
		account, ok := parsePasswdEntry(scanner.Text())
		if !ok {
			continue
		}
		account.isSystem = account.uid < minRegularUID
		account.isAdmin = sudoers[account.username]

		if entry, ok := shadowEntries[account.username]; ok {
			account.password = shadowPasswordState(entry)
		}

		users = append(users, account)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading /etc/passwd: %w", err)
	}

	return users, nil
}

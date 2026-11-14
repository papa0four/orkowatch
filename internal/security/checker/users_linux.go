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
	// loginDefsFile configures the range useradd assigns to regular accounts.
	// The defaults are the ones login.defs(5) documents for a missing key.
	loginDefsFile = "/etc/login.defs"
	defaultUIDMin = 1000
	defaultUIDMax = 60000

	// loginDefsFields is the key and value a login.defs setting consists of.
	loginDefsFields = 2

	// shadowMinFields is the fewest fields a usable /etc/shadow line has:
	// the account name and its password field.
	shadowMinFields = 2

	// /etc/group field indices and minimum field count as defined by POSIX.
	// The identifier sits at unixIDField, as it does in /etc/passwd.
	groupFieldMembers = 3
	groupFieldCount   = 4
)

type (
	// uidRange is the inclusive range of identifiers assigned to regular
	// accounts.
	uidRange struct {
		min uint32
		max uint32
	}

	// privilegedGroups is who the administrative groups admit: the accounts
	// their member lists name, and the groups' own identifiers, because an
	// account whose primary group is one of them belongs to it without being
	// listed.
	privilegedGroups struct {
		members map[string]bool
		gids    map[uint32]bool
	}
)

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

func (r uidRange) contains(uid uint32) bool {
	return uid >= r.min && uid <= r.max
}

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

// add records the groups in POSIX group-database entries. An entry is
// name:password:gid:comma-separated-members; a line with fewer fields is
// skipped rather than treated as a group with no members.
func (g privilegedGroups) add(output []byte) {
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < groupFieldCount {
			continue
		}
		if gid, ok := parseUnixID(fields[unixIDField]); ok {
			g.gids[gid] = true
		}
		for _, member := range strings.Split(fields[groupFieldMembers], ",") {
			if name := strings.TrimSpace(member); name != "" {
				g.members[name] = true
			}
		}
	}
}

// admits reports whether account belongs to an administrative group, by
// being listed or by holding one as its primary group.
func (g privilegedGroups) admits(account userAccount) bool {
	return g.members[account.username] || g.gids[account.gid]
}

// privilegedGroups returns the groups that confer administrative access.
// Each is queried independently so one that does not exist on this
// distribution does not discard the ones that do. The error is non-nil only
// when no group could be read at all, which is the case a caller must not
// mistake for a host with no administrators.
func (u *UnixUserChecker) privilegedGroups(ctx context.Context) (privilegedGroups, error) {
	groups := privilegedGroups{
		members: make(map[string]bool),
		gids:    make(map[uint32]bool),
	}
	var read int
	var lastErr error

	for _, group := range []string{"sudo", "wheel", "admin"} {
		output, err := exec.CommandContext(ctx, "getent", "group", group).Output() // #nosec G204 -- group names are hardcoded literals, not user input
		if err != nil {
			lastErr = execError(err)
			continue
		}
		read++
		groups.add(output)
	}

	if read == 0 {
		return groups, lastErr
	}

	return groups, nil
}

// getUsers reads /etc/passwd and, when readable, /etc/shadow, and resolves
// administrative membership through the privileged groups.
func (u *UnixUserChecker) getUsers(ctx context.Context) ([]userAccount, error) {
	users, err := localAccounts()
	if err != nil {
		return nil, err
	}

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

	admins, err := u.privilegedGroups(ctx)
	if err != nil {
		u.adminLookupErr = err
	}

	regular := regularUIDRange()
	for i := range users {
		account := &users[i]
		account.isSystem = !regular.contains(account.uid)
		account.isAdmin = admins.admits(*account)

		if entry, ok := shadowEntries[account.username]; ok {
			account.password = shadowPasswordState(entry)
		}
	}

	return users, nil
}

//go:build freebsd || openbsd || netbsd

// internal/security/checker/users_bsd.go

package checker

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// minRegularUID is the first UID adduser assigns to a regular account.
const minRegularUID = 1000

// getUsers reads /etc/passwd and resolves administrative membership through
// each account's group list.
func (u *UnixUserChecker) getUsers(ctx context.Context) ([]userAccount, error) {
	var users []userAccount

	file, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, err
	}
	defer file.Close() //nolint:errcheck // read-only passwd file; close error does not affect scan results

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		account, ok := parsePasswdEntry(scanner.Text())
		if !ok {
			continue
		}
		account.isSystem = account.uid < minRegularUID

		// A name that cannot be handed to id leaves that account's membership
		// unknown; the account is still reported rather than dropped.
		switch admin, err := u.inWheel(ctx, account.username); {
		case err != nil:
			u.adminLookupErr = err
		default:
			account.isAdmin = admin
		}

		users = append(users, account)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading /etc/passwd: %w", err)
	}

	return users, nil
}

// inWheel reports whether username belongs to wheel, the group that confers
// administrative access on the BSDs. An error means membership could not be
// determined, which the caller must not mistake for a non-member.
func (u *UnixUserChecker) inWheel(ctx context.Context, username string) (bool, error) {
	if !isSafeUsername(username) {
		return false, fmt.Errorf("account %q: name is not safe to pass to id", username)
	}

	output, err := exec.CommandContext(ctx, "id", "-Gn", username).Output() // #nosec G204 -- username validated by isSafeUsername above
	if err != nil {
		return false, execError(err)
	}

	for _, group := range strings.Fields(string(output)) {
		if group == "wheel" {
			return true, nil
		}
	}
	return false, nil
}

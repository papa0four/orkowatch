//go:build openbsd || netbsd

// internal/security/checker/users_otherbsd.go

// The users reader of the BSDs that have no finding definitions yet. It reads
// what it read before FreeBSD gained its own reader and is changed only when
// a host of its platform has been observed.

package checker

import (
	"context"
	"fmt"
	"os/exec"
	"slices"
	"strings"
)

// minRegularUID is the first UID adduser assigns to a regular account.
const minRegularUID = 1000

// readHostAccounts reads /etc/passwd and resolves administrative membership
// through each account's group list. It takes no password state. A
// membership that could not be read leaves the rule on administrative access
// without a judgment, for the first reason met; the account is still
// reported.
func readHostAccounts(ctx context.Context) (hostAccounts, error) {
	accounts, err := localAccounts()
	if err != nil {
		return hostAccounts{}, err
	}
	host := hostAccounts{accounts: accounts, credentialsUnread: "password state is not read on this platform"}

	var unread error
	for i := range host.accounts {
		account := &host.accounts[i]
		account.isSystem = account.uid < minRegularUID

		switch admin, err := inWheel(ctx, account.username); {
		case err != nil && unread == nil:
			unread = err
		case err == nil:
			account.isAdmin = admin
		}
	}
	if unread != nil {
		host.unjudged = append(host.unjudged, groupLookupFailed(unread))
	}

	return host, nil
}

// inWheel reports whether username belongs to wheel, the group that confers
// administrative access on the BSDs. An error means membership could not be
// determined, which the caller must not mistake for a non-member.
func inWheel(ctx context.Context, username string) (bool, error) {
	if !isSafeUsername(username) {
		return false, fmt.Errorf("account %q: name is not safe to pass to id", username)
	}

	output, err := exec.CommandContext(ctx, "id", "-Gn", username).Output() // #nosec G204 -- username validated by isSafeUsername above
	if err != nil {
		return false, execError(err)
	}

	return slices.Contains(strings.Fields(string(output)), "wheel"), nil
}

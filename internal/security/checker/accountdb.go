//go:build linux || freebsd || openbsd || netbsd

// internal/security/checker/accountdb.go

// Account database access shared by the Linux and BSD readers: the records
// the account package reads, held as the checks hold them, and the name
// service switch that resolves identifiers the local files do not declare.

package checker

import (
	"bytes"
	"context"
	"os/exec"

	"github.com/papa0four/orkowatch/internal/account"
)

// fromAccount holds the identity every POSIX platform records for an account
// as the checks hold it. What the identity means, and whether it is
// privileged, is the platform reader's judgment.
func fromAccount(a account.Account) userAccount {
	return userAccount{username: a.Name, uid: a.UID, gid: a.GID, homeDir: a.Home, shell: a.Shell}
}

// localAccounts returns the accounts the local passwd file declares.
func localAccounts() ([]userAccount, error) {
	local, err := account.Local()
	if err != nil {
		return nil, err
	}
	accounts := make([]userAccount, 0, len(local))
	for _, a := range local {
		accounts = append(accounts, fromAccount(a))
	}
	return accounts, nil
}

// nameServiceKnows asks the name service switch about a single identifier.
// getent reports absence through its exit status, and an empty result is
// treated the same way.
func nameServiceKnows(ctx context.Context, kind identityKind, id uint32) bool {
	database := "passwd"
	if kind == identityKindGroup {
		database = "group"
	}
	cmd := exec.CommandContext(ctx, account.GetentProgram, database, account.FormatID(id)) // #nosec G204 -- command is fixed and the sole variable argument is a numeric identifier read from the filesystem
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	return len(bytes.TrimSpace(out)) > 0
}

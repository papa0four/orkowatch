//go:build linux || darwin || freebsd || openbsd || netbsd

// internal/account/account.go

package account

import (
	"context"
	"errors"
	"strings"
	"time"
)

// Account is one account's record.
type Account struct {
	Name  string
	UID   uint32
	GID   uint32
	Home  string
	Shell string
}

// ErrNotFound means no account has the identifier or name asked for.
var ErrNotFound = errors.New("no such account")

const (
	// PasswdFile is the local account database.
	PasswdFile = "/etc/passwd"

	// lookupTimeout bounds a lookup that reaches a directory service, so an
	// unreachable server cannot hold a run.
	lookupTimeout = 10 * time.Second
)

// passwd line fields, as POSIX defines them.
const (
	fieldName = iota
	fieldPassword
	fieldUID
	fieldGID
	fieldGECOS
	fieldHome
	fieldShell
	fieldCount
)

// Parse reads one passwd line. It reports false for a blank line, a comment,
// and a record too short or malformed to name an account.
func Parse(line string) (Account, bool) {
	if line == "" || line[0] == '#' {
		return Account{}, false
	}
	fields := strings.Split(line, ":")
	if len(fields) < fieldCount {
		return Account{}, false
	}
	uid, ok := ParseID(fields[fieldUID])
	if !ok {
		return Account{}, false
	}
	gid, ok := ParseID(fields[fieldGID])
	if !ok {
		return Account{}, false
	}
	return Account{
		Name:  fields[fieldName],
		UID:   uid,
		GID:   gid,
		Home:  fields[fieldHome],
		Shell: fields[fieldShell],
	}, true
}

// ParseAll reads passwd-format data, one account per line, skipping what
// Parse refuses. The local file and getent passwd both write this format.
func ParseAll(data []byte) []Account {
	var accounts []Account
	for _, line := range strings.Split(string(data), "\n") {
		if a, ok := Parse(line); ok {
			accounts = append(accounts, a)
		}
	}
	return accounts
}

// ByID returns the account whose identifier is uid.
func ByID(ctx context.Context, uid uint32) (Account, error) {
	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	return lookup(ctx, FormatID(uid), func(a Account) bool { return a.UID == uid })
}

// ByName returns the account named name. A name holding a field separator or
// a line break names no account, and is refused before anything is asked.
func ByName(ctx context.Context, name string) (Account, error) {
	if name == "" || strings.ContainsAny(name, ":\n") {
		return Account{}, ErrNotFound
	}
	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	return lookup(ctx, name, func(a Account) bool { return a.Name == name })
}

//go:build linux || freebsd || openbsd || netbsd

// internal/security/checker/accountdb.go

// Account database access shared by the Linux and BSD readers: the POSIX
// passwd line format read from disk, and the name service switch that
// resolves identifiers the local files do not declare.

package checker

import (
	"bytes"
	"context"
	"os/exec"
	"strconv"
	"strings"
)

// /etc/passwd field indices as defined by POSIX.
const (
	passwdFieldUsername = iota
	passwdFieldPassword
	passwdFieldUID
	passwdFieldGID
	passwdFieldGECOS
	passwdFieldHomeDir
	passwdFieldShell
	passwdFieldCount
)

// parsePasswdEntry parses one /etc/passwd line into the identity every POSIX
// platform records for an account. It reports false for blank and comment
// lines and for records too short or malformed to name an account; what the
// identity means, and whether it is privileged, is the platform reader's
// judgment.
func parsePasswdEntry(line string) (userAccount, bool) {
	if line == "" || line[0] == '#' {
		return userAccount{}, false
	}

	fields := strings.Split(line, ":")
	if len(fields) < passwdFieldCount {
		return userAccount{}, false
	}

	uid, ok := parseUnixID(fields[passwdFieldUID])
	if !ok {
		return userAccount{}, false
	}
	gid, ok := parseUnixID(fields[passwdFieldGID])
	if !ok {
		return userAccount{}, false
	}

	return userAccount{
		username: fields[passwdFieldUsername],
		uid:      uid,
		gid:      gid,
		homeDir:  fields[passwdFieldHomeDir],
		shell:    fields[passwdFieldShell],
	}, true
}

// nameServiceKnows asks the name service switch about a single identifier.
// getent reports absence through its exit status, and an empty result is
// treated the same way.
func nameServiceKnows(ctx context.Context, kind identityKind, id uint32) bool {
	database := "passwd"
	if kind == identityKindGroup {
		database = "group"
	}
	value := strconv.FormatUint(uint64(id), decimalBase)

	cmd := exec.CommandContext(ctx, "getent", database, value) // #nosec G204 -- command is fixed and the sole variable argument is a numeric identifier read from the filesystem
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	return len(bytes.TrimSpace(out)) > 0
}

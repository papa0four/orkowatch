// internal/security/checker/fileaccess.go

package checker

import (
	"io/fs"
	"strconv"
	"strings"
)

// The permission bits that give a file's group and everyone else read or
// write access.
const (
	groupRead  fs.FileMode = 0o040
	groupWrite fs.FileMode = 0o020
	otherRead  fs.FileMode = 0o004
	otherWrite fs.FileMode = 0o002
)

type (
	// fileOwner returns who owns a file, which only a POSIX file system
	// records.
	fileOwner func(fs.FileInfo) (uid, gid uint32, ok bool)

	// localAccount is a service account as the host's own account files hold
	// it. The zero value is no account, which leaves root alone.
	localAccount struct {
		uid, gid    uint32
		user, group bool
	}
)

// fileExcess reports whether a file's owner, group and mode let an account
// other than root and service read it or write it. An owner that is neither
// can change the mode, so it has both.
func fileExcess(perm fs.FileMode, uid, gid uint32, service localAccount) (read, write bool) {
	if uid != 0 && (!service.user || uid != service.uid) {
		return true, true
	}
	if !service.group || gid != service.gid {
		read, write = perm&groupRead != 0, perm&groupWrite != 0
	}
	return read || perm&otherRead != 0, write || perm&otherWrite != 0
}

// lookupLocalAccount looks the user and group called name up in the host's
// own account files, where a service account is kept.
func lookupLocalAccount(fsys fs.FS, name string) localAccount {
	var account localAccount
	account.uid, account.user = localID(fsys, "etc/passwd", name)
	account.gid, account.group = localID(fsys, "etc/group", name)
	return account
}

// localID returns the identifier of name in a passwd or group file, whose
// third field holds it.
func localID(fsys fs.FS, file, name string) (uint32, bool) {
	const idField, fields, base, bits = 2, 3, 10, 32
	data, err := fs.ReadFile(fsys, file)
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Split(line, ":")
		if len(parts) < fields || parts[0] != name {
			continue
		}
		id, err := strconv.ParseUint(parts[idField], base, bits)
		return uint32(id), err == nil
	}
	return 0, false
}

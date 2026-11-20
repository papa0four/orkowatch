// internal/security/checker/fileaccess.go

package checker

import (
	"fmt"
	"io/fs"
	"strings"

	"github.com/papa0four/orkowatch/internal/security/finding"
)

// The permission bits that give a file's group and everyone else read or
// write access.
const (
	groupRead  fs.FileMode = 0o040
	groupWrite fs.FileMode = 0o020
	otherRead  fs.FileMode = 0o004
	otherWrite fs.FileMode = 0o002
)

// expectRootOnly is what a file holding a secret is expected to be where
// root alone is to reach it.
const expectRootOnly = "owned by root, with no access for its group or others"

type (
	// fileOwner returns who owns a file, which only a POSIX file system
	// records.
	fileOwner func(fs.FileInfo) (uid, gid uint32, ok bool)

	// ownedFile is a file with its mode and who owns it. path is the file as
	// a report names it.
	ownedFile struct {
		path     string
		mode     fs.FileMode
		uid, gid uint32
	}

	// localAccount is a service account as the host's own account files hold
	// it. The zero value is no account, which leaves root alone.
	localAccount struct {
		uid, gid    uint32
		user, group bool
	}
)

// statOwned returns the file called name under fsys with who owns it, or
// why that could not be determined.
func statOwned(fsys fs.FS, name string, owner fileOwner) (ownedFile, string) {
	info, err := fs.Stat(fsys, name)
	if err != nil {
		return ownedFile{}, fmt.Sprintf("/%s could not be checked: %v", name, err)
	}
	uid, gid, ok := owner(info)
	if !ok {
		return ownedFile{}, "/" + name + " ownership could not be determined"
	}
	return ownedFile{path: "/" + name, mode: info.Mode(), uid: uid, gid: gid}, ""
}

// excess reports whether an account other than root and service can read
// the file or write it.
func (f ownedFile) excess(service localAccount) (read, write bool) {
	return fileExcess(f.mode.Perm(), f.uid, f.gid, service)
}

// evidence is the file as the rules on who can reach it record it: its mode
// and owner, what was expected of them, then whatever else was observed.
func (f ownedFile) evidence(expected string, facts ...finding.Fact) finding.Evidence {
	return evidence(finding.KindFile, f.path, append([]finding.Fact{
		fact(finding.FactMode, formatMode(f.mode)),
		fact(finding.FactUID, formatUnixID(f.uid)),
		fact(finding.FactGID, formatUnixID(f.gid)),
		fact(finding.FactExpected, expected),
	}, facts...)...)
}

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
	data, err := fs.ReadFile(fsys, file)
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Split(line, ":")
		if len(parts) <= unixIDField || parts[0] != name {
			continue
		}
		return parseUnixID(parts[unixIDField])
	}
	return 0, false
}

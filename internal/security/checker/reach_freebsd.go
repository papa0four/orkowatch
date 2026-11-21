//go:build freebsd

// internal/security/checker/reach_freebsd.go

package checker

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// What pathconf(2) is asked and what __acl_get_file returns, from
// sys/unistd.h and sys/acl.h: struct acl is two counts and four spare words
// ahead of ACL_MAX_ENTRIES entries, each a tag, an identifier, a permission
// set, an entry type and flags.
const (
	pathconfACLExtended = 59
	pathconfACLNFS4     = 64

	aclTypeAccess = 2
	aclTypeNFS4   = 4

	aclMaxEntries = 254

	aclCountOffset  = 4
	aclHeaderSize   = 24
	aclEntrySize    = 16
	aclEntryIDAt    = 4
	aclEntryPermAt  = 8
	aclEntryTypeAt  = 12
	aclEntryFlagsAt = 14
	aclSize         = aclHeaderSize + aclMaxEntries*aclEntrySize

	aclTagUserObj  = 0x01
	aclTagEveryone = 0x40

	nfs4EntryAllow       = 0x0100
	nfs4EntryDeny        = 0x0200
	nfs4EntryInheritOnly = 0x0008
)

type (
	// kernelACLEntry is one entry as __acl_get_file returns it. A POSIX.1e
	// entry leaves entryType and flags zero.
	kernelACLEntry struct {
		aclEntry
		entryType uint16
		flags     uint16
	}

	// nfs4Principal is who an NFSv4 entry names once owner@ and group@ are
	// resolved to the directory's owner and group: a user or a group by
	// identifier, or everyone.
	nfs4Principal struct {
		tag uint32
		id  uint32
	}
)

// everyone is the principal of an everyone@ entry.
var everyone = nfs4Principal{tag: aclTagEveryone}

// reach judges a directory traversableByNonRoot rejected. A filesystem keeps
// NFSv4 ACLs, POSIX.1e ACLs or none, and pathconf says which. Under NFSv4
// the mode bits say nothing of a named entry, so the ACL is always read.
func (j *deniedJudge) reach(ctx context.Context, dir string, mode fs.FileMode, uid, gid uint32) reachability {
	nfs4, err := unix.Pathconf(dir, pathconfACLNFS4)
	if err != nil {
		return reachUndetermined
	}
	if nfs4 > 0 {
		entries, err := readACL(dir, aclTypeNFS4)
		if err != nil {
			return reachUndetermined
		}
		return j.nfs4Reach(ctx, entries, uid, gid)
	}

	return j.posixReach(ctx, mode, func() ([]aclEntry, error) { return readPOSIXACL(dir) })
}

// nfs4Reach judges an NFSv4 ACL, whose entries are evaluated in order: an
// allow grants a search unless an entry ahead of it denied the same principal
// or everyone. A deny for one principal is not held against another, which
// would need every account's groups, so a directory it closes may be called
// reachable. An inherit-only entry applies to what the directory will hold,
// not to the directory.
func (j *deniedJudge) nfs4Reach(ctx context.Context, entries []kernelACLEntry, uid, gid uint32) reachability {
	denied := make(map[nfs4Principal]bool)

	var rootGroupGranted bool
	for _, entry := range entries {
		if entry.flags&nfs4EntryInheritOnly != 0 || entry.perm&aclPermExecute == 0 {
			continue
		}
		who, ok := entry.principal(uid, gid)
		if !ok {
			return reachUndetermined
		}

		switch entry.entryType {
		case nfs4EntryDeny:
			denied[who] = true
		case nfs4EntryAllow:
			switch {
			case denied[who], denied[everyone]:
			case who == everyone:
				return reachNonRoot
			case who.tag == aclTagUser && who.id != rootUID:
				return reachNonRoot
			case who.tag == aclTagGroup && who.id != rootGID:
				return reachNonRoot
			case who.tag == aclTagGroup:
				rootGroupGranted = true
			}
		}
	}

	if rootGroupGranted {
		return j.rootGroupReach(ctx)
	}
	return reachRootOnly
}

// principal resolves who the entry names, given the directory's owner and
// group. It reports false for a tag NFSv4 does not define.
func (e kernelACLEntry) principal(uid, gid uint32) (nfs4Principal, bool) {
	switch e.tag {
	case aclTagUserObj:
		return nfs4Principal{tag: aclTagUser, id: uid}, true
	case aclTagUser:
		return nfs4Principal{tag: aclTagUser, id: e.id}, true
	case aclTagGroupObj:
		return nfs4Principal{tag: aclTagGroup, id: gid}, true
	case aclTagGroup:
		return nfs4Principal{tag: aclTagGroup, id: e.id}, true
	case aclTagEveryone:
		return everyone, true
	default:
		return nfs4Principal{}, false
	}
}

// readPOSIXACL returns the POSIX.1e access ACL of dir, and errNoACL where
// the filesystem keeps none.
func readPOSIXACL(dir string) ([]aclEntry, error) {
	extended, err := unix.Pathconf(dir, pathconfACLExtended)
	switch {
	case err != nil:
		return nil, err
	case extended <= 0:
		return nil, errNoACL
	}

	list, err := readACL(dir, aclTypeAccess)
	if err != nil {
		return nil, err
	}
	entries := make([]aclEntry, len(list))
	for i, entry := range list {
		entries[i] = entry.aclEntry
	}
	return entries, nil
}

// readACL returns the ACL of the given type through __acl_get_file, the
// system call under acl_get_file(3), so no process is run per directory.
func readACL(dir string, aclType uintptr) ([]kernelACLEntry, error) {
	path, err := unix.BytePtrFromString(dir)
	if err != nil {
		return nil, err
	}

	list := make([]byte, aclSize)
	binary.NativeEndian.PutUint32(list, aclMaxEntries)
	// #nosec G103 -- the kernel writes one struct acl, which is aclSize bytes, into a buffer of that size
	if _, _, errno := unix.Syscall(unix.SYS___ACL_GET_FILE, uintptr(unsafe.Pointer(path)), aclType, uintptr(unsafe.Pointer(&list[0]))); errno != 0 {
		return nil, errno
	}
	return decodeACL(list)
}

// decodeACL decodes a struct acl, rejecting a length or count it does not
// recognize rather than guessing at the layout.
func decodeACL(list []byte) ([]kernelACLEntry, error) {
	if len(list) != aclSize {
		return nil, fmt.Errorf("acl: unexpected length %d", len(list))
	}
	count := binary.NativeEndian.Uint32(list[aclCountOffset:])
	if count > aclMaxEntries {
		return nil, fmt.Errorf("acl: unexpected entry count %d", count)
	}

	body := list[aclHeaderSize:]
	entries := make([]kernelACLEntry, count)
	for i := range entries {
		entry := body[i*aclEntrySize:]
		entries[i] = kernelACLEntry{
			aclEntry: aclEntry{
				tag:  binary.NativeEndian.Uint32(entry),
				id:   binary.NativeEndian.Uint32(entry[aclEntryIDAt:]),
				perm: binary.NativeEndian.Uint32(entry[aclEntryPermAt:]),
			},
			entryType: binary.NativeEndian.Uint16(entry[aclEntryTypeAt:]),
			flags:     binary.NativeEndian.Uint16(entry[aclEntryFlagsAt:]),
		}
	}
	return entries, nil
}

// anyInRootGroup reports whether any named account is a member of a group
// whose identifier is 0. The whole listing is read, since getent group 0
// answers with the first such group and no other, and FreeBSD's getent has
// no initgroups database.
func anyInRootGroup(ctx context.Context, names []string) (bool, error) {
	output, err := exec.CommandContext(ctx, getentProgram, "group").Output()
	if err != nil {
		return false, execError(err)
	}
	return listsRootGroupMember(output, names), nil
}

// listsRootGroupMember reports whether any entry of a group listing with
// gid 0 names one of the accounts as a member.
func listsRootGroupMember(listing []byte, names []string) bool {
	accounts := make(map[string]bool, len(names))
	for _, name := range names {
		accounts[name] = true
	}

	for _, line := range strings.Split(string(listing), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) <= groupFieldMembers {
			continue
		}
		if gid, ok := parseUnixID(fields[unixIDField]); !ok || gid != rootGID {
			continue
		}
		for _, member := range strings.Split(fields[groupFieldMembers], ",") {
			if accounts[strings.TrimSpace(member)] {
				return true
			}
		}
	}
	return false
}

// accountSourcesEnumerable reports whether getent lists every account and
// group the host resolves. A configuration that cannot be read is treated as
// one it does not; a missing one is the default.
func accountSourcesEnumerable() bool {
	conf, err := os.ReadFile(nsswitchFile)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false
	}
	return sourcesEnumerable(conf, unixPasswdFile, unixGroupFile)
}

// sourcesEnumerable judges the passwd and group lines of nsswitch.conf.
// files is listed in full. compat, which nsswitch.conf(5) gives as the
// default for both databases, is files unless a line of the database's file
// begins with + or -, which brings in or leaves out entries of another
// source; what such a line brings in is not known here.
func sourcesEnumerable(conf []byte, passwdFile, groupFile string) bool {
	files := map[string]string{"passwd": passwdFile, "group": groupFile}

	listed := make(map[string]bool, len(files))
	for _, line := range parseNsswitch(conf) {
		file, ok := files[line.database]
		if !ok || len(line.sources) == 0 {
			continue
		}
		listed[line.database] = true
		for _, source := range line.sources {
			if !sourceEnumerable(source, file) {
				return false
			}
		}
	}

	for database, file := range files {
		if !listed[database] && !sourceEnumerable("compat", file) {
			return false
		}
	}
	return true
}

// sourceEnumerable judges one source of the database kept in file.
func sourceEnumerable(source, file string) bool {
	switch source {
	case "files":
		return true
	case "compat":
		data, err := os.ReadFile(file) // #nosec G304 -- the path is the system's passwd or group file outside tests
		return err == nil && !importsEntries(data)
	default:
		return false
	}
}

// importsEntries reports whether a passwd or group file holds a compat line.
func importsEntries(data []byte) bool {
	for _, line := range bytes.Split(data, []byte("\n")) {
		if bytes.HasPrefix(line, []byte("+")) || bytes.HasPrefix(line, []byte("-")) {
			return true
		}
	}
	return false
}

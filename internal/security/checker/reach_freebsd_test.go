//go:build freebsd

// internal/security/checker/reach_freebsd_test.go

package checker

import (
	"context"
	"encoding/binary"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
)

// The accounts of the guest the lists below were read in: a_w is uid 1001, a
// member of g_w, gid 1002, and of no group with gid 0.
const (
	guestUser  = 1001
	guestGroup = 1002
)

// The permission sets FreeBSD 15.1 gave the three entries of a directory of
// mode 0700 that no entry was added to, on ZFS and on UFS mounted nfsv4acls.
const (
	ownerPerms = 0xf6f9
	otherPerms = 0x9240
)

func nfs4(tag, id, perm uint32, entryType, flags uint16) kernelACLEntry {
	return kernelACLEntry{aclEntry: aclEntry{tag: tag, id: id, perm: perm}, entryType: entryType, flags: flags}
}

func allow(tag, id uint32) kernelACLEntry {
	return nfs4(tag, id, aclPermExecute, nfs4EntryAllow, 0)
}

func deny(tag, id uint32) kernelACLEntry {
	return nfs4(tag, id, aclPermExecute, nfs4EntryDeny, 0)
}

// closed is what a directory of mode 0700 holds beneath any entry added.
func closed(ahead ...kernelACLEntry) []kernelACLEntry {
	return append(ahead,
		nfs4(aclTagUserObj, noID, ownerPerms, nfs4EntryAllow, 0),
		nfs4(aclTagGroupObj, noID, otherPerms, nfs4EntryAllow, 0),
		nfs4(aclTagEveryone, noID, otherPerms, nfs4EntryAllow, 0))
}

// Each case of the first group names whether a_w read a file in the
// directory in the guest, and its list is the one __acl_get_file returned
// there. No directory was made for the cases of the second group.
func TestNFS4Reach(t *testing.T) {
	const inheritOnly = 0x0b // file, directory and inherit-only, as setfacl's fdi set it

	owningGroupAllowed := []kernelACLEntry{
		nfs4(aclTagUserObj, noID, ownerPerms, nfs4EntryAllow, 0),
		allow(aclTagGroupObj, noID),
		nfs4(aclTagEveryone, noID, otherPerms, nfs4EntryAllow, 0),
	}

	tests := []struct {
		name      string
		entries   []kernelACLEntry
		uid, gid  uint32
		rootGroup reachability
		want      reachability
	}{
		{"no entry added: not read", closed(), rootUID, rootGID, reachNonRoot, reachRootOnly},
		{"a_w allowed: read", closed(allow(aclTagUser, guestUser)), rootUID, rootGID, reachRootOnly, reachNonRoot},
		{"a_w denied ahead of a_w allowed: not read",
			closed(deny(aclTagUser, guestUser), allow(aclTagUser, guestUser)), rootUID, rootGID, reachNonRoot, reachRootOnly},
		{"a_w allowed ahead of a_w denied: read",
			closed(allow(aclTagUser, guestUser), deny(aclTagUser, guestUser)), rootUID, rootGID, reachRootOnly, reachNonRoot},
		{"everyone denied ahead of a_w allowed: not read",
			closed(deny(aclTagEveryone, noID), allow(aclTagUser, guestUser)), rootUID, rootGID, reachNonRoot, reachRootOnly},
		{"an inherit-only entry for a_w: not read",
			closed(nfs4(aclTagUser, guestUser, aclPermExecute, nfs4EntryAllow, inheritOnly)), rootUID, rootGID, reachNonRoot, reachRootOnly},
		{"g_w allowed: read", closed(allow(aclTagGroup, guestGroup)), rootUID, rootGID, reachRootOnly, reachNonRoot},
		{"an account that does not exist allowed", closed(allow(aclTagUser, 4242)), rootUID, rootGID, reachRootOnly, reachNonRoot},
		// Not read in the guest: the deny for a_w's group is not held
		// against a_w, so the directory is over-reported.
		{"g_w denied ahead of a_w allowed: called reachable",
			closed(deny(aclTagGroup, guestGroup), allow(aclTagUser, guestUser)), rootUID, rootGID, reachRootOnly, reachNonRoot},
		{"the owning group allowed, wheel held by root alone: not read", owningGroupAllowed, rootUID, rootGID, reachRootOnly, reachRootOnly},
		{"the owning group allowed, a_w in wheel: read", owningGroupAllowed, rootUID, rootGID, reachNonRoot, reachNonRoot},
		{"wheel named, held by root alone: not read", closed(allow(aclTagGroup, rootGID)), rootUID, rootGID, reachRootOnly, reachRootOnly},
		{"wheel named, a_w in wheel: read", closed(allow(aclTagGroup, rootGID)), rootUID, rootGID, reachNonRoot, reachNonRoot},

		{"wheel denied ahead of the owning group", closed(deny(aclTagGroup, rootGID), allow(aclTagGroupObj, noID)), rootUID, rootGID, reachNonRoot, reachRootOnly},
		{"an owning group that is not root's", owningGroupAllowed, rootUID, guestGroup, reachRootOnly, reachNonRoot},
		{"an owner that is not root", closed(), guestUser, rootGID, reachRootOnly, reachNonRoot},
		{"a tag NFSv4 does not define", closed(allow(aclTagMask, noID)), rootUID, rootGID, reachRootOnly, reachUndetermined},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := judgeAnswering(tt.rootGroup).nfs4Reach(context.Background(), tt.entries, tt.uid, tt.gid); got != tt.want {
				t.Errorf("nfs4Reach() = %d, want %d", got, tt.want)
			}
		})
	}
}

// encodeACL lays entries out as sys/acl.h declares struct acl.
func encodeACL(count uint32, entries []kernelACLEntry) []byte {
	list := make([]byte, aclSize)
	binary.NativeEndian.PutUint32(list, aclMaxEntries)
	binary.NativeEndian.PutUint32(list[aclCountOffset:], count)
	for i, entry := range entries {
		at := list[aclHeaderSize+i*aclEntrySize:]
		binary.NativeEndian.PutUint32(at, entry.tag)
		binary.NativeEndian.PutUint32(at[aclEntryIDAt:], entry.id)
		binary.NativeEndian.PutUint32(at[aclEntryPermAt:], entry.perm)
		binary.NativeEndian.PutUint16(at[aclEntryTypeAt:], entry.entryType)
		binary.NativeEndian.PutUint16(at[aclEntryFlagsAt:], entry.flags)
	}
	return list
}

func TestDecodeACL(t *testing.T) {
	const structACLSize = 4088
	if aclSize != structACLSize {
		t.Fatalf("struct acl is taken as %d bytes, want %d", aclSize, structACLSize)
	}

	want := closed(nfs4(aclTagUser, guestUser, aclPermExecute, nfs4EntryAllow, 0x0b))
	got, err := decodeACL(encodeACL(uint32(len(want)), want))
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("decodeACL() = %+v, %v, want %+v", got, err, want)
	}

	if got, err := decodeACL(encodeACL(0, nil)); err != nil || len(got) != 0 {
		t.Errorf("an empty list = %+v, %v", got, err)
	}
	if _, err := decodeACL(encodeACL(aclMaxEntries+1, nil)); err == nil {
		t.Error("a count beyond the entries the structure holds was accepted")
	}
	if _, err := decodeACL(make([]byte, aclSize-1)); err == nil {
		t.Error("a short structure was accepted")
	}
}

// The listings are what getent group printed in the guest, cut to the
// entries that bear on the answer.
func TestListsRootGroupMember(t *testing.T) {
	accounts := []string{"daemon", "a_w"}

	tests := []struct {
		name    string
		listing string
		want    bool
	}{
		{"as installed", "wheel:*:0:root\ndaemon:*:1:\noperator:*:5:root\na_w:*:1001:\n", false},
		{"a_w added to wheel", "wheel:*:0:root,a_w\ndaemon:*:1:\n", true},
		{"a second group with gid 0 ahead of wheel", "wheel0:*:0:a_w\nwheel:*:0:root\n", true},
		{"a second group with gid 0 behind wheel", "wheel:*:0:root\ndaemon:*:1:\nwheel0:*:0:a_w\n", true},
		{"a member that is another name of root", "wheel:*:0:root,toor\n", false},
		{"a_w in a group that is not root's", "wheel:*:0:root\ng_w:*:1002:a_w\n", false},
		{"an entry that ends at its identifier", "wheel:*:0\n", false},
		{"nothing listed", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := listsRootGroupMember([]byte(tt.listing), accounts); got != tt.want {
				t.Errorf("listsRootGroupMember() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSourcesEnumerable(t *testing.T) {
	// What nsswitch.conf holds as FreeBSD 15.1 installs it.
	const installed = "group: compat\ngroup_compat: nis\nhosts: files dns\nnetgroup: compat\nnetworks: files\npasswd: compat\npasswd_compat: nis\nshells: files\n"

	dir := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	plainPasswd := write("passwd", "root:*:0:0:Charlie &:/root:/bin/sh\na_w:*:1001:1001:User &:/home/a_w:/bin/sh\n")
	plainGroup := write("group", "wheel:*:0:root\na_w:*:1001:\n")
	plusPasswd := write("passwd.plus", "root:*:0:0:Charlie &:/root:/bin/sh\n+:*:::::\n")
	plusGroup := write("group.plus", "wheel:*:0:root\n+:*::\n")
	minusGroup := write("group.minus", "wheel:*:0:root\n-wheel:*::\n")
	missing := filepath.Join(dir, "absent")

	tests := []struct {
		name          string
		conf          string
		passwd, group string
		want          bool
	}{
		{"as installed", installed, plainPasswd, plainGroup, true},
		{"a + line in the group file", installed, plainPasswd, plusGroup, false},
		{"a - line in the group file", installed, plainPasswd, minusGroup, false},
		{"a + line in the passwd file", installed, plusPasswd, plainGroup, false},
		{"no nsswitch.conf: both default to compat", "", plainPasswd, plainGroup, true},
		{"no nsswitch.conf and a + line", "", plainPasswd, plusGroup, false},
		{"a database with no source defaults to compat", "passwd:\ngroup: files\n", plusPasswd, plainGroup, false},
		{"files does not read + lines", "passwd: files\ngroup: files\n", plusPasswd, plusGroup, true},
		{"files ahead of an action item", "passwd: files [notfound=return]\ngroup: files\n", plainPasswd, plainGroup, true},
		{"a source that is not listed here", "passwd: files ldap\ngroup: files\n", plainPasswd, plainGroup, false},
		{"nis named outright", "passwd: files\ngroup: nis [notfound=return] files\n", plainPasswd, plainGroup, false},
		{"compat over a file that cannot be read", installed, plainPasswd, missing, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sourcesEnumerable([]byte(tt.conf), tt.passwd, tt.group); got != tt.want {
				t.Errorf("sourcesEnumerable() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestReachOfDirectories judges directories made where TMPDIR points, with
// whichever kind of ACL that filesystem keeps, so it is run once on each. A
// case resting on root's group wants undetermined, which is what the judge
// is told of that group and what no other path of those cases returns.
func TestReachOfDirectories(t *testing.T) {
	if os.Geteuid() != rootUID {
		t.Skip("making a directory of root's needs root")
	}
	const stranger = "65534" // nobody

	base := t.TempDir()
	keepsNFS4, err := unix.Pathconf(base, pathconfACLNFS4)
	if err != nil {
		t.Fatal(err)
	}
	keepsPOSIX, err := unix.Pathconf(base, pathconfACLExtended)
	if err != nil {
		t.Fatal(err)
	}

	directories := []directory{
		{"closed", 0700, nil, reachRootOnly},
		{"group", 0750, nil, reachUndetermined},
	}
	switch {
	case keepsNFS4 > 0:
		t.Log("the filesystem keeps NFSv4 ACLs")
		directories = append(directories,
			directory{"named", 0700, [][]string{{"-m", "u:" + stranger + ":x::allow"}}, reachNonRoot},
			directory{"named-group", 0700, [][]string{{"-m", "g:" + stranger + ":x::allow"}}, reachNonRoot},
			directory{"denied-ahead", 0700, [][]string{{"-m", "u:" + stranger + ":x::allow"}, {"-a", "0", "u:" + stranger + ":x::deny"}}, reachRootOnly},
			directory{"allowed-ahead", 0700, [][]string{{"-m", "u:" + stranger + ":x::deny"}, {"-a", "0", "u:" + stranger + ":x::allow"}}, reachNonRoot},
			directory{"everyone-denied", 0700, [][]string{{"-m", "u:" + stranger + ":x::allow"}, {"-a", "0", "everyone@:x::deny"}}, reachRootOnly},
			directory{"inherit-only", 0700, [][]string{{"-m", "u:" + stranger + ":x:fdi:allow"}}, reachRootOnly},
			directory{"owning-group", 0700, [][]string{{"-m", "group@:x::allow"}}, reachUndetermined},
			directory{"wheel-named", 0700, [][]string{{"-m", "g:0:x::allow"}}, reachUndetermined})
	case keepsPOSIX > 0:
		t.Log("the filesystem keeps POSIX.1e ACLs")
		directories = append(directories,
			directory{"named", 0700, [][]string{{"-m", "u:" + stranger + ":--x"}}, reachNonRoot},
			directory{"named-group", 0700, [][]string{{"-m", "g:" + stranger + ":--x"}}, reachNonRoot},
			directory{"masked", 0700, [][]string{{"-m", "u:" + stranger + ":--x"}, {"-m", "m::---"}}, reachRootOnly},
			directory{"wheel-named", 0700, [][]string{{"-m", "g:0:--x"}}, reachUndetermined})
	default:
		t.Log("the filesystem keeps no ACL")
	}

	for _, d := range directories {
		t.Run(d.name, func(t *testing.T) {
			dir, mode := d.make(t, base)
			if got := judgeAnswering(reachUndetermined).reach(context.Background(), dir, mode, rootUID, rootGID); got != d.want {
				t.Errorf("reach() of %s, mode %v = %d, want %d", d.name, mode, got, d.want)
			}
		})
	}
}

// directory is one a test makes: its mode, the setfacl runs that follow, and
// the reach wanted of it.
type directory struct {
	name    string
	mode    fs.FileMode
	setfacl [][]string
	want    reachability
}

// make creates the directory as root's and returns its path and the mode it
// has once its ACL is set.
func (d directory) make(t *testing.T, base string) (string, fs.FileMode) {
	t.Helper()

	dir := filepath.Join(base, d.name)
	if err := os.Mkdir(dir, d.mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dir, rootUID, rootGID); err != nil {
		t.Fatal(err)
	}
	for _, args := range d.setfacl {
		if out, err := exec.Command("setfacl", append(args, dir)...).CombinedOutput(); err != nil {
			t.Fatalf("setfacl %v: %v: %s", args, err, out)
		}
	}
	info, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	return dir, info.Mode()
}

//go:build linux

// internal/security/checker/reach_linux.go

package checker

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/sys/unix"
)

// The access ACL extended attribute as the kernel stores it, from
// linux/posix_acl_xattr.h and linux/posix_acl.h: a little-endian header
// holding the version, then fixed-size entries of tag, permissions and
// identifier.
const (
	posixACLAttr = "system.posix_acl_access"

	aclVersion    = 0x0002
	aclHeaderSize = 4
	aclEntrySize  = 8

	aclEntryPermOffset = 2
	aclEntryIDOffset   = 4

	aclTagUser     = 0x02
	aclTagGroupObj = 0x04
	aclTagGroup    = 0x08
	aclTagMask     = 0x10

	aclPermExecute = 0x01
)

const (
	nsswitchFile = "/etc/nsswitch.conf"

	// sssNSSPipe is the socket libnss_sss queries. Without it the sss source
	// answers nothing, whatever nsswitch.conf lists.
	sssNSSPipe = "/var/lib/sss/pipes/nss"

	// initgroupsBatch bounds the account names passed to one getent call so
	// a large account database cannot exceed the argument length limit.
	initgroupsBatch = 256
)

type (
	// deniedJudge decides what a directory confers when its mode bits deny
	// traversal. Whether root's group has another member is the same answer
	// for every directory, so it is asked once and kept.
	deniedJudge struct {
		rootGroup *reachability
	}

	// aclEntry is one entry of a POSIX access ACL.
	aclEntry struct {
		tag  uint16
		perm uint16
		id   uint32
	}
)

// reach judges a directory traversableByNonRoot rejected. Without
// group-execute nothing can grant traversal, because the group bits of a
// directory carrying an ACL are the ACL mask and the mask caps every entry
// but the owner's and other's. With it, the owning group is root's, and the
// answer rests on the ACL entries and on who belongs to that group.
func (j *deniedJudge) reach(ctx context.Context, dir string, mode fs.FileMode) reachability {
	if mode.Perm()&bitGroupExecute == 0 {
		return reachRootOnly
	}

	entries, err := readPOSIXACL(dir)
	switch {
	case errors.Is(err, unix.ENODATA), errors.Is(err, unix.ENOTSUP):
		// No ACL: the group bits belong to the owning group alone.
		return j.rootGroupReach(ctx)
	case err != nil:
		return reachUndetermined
	}

	return j.aclReach(ctx, entries)
}

// aclReach judges the entries of an ACL whose mask grants execute. A named
// user or group other than root's is reachable outright, over-approximating
// for groups the way traversableByNonRoot does; root's group, whether owning
// or named, defers to its membership.
func (j *deniedJudge) aclReach(ctx context.Context, entries []aclEntry) reachability {
	mask := uint16(aclPermExecute)
	for _, entry := range entries {
		if entry.tag == aclTagMask {
			mask = entry.perm
		}
	}

	var rootGroupGranted bool
	for _, entry := range entries {
		if entry.perm&mask&aclPermExecute == 0 {
			continue
		}
		switch entry.tag {
		case aclTagUser:
			if entry.id != rootUID {
				return reachNonRoot
			}
		case aclTagGroup:
			if entry.id != rootGID {
				return reachNonRoot
			}
			rootGroupGranted = true
		case aclTagGroupObj:
			rootGroupGranted = true
		}
	}

	if rootGroupGranted {
		return j.rootGroupReach(ctx)
	}
	return reachRootOnly
}

func (j *deniedJudge) rootGroupReach(ctx context.Context) reachability {
	if j.rootGroup == nil {
		reach := rootGroupReach(ctx)
		j.rootGroup = &reach
	}
	return *j.rootGroup
}

// readPOSIXACL returns the access ACL of dir. A directory with no ACL fails
// with ENODATA, and a filesystem without ACL support with ENOTSUP.
func readPOSIXACL(dir string) ([]aclEntry, error) {
	size, err := unix.Getxattr(dir, posixACLAttr, nil)
	if err != nil {
		return nil, err
	}
	data := make([]byte, size)
	size, err = unix.Getxattr(dir, posixACLAttr, data)
	if err != nil {
		return nil, err
	}
	return parsePOSIXACL(data[:size])
}

// parsePOSIXACL decodes the extended attribute value, rejecting a version or
// length it does not recognize rather than guessing at the layout.
func parsePOSIXACL(data []byte) ([]aclEntry, error) {
	if len(data) < aclHeaderSize || (len(data)-aclHeaderSize)%aclEntrySize != 0 {
		return nil, fmt.Errorf("posix acl: unexpected length %d", len(data))
	}
	if version := binary.LittleEndian.Uint32(data); version != aclVersion {
		return nil, fmt.Errorf("posix acl: unsupported version %d", version)
	}

	body := data[aclHeaderSize:]
	entries := make([]aclEntry, 0, len(body)/aclEntrySize)
	for ; len(body) > 0; body = body[aclEntrySize:] {
		entries = append(entries, aclEntry{
			tag:  binary.LittleEndian.Uint16(body),
			perm: binary.LittleEndian.Uint16(body[aclEntryPermOffset:]),
			id:   binary.LittleEndian.Uint32(body[aclEntryIDOffset:]),
		})
	}
	return entries, nil
}

// rootGroupReach reports what group-execute held by root's group confers.
// Any account other than root holding gid 0, as its primary group or among
// its supplementary groups, makes the directory reachable. Finding none
// proves root-only just when every configured account source can be
// enumerated; otherwise an account this host cannot list might hold the
// group, and the answer is undetermined.
func rootGroupReach(ctx context.Context) reachability {
	output, err := exec.CommandContext(ctx, "getent", "passwd").Output()
	if err != nil {
		return reachUndetermined
	}

	var names []string
	for _, account := range parseAccounts(output) {
		switch {
		case account.uid == rootUID:
		case account.gid == rootGID:
			return reachNonRoot
		default:
			names = append(names, account.username)
		}
	}

	member, err := anyInRootGroup(ctx, names)
	switch {
	case err != nil:
		return reachUndetermined
	case member:
		return reachNonRoot
	case !accountSourcesEnumerable():
		return reachUndetermined
	default:
		return reachRootOnly
	}
}

// anyInRootGroup reports whether any named account holds gid 0 as a
// supplementary group. getent initgroups resolves through every configured
// source the way login does, which a group's member list alone does not:
// that list comes from the first source to answer.
func anyInRootGroup(ctx context.Context, names []string) (bool, error) {
	for len(names) > 0 {
		batch := names[:min(len(names), initgroupsBatch)]
		names = names[len(batch):]

		args := append([]string{"initgroups", "--"}, batch...)
		output, err := exec.CommandContext(ctx, "getent", args...).Output() // #nosec G204 -- fixed command; account names follow "--" and reach no shell
		if err != nil {
			return false, execError(err)
		}
		if listsRootGroup(output) {
			return true, nil
		}
	}
	return false, nil
}

// listsRootGroup reports whether any line of getent initgroups output, an
// account name followed by its supplementary group identifiers, carries
// gid 0.
func listsRootGroup(output []byte) bool {
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		for _, field := range fields[1:] {
			if gid, ok := parseUnixID(field); ok && gid == rootGID {
				return true
			}
		}
	}
	return false
}

// accountSourcesEnumerable reports whether every source nsswitch.conf lists
// for accounts and groups is one getent passwd lists in full. files and
// systemd are. sss is ignored while its daemon is not answering and is not
// enumerable while it is, because whether a directory lists its accounts
// depends on how it is configured. Any other source, and a configuration that cannot be read, is
// treated as not enumerable.
func accountSourcesEnumerable() bool {
	data, err := os.ReadFile(nsswitchFile)
	if err != nil {
		return false
	}

	var configured bool
	for _, line := range strings.Split(string(data), "\n") {
		line, _, _ = strings.Cut(line, "#")
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "passwd:", "group:", "initgroups:":
			configured = true
			if !sourcesEnumerable(fields[1:]) {
				return false
			}
		}
	}
	return configured
}

// sourcesEnumerable judges the sources of one nsswitch.conf database line.
// Bracketed action items such as [NOTFOUND=return] are not sources.
func sourcesEnumerable(sources []string) bool {
	var inAction bool
	for _, source := range sources {
		if strings.HasPrefix(source, "[") {
			inAction = true
		}
		if inAction {
			inAction = !strings.HasSuffix(source, "]")
			continue
		}

		switch source {
		case "files", "systemd":
		case "sss":
			if _, err := os.Stat(sssNSSPipe); !errors.Is(err, fs.ErrNotExist) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

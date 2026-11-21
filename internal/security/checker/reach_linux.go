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
)

const (
	// sssNSSPipe is the socket libnss_sss queries. Without it the sss source
	// answers nothing, whatever nsswitch.conf lists.
	sssNSSPipe = "/var/lib/sss/pipes/nss"

	// initgroupsBatch bounds the account names passed to one getent call so
	// a large account database cannot exceed the argument length limit.
	initgroupsBatch = 256
)

// reach judges a directory traversableByNonRoot rejected, by its mode bits
// and the POSIX ACL its extended attribute holds. The owner and group are
// not asked: with group-execute denied to others, the owning group is root's.
func (j *deniedJudge) reach(ctx context.Context, dir string, mode fs.FileMode, _, _ uint32) reachability {
	return j.posixReach(ctx, mode, func() ([]aclEntry, error) {
		entries, err := readPOSIXACL(dir)
		if errors.Is(err, unix.ENODATA) || errors.Is(err, unix.ENOTSUP) {
			return nil, errNoACL
		}
		return entries, err
	})
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
			tag:  uint32(binary.LittleEndian.Uint16(body)),
			perm: uint32(binary.LittleEndian.Uint16(body[aclEntryPermOffset:])),
			id:   binary.LittleEndian.Uint32(body[aclEntryIDOffset:]),
		})
	}
	return entries, nil
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
		output, err := exec.CommandContext(ctx, getentProgram, args...).Output() // #nosec G204 -- fixed command; account names follow "--" and reach no shell
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
	for _, line := range parseNsswitch(data) {
		switch line.database {
		case "passwd", "group", "initgroups":
			configured = true
			if !sourcesEnumerable(line.sources) {
				return false
			}
		}
	}
	return configured
}

// sourcesEnumerable judges the sources of one nsswitch.conf database line.
func sourcesEnumerable(sources []string) bool {
	for _, source := range sources {
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

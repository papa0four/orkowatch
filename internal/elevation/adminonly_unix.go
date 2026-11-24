//go:build linux || darwin || freebsd || openbsd || netbsd

// internal/elevation/adminonly_unix.go

package elevation

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// OpenBeyondAdmins names what lets anyone but root change dir, or returns the
// empty string when nothing does. It is the rule for a directory a privileged
// run trusts what it reads from, and is stricter than Exposure, which also
// accepts the operator: here the operator is one of the others. A link is
// judged as a link and refused, so the directory named is the one judged.
func OpenBeyondAdmins(dir string) (string, error) {
	info, err := os.Lstat(dir)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "not a directory", nil
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", errors.New("no ownership information for the directory")
	}
	return beyondAdmins(st.Uid, st.Gid, info.Mode()), nil
}

// beyondAdmins judges a directory by its owner, group and mode. The owner
// must be root, since a directory's owner can rename what is inside it
// whatever the mode says. No group but root's may write, and the world may
// not write at all: the sticky bit, which Exposure accepts for a place a
// file is written once, still lets anyone add an entry, and an entry added to
// a trusted directory is one a privileged run may come to read.
func beyondAdmins(uid, gid uint32, mode os.FileMode) string {
	perm := mode.Perm()
	switch {
	case uid != rootID:
		return fmt.Sprintf("owned by uid %d, not root", uid)
	case perm&bitGroupWrite != 0 && gid != rootID:
		return fmt.Sprintf("group-writable by gid %d, not root's group", gid)
	case perm&bitOtherWrite != 0:
		return "world-writable"
	default:
		return ""
	}
}

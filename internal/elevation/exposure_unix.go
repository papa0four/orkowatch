//go:build linux || darwin || freebsd || openbsd || netbsd

// internal/elevation/exposure_unix.go

package elevation

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// Permission bits the exposure rule reads.
const (
	bitGroupWrite os.FileMode = 0020
	bitOtherWrite os.FileMode = 0002
)

// Exposure names what lets a user other than root and the invoking operator
// replace entries in dir, or returns the empty string when nothing does.
func Exposure(dir string) (string, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return "", err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", errors.New("no ownership information for the directory")
	}
	invoker, sudo := InvokingOperator()
	return exposed(st.Uid, st.Gid, info.Mode(), invoker, sudo), nil
}

// exposed judges a directory by its owner, group and mode. Ownership decides
// first, because a directory's owner can always rename what is inside it
// whatever the mode says. Group and other write are then judged by who holds
// them: root's group and the operator's primary group are accepted, and the
// sticky bit confines other-write to an entry's own owner.
func exposed(uid, gid uint32, mode os.FileMode, invoker Operator, sudo bool) string {
	perm := mode.Perm()
	switch {
	case uid != rootID && (!sudo || uid != invoker.uid):
		return fmt.Sprintf("owned by uid %d, neither root nor the invoking user", uid)
	case perm&bitGroupWrite != 0 && gid != rootID && (!sudo || gid != invoker.gid):
		return fmt.Sprintf("group-writable by gid %d, neither root's group nor the invoking user's", gid)
	case perm&bitOtherWrite != 0 && mode&os.ModeSticky == 0:
		return "world-writable without the sticky bit"
	default:
		return ""
	}
}

//go:build linux || darwin || freebsd || openbsd || netbsd

// internal/elevation/operator_unix.go

package elevation

import (
	"os"
	"os/user"
	"strconv"
)

const (
	// rootID is the superuser's uid and the gid of its group.
	rootID = 0

	// decimalBase and idBitSize describe the numeric identifiers os/user
	// returns as text: base-10, uid_t and gid_t width.
	decimalBase = 10
	idBitSize   = 32
)

// Operator is the user behind sudo: the identity an elevated run acts for.
type Operator struct {
	Home string
	uid  uint32
	gid  uint32
}

// InvokingOperator returns the user behind sudo, so an elevated run can still
// act in that user's space rather than only root's. It reports false when the
// run was not started through sudo or the account cannot be resolved, which
// leaves root as the only identity a directory is judged against.
func InvokingOperator() (Operator, bool) {
	name := os.Getenv("SUDO_USER")
	if name == "" {
		return Operator{}, false
	}
	u, err := user.Lookup(name)
	if err != nil || u.HomeDir == "" {
		return Operator{}, false
	}
	uid, err := strconv.ParseUint(u.Uid, decimalBase, idBitSize)
	if err != nil {
		return Operator{}, false
	}
	gid, err := strconv.ParseUint(u.Gid, decimalBase, idBitSize)
	if err != nil {
		return Operator{}, false
	}
	return Operator{Home: u.HomeDir, uid: uint32(uid), gid: uint32(gid)}, true
}

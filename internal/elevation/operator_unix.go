//go:build linux || darwin || freebsd || openbsd || netbsd

// internal/elevation/operator_unix.go

package elevation

import (
	"context"
	"os"

	"github.com/papa0four/orkowatch/internal/account"
)

// rootID is the superuser's uid and the gid of its group.
const rootID = 0

// Operator is the user behind sudo: the identity an elevated run acts for.
type Operator struct {
	Home string
	uid  uint32
	gid  uint32
}

// InvokingOperator returns the user behind sudo, so an elevated run can still
// act in that user's space rather than only root's. The account is read from
// the system's records, a directory service's included, and its home is the
// one recorded there. It reports false when the run was not started through
// sudo or the account cannot be resolved, which leaves root as the only
// identity a directory is judged against.
func InvokingOperator() (Operator, bool) {
	name := os.Getenv("SUDO_USER")
	if name == "" {
		return Operator{}, false
	}
	a, err := account.ByName(context.Background(), name)
	if err != nil || a.Home == "" {
		return Operator{}, false
	}
	return Operator{Home: a.Home, uid: a.UID, gid: a.GID}, true
}

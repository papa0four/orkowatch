//go:build linux || darwin || freebsd || openbsd || netbsd

// internal/elevation/operator_unix.go

package elevation

import (
	"context"
	"errors"
	"os"
	"syscall"

	"github.com/papa0four/orkowatch/internal/account"
)

// rootID is the superuser's uid and the gid of its group.
const rootID = 0

// invokerVariables are the variables in which sudo and doas each give the
// command they run the name of the user who ran them.
var invokerVariables = []string{"SUDO_USER", "DOAS_USER"}

// Operator is the user behind sudo or doas: the identity an elevated run acts
// for.
type Operator struct {
	Home string
	uid  uint32
	gid  uint32
}

// InvokingOperator returns the user behind sudo or doas, so an elevated run
// can still act in that user's space rather than only root's. The account is
// read from the system's records, a directory service's included, and its
// home is the one recorded there. It reports false when the run was started
// through neither or the account cannot be resolved, which leaves root as the
// only identity a directory is judged against.
func InvokingOperator() (Operator, bool) {
	var name string
	for _, variable := range invokerVariables {
		if name = os.Getenv(variable); name != "" {
			break
		}
	}
	if name == "" {
		return Operator{}, false
	}
	a, err := account.ByName(context.Background(), name)
	if err != nil || a.Home == "" {
		return Operator{}, false
	}
	return Operator{Home: a.Home, uid: a.UID, gid: a.GID}, true
}

// Owns reports whether the open file f belongs to the operator. It is asked
// of the open file and not of a path, so what is judged is what will be read.
func (o Operator) Owns(f *os.File) (bool, error) {
	info, err := f.Stat()
	if err != nil {
		return false, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false, errors.New("no ownership information for the file")
	}
	return st.Uid == o.uid, nil
}

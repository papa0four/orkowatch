//go:build windows

// internal/elevation/operator_windows.go

package elevation

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"

	"github.com/papa0four/orkowatch/internal/winfolder"
)

// Operator is the account the process runs as: the identity an elevated run
// acts for on Windows, the way the user behind sudo is on Unix.
type Operator struct {
	Home string
	sid  *windows.SID
}

// InvokingOperator returns the account running the process, with its profile
// folder as Windows records it for the account, not as USERPROFILE states it,
// so the environment a run was started with cannot change whose space it acts
// in. It reports false when the profile or the account cannot be resolved.
func InvokingOperator() (Operator, bool) {
	home, err := winfolder.Profile()
	if err != nil {
		return Operator{}, false
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return Operator{}, false
	}
	return Operator{Home: home, sid: user.User.Sid}, true
}

// Owns reports whether the open file f belongs to the operator. It is asked
// of the open file and not of a path, so what is judged is what will be read.
func (o Operator) Owns(f *os.File) (bool, error) {
	if o.sid == nil {
		return false, errors.New("the operator's account is not known")
	}
	sd, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return false, fmt.Errorf("read the file's owner: %w", err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return false, errors.Join(errors.New("the file's owner could not be read"), err)
	}
	return owner.Equals(o.sid), nil
}

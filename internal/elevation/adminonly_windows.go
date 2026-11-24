//go:build windows

// internal/elevation/adminonly_windows.go

package elevation

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows"
)

// OpenBeyondAdmins names what lets a principal other than the system and the
// administrators change dir, or returns the empty string when nothing does.
// It is the rule for a directory a privileged run trusts what it reads from,
// and is stricter than Exposure, which also accepts the directory's owner and
// the account running the process: here the owner must itself be the system
// or the administrators, and that account is one of the others. A reparse
// point is refused, so the directory named is the one judged.
func OpenBeyondAdmins(dir string) (string, error) {
	path, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return "", err
	}
	attrs, err := windows.GetFileAttributes(path)
	if err != nil {
		return "", fmt.Errorf("read attributes: %w", err)
	}
	switch {
	case attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0:
		return "a reparse point, not a directory", nil
	case attrs&windows.FILE_ATTRIBUTE_DIRECTORY == 0:
		return "not a directory", nil
	}

	sd, err := windows.GetNamedSecurityInfo(
		dir,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return "", fmt.Errorf("read security info: %w", err)
	}
	admins, err := wellKnownSIDs(windows.WinLocalSystemSid, windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return "", err
	}

	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return "", errors.Join(errors.New("the directory's owner could not be read"), err)
	}
	if !sidTrusted(owner, admins) {
		return fmt.Sprintf("owned by %s, neither the system nor the administrators", owner), nil
	}
	return writerBeyond(sd, admins)
}

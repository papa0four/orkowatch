//go:build windows

// internal/elevation/exposure_windows.go

package elevation

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// fileDeleteChild is the directory right to delete child objects
const fileDeleteChild = 0x40

// Exposure names what gives a principal other than the system, the
// administrators and the directory's owner write access to dir, or returns
// the empty string when nothing does.
func Exposure(dir string) (string, error) {
	sd, err := windows.GetNamedSecurityInfo(
		dir,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return "", fmt.Errorf("read security info: %w", err)
	}

	trusted, err := trustedSIDs(sd)
	if err != nil {
		return "", err
	}
	return writerBeyond(sd, trusted)
}

// writerBeyond names the first principal outside trusted that sd's access
// control list lets change the directory, or returns the empty string when
// there is none. An entry that cannot be read is an error rather than the end
// of the list: stopping there would call a directory safe on the strength of
// entries nobody examined.
func writerBeyond(sd *windows.SECURITY_DESCRIPTOR, trusted []*windows.SID) (string, error) {
	dacl, _, err := sd.DACL()
	if errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) || (err == nil && dacl == nil) {
		// A missing or NULL DACL grants everyone full access.
		return "open to every principal: it has no access control list", nil
	}
	if err != nil {
		return "", fmt.Errorf("read dacl: %w", err)
	}

	const writeMask = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA |
		fileDeleteChild | windows.DELETE |
		windows.GENERIC_WRITE | windows.GENERIC_ALL |
		windows.WRITE_DAC | windows.WRITE_OWNER

	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return "", fmt.Errorf("read access control entry %d: %w", i, err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Mask&writeMask == 0 {
			continue
		}

		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)) // #nosec G103 -- SID embedded in an entry GetAce validated
		if !sidTrusted(sid, trusted) {
			return fmt.Sprintf("writable by %s", sid), nil
		}
	}
	return "", nil
}

// trustedSIDs returns the principals whose write access to a directory is
// not an exposure: the system, the administrators, the directory's owner, and
// the account running the elevated process, which is the operator on Windows
// the way the user behind sudo is on Unix.
func trustedSIDs(sd *windows.SECURITY_DESCRIPTOR) ([]*windows.SID, error) {
	trusted, err := wellKnownSIDs(windows.WinLocalSystemSid, windows.WinBuiltinAdministratorsSid, windows.WinCreatorOwnerSid)
	if err != nil {
		return nil, err
	}
	if owner, _, err := sd.Owner(); err == nil && owner != nil {
		trusted = append(trusted, owner)
	}

	operator, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("token user: %w", err)
	}
	trusted = append(trusted, operator.User.Sid)

	return trusted, nil
}

// wellKnownSIDs returns the SIDs Windows defines for kinds.
func wellKnownSIDs(kinds ...windows.WELL_KNOWN_SID_TYPE) ([]*windows.SID, error) {
	sids := make([]*windows.SID, 0, len(kinds))
	for _, kind := range kinds {
		sid, err := windows.CreateWellKnownSid(kind)
		if err != nil {
			return nil, fmt.Errorf("well-known sid: %w", err)
		}
		sids = append(sids, sid)
	}
	return sids, nil
}

func sidTrusted(sid *windows.SID, trusted []*windows.SID) bool {
	for _, t := range trusted {
		if sid.Equals(t) {
			return true
		}
	}
	return false
}

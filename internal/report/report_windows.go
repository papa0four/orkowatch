//go:build windows

// internal/report/report_windows.go

package report

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/papa0four/orkowatch/internal/winfolder"
)

// fileDeleteChild is the directory right to delete child objects
const fileDeleteChild = 0x40

// refusedFolders are the system locations a report is never written into:
// the OS files and the installed programs.
var refusedFolders = []winfolder.Folder{
	winfolder.Windows,
	winfolder.ProgramFiles,
	winfolder.ProgramFilesX86,
}

// refusedReason names the refused location target lies in, or returns empty
// when it lies in none. The locations are the system folders and every place
// a Startup folder, for every user or for this one, may be, which an attacker
// would use for persistence. None is read from an environment variable. A
// location that cannot be resolved refuses the write: whether target lies in
// it is unknown.
func refusedReason(target string) string {
	bases, err := refusedBases()
	if err != nil {
		return err.Error()
	}
	// Windows paths are case-insensitive, so fold both sides before comparing.
	target = strings.ToLower(filepath.Clean(target))
	for _, base := range bases {
		if pathWithin(target, strings.ToLower(filepath.Clean(base))) {
			return base
		}
	}
	return ""
}

// refusedBases resolves every refused location.
func refusedBases() ([]string, error) {
	bases, err := winfolder.StartupFolders()
	if err != nil {
		return nil, err
	}
	for _, folder := range refusedFolders {
		base, err := folder.Path()
		if err != nil {
			return nil, err
		}
		bases = append(bases, base)
	}
	return bases, nil
}

// canonicalParent returns the OS-resolved long-form path of parent so the
// location checks cannot be evaded by 8.3 short names, links, or trailing dots
// and spaces.
func canonicalParent(parent string) (final string, err error) {
	if strings.HasPrefix(parent, `\\?\`) || strings.HasPrefix(parent, `\\.\`) {
		return "", fmt.Errorf("%w: extended-length or device path", ErrRefusedLocation)
	}

	p, err := windows.UTF16PtrFromString(parent)
	if err != nil {
		return "", fmt.Errorf("encode path: %w", err)
	}

	// Backup semantics are required to obtain a directory handle.
	h, err := windows.CreateFile(
		p,
		windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrParentMissing, parent)
	}
	defer func() {
		if cerr := windows.CloseHandle(h); cerr != nil && err == nil {
			err = fmt.Errorf("close directory handle: %w", cerr)
		}
	}()

	const finalPathFlags = 0
	buf := make([]uint16, windows.MAX_PATH)
	n, err := windows.GetFinalPathNameByHandle(h, &buf[0], windows.MAX_PATH, finalPathFlags)
	if err != nil {
		return "", fmt.Errorf("canonicalize path: %w", err)
	}
	if int(n) > len(buf) {
		buf = make([]uint16, n)
		if _, err := windows.GetFinalPathNameByHandle(h, &buf[0], n, finalPathFlags); err != nil {
			return "", fmt.Errorf("canonicalize path: %w", err)
		}
	}

	final = windows.UTF16ToString(buf)
	if rest := strings.TrimPrefix(final, `\\?\UNC\`); rest != final {
		return `\\` + rest, nil
	}
	return strings.TrimPrefix(final, `\\?\`), nil
}

// isElevated reports an elevated (Administrator) token, where a write can land
// anywhere and the tool becomes a privileged write primitive.
func isElevated() (bool, error) {
	return windows.GetCurrentProcessToken().IsElevated(), nil
}

// withinAllowlist permits an elevated write only under roots the operator
// clearly owns, so a privileged run cannot silently write elsewhere.
func withinAllowlist(target string) (bool, error) {
	target = strings.ToLower(filepath.Clean(target))
	for _, root := range allowlistRoots() {
		real, err := canonicalParent(root)
		if err != nil {
			continue
		}
		if pathWithin(target, strings.ToLower(filepath.Clean(real))) {
			return true, nil
		}
	}
	return false, nil
}

// allowlistRoots are the working directory and the operator's profile folder
// as Windows records it for the account, not as USERPROFILE states it, so
// the environment a run was started with cannot widen where it may write.
func allowlistRoots() []string {
	roots := make([]string, 0, maxOperatorHomes)
	if cwd, err := os.Getwd(); err == nil {
		roots = append(roots, cwd)
	}
	if home, err := winfolder.Profile(); err == nil {
		roots = append(roots, home)
	}
	return roots
}

// exposure names what gives a principal other than the system, the
// administrators and the directory's owner write access to dir, or returns
// the empty string when nothing does. An entry that cannot be read is an
// error rather than the end of the list: stopping there would call a
// directory safe on the strength of entries nobody examined.
func exposure(dir string) (string, error) {
	sd, err := windows.GetNamedSecurityInfo(
		dir,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return "", fmt.Errorf("read security info: %w", err)
	}

	dacl, _, err := sd.DACL()
	if errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) || (err == nil && dacl == nil) {
		// A missing or NULL DACL grants everyone full access.
		return "open to every principal: it has no access control list", nil
	}
	if err != nil {
		return "", fmt.Errorf("read dacl: %w", err)
	}

	trusted, err := trustedSIDs(sd)
	if err != nil {
		return "", err
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

// trustedSIDs returns the principals whose write access to a destination is
// not an exposure: the system, the administrators, the directory's owner, and
// the account running the elevated process, which is the operator on Windows
// the way the user behind sudo is on Unix.
func trustedSIDs(sd *windows.SECURITY_DESCRIPTOR) ([]*windows.SID, error) {
	wellKnown := []windows.WELL_KNOWN_SID_TYPE{
		windows.WinLocalSystemSid,
		windows.WinBuiltinAdministratorsSid,
		windows.WinCreatorOwnerSid,
	}
	trusted := make([]*windows.SID, 0, len(wellKnown))
	for _, t := range wellKnown {
		sid, err := windows.CreateWellKnownSid(t)
		if err != nil {
			return nil, fmt.Errorf("well-known sid: %w", err)
		}
		trusted = append(trusted, sid)
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

func sidTrusted(sid *windows.SID, trusted []*windows.SID) bool {
	for _, t := range trusted {
		if sid.Equals(t) {
			return true
		}
	}
	return false
}

// openAndWrite creates target and writes data to it. The name is generated
// per run, so nothing legitimate is ever there already: CREATE_NEW refuses
// whatever is, and OPEN_REPARSE_POINT makes a planted link count as that
// existing entry where the default open would resolve it and create its
// target.
func openAndWrite(target string, data []byte) (err error) {
	path, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return fmt.Errorf("encode path: %w", err)
	}

	handle, err := windows.CreateFile(
		path,
		windows.GENERIC_WRITE,
		0,
		nil,
		windows.CREATE_NEW,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return fmt.Errorf("create destination: %w", err)
	}
	f := os.NewFile(uintptr(handle), target)
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	if _, werr := f.Write(data); werr != nil {
		return fmt.Errorf("write report: %w", werr)
	}
	return nil
}

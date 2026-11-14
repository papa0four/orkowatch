//go:build windows

// internal/security/checker/acl_windows.go

// Native reads of file and directory access control lists. Grants are judged
// by the SID they name and the access mask they carry, which are the same on
// every Windows installation, where the text icacls prints is localized.

package checker

import (
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	// fileAllAccess is FILE_ALL_ACCESS: every standard and file-specific
	// right, which is what the access editor calls full control.
	fileAllAccess = 0x1F01FF

	// fileDeleteChild is the directory right to delete child objects.
	fileDeleteChild = 0x40

	// Access control entry flags from winnt.h.
	aceInheritOnly = 0x08
	aceInherited   = 0x10

	// aclInitialBuffer holds the security descriptor of nearly every file
	// without a second call; the reader grows it when one does not fit.
	aclInitialBuffer = 1024

	// longPathThreshold is where a path needs the extended-length prefix to
	// be accepted by the file security call.
	longPathThreshold = 248
	longPathPrefix    = `\\?\`

	// accountSIDPrefix begins the SIDs of user and group accounts issued by
	// a machine or a domain, which are the ones that can be orphaned.
	accountSIDPrefix = "S-1-5-21-"
)

// The access a grant confers, as the facts recorded about it.
const (
	accessFull   = "full control"
	accessModify = "modify"
	accessWrite  = "write"

	writeDataRights = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA
	changeRights    = writeDataRights | fileDeleteChild | windows.DELETE |
		windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_WRITE | windows.GENERIC_ALL
)

type (
	// aclReader reads access control lists into one reused buffer, so a
	// traversal of a whole volume does not allocate per entry. principals
	// caches what each account SID resolved to.
	aclReader struct {
		buf        []byte
		broad      []broadPrincipal
		principals map[string]principal
	}

	// broadPrincipal is a well-known group that takes in accounts beyond
	// the administrators and the system.
	broadPrincipal struct {
		sid  *windows.SID
		kind windows.WELL_KNOWN_SID_TYPE
	}

	// principal is what a SID resolved to. resolved is false for a SID no
	// account answers to.
	principal struct {
		name     string
		resolved bool
	}

	// aclGrant is one allow entry of an access control list.
	aclGrant struct {
		sid   *windows.SID
		mask  uint32
		flags uint8
	}
)

// advapi32 procedure golang.org/x/sys/windows does not wrap.
// GetNamedSecurityInfo is not used for the traversal because it allocates a
// descriptor per call.
var procGetFileSecurity = windows.NewLazySystemDLL("advapi32.dll").NewProc("GetFileSecurityW")

// newACLReader prepares a reader and the well-known SIDs it classifies
// grants against.
func newACLReader() (*aclReader, error) {
	reader := &aclReader{
		buf:        make([]byte, aclInitialBuffer),
		principals: make(map[string]principal),
	}
	for _, kind := range []windows.WELL_KNOWN_SID_TYPE{
		windows.WinWorldSid,
		windows.WinAuthenticatedUserSid,
		windows.WinBuiltinUsersSid,
	} {
		sid, err := windows.CreateWellKnownSid(kind)
		if err != nil {
			return nil, fmt.Errorf("well-known sid: %w", err)
		}
		reader.broad = append(reader.broad, broadPrincipal{sid: sid, kind: kind})
	}
	return reader, nil
}

// grants returns the allow entries of path's access control list. open
// reports a path with no list at all, which grants everyone everything. The
// returned grants point into the reader's buffer and are valid until the next
// call.
func (a *aclReader) grants(path string) (grants []aclGrant, open bool, err error) {
	if len(path) >= longPathThreshold && !strings.HasPrefix(path, longPathPrefix) {
		path = longPathPrefix + path
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, false, err
	}

	for {
		var needed uint32
		ok, _, callErr := procGetFileSecurity.Call(
			uintptr(unsafe.Pointer(name)), // #nosec G103 -- pointer to a NUL-terminated UTF-16 string for the duration of the call
			uintptr(windows.DACL_SECURITY_INFORMATION),
			uintptr(unsafe.Pointer(&a.buf[0])), // #nosec G103 -- buffer the call fills, sized by the next argument
			uintptr(len(a.buf)),
			uintptr(unsafe.Pointer(&needed)), // #nosec G103 -- out parameter
		)
		if ok != 0 {
			break
		}
		if !errors.Is(callErr, windows.ERROR_INSUFFICIENT_BUFFER) || int(needed) <= len(a.buf) {
			return nil, false, callErr
		}
		a.buf = make([]byte, needed)
	}

	sd := (*windows.SECURITY_DESCRIPTOR)(unsafe.Pointer(&a.buf[0])) // #nosec G103 -- the call wrote a self-relative security descriptor at the start of the buffer
	dacl, _, err := sd.DACL()
	switch {
	case errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND), err == nil && dacl == nil:
		return nil, true, nil
	case err != nil:
		return nil, false, err
	}

	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return nil, false, fmt.Errorf("read access control entry %d: %w", i, err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		grants = append(grants, aclGrant{
			sid:   (*windows.SID)(unsafe.Pointer(&ace.SidStart)), // #nosec G103 -- SID embedded in an entry GetAce validated
			mask:  uint32(ace.Mask),
			flags: ace.Header.AceFlags,
		})
	}
	return grants, false, nil
}

// broadGroup reports which well-known broad group sid is, if any.
func (a *aclReader) broadGroup(sid *windows.SID) (windows.WELL_KNOWN_SID_TYPE, bool) {
	for _, group := range a.broad {
		if windows.EqualSid(sid, group.sid) {
			return group.kind, true
		}
	}
	return 0, false
}

// resolve returns what sid resolves to, asking the system once per SID. A
// lookup that fails for any reason other than the SID being unmapped is
// treated as resolved, so an unreachable domain controller does not turn
// every domain account into an orphan.
func (a *aclReader) resolve(sid *windows.SID) principal {
	key := sid.String()
	if known, seen := a.principals[key]; seen {
		return known
	}

	account, domain, _, err := sid.LookupAccount("")
	resolved := principal{name: key, resolved: !errors.Is(err, windows.ERROR_NONE_MAPPED)}
	if err == nil {
		resolved.name = account
		if domain != "" {
			resolved.name = domain + `\` + account
		}
	}
	a.principals[key] = resolved
	return resolved
}

// accessLevel names the access a mask confers, or returns the empty string
// for one that lets its holder change nothing.
func accessLevel(mask uint32) string {
	switch {
	case mask&windows.GENERIC_ALL != 0, mask&fileAllAccess == fileAllAccess:
		return accessFull
	case mask&changeRights == 0:
		return ""
	case mask&windows.DELETE != 0 && mask&writeDataRights != 0:
		return accessModify
	default:
		return accessWrite
	}
}

// grantScope names how an entry came to be on the object it was read from.
func grantScope(flags uint8) string {
	switch {
	case flags&aceInherited != 0:
		return "inherited"
	case flags&aceInheritOnly != 0:
		return "set here, applies to children only"
	default:
		return "set here"
	}
}

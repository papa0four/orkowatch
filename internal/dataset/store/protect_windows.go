//go:build windows

// internal/dataset/store/protect_windows.go

package store

import (
	"errors"
	"fmt"
	"io/fs"
	"unsafe"

	"golang.org/x/sys/windows"
)

// protectedSDDL is the access control list a directory of the protected store
// is made with: the system and the administrators in full, for the directory
// and everything made in it, and nothing inherited from the directory above.
// The ProgramData folder lets any user make a directory others of its kind
// can write, so the list is stated and not left to inheritance.
const protectedSDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

// tokenOwner is the TOKEN_OWNER structure: the default owner of what a
// process creates.
type tokenOwner struct {
	Owner *windows.SID
}

// makeProtected makes dir with the protected store's access control list. Its
// owner is the process's default, which beginProtected has made the
// administrators.
func makeProtected(dir string) error {
	sd, err := windows.SecurityDescriptorFromString(protectedSDDL)
	if err != nil {
		return fmt.Errorf("build the protected store's access control list: %w", err)
	}
	path, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return &fs.PathError{Op: "mkdir", Path: dir, Err: err}
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(sa))
	if err := windows.CreateDirectory(path, &sa); err != nil {
		return &fs.PathError{Op: "mkdir", Path: dir, Err: err}
	}
	return nil
}

// beginProtected makes the administrators the default owner of what the
// process creates, and returns what puts the default back. An elevated
// process's default owner is the account it runs as, and an owner can rewrite
// the access control list of what it owns, so a file left to that default
// could be changed by the same account's processes that are not elevated.
// The store sets it only while it holds its lock, so nothing else the run
// writes, such as a report, changes owner.
func beginProtected() (func() error, error) {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_ADJUST_DEFAULT, &token); err != nil {
		return nil, fmt.Errorf("open the process token: %w", err)
	}
	prior, err := defaultOwner(token)
	if err != nil {
		return nil, errors.Join(err, token.Close())
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("the administrators' sid: %w", err), token.Close())
	}
	if err := setDefaultOwner(token, admins); err != nil {
		return nil, errors.Join(fmt.Errorf("make the administrators the owner of what the store creates: %w", err), token.Close())
	}
	return func() error {
		return errors.Join(setDefaultOwner(token, prior), token.Close())
	}, nil
}

// defaultOwner reads the default owner of what the process creates, as a SID
// of its own that outlives the buffer it was read into.
func defaultOwner(token windows.Token) (*windows.SID, error) {
	var size uint32
	err := windows.GetTokenInformation(token, windows.TokenOwner, nil, 0, &size)
	if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
		return nil, fmt.Errorf("size the token's owner: %w", err)
	}
	buf := make([]byte, size)
	if err := windows.GetTokenInformation(token, windows.TokenOwner, &buf[0], size, &size); err != nil {
		return nil, fmt.Errorf("read the token's owner: %w", err)
	}
	owner := (*tokenOwner)(unsafe.Pointer(&buf[0])).Owner // #nosec G103 -- the TOKEN_OWNER GetTokenInformation wrote into buf
	return owner.Copy()
}

// setDefaultOwner makes owner the default owner of what the process creates.
func setDefaultOwner(token windows.Token, owner *windows.SID) error {
	info := tokenOwner{Owner: owner}
	return windows.SetTokenInformation(token, windows.TokenOwner, (*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))) // #nosec G103 -- the TOKEN_OWNER SetTokenInformation reads
}

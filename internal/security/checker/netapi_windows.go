//go:build windows

// internal/security/checker/netapi_windows.go

// Native reads of the local account database, group membership and account
// policy through the Network Management API. These return flag bits, SIDs and
// integers where the tools they replace print localized text.

package checker

import (
	"errors"
	"fmt"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Network Management API values from lmaccess.h. The structure layouts below
// were confirmed on a live host against what Get-LocalUser and net accounts
// report for the same accounts and policy.
const (
	// netFilterNormalAccount selects ordinary user accounts, leaving out the
	// machine and trust accounts a domain controller also holds.
	netFilterNormalAccount = 0x0002

	// netPreferAllEntries asks for every entry in one buffer.
	netPreferAllEntries = 0xFFFFFFFF

	// policyForever is how the policy calls report a limit that is not set.
	policyForever = 0xFFFFFFFF

	// Account flag bits in USER_INFO_1.usri1_flags.
	ufAccountDisable = 0x0002
	ufPasswordNotReq = 0x0020

	// Information levels: which structure a call returns.
	userLevelFlags      = 1
	userLevelIdentity   = 24
	modalsLevelPassword = 0
	modalsLevelLockout  = 3
	membersLevelSID     = 0
)

type (
	// userInfo1 is USER_INFO_1. A member this reader does not use keeps its
	// place in the layout under the blank name, with its own name beside it.
	userInfo1 struct {
		name  *uint16
		_     *uint16 // usri1_password
		_     uint32  // usri1_password_age
		_     uint32  // usri1_priv
		_     *uint16 // usri1_home_dir
		_     *uint16 // usri1_comment
		flags uint32
		_     *uint16 // usri1_script_path
	}

	// userInfo24 is USER_INFO_24, which reports whether an account is
	// connected to an Internet identity and carries the account's SID.
	userInfo24 struct {
		internetIdentity int32
		_                uint32  // usri24_flags
		_                *uint16 // usri24_internet_provider_name
		_                *uint16 // usri24_internet_principal_name
		sid              *windows.SID
	}

	// userModals0 is USER_MODALS_INFO_0: the password policy.
	userModals0 struct {
		minPasswordLen     uint32
		maxPasswordAge     uint32
		minPasswordAge     uint32
		_                  uint32 // usrmod0_force_logoff
		passwordHistoryLen uint32
	}

	// userModals3 is USER_MODALS_INFO_3: the lockout policy.
	userModals3 struct {
		lockoutDuration          uint32
		lockoutObservationWindow uint32
		lockoutThreshold         uint32
	}

	// localGroupMember0 is LOCALGROUP_MEMBERS_INFO_0.
	localGroupMember0 struct {
		sid *windows.SID
	}

	// windowsAccount is one local account as the account database records
	// it. identityErr is set when the account's SID and Internet identity
	// could not be read, in which case neither sid nor internetIdentity
	// means anything.
	windowsAccount struct {
		name             string
		sid              string
		enabled          bool
		passwordRequired bool
		internetIdentity bool
		identityErr      error
	}

	// windowsPasswordPolicy is the local password and lockout policy. Ages
	// and durations are zero when the policy sets none.
	windowsPasswordPolicy struct {
		minLength        uint32
		historyLength    uint32
		maxAge           time.Duration
		minAge           time.Duration
		lockoutThreshold uint32
		lockoutDuration  time.Duration
		lockoutWindow    time.Duration
	}
)

// netapi32 procedures golang.org/x/sys/windows does not wrap.
var (
	netapi32                    = windows.NewLazySystemDLL("netapi32.dll")
	procNetUserModalsGet        = netapi32.NewProc("NetUserModalsGet")
	procNetLocalGroupGetMembers = netapi32.NewProc("NetLocalGroupGetMembers")
)

// errNoBuffer is the answer to a Network Management call that reported
// success and entries and returned no buffer to read them from.
var errNoBuffer = errors.New("the call reported success and returned no buffer")

// netEntries returns the count entries of layout T that a Network Management
// call returned at buf. Every structure these calls return is read through
// it, so a call that reports entries and hands back no buffer is an error the
// check reports, where reading the layout from nothing would end the run.
func netEntries[T any](buf *byte, count uint32) ([]T, error) {
	switch {
	case count == 0:
		return nil, nil
	case buf == nil:
		return nil, errNoBuffer
	}
	return unsafe.Slice((*T)(unsafe.Pointer(buf)), count), nil // #nosec G103 -- the call returned count entries of this layout at buf, which is not nil
}

// localAccounts enumerates the local account database.
func localAccounts() ([]windowsAccount, error) {
	var accounts []windowsAccount
	var resume uint32

	for {
		var buf *byte
		var read, total uint32
		err := windows.NetUserEnum(nil, userLevelFlags, netFilterNormalAccount, &buf, netPreferAllEntries, &read, &total, &resume)
		if err != nil && !errors.Is(err, windows.ERROR_MORE_DATA) {
			return nil, fmt.Errorf("enumerate local accounts: %w", err)
		}

		entries, entriesErr := netEntries[userInfo1](buf, read)
		if entriesErr != nil {
			return nil, fmt.Errorf("enumerate local accounts: %w", entriesErr)
		}
		for _, entry := range entries {
			account := windowsAccount{
				name:             windows.UTF16PtrToString(entry.name),
				enabled:          entry.flags&ufAccountDisable == 0,
				passwordRequired: entry.flags&ufPasswordNotReq == 0,
			}
			account.sid, account.internetIdentity, account.identityErr = accountIdentity(entry.name)
			accounts = append(accounts, account)
		}
		freeNetBuffer(buf)

		if err == nil {
			return accounts, nil
		}
	}
}

// accountIdentity returns an account's SID and whether Windows records it as
// connected to an Internet identity, which is how a Microsoft account sign-in
// is represented on a local account.
func accountIdentity(name *uint16) (sid string, internetIdentity bool, err error) {
	var buf *byte
	if err := windows.NetUserGetInfo(nil, name, userLevelIdentity, &buf); err != nil {
		return "", false, err
	}
	defer freeNetBuffer(buf)

	info, err := netEntries[userInfo24](buf, 1)
	switch {
	case err != nil:
		return "", false, err
	case info[0].sid == nil:
		return "", false, errors.New("account record carries no SID")
	}
	return info[0].sid.String(), info[0].internetIdentity != 0, nil
}

// administratorSIDs returns the SIDs of the members of the local
// Administrators group. The group is found by its well-known SID, because its
// name is localized.
func administratorSIDs() (map[string]bool, error) {
	group, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return nil, fmt.Errorf("administrators group sid: %w", err)
	}
	groupName, _, _, err := group.LookupAccount("")
	if err != nil {
		return nil, fmt.Errorf("resolve administrators group name: %w", err)
	}
	name, err := windows.UTF16PtrFromString(groupName)
	if err != nil {
		return nil, fmt.Errorf("encode group name: %w", err)
	}

	var buf *byte
	var read, total uint32
	var resume uintptr
	status, _, _ := procNetLocalGroupGetMembers.Call( //nolint:errcheck // the third result is GetLastError, which this API does not set; status carries the outcome
		0,
		uintptr(unsafe.Pointer(name)), // #nosec G103 -- pointer to a NUL-terminated UTF-16 string for the duration of the call
		membersLevelSID,
		uintptr(unsafe.Pointer(&buf)), // #nosec G103 -- out parameter receiving the buffer
		netPreferAllEntries,
		uintptr(unsafe.Pointer(&read)),   // #nosec G103 -- out parameter
		uintptr(unsafe.Pointer(&total)),  // #nosec G103 -- out parameter
		uintptr(unsafe.Pointer(&resume)), // #nosec G103 -- in-out parameter
	)
	if status != 0 {
		return nil, fmt.Errorf("list administrators group members: %w", syscall.Errno(status))
	}
	defer freeNetBuffer(buf)

	entries, err := netEntries[localGroupMember0](buf, read)
	if err != nil {
		return nil, fmt.Errorf("list administrators group members: %w", err)
	}
	members := make(map[string]bool, read)
	for _, member := range entries {
		if member.sid != nil {
			members[member.sid.String()] = true
		}
	}
	return members, nil
}

// passwordPolicy reads the local password and lockout policy.
func passwordPolicy() (windowsPasswordPolicy, error) {
	var policy windowsPasswordPolicy

	info, err := userModals[userModals0](modalsLevelPassword)
	if err != nil {
		return policy, fmt.Errorf("read password policy: %w", err)
	}
	policy.minLength = info.minPasswordLen
	policy.historyLength = info.passwordHistoryLen
	policy.maxAge = policyDuration(info.maxPasswordAge)
	policy.minAge = policyDuration(info.minPasswordAge)

	limits, err := userModals[userModals3](modalsLevelLockout)
	if err != nil {
		return policy, fmt.Errorf("read lockout policy: %w", err)
	}
	policy.lockoutThreshold = limits.lockoutThreshold
	policy.lockoutDuration = policyDuration(limits.lockoutDuration)
	policy.lockoutWindow = policyDuration(limits.lockoutObservationWindow)

	return policy, nil
}

// userModals returns a copy of the policy structure for level, whose layout
// T is, and frees what the call allocated.
func userModals[T any](level uintptr) (T, error) {
	var policy T
	var buf *byte
	out := uintptr(unsafe.Pointer(&buf))                     // #nosec G103 -- out parameter receiving the buffer
	status, _, _ := procNetUserModalsGet.Call(0, level, out) //nolint:errcheck // the third result is GetLastError, which this API does not set; status carries the outcome
	if status != 0 {
		return policy, syscall.Errno(status)
	}
	defer freeNetBuffer(buf)

	entries, err := netEntries[T](buf, 1)
	if err != nil {
		return policy, err
	}
	return entries[0], nil
}

// policyDuration converts a policy value in seconds, returning zero for a
// limit the policy does not set.
func policyDuration(seconds uint32) time.Duration {
	if seconds == policyForever {
		return 0
	}
	return time.Duration(seconds) * time.Second
}

// freeNetBuffer releases a buffer the Network Management API allocated.
func freeNetBuffer(buf *byte) {
	if buf != nil {
		_ = windows.NetApiBufferFree(buf) //nolint:errcheck // nothing to do if the system cannot free its own buffer
	}
}

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
	// userInfo1 is USER_INFO_1.
	userInfo1 struct {
		name        *uint16
		password    *uint16
		passwordAge uint32
		priv        uint32
		homeDir     *uint16
		comment     *uint16
		flags       uint32
		scriptPath  *uint16
	}

	// userInfo24 is USER_INFO_24, which reports whether an account is
	// connected to an Internet identity and carries the account's SID.
	userInfo24 struct {
		internetIdentity      int32
		flags                 uint32
		internetProviderName  *uint16
		internetPrincipalName *uint16
		sid                   *windows.SID
	}

	// userModals0 is USER_MODALS_INFO_0: the password policy.
	userModals0 struct {
		minPasswordLen     uint32
		maxPasswordAge     uint32
		minPasswordAge     uint32
		forceLogoff        uint32
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

		for _, entry := range unsafe.Slice((*userInfo1)(unsafe.Pointer(buf)), read) { // #nosec G103 -- NetUserEnum returned read entries of this layout at buf
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

	info := (*userInfo24)(unsafe.Pointer(buf)) // #nosec G103 -- NetUserGetInfo returned one entry of this layout at buf
	if info.sid == nil {
		return "", false, errors.New("account record carries no SID")
	}
	return info.sid.String(), info.internetIdentity != 0, nil
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

	members := make(map[string]bool, read)
	for _, member := range unsafe.Slice((*localGroupMember0)(unsafe.Pointer(buf)), read) { // #nosec G103 -- NetLocalGroupGetMembers returned read entries of this layout at buf
		if member.sid != nil {
			members[member.sid.String()] = true
		}
	}
	return members, nil
}

// passwordPolicy reads the local password and lockout policy.
func passwordPolicy() (windowsPasswordPolicy, error) {
	var policy windowsPasswordPolicy

	password, err := userModals(modalsLevelPassword)
	if err != nil {
		return policy, fmt.Errorf("read password policy: %w", err)
	}
	info := (*userModals0)(unsafe.Pointer(password)) // #nosec G103 -- NetUserModalsGet returned this layout for level 0
	policy.minLength = info.minPasswordLen
	policy.historyLength = info.passwordHistoryLen
	policy.maxAge = policyDuration(info.maxPasswordAge)
	policy.minAge = policyDuration(info.minPasswordAge)
	freeNetBuffer(password)

	lockout, err := userModals(modalsLevelLockout)
	if err != nil {
		return policy, fmt.Errorf("read lockout policy: %w", err)
	}
	limits := (*userModals3)(unsafe.Pointer(lockout)) // #nosec G103 -- NetUserModalsGet returned this layout for level 3
	policy.lockoutThreshold = limits.lockoutThreshold
	policy.lockoutDuration = policyDuration(limits.lockoutDuration)
	policy.lockoutWindow = policyDuration(limits.lockoutObservationWindow)
	freeNetBuffer(lockout)

	return policy, nil
}

// userModals returns the policy structure for level. The caller frees it.
func userModals(level uintptr) (*byte, error) {
	var buf *byte
	out := uintptr(unsafe.Pointer(&buf))                     // #nosec G103 -- out parameter receiving the buffer
	status, _, _ := procNetUserModalsGet.Call(0, level, out) //nolint:errcheck // the third result is GetLastError, which this API does not set; status carries the outcome
	if status != 0 {
		return nil, syscall.Errno(status)
	}
	return buf, nil
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

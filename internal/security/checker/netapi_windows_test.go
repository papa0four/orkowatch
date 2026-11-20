//go:build windows

// internal/security/checker/netapi_windows_test.go

package checker

import (
	"errors"
	"testing"
	"unsafe"
)

// The entries a Network Management call returned are read from its buffer,
// and a call that reports entries with no buffer is an error and not a read
// of nothing, which would end the run.
func TestNetEntries(t *testing.T) {
	records := []userModals3{
		{lockoutDuration: 1800, lockoutObservationWindow: 900, lockoutThreshold: 5},
		{lockoutDuration: 60, lockoutObservationWindow: 30, lockoutThreshold: 3},
	}
	buf := (*byte)(unsafe.Pointer(&records[0]))

	got, err := netEntries[userModals3](buf, uint32(len(records)))
	if err != nil || len(got) != len(records) || got[0] != records[0] || got[1] != records[1] {
		t.Errorf("two entries at a buffer: %+v, %v", got, err)
	}

	if got, err := netEntries[userModals3](nil, 0); err != nil || len(got) != 0 {
		t.Errorf("no entries and no buffer: %+v, %v", got, err)
	}
	if got, err := netEntries[userModals3](buf, 0); err != nil || len(got) != 0 {
		t.Errorf("no entries at a buffer: %+v, %v", got, err)
	}
	if got, err := netEntries[userInfo24](nil, 1); !errors.Is(err, errNoBuffer) || got != nil {
		t.Errorf("an entry reported with no buffer: %+v, %v", got, err)
	}
}

// The local accounts, the members of the Administrators group and the
// password policy are read from this host through the same path, and each
// answers.
func TestNetworkManagementReadsThisHost(t *testing.T) {
	accounts, err := localAccounts()
	if err != nil || len(accounts) == 0 {
		t.Fatalf("local accounts: %d, %v", len(accounts), err)
	}
	for _, account := range accounts {
		if account.name == "" || (account.identityErr == nil && account.sid == "") {
			t.Errorf("an account was read without its name or SID: %+v", account)
		}
	}
	if admins, err := administratorSIDs(); err != nil || len(admins) == 0 {
		t.Errorf("administrators: %d, %v", len(admins), err)
	}
	if _, err := passwordPolicy(); err != nil {
		t.Errorf("password policy: %v", err)
	}
}

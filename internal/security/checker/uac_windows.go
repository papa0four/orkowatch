//go:build windows

// internal/security/checker/uac_windows.go

package checker

import (
	"fmt"

	"golang.org/x/sys/windows/registry"
)

const (
	// uacPolicyKey and uacPolicyValue locate the User Account control policy
	// setting. EnableLUA is a DWORD: 1 when UAC is on, 0 when it is off.
	uacPolicyKey    = `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`
	uacPolicyValue  = "EnableLUA"
	uacEnabledValue = 1
)

// uacEnabled reports whether User Account Control is enabled, reading the
// policy value directly rather than parsing a command's rendering of it. An
// error means the setting could not be read, which the caller must report
// rather than treat as disabled.
func uacEnabled() (bool, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, uacPolicyKey, registry.QUERY_VALUE)
	if err != nil {
		return false, fmt.Errorf("open %s: %w", uacPolicyKey, err)
	}
	defer key.Close() //nolint:errcheck // read-only registry handle; close error does not affect scan results

	value, _, err := key.GetIntegerValue(uacPolicyValue)
	if err != nil {
		return false, fmt.Errorf("read %s: %w", uacPolicyValue, err)
	}

	return value == uacEnabledValue, nil
}

//go:build windows

// internal/softwarelist/softwarelist_windows.go

package softwarelist

import (
	"context"
	"fmt"

	"golang.org/x/sys/windows/registry"
)

const (
	uninstallPath   = `Software\Microsoft\Windows\CurrentVersion\Uninstall`
	uninstallPath32 = `Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall`
)

// uninstallHive names one registry location that records installed software.
type uninstallHive struct {
	root registry.Key
	path string
}

// getPlatformSoftwareList reads installed software directly from the Windows
// registry. Four locations are checked for complete coverage:
//   - HKLM 64-bit uninstall path (system-wide 64-bit installs)
//   - HKLM 32-bit Wow6432Node path (system-wide 32-bit installs)
//   - HKCU 64-bit uninstall path (current user 64-bit installs)
//   - HKCU 32-bit Wow6432Node path (current user 32-bit installs)
//
// A display name map deduplicates entries that appear in multiple paths.
// There is deliberately no exec fallback: the former wmic path queried
// Win32_Product, whose enumeration triggers MSI consistency checks that can
// reconfigure installed packages -- a read that mutates target state has no
// place in an auditing tool. All four hives yielding nothing means the token
// or host is broken, and the honest behavior is the error path. ctx is
// accepted for cross-platform signature parity; the registry API offers no
// cancellation point.
func getPlatformSoftwareList(ctx context.Context) ([]SoftwareEntry, error) {
	hives := []uninstallHive{
		{registry.LOCAL_MACHINE, uninstallPath},
		{registry.LOCAL_MACHINE, uninstallPath32},
		{registry.CURRENT_USER, uninstallPath},
		{registry.CURRENT_USER, uninstallPath32},
	}

	seen := make(map[string]bool)
	var entries []SoftwareEntry

	for _, hive := range hives {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		for _, sub := range subkeyNames(hive) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			entry, ok := readUninstallEntry(hive.root, hive.path+`\`+sub)
			if !ok || seen[entry.Name] {
				continue
			}
			seen[entry.Name] = true
			entries = append(entries, entry)
		}
	}

	if len(entries) > 0 {
		return entries, nil
	}

	return nil, fmt.Errorf("no software entries readable from any registry uninstall hive; verify registry access or rerun as Administrator")
}

// subkeyNames enumerates the subkeys of a hive, or nothing when it cannot be
// opened or read. A hive that does not exist is normal on a host that never
// installed software of that class.
func subkeyNames(hive uninstallHive) []string {
	k, err := registry.OpenKey(hive.root, hive.path, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer k.Close() //nolint:errcheck // read-only registry handle; close error does not affect the inventory

	names, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil
	}
	return names
}

// readUninstallEntry reads one uninstall subkey into a SoftwareEntry. A key
// without a display name is not an installed product and reports false.
func readUninstallEntry(root registry.Key, path string) (SoftwareEntry, bool) {
	sk, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return SoftwareEntry{}, false
	}
	defer sk.Close() //nolint:errcheck // read-only registry handle; close error does not affect the inventory

	name, _, err := sk.GetStringValue("DisplayName")
	if err != nil || name == "" {
		return SoftwareEntry{}, false
	}

	version, _, _ := sk.GetStringValue("DisplayVersion") //nolint:errcheck // version is optional; missing or unreadable value is treated as empty
	return SoftwareEntry{Name: name, Version: version}, true
}

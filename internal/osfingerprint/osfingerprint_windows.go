//go:build windows

// internal/osfingerprint/osfingerprint_windows.go

package osfingerprint

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/shirou/gopsutil/host"
	"golang.org/x/sys/windows/registry"
)

// currentVersionKey states the running Windows build, release, edition, and
// installation type.
const currentVersionKey = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`

// shownValues are the values of currentVersionKey shown as they are stated.
// Windows releases before DisplayVersion was introduced do not hold it, so a
// shown value that is absent is left out rather than refused.
var shownValues = []string{"DisplayVersion", "EditionID", "InstallationType"}

// values reads named values of one registry key, as registry.Key does, so
// the reading can be tested without the host's registry.
type values interface {
	GetStringValue(name string) (string, uint32, error)
	GetIntegerValue(name string) (uint64, uint32, error)
}

// platformDetails reads the Windows build to its update revision, which is
// what Microsoft's fixed builds are ordered by, and the release, edition, and
// installation type, which gopsutil does not read.
func platformDetails(o *OSInfo, _ *host.InfoStat) error {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, currentVersionKey, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return fmt.Errorf("osfingerprint: open %s: %w", currentVersionKey, err)
	}
	defer key.Close() //nolint:errcheck // read-only registry handle; close error does not affect the fingerprint
	return readWindows(key, o)
}

// readWindows sets o's version, as 10.0.26300.10075, and the shown values
// key holds. The version and kernel version are one build string on Windows.
func readWindows(key values, o *OSInfo) error {
	major, err := integerValue(key, "CurrentMajorVersionNumber")
	if err != nil {
		return err
	}
	minor, err := integerValue(key, "CurrentMinorVersionNumber")
	if err != nil {
		return err
	}
	build, err := stringValue(key, "CurrentBuildNumber")
	if err != nil {
		return err
	}
	if _, err := strconv.ParseUint(build, 10, 32); err != nil {
		return fmt.Errorf("osfingerprint: CurrentBuildNumber %q is not a build number", build)
	}
	revision, err := integerValue(key, "UBR")
	if err != nil {
		return err
	}
	o.PlatformVersion = fmt.Sprintf("%d.%d.%s.%d", major, minor, build, revision)
	o.KernelVersion = o.PlatformVersion

	for _, name := range shownValues {
		value, err := stringValue(key, name)
		switch {
		case errors.Is(err, registry.ErrNotExist):
			continue
		case err != nil:
			return err
		}
		o.AdditionalInfo[name] = value
	}
	return nil
}

// integerValue reads the named DWORD or QWORD value of key.
func integerValue(key values, name string) (uint64, error) {
	value, _, err := key.GetIntegerValue(name)
	if err != nil {
		return 0, fmt.Errorf("osfingerprint: read %s: %w", name, err)
	}
	return value, nil
}

// stringValue reads the named string value of key, refusing one that is
// empty, since Windows states none of the values it is used for as empty.
func stringValue(key values, name string) (string, error) {
	value, _, err := key.GetStringValue(name)
	switch {
	case err != nil:
		return "", fmt.Errorf("osfingerprint: read %s: %w", name, err)
	case value == "":
		return "", fmt.Errorf("osfingerprint: %s is empty", name)
	}
	return value, nil
}

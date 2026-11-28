//go:build windows

// internal/osfingerprint/osfingerprint_windows.go

package osfingerprint

import (
	"debug/pe"
	"errors"
	"fmt"
	"runtime"
	"strconv"

	"github.com/shirou/gopsutil/host"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// currentVersionKey states the running Windows build, release, edition, and
// installation type.
const currentVersionKey = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`

// shownValues are the values of currentVersionKey shown as they are stated.
// Windows releases before DisplayVersion was introduced do not hold it, so a
// shown value that is absent is left out rather than refused.
var shownValues = []string{"DisplayVersion", "EditionID", "InstallationType"}

// nativeMachines names the machines IsWow64Process2 reports as Go names
// their architectures.
var nativeMachines = map[uint16]string{
	pe.IMAGE_FILE_MACHINE_AMD64: "amd64",
	pe.IMAGE_FILE_MACHINE_ARM64: "arm64",
	pe.IMAGE_FILE_MACHINE_I386:  "386",
	pe.IMAGE_FILE_MACHINE_ARMNT: "arm",
}

// isWow64Process2 is IsWow64Process2, which only some Windows releases have.
var isWow64Process2 = windows.NewLazySystemDLL("kernel32.dll").NewProc("IsWow64Process2")

// values reads named values of one registry key, as registry.Key does, so
// the reading can be tested without the host's registry.
type values interface {
	GetStringValue(name string) (string, uint32, error)
	GetIntegerValue(name string) (uint64, uint32, error)
}

// platformDetails reads the host's machine, the Windows version to its update
// revision, which Microsoft's fixed builds are ordered by, and the release,
// edition, and installation type, which gopsutil does not read.
func platformDetails(o *OSInfo, _ *host.InfoStat) error {
	arch, err := nativeArchitecture()
	if err != nil {
		return err
	}
	o.Architecture = arch

	key, err := registry.OpenKey(registry.LOCAL_MACHINE, currentVersionKey, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return fmt.Errorf("osfingerprint: open %s: %w", currentVersionKey, err)
	}
	defer key.Close() //nolint:errcheck // read-only registry handle; close error does not affect the fingerprint
	return readWindows(key, windows.RtlGetVersion(), o)
}

// readWindows sets o's version from version and the update revision key
// holds, as 10.0.26300.10075, and the shown values key holds. A release whose
// key holds no update revision is versioned to its build, as 6.1.7601. The
// version and kernel version are one build string on Windows.
func readWindows(key values, version *windows.OsVersionInfoEx, o *OSInfo) error {
	o.PlatformVersion = fmt.Sprintf("%d.%d.%d", version.MajorVersion, version.MinorVersion, version.BuildNumber)
	revision, err := integerValue(key, "UBR")
	switch {
	case err == nil:
		o.PlatformVersion += "." + strconv.FormatUint(revision, 10)
	case !errors.Is(err, registry.ErrNotExist):
		return err
	}
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

// nativeArchitecture is the host's machine. IsWow64Process2 names it even to
// a process the host emulates, as the amd64 owatch released for Windows is on
// an ARM64 host, where runtime.GOARCH names the build instead.
func nativeArchitecture() (string, error) {
	if isWow64Process2.Find() != nil {
		return wow64Architecture()
	}
	var process, native uint16
	if err := windows.IsWow64Process2(windows.CurrentProcess(), &process, &native); err != nil {
		return "", fmt.Errorf("osfingerprint: read the host's machine: %w", err)
	}
	return machineArchitecture(native)
}

// wow64Architecture is the host's machine on a release without
// IsWow64Process2, which predates ARM64 Windows: a process WOW64 runs there
// is a 32-bit x86 build on an x64 host, and any other runs natively.
func wow64Architecture() (string, error) {
	var wow64 bool
	if err := windows.IsWow64Process(windows.CurrentProcess(), &wow64); err != nil {
		return "", fmt.Errorf("osfingerprint: read whether WOW64 runs owatch: %w", err)
	}
	if wow64 {
		return "amd64", nil
	}
	return runtime.GOARCH, nil
}

// machineArchitecture names machine as Go names its architecture, refusing
// one owatch does not name.
func machineArchitecture(machine uint16) (string, error) {
	arch, ok := nativeMachines[machine]
	if !ok {
		return "", fmt.Errorf("osfingerprint: the host's machine %#04x is not one owatch names", machine)
	}
	return arch, nil
}

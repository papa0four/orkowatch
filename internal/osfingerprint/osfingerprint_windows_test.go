//go:build windows

// internal/osfingerprint/osfingerprint_windows_test.go

package osfingerprint

import (
	"debug/pe"
	"os"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// fakeKey holds a registry key's values as strings and integers, answering as
// registry.Key does for a value that is missing or of the other type.
type fakeKey struct {
	strings  map[string]string
	integers map[string]uint64
}

func (k fakeKey) GetStringValue(name string) (string, uint32, error) {
	if v, ok := k.strings[name]; ok {
		return v, registry.SZ, nil
	}
	if _, ok := k.integers[name]; ok {
		return "", registry.DWORD, registry.ErrUnexpectedType
	}
	return "", 0, registry.ErrNotExist
}

func (k fakeKey) GetIntegerValue(name string) (uint64, uint32, error) {
	if v, ok := k.integers[name]; ok {
		return v, registry.DWORD, nil
	}
	if _, ok := k.strings[name]; ok {
		return 0, registry.SZ, registry.ErrUnexpectedType
	}
	return 0, 0, registry.ErrNotExist
}

// windows11 is the key as this Windows 11 26H2 host holds it.
func windows11() fakeKey {
	return fakeKey{
		strings: map[string]string{
			"DisplayVersion":   "26H2",
			"EditionID":        "Core",
			"InstallationType": "Client",
		},
		integers: map[string]uint64{"UBR": 10075},
	}
}

// build26300 is the version RtlGetVersion gives this host.
func build26300() *windows.OsVersionInfoEx {
	return &windows.OsVersionInfoEx{MajorVersion: 10, MinorVersion: 0, BuildNumber: 26300}
}

// The version is the build to its update revision, and the release, edition,
// and installation type are shown as the key states them.
func TestReadWindows(t *testing.T) {
	o := &OSInfo{AdditionalInfo: map[string]string{}}
	if err := readWindows(windows11(), build26300(), o); err != nil {
		t.Fatal(err)
	}
	if o.PlatformVersion != "10.0.26300.10075" || o.KernelVersion != o.PlatformVersion {
		t.Errorf("version %q, kernel %q, want 10.0.26300.10075 for both", o.PlatformVersion, o.KernelVersion)
	}
	want := map[string]string{"DisplayVersion": "26H2", "EditionID": "Core", "InstallationType": "Client"}
	if len(o.AdditionalInfo) != len(want) {
		t.Errorf("additional info %v, want %v", o.AdditionalInfo, want)
	}
	for name, value := range want {
		if o.AdditionalInfo[name] != value {
			t.Errorf("%s = %q, want %q", name, o.AdditionalInfo[name], value)
		}
	}
}

// A key that holds no update revision gives the version to its build, and one
// that holds it as another type is refused with its name.
func TestReadWindowsRevision(t *testing.T) {
	k := windows11()
	delete(k.integers, "UBR")
	o := &OSInfo{AdditionalInfo: map[string]string{}}
	if err := readWindows(k, &windows.OsVersionInfoEx{MajorVersion: 6, MinorVersion: 3, BuildNumber: 9600}, o); err != nil {
		t.Fatal(err)
	}
	if o.PlatformVersion != "6.3.9600" || o.KernelVersion != o.PlatformVersion {
		t.Errorf("version %q, kernel %q, want 6.3.9600 for both", o.PlatformVersion, o.KernelVersion)
	}

	k.strings["UBR"] = "10075"
	if err := readWindows(k, build26300(), &OSInfo{AdditionalInfo: map[string]string{}}); err == nil || !strings.Contains(err.Error(), "UBR") {
		t.Errorf("UBR a string: err %v, want a refusal naming it", err)
	}
}

// A shown value the key does not hold is left out, as on releases from before
// DisplayVersion; one it holds as another type, or empty, is refused.
func TestReadWindowsShownValues(t *testing.T) {
	k := windows11()
	delete(k.strings, "DisplayVersion")
	o := &OSInfo{AdditionalInfo: map[string]string{}}
	if err := readWindows(k, build26300(), o); err != nil {
		t.Fatal(err)
	}
	if _, ok := o.AdditionalInfo["DisplayVersion"]; ok {
		t.Errorf("an absent DisplayVersion is shown: %v", o.AdditionalInfo)
	}

	k = windows11()
	delete(k.strings, "EditionID")
	k.integers["EditionID"] = 1
	if err := readWindows(k, build26300(), &OSInfo{AdditionalInfo: map[string]string{}}); err == nil || !strings.Contains(err.Error(), "EditionID") {
		t.Errorf("EditionID of another type: err %v, want a refusal naming it", err)
	}

	k = windows11()
	k.strings["InstallationType"] = ""
	if err := readWindows(k, build26300(), &OSInfo{AdditionalInfo: map[string]string{}}); err == nil || !strings.Contains(err.Error(), "InstallationType") {
		t.Errorf("an empty InstallationType: err %v, want a refusal naming it", err)
	}
}

// Each machine Windows reports is named as Go names its architecture, and one
// owatch does not name is refused with its number.
func TestMachineArchitecture(t *testing.T) {
	for machine, want := range map[uint16]string{
		pe.IMAGE_FILE_MACHINE_AMD64: "amd64",
		pe.IMAGE_FILE_MACHINE_ARM64: "arm64",
		pe.IMAGE_FILE_MACHINE_I386:  "386",
		pe.IMAGE_FILE_MACHINE_ARMNT: "arm",
	} {
		if got, err := machineArchitecture(machine); err != nil || got != want {
			t.Errorf("machineArchitecture(%#04x) = %q, %v, want %q", machine, got, err, want)
		}
	}
	if got, err := machineArchitecture(pe.IMAGE_FILE_MACHINE_IA64); err == nil || !strings.Contains(err.Error(), "0x0200") {
		t.Errorf("machineArchitecture(IA64) = %q, %v, want a refusal naming 0x0200", got, err)
	}
}

// hostArchitecture is the host's machine as Windows states it in the
// environment of a process, apart from owatch's own reading: an emulated
// process is told the host's in PROCESSOR_ARCHITEW6432.
func hostArchitecture(t *testing.T) string {
	t.Helper()
	machine := os.Getenv("PROCESSOR_ARCHITEW6432")
	if machine == "" {
		machine = os.Getenv("PROCESSOR_ARCHITECTURE")
	}
	arch, ok := map[string]string{"AMD64": "amd64", "ARM64": "arm64", "x86": "386"}[machine]
	if !ok {
		t.Skipf("the environment names no machine this test knows: %q", machine)
	}
	return arch
}

// Both ways of reading the host's machine give the host's, also when this
// test runs as a build the host emulates, as GOARCH=386 go test runs it.
func TestNativeArchitecture(t *testing.T) {
	want := hostArchitecture(t)
	if got, err := nativeArchitecture(); err != nil || got != want {
		t.Errorf("nativeArchitecture() = %q, %v, want %q", got, err, want)
	}
	if want != "arm64" {
		if got, err := wow64Architecture(); err != nil || got != want {
			t.Errorf("wow64Architecture() = %q, %v, want %q", got, err, want)
		}
	}
}

// fullBuild is a Windows version to its update revision.
var fullBuild = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$`)

// This host's fingerprint carries its full build, its edition, not gopsutil's
// platform family, its own machine, and no ProductName, which Platform holds.
func TestGetOSFingerprintWindows(t *testing.T) {
	o, err := GetOSFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if !fullBuild.MatchString(o.PlatformVersion) {
		t.Errorf("version %q is not a full build", o.PlatformVersion)
	}
	if edition := o.AdditionalInfo["EditionID"]; edition == "" || edition == "Standalone Workstation" {
		t.Errorf("EditionID %q is not the edition", edition)
	}
	if name, ok := o.AdditionalInfo["ProductName"]; ok {
		t.Errorf("ProductName %q is shown beside Platform %q", name, o.Platform)
	}
	if want := hostArchitecture(t); o.Architecture != want {
		t.Errorf("architecture %q, want the host's %q", o.Architecture, want)
	}
}

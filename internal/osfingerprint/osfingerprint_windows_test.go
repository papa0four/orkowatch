//go:build windows

// internal/osfingerprint/osfingerprint_windows_test.go

package osfingerprint

import (
	"regexp"
	"strings"
	"testing"

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
			"CurrentBuildNumber": "26300",
			"DisplayVersion":     "26H2",
			"EditionID":          "Core",
			"InstallationType":   "Client",
		},
		integers: map[string]uint64{
			"CurrentMajorVersionNumber": 10,
			"CurrentMinorVersionNumber": 0,
			"UBR":                       10075,
		},
	}
}

// The version is the build to its update revision, and the release, edition,
// and installation type are shown as the key states them.
func TestReadWindows(t *testing.T) {
	o := &OSInfo{AdditionalInfo: map[string]string{}}
	if err := readWindows(windows11(), o); err != nil {
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

// A build value that is missing, of the other type, or not a number is
// refused with its name, since a version without it cannot be ordered against
// a fixed build.
func TestReadWindowsRefusesBuild(t *testing.T) {
	cases := map[string]func(k fakeKey){
		"CurrentMajorVersionNumber missing": func(k fakeKey) { delete(k.integers, "CurrentMajorVersionNumber") },
		"CurrentMinorVersionNumber missing": func(k fakeKey) { delete(k.integers, "CurrentMinorVersionNumber") },
		"UBR missing":                       func(k fakeKey) { delete(k.integers, "UBR") },
		"CurrentBuildNumber missing":        func(k fakeKey) { delete(k.strings, "CurrentBuildNumber") },
		"UBR a string": func(k fakeKey) {
			delete(k.integers, "UBR")
			k.strings["UBR"] = "10075"
		},
		"CurrentBuildNumber an integer": func(k fakeKey) {
			delete(k.strings, "CurrentBuildNumber")
			k.integers["CurrentBuildNumber"] = 26300
		},
		"CurrentBuildNumber not a number": func(k fakeKey) { k.strings["CurrentBuildNumber"] = "26300a" },
		"CurrentBuildNumber empty":        func(k fakeKey) { k.strings["CurrentBuildNumber"] = "" },
	}
	for name, change := range cases {
		k := windows11()
		change(k)
		err := readWindows(k, &OSInfo{AdditionalInfo: map[string]string{}})
		value := strings.Fields(name)[0]
		if err == nil || !strings.Contains(err.Error(), value) {
			t.Errorf("%s: err %v, want a refusal naming %s", name, err, value)
		}
	}
}

// A shown value the key does not hold is left out, as on releases from before
// DisplayVersion; one it holds as another type, or empty, is refused.
func TestReadWindowsShownValues(t *testing.T) {
	k := windows11()
	delete(k.strings, "DisplayVersion")
	o := &OSInfo{AdditionalInfo: map[string]string{}}
	if err := readWindows(k, o); err != nil {
		t.Fatal(err)
	}
	if _, ok := o.AdditionalInfo["DisplayVersion"]; ok {
		t.Errorf("an absent DisplayVersion is shown: %v", o.AdditionalInfo)
	}

	k = windows11()
	delete(k.strings, "EditionID")
	k.integers["EditionID"] = 1
	if err := readWindows(k, &OSInfo{AdditionalInfo: map[string]string{}}); err == nil || !strings.Contains(err.Error(), "EditionID") {
		t.Errorf("EditionID of another type: err %v, want a refusal naming it", err)
	}

	k = windows11()
	k.strings["InstallationType"] = ""
	if err := readWindows(k, &OSInfo{AdditionalInfo: map[string]string{}}); err == nil || !strings.Contains(err.Error(), "InstallationType") {
		t.Errorf("an empty InstallationType: err %v, want a refusal naming it", err)
	}
}

// fullBuild is a Windows version to its update revision.
var fullBuild = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$`)

// This host's fingerprint carries its full build and its edition, not
// gopsutil's platform family, and no ProductName, which Platform holds.
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
}

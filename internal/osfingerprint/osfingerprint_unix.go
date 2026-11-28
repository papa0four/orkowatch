//go:build linux || darwin || freebsd || openbsd || netbsd

// internal/osfingerprint/osfingerprint_unix.go

package osfingerprint

import (
	"fmt"
	"runtime"

	"golang.org/x/sys/unix"
)

// unameMachines names the machines uname reports as Go names their
// architectures: Linux and macOS say x86_64 where the BSDs say amd64, and
// Linux says aarch64 where the others say arm64.
var unameMachines = map[string]string{
	"x86_64":  "amd64",
	"amd64":   "amd64",
	"aarch64": "arm64",
	"arm64":   "arm64",
	"i386":    "386",
	"i686":    "386",
	"armv6l":  "arm",
	"armv7l":  "arm",
}

// platformDetails reads the host's machine and adds what each system's
// identity holds beyond gopsutil's fields.
func platformDetails(o *OSInfo, family string) error {
	arch, err := nativeArchitecture()
	if err != nil {
		return err
	}
	o.Architecture = arch

	switch runtime.GOOS {
	case "darwin":
		o.AdditionalInfo["ProductName"] = "MacOS"
	case "linux":
		o.AdditionalInfo["DistroFamily"] = family
	case "freebsd":
		o.AdditionalInfo["ProductName"] = "FreeBSD"
	default:
		o.AdditionalInfo["ProductName"] = "Unknown"
	}
	return nil
}

// nativeArchitecture is the host's machine as uname reports it, which is the
// kernel's, not the build's. Under Rosetta, macOS reports an amd64 build's
// machine as x86_64, so an amd64 owatch there names amd64.
func nativeArchitecture() (string, error) {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return "", fmt.Errorf("osfingerprint: uname: %w", err)
	}
	return machineArchitecture(unix.ByteSliceToString(u.Machine[:]))
}

// machineArchitecture names machine as Go names its architecture, refusing
// one owatch does not name.
func machineArchitecture(machine string) (string, error) {
	arch, ok := unameMachines[machine]
	if !ok {
		return "", fmt.Errorf("osfingerprint: the host's machine %q is not one owatch names", machine)
	}
	return arch, nil
}

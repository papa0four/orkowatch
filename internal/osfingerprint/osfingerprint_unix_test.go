//go:build linux || darwin || freebsd || openbsd || netbsd

// internal/osfingerprint/osfingerprint_unix_test.go

package osfingerprint

import (
	"os/exec"
	"strings"
	"testing"
)

// Each machine uname reports is named as Go names its architecture, and one
// owatch does not name is refused with its name.
func TestMachineArchitecture(t *testing.T) {
	for machine, want := range map[string]string{
		"x86_64":  "amd64",
		"amd64":   "amd64",
		"aarch64": "arm64",
		"arm64":   "arm64",
		"i386":    "386",
		"i686":    "386",
		"armv6l":  "arm",
		"armv7l":  "arm",
	} {
		if got, err := machineArchitecture(machine); err != nil || got != want {
			t.Errorf("machineArchitecture(%q) = %q, %v, want %q", machine, got, err, want)
		}
	}
	if got, err := machineArchitecture("evbarm"); err == nil || !strings.Contains(err.Error(), "evbarm") {
		t.Errorf("machineArchitecture(evbarm) = %q, %v, want a refusal naming it", got, err)
	}
}

// This host's fingerprint carries the machine uname -m reports, which is the
// kernel's, also when this test runs as a build of another architecture, as
// GOARCH=386 go test runs it on an amd64 host.
func TestGetOSFingerprintArchitecture(t *testing.T) {
	out, err := exec.Command("uname", "-m").Output()
	if err != nil {
		t.Skipf("uname -m: %v", err)
	}
	want, err := machineArchitecture(strings.TrimSpace(string(out)))
	if err != nil {
		t.Skip(err)
	}
	o, err := GetOSFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if o.Architecture != want {
		t.Errorf("architecture %q, want the host's %q", o.Architecture, want)
	}
}

//go:build linux || darwin || freebsd || openbsd || netbsd

// internal/security/checker/permissions_unix_test.go

package checker

import (
	"io/fs"
	"testing"

	"github.com/papa0four/orkowatch/internal/security/finding"
)

// A path is recorded as lying in a temporary or home location only when it is
// at or beneath one, on path boundaries, so a sibling that shares a prefix is
// not taken for a child.
func TestLocationOf(t *testing.T) {
	for path, want := range map[string]string{
		"/tmp":                finding.LocationTemporary,
		"/tmp/a/b":            finding.LocationTemporary,
		"/var/tmp/x":          finding.LocationTemporary,
		"/home/alice/.bashrc": finding.LocationHome,
		"/root/.profile":      finding.LocationHome,
		"/tmpfiles/x":         "",
		"/homes/alice":        "",
		"/usr/bin/su":         "",
		"/var/tmpx":           "",
	} {
		if got := locationOf(path); got != want {
			t.Errorf("locationOf(%q) = %q, want %q", path, got, want)
		}
	}
}

// A scanned entry carries its location as a fact when it has one and carries
// no such fact otherwise, so the common entry adds nothing.
func TestScanEntryEvidenceLocation(t *testing.T) {
	names := func(e finding.Evidence) map[string]string {
		facts := map[string]string{}
		for _, f := range e.Facts {
			facts[f.Name] = f.Value
		}
		return facts
	}

	temp := names(scanEntry{path: "/tmp/dropper", mode: 0o4755}.evidence())
	if temp[string(finding.FactLocation)] != finding.LocationTemporary || temp[string(finding.FactMode)] == "" {
		t.Errorf("a setuid file in /tmp lacks its location or mode: %v", temp)
	}

	system := names(scanEntry{path: "/usr/bin/su", mode: fs.FileMode(0o4755)}.evidence())
	if _, ok := system[string(finding.FactLocation)]; ok {
		t.Errorf("an entry in neither place has a location fact: %v", system)
	}
}

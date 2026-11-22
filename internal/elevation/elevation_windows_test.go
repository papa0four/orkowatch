//go:build windows

// internal/elevation/elevation_windows_test.go

package elevation

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/papa0four/orkowatch/internal/winfolder"
)

const (
	// everyoneSID is the well-known SID of the Everyone group.
	everyoneSID = "S-1-1-0"

	// administratorsSID is the well-known SID of the Administrators group.
	administratorsSID = "S-1-5-32-544"

	// highIntegritySID and systemIntegritySID are the mandatory labels of an
	// elevated token and of the system's.
	highIntegritySID   = "S-1-16-12288"
	systemIntegritySID = "S-1-16-16384"
)

// systemProgram is the path of a program in the Windows system folder, so a
// test runs Windows' own and not one of the same name earlier on PATH.
func systemProgram(t *testing.T, name string) string {
	t.Helper()
	path, err := winfolder.System.Path(name)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

// The process is elevated exactly when whoami lists a high or system
// integrity label among its groups.
func TestElevated(t *testing.T) {
	out, err := exec.Command(systemProgram(t, "whoami.exe"), "/groups", "/fo", "csv").Output()
	if err != nil {
		t.Fatal(err)
	}
	groups := string(out)
	want := strings.Contains(groups, highIntegritySID) || strings.Contains(groups, systemIntegritySID)
	if Elevated() != want {
		t.Errorf("Elevated() = %v with these groups:\n%s", Elevated(), groups)
	}
}

// The Administrators group is in effect exactly when whoami lists it as an
// enabled group, and not when it is absent or held for deny only.
func TestAdministratorInEffect(t *testing.T) {
	out, err := exec.Command(systemProgram(t, "whoami.exe"), "/groups", "/fo", "csv").Output()
	if err != nil {
		t.Fatal(err)
	}
	var want bool
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, `"`+administratorsSID+`"`) {
			want = strings.Contains(line, "Enabled group")
		}
	}
	if AdministratorInEffect() != want {
		t.Errorf("AdministratorInEffect() = %v with these groups:\n%s", AdministratorInEffect(), out)
	}
}

// The operator is the account running the process, with the profile Windows
// records for it.
func TestInvokingOperator(t *testing.T) {
	profile, err := winfolder.Profile()
	if err != nil {
		t.Fatal(err)
	}
	if invoker, ok := InvokingOperator(); !ok || invoker.Home != profile {
		t.Errorf("the operator is %+v, %v, want the profile %s", invoker, ok, profile)
	}
}

// A directory the account made is not exposed, and granting Everyone the
// right to change it exposes it, by name.
func TestExposure(t *testing.T) {
	dir := t.TempDir()
	if reason, err := Exposure(dir); err != nil || reason != "" {
		t.Errorf("a directory the account made: %q, %v", reason, err)
	}

	if out, err := exec.Command(systemProgram(t, "icacls.exe"), dir, "/grant", "*"+everyoneSID+":(OI)(CI)M").CombinedOutput(); err != nil {
		t.Fatalf("icacls: %v: %s", err, out)
	}
	if reason, err := Exposure(dir); err != nil || reason != "writable by "+everyoneSID {
		t.Errorf("a directory Everyone may change: %q, %v", reason, err)
	}

	if _, err := Exposure(dir + "-absent"); err == nil {
		t.Error("a directory that does not exist was judged")
	}
}

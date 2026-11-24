//go:build windows

// internal/elevation/elevation_windows_test.go

package elevation

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

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

// The operator owns an open file whose owner is the account running the
// process, and not one given to the administrators, which takes an elevated
// process to do; where the test is not one, that part is skipped and says so.
func TestOperatorOwns(t *testing.T) {
	operator, ok := InvokingOperator()
	if !ok {
		t.Fatal("no operator")
	}
	owns := func(path string) bool {
		t.Helper()
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close() //nolint:errcheck // a test's own file, read for its owner only
		got, err := operator.Owns(f)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	setOwner := func(path, sid string) ([]byte, error) {
		return exec.Command(systemProgram(t, "icacls.exe"), path, "/setowner", "*"+sid).CombinedOutput()
	}

	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := setOwner(path, operator.sid.String()); err != nil {
		t.Fatalf("icacls: %v: %s", err, out)
	}
	if !owns(path) {
		t.Error("the operator does not own a file of the account's own")
	}
	if out, err := setOwner(path, administratorsSID); err != nil {
		t.Skipf("the file could not be given to the administrators, which takes an elevated process: %v: %s", err, out)
	}
	if owns(path) {
		t.Error("the operator owns a file of the administrators'")
	}
}

// A directory owned by the administrators, which the system and they alone
// may change, is not open beyond them. One the account made and owns is, as
// is one Everyone may change, and a file is not a directory. Giving a
// directory to the administrators takes an elevated process; where the test
// is not one, that part is skipped and says so.
func TestOpenBeyondAdmins(t *testing.T) {
	icacls := func(args ...string) ([]byte, error) {
		return exec.Command(systemProgram(t, "icacls.exe"), args...).CombinedOutput()
	}
	const systemSID = "S-1-5-18"

	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if reason, err := OpenBeyondAdmins(file); err != nil || reason != "not a directory" {
		t.Errorf("a file: %q, %v", reason, err)
	}
	if _, err := OpenBeyondAdmins(file + "-absent"); err == nil {
		t.Error("a directory that does not exist was judged")
	}

	dir := t.TempDir()
	if out, err := icacls(dir, "/inheritance:r", "/grant:r", "*"+systemSID+":(OI)(CI)F", "*"+administratorsSID+":(OI)(CI)F"); err != nil {
		t.Fatalf("icacls: %v: %s", err, out)
	}
	if out, err := icacls(dir, "/setowner", "*"+administratorsSID); err != nil {
		t.Skipf("the directory could not be given to the administrators, which takes an elevated process: %v: %s", err, out)
	}
	if reason, err := OpenBeyondAdmins(dir); err != nil || reason != "" {
		t.Errorf("a directory of the administrators alone: %q, %v", reason, err)
	}

	if out, err := icacls(dir, "/grant", "*"+everyoneSID+":(OI)(CI)M"); err != nil {
		t.Fatalf("icacls: %v: %s", err, out)
	}
	if reason, err := OpenBeyondAdmins(dir); err != nil || reason != "writable by "+everyoneSID {
		t.Errorf("a directory Everyone may change: %q, %v", reason, err)
	}

	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	owned := t.TempDir()
	if out, err := icacls(owned, "/inheritance:r", "/grant:r", "*"+systemSID+":(OI)(CI)F", "*"+administratorsSID+":(OI)(CI)F"); err != nil {
		t.Fatalf("icacls: %v: %s", err, out)
	}
	if out, err := icacls(owned, "/setowner", "*"+user.User.Sid.String()); err != nil {
		t.Fatalf("icacls: %v: %s", err, out)
	}
	if reason, err := OpenBeyondAdmins(owned); err != nil || !strings.HasPrefix(reason, "owned by "+user.User.Sid.String()) {
		t.Errorf("a directory the account owns: %q, %v", reason, err)
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

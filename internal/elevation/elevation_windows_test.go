//go:build windows

// internal/elevation/elevation_windows_test.go

package elevation

import (
	"os/exec"
	"testing"

	"github.com/papa0four/orkowatch/internal/winfolder"
)

// everyoneSID is the well-known SID of the Everyone group.
const everyoneSID = "S-1-1-0"

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

	if out, err := exec.Command("icacls", dir, "/grant", "*"+everyoneSID+":(OI)(CI)M").CombinedOutput(); err != nil {
		t.Fatalf("icacls: %v: %s", err, out)
	}
	if reason, err := Exposure(dir); err != nil || reason != "writable by "+everyoneSID {
		t.Errorf("a directory Everyone may change: %q, %v", reason, err)
	}

	if _, err := Exposure(dir + "-absent"); err == nil {
		t.Error("a directory that does not exist was judged")
	}
}

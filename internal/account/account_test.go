//go:build linux || darwin || freebsd || openbsd || netbsd

// internal/account/account_test.go

package account

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// A passwd line gives its account; a comment, a blank line, and a record too
// short or with a malformed identifier give none.
func TestParse(t *testing.T) {
	got, ok := Parse("alice:x:1000:1001:Alice:/home/alice:/bin/bash")
	want := Account{Name: "alice", UID: 1000, GID: 1001, Home: "/home/alice", Shell: "/bin/bash"}
	if !ok || got != want {
		t.Errorf("Parse gave %+v, %v, want %+v", got, ok, want)
	}
	for _, line := range []string{
		"",
		"# alice:x:1000:1001:Alice:/home/alice:/bin/bash",
		"alice:x:1000:1001:Alice:/home/alice",
		"alice:x:-1:1001:Alice:/home/alice:/bin/bash",
		"alice:x:1000:group:Alice:/home/alice:/bin/bash",
	} {
		if a, ok := Parse(line); ok {
			t.Errorf("Parse(%q) gave %+v, want no account", line, a)
		}
	}

	all := ParseAll([]byte("root:x:0:0:root:/root:/bin/sh\n\n# note\nbad\nalice:x:1000:1001::/home/alice:/bin/bash\n"))
	if len(all) != 2 || all[0].Name != "root" || all[1].Name != "alice" {
		t.Errorf("ParseAll gave %+v, want root and alice", all)
	}
}

// The account running the tests is found by its identifier and by its name,
// as id(1) names it, with the home the system records and not the one HOME
// gives.
func TestLookupFindsThisAccount(t *testing.T) {
	name := command(t, "id", "-un")
	uid, ok := ParseID(command(t, "id", "-u"))
	if !ok {
		t.Fatal("id -u gave no identifier")
	}
	t.Setenv("HOME", t.TempDir())

	byID, err := ByID(context.Background(), uid)
	if err != nil {
		t.Fatal(err)
	}
	byName, err := ByName(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	if byID != byName || byID.Name != name || byID.UID != uid {
		t.Errorf("by identifier %+v, by name %+v, want %s with %d", byID, byName, name, uid)
	}
	if byID.Home == os.Getenv("HOME") {
		t.Errorf("the home %s is the one HOME gives", byID.Home)
	}
	if info, err := os.Stat(byID.Home); err != nil || !info.IsDir() {
		t.Errorf("the home %s is not a directory: %v", byID.Home, err)
	}
}

// An identifier or name no account has is not found, and a name holding a
// field separator is refused without a lookup.
func TestLookupNotFound(t *testing.T) {
	const unused = 4000000000
	if _, err := ByID(context.Background(), unused); !errors.Is(err, ErrNotFound) {
		t.Errorf("an unused identifier gave %v, want ErrNotFound", err)
	}
	for _, name := range []string{"owatch-no-such-account", "root:x", "", "a\nb"} {
		if _, err := ByName(context.Background(), name); !errors.Is(err, ErrNotFound) {
			t.Errorf("ByName(%q) gave %v, want ErrNotFound", name, err)
		}
	}
}

// command runs a program the system ships and returns what it prints.
func command(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).Output() // #nosec G204 -- fixed programs and arguments in a test
	if err != nil {
		t.Fatalf("%s %v: %v", name, args, err)
	}
	return strings.TrimSpace(string(out))
}

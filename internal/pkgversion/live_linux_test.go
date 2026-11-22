//go:build linux

// internal/pkgversion/live_linux_test.go

// The comparisons set against the package manager on the machine running the
// tests, where it has one. The recorded pairs say what a manager answered
// when they were recorded; these say what it answers now, so a manager whose
// rules change shows up the next time the tests run on a host of it.

package pkgversion

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// liveStride takes every so many of a scheme's recorded pairs for the
// managers that are run once for each pair.
const liveStride = 17

// have skips the test where the program is not on the machine.
func have(t *testing.T, program string) string {
	t.Helper()
	path, err := exec.LookPath(program)
	if err != nil {
		t.Skipf("%s is not on this machine", program)
	}
	return path
}

// sample returns every liveStride-th recorded pair of a scheme.
func sample(t *testing.T, scheme string) []recorded {
	t.Helper()
	all := corpus(t, scheme)
	var some []recorded
	for i := 0; i < len(all); i += liveStride {
		some = append(some, all[i])
	}
	return some
}

// same checks one pair against what the manager said of it now: asked is
// the manager's order, and refuses whether it would not give one.
func same(t *testing.T, compare Compare, a, b string, asked int, refuses bool) {
	t.Helper()
	got, err := compare(a, b)
	switch {
	case refuses && err == nil:
		t.Errorf("%q and %q were ordered %d; the manager refuses them", a, b, got)
	case !refuses && err != nil:
		t.Errorf("%q and %q were refused (%v); the manager orders them %d", a, b, err, asked)
	case !refuses && sign(got) != asked:
		t.Errorf("%q and %q were ordered %d; the manager orders them %d", a, b, sign(got), asked)
	}
}

func TestDpkgLive(t *testing.T) {
	dpkg := have(t, "dpkg")
	holds := func(a, relation, b string) bool {
		return exec.Command(dpkg, "--compare-versions", a, relation, b).Run() == nil // #nosec G204 -- recorded test versions
	}
	for _, pair := range sample(t, "dpkg") {
		switch {
		case holds(pair.a, "lt", pair.b):
			same(t, Dpkg, pair.a, pair.b, -1, false)
		case holds(pair.a, "eq", pair.b):
			same(t, Dpkg, pair.a, pair.b, 0, false)
		case holds(pair.a, "gt", pair.b):
			same(t, Dpkg, pair.a, pair.b, 1, false)
		default:
			same(t, Dpkg, pair.a, pair.b, 0, true)
		}
	}
}

// rpm answers every recorded pair in one run of its built-in Lua. An rpm
// whose rpm.vercmp does not divide a version into epoch, version and release
// is passed over: rpm 4.14 compares the whole string as one part there, which
// is not how it orders packages.
func TestRPMLive(t *testing.T) {
	rpm := have(t, "rpm")
	probe, err := exec.Command(rpm, "--eval", `%{lua:print(rpm.vercmp("1:1.0-1", "2.0-1"))}`).Output() // #nosec G204 -- fixed arguments
	if err != nil || strings.TrimSpace(string(probe)) != "1" {
		t.Skipf("this rpm's rpm.vercmp does not read an epoch (answered %q, %v)", probe, err)
	}

	dir := t.TempDir()
	pairs := corpus(t, "rpm")
	var lines strings.Builder
	for _, pair := range pairs {
		lines.WriteString(pair.a + "\t" + pair.b + "\n")
	}
	pairsFile := filepath.Join(dir, "pairs.tsv")
	if err := os.WriteFile(pairsFile, []byte(lines.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	script := `for line in io.lines(` + strconv.Quote(pairsFile) + `) do
  local t = string.find(line, "\t", 1, true)
  print(tostring(rpm.vercmp(string.sub(line, 1, t - 1), string.sub(line, t + 1))) .. "\n")
end
`
	scriptFile := filepath.Join(dir, "ask.lua")
	if err := os.WriteFile(scriptFile, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}

	output, err := exec.Command(rpm, "--eval", `%{lua:dofile(`+strconv.Quote(scriptFile)+`)}`).Output() // #nosec G204 -- a script this test wrote
	if err != nil {
		t.Fatalf("rpm: %v", err)
	}
	answers := strings.Fields(string(output))
	if len(answers) != len(pairs) {
		t.Fatalf("rpm answered %d of %d pairs", len(answers), len(pairs))
	}
	for i, pair := range pairs {
		asked, err := strconv.Atoi(answers[i])
		if err != nil {
			t.Fatalf("rpm answered %q", answers[i])
		}
		same(t, RPM, pair.a, pair.b, asked, false)
	}
}

// apk-tools 3 reads versions by other rules than apk-tools 2, which is what
// the comparison follows, so the test runs against apk-tools 2 alone.
func TestAPKLive(t *testing.T) {
	apk := have(t, "apk")
	version, err := exec.Command(apk, "--version").Output() // #nosec G204 -- fixed arguments
	if err != nil || !strings.HasPrefix(string(version), "apk-tools 2.") {
		t.Skipf("this is not apk-tools 2 (%q, %v)", version, err)
	}

	orders := map[string]int{"<": -1, "=": 0, ">": 1}
	for _, pair := range sample(t, "apk") {
		invalid, _ := exec.Command(apk, "version", "--check", pair.a, pair.b).Output() //nolint:errcheck // #nosec G204 -- apk exits non-zero when it names an invalid version
		if len(strings.TrimSpace(string(invalid))) > 0 {
			same(t, APK, pair.a, pair.b, 0, true)
			continue
		}
		output, err := exec.Command(apk, "version", "-t", pair.a, pair.b).Output() // #nosec G204 -- recorded test versions
		asked, known := orders[strings.TrimSpace(string(output))]
		if err != nil || !known {
			t.Fatalf("apk version -t %q %q answered %q, %v", pair.a, pair.b, output, err)
		}
		same(t, APK, pair.a, pair.b, asked, false)
	}
}

func TestPacmanLive(t *testing.T) {
	vercmp := have(t, "vercmp")
	for _, pair := range sample(t, "pacman") {
		output, err := exec.Command(vercmp, pair.a, pair.b).Output() // #nosec G204 -- recorded test versions
		asked, convErr := strconv.Atoi(strings.TrimSpace(string(output)))
		if err != nil || convErr != nil {
			t.Fatalf("vercmp %q %q answered %q, %v", pair.a, pair.b, output, err)
		}
		same(t, Pacman, pair.a, pair.b, sign(asked), false)
	}
}

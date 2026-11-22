//go:build freebsd

// internal/pkgversion/live_freebsd_test.go

// Pkg set against the pkg on the machine running the tests, so a pkg whose
// rules change shows up the next time the tests run on a FreeBSD host.

package pkgversion

import (
	"os/exec"
	"strings"
	"testing"
)

// liveStride takes every so many of the recorded pairs.
const liveStride = 17

func TestPkgLive(t *testing.T) {
	pkg, err := exec.LookPath("pkg")
	if err != nil {
		t.Skip("pkg is not on this machine")
	}

	orders := map[string]int{"<": -1, "=": 0, ">": 1}
	pairs := corpus(t, "pkg")
	for i := 0; i < len(pairs); i += liveStride {
		pair := pairs[i]
		output, err := exec.Command(pkg, "version", "-t", pair.a, pair.b).Output() // #nosec G204 -- recorded test versions
		asked, known := orders[strings.TrimSpace(string(output))]
		if err != nil || !known {
			t.Fatalf("pkg version -t %q %q answered %q, %v", pair.a, pair.b, output, err)
		}
		got, err := Pkg(pair.a, pair.b)
		if err != nil || sign(got) != asked {
			t.Errorf("%q and %q were ordered %d, %v; pkg orders them %d", pair.a, pair.b, sign(got), err, asked)
		}
	}
}

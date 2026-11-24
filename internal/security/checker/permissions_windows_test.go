//go:build windows

// internal/security/checker/permissions_windows_test.go

package checker

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/papa0four/orkowatch/internal/fspath"
	"github.com/papa0four/orkowatch/internal/security/finding"
	"github.com/papa0four/orkowatch/internal/security/registry"
	"github.com/papa0four/orkowatch/internal/winfolder"
)

// scanOf runs the access control scan over root and returns its report.
func scanOf(t *testing.T, root string) finding.AuditResult {
	t.Helper()

	p := NewPermissionChecker(registry.OSContext{Platform: registry.PlatformWindows}, root, nil)
	r := newReport(p.checkIdentity)
	p.scanACLs(context.Background(), root, r)
	return r.finish()
}

// A scan root is a directory walked with what lies under it, or a file judged
// alone. Neither is unreadable to the account that made it.
func TestScanRootIsADirectoryOrAFile(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(file, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}

	for _, tt := range []struct {
		name, root, scanned string
	}{
		{"a file", file, finding.SymbolInfo + " Scanned 1 entries"},
		{"a directory holding one file", dir, finding.SymbolInfo + " Scanned 2 entries"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			result := scanOf(t, tt.root)
			if !slices.Contains(result.Details, tt.scanned) {
				t.Errorf("details %q lack %q", result.Details, tt.scanned)
			}
			for _, condition := range result.Conditions {
				if condition.Result == finding.ResultError {
					t.Errorf("%s: %s", condition.Key, condition.Reason)
				}
			}
		})
	}
}

// A scan root is resolved to the path Windows records for it, however it was
// spelled: through a junction, in another case, or with a trailing dot. A
// file resolves to itself, and a path in extended-length form is refused.
func TestScanRootIsResolved(t *testing.T) {
	base, err := fspath.Real(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(base, "Target")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(target, "file.txt")
	if err := os.WriteFile(file, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(base, "junction")
	shell, err := winfolder.System.Path("cmd.exe")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(shell, "/c", "mklink", "/J", junction, target).CombinedOutput(); err != nil { // #nosec G204 -- the system's own cmd.exe, on paths this test made
		t.Fatalf("the junction could not be made: %v: %s", err, out)
	}

	for _, tt := range []struct {
		name, root, want string
	}{
		{"a junction", junction, target},
		{"another case", strings.ToUpper(target), target},
		{"a trailing dot", target + ".", target},
		{"a file through a junction", filepath.Join(junction, "file.txt"), file},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := NewPermissionChecker(registry.OSContext{Platform: registry.PlatformWindows}, tt.root, nil)
			if got, err := p.effectiveRoot(); err != nil || got != tt.want {
				t.Errorf("effectiveRoot of %q = %q, %v, want %q", tt.root, got, err, tt.want)
			}
		})
	}

	p := NewPermissionChecker(registry.OSContext{Platform: registry.PlatformWindows}, `\\?\`+target, nil)
	if _, err := p.effectiveRoot(); !errors.Is(err, fspath.ErrDevicePath) {
		t.Errorf("a root in extended-length form gave %v, want it refused as a device path", err)
	}
}

func TestScanRootThatIsGone(t *testing.T) {
	result := scanOf(t, filepath.Join(t.TempDir(), "gone"))

	var errored int
	for _, condition := range result.Conditions {
		if condition.Result == finding.ResultError {
			errored++
		}
	}
	if errored != len(aclRules) {
		t.Errorf("%d rules report an error for a root that does not exist, want %d", errored, len(aclRules))
	}
}

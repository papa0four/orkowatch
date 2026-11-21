//go:build windows

// internal/security/checker/permissions_windows_test.go

package checker

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/papa0four/orkowatch/internal/security/finding"
	"github.com/papa0four/orkowatch/internal/security/registry"
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

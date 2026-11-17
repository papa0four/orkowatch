//go:build windows

// internal/report/report_windows_test.go

package report

import (
	"path/filepath"
	"testing"

	"github.com/papa0four/orkowatch/internal/winfolder"
)

// A report is refused inside the Windows folder, the program folders and every
// Startup location, and only there. That the locations do not follow the
// environment is winfolder's to prove, in a process started with it changed.
func TestRefusedLocations(t *testing.T) {
	bases, err := refusedBases()
	if err != nil {
		t.Fatal(err)
	}
	if len(bases) < len(refusedFolders)+2 {
		t.Fatalf("refused locations %q lack the system folders or a Startup folder", bases)
	}
	for _, base := range bases {
		if reason := refusedReason(filepath.Join(base, "report.json")); reason != base {
			t.Errorf("a report in %s was not refused: reason %q", base, reason)
		}
	}

	if reason := refusedReason(filepath.Join(t.TempDir(), "report.json")); reason != "" {
		t.Errorf("a report in a temporary directory was refused: %q", reason)
	}
	data, err := winfolder.ProgramData.Path()
	if err != nil {
		t.Fatal(err)
	}
	if reason := refusedReason(filepath.Join(data, "owatch", "report.json")); reason != "" {
		t.Errorf("ProgramData outside its Startup folder was refused: %q", reason)
	}
}

// cmd/commands/security/security_test.go

package security

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/papa0four/orkowatch/internal/selection"
)

// selected runs the audit command's own parsing and validation on args,
// through cobra, and returns the checks and the scan root they settle on in
// place of running the audit.
func selected(t *testing.T, args ...string) (selection.CheckMask, string, error) {
	t.Helper()

	c, cmd := newAuditCmd()
	var mask selection.CheckMask
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		if err := c.validateFlags(cmd); err != nil {
			return err
		}
		var err error
		mask, err = c.buildMask()
		return err
	}
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(args)

	err := cmd.Execute()
	return mask, c.scanRoot, err
}

func TestFilePermsSelection(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing")

	tests := []struct {
		name     string
		args     []string
		wantMask selection.CheckMask
		wantRoot string
		wantErr  string
	}{
		{"no flag selects every check", nil, EveryCheck, "", ""},
		{"a bare flag selects the check over the whole system", []string{"--fperms"}, selection.CheckPerms, "", ""},
		{"a flag after a bare flag is a flag", []string{"--fperms", "--plain"}, selection.CheckPerms, "", ""},
		{"a bare flag beside another check", []string{"--fperms", "--ssh"}, selection.CheckPerms | selection.CheckSSH, "", ""},
		{"a directory after the flag", []string{"--fperms", dir}, selection.CheckPerms, dir, ""},
		{"a directory after an equals sign", []string{"--fperms=" + dir}, selection.CheckPerms, dir, ""},
		{"a file after the flag", []string{"--plain", "--fperms", file}, selection.CheckPerms, file, ""},
		{"a path and then another check", []string{"--fperms", dir, "--users"}, selection.CheckPerms | selection.CheckUsers, dir, ""},

		{"a path that does not exist", []string{"--fperms", missing}, 0, "", "path is not accessible"},
		{"an empty path after the flag", []string{"--fperms", ""}, 0, "", "requires a path"},
		{"an empty path after an equals sign", []string{"--fperms="}, 0, "", "requires a path"},
		{"two paths after the flag", []string{"--fperms", dir, file}, 0, "", "one path is taken"},
		{"a path after an equals sign and another", []string{"--fperms=" + dir, file}, 0, "", "one path is taken"},
		{"a path with no flag", []string{dir}, 0, "", "unexpected argument " + strconv.Quote(dir) + " to audit; a list given to --skip-checks is one argument, its names joined by commas with no spaces; a path to scan is given after --fperms"},
		{"a path after another check's flag", []string{"--ssh", dir}, 0, "", "a path to scan is given after --fperms"},
		{"the check selected and skipped", []string{"--fperms", "--skip-checks", "permissions"}, 0, "", "all available checks were skipped"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mask, root, err := selected(t, tt.args...)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want one containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if mask != tt.wantMask || root != tt.wantRoot {
				t.Errorf("selected checks %v over %q, want %v over %q",
					selection.EnabledChecks(mask), root, selection.EnabledChecks(tt.wantMask), tt.wantRoot)
			}
		})
	}
}

// The question is asked before a scan of the whole system and before no
// other, which is what a bare --fperms now selects.
func TestConfirmFullScan(t *testing.T) {
	tests := []struct {
		name        string
		yes         bool
		mask        selection.CheckMask
		scanRoot    string
		interactive bool
		answer      string
		asked       bool
		wantErr     error
	}{
		{"the whole system, declined", false, selection.CheckPerms, "", true, "n\n", true, ErrScanDeclined},
		{"the whole system, no answer", false, selection.CheckPerms, "", true, "", true, ErrScanDeclined},
		{"the whole system, accepted", false, selection.CheckPerms, "", true, "y\n", true, nil},
		{"the whole system with --yes", true, selection.CheckPerms, "", true, "", false, nil},
		{"the whole system with no terminal", false, selection.CheckPerms, "", false, "", false, nil},
		{"a path", false, selection.CheckPerms, "/etc", true, "", false, nil},
		{"the check not selected", false, selection.CheckSSH, "", true, "", false, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			flags := &AuditFlags{yes: tt.yes}
			err := flags.ConfirmFullScan(tt.mask, tt.scanRoot, tt.interactive, strings.NewReader(tt.answer), &out)
			if !errors.Is(err, tt.wantErr) || (tt.wantErr == nil && err != nil) {
				t.Errorf("ConfirmFullScan() = %v, want %v", err, tt.wantErr)
			}
			if asked := out.Len() > 0; asked != tt.asked {
				t.Errorf("asked = %v, want %v", asked, tt.asked)
			}
		})
	}
}

// A check left out of a run says which way it was left out: named in
// --skip-checks, or not among the checks the selection flags named.
func TestUnselectedSaysWhy(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want map[string]string
	}{
		{"every check runs", nil, map[string]string{}},
		{"one check selected", []string{"--fperms"},
			map[string]string{"firewall": reasonNotSelected, "ssh": reasonNotSelected, "users": reasonNotSelected}},
		{"two checks skipped", []string{"--skip-checks", "ssh,users"},
			map[string]string{"ssh": reasonSkipped, "users": reasonSkipped}},
		{"two selected and one of them skipped", []string{"--fperms", "--ssh", "--skip-checks", "ssh"},
			map[string]string{"firewall": reasonNotSelected, "ssh": reasonSkipped, "users": reasonNotSelected}},
		{"a check both unselected and skipped", []string{"--fperms", "--skip-checks", "users"},
			map[string]string{"firewall": reasonNotSelected, "ssh": reasonNotSelected, "users": reasonSkipped}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, cmd := newAuditCmd()
			var got map[string]string
			cmd.RunE = func(cmd *cobra.Command, _ []string) error {
				if err := c.validateFlags(cmd); err != nil {
					return err
				}
				mask, err := c.buildMask()
				got = c.audit.Unselected(mask)
				return err
			}
			cmd.SilenceUsage, cmd.SilenceErrors = true, true
			cmd.SetArgs(tt.args)
			if err := cmd.Execute(); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Unselected() = %v, want %v", got, tt.want)
			}
		})
	}
}

// The audit takes no flag asking for CVE data: matching runs whenever
// datasets are held, so there is nothing to ask for.
func TestAuditHasNoEnrichFlag(t *testing.T) {
	for _, flag := range []string{"--enrich", "-e"} {
		if _, _, err := selected(t, flag); err == nil || !strings.Contains(err.Error(), "unknown") {
			t.Errorf("%s: %v, want it refused as unknown", flag, err)
		}
	}
}

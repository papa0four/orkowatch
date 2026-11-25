// cmd/commands/security/security_test.go

package security

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/papa0four/orkowatch/cmd/commands/cliargs"
	"github.com/papa0four/orkowatch/cmd/commands/held"
	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/dataset/store"
	"github.com/papa0four/orkowatch/internal/osfingerprint"
	"github.com/papa0four/orkowatch/internal/security/audit"
	"github.com/papa0four/orkowatch/internal/selection"
	"github.com/papa0four/orkowatch/internal/tui"
)

// The audit command's report states what its run installed from the
// operator's store, in its projection, its text, and the browser; the
// audit's own projection never does, so under all the run states it once.
func TestAuditReportStatesWhatWasInstalled(t *testing.T) {
	operator := &dataset.Operator{Store: "/home/a/store", Installed: []string{"kev"}}
	result := &audit.Result{}
	if result.View("").Operator != nil {
		t.Fatal("the audit's own projection states what was installed")
	}
	r := auditReport{c: &auditCmd{audit: &AuditFlags{}}, result: result, operator: operator}
	if v, ok := r.View().(audit.View); !ok || v.Operator != operator {
		t.Errorf("the report's projection states %+v", v.Operator)
	}
	var b strings.Builder
	if err := r.WriteText(&b); err != nil || !strings.Contains(b.String(), "Installed from /home/a/store: kev\n") {
		t.Errorf("the report's text is %q, %v", b.String(), err)
	}
	if !slices.ContainsFunc(r.Browse("").Tabs, func(tab tui.Tab) bool { return tab.ID == tui.TabDatasets }) {
		t.Error("the browser offers no Datasets tab")
	}
}

// The audit command hands what its run installed on opening the store to the
// report it delivers.
func TestAuditCommandReportsWhatItsRunInstalled(t *testing.T) {
	s := store.At(filepath.Join(t.TempDir(), "store"))
	data := held.New(func(context.Context, []dataset.Dataset, *osfingerprint.OSInfo, time.Time) (store.Store, store.Adoption, error) {
		return s, store.Adoption{From: "/home/a/store", Outcomes: []store.Outcome{{ID: "kev", Result: store.Installed}}}, nil
	}, nil, time.Now())
	dir := t.TempDir()

	c, cmd := newAuditCmd()
	var runErr error
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		if err := c.validateFlags(cmd); err != nil {
			return err
		}
		mask, err := c.buildMask()
		if err != nil {
			return err
		}
		runErr = c.runAuditWithTimeout(cmd, mask, data)
		return nil
	}
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs([]string{"--ssh", "-o", "json", "--report-file", dir, "--allow-elevated-write"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if runErr != nil {
		t.Skipf("the audit does not run on this host: %v", runErr)
	}

	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil || len(files) != 1 {
		t.Fatalf("the report files are %v, %v", files, err)
	}
	raw, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Operator *dataset.Operator `json:"operator"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	if report.Operator == nil || !slices.Equal(report.Operator.Installed, []string{"kev"}) {
		t.Errorf("the report states %+v, want kev installed", report.Operator)
	}
}

// selected runs the audit command's own parsing and validation on args,
// through cobra, and returns the checks and the scan root they settle on in
// place of running the audit. The arguments are read as the binary reads
// them, with a name a shell split off a list put back.
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
	cmd.SetArgs(cliargs.Rejoin(cmd, args))

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
		{"a path with no flag", []string{dir}, 0, "", "unexpected argument " + strconv.Quote(dir) + " to audit; a path to scan is given after --fperms"},
		{"a path after another check's flag", []string{"--ssh", dir}, 0, "", "a path to scan is given after --fperms"},
		{"the check selected and skipped", []string{"--fperms", "--skip-checks", "permissions"}, 0, "", "all available checks were skipped"},
		{"a list a shell split on its comma", []string{"--ssh", "--fwall", "--users", "--skip-checks", "ssh", "fwall"}, selection.CheckUsers, "", ""},
		{"a list a shell split after its comma", []string{"--ssh", "--users", "--skip-checks", "ssh,", "users", "--fwall"}, selection.CheckFirewall, "", ""},
		{"a path after a list", []string{"--fperms", "--ssh", "--skip-checks", "ssh", dir}, selection.CheckPerms, dir, ""},
		{"a check skipped that was not selected", []string{"--ssh", "--skip-checks", "ssh,users"}, 0, "",
			"--skip-checks names users, not among the checks selected by --ssh"},
		{"two checks skipped that were not selected", []string{"--fperms", "--ssh", "--skip-checks", "users", "fwall"}, 0, "",
			"--skip-checks names firewall and users, not among the checks selected by --fperms and --ssh"},
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

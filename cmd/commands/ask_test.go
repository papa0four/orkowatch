// cmd/commands/ask_test.go

package cmd

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/papa0four/orkowatch/cmd/commands/held"
	"github.com/papa0four/orkowatch/cmd/commands/security"
	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/dataset/datasettest"
	"github.com/papa0four/orkowatch/internal/dataset/store"
	"github.com/papa0four/orkowatch/internal/osfingerprint"
	"github.com/papa0four/orkowatch/internal/selection"
)

// A module that reads a dataset its store does not hold is asked about
// before it runs: at a terminal, no ends the command with ErrDeclined and
// nothing collected, and yes runs it; with no one at the terminal it runs and
// says in one line what it goes without.
func TestModuleAsksBeforeCollecting(t *testing.T) {
	missing := datasettest.Dataset{Name: "missing", Applies: true}
	for name, c := range map[string]struct {
		interactive bool
		answer      string
		collected   bool
		said        string
	}{
		"answered no":  {true, "n\n", false, "Continue without them? [y/N] "},
		"answered yes": {true, "y\n", true, "Continue without them? [y/N] "},
		"no terminal":  {false, "", true, "This run goes without missing (what missing gives): not held; its report says what was not read.\n"},
	} {
		collected := false
		module := inventory{
			name: selection.NameOS, mask: selection.ModuleOS, label: "probe",
			collect: func(_ context.Context, _ *held.Run, result *ScanResult) {
				collected = true
				result.Modules = append(result.Modules, inventoryModule(selection.NameOS))
			},
			reads: func(*osfingerprint.OSInfo) []dataset.Dataset { return []dataset.Dataset{missing} },
		}
		s := store.At(filepath.Join(t.TempDir(), "store"))
		data := func() *held.Run {
			return held.New(func(context.Context, []dataset.Dataset, *osfingerprint.OSInfo, time.Time) (store.Store, store.Adoption, error) {
				return s, store.Adoption{}, nil
			}, []dataset.Dataset{missing}, dataNow)
		}
		cmd := newModuleCmd(standaloneModule{use: "probe"}, module, "probe", data, func() bool { return c.interactive })
		var said bytes.Buffer
		cmd.SetIn(strings.NewReader(c.answer))
		cmd.SetErr(&said)
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetArgs([]string{"--plain"})
		cmd.SilenceErrors, cmd.SilenceUsage = true, true
		err := cmd.Execute()

		if declined := name == "answered no"; declined != errors.Is(err, held.ErrDeclined) || !declined && err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if collected != c.collected {
			t.Errorf("%s: collected %v, want %v", name, collected, c.collected)
		}
		if !strings.HasSuffix(said.String(), c.said) {
			t.Errorf("%s: said %q, want it to end %q", name, said.String(), c.said)
		}
	}
}

// No command that runs one module has --yes: the question about datasets not
// held is the only one such a command asks, and no flag answers it.
func TestNoModuleCommandHasYes(t *testing.T) {
	status, _, err := dataCommand(&dataCmd{}).Find([]string{"status"})
	if err != nil {
		t.Fatal(err)
	}
	for name, cmd := range map[string]*cobra.Command{
		"software":    newSoftwareCmd(),
		"osinfo":      newOsinfoCmd(),
		"listeners":   newListenersCmd(),
		"data status": status,
	} {
		if cmd.Flags().Lookup("yes") != nil || cmd.Flags().ShorthandLookup("y") != nil {
			t.Errorf("%s has --yes or -y", name)
		}
	}
}

// all reads what its modules not skipped read and the catalog the audit
// consults: on a host a dataset of records covers, that dataset, the catalog,
// and the scores; on one none covers, the catalog alone, for the audit; and
// nothing, so it asks nothing, when software and the audit are both skipped.
func TestAllReads(t *testing.T) {
	ids := func(skip []string, host *osfingerprint.OSInfo) []string {
		reads := (&allCmd{audit: &security.AuditFlags{}, skipModules: skip}).reads()
		if reads == nil {
			return nil
		}
		var got []string
		for _, d := range reads(host) {
			got = append(got, d.ID())
		}
		return got
	}
	ubuntu := &osfingerprint.OSInfo{OS: "linux", Platform: "ubuntu", PlatformVersion: "22.04"}
	windows := &osfingerprint.OSInfo{OS: "windows"}
	for name, c := range map[string]struct {
		skip []string
		host *osfingerprint.OSInfo
		want []string
	}{
		"everything on ubuntu":  {nil, ubuntu, []string{"osv-ubuntu", "kev", "epss", "kev"}},
		"everything on windows": {nil, windows, []string{"kev"}},
		"software alone":        {[]string{selection.NameAudit}, ubuntu, []string{"osv-ubuntu", "kev", "epss"}},
		"the audit alone":       {[]string{selection.NameSoftware}, ubuntu, []string{"kev"}},
		"neither":               {[]string{selection.NameSoftware, selection.NameAudit}, ubuntu, nil},
	} {
		if got := ids(c.skip, c.host); !slices.Equal(got, c.want) {
			t.Errorf("%s: reads %v, want %v", name, got, c.want)
		}
	}
}

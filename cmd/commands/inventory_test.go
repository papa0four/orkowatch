// cmd/commands/inventory_test.go

package cmd

import (
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/papa0four/orkowatch/internal/selection"
)

// Every inventory module is named and selected as the registry names and
// selects it, so a module that all runs is one --skip-modules accepts and its
// report file is coded for.
func TestInventoryModulesMatchTheRegistry(t *testing.T) {
	var names []string
	for _, module := range inventoryModules() {
		mask, err := selection.MaskFromNames([]string{module.name}, selection.CategoryModule)
		if err != nil || mask != module.mask {
			t.Errorf("%s: the registry gives it %b, %v; the module is selected by %b", module.name, mask, err, module.mask)
		}
		if module.label == "" || module.collect == nil {
			t.Errorf("%s has no label or nothing to run", module.name)
		}
		if slices.Contains(names, module.name) {
			t.Errorf("%s is listed twice", module.name)
		}
		names = append(names, module.name)
	}
	if slices.Contains(names, selection.NameAudit) {
		t.Error("the audit is listed as an inventory module")
	}
}

// A module that runs alone is one all runs, taken from the same entry, and
// its command is called by the module's name.
func TestStandaloneCommandsAreInventoryModules(t *testing.T) {
	commands := map[string]string{
		selection.NameOS:        newOsinfoCmd().Name(),
		selection.NameSoftware:  newSoftwareCmd().Name(),
		selection.NameListeners: newListenersCmd().Name(),
	}
	for _, module := range inventoryModules() {
		if got := commands[module.name]; got != module.name {
			t.Errorf("the command of the %s module is called %q", module.name, got)
		}
	}
	if len(commands) != len(inventoryModules()) {
		t.Errorf("%d commands for %d inventory modules", len(commands), len(inventoryModules()))
	}

	defer func() {
		if recover() == nil {
			t.Error("a command was built for a module that is not one")
		}
	}()
	newInventoryCmd(standaloneModule{use: "nosuchmodule"})
}

// all refuses a run that skips every module, the audit among them, and says
// so before anything runs.
func TestAllRefusesWhenEveryModuleIsSkipped(t *testing.T) {
	skipped := []string{selection.NameAudit}
	for _, module := range inventoryModules() {
		skipped = append(skipped, module.name)
	}

	cmd := newAllCmd()
	cmd.SetArgs([]string{"--skip-modules", strings.Join(skipped, ",")})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "all modules have been skipped") {
		t.Errorf("every module skipped: %v", err)
	}
}

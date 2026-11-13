// cmd/commands/all.go

package cmd

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/papa0four/orkowatch/cmd/commands/delivery"
	"github.com/papa0four/orkowatch/cmd/commands/security"
	"github.com/papa0four/orkowatch/internal/osfingerprint"
	"github.com/papa0four/orkowatch/internal/render"
	"github.com/papa0four/orkowatch/internal/scan"
	"github.com/papa0four/orkowatch/internal/security/audit"
	"github.com/papa0four/orkowatch/internal/security/types"
	"github.com/papa0four/orkowatch/internal/softwarelist"
)

type (
	// allCmd holds one invocation's flag state. Cobra binds flags directly
	// into these fields, so the values a run reads are the values that run
	// parsed.
	allCmd struct {
		verbose     bool
		skipModules []string
		timeout     time.Duration

		// audit owns the configuration flags the audit command defines; all
		// attaches them rather than retyping them.
		audit *security.AuditFlags

		// out owns the output destination flags and the emission of the
		// finished report.
		out *delivery.Flags
	}

	// ScanResult represents the combined results of all scans. It is the
	// authoritative result type for the all command and is not shared with
	// the audit subsystem.
	ScanResult struct {
		Timestamp     time.Time
		Duration      time.Duration
		Modules       []moduleRun
		OSInfo        *osfingerprint.OSInfo
		Software      []softwarelist.SoftwareEntry
		SecurityAudit *audit.Result
		Errors        []string
	}

	// moduleRun records one module's outcome in the result vocabulary the
	// audit uses, with the reason whenever the result is neither pass nor
	// fail. A skipped or errored module keeps its row rather than vanishing
	// from the run record.
	moduleRun struct {
		Name   string       `json:"name" yaml:"name"`
		Result types.Result `json:"result" yaml:"result"`
		Reason string       `json:"reason,omitempty" yaml:"reason,omitempty"`
	}

	// allResult is the typed serialization structure for all command JSON and
	// YAML output. It defines clean section boundaries between system, software,
	// and security data.
	allResult struct {
		Timestamp string                     `json:"timestamp" yaml:"timestamp"`
		Duration  string                     `json:"duration" yaml:"duration"`
		Modules   []moduleRun                `json:"modules" yaml:"modules"`
		System    *osfingerprint.SystemView  `json:"system,omitempty" yaml:"system,omitempty"`
		Software  *softwarelist.SoftwareView `json:"software,omitempty" yaml:"software,omitempty"`
		Security  *audit.View                `json:"security,omitempty" yaml:"security,omitempty"`
		Errors    []string                   `json:"errors,omitempty" yaml:"errors,omitempty"`
	}

	// allReport adapts a finished ScanResult to delivery.Report. It pairs the
	// result with the command whose flags govern its projection.
	allReport struct {
		c      *allCmd
		result *ScanResult
	}
)

// newAllCmd returns the command that combines all scanning modules
func newAllCmd() *cobra.Command {
	c := &allCmd{}

	cmd := &cobra.Command{
		Use:   "all",
		Args:  cobra.NoArgs,
		Short: "Run all available scans",
		RunE:  c.runAllScans,
		Long: `The all command performs a comprehensive system scan including:
- OS fingerprinting
- Software inventory
- Security audit
- System configuration analysis

Results can be output in various formats and saved to a file.`,
		Example: `  # Run all scans with default settings
  owatch all

  # Show module and check progress while scanning
  owatch all -v

  # Skip modules; skipped modules are still reported
  owatch all --skip-modules audit,software

  # Skip individual audit checks within the audit module
  owatch all --skip-checks firewall,permissions

  # Save report to directory in JSON format
  owatch all -o json --report-file /path/to/reports`,
	}

	cmd.Flags().BoolVarP(&c.verbose, "verbose", "v", false,
		"Enable verbose output for all scans")
	cmd.Flags().StringSliceVar(&c.skipModules, "skip-modules", []string{},
		fmt.Sprintf("Modules to skip (comma-separated: %s)",
			scan.ValidNamesFor(scan.CategoryModule)))
	cmd.Flags().DurationVar(&c.timeout, "timeout", 30*time.Minute,
		"Maximum time to run all scans")

	c.audit = security.BindAudit(cmd)
	c.out = delivery.Bind(cmd)

	return cmd
}

// buildAllMask composes a CheckMask from the active module and security check flags
func (c *allCmd) buildAllMask() (scan.CheckMask, error) {
	var mask scan.CheckMask
	if !c.isModuleSkipped("osinfo") {
		mask |= scan.ModuleOS
	}
	if !c.isModuleSkipped("software") {
		mask |= scan.ModuleSoftware
	}
	if !c.isModuleSkipped("audit") {
		allChecks := scan.CheckSSH | scan.CheckFirewall | scan.CheckUsers | scan.CheckPerms
		allChecks &^= c.audit.SkipMask()
		if allChecks == 0 {
			return 0, fmt.Errorf("all audit checks were skipped; use --skip-modules audit to skip the audit module")
		}
		mask |= allChecks
	}
	return mask, nil
}

// toAllResult converts a ScanResult into the typed serialization structure
// for all command output.
func (c *allCmd) toAllResult(scan *ScanResult) allResult {
	out := allResult{
		Timestamp: scan.Timestamp.UTC().Format(time.RFC3339),
		Duration:  scan.Duration.String(),
		Modules:   scan.Modules,
		Errors:    scan.Errors,
	}

	// system info
	if scan.OSInfo != nil {
		view := scan.OSInfo.View()
		out.System = &view
	}

	// software inventory
	if len(scan.Software) > 0 {
		view := softwarelist.View(scan.Software)
		out.Software = &view
	}

	// security audit
	if scan.SecurityAudit != nil {
		view := scan.SecurityAudit.View(c.audit.MinSeverity())
		if out.System != nil {
			// avoid duplicating hist identity alread in out.System
			view.SystemInfo = nil
		}
		out.Security = &view
	}

	return out
}

// validateSkipModules rejects any --skip-modules value that is not recognized
func (c *allCmd) validateSkipModules() error {
	if _, err := scan.MaskFromNames(c.skipModules, scan.CategoryModule); err != nil {
		return err
	}
	return nil
}

// validateAllFlags rejects invalid flag combinations for the all command.
func (c *allCmd) validateAllFlags(cmd *cobra.Command) error {
	if err := c.out.Resolve(cmd); err != nil {
		return err
	}

	if err := c.validateSkipModules(); err != nil {
		return err
	}

	return c.audit.Resolve()
}

func (c *allCmd) runAllScans(cmd *cobra.Command, args []string) error {
	startTime := time.Now()

	if err := c.validateAllFlags(cmd); err != nil {
		return err
	}

	if c.isModuleSkipped("osinfo") && c.isModuleSkipped("software") && c.isModuleSkipped("audit") {
		return fmt.Errorf("all modules have been skipped, at least one module must be run")
	}

	mask, err := c.buildAllMask()
	if err != nil {
		return err
	}

	// Verbose module headers print only when writing to an interactive
	// terminal without --report-file, preventing duplication when piping
	// or redirecting output. Computed once here as the single suppression
	// point for the whole run.
	verboseHeaders := c.verbose && render.StdoutIsTerminal() && !c.out.ToFile()

	// The whole scan runs synchronously under one deadline. Cancellation
	// reaches the audit's checkers and the software module's package-manager
	// invocations, so a timed-out scan leaves nothing running -- the prior
	// goroutine-and-select pattern reported the timeout but abandoned the
	// scan to keep executing against the host.
	ctx, cancel := context.WithTimeout(cmd.Context(), c.timeout)
	defer cancel()

	result := &ScanResult{
		Timestamp: startTime,
		Errors:    make([]string, 0),
	}

	if c.isModuleSkipped("osinfo") {
		result.Modules = append(result.Modules, skippedModule("osinfo"))
	} else if osInfo, err := runOSFingerprint(verboseHeaders); err != nil {
		result.Errors = append(result.Errors,
			fmt.Sprintf("OS fingerprint error: %v", err))
		result.Modules = append(result.Modules, erroredModule("osinfo", err))
	} else {
		result.OSInfo = osInfo
		result.Modules = append(result.Modules, inventoryModule("osinfo"))
	}

	if c.isModuleSkipped("software") {
		result.Modules = append(result.Modules, skippedModule("software"))
	} else if software, err := runSoftwareInventory(ctx, verboseHeaders); err != nil {
		result.Errors = append(result.Errors,
			fmt.Sprintf("Software inventory error: %v", err))
		result.Modules = append(result.Modules, erroredModule("software", err))
	} else {
		result.Software = software
		result.Modules = append(result.Modules, inventoryModule("software"))
	}

	if c.isModuleSkipped("audit") {
		result.Modules = append(result.Modules, skippedModule("audit"))
	} else if securityResult, err := c.runSecurityAuditModule(ctx, mask, result.OSInfo, verboseHeaders); err != nil {
		result.Errors = append(result.Errors,
			fmt.Sprintf("Security audit error: %v", err))
		result.Modules = append(result.Modules, erroredModule("audit", err))
	} else {
		result.SecurityAudit = securityResult
		result.Modules = append(result.Modules, auditModule(securityResult))
	}

	result.Duration = time.Since(startTime)
	if err := c.out.Deliver(allReport{c: c, result: result}, mask); err != nil {
		return err
	}

	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("scan timed out after %v; %s", c.timeout, incompleteDetail(result))
	}
	return nil
}

// skippedModule is the row for a module the operator excluded.
func skippedModule(name string) moduleRun {
	return moduleRun{Name: name, Result: types.ResultNotSelected, Reason: "excluded by --skip-modules"}
}

// erroredModule is the row for a module that could not complete.
func erroredModule(name string, err error) moduleRun {
	return moduleRun{Name: name, Result: types.ResultError, Reason: err.Error()}
}

// inventoryModule is the row for a module that enumerates facts about the
// host. It produces no compliance judgment, so it can neither pass nor fail.
func inventoryModule(name string) moduleRun {
	return moduleRun{Name: name, Result: types.ResultInformational, Reason: "inventory, not a compliance judgment"}
}

// auditModule is the row for the audit, whose result is the aggregate of the
// checks it ran: the audit asserts no outcome of its own.
func auditModule(result *audit.Result) moduleRun {
	aggregate := types.AuditResult{}
	for _, check := range result.Results {
		aggregate.Conditions = append(aggregate.Conditions,
			types.Condition{Result: check.Result, Reason: check.Reason})
	}
	aggregate.Conclude()
	return moduleRun{Name: "audit", Result: aggregate.Result, Reason: aggregate.Reason}
}

func runOSFingerprint(verboseHeaders bool) (*osfingerprint.OSInfo, error) {
	if verboseHeaders {
		fmt.Println("[*] OS Fingerprint Scan")
	}

	return osfingerprint.GetOSFingerprint()
}

// incompleteDetail names the modules and checks that did not finish, so a
// timed-out run tells the operator what to exclude or allow more time for.
func incompleteDetail(result *ScanResult) string {
	var parts []string

	var modules []string
	for _, m := range result.Modules {
		if m.Result == types.ResultError {
			modules = append(modules, m.Name)
		}
	}
	if hint := scan.SkipHint(scan.CategoryModule, modules); hint != "" {
		parts = append(parts, hint)
	}

	if result.SecurityAudit != nil {
		if hint := scan.SkipHint(scan.CategoryCheck, result.SecurityAudit.IncompleteChecks); hint != "" {
			parts = append(parts, hint)
		}
	}

	if len(parts) == 0 {
		return "results above are incomplete"
	}
	return "results above are incomplete; rerun with a longer --timeout or " + strings.Join(parts, " ")
}

// runSoftwareInventory enumerates installed software packages. verboseHeaders
// gates only the progress announcement; the inventory itself always renders
// in renderAllText, matching structured output.
func runSoftwareInventory(ctx context.Context, verboseHeaders bool) ([]softwarelist.SoftwareEntry, error) {
	if verboseHeaders {
		fmt.Println("[*] Software Inventory Scan")
	}

	return softwarelist.GetInstalledSoftwareList(ctx)
}

func (c *allCmd) runSecurityAuditModule(ctx context.Context, mask scan.CheckMask, hostInfo *osfingerprint.OSInfo, verboseHeaders bool) (*audit.Result, error) {
	if verboseHeaders {
		fmt.Println("[*] Security Audit Scan")
	}

	opts := audit.Options{
		Verbose:     verboseHeaders,
		MinSeverity: c.audit.MinSeverity(),
		Enrich:      c.audit.Enrich(),
		Checks:      scan.EnabledChecks(mask),
		HostInfo:    hostInfo,
	}

	auditor := audit.NewSecurityAuditor(opts)
	return auditor.RunAudit(ctx)
}

// View returns the typed serialization structure for the all command.
func (r allReport) View() any {
	return r.c.toAllResult(r.result)
}

// WriteText renders the human-readable summary of the scan.
func (r allReport) WriteText(w io.Writer) error {
	return r.c.renderAllText(w, r.result)
}

// renderAllText writes a concise human-readable summary of the scan result
// to w, returning the first write error. This is the non-TUI text path; it
// will be replaced by the Bubbletea progress display when #35 lands.
func (c *allCmd) renderAllText(w io.Writer, result *ScanResult) error {
	ew := render.NewErrWriter(w)
	ew.Printf("owatch all  --  %s\n\n", result.Timestamp.UTC().Format(time.RFC3339))

	// module accounting
	if len(result.Modules) > 0 {
		ew.Printf("Modules:\n")
		for _, m := range result.Modules {
			ew.Printf("  %-10s %s\n", m.Name, strings.ToUpper(string(m.Result)))
		}
		ew.Printf("\n")
	}

	// system
	if result.OSInfo != nil {
		ew.Printf("System\n")
		if err := ew.Err(); err != nil {
			return err
		}
		if err := osfingerprint.WriteText(w, result.OSInfo); err != nil {
			return err
		}
	}

	// software
	if len(result.Software) > 0 {
		ew.Printf("Software: %d packages installed\n", len(result.Software))
		if err := ew.Err(); err != nil {
			return err
		}
		if err := softwarelist.WriteText(w, softwarelist.View(result.Software)); err != nil {
			return err
		}
	}

	ew.Printf("\n")

	// security findings
	if result.SecurityAudit != nil {
		ew.Printf("Security Audit\n")
		if err := ew.Err(); err != nil {
			return err
		}
		if err := audit.WriteText(w, result.SecurityAudit, c.audit.MinSeverity()); err != nil {
			return err
		}
	}
	return ew.Err()
}

func (c *allCmd) isModuleSkipped(module string) bool {
	if len(c.skipModules) == 0 {
		return false
	}

	for _, skip := range c.skipModules {
		if strings.EqualFold(skip, module) {
			return true
		}
	}
	return false
}

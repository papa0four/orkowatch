// cmd/commands/all.go

package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/papa0four/orkowatch/cmd/commands/delivery"
	"github.com/papa0four/orkowatch/cmd/commands/security"
	"github.com/papa0four/orkowatch/internal/osfingerprint"
	"github.com/papa0four/orkowatch/internal/render"
	"github.com/papa0four/orkowatch/internal/security/audit"
	"github.com/papa0four/orkowatch/internal/security/finding"
	"github.com/papa0four/orkowatch/internal/selection"
	"github.com/papa0four/orkowatch/internal/sockets"
	"github.com/papa0four/orkowatch/internal/softwarelist"
	"github.com/papa0four/orkowatch/internal/tui"
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
		Sockets       *sockets.View
		SecurityAudit *audit.Result
		Errors        []string
	}

	// moduleRun records one module's outcome in the result vocabulary the
	// audit uses, with the reason whenever the result is neither pass nor
	// fail. A skipped or errored module keeps its row rather than vanishing
	// from the run record.
	moduleRun struct {
		Name   string         `json:"name" yaml:"name"`
		Result finding.Result `json:"result" yaml:"result"`
		Reason string         `json:"reason,omitempty" yaml:"reason,omitempty"`
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
		Sockets   *sockets.View              `json:"sockets,omitempty" yaml:"sockets,omitempty"`
		Security  *audit.View                `json:"security,omitempty" yaml:"security,omitempty"`
		Errors    []string                   `json:"errors,omitempty" yaml:"errors,omitempty"`
	}

	// allReport adapts a finished ScanResult to delivery.Report. The all,
	// osinfo and software commands share it: they differ in the title the
	// browser shows and in the severity floor that governs the audit's
	// projection, which only all has.
	allReport struct {
		title       string
		minSeverity string
		result      *ScanResult
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
- The host's sockets and the processes holding them
- Security audit
- System configuration analysis

Results can be output in various formats and saved to a file.`,
		Example: `  # Run all scans with default settings
  owatch all

  # Add the live findings feed to the progress display
  owatch all -v

  # Scan the whole filesystem without being asked first
  owatch all --yes

  # Skip modules; skipped modules are still reported
  owatch all --skip-modules audit,software

  # Skip individual audit checks within the audit module
  owatch all --skip-checks firewall,permissions

  # Print the report as text instead of opening the results browser
  owatch all --plain

  # Save report to directory in JSON format
  owatch all -o json --report-file /path/to/reports`,
	}

	cmd.Flags().BoolVarP(&c.verbose, "verbose", "v", false,
		"Enable verbose output for all scans")
	cmd.Flags().StringSliceVar(&c.skipModules, "skip-modules", []string{},
		fmt.Sprintf("Modules to skip (comma-separated: %s)",
			selection.ValidNamesFor(selection.CategoryModule)))
	cmd.Flags().DurationVar(&c.timeout, "timeout", 30*time.Minute,
		"Maximum time to run all scans")

	c.audit = security.BindAudit(cmd)
	c.out = delivery.Bind(cmd)

	return cmd
}

// buildAllMask composes a CheckMask from the active module and security check flags
func (c *allCmd) buildAllMask() (selection.CheckMask, error) {
	var mask selection.CheckMask
	if !c.isModuleSkipped("osinfo") {
		mask |= selection.ModuleOS
	}
	if !c.isModuleSkipped("software") {
		mask |= selection.ModuleSoftware
	}
	if !c.isModuleSkipped("listeners") {
		mask |= selection.ModuleListeners
	}
	if !c.isModuleSkipped("audit") {
		allChecks := selection.CheckSSH | selection.CheckFirewall | selection.CheckUsers | selection.CheckPerms
		allChecks &^= c.audit.SkipMask()
		if allChecks == 0 {
			return 0, fmt.Errorf("all audit checks were skipped; use --skip-modules audit to skip the audit module")
		}
		mask |= allChecks
	}
	return mask, nil
}

// toAllResult converts a ScanResult into the typed serialization structure
// for all command output, with the audit filtered to minSeverity.
func toAllResult(result *ScanResult, minSeverity string) allResult {
	out := allResult{
		Timestamp: result.Timestamp.UTC().Format(time.RFC3339),
		Duration:  result.Duration.String(),
		Modules:   result.Modules,
		Errors:    result.Errors,
	}

	// system info
	if result.OSInfo != nil {
		view := result.OSInfo.View()
		out.System = &view
	}

	// software inventory
	if len(result.Software) > 0 {
		view := softwarelist.View(result.Software)
		out.Software = &view
	}

	// sockets
	out.Sockets = result.Sockets

	// security audit
	if result.SecurityAudit != nil {
		view := result.SecurityAudit.View(minSeverity)
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
	if _, err := selection.MaskFromNames(c.skipModules, selection.CategoryModule); err != nil {
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

	if c.isModuleSkipped("osinfo") && c.isModuleSkipped("software") && c.isModuleSkipped("listeners") && c.isModuleSkipped("audit") {
		return fmt.Errorf("all modules have been skipped, at least one module must be run")
	}

	mask, err := c.buildAllMask()
	if err != nil {
		return err
	}

	interactive := render.StdoutIsTerminal()
	switch err := c.audit.ConfirmFullScan(c.auditMask(mask), "", interactive && render.StdinIsTerminal(), os.Stdin, os.Stderr); {
	case errors.Is(err, security.ErrScanDeclined):
		fmt.Fprintln(os.Stderr, "Scan cancelled.")
		return nil
	case err != nil:
		return err
	}

	// The whole scan runs under one deadline. Cancellation reaches the
	// audit's checkers and the software module's package-manager
	// invocations, so a timed-out or interrupted scan leaves nothing running.
	ctx, cancel := context.WithTimeout(cmd.Context(), c.timeout)
	defer cancel()

	result := &ScanResult{
		Timestamp: startTime,
		Errors:    make([]string, 0),
	}

	runErr := tui.Run(ctx, tui.Options{
		Title:       "owatch all",
		Tasks:       c.tasks(mask),
		Interactive: interactive,
		Verbose:     c.verbose,
	}, func(ctx context.Context, reporter tui.Reporter) error {
		c.runModules(ctx, mask, result, reporter)
		return nil
	})
	interrupted := errors.Is(runErr, tui.ErrInterrupted)
	if runErr != nil && !interrupted {
		return runErr
	}

	result.Duration = time.Since(startTime)
	if err := c.out.Deliver(allReport{title: "owatch all", minSeverity: c.audit.MinSeverity(), result: result}, mask); err != nil {
		return err
	}

	switch {
	case interrupted:
		return fmt.Errorf("scan interrupted; %s", incompleteDetail(result))
	case ctx.Err() == context.DeadlineExceeded:
		return fmt.Errorf("scan timed out after %v; %s", c.timeout, incompleteDetail(result))
	default:
		return nil
	}
}

// Display task identifiers for the inventory modules. The audit's checks
// use their own names.
const (
	taskOSInfo    = "osinfo"
	taskSoftware  = "software"
	taskListeners = "listeners"
)

// auditMask returns the checks the audit module will run, which is none of
// them when the module itself is skipped.
func (c *allCmd) auditMask(mask selection.CheckMask) selection.CheckMask {
	if c.isModuleSkipped("audit") {
		return 0
	}
	return mask
}

// tasks lists what the progress display shows a row for: the inventory
// modules, then every audit check.
func (c *allCmd) tasks(mask selection.CheckMask) []tui.Task {
	tasks := []tui.Task{
		{ID: taskOSInfo, Label: "OS fingerprint", Skipped: c.isModuleSkipped("osinfo")},
		{ID: taskSoftware, Label: "software inventory", Skipped: c.isModuleSkipped("software")},
		{ID: taskListeners, Label: "sockets", Skipped: c.isModuleSkipped("listeners")},
	}
	return append(tasks, security.CheckTasks(c.auditMask(mask))...)
}

// runModules runs each module that was not skipped, recording its outcome in
// result and reporting it to the display as it happens.
func (c *allCmd) runModules(ctx context.Context, mask selection.CheckMask, result *ScanResult, reporter tui.Reporter) {
	if c.isModuleSkipped("osinfo") {
		result.Modules = append(result.Modules, skippedModule("osinfo"))
	} else {
		reporter.Start(taskOSInfo)
		collectOSInfo(result)
		reporter.Finish(taskOSInfo, moduleOutcome(result.Modules))
	}

	if c.isModuleSkipped("software") {
		result.Modules = append(result.Modules, skippedModule("software"))
	} else {
		reporter.Start(taskSoftware)
		collectSoftware(ctx, result)
		reporter.Finish(taskSoftware, moduleOutcome(result.Modules))
	}

	if c.isModuleSkipped("listeners") {
		result.Modules = append(result.Modules, skippedModule("listeners"))
	} else {
		reporter.Start(taskListeners)
		collectListeners(ctx, result)
		reporter.Finish(taskListeners, moduleOutcome(result.Modules))
	}

	if c.isModuleSkipped("audit") {
		result.Modules = append(result.Modules, skippedModule("audit"))
		return
	}
	securityResult, err := c.runSecurityAuditModule(ctx, mask, result.OSInfo, result.Sockets, reporter)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Security audit error: %v", err))
		result.Modules = append(result.Modules, erroredModule("audit", err))
		return
	}
	result.SecurityAudit = securityResult
	result.Modules = append(result.Modules, auditModule(securityResult))
}

// collectOSInfo runs the OS fingerprint module and records how it ended in
// result, whether the module returned or failed.
func collectOSInfo(result *ScanResult) {
	osInfo, err := osfingerprint.GetOSFingerprint()
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("OS fingerprint error: %v", err))
		result.Modules = append(result.Modules, erroredModule("osinfo", err))
		return
	}
	result.OSInfo = osInfo
	result.Modules = append(result.Modules, inventoryModule("osinfo"))
}

// collectSoftware runs the software inventory module and records how it ended
// in result, as collectOSInfo does.
func collectSoftware(ctx context.Context, result *ScanResult) {
	software, err := softwarelist.GetInstalledSoftwareList(ctx)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Software inventory error: %v", err))
		result.Modules = append(result.Modules, erroredModule("software", err))
		return
	}
	result.Software = software
	result.Modules = append(result.Modules, inventoryModule("software"))
}

// collectListeners runs the sockets module and records how it ended in
// result, as collectOSInfo does. A platform whose sockets are not read is not
// an error: the module does not apply there, and its row says so.
func collectListeners(ctx context.Context, result *ScanResult) {
	view, err := sockets.Read(ctx)
	switch {
	case errors.Is(err, sockets.ErrUnsupported):
		result.Modules = append(result.Modules, moduleRun{Name: "listeners", Result: finding.ResultNotApplicable, Reason: err.Error()})
	case err != nil:
		result.Errors = append(result.Errors, fmt.Sprintf("Sockets error: %v", err))
		result.Modules = append(result.Modules, erroredModule("listeners", err))
	default:
		result.Sockets = &view
		result.Modules = append(result.Modules, inventoryModule("listeners"))
	}
}

// moduleOutcome is the display outcome of the module most recently recorded.
func moduleOutcome(modules []moduleRun) tui.Outcome {
	last := modules[len(modules)-1]
	return tui.Outcome{Result: last.Result, Reason: last.Reason}
}

// skippedModule is the row for a module the operator excluded.
func skippedModule(name string) moduleRun {
	return moduleRun{Name: name, Result: finding.ResultNotSelected, Reason: "excluded by --skip-modules"}
}

// erroredModule is the row for a module that could not complete.
func erroredModule(name string, err error) moduleRun {
	return moduleRun{Name: name, Result: finding.ResultError, Reason: err.Error()}
}

// inventoryModule is the row for a module that enumerates facts about the
// host. It produces no compliance judgment, so it can neither pass nor fail.
func inventoryModule(name string) moduleRun {
	return moduleRun{Name: name, Result: finding.ResultInformational, Reason: "inventory, not a compliance judgment"}
}

// auditModule is the row for the audit, whose result is the aggregate of the
// checks it ran: the audit asserts no outcome of its own.
func auditModule(result *audit.Result) moduleRun {
	aggregate := finding.AuditResult{}
	for _, check := range result.Results {
		aggregate.Conditions = append(aggregate.Conditions,
			finding.Condition{Result: check.Result, Reason: check.Reason})
	}
	aggregate.Conclude()
	return moduleRun{Name: "audit", Result: aggregate.Result, Reason: aggregate.Reason}
}

// incompleteDetail names the modules and checks that did not finish, so a
// timed-out run tells the operator what to exclude or allow more time for.
func incompleteDetail(result *ScanResult) string {
	var parts []string

	var modules []string
	for _, m := range result.Modules {
		if m.Result == finding.ResultError {
			modules = append(modules, m.Name)
		}
	}
	if hint := selection.SkipHint(selection.CategoryModule, modules); hint != "" {
		parts = append(parts, hint)
	}

	if result.SecurityAudit != nil {
		if hint := selection.SkipHint(selection.CategoryCheck, result.SecurityAudit.IncompleteChecks); hint != "" {
			parts = append(parts, hint)
		}
	}

	if len(parts) == 0 {
		return "results shown are incomplete"
	}
	return "results shown are incomplete; rerun with a longer --timeout or " + strings.Join(parts, " ")
}

// runSecurityAuditModule runs the audit with what the modules before it read,
// so the host is fingerprinted and its sockets read once for the whole run.
func (c *allCmd) runSecurityAuditModule(ctx context.Context, mask selection.CheckMask, hostInfo *osfingerprint.OSInfo, hostSockets *sockets.View, reporter tui.Reporter) (*audit.Result, error) {
	auditor := audit.NewSecurityAuditor(audit.Options{
		Observer:    security.Observe(reporter),
		MinSeverity: c.audit.MinSeverity(),
		Enrich:      c.audit.Enrich(),
		Checks:      selection.EnabledChecks(mask),
		HostInfo:    hostInfo,
		Sockets:     hostSockets,
	})
	return auditor.RunAudit(ctx)
}

// View returns the typed serialization structure for the all command.
func (r allReport) View() any {
	return toAllResult(r.result, r.minSeverity)
}

// Browse returns what the results browser shows for the scan, from the same
// projection View returns, so a saved report opens to the same tabs.
func (r allReport) Browse(text string) tui.Report {
	return security.BrowserReport(allSource(r.title, toAllResult(r.result, r.minSeverity), text))
}

// allSource is what the browser shows for an all report: the projection a
// saved report carries and its full-report text. A live run and a saved
// report both build their source here, so the two cannot differ in what they
// take from the projection.
func allSource(title string, v allResult, text string) security.BrowserSource {
	return security.BrowserSource{
		Title:    title,
		Audit:    v.Security,
		System:   v.System,
		Software: v.Software,
		Sockets:  v.Sockets,
		Modules:  moduleNotes(v.Modules),
		Text:     text,
	}
}

// moduleNotes converts how each module ended to what the browser explains an
// empty tab with.
func moduleNotes(modules []moduleRun) []security.ModuleNote {
	notes := make([]security.ModuleNote, 0, len(modules))
	for _, m := range modules {
		notes = append(notes, security.ModuleNote{Name: m.Name, Result: m.Result, Reason: m.Reason})
	}
	return notes
}

// WriteText renders the human-readable summary of the scan from the same
// projection View returns.
func (r allReport) WriteText(w io.Writer) error {
	return writeAllText(w, toAllResult(r.result, r.minSeverity))
}

// writeAllText writes a concise human-readable summary of an all report to w,
// returning the first write error. It renders from the projection a saved
// report carries, so what plain output prints, what the results browser pages
// through as the full report, and what owatch browse shows for a saved file
// are one text.
func writeAllText(w io.Writer, v allResult) error {
	if len(v.Modules) == 1 {
		return writeSingleModuleText(w, v)
	}
	ew := render.NewErrWriter(w)
	ew.Printf("owatch all  --  %s\n\n", v.Timestamp)

	// module accounting
	if len(v.Modules) > 0 {
		ew.Printf("Modules:\n")
		for _, m := range v.Modules {
			ew.Printf("  %-10s %s\n", m.Name, strings.ToUpper(string(m.Result)))
		}
		ew.Printf("\n")
	}

	// Each module that ran writes its own section under a heading; the
	// inventory modules come first and the audit after a blank line.
	inventory := []textSection{
		{v.System != nil, func() string { return "System" },
			func(w io.Writer) error { return osfingerprint.WriteViewText(w, *v.System) }},
		{v.Software != nil, func() string { return fmt.Sprintf("Software: %d packages installed", v.Software.Count) },
			func(w io.Writer) error { return softwarelist.WriteText(w, *v.Software) }},
		{v.Sockets != nil, func() string { return "\nSockets" },
			func(w io.Writer) error { return sockets.WriteText(w, *v.Sockets) }},
	}
	if err := writeSections(ew, w, inventory); err != nil {
		return err
	}
	ew.Printf("\n")
	if err := writeSections(ew, w, []textSection{
		{v.Security != nil, func() string { return "Security Audit" },
			func(w io.Writer) error { return audit.WriteViewText(w, *v.Security) }},
	}); err != nil {
		return err
	}
	return ew.Err()
}

// textSection is one module's part of the all report: whether the module
// produced anything, its heading, and the module's own renderer. The heading
// and renderer are called only when the section is present, since they read
// the module's projection.
type textSection struct {
	present bool
	heading func() string
	write   func(io.Writer) error
}

// writeSections writes each present section's heading and then its body,
// stopping at the first write error.
func writeSections(ew *render.ErrWriter, w io.Writer, sections []textSection) error {
	for _, s := range sections {
		if !s.present {
			continue
		}
		ew.Printf("%s\n", s.heading())
		if err := ew.Err(); err != nil {
			return err
		}
		if err := s.write(w); err != nil {
			return err
		}
	}
	return nil
}

// writeSingleModuleText writes the report of a command that ran one inventory
// module, osinfo or software, as that module's own text with no all-report
// heading around it. The projection holds one module row only for such a
// command, so a saved report is rendered as the run that wrote it was.
func writeSingleModuleText(w io.Writer, v allResult) error {
	switch v.Modules[0].Name {
	case "osinfo":
		if v.System != nil {
			return osfingerprint.WriteViewText(w, *v.System)
		}
	case "software":
		view := softwarelist.SoftwareView{}
		if v.Software != nil {
			view = *v.Software
		}
		return softwarelist.WriteText(w, view)
	case "listeners":
		if v.Sockets != nil {
			return sockets.WriteText(w, *v.Sockets)
		}
	}
	return nil
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

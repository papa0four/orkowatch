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

	"github.com/papa0four/orkowatch/cmd/commands/cliargs"
	"github.com/papa0four/orkowatch/cmd/commands/delivery"
	"github.com/papa0four/orkowatch/cmd/commands/held"
	"github.com/papa0four/orkowatch/cmd/commands/security"
	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/osfingerprint"
	"github.com/papa0four/orkowatch/internal/render"
	"github.com/papa0four/orkowatch/internal/security/audit"
	"github.com/papa0four/orkowatch/internal/security/finding"
	"github.com/papa0four/orkowatch/internal/selection"
	"github.com/papa0four/orkowatch/internal/sockets"
	"github.com/papa0four/orkowatch/internal/softwarelist"
	"github.com/papa0four/orkowatch/internal/tui"
	"github.com/papa0four/orkowatch/internal/vulnmatch"
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
		Timestamp time.Time
		Duration  time.Duration
		Modules   []moduleRun

		// Operator is what the run, elevated, did with the operator's
		// datasets when it opened its store: a fact of the run, not of any
		// one module.
		Operator *dataset.Operator

		OSInfo        *osfingerprint.OSInfo
		Software      []softwarelist.SoftwareEntry
		Vulns         *vulnmatch.View
		Sockets       *sockets.View
		Datasets      *dataset.View
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
		Operator  *dataset.Operator          `json:"operator,omitempty" yaml:"operator,omitempty"`
		System    *osfingerprint.SystemView  `json:"system,omitempty" yaml:"system,omitempty"`
		Software  *softwarelist.SoftwareView `json:"software,omitempty" yaml:"software,omitempty"`
		Vulns     *vulnmatch.View            `json:"vulnerabilities,omitempty" yaml:"vulnerabilities,omitempty"`
		Sockets   *sockets.View              `json:"sockets,omitempty" yaml:"sockets,omitempty"`
		Datasets  *dataset.View              `json:"datasets,omitempty" yaml:"datasets,omitempty"`
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
		Args:  cliargs.None,
		Short: "Run all available scans",
		RunE:  c.runAllScans,
		Long: `The all command performs a comprehensive system scan including:
- OS fingerprinting
- Software inventory
- The host's sockets and the processes holding them
- Security audit
- System configuration analysis

Results can be output in various formats and saved to a file.

` + held.AskHelp + `

` + held.ElevatedHelp,
		Example: `  # Run all scans with default settings
  owatch all

  # Add the live findings feed to the progress display
  owatch all -v

  # Run without being asked first, about a scan of the whole filesystem or
  # about datasets not held
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
	cliargs.NameList(cmd, &c.skipModules, "skip-modules",
		fmt.Sprintf("Modules to skip (comma-separated: %s)", selection.ValidNamesFor(selection.CategoryModule)),
		selection.AcceptedNames(selection.CategoryModule))
	cmd.Flags().DurationVar(&c.timeout, "timeout", 30*time.Minute,
		"Maximum time to run all scans")

	c.audit = security.BindAudit(cmd)
	c.out = delivery.Bind(cmd)

	return cmd
}

// buildAllMask composes a CheckMask from the active module and security check flags
func (c *allCmd) buildAllMask() (selection.CheckMask, error) {
	var mask selection.CheckMask
	for _, module := range inventoryModules() {
		if !c.isModuleSkipped(module.name) {
			mask |= module.mask
		}
	}
	if !c.isModuleSkipped(selection.NameAudit) {
		checks := security.EveryCheck &^ c.audit.SkipMask()
		if checks == 0 {
			return 0, errors.New("all audit checks were skipped; use --skip-modules audit to skip the audit module")
		}
		mask |= checks
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
		Operator:  result.Operator,
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

	// what the software was matched against, the sockets, and the datasets
	out.Vulns = result.Vulns
	out.Sockets = result.Sockets
	out.Datasets = result.Datasets

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

	// The audit module's own bit is never set into a mask, so a mask with
	// no bit is a run with every module skipped.
	mask, err := c.buildAllMask()
	if err != nil {
		return err
	}
	if mask == 0 {
		return errors.New("all modules have been skipped, at least one module must be run")
	}

	interactive := render.StdoutIsTerminal()
	switch err := c.audit.ConfirmFullScan(c.auditMask(mask), "", interactive && render.StdinIsTerminal(), os.Stdin, os.Stderr); {
	case errors.Is(err, security.ErrScanDeclined):
		fmt.Fprintln(os.Stderr, "Scan canceled.")
		return nil
	case err != nil:
		return err
	}
	data := held.ForHost()
	if err := data.Ask(cmd.Context(), c.reads(), c.audit.Yes(), interactive && render.StdinIsTerminal(), os.Stdin, os.Stderr); err != nil {
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

	ending, err := tui.Run(ctx, tui.Options{
		Title:       "owatch all",
		Tasks:       c.tasks(mask),
		Interactive: interactive,
		Verbose:     c.verbose,
	}, func(ctx context.Context, reporter tui.Reporter) error {
		c.runModules(ctx, data, mask, result, reporter)
		return nil
	})
	if err != nil {
		return err
	}

	// How the scan ended was settled when it returned. Delivering can keep
	// the results browser open for as long as the operator reads, and that
	// time is not the scan's.
	result.Duration = time.Since(startTime)
	if err := c.out.Deliver(allReport{title: "owatch all", minSeverity: c.audit.MinSeverity(), result: result}, mask); err != nil {
		return err
	}

	switch ending {
	case tui.Interrupted:
		return fmt.Errorf("scan interrupted; %s", incompleteDetail(result))
	case tui.TimedOut:
		return fmt.Errorf("scan timed out after %v; %s", c.timeout, incompleteDetail(result))
	default:
		return nil
	}
}

// inventory is a module that enumerates facts about the host: its name, as
// --skip-modules, the progress display and its row in the report spell it,
// the bit that selects it, its label in the progress display, the function
// that runs it, reading any dataset through the run's data, and records how
// it ended, and the datasets it reads, nil for a module that reads none.
type inventory struct {
	name    string
	mask    selection.CheckMask
	label   string
	collect func(ctx context.Context, data *held.Run, result *ScanResult)
	reads   held.Reads
}

// inventoryModules lists the inventory modules in the order all runs them,
// ahead of the audit, which reads what they collected. all selects, skips,
// shows and runs a module from its entry here, and the command that runs one
// alone takes it from here too, so a module is added in this one place.
func inventoryModules() []inventory {
	return []inventory{
		{selection.NameOS, selection.ModuleOS, "OS fingerprint", collectOSInfo, nil},
		{selection.NameSoftware, selection.ModuleSoftware, "software inventory", collectSoftware, hostMatching().reads},
		{selection.NameListeners, selection.ModuleListeners, "sockets", collectListeners, nil},
	}
}

// auditMask returns the checks the audit module will run, which is none of
// them when the module itself is skipped.
func (c *allCmd) auditMask(mask selection.CheckMask) selection.CheckMask {
	if c.isModuleSkipped(selection.NameAudit) {
		return 0
	}
	return mask
}

// reads is what the run reads: what each module not skipped reads, and the
// catalog the audit consults unless it is skipped. It is nil when no part of
// the run reads a dataset, so such a run is asked nothing.
func (c *allCmd) reads() held.Reads {
	var parts []held.Reads
	for _, module := range inventoryModules() {
		if module.reads != nil && !c.isModuleSkipped(module.name) {
			parts = append(parts, module.reads)
		}
	}
	if !c.isModuleSkipped(selection.NameAudit) {
		parts = append(parts, security.AuditReads)
	}
	if len(parts) == 0 {
		return nil
	}
	return func(host *osfingerprint.OSInfo) []dataset.Dataset {
		var all []dataset.Dataset
		for _, part := range parts {
			all = append(all, part(host)...)
		}
		return all
	}
}

// tasks lists what the progress display shows a row for: the inventory
// modules, each under its name, then every audit check.
func (c *allCmd) tasks(mask selection.CheckMask) []tui.Task {
	var tasks []tui.Task
	for _, module := range inventoryModules() {
		tasks = append(tasks, tui.Task{ID: module.name, Label: module.label, Skipped: c.isModuleSkipped(module.name)})
	}
	return append(tasks, security.CheckTasks(c.auditMask(mask))...)
}

// runModules runs each module that was not skipped, recording its outcome in
// result and reporting it to the display as it happens. The modules read
// datasets through data, so the run opens the store once, and result then
// holds what opening it did with the operator's datasets, however the
// modules ended.
func (c *allCmd) runModules(ctx context.Context, data *held.Run, mask selection.CheckMask, result *ScanResult, reporter tui.Reporter) {
	defer func() { result.Operator = data.Operator() }()
	for _, module := range inventoryModules() {
		if c.isModuleSkipped(module.name) {
			result.Modules = append(result.Modules, skippedModule(module.name))
			continue
		}
		reporter.Start(module.name)
		module.collect(ctx, data, result)
		reporter.Finish(module.name, moduleOutcome(result.Modules))
	}

	if c.isModuleSkipped(selection.NameAudit) {
		result.Modules = append(result.Modules, skippedModule(selection.NameAudit))
		return
	}
	securityResult, err := c.runSecurityAuditModule(ctx, data, mask, result.OSInfo, result.Sockets, reporter)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Security audit error: %v", err))
		result.Modules = append(result.Modules, erroredModule(selection.NameAudit, err))
		return
	}
	result.SecurityAudit = securityResult
	result.Modules = append(result.Modules, auditModule(securityResult))
}

// collectOSInfo runs the OS fingerprint module and records how it ended in
// result, whether the module returned or failed. The fingerprint is read
// without a context, so the one every module is given goes unused, as does
// the run's data.
func collectOSInfo(_ context.Context, _ *held.Run, result *ScanResult) {
	osInfo, err := osfingerprint.GetOSFingerprint()
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("OS fingerprint error: %v", err))
		result.Modules = append(result.Modules, erroredModule(selection.NameOS, err))
		return
	}
	result.OSInfo = osInfo
	result.Modules = append(result.Modules, inventoryModule(selection.NameOS))
}

// collectSoftware runs the software inventory module and records how it ended
// in result, as collectOSInfo does. The inventory is then matched against the
// vulnerability dataset of the host's distribution as data reads it, with the
// fingerprint the run read or, when it read none, one read here.
func collectSoftware(ctx context.Context, data *held.Run, result *ScanResult) {
	software, err := softwarelist.GetInstalledSoftwareList(ctx)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Software inventory error: %v", err))
		result.Modules = append(result.Modules, erroredModule(selection.NameSoftware, err))
		return
	}
	result.Software = software
	result.Vulns = hostMatching().run(ctx, data, result.OSInfo, software)
	result.Modules = append(result.Modules, softwareModule(result.Vulns))
}

// collectListeners runs the sockets module and records how it ended in
// result, as collectOSInfo does. A platform whose sockets are not read is not
// an error: the module does not apply there, and its row says so. It reads
// no dataset.
func collectListeners(ctx context.Context, _ *held.Run, result *ScanResult) {
	view, err := sockets.Read(ctx)
	switch {
	case errors.Is(err, sockets.ErrUnsupported):
		result.Modules = append(result.Modules, moduleRun{Name: selection.NameListeners, Result: finding.ResultNotApplicable, Reason: err.Error()})
	case err != nil:
		result.Errors = append(result.Errors, fmt.Sprintf("Sockets error: %v", err))
		result.Modules = append(result.Modules, erroredModule(selection.NameListeners, err))
	default:
		result.Sockets = &view
		result.Modules = append(result.Modules, inventoryModule(selection.NameListeners))
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

// softwareModule is the row for the software module: an inventory, so it
// neither passes nor fails, and the match made of it as the match states
// itself, so a run whose match was not made says why.
func softwareModule(v *vulnmatch.View) moduleRun {
	return moduleRun{Name: selection.NameSoftware, Result: finding.ResultInformational, Reason: "inventory, " + v.Summary()}
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
	return moduleRun{Name: selection.NameAudit, Result: aggregate.Result, Reason: aggregate.Reason}
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
// so the host is fingerprinted, its sockets read, and the dataset store opened
// once for the whole run.
func (c *allCmd) runSecurityAuditModule(ctx context.Context, data *held.Run, mask selection.CheckMask, hostInfo *osfingerprint.OSInfo, hostSockets *sockets.View, reporter tui.Reporter) (*audit.Result, error) {
	auditor := audit.NewSecurityAuditor(audit.Options{
		Observer:       security.Observe(reporter),
		MinSeverity:    c.audit.MinSeverity(),
		Checks:         selection.EnabledChecks(mask),
		Unselected:     c.audit.Unselected(mask),
		HostInfo:       hostInfo,
		Sockets:        hostSockets,
		KnownExploited: security.ExploitedClasses(data),
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
		Vulns:    v.Vulns,
		Datasets: v.Datasets,
		Operator: v.Operator,
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
	if err := ew.Err(); err != nil {
		return err
	}
	if err := dataset.WriteOperatorText(w, v.Operator); err != nil {
		return err
	}

	// Each module that ran writes its own section under a heading; the
	// inventory modules come first and the audit after a blank line.
	inventory := []textSection{
		{v.System != nil, func() string { return "System" },
			func(w io.Writer) error { return osfingerprint.WriteViewText(w, *v.System) }},
		{v.Software != nil, func() string { return fmt.Sprintf("Software: %d packages installed", v.Software.Count) },
			func(w io.Writer) error { return softwarelist.WriteText(w, *v.Software) }},
		{v.Vulns != nil, func() string { return "\nVulnerabilities" },
			func(w io.Writer) error { return vulnmatch.WriteText(w, *v.Vulns) }},
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
// module, such as osinfo or owatch data status, as that module's own text with no all-report
// heading around it, after what the run installed from the operator's store.
// The projection holds one module row only for such a command, so a saved
// report is rendered as the run that wrote it was.
func writeSingleModuleText(w io.Writer, v allResult) error {
	if err := dataset.WriteOperatorText(w, v.Operator); err != nil {
		return err
	}
	switch v.Modules[0].Name {
	case selection.NameOS:
		if v.System != nil {
			return osfingerprint.WriteViewText(w, *v.System)
		}
	case selection.NameSoftware:
		view := softwarelist.SoftwareView{}
		if v.Software != nil {
			view = *v.Software
		}
		if err := softwarelist.WriteText(w, view); err != nil || v.Vulns == nil {
			return err
		}
		if _, err := io.WriteString(w, "\nVulnerabilities\n"); err != nil {
			return err
		}
		return vulnmatch.WriteText(w, *v.Vulns)
	case selection.NameListeners:
		if v.Sockets != nil {
			return sockets.WriteText(w, *v.Sockets)
		}
	case selection.NameDatasets:
		if v.Datasets != nil {
			return dataset.WriteText(w, *v.Datasets)
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

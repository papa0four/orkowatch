// cmd/commands/security/security.go

// Package security implements the owatch audit command, which runs the
// configuration security checks and renders their results as text, JSON, or
// YAML, optionally writing them to a generated report file.
package security

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/papa0four/orkowatch/cmd/commands/delivery"
	"github.com/papa0four/orkowatch/internal/osfingerprint"
	"github.com/papa0four/orkowatch/internal/render"
	"github.com/papa0four/orkowatch/internal/security/audit"
	"github.com/papa0four/orkowatch/internal/security/finding"
	"github.com/papa0four/orkowatch/internal/selection"
	"github.com/papa0four/orkowatch/internal/tui"
)

type (
	// AuditFlags holds the audit configuration one invocation parsed. The audit
	// command binds to it, and all attaches the same surface rather than retyping
	// it, so the two cannot drift.
	AuditFlags struct {
		skipChecks  []string
		minSeverity string
		enrich      bool
		yes         bool

		// skipMask is the resolved exclusion set, computed once in Resolve
		// from skipChecks.
		skipMask selection.CheckMask
	}

	// auditCmd holds one invocation's flag state. Cobra binds flags directly into
	// these fields, so the values a run needs are the values that run parsed.
	auditCmd struct {
		// Command flags
		verbose bool
		timeout time.Duration

		// Individual check flags
		checkSSH      bool
		checkFirewall bool
		checkUsers    bool

		// checkFilePerms is set by --fperms, given with a path or without.
		// scanRoot is the path it named, and empty for the whole system.
		checkFilePerms bool
		scanRoot       string

		// audit owns the configuration flags shared with the all command.
		audit *AuditFlags

		// out owns the output destination flags and the emission of the
		// finished report.
		out *delivery.Flags
	}

	// auditReport adapts a finished audit result to delivery.Report. It pairs the
	// result with the command whose min-severity governs its projection.
	auditReport struct {
		c      *auditCmd
		result *audit.Result
	}
)

// BindAudit registers the audit configuration flags on cmd and returns the
// state they write into. Resolve must run before any accessor.
func BindAudit(cmd *cobra.Command) *AuditFlags {
	a := &AuditFlags{}

	cmd.Flags().StringSliceVar(&a.skipChecks, "skip-checks", []string{},
		fmt.Sprintf("Audit checks to skip (comma-separated: %s)",
			selection.ValidNamesFor(selection.CategoryCheck)))
	cmd.Flags().StringVar(&a.minSeverity, "min-severity", finding.SeverityNone,
		fmt.Sprintf("Minimum severity level to report, judged on the severity on this host (%s)", finding.SeverityNames()))
	cmd.Flags().BoolVarP(&a.enrich, "enrich", "e", false,
		"Query external sources to annotate findings with CVEs mapped to referenced CWEs")
	cmd.Flags().BoolVarP(&a.yes, "yes", "y", false,
		"Do not ask before a permissions check that scans the entire filesystem")
	return a
}

// Resolve validates the parsed values, resolves the skip set, and normalizes
// severity to its canonical form so every downstream consumer sees one shape.
// Skip-check names are validated before severity, which is the order both
// commands already report in.
func (a *AuditFlags) Resolve() error {
	if a == nil {
		return errors.New("audit flags were not bound to the command")
	}

	skipMask, err := selection.MaskFromNames(a.skipChecks, selection.CategoryCheck)
	if err != nil {
		return err
	}
	a.skipMask = skipMask

	normalized, ok := finding.NormalizeSeverity(a.minSeverity)
	if !ok {
		return fmt.Errorf("invalid min-severity: %s (valid: %s)", a.minSeverity, finding.SeverityNames())
	}
	a.minSeverity = normalized

	return nil
}

// MinSeverity returns the canonical severity floor Resolve settled on.
func (a *AuditFlags) MinSeverity() string {
	return a.minSeverity
}

// Enrich reports whether findings are annotated from external sources.
func (a *AuditFlags) Enrich() bool {
	return a.enrich
}

// SkipMask returns the checks excluded by --skip-checks. Callers clear these
// bits from the set they would otherwise run.
func (a *AuditFlags) SkipMask() selection.CheckMask {
	return a.skipMask
}

// Unselected returns why each check outside mask is not run: named in
// --skip-checks, or left out by the flags that selected the others.
func (a *AuditFlags) Unselected(mask selection.CheckMask) map[string]string {
	reasons := make(map[string]string)
	for _, name := range selection.EnabledChecks(EveryCheck &^ mask) {
		reasons[name] = reasonNotSelected
	}
	for _, name := range selection.EnabledChecks(a.skipMask &^ mask) {
		reasons[name] = reasonSkipped
	}
	return reasons
}

// SkipChecks returns the raw --skip-checks values, for operator-facing output
// that echoes what was passed rather than what it resolved to.
func (a *AuditFlags) SkipChecks() []string {
	return a.skipChecks
}

// bareFlag is the value pflag passes a flag that was given none.
const bareFlag = "true"

// EveryCheck is the set of audit checks, which a run that selects none runs.
const EveryCheck = selection.CheckSSH | selection.CheckFirewall | selection.CheckUsers | selection.CheckPerms

// Why a check is not run, as the report gives it.
const (
	reasonSkipped     = "excluded by --skip-checks"
	reasonNotSelected = "not among the checks this run selected"
)

// NewCmd returns the security audit command.
func NewCmd() *cobra.Command {
	_, cmd := newAuditCmd()
	return cmd
}

// newAuditCmd returns the audit command with the state its flags write into.
func newAuditCmd() (*auditCmd, *cobra.Command) {
	c := &auditCmd{}

	cmd := &cobra.Command{
		Use:     "audit",
		Args:    c.validateArgs,
		Aliases: []string{"security_audit"},
		Short:   "Perform a security audit of the system",
		RunE:    c.runE,
		Long: `Perform a comprehensive security audit of the system.
This command checks various security aspects including:
- SSH configuration
- Firewall rules
- User accounts
- File permissions

You can run all checks or specify individual checks to run.`,
		Example: `  # Run all security checks
  owatch audit

  # Show progress while checks run
  owatch audit -v

  # Run specific checks
  owatch audit --ssh
  owatch audit --fwall
  owatch audit --users

  # Run the permissions check alone: over the whole system, over a
  # directory and everything beneath it, or on one file
  owatch audit --fperms
  owatch audit --fperms /path/to/directory
  owatch audit --fperms /path/to/file

  # Skip checks; skipped checks are still reported, as notselected
  owatch audit --skip-checks ssh,firewall

  # Report findings whose severity on this host is HIGH or above
  owatch audit --min-severity HIGH

  # Scan the whole filesystem without being asked first
  owatch audit --yes

  # Print the report as text instead of opening the results browser
  owatch audit --plain

  # Run checks and save report to file
  owatch audit -o json --report-file /path/to/reports`,
	}

	cmd.Flags().BoolVarP(&c.verbose, "verbose", "v", false,
		"Enable verbose output")
	cmd.Flags().DurationVar(&c.timeout, "timeout", 10*time.Minute,
		"Maximum time to run the audit")
	cmd.Flags().BoolVar(&c.checkSSH, "ssh", false,
		"Run SSH configuration check")
	cmd.Flags().BoolVar(&c.checkFirewall, "fwall", false,
		"Run firewall configuration check")
	cmd.Flags().BoolVar(&c.checkUsers, "users", false,
		"Run user accounts check")
	cmd.Flags().BoolFunc("fperms",
		"Run file permissions check over the whole system, or over the directory or file that follows",
		c.selectFilePerms)

	c.audit = BindAudit(cmd)
	c.out = delivery.Bind(cmd)

	return c, cmd
}

// selectFilePerms receives --fperms. An optional value cannot also be taken
// from the next argument, so a bare flag selects the check and leaves its
// path, if one follows, to validateArgs; --fperms=path names it here.
func (c *auditCmd) selectFilePerms(value string) error {
	c.checkFilePerms = true
	switch value {
	case bareFlag:
	case "":
		return errors.New("requires a path after =")
	default:
		c.scanRoot = value
	}
	return nil
}

// validateArgs admits the one argument the command takes, the path that
// follows a bare --fperms, and keeps it as the scan root.
func (c *auditCmd) validateArgs(cmd *cobra.Command, args []string) error {
	switch {
	case len(args) == 0:
		return nil
	case !c.checkFilePerms:
		return cobra.NoArgs(cmd, args)
	case c.scanRoot != "":
		return fmt.Errorf("--fperms: one path is taken, and %q follows %q", args[0], c.scanRoot)
	case len(args) > 1:
		return fmt.Errorf("--fperms: one path is taken, and %q follows %q", args[1], args[0])
	case args[0] == "":
		return errors.New("--fperms: requires a path")
	}
	c.scanRoot = args[0]
	return nil
}

// buildMask composes a CheckMask from the active flag values
func (c *auditCmd) buildMask() (selection.CheckMask, error) {
	mask := EveryCheck

	if c.checkSSH || c.checkFirewall || c.checkUsers || c.checkFilePerms {
		mask = 0
		if c.checkSSH {
			mask |= selection.CheckSSH
		}
		if c.checkFirewall {
			mask |= selection.CheckFirewall
		}
		if c.checkUsers {
			mask |= selection.CheckUsers
		}
		if c.checkFilePerms {
			mask |= selection.CheckPerms
		}
	}

	mask &^= c.audit.SkipMask()

	if mask == 0 {
		return 0, errors.New("all available checks were skipped; at least one must run")
	}

	return mask, nil
}

func (c *auditCmd) validateFlags(cmd *cobra.Command) error {
	if err := c.out.Resolve(cmd); err != nil {
		return err
	}

	if err := c.audit.Resolve(); err != nil {
		return err
	}

	return c.validateScanRoot()
}

// runE is the audit command's entry point. Nothing in it differs by platform:
// the checkers behind RunAudit carry the build constraints.
func (c *auditCmd) runE(cmd *cobra.Command, _ []string) error {
	if err := c.validateFlags(cmd); err != nil {
		return err
	}

	mask, err := c.buildMask()
	if err != nil {
		return err
	}

	interactive := render.StdoutIsTerminal() && render.StdinIsTerminal()
	switch err := c.audit.ConfirmFullScan(mask, c.scanRoot, interactive, os.Stdin, os.Stderr); {
	case errors.Is(err, ErrScanDeclined):
		fmt.Fprintln(os.Stderr, "Scan cancelled.")
		return nil
	case err != nil:
		return err
	}

	if c.verbose && !c.out.ToFile() {
		fmt.Printf("[*] Running security audit for OS: %s\n", runtime.GOOS)
	}
	c.logVerboseConfig(mask)

	return c.runAuditWithTimeout(cmd, mask)
}

// validateScanRoot rejects a scan root that cannot be read, before any check
// starts. No scan root is the whole system, which the checker resolves.
func (c *auditCmd) validateScanRoot() error {
	if c.scanRoot == "" {
		return nil
	}
	if _, err := os.Stat(c.scanRoot); err != nil {
		return fmt.Errorf("--fperms: path is not accessible: %w", err)
	}
	return nil
}

func (c *auditCmd) logVerboseConfig(mask selection.CheckMask) {
	if !c.verbose || c.out.ToFile() {
		return
	}
	checks := selection.EnabledChecks(mask)
	if len(checks) > 0 {
		fmt.Printf("[*] Running checks: %s\n", strings.Join(checks, ", "))
	} else {
		fmt.Println("[*] Running comprehensive security audit")
	}
	fmt.Printf("[*] Output format: %s\n", c.out.Format())
	if skipped := c.audit.SkipChecks(); len(skipped) > 0 {
		fmt.Printf("[*] Skipped checks: %s\n", strings.Join(skipped, ", "))
	}
	fmt.Printf("[*] Minimum severity: %s\n", c.audit.minSeverity)
	fmt.Printf("[*] Timeout: %s\n", c.timeout)
	fmt.Println()
}

// runAuditWithTimeout executes the audit under a deadline, showing its
// progress while it runs. Cancellation propagates through RunAudit into
// checker exec and filesystem work, so on timeout or interrupt nothing owatch
// started is left running. Whatever finished is reported before the error
// that says the run was cut short, and whether it was is settled when the
// audit returns: the time the results browser then stays open is not the
// audit's.
func (c *auditCmd) runAuditWithTimeout(cmd *cobra.Command, mask selection.CheckMask) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), c.timeout)
	defer cancel()

	var result *audit.Result
	ending, runErr := tui.Run(ctx, c.progressOptions(mask), func(ctx context.Context, reporter tui.Reporter) error {
		auditor := audit.NewSecurityAuditor(audit.Options{
			Observer:      Observe(reporter),
			FilePermsPath: c.scanRoot,
			MinSeverity:   c.audit.MinSeverity(),
			Checks:        selection.EnabledChecks(mask),
			Unselected:    c.audit.Unselected(mask),
			Enrich:        c.audit.Enrich(),
		})
		var err error
		result, err = auditor.RunAudit(ctx)
		return err
	})
	if runErr != nil {
		return fmt.Errorf("audit failed: %w", runErr)
	}

	if c.verbose && result != nil && result.FingerprintError != nil {
		fmt.Fprintf(os.Stderr, "[!] OS fingerprint unavailable: %v\n", result.FingerprintError)
	}

	if err := c.outputResults(result, mask); err != nil {
		return err
	}

	var cause string
	switch ending {
	case tui.Interrupted:
		cause = "audit interrupted"
	case tui.TimedOut:
		cause = fmt.Sprintf("audit timeout after %v", c.timeout)
	default:
		return nil
	}
	if hint := selection.SkipHint(selection.CategoryCheck, result.IncompleteChecks); hint != "" {
		return fmt.Errorf("%s; results shown are incomplete; rerun with a longer --timeout or %s", cause, hint)
	}
	return fmt.Errorf("%s; results shown are incomplete", cause)
}

// progressOptions describes this run to the progress display. The live
// display is used when standard output is a terminal. Otherwise verbose runs
// keep the plain progress lines they have always printed, and those are
// withheld when the report is going to a file so they cannot interleave with
// the one line that confirms where it was saved.
func (c *auditCmd) progressOptions(mask selection.CheckMask) tui.Options {
	opts := tui.Options{
		Title:       "owatch audit",
		Tasks:       CheckTasks(mask),
		Interactive: render.StdoutIsTerminal(),
		Verbose:     c.verbose,
	}
	if c.verbose && !c.out.ToFile() {
		opts.Lines = os.Stdout
	}
	return opts
}

func (c *auditCmd) outputResults(result *audit.Result, mask selection.CheckMask) error {
	if result == nil || len(result.Results) == 0 {
		return errors.New("audit produced no results")
	}

	return c.out.Deliver(auditReport{c: c, result: result}, mask)
}

// View returns the severity-filtered audit projection.
func (r auditReport) View() any {
	return r.result.View(r.c.audit.MinSeverity())
}

// Browse returns what the results browser shows for the audit, from the same
// severity-filtered projection View returns.
func (r auditReport) Browse(text string) tui.Report {
	return BrowserReport(AuditSource("owatch audit", r.result.View(r.c.audit.MinSeverity()), text))
}

// WriteText renders the audit as human-readable text from the same
// severity-filtered projection View returns.
func (r auditReport) WriteText(w io.Writer) error {
	return WriteAuditText(w, r.result.View(r.c.audit.MinSeverity()))
}

// WriteAuditText renders an audit report as human-readable text: the system
// block via osfingerprint.WriteViewText, then the security section via
// audit.WriteViewText. It renders from the projection a saved report carries,
// so a live run, and a report reopened by owatch browse, show the same text.
func WriteAuditText(w io.Writer, v audit.View) error {
	ew := render.NewErrWriter(w)
	ew.Printf("\nSecurity Audit Report\n")
	ew.Printf("====================\n\n")
	if err := ew.Err(); err != nil {
		return err
	}

	if v.SystemInfo != nil {
		if err := osfingerprint.WriteViewText(w, *v.SystemInfo); err != nil {
			return err
		}
		ew.Printf("\n")
		if err := ew.Err(); err != nil {
			return err
		}
	}

	return audit.WriteViewText(w, v)
}

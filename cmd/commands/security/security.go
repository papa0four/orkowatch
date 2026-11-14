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
)

type (
	// AuditFlags holds the audit configuration one invocation parsed. The audit
	// command binds to it, and all attaches the same surface rather than retyping
	// it, so the two cannot drift.
	AuditFlags struct {
		skipChecks  []string
		minSeverity string
		enrich      bool

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
		checkSSH       bool
		checkFirewall  bool
		checkUsers     bool
		checkFilePerms string

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
		fmt.Sprintf("Minimum severity level to report (%s)", finding.SeverityNames()))
	cmd.Flags().BoolVarP(&a.enrich, "enrich", "e", false,
		"Query external sources to annotate findings with CVEs mapped to referenced CWEs")
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

// SkipChecks returns the raw --skip-checks values, for operator-facing output
// that echoes what was passed rather than what it resolved to.
func (a *AuditFlags) SkipChecks() []string {
	return a.skipChecks
}

// NewCmd returns the security audit command.
func NewCmd() *cobra.Command {
	c := &auditCmd{}

	cmd := &cobra.Command{
		Use:     "audit",
		Args:    cobra.NoArgs,
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
  owatch audit --fperms /path/to/file

  # Skip checks; skipped checks are still reported, as notselected
  owatch audit --skip-checks ssh,firewall

  # Set minimum severity level
  owatch audit --min-severity HIGH

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
	cmd.Flags().StringVar(&c.checkFilePerms, "fperms", "",
		"Check permissions of specified file path")

	c.audit = BindAudit(cmd)
	c.out = delivery.Bind(cmd)

	return cmd
}

// buildMask composes a CheckMask from the active flag values
func (c *auditCmd) buildMask() (selection.CheckMask, error) {
	mask := selection.CheckSSH | selection.CheckFirewall | selection.CheckUsers | selection.CheckPerms

	if c.checkSSH || c.checkFirewall || c.checkUsers || c.checkFilePerms != "" {
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
		if c.checkFilePerms != "" {
			mask |= selection.CheckPerms
		}
	}

	mask &^= c.audit.SkipMask()

	if mask == 0 {
		return 0, fmt.Errorf("all available checks were skipped; at least one must run")
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

	return c.validateFilePermsPath(cmd)
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

	if c.verbose && !c.out.ToFile() {
		fmt.Printf("[*] Running security audit for OS: %s\n", runtime.GOOS)
	}
	c.logVerboseConfig(mask)

	return c.runAuditWithTimeout(cmd, mask)
}

// validateFilePermsPath enforces existing path and file rejecting explicit empty value
func (c *auditCmd) validateFilePermsPath(cmd *cobra.Command) error {
	if !cmd.Flags().Changed("fperms") {
		return nil
	}
	if c.checkFilePerms == "" {
		return fmt.Errorf("--fperms: requires a path")
	}
	if _, err := os.Stat(c.checkFilePerms); err != nil {
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

// runAuditWithTimeout executes the audit synchronously under a deadline.
// Cancellation propagates through RunAudit into checker exec and filesystem
// work, so on timeout nothing owatch started is left running -- the prior
// goroutine-and-select pattern reported the timeout but abandoned the scan
// to keep executing against the host.
func (c *auditCmd) runAuditWithTimeout(cmd *cobra.Command, mask selection.CheckMask) error {
	opts := audit.Options{
		Verbose:       c.verbose && !c.out.ToFile(),
		FilePermsPath: c.checkFilePerms,
		MinSeverity:   c.audit.MinSeverity(),
		Checks:        selection.EnabledChecks(mask),
		Enrich:        c.audit.Enrich(),
	}

	auditor := audit.NewSecurityAuditor(opts)

	ctx, cancel := context.WithTimeout(cmd.Context(), c.timeout)
	defer cancel()

	result, err := auditor.RunAudit(ctx)
	if err != nil {
		return fmt.Errorf("audit failed: %w", err)
	}

	if err := c.outputResults(result, mask); err != nil {
		return err
	}

	if ctx.Err() == context.DeadlineExceeded {
		if hint := selection.SkipHint(selection.CategoryCheck, result.IncompleteChecks); hint != "" {
			return fmt.Errorf("audit timeout after %v; results above are incomplete; rerun with a longer --timeout or %s",
				c.timeout, hint)
		}
		return fmt.Errorf("audit timeout after %v; results above are incomplete", c.timeout)
	}
	return nil
}

func (c *auditCmd) outputResults(result *audit.Result, mask selection.CheckMask) error {
	if result == nil || len(result.Results) == 0 {
		return fmt.Errorf("audit produced no results")
	}

	return c.out.Deliver(auditReport{c: c, result: result}, mask)
}

// View returns the severity-filtered audit projection.
func (r auditReport) View() any {
	return r.result.View(r.c.audit.MinSeverity())
}

// WriteText renders the audit as human-readable text: the system block via
// osfingerprint.WriteText, then the security section via audit.WriteText.
func (r auditReport) WriteText(w io.Writer) error {
	ew := render.NewErrWriter(w)
	ew.Printf("\nSecurity Audit Report\n")
	ew.Printf("====================\n\n")
	if err := ew.Err(); err != nil {
		return err
	}

	if r.result.HostInfo != nil {
		if err := osfingerprint.WriteText(w, r.result.HostInfo); err != nil {
			return err
		}
		ew.Printf("\n")
		if err := ew.Err(); err != nil {
			return err
		}
	}

	return audit.WriteText(w, r.result, r.c.audit.MinSeverity())
}

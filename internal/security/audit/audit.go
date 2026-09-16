// internal/security/audit/audit.go

// Package audit orchestrates the security checks: it selects the enabled set,
// runs them concurrently under a caller-supplied deadline, aggregates their
// findings and CWE references, and optionally enriches those references. It
// owns the serializable projection of a completed run and its text rendering.
package audit

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/papa0four/orkowatch/internal/osfingerprint"
	"github.com/papa0four/orkowatch/internal/security/checker"
	"github.com/papa0four/orkowatch/internal/security/enrichment"
	"github.com/papa0four/orkowatch/internal/security/registry"
	"github.com/papa0four/orkowatch/internal/security/types"
)

type (
	// SecurityAuditor handles the orchestration of security checks
	SecurityAuditor struct {
		sshChecker        checker.SSHChecker
		firewallChecker   checker.FirewallChecker
		userChecker       checker.UserChecker
		permissionChecker checker.PermissionChecker
		verbose           bool
		options           Options
		osContext         registry.OSContext
	}

	// Options configures the audit process. The run's deadline is not part of
	// Options: it arrives as the context passed to RunAudit, owned by the
	// command layer, and bounds checks and enrichment together as one budget.
	Options struct {
		Verbose       bool
		Checks        []string
		FilePermsPath string
		MinSeverity   string
		Enrich        bool
		HostInfo      *osfingerprint.OSInfo
	}

	// Result represents the complete audit results. IncompleteChecks names,
	// in canonical order, the checks interrupted before they finished, so a
	// caller can report which ones to exclude or allow more time for.
	Result struct {
		StartTime           time.Time
		EndTime             time.Time
		Duration            time.Duration
		Results             []types.AuditResult
		IncompleteChecks    []string
		HostInfo            *osfingerprint.OSInfo
		Summary             Summary
		EnrichmentRequested bool
		EnrichmentError     error
		Enrichment          *enrichment.Result
		References          types.ReferenceExtraction
	}

	// Summary reports the outcome of a completed audit at both check and finding
	// level. PassedChecks counts checks that reached StatusCompleted with zero
	// findings; a WARNING or ERROR check is never counted as passed.
	// SkippedChecks counts checks excluded via --skip-checks. Finding counts are
	// broken down by severity so the analyst can assess exposure at a glance
	// without reading individual check output. TotalFindings is the sum of all
	// severity buckets.
	Summary struct {
		TotalChecks      int
		PassedChecks     int
		SkippedChecks    int
		TotalFindings    int
		CriticalFindings int
		HighFindings     int
		MediumFindings   int
		LowFindings      int
	}

	// checkRunner pairs a check's canonical name with its execution function
	checkRunner struct {
		name        string
		display     string
		description string
		run         func(ctx context.Context) types.AuditResult
	}

	// indexedResult pairs a check result with its canonical index so
	// concurrent completions can be written back into a fixed-order slice.
	// incomplete marks a check interrupted before it finished.
	indexedResult struct {
		index      int
		result     types.AuditResult
		incomplete bool
	}
)

// NewSecurityAuditor creates a new security auditor based on the OS
func NewSecurityAuditor(opts Options) *SecurityAuditor {
	osCtx := registry.DetectOS()

	auditor := &SecurityAuditor{
		verbose:   opts.Verbose,
		options:   opts,
		osContext: osCtx,
	}

	auditor.userChecker = checker.NewUserChecker(osCtx)
	auditor.permissionChecker = checker.NewPermissionChecker(osCtx, opts.FilePermsPath)

	switch runtime.GOOS {
	case "windows":
		auditor.sshChecker = checker.NewWindowsSSHChecker(osCtx)
		auditor.firewallChecker = checker.NewWindowsFirewallChecker(osCtx)
	default:
		auditor.sshChecker = checker.NewUnixSSHChecker(osCtx)
		auditor.firewallChecker = checker.NewUnixFirewallChecker(osCtx)
	}

	return auditor
}

// maxConcurrentChecks returns the bound on simultaneously executing checks.
// The bound scales with the host rather than the check set, so adding checks
// queues work instead of multiplying simultaneous subprocess and filesystem
// load. Operators can lower it through the GOMAXPROCS environment variable.
func maxConcurrentChecks() int {
	return runtime.GOMAXPROCS(0)
}

// RunAudit executes the enabled checks concurrently, writing each result to
// its check's canonical index so output order is independent of completion
// order. A skipped check occupies its index with a StatusSkipped result.
// ctx bounds the entire run -- checks and enrichment share its deadline --
// and cancellation propagates into checker exec and filesystem work.
func (sa *SecurityAuditor) RunAudit(ctx context.Context) (*Result, error) {
	if !registry.HasDefinitions(sa.osContext) {
		return nil, fmt.Errorf("no finding definitions for %s; the audit cannot report findings on this platform",
			sa.osContext.DisplayLabel())
	}
	runners := sa.checkRunners()
	enabled, err := enabledSet(runners, sa.options.Checks)
	if err != nil {
		return nil, err
	}

	fingerprint := sa.options.HostInfo
	if fingerprint == nil {
		if fingerprint, err = osfingerprint.GetOSFingerprint(); err != nil && sa.verbose {
			fmt.Printf("[!] OS fingerprint unavailable: %v\n", err)
		}
	}

	result := &Result{
		StartTime:           time.Now(),
		HostInfo:            fingerprint,
		Results:             make([]types.AuditResult, len(runners)),
		EnrichmentRequested: sa.options.Enrich,
	}

	sem := make(chan struct{}, maxConcurrentChecks())
	resultsChan := make(chan indexedResult)
	incompleteByIndex := make([]bool, len(runners))
	var wg sync.WaitGroup

	for i, r := range runners {
		if !enabled[r.name] {
			if sa.verbose {
				fmt.Printf("[*] Skipping %s check...\n", r.name)
			}
			result.Results[i] = skippedResult(r)
			continue
		}
		if sa.verbose {
			fmt.Printf("[*] Running %s check...\n", r.name)
		}
		wg.Add(1)
		go func(idx int, c checkRunner) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			res, incomplete := timeCheck(ctx, c.run)
			resultsChan <- indexedResult{index: idx, result: res, incomplete: incomplete}
		}(i, r)
	}

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	for ir := range resultsChan {
		result.Results[ir.index] = ir.result
		incompleteByIndex[ir.index] = ir.incomplete
	}

	for i, r := range runners {
		if incompleteByIndex[i] {
			result.IncompleteChecks = append(result.IncompleteChecks, r.name)
		}
	}

	sa.finalize(ctx, result)
	return result, nil
}

// checkRunners returns the canonical ordered check set. Slice position is
// the check's fixed output index.
func (sa *SecurityAuditor) checkRunners() []checkRunner {
	return []checkRunner{
		{
			name:        "firewall",
			display:     sa.firewallChecker.Name(),
			description: sa.firewallChecker.Description(),
			run:         sa.firewallChecker.Check,
		},
		{
			name:        "permissions",
			display:     sa.permissionChecker.Name(),
			description: sa.permissionChecker.Description(),
			run:         sa.permissionChecker.Check,
		},
		{
			name:        "ssh",
			display:     sa.sshChecker.Name(),
			description: sa.sshChecker.Description(),
			run:         sa.sshChecker.Check,
		},
		{
			name:        "users",
			display:     sa.userChecker.Name(),
			description: sa.userChecker.Description(),
			run:         sa.userChecker.Check,
		},
	}
}

// enabledSet  validates checks against the canonical runner set, rejecting
// unknown names and an empty set
func enabledSet(runners []checkRunner, checks []string) (map[string]bool, error) {
	known := make(map[string]bool, len(runners))
	for _, r := range runners {
		known[r.name] = true
	}
	enabled := make(map[string]bool, len(checks))
	for _, name := range checks {
		if !known[name] {
			return nil, fmt.Errorf("unknown check name %q", name)
		}
		enabled[name] = true
	}
	if len(enabled) == 0 {
		return nil, fmt.Errorf("all available checks were skipped; at least one must run")
	}
	return enabled, nil
}

// skippedResult returns the result row for a check excluded by flag, so a
// skip occupies its canonical index rather than vanishing from the set
func skippedResult(r checkRunner) types.AuditResult {
	return types.AuditResult{
		Name:        r.display,
		Description: r.description,
		Status:      types.StatusSkipped,
	}
}

// finalize computes duration, summary, and reference aggregation, then runs
// enrichment when requested. Enrichment shares the caller's ctx rather than
// opening a fresh deadline: --timeout is one budget for the whole run, not
// a separate window per phase.
func (sa *SecurityAuditor) finalize(ctx context.Context, result *Result) {
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)
	result.Summary = sa.calculateSummary(result.Results)
	result.References = aggregateReferences(result.Results)

	if !sa.options.Enrich {
		return
	}

	enricher, err := enrichment.NewEnricher()
	if err != nil {
		result.EnrichmentError = err
		return
	}

	if len(result.References.CWEs) == 0 {
		return
	}

	req := enrichment.EnrichRequest{
		CWEs:        result.References.CWEs,
		MinSeverity: sa.options.MinSeverity,
	}

	enrichResult, err := enricher.Enrich(ctx, req)
	if err != nil {
		result.EnrichmentError = err
		return
	}
	result.Enrichment = &enrichResult
}

func aggregateReferences(results []types.AuditResult) types.ReferenceExtraction {
	var ext types.ReferenceExtraction
	seen := make(map[string]struct{})
	for i := range results {
		sub := results[i].AllCWEReferences()
		for _, id := range sub.CWEs {
			if _, dup := seen[id]; dup {
				continue
			}
			seen[id] = struct{}{}
			ext.CWEs = append(ext.CWEs, id)
		}
		ext.Errors = append(ext.Errors, sub.Errors...)
	}
	return ext
}

// calculateSummary iterates all check results and produces a Summary with
// per-severity finding counts. A check is counted as passed only when it
// completes with zero findings. ERROR status checks are not counted as
// passed or skipped -- their findings still contribute to severity totals.
// Severity classification uses the canonical SeverityX constants from the
// types package so the bucketing is consistent with registry and enrichment
// output.
func (sa *SecurityAuditor) calculateSummary(results []types.AuditResult) Summary {
	summary := Summary{
		TotalChecks: len(results),
	}

	for _, result := range results {
		switch {
		case result.Status == types.StatusError:
			// ERROR checks are neither passed nor skipped --
			// their findings still count toward severity totals
		case result.Status == types.StatusSkipped:
			summary.SkippedChecks++
			continue
		case result.Status == types.StatusCompleted && len(result.Findings) == 0:
			summary.PassedChecks++
		}

		for _, finding := range result.Findings {
			summary.TotalFindings++
			switch strings.ToUpper(finding.Severity) {
			case types.SeverityCritical:
				summary.CriticalFindings++
			case types.SeverityHigh:
				summary.HighFindings++
			case types.SeverityMedium:
				summary.MediumFindings++
			case types.SeverityLow:
				summary.LowFindings++
			}
		}
	}
	return summary
}

// timeCheck runs fn and records its wall-clock span. A check whose context
// expired before fn returned is marked StatusError: its output reflects an
// interrupted run and cannot be reported as a completed check. The second
// return value reports whether the check was interrupted.
func timeCheck(ctx context.Context, fn func(context.Context) types.AuditResult) (types.AuditResult, bool) {
	start := time.Now()
	result := fn(ctx)
	end := time.Now()
	result.StartTime = start
	result.EndTime = end
	result.Duration = end.Sub(start)

	if ctx.Err() != nil {
		result.Status = types.StatusError
		result.Description = fmt.Sprintf("Check did not complete: %v", ctx.Err())
		result.Details = append(result.Details,
			fmt.Sprintf("%s Check interrupted: %v", types.SymbolError, ctx.Err()))
		return result, true
	}
	return result, false
}

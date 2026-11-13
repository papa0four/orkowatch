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
		CWEs                []string
	}

	// Summary counts a completed audit at three levels: checks by their
	// aggregate result, the conditions those checks evaluated by result, and
	// the findings, which are the conditions that failed, by severity. The
	// result counts are what tell a check that determined something adverse
	// from one that could not determine anything. Only results and
	// severities that occurred are present in the maps.
	Summary struct {
		TotalChecks     int                  `json:"total_checks" yaml:"total_checks"`
		Checks          map[types.Result]int `json:"checks" yaml:"checks"`
		TotalConditions int                  `json:"total_conditions" yaml:"total_conditions"`
		Conditions      map[types.Result]int `json:"conditions" yaml:"conditions"`
		TotalFindings   int                  `json:"total_findings" yaml:"total_findings"`
		Findings        map[string]int       `json:"findings" yaml:"findings"`
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

	auditor.sshChecker = checker.NewSSHChecker(osCtx)
	auditor.firewallChecker = checker.NewFirewallChecker(osCtx)
	auditor.userChecker = checker.NewUserChecker(osCtx)
	auditor.permissionChecker = checker.NewPermissionChecker(osCtx, opts.FilePermsPath)

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
// order. A skipped check occupies its index with a notselected result.
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
		Result:      types.ResultNotSelected,
		Reason:      "excluded by --skip-checks",
	}
}

// finalize computes duration, summary, and reference aggregation, then runs
// enrichment when requested. Enrichment shares the caller's ctx rather than
// opening a fresh deadline: --timeout is one budget for the whole run, not
// a separate window per phase.
func (sa *SecurityAuditor) finalize(ctx context.Context, result *Result) {
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)
	result.Summary = summarize(result.Results)
	result.CWEs = failedCWEs(result.Results)

	if !sa.options.Enrich {
		return
	}

	enricher, err := enrichment.NewEnricher()
	if err != nil {
		result.EnrichmentError = err
		return
	}

	if len(result.CWEs) == 0 {
		return
	}

	req := enrichment.EnrichRequest{
		CWEs:        result.CWEs,
		MinSeverity: sa.options.MinSeverity,
	}

	enrichResult, err := enricher.Enrich(ctx, req)
	if err != nil {
		result.EnrichmentError = err
		return
	}
	result.Enrichment = &enrichResult
}

// failedCWEs returns the weaknesses the failed conditions map to,
// deduplicated in order of first occurrence. Each comes from the typed field
// its registry definition was validated to carry, so there is nothing to
// parse and nothing that can fail.
func failedCWEs(results []types.AuditResult) []string {
	var cwes []string
	seen := make(map[types.CWE]struct{})
	for _, result := range results {
		for _, condition := range result.Conditions {
			if condition.Result != types.ResultFail || condition.Finding == nil || condition.Finding.CWE == "" {
				continue
			}
			if _, dup := seen[condition.Finding.CWE]; dup {
				continue
			}
			seen[condition.Finding.CWE] = struct{}{}
			cwes = append(cwes, string(condition.Finding.CWE))
		}
	}
	return cwes
}

// summarize counts checks and conditions by result and findings by severity.
// Everything derives from the conditions the checks recorded, so a check is
// never counted as passed for the mere absence of findings.
func summarize(results []types.AuditResult) Summary {
	summary := Summary{
		TotalChecks: len(results),
		Checks:      make(map[types.Result]int),
		Conditions:  make(map[types.Result]int),
		Findings:    make(map[string]int),
	}

	for _, result := range results {
		summary.Checks[result.Result]++
		for _, condition := range result.Conditions {
			summary.TotalConditions++
			summary.Conditions[condition.Result]++
			if condition.Result == types.ResultFail && condition.Finding != nil {
				summary.TotalFindings++
				summary.Findings[strings.ToUpper(types.EffectiveSeverity(*condition.Finding))]++
			}
		}
	}
	return summary
}

// timeCheck runs fn and records its wall-clock span. A check whose context
// expired before fn returned is reported as an error whatever its conditions
// concluded: its output reflects an interrupted run and cannot stand as a
// completed evaluation. The second return value reports whether the check
// was interrupted.
func timeCheck(ctx context.Context, fn func(context.Context) types.AuditResult) (types.AuditResult, bool) {
	start := time.Now()
	result := fn(ctx)
	end := time.Now()
	result.StartTime = start
	result.EndTime = end
	result.Duration = end.Sub(start)

	if ctx.Err() != nil {
		result.Result = types.ResultError
		result.Reason = fmt.Sprintf("check did not complete: %v", ctx.Err())
		return result, true
	}
	return result, false
}

// cmd/commands/refresh_browser.go

package cmd

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/charmbracelet/x/ansi"

	"github.com/papa0four/orkowatch/cmd/commands/delivery"
	"github.com/papa0four/orkowatch/cmd/commands/held"
	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/dataset/progress"
	"github.com/papa0four/orkowatch/internal/dataset/store"
	"github.com/papa0four/orkowatch/internal/osfingerprint"
	"github.com/papa0four/orkowatch/internal/render"
	"github.com/papa0four/orkowatch/internal/tui"
)

// liveRefresh is the r of the results browser of a live run whose inventory
// was matched against a dataset: it refreshes what the host's datasets are
// through owatch data refresh's own plan and fetch, matches the run's
// inventory again, recounts the audit from the refreshed catalog when the
// audit ran, and gives the report matched again. Nothing of the host is
// collected again.
type liveRefresh struct {
	data     *dataCmd
	matching inventoryMatching
	run      *held.Run
	result   *ScanResult
	title    string
	severity string
	out      *delivery.Flags
	plan     refreshPlan
}

// liveRefreshFor is the refresh the browser of result offers, or nil when
// result's inventory was matched against no dataset, as on a host no dataset
// covers or a run with no software module. run is the run's own data, which
// says what an elevated run is to do instead.
func liveRefreshFor(data *dataCmd, m inventoryMatching, run *held.Run, result *ScanResult, title, minSeverity string, out *delivery.Flags) tui.Refresher {
	if result.Vulns == nil || result.Vulns.ID == "" {
		return nil
	}
	return &liveRefresh{data: data, matching: m, run: run, result: result, title: title, severity: minSeverity, out: out}
}

// host is the host the run was matched for: the fingerprint the run read, or
// this host's when the run read none.
func (l *liveRefresh) host() (*osfingerprint.OSInfo, error) {
	if l.result.OSInfo != nil {
		return l.result.OSInfo, nil
	}
	return l.data.host()
}

// Plan is each dataset that applies to the host, with its download. An
// elevated run fetches nothing: it leaves the browser with what a run that
// does not hold its datasets is told to run, and then this command again.
func (l *liveRefresh) Plan(ctx context.Context) ([]string, error) {
	host, err := l.host()
	if err != nil {
		return nil, fmt.Errorf("the host could not be identified: %w", err)
	}
	plan, err := l.data.planRefresh(ctx, host)
	switch {
	case errors.Is(err, errRefreshElevated):
		return nil, tui.Leave{Text: l.run.ToFetch(ctx, host) + " Then run this command again."}
	case err != nil:
		return nil, err
	case len(plan.datasets) == 0:
		return nil, errors.New("this version of owatch knows no dataset for this host")
	}
	l.plan = plan
	lines := make([]string, len(plan.datasets))
	for i, p := range plan.datasets {
		lines[i] = render.HostText(p.String())
		if p.large() {
			lines[i] += ", larger than " + dataset.Size(largeDownload)
		}
	}
	return lines, nil
}

// Fetch fetches every dataset the plan named into the account's store,
// telling line each line of its progress as owatch data refresh words it,
// then matches the run again. A refresh that does not bring every dataset is
// an error with what happened to each, and the result is left as it was.
func (l *liveRefresh) Fetch(ctx context.Context, line func(string)) (tui.Report, error) {
	dest, err := l.data.open(ctx)
	if err != nil {
		return tui.Report{}, err
	}
	report := progress.New(lineWriter(line), render.StdoutWidth, l.data.now)
	for _, p := range l.plan.datasets {
		report.Expect(p.dataset.ID(), p.size, p.stated)
	}
	report.Start()
	outcomes, err := l.plan.fetch(ctx, dest, l.plan.datasets, l.data.now(), report)
	err = errors.Join(err, report.Stop())
	switch {
	case errors.Is(err, store.ErrUnreachable):
		return tui.Report{}, noNetwork(err, l.plan.host)
	case err != nil:
		return tui.Report{}, err
	}
	var said strings.Builder
	if failed, err := printOutcomes(&said, outcomes); err != nil {
		return tui.Report{}, err
	} else if failed > 0 {
		return tui.Report{}, fmt.Errorf("%d of %s not refreshed: %s", failed, render.Count(len(outcomes), "dataset", "datasets"),
			strings.Join(strings.Split(strings.TrimSpace(said.String()), "\n"), "; "))
	}
	return l.matched(ctx)
}

// matched is the report of the run matched again against the datasets the
// account's store now holds, read through a new run's data, since the run's
// own read them once. The run's result is copied, not changed.
func (l *liveRefresh) matched(ctx context.Context) (tui.Report, error) {
	result := *l.result
	result.Modules = slices.Clone(l.result.Modules)
	data := l.data.run()
	matchSoftware(ctx, l.matching, data, &result)
	if l.result.SecurityAudit != nil {
		recounted := *l.result.SecurityAudit
		host, err := l.host()
		if err != nil {
			return tui.Report{}, fmt.Errorf("the host could not be identified: %w", err)
		}
		recounted.MarkExploited(data.Exploited(ctx, host))
		result.SecurityAudit = &recounted
	}
	next := &liveRefresh{data: l.data, matching: l.matching, run: l.run, result: &result, title: l.title, severity: l.severity, out: l.out}
	r := allReport{title: l.title, minSeverity: l.severity, result: &result, refresh: next}
	payload, err := l.out.Payload(r)
	if err != nil {
		return tui.Report{}, err
	}
	l.result = &result
	return r.Browse(string(payload)), nil
}

// lineWriter gives line the last line of what the progress writes, as a
// terminal would show it: the line under way rewritten in place, or the line
// a step ended on, without color.
type lineWriter func(string)

func (w lineWriter) Write(b []byte) (int, error) {
	text := ansi.Strip(string(b))
	parts := strings.FieldsFunc(text, func(r rune) bool { return r == '\r' || r == '\n' })
	if len(parts) > 0 {
		w(parts[len(parts)-1])
	}
	return len(b), nil
}

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

// refreshHelp is what the help of owatch software and owatch all says of r in
// the results browser, so the two say it alike.
const refreshHelp = `In the results browser, r refreshes the datasets the packages were matched
against and matches them again, after naming each dataset with its size and
asking; under owatch all it also recounts the audit's counts of known-exploited
vulnerabilities. Elevated, it fetches nothing and prints what to run instead.`

// browserRefresh is the r of the results browser of a report whose inventory
// was matched against a dataset: it refreshes the host's datasets through
// owatch data refresh's own plan and fetch, then matches the report again by
// rematch. A live run and a saved report differ only in their rematch and in
// whether check finds the report can be matched here; the refresh is this one.
type browserRefresh struct {
	data    *dataCmd
	run     *held.Run
	host    func() (*osfingerprint.OSInfo, error)
	check   func(host *osfingerprint.OSInfo) error
	rematch func(ctx context.Context, data *held.Run, host *osfingerprint.OSInfo) (tui.Report, error)
	plan    refreshPlan
}

// Plan is each dataset that applies to the host, with its download, once the
// report is found to be one that can be matched here. An elevated run fetches
// nothing: it leaves the browser with what a run that does not hold its
// datasets is told to run, and then this command again.
func (r *browserRefresh) Plan(ctx context.Context) ([]string, error) {
	host, err := r.host()
	if err != nil {
		return nil, fmt.Errorf("the host could not be identified: %w", err)
	}
	if r.check != nil {
		if err := r.check(host); err != nil {
			return nil, err
		}
	}
	plan, err := r.data.planRefresh(ctx, host)
	switch {
	case errors.Is(err, errRefreshElevated):
		return nil, tui.Leave{Text: r.run.ToFetch(ctx, host) + " Then run this command again."}
	case err != nil:
		return nil, err
	case len(plan.datasets) == 0:
		return nil, errors.New("this version of owatch knows no dataset for this host")
	}
	r.plan = plan
	lines := make([]string, len(plan.datasets))
	for i, p := range plan.datasets {
		lines[i] = render.HostText(p.brief())
		if p.large() {
			lines[i] += ", larger than " + dataset.Size(largeDownload)
		}
	}
	return lines, nil
}

// Fetch fetches every dataset the plan named into the account's store,
// telling line each line of its progress as owatch data refresh words it,
// then matches the report again through a new run's data, since a run's data
// reads each dataset once. A refresh that does not bring every dataset is an
// error with what happened to each, and nothing is matched again.
func (r *browserRefresh) Fetch(ctx context.Context, line func(string)) (tui.Report, error) {
	dest, err := r.data.open(ctx)
	if err != nil {
		return tui.Report{}, err
	}
	report := progress.New(lineWriter(line), render.StdoutWidth, r.data.now)
	for _, p := range r.plan.datasets {
		report.Expect(p.dataset.ID(), p.size, p.stated)
	}
	report.Start()
	outcomes, err := r.plan.fetch(ctx, dest, r.plan.datasets, r.data.now(), report)
	err = errors.Join(err, report.Stop())
	switch {
	case errors.Is(err, store.ErrUnreachable):
		return tui.Report{}, noNetwork(err, r.plan.host)
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
	matched, err := r.rematch(ctx, r.data.run(), r.plan.host)
	if err != nil {
		return tui.Report{}, err
	}
	matched.Refresh = r
	return matched, nil
}

// liveRun is what the refresh of a live run's browser matches again: the
// run's result, and how its report is titled, filtered, and encoded.
type liveRun struct {
	matching inventoryMatching
	result   *ScanResult
	title    string
	severity string
	out      *delivery.Flags
}

// liveRefreshFor is the refresh the browser of result offers, or nil when
// result's inventory was matched against no dataset, as on a host no dataset
// covers or a run with no software module. run is the run's own data, which
// says what an elevated run is to do instead.
func liveRefreshFor(data *dataCmd, m inventoryMatching, run *held.Run, result *ScanResult, title, minSeverity string, out *delivery.Flags) tui.Refresher {
	if refresh, _ := newLiveRefresh(data, m, run, result, title, minSeverity, out); refresh != nil {
		return refresh
	}
	return nil
}

// newLiveRefresh is liveRefreshFor's refresh with the run it matches again.
func newLiveRefresh(data *dataCmd, m inventoryMatching, run *held.Run, result *ScanResult, title, minSeverity string, out *delivery.Flags) (*browserRefresh, *liveRun) {
	if result.Vulns == nil || result.Vulns.ID == "" {
		return nil, nil
	}
	live := &liveRun{matching: m, result: result, title: title, severity: minSeverity, out: out}
	host := func() (*osfingerprint.OSInfo, error) {
		if live.result.OSInfo != nil {
			return live.result.OSInfo, nil
		}
		return data.host()
	}
	return &browserRefresh{data: data, run: run, host: host, rematch: live.rematch}, live
}

// rematch is the report of the run matched again against what data reads,
// with the audit recounted from the catalog when the audit ran. The run's
// result is copied, not changed; the copy is what a later r matches again.
func (l *liveRun) rematch(ctx context.Context, data *held.Run, host *osfingerprint.OSInfo) (tui.Report, error) {
	result := *l.result
	result.Modules = slices.Clone(l.result.Modules)
	matchSoftware(ctx, l.matching, data, &result)
	if l.result.SecurityAudit != nil {
		recounted := *l.result.SecurityAudit
		recounted.MarkExploited(data.Exploited(ctx, host))
		result.SecurityAudit = &recounted
	}
	r := allReport{title: l.title, minSeverity: l.severity, result: &result}
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

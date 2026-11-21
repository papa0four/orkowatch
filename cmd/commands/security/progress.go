// cmd/commands/security/progress.go

package security

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/papa0four/orkowatch/internal/security/audit"
	"github.com/papa0four/orkowatch/internal/security/finding"
	"github.com/papa0four/orkowatch/internal/selection"
	"github.com/papa0four/orkowatch/internal/tui"
)

// ErrScanDeclined is returned when the operator answers no to the full
// filesystem scan confirmation. Nothing went wrong, so callers end the
// command without reporting a failure.
var ErrScanDeclined = errors.New("scan declined by operator")

// digitGroup is how many digits sit between separators in a large number.
const digitGroup = 3

// progressObserver forwards the audit's progress to a display.
type progressObserver struct {
	reporter tui.Reporter
}

// CheckTasks returns one display task per audit check, in canonical order.
// A check outside mask keeps its row, marked as skipped, so the display
// accounts for every check the way the report does.
func CheckTasks(mask selection.CheckMask) []tui.Task {
	enabled := make(map[string]bool)
	for _, name := range selection.EnabledChecks(mask) {
		enabled[name] = true
	}

	var tasks []tui.Task
	for _, name := range selection.EnabledChecks(EveryCheck) {
		tasks = append(tasks, tui.Task{ID: name, Label: name + " check", Skipped: !enabled[name]})
	}
	return tasks
}

// Observe returns the audit observer that reports each check to reporter
// under the task identifiers CheckTasks assigned.
func Observe(reporter tui.Reporter) audit.Observer {
	return progressObserver{reporter: reporter}
}

func (o progressObserver) CheckStarted(name string) {
	o.reporter.Start(name)
}

func (o progressObserver) CheckProgress(name string, scanned int) {
	o.reporter.Progress(name, grouped(scanned)+" entries scanned")
}

// grouped renders n with a comma between each group of three digits.
func grouped(n int) string {
	digits := strconv.Itoa(n)
	for i := len(digits) - digitGroup; i > 0; i -= digitGroup {
		digits = digits[:i] + "," + digits[i:]
	}
	return digits
}

func (o progressObserver) CheckFinished(name string, result finding.AuditResult) {
	outcome := tui.Outcome{Result: result.Result, Reason: result.Reason}
	for _, condition := range result.Conditions {
		if condition.Result == finding.ResultFail && condition.Finding != nil {
			outcome.Findings = append(outcome.Findings, tui.Finding{
				Severity: finding.EffectiveSeverity(*condition.Finding),
				Title:    condition.Finding.Title,
			})
		}
	}
	o.reporter.Finish(name, outcome)
}

// ConfirmFullScan asks the operator before a permissions check that will
// read the whole filesystem, which takes long enough that starting one by
// accident is worth a question. It returns ErrScanDeclined on anything but
// yes. It is only asked when a person is there to answer: the caller passes
// interactive as false when input or output is not a terminal, and the run
// then proceeds as it always has, so scripts and pipelines are unaffected.
func (a *AuditFlags) ConfirmFullScan(mask selection.CheckMask, scanRoot string, interactive bool, in io.Reader, out io.Writer) error {
	if a.yes || !interactive || mask&selection.CheckPerms == 0 || scanRoot != "" {
		return nil
	}

	if _, err := fmt.Fprint(out, "The permissions check will scan the entire filesystem, which can take several minutes.\n"+
		"Narrow it with --fperms <path>, or skip this question with --yes.\n"+
		"Proceed? [y/N] "); err != nil {
		return fmt.Errorf("ask for confirmation: %w", err)
	}

	answer, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read confirmation: %w", err)
	}
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "y", "yes":
		return nil
	default:
		return ErrScanDeclined
	}
}

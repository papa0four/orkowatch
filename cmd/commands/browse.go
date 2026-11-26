// cmd/commands/browse.go

package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/papa0four/orkowatch/cmd/commands/delivery"
	"github.com/papa0four/orkowatch/cmd/commands/held"
	"github.com/papa0four/orkowatch/cmd/commands/security"
	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/osfingerprint"
	"github.com/papa0four/orkowatch/internal/render"
	"github.com/papa0four/orkowatch/internal/security/audit"
	"github.com/papa0four/orkowatch/internal/sockets"
	"github.com/papa0four/orkowatch/internal/softwarelist"
	"github.com/papa0four/orkowatch/internal/tui"
	"github.com/papa0four/orkowatch/internal/vulnmatch"
)

// maxReportBytes is the largest report file browse reads. A whole-filesystem
// audit of a large host runs to tens of megabytes; the limit is far above
// that and still refuses a file that would exhaust memory before the browser
// opened.
const maxReportBytes = 512 << 20

type (
	// browseCmd holds one invocation's flag state. Cobra binds the flag
	// directly into the field.
	browseCmd struct {
		inputFormat  string
		outputFormat string
	}

	// savedReport is a report file decoded as either shape owatch writes:
	// the audit report, whose view sits at the top level, and the all
	// report, which carries the audit under security beside its modules and
	// system block.
	savedReport struct {
		audit.View `yaml:",inline"`

		Modules  []moduleRun                `json:"modules" yaml:"modules"`
		System   *osfingerprint.SystemView  `json:"system" yaml:"system"`
		Software *softwarelist.SoftwareView `json:"software" yaml:"software"`
		Vulns    *vulnmatch.View            `json:"vulnerabilities" yaml:"vulnerabilities"`
		Sockets  *sockets.View              `json:"sockets" yaml:"sockets"`
		Datasets *dataset.View              `json:"datasets" yaml:"datasets"`
		Security *audit.View                `json:"security" yaml:"security"`
	}
)

// newBrowseCmd returns the command that opens a saved report in the results
// browser.
func newBrowseCmd() *cobra.Command {
	c := &browseCmd{}
	cmd := &cobra.Command{
		Use:   "browse [report-file]",
		Args:  cobra.MaximumNArgs(1),
		Short: "Open a saved report in the results browser",
		Long: fmt.Sprintf(`Open a report saved with --report-file in the interactive results browser.
The report must be in a format that holds the whole report (%s) and come from
owatch audit, owatch all, a command that runs one of all's modules, or owatch
data status. The format is taken from the file's extension, or
from --input-format when the extension does not say. With no file named, the
newest owatch report in the current directory is opened. The full report under
t is shown as text unless --output names another format; every other part of the
browser is plain text.`, delivery.LosslessNames()),
		Example: `  # Open the newest report in the current directory
  owatch browse

  # Open a specific report
  owatch browse /path/to/reports/owatch-host-SFUP-20261114T120000Z.json

  # Open a report whose extension does not name its format
  owatch browse --input-format yaml /path/to/reports/last-scan.out

  # Show the full report under t as JSON
  owatch browse -o json /path/to/reports/owatch-host-SFUP-20261114T120000Z.json`,
		RunE: c.runE,
	}
	cmd.Flags().StringVar(&c.inputFormat, "input-format", "",
		fmt.Sprintf("Format of the report file (%s); by default taken from its extension", delivery.LosslessNames()))
	cmd.Flags().StringVarP(&c.outputFormat, "output", "o", string(delivery.FormatText),
		fmt.Sprintf("Format of the full report shown under t (%s)", delivery.FormatNames()))
	return cmd
}

func (c *browseCmd) runE(_ *cobra.Command, args []string) error {
	named, err := c.namedFormat()
	if err != nil {
		return err
	}
	view, ok := delivery.ParseFormat(c.outputFormat)
	if !ok {
		return fmt.Errorf("invalid output format: %s (valid: %s)", c.outputFormat, delivery.FormatNames())
	}
	if !render.StdoutIsTerminal() || !render.StdinIsTerminal() {
		return errors.New("browse needs an interactive terminal")
	}

	path, err := reportPath(args)
	if err != nil {
		return err
	}
	format, err := inputFormat(named, path)
	if err != nil {
		return err
	}
	data, err := readReport(path)
	if err != nil {
		return err
	}
	saved, err := readSaved(path, format, data)
	if err != nil {
		return err
	}
	report, err := savedBrowserReport(path, view, saved)
	if err != nil {
		return err
	}
	if saved.isAll() {
		report.Refresh = savedRefreshFor(hostData(), hostMatching(), held.ForHost(), path, saved.all(), view)
	}
	return delivery.Browse(report)
}

// namedFormat resolves --input-format, or returns the empty format when it was
// not given. A format that does not hold the whole report is refused with the
// reason, since a flat or text export has no structure to list.
func (c *browseCmd) namedFormat() (delivery.Format, error) {
	if c.inputFormat == "" {
		return "", nil
	}
	format, ok := delivery.ParseFormat(c.inputFormat)
	if !ok {
		return "", fmt.Errorf("invalid input format: %s (valid: %s)", c.inputFormat, delivery.LosslessNames())
	}
	return format, losslessOrRefuse(format)
}

// inputFormat settles the format a report file is read in: the one named, or
// the one its extension names.
func inputFormat(named delivery.Format, path string) (delivery.Format, error) {
	if named != "" {
		return named, nil
	}
	format, ok := delivery.FormatForExtension(strings.TrimPrefix(filepath.Ext(path), "."))
	if !ok {
		return "", fmt.Errorf("%s: cannot tell its format from the extension; name it with --input-format (%s)",
			path, delivery.LosslessNames())
	}
	return format, losslessOrRefuse(format)
}

// losslessOrRefuse refuses a format that does not hold the whole report. The
// text report is a rendering of one, and the flat exports cannot hold the
// modules, system block, software or checks with no findings that the
// browser's tabs are built from.
func losslessOrRefuse(format delivery.Format) error {
	if format.Lossless() {
		return nil
	}
	return fmt.Errorf("%s is not a format browse can read: it does not hold the whole report. Save one with -o %s",
		format, strings.ReplaceAll(delivery.LosslessNames(), ", ", " or -o "))
}

// reportPath returns the file named on the command line, or the newest
// owatch report in the current directory when none was.
func reportPath(args []string) (string, error) {
	if len(args) == 1 {
		return args[0], nil
	}

	var patterns []string
	var newest string
	var newestTime time.Time
	for _, format := range delivery.LosslessFormats() {
		pattern := "owatch-*." + format.Extension()
		patterns = append(patterns, pattern)
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return "", fmt.Errorf("find reports: %w", err)
		}
		for _, match := range matches {
			info, err := os.Stat(match)
			if err != nil || !info.Mode().IsRegular() {
				continue
			}
			if newest == "" || info.ModTime().After(newestTime) {
				newest, newestTime = match, info.ModTime()
			}
		}
	}
	if newest == "" {
		return "", fmt.Errorf("no report found matching %s in the current directory; save one with --report-file, or name the file",
			strings.Join(patterns, " or "))
	}
	return newest, nil
}

// readReport reads a report file, refusing one over maxReportBytes. The
// limit is enforced on what is read rather than on the size the file
// reports, so a file that grows while it is read is refused too.
func readReport(path string) ([]byte, error) {
	file, err := os.Open(path) // #nosec G304 -- operator-supplied report path
	if err != nil {
		return nil, fmt.Errorf("open report: %w", err)
	}
	defer file.Close() //nolint:errcheck // read-only file; everything wanted from it is read before it closes

	data, err := io.ReadAll(io.LimitReader(file, maxReportBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read report: %w", err)
	}
	if len(data) > maxReportBytes {
		return nil, fmt.Errorf("%s is larger than %d MiB, more than browse will read", path, maxReportBytes>>20)
	}
	return data, nil
}

// decodeReport decodes a report file in the format given and builds what the
// browser shows from it, the full report under t included, rendered from the
// decoded projection in the format view names by the same writers and encoders
// a live run uses, so a saved report opens to exactly what the run that wrote
// it showed. The shape is judged by what the file holds, not by its name: an
// all report has modules, an audit report has results. A file with neither, or
// whose results carry no result, which reports from before the current result
// model lack, is refused.
func decodeReport(path string, format, view delivery.Format, data []byte) (tui.Report, error) {
	saved, err := readSaved(path, format, data)
	if err != nil {
		return tui.Report{}, err
	}
	return savedBrowserReport(path, view, saved)
}

// readSaved decodes a report file in the format given.
func readSaved(path string, format delivery.Format, data []byte) (savedReport, error) {
	var saved savedReport
	var err error
	switch format {
	case delivery.FormatJSON:
		err = json.Unmarshal(data, &saved)
	case delivery.FormatYAML:
		err = yaml.NewDecoder(bytes.NewReader(data)).Decode(&saved)
	default:
		return savedReport{}, losslessOrRefuse(format)
	}
	if err != nil {
		return savedReport{}, fmt.Errorf("%s is not an owatch report this version can read: %w", path, err)
	}
	return saved, nil
}

// isAll reports whether saved is an all report, or one of a command that runs
// one of all's modules, and one this version can read.
func (saved savedReport) isAll() bool {
	return len(saved.Modules) > 0 && readable(saved.Security)
}

// all is the all report saved holds, as a run projects one.
func (saved savedReport) all() allResult {
	return allResult{
		Timestamp: saved.Timestamp,
		Duration:  saved.Duration,
		Modules:   saved.Modules,
		System:    saved.System,
		Software:  saved.Software,
		Vulns:     saved.Vulns,
		Sockets:   saved.Sockets,
		Datasets:  saved.Datasets,
		Security:  saved.Security,
	}
}

// allBrowserReport is what the browser shows of the saved all report all,
// titled title, with its full report in the format view names: as the file
// was read, and as it is matched again.
func allBrowserReport(title string, view delivery.Format, all allResult) (tui.Report, error) {
	text, err := fullReport(all, view, func(w io.Writer) error { return writeAllText(w, all) })
	if err != nil {
		return tui.Report{}, err
	}
	return security.BrowserReport(allSource(title, all, text)), nil
}

// savedBrowserReport is what the browser shows of saved, read from path.
func savedBrowserReport(path string, view delivery.Format, saved savedReport) (tui.Report, error) {
	title := "owatch browse  " + filepath.Base(path)
	switch {
	case saved.isAll():
		report, err := allBrowserReport(title, view, saved.all())
		if err != nil {
			return tui.Report{}, fmt.Errorf("render %s: %w", path, err)
		}
		return report, nil
	case len(saved.Modules) == 0 && len(saved.Results) > 0 && readable(&saved.View):
		text, err := fullReport(saved.View, view, func(w io.Writer) error { return security.WriteAuditText(w, saved.View) })
		if err != nil {
			return tui.Report{}, fmt.Errorf("render %s: %w", path, err)
		}
		return security.BrowserReport(security.AuditSource(title, saved.View, text)), nil
	default:
		return tui.Report{}, fmt.Errorf("%s is not an owatch audit or all report this version can read", path)
	}
}

// fullReport renders a report as the full-report view shows it: as text
// through write, or as the structured encoding of its projection, the same
// encoding a command delivers.
func fullReport(projection any, view delivery.Format, write func(io.Writer) error) (string, error) {
	if view == delivery.FormatText {
		var text strings.Builder
		if err := write(&text); err != nil {
			return "", err
		}
		return text.String(), nil
	}
	data, err := delivery.Encode(projection, view)
	return string(data), err
}

// readable reports whether every check and condition in view states its
// result. A nil view is an all report that ran no audit, which is readable.
func readable(view *audit.View) bool {
	if view == nil {
		return true
	}
	for _, check := range view.Results {
		if check.Result == "" {
			return false
		}
		for _, condition := range check.Conditions {
			if condition.Result == "" {
				return false
			}
		}
	}
	return true
}

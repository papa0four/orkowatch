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
	"github.com/papa0four/orkowatch/cmd/commands/security"
	"github.com/papa0four/orkowatch/internal/osfingerprint"
	"github.com/papa0four/orkowatch/internal/render"
	"github.com/papa0four/orkowatch/internal/security/audit"
	"github.com/papa0four/orkowatch/internal/softwarelist"
	"github.com/papa0four/orkowatch/internal/tui"
)

// maxReportBytes is the largest report file browse reads. A whole-filesystem
// audit of a large host runs to tens of megabytes; the limit is far above
// that and still refuses a file that would exhaust memory before the browser
// opened.
const maxReportBytes = 512 << 20

type (
	// savedReport is a report file decoded as either shape owatch writes:
	// the audit report, whose view sits at the top level, and the all
	// report, which carries the audit under security beside its modules and
	// system block.
	savedReport struct {
		audit.View `yaml:",inline"`

		Modules  []moduleRun                `json:"modules" yaml:"modules"`
		System   *osfingerprint.SystemView  `json:"system" yaml:"system"`
		Software *softwarelist.SoftwareView `json:"software" yaml:"software"`
		Security *audit.View                `json:"security" yaml:"security"`
	}
)

// structuredFormats are the formats a saved report can be browsed from.
// Text has no structure to list rules from.
var structuredFormats = []delivery.Format{delivery.FormatJSON, delivery.FormatYAML}

// newBrowseCmd returns the command that opens a saved report in the results
// browser.
func newBrowseCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "browse [report-file]",
		Args:  cobra.MaximumNArgs(1),
		Short: "Open a saved report in the results browser",
		Long: `Open a report saved with --report-file in the interactive results browser.
The report must be JSON or YAML from owatch audit or owatch all. With no file
named, the newest owatch report in the current directory is opened.`,
		Example: `  # Open the newest report in the current directory
  owatch browse

  # Open a specific report
  owatch browse /path/to/reports/owatch-host-SFUP-20261114T120000Z.json`,
		RunE: runBrowse,
	}
}

func runBrowse(_ *cobra.Command, args []string) error {
	if !render.StdoutIsTerminal() || !render.StdinIsTerminal() {
		return errors.New("browse needs an interactive terminal")
	}

	path, err := reportPath(args)
	if err != nil {
		return err
	}
	data, err := readReport(path)
	if err != nil {
		return err
	}
	report, err := decodeReport(path, data)
	if err != nil {
		return err
	}
	return tui.Browse(report)
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
	for _, format := range structuredFormats {
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

// decodeReport decodes a report file in the format its extension names and
// builds what the browser shows from it. The shape is judged by what the file
// holds, not by its name: an all report has modules, an audit report has
// results. A file with neither, or whose results carry no result, which
// reports from before the current result model lack, is refused.
func decodeReport(path string, data []byte) (tui.Report, error) {
	format, ok := delivery.FormatForExtension(strings.TrimPrefix(filepath.Ext(path), "."))
	var saved savedReport
	var err error
	switch {
	case ok && format == delivery.FormatJSON:
		err = json.Unmarshal(data, &saved)
	case ok && format == delivery.FormatYAML:
		err = yaml.NewDecoder(bytes.NewReader(data)).Decode(&saved)
	default:
		return tui.Report{}, fmt.Errorf("%s: browse reads JSON or YAML reports; save one with -o json or -o yaml", path)
	}
	if err != nil {
		return tui.Report{}, fmt.Errorf("%s is not an owatch report this version can read: %w", path, err)
	}

	title := "owatch browse  " + filepath.Base(path)
	switch {
	case len(saved.Modules) > 0 && readable(saved.Security):
		return security.BrowserReport(security.BrowserSource{
			Title:    title,
			Audit:    saved.Security,
			System:   saved.System,
			Software: saved.Software,
			Modules:  moduleNotes(saved.Modules),
			Text:     string(data),
		}), nil
	case len(saved.Modules) == 0 && len(saved.Results) > 0 && readable(&saved.View):
		return security.BrowserReport(security.BrowserSource{
			Title:  title,
			Audit:  &saved.View,
			System: saved.SystemInfo,
			Text:   string(data),
		}), nil
	default:
		return tui.Report{}, fmt.Errorf("%s is not an owatch audit or all report this version can read", path)
	}
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

// cmd/commands/delivery/delivery.go

// Package delivery owns the output destination surface shared by the owatch
// commands that produce a report: the --output, --report-file,
// --allow-elevated-write and --plain flags, the rule that resolves the
// effective encoding, the encoding of a command's result at that format, and
// its emission to stdout, to a generated file, or to the results browser.
//
// It lives under cmd because binding flags requires pflag, which the write
// guards in internal/report must not depend on.
package delivery

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/papa0four/orkowatch/internal/render"
	"github.com/papa0four/orkowatch/internal/report"
	"github.com/papa0four/orkowatch/internal/selection"
	"github.com/papa0four/orkowatch/internal/tui"
)

type (
	// Report is a command's finished result. View supplies the value for
	// structured encoding; WriteText renders the same result as text.
	// Commands implement it so format dispatch lives in Deliver alone.
	Report interface {
		View() any
		WriteText(w io.Writer) error
	}

	// Browsable is implemented by a report the results browser can show.
	// text is the report's complete plain rendering, which the browser can
	// page through.
	Browsable interface {
		Browse(text string) tui.Report
	}

	// Flags holds one invocation's output destination state. Cobra binds the flags
	// directly into these fields, so the values Deliver reads are the values that
	// invocation parsed.
	Flags struct {
		outputFormat       string
		reportFile         string
		allowElevatedWrite bool
		plain              bool

		// format is the effective encoding, resolved once in Resolve from
		// outputFormat and reportFile.
		format Format
	}
)

// Bind registers the output destination flags on cmd and returns the state they
// write into. Resolve must run before Format, ToFile, or Deliver.
func Bind(cmd *cobra.Command) *Flags {
	f := &Flags{}

	cmd.Flags().StringVarP(&f.outputFormat, "output", "o", string(FormatText),
		fmt.Sprintf("Format of the full report (%s), wherever it goes: printed with --plain, written with "+
			"--report-file, or shown by t in the results browser. Unspecified, a report file is JSON and "+
			"anything else is text", FormatNames()))
	cmd.Flags().StringVar(&f.reportFile, "report-file", "",
		"Save the report to the specified directory; filename is generated automatically")
	cmd.Flags().BoolVar(&f.allowElevatedWrite, "allow-elevated-write", false,
		"Permit an elevated write outside the allowlisted directories or into a directory other users control")
	cmd.Flags().BoolVar(&f.plain, "plain", false,
		"Print the report to the terminal instead of opening the results browser")

	return f
}

// Resolve validates the parsed values and fixes the effective encoding: an
// explicit --output wins, otherwise a report file implies JSON and a bare run
// is text.
func (f *Flags) Resolve(cmd *cobra.Command) error {
	if f == nil {
		return errors.New("output flags were not bound to the command")
	}

	format, ok := ParseFormat(f.outputFormat)
	if !ok {
		return fmt.Errorf("invalid output format: %s (valid: %s)", f.outputFormat, FormatNames())
	}

	switch {
	case cmd.Flags().Changed("output"):
		f.format = format
	case f.reportFile != "":
		f.format = FormatJSON
	default:
		f.format = FormatText
	}

	if cmd.Flags().Changed("report-file") {
		if err := report.ValidateDir(f.reportFile); err != nil {
			return fmt.Errorf("--report-file: %w", err)
		}
	}

	return nil
}

// Format returns the encoding Resolve settled on.
func (f *Flags) Format() Format {
	return f.format
}

// ToFile reports whether output goes to a report file rather than stdout.
// Callers suppress progress output when it does, so it cannot interleave with
// the report.
func (f *Flags) ToFile() bool {
	return f.reportFile != ""
}

// browses reports whether the report opens in the results browser rather
// than being printed or written. It does when a person is at a terminal to use
// it, on both input and output, and has not asked for the report itself with
// --plain or --report-file. The format named with --output does not decide
// this: it is the format of the full report, which the browser shows under t,
// while every other part of the browser is plain text. Anything that reads
// owatch's output, a pipe, a redirect or a script, is not a terminal and gets
// the report in the format asked for.
func (f *Flags) browses() bool {
	return f.reportFile == "" && !f.plain &&
		render.StdoutIsTerminal() && render.StdinIsTerminal()
}

// Encode encodes v in a structured format, JSON indented or YAML. It is the
// one place those encodings are made, so a report a command delivers and a
// saved report shown by owatch browse are encoded alike.
func Encode(v any, format Format) ([]byte, error) {
	var buf bytes.Buffer
	switch format {
	case FormatJSON:
		enc := json.NewEncoder(&buf)
		enc.SetIndent("", "  ")
		if err := enc.Encode(v); err != nil {
			return nil, fmt.Errorf("failed to encode JSON: %w", err)
		}
	case FormatYAML:
		if err := yaml.NewEncoder(&buf).Encode(v); err != nil {
			return nil, fmt.Errorf("failed to encode YAML: %w", err)
		}
	default:
		return nil, fmt.Errorf("%s is not a structured format", format)
	}
	return buf.Bytes(), nil
}

// Deliver encodes r at the resolved format and emits it: to the results
// browser, where it is the full report under t, when browses says to and r
// can be browsed, and otherwise to stdout or to a generated file. The default
// arm is the reason this dispatch exists once rather than per command: a
// format added to report.formats and not handled here fails loudly instead of
// silently falling back to text.
func (f *Flags) Deliver(r Report, mask selection.CheckMask) error {
	payload, err := f.Payload(r)
	if err != nil {
		return err
	}

	if b, ok := r.(Browsable); ok && f.browses() {
		if err := tui.Browse(b.Browse(string(payload))); err != nil {
			return fmt.Errorf("results browser: %w", err)
		}
		return nil
	}
	return f.emit(payload, mask)
}

// Payload is r encoded at the resolved format: what Deliver prints, writes,
// or gives the results browser as the full report under t, and what a report
// the browser replaces is rendered as, so the two cannot differ in format.
func (f *Flags) Payload(r Report) ([]byte, error) {
	switch f.format {
	case FormatJSON, FormatYAML:
		return Encode(r.View(), f.format)
	case FormatText:
		var buf bytes.Buffer
		if err := r.WriteText(&buf); err != nil {
			return nil, fmt.Errorf("failed to render text output: %w", err)
		}
		return buf.Bytes(), nil
	}
	return nil, fmt.Errorf("unsupported output format: %s", f.format)
}

// emit writes payload to the resolved destination: a file under --report-file
// named from mask, or stdout. The payload is newline-terminated first, so a
// report file ends in a newline and a shell prompt returns to column zero
// whichever encoder produced it.
func (f *Flags) emit(payload []byte, mask selection.CheckMask) error {
	if len(payload) == 0 || payload[len(payload)-1] != '\n' {
		payload = append(payload, '\n')
	}

	if f.reportFile == "" {
		fmt.Print(string(payload))
		return nil
	}

	path := report.DefaultPath(f.reportFile, report.ResolveHostname(), selection.Codes(mask), f.format.Extension())
	opts := report.Options{AllowElevatedWrite: f.allowElevatedWrite}
	if err := report.Write(path, payload, opts); err != nil {
		if errors.Is(err, report.ErrElevatedWriteDenied) || errors.Is(err, report.ErrElevatedExposedDir) {
			return fmt.Errorf("%w; pass --allow-elevated-write to permit it", err)
		}
		return fmt.Errorf("failed to write report file: %w", err)
	}

	// Confirm the written path; this is the only stdout output when
	// --report-file is set.
	fmt.Printf("[+] Report saved to: %s\n", path)
	return nil
}

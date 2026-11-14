// cmd/commands/delivery/delivery.go

// Package delivery owns the output destination surface shared by the owatch
// commands that produce a report: the --output, --report-file and
// --allow-elevated-write flags, the rule that resolves the effective encoding,
// the encoding of a command's result at that format, and its emission to
// stdout or to a generated file.
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

	"github.com/papa0four/orkowatch/internal/report"
	"github.com/papa0four/orkowatch/internal/selection"
)

type (
	// Report is a command's finished result. View supplies the value for
	// structured encoding; WriteText renders the same result as text.
	// Commands implement it so format dispatch lives in Deliver alone.
	Report interface {
		View() any
		WriteText(w io.Writer) error
	}

	// Flags holds one invocation's output destination state. Cobra binds the flags
	// directly into these fields, so the values Deliver reads are the values that
	// invocation parsed.
	Flags struct {
		outputFormat       string
		reportFile         string
		allowElevatedWrite bool

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
		fmt.Sprintf("Output format (%s)", FormatNames()))
	cmd.Flags().StringVar(&f.reportFile, "report-file", "",
		"Save the report to the specified directory; filename is generated automatically")
	cmd.Flags().BoolVar(&f.allowElevatedWrite, "allow-elevated-write", false,
		"Permit an elevated write outside the allowlisted directories or into a directory other users control")

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

// Deliver encodes r at the resolved format and emits it. The default arm is
// the reason this dispatch exists once rather than per command: a format added
// to report.formats and not handled here fails loudly instead of silently
// falling back to text.
func (f *Flags) Deliver(r Report, mask selection.CheckMask) error {
	var buf bytes.Buffer
	switch f.format {
	case FormatJSON:
		enc := json.NewEncoder(&buf)
		enc.SetIndent("", "  ")
		if err := enc.Encode(r.View()); err != nil {
			return fmt.Errorf("failed to encode JSON: %w", err)
		}
	case FormatYAML:
		if err := yaml.NewEncoder(&buf).Encode(r.View()); err != nil {
			return fmt.Errorf("failed to encode YAML: %w", err)
		}
	case FormatText:
		if err := r.WriteText(&buf); err != nil {
			return fmt.Errorf("failed to render text output: %w", err)
		}
	default:
		return fmt.Errorf("unsupported output format: %s", f.format)
	}

	return f.emit(buf.Bytes(), mask)
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

// cmd/commands/delivery/format.go

package delivery

import "strings"

// Format identifies an output encoding. ParseFormat is the only constructor
// from operator input, so a Format reaching Deliver names one of the
// canonical set. It lives here because choosing an encoding is a decision
// about delivery, to stdout as much as to a file.
type Format string

const (
	// FormatText is the default human-readable encoding.
	FormatText Format = "text"
	// FormatJSON is the structured encoding, and the implied format when a
	// report file is written without an explicit --output.
	FormatJSON Format = "json"
	// FormatYAML is the alternate structured encoding.
	FormatYAML Format = "yaml"
)

// formats is the canonical ordered format set paired with its filename
// extension and whether it is lossless, that is whether it holds the whole
// report: the modules, system block, software, and every check including those
// with no findings. ParseFormat, FormatNames, Extension, Lossless and the
// lossless listings all derive from it, so the set is enumerated once. The
// first entry supplies the fallback extension for an unrecognized Format.
var formats = []struct {
	name     Format
	ext      string
	lossless bool
}{
	{FormatText, "txt", false},
	{FormatJSON, "json", true},
	{FormatYAML, "yaml", true},
}

// ParseFormat resolves s to a canonical Format, reporting whether it names a
// supported encoding
func ParseFormat(s string) (Format, bool) {
	for _, spec := range formats {
		if string(spec.name) == s {
			return spec.name, true
		}
	}
	return "", false
}

// FormatNames returns the canonical format names in declaration order for
// operator-facing messages.
func FormatNames() string {
	names := make([]string, 0, len(formats))
	for _, spec := range formats {
		names = append(names, string(spec.name))
	}
	return strings.Join(names, ", ")
}

// Extension returns f's filename extension without a leading dot
func (f Format) Extension() string {
	for _, spec := range formats {
		if spec.name == f {
			return spec.ext
		}
	}
	return formats[0].ext
}

// Lossless reports whether f holds the whole report, so a saved report in it
// can be reopened exactly. Text is a rendering of a report, and a flat export
// such as CSV holds one row per finding; neither can hold what has no finding.
func (f Format) Lossless() bool {
	for _, spec := range formats {
		if spec.name == f {
			return spec.lossless
		}
	}
	return false
}

// LosslessFormats returns the lossless formats in declaration order.
func LosslessFormats() []Format {
	var out []Format
	for _, spec := range formats {
		if spec.lossless {
			out = append(out, spec.name)
		}
	}
	return out
}

// LosslessNames returns the lossless format names in declaration order for
// operator-facing messages.
func LosslessNames() string {
	names := make([]string, 0, len(formats))
	for _, f := range LosslessFormats() {
		names = append(names, string(f))
	}
	return strings.Join(names, ", ")
}

// FormatForExtension returns the format a filename extension, without its
// leading dot, was written in, so a report is read back by the same table
// that named it.
func FormatForExtension(ext string) (Format, bool) {
	for _, spec := range formats {
		if strings.EqualFold(spec.ext, ext) {
			return spec.name, true
		}
	}
	return "", false
}

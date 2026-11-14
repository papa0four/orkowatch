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
// extension. ParseFormat, FormatNames, and Extension all derive from it, so
// the set is enumerated once. The first entry supplies the fallback extension
// for an unrecognized Format.
var formats = []struct {
	name Format
	ext  string
}{
	{FormatText, "txt"},
	{FormatJSON, "json"},
	{FormatYAML, "yaml"},
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

// internal/report/write.go

package report

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type (
	// Format identifies an output encoding. ParseFormat is the only
	// constructor from operator input, so a Format reaching a writer names
	// one of the canonical set.
	Format string

	// Options carries caller decisions that affect write policy.
	Options struct {
		// AllowElevatedWrite is set when --allow-elevated-write is passed
		// and, where a TTY exists, confirmed the prompt.
		AllowElevatedWrite bool
	}
)

const (
	// FormatText is the default human-readable encoding.
	FormatText Format = "text"
	// FormatJSON is the structured encoding, and the implied format when a
	// report file is written without an explicit --output.
	FormatJSON Format = "json"
	// FormatYAML is the alternate structured encoding.
	FormatYAML Format = "yaml"

	// maxOperatorHomes bounds the operator identities a write is judged
	// against: the effective user's and, on Unix under sudo, the invoking
	// user's. Windows has no effective/invoking split, but the same bound
	// covers its cwd-plus-home allowlist roots.
	maxOperatorHomes = 2

	// maxHostnameLen is the longest a single DNS label can be (RFC 1035
	// section 2.3.4), which is the most os.Hostname can return.
	maxHostnameLen = 63
)

// Sentinel errors returned by Write for unsafe destinations.
var (
	ErrParentMissing       = errors.New("destination directory does not exist")
	ErrRefusedLocation     = errors.New("destination is a protected location")
	ErrElevatedWriteDenied = errors.New("elevated write outside allowlisted roots requires explicit confirmation")
	ErrNotRegularFile      = errors.New("destination exists and is not a regular file")
	ErrElevatedExposedDir  = errors.New("elevated write refused: destination directory is writable by other users")

	// formats is the canonical ordered format set paired with its filename
	// extension. ParseFormat, FormatNames, and Extension all derive from it,
	// so the set is enumerated once. The first entry supplies the fallback
	// extension for an unrecognized Format.
	formats = []struct {
		name Format
		ext  string
	}{
		{FormatText, "txt"},
		{FormatJSON, "json"},
		{FormatYAML, "yaml"},
	}

	// hostnameRe matches every character that is not safe in a filename on
	// all supported platforms; ResolveHostname replaces each with a hyphen.
	hostnameRe = regexp.MustCompile(`[^a-zA-Z0-9\-.]`)
)

// Write validates path through the full guard pipeline and writes data to it.
func Write(path string, data []byte, opts Options) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve path: %w", err)
	}

	// Resolve the parent against the real filesystem so a symlinked
	// directory is judged by where it leads
	parent := filepath.Dir(abs)
	realParent, err := canonicalParent(parent)
	if err != nil {
		return err
	}

	info, err := os.Stat(realParent)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("%w: %s", ErrParentMissing, parent)
	}

	target := filepath.Join(realParent, filepath.Base(abs))

	if reason := refusedReason(target); reason != "" {
		return fmt.Errorf("%w: %s", ErrRefusedLocation, reason)
	}

	elevated, err := isElevated()
	if err != nil {
		return fmt.Errorf("determine privilege: %w", err)
	}
	if elevated {
		if err := guardElevatedWrite(target, realParent, opts); err != nil {
			return err
		}
	}

	return openAndWrite(target, data)
}

// guardElevatedWrite applies the refusals that exist only because the process
// is privileged: a root write must not land in a directory other users can
// control, and outside the allowlisted roots it needs the operator's explicit
// confirmation.
func guardElevatedWrite(target, realParent string, opts Options) error {
	exposed, err := parentWritableByOthers(realParent)
	if err != nil {
		return fmt.Errorf("inspect destination directory: %w", err)
	}
	if exposed {
		return fmt.Errorf("%w: %s", ErrElevatedExposedDir, realParent)
	}

	if opts.AllowElevatedWrite {
		return nil
	}
	allowed, err := withinAllowlist(target)
	if err != nil {
		return err
	}
	if !allowed {
		return ErrElevatedWriteDenied
	}
	return nil
}

// ValidateDir confirms path is an existing directory a report can be written
// into. The filename is generated inside it, so the caller supplies only the
// destination directory. Errors describe the condition without naming a flag,
// so the caller supplies its own flag prefix.
func ValidateDir(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("directory is not accessible: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", path)
	}
	return nil
}

// DefaultPath returns the full path for a generated report file inside dir.
// The filename follows the pattern owatch-<hostname>-<codes>-<timestamp>.<ext>
// where codes is the category-prefixed segment string produced by scan.Codes
// (e.g. "m.os-c.fpsu"). Empty code segments are omitted by the caller.
// dir must be an existing directory; the caller is responsible for validating it.
func DefaultPath(dir, hostname, codes string, format Format) string {
	stamp := time.Now().UTC().Format("20060102T150405Z")
	var name string
	if codes != "" {
		name = fmt.Sprintf("owatch-%s-%s-%s.%s", hostname, codes, stamp, format.Extension())
	} else {
		name = fmt.Sprintf("owatch-%s-%s.%s", hostname, stamp, format.Extension())
	}
	return filepath.Join(dir, name)
}

// ResolveHostname returns a filename-safe host identifier using a fallback
// chain: sanitized os.Hostname(), then unknown-<mac> using the first valid
// non-loopback MAC address (hex, no separators), then unknown.
//
// Exempt from the single-reader rule that makes internal/osfingerprint the
// sole source of host identity: report naming must succeed even when
// fingerprinting was skipped or failed, so it cannot depend on fingerprint
// data existing.
func ResolveHostname() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		sanitized := hostnameRe.ReplaceAllString(h, "-")
		if len(sanitized) > maxHostnameLen {
			sanitized = sanitized[:maxHostnameLen]
		}
		if sanitized != "" {
			return sanitized
		}
	}

	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			if len(iface.HardwareAddr) == 0 {
				continue
			}
			mac := strings.ReplaceAll(iface.HardwareAddr.String(), ":", "")
			if mac != "" {
				return "unknown-" + mac
			}
		}
	}

	return "unknown"
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

// pathWithin compares on path boundaries so a sibling is not mistaken for a child
func pathWithin(target, base string) bool {
	if target == base {
		return true
	}
	rel, err := filepath.Rel(base, target)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

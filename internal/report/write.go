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

	"github.com/papa0four/orkowatch/internal/elevation"
	"github.com/papa0four/orkowatch/internal/fspath"
)

type (
	// Options carries caller decisions that affect write policy.
	Options struct {
		// AllowElevatedWrite is set when --allow-elevated-write is passed.
		// The flag is the operator's whole confirmation; nothing prompts, so
		// an unattended run behaves the same as an interactive one.
		AllowElevatedWrite bool
	}
)

const (
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
	ErrElevatedExposedDir  = errors.New("elevated write refused: destination directory is exposed to other users")

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
	realParent, err := fspath.Real(parent)
	switch {
	case errors.Is(err, fspath.ErrDevicePath):
		return fmt.Errorf("%w: %w", ErrRefusedLocation, err)
	case errors.Is(err, fspath.ErrMissing):
		return fmt.Errorf("%w: %s", ErrParentMissing, parent)
	case err != nil:
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

	if elevation.Elevated() {
		if err := guardElevatedWrite(target, realParent, opts); err != nil {
			return err
		}
	}

	return openAndWrite(target, data)
}

// guardElevatedWrite applies the refusals that exist only because the process
// is privileged: a root write must not land in a directory other users can
// control, nor outside the allowlisted roots. Both are the operator's to
// override, because a guard with no way to say yes makes a deliberately
// shared destination impossible; the refusal names what failed so that the
// override is an informed one.
func guardElevatedWrite(target, realParent string, opts Options) error {
	if opts.AllowElevatedWrite {
		return nil
	}

	reason, err := elevation.Exposure(realParent)
	if err != nil {
		return fmt.Errorf("inspect destination directory: %w", err)
	}
	if reason != "" {
		return fmt.Errorf("%w: %s is %s", ErrElevatedExposedDir, realParent, reason)
	}

	if !withinAllowlist(target) {
		return ErrElevatedWriteDenied
	}
	return nil
}

// withinAllowlist permits an elevated write only under roots the operator
// clearly owns, so a privileged run cannot silently write elsewhere. A root
// that cannot be resolved admits nothing.
func withinAllowlist(target string) bool {
	for _, root := range allowlistRoots() {
		real, err := fspath.Real(root)
		if err != nil {
			continue
		}
		if fspath.Within(target, real) {
			return true
		}
	}
	return false
}

// allowlistRoots are the working directory and the operator's home: on Unix
// that of the user behind sudo, on Windows the profile of the account running
// the process.
func allowlistRoots() []string {
	roots := make([]string, 0, maxOperatorHomes)
	if cwd, err := os.Getwd(); err == nil {
		roots = append(roots, cwd)
	}
	if invoker, ok := elevation.InvokingOperator(); ok {
		roots = append(roots, invoker.Home)
	}
	return roots
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
// where codes is the category-prefixed segment string produced by selection.Codes
// (e.g. "m.os-c.fpsu"). Empty code segments are omitted by the caller. ext
// is the filename extension without a leading dot, which the caller derives
// from the encoding it chose. dir must be an existing directory; the caller
// is responsible for validating it.
func DefaultPath(dir, hostname, codes, ext string) string {
	stamp := time.Now().UTC().Format("20060102T150405Z")
	var name string
	if codes != "" {
		name = fmt.Sprintf("owatch-%s-%s-%s.%s", hostname, codes, stamp, ext)
	} else {
		name = fmt.Sprintf("owatch-%s-%s.%s", hostname, stamp, ext)
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

// internal/osfingerprint/osfingerprint.go

// Package osfingerprint reports host operating system identity: OS, platform,
// version, kernel, hostname, architecture, and platform-specific details. It
// owns both the serializable projection of that data and its text rendering,
// so structured and text output cannot drift apart.
package osfingerprint

import (
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"

	"github.com/shirou/gopsutil/host"
)

// targetParts is the number of parts a target holds: an operating system, a
// platform, and a platform version.
const targetParts = 3

// supportedOS are the operating systems a target can name, as OS holds them.
var supportedOS = []string{"darwin", "freebsd", "linux", "netbsd", "openbsd", "windows"}

type (
	// OSInfo holds operating system fingerprint details retrieved from the host.
	OSInfo struct {
		OS              string
		Platform        string
		PlatformVersion string
		KernelVersion   string
		Hostname        string
		Architecture    string
		AdditionalInfo  map[string]string // store any additional OS-Specific details
	}

	// SystemView is the serializable projection of an OSInfo with duplicate
	// host-identity fields collapsed, so JSON and YAML output carries exactly the
	// information WriteText renders as text. Platform is omitted when it equals OS,
	// KernelVersion when it equals PlatformVersion; PlatformVersion is the
	// always-present version anchor. This is the single structured shape for the
	// system block across every command, so audit and all serialize host identity
	// identically rather than each maintaining its own struct. Target is the
	// host named as another host's owatch data refresh --for takes it, with the
	// platform as the host reports it, so it carries Platform even where the
	// Platform field is omitted.
	SystemView struct {
		OS              string            `json:"os" yaml:"os"`
		Hostname        string            `json:"hostname" yaml:"hostname"`
		Platform        string            `json:"platform,omitempty" yaml:"platform,omitempty"`
		PlatformVersion string            `json:"platform_version" yaml:"platform_version"`
		KernelVersion   string            `json:"kernel_version,omitempty" yaml:"kernel_version,omitempty"`
		Architecture    string            `json:"architecture" yaml:"architecture"`
		Target          string            `json:"target,omitempty" yaml:"target,omitempty"`
		AdditionalInfo  map[string]string `json:"additional_info,omitempty" yaml:"additional_info,omitempty"`
	}
)

// DistinctPlatform returns Platform when it differs from OS, and the empty
// string when they are equal. A caller renders the Platform line only when
// this returns non-empty. OS is the anchor because it is the more general,
// always-meaningful identifier; Platform is the refinement worth showing only
// when it adds information. On darwin the two are identical, so Platform is
// omitted.
func (o *OSInfo) DistinctPlatform() string {
	if o.Platform == o.OS {
		return ""
	}
	return o.Platform
}

// DistinctKernelVersion returns KernelVersion when it differs from
// PlatformVersion, and the empty string when they are equal. A caller renders
// the platform version unconditionally and renders a kernel line only when
// this returns non-empty. PlatformVersion is the anchor: on Windows it and
// KernelVersion are the same build string, and "version" describes that string
// more truthfully than "kernel version," which carries a distinct meaning only
// on Linux where the kernel is versioned separately from the platform. On
// those systems the two differ and both lines appear.
func (o *OSInfo) DistinctKernelVersion() string {
	if o.KernelVersion == o.PlatformVersion {
		return ""
	}
	return o.KernelVersion
}

// Target returns o named as os/platform/version, with trailing empty parts
// dropped, so that ParseTarget on another host reads back the fields a
// dataset decides by as this host reports them. It returns the empty string
// when o cannot be named that way: an operating system a target cannot name,
// or a part that holds a slash.
func (o *OSInfo) Target() string {
	parts := []string{o.OS, o.Platform, o.PlatformVersion}
	if !slices.Contains(supportedOS, o.OS) || slices.ContainsFunc(parts, func(p string) bool { return strings.Contains(p, "/") }) {
		return ""
	}
	for parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	return strings.Join(parts, "/")
}

// ParseTarget reads a target as Target writes it: os, os/platform, or
// os/platform/version. The operating system is read in any case. The platform
// and version are kept as given, since a dataset compares them with what the
// named host reports.
func ParseTarget(value string) (*OSInfo, error) {
	parts := strings.Split(value, "/")
	parts[0] = strings.ToLower(parts[0])
	if len(parts) > targetParts || !slices.Contains(supportedOS, parts[0]) {
		return nil, fmt.Errorf("%q does not name a host: give it as owatch osinfo prints Target there, os/platform/version, where os is one of %s",
			value, strings.Join(supportedOS, ", "))
	}
	parts = append(parts, make([]string, targetParts-len(parts))...)
	return &OSInfo{OS: parts[0], Platform: parts[1], PlatformVersion: parts[2]}, nil
}

// GetOSFingerprint reads the running host's identity. What gopsutil cannot
// read exactly is read by platformDetails, which each build of owatch
// defines for the systems it runs on.
func GetOSFingerprint() (*OSInfo, error) {
	info, err := host.Info()
	if err != nil {
		return nil, err
	}

	osInfo := &OSInfo{
		OS:              info.OS,
		Platform:        info.Platform,
		PlatformVersion: info.PlatformVersion,
		KernelVersion:   info.KernelVersion,
		Hostname:        info.Hostname,
		AdditionalInfo:  make(map[string]string),
	}
	if err := platformDetails(osInfo, info); err != nil {
		return nil, err
	}
	return osInfo, nil
}

// WriteText writes o's fields to w as WriteViewText renders its projection.
func WriteText(w io.Writer, o *OSInfo) error {
	if o == nil {
		return fmt.Errorf("osfingerprint: cannot render nil OSInfo")
	}
	return WriteViewText(w, o.View())
}

// WriteViewText writes v's fields to w as labeled lines in fixed order. The
// Platform and Kernel lines are omitted when the view omits them, which
// View does where they duplicate OS and the platform version; see
// DistinctPlatform and DistinctKernelVersion, which own that rule so every
// renderer inherits it identically. AdditionalInfo keys are sorted before
// writing so output is deterministic -- Go map iteration order is randomized
// and would otherwise produce nondeterministic diffs in reports and tests.
// It renders from the projection a saved report carries, so a live run and a
// saved report show the same text.
func WriteViewText(w io.Writer, v SystemView) error {
	if err := writeLine(w, "OS", v.OS); err != nil {
		return err
	}
	if err := writeLine(w, "Hostname", v.Hostname); err != nil {
		return err
	}
	if v.Platform != "" {
		if err := writeLine(w, "Platform", v.Platform); err != nil {
			return err
		}
	}
	if err := writeLine(w, "Version", v.PlatformVersion); err != nil {
		return err
	}
	if v.KernelVersion != "" {
		if err := writeLine(w, "Kernel", v.KernelVersion); err != nil {
			return err
		}
	}
	if err := writeLine(w, "Architecture", v.Architecture); err != nil {
		return err
	}
	if v.Target != "" {
		if err := writeLine(w, "Target", v.Target); err != nil {
			return err
		}
	}

	keys := make([]string, 0, len(v.AdditionalInfo))
	for key := range v.AdditionalInfo {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		if err := writeLine(w, key, v.AdditionalInfo[key]); err != nil {
			return err
		}
	}
	return nil
}

// View returns o's serializable projection with the duplicate fields collapsed
// through DistinctPlatform and DistinctKernelVersion, the same rule WriteText
// renders, so a caller's structured output cannot drift from its text output.
// The omitempty tags on Platform and KernelVersion turn the methods' empty
// return into an omitted field, matching WriteText skipping those lines.
func (o *OSInfo) View() SystemView {
	return SystemView{
		OS:              o.OS,
		Hostname:        o.Hostname,
		Platform:        o.DistinctPlatform(),
		PlatformVersion: o.PlatformVersion,
		KernelVersion:   o.DistinctKernelVersion(),
		Architecture:    o.Architecture,
		Target:          o.Target(),
		AdditionalInfo:  o.AdditionalInfo,
	}
}

// writeLine writes a single "label: value\n" line to w, wrapping any write
// error with package context. It is the one path through which WriteText emits
// labeled lines, so field omission is expressed by the caller skipping the
// call rather than by branching inside a format string.
func writeLine(w io.Writer, label, value string) error {
	if _, err := fmt.Fprintf(w, "%s: %s\n", label, value); err != nil {
		return fmt.Errorf("osfingerprint: write failed: %w", err)
	}
	return nil
}

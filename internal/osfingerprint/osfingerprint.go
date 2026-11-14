// internal/osfingerprint/osfingerprint.go

// Package osfingerprint reports host operating system identity: OS, platform,
// version, kernel, hostname, architecture, and platform-specific details. It
// owns both the serializable projection of that data and its text rendering,
// so structured and text output cannot drift apart.
package osfingerprint

import (
	"fmt"
	"io"
	"runtime"
	"sort"

	"github.com/shirou/gopsutil/host"
)

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
	// identically rather than each maintaining its own struct.
	SystemView struct {
		OS              string            `json:"os" yaml:"os"`
		Hostname        string            `json:"hostname" yaml:"hostname"`
		Platform        string            `json:"platform,omitempty" yaml:"platform,omitempty"`
		PlatformVersion string            `json:"platform_version" yaml:"platform_version"`
		KernelVersion   string            `json:"kernel_version,omitempty" yaml:"kernel_version,omitempty"`
		Architecture    string            `json:"architecture" yaml:"architecture"`
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

// GetOSFingerprint retrieves OS-Specific fingerprinting information
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
		Architecture:    runtime.GOARCH,
		AdditionalInfo:  make(map[string]string),
	}

	// Check the platform (Windows, Unix, MacOS, etc.)
	switch runtime.GOOS {
	case "windows":
		osInfo.AdditionalInfo["ProductName"] = "Windows"
		osInfo.AdditionalInfo["EditionID"] = info.PlatformFamily // Windows-specific details
	case "darwin":
		osInfo.AdditionalInfo["ProductName"] = "MacOS"
		osInfo.AdditionalInfo["HardwareModel"] = runtime.GOARCH // Specific to MacOS
	case "linux":
		osInfo.AdditionalInfo["DistroFamily"] = info.PlatformFamily // Linux/Unix distribution
	case "freebsd":
		osInfo.AdditionalInfo["ProductName"] = "FreeBSD"
	default:
		osInfo.AdditionalInfo["ProductName"] = "Unknown"
	}

	return osInfo, nil
}

// WriteText writes o's fields to w as labeled lines in fixed order. The
// Platform and Kernel lines are omitted when they duplicate OS and the
// platform version respectively; see DistinctPlatform and
// DistinctKernelVersion, which own that rule so every OSInfo renderer inherits
// it identically. AdditionalInfo keys are sorted before writing so output is
// deterministic -- Go map iteration order is randomized and would otherwise
// produce nondeterministic diffs in reports and tests.
func WriteText(w io.Writer, o *OSInfo) error {
	if o == nil {
		return fmt.Errorf("osfingerprint: cannot render nil OSInfo")
	}

	if err := writeLine(w, "OS", o.OS); err != nil {
		return err
	}
	if err := writeLine(w, "Hostname", o.Hostname); err != nil {
		return err
	}
	if platform := o.DistinctPlatform(); platform != "" {
		if err := writeLine(w, "Platform", platform); err != nil {
			return err
		}
	}
	if err := writeLine(w, "Version", o.PlatformVersion); err != nil {
		return err
	}
	if kernel := o.DistinctKernelVersion(); kernel != "" {
		if err := writeLine(w, "Kernel", kernel); err != nil {
			return err
		}
	}
	if err := writeLine(w, "Architecture", o.Architecture); err != nil {
		return err
	}

	keys := make([]string, 0, len(o.AdditionalInfo))
	for key := range o.AdditionalInfo {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		if err := writeLine(w, key, o.AdditionalInfo[key]); err != nil {
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

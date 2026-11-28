//go:build !windows

// internal/osfingerprint/osfingerprint_other.go

package osfingerprint

import (
	"runtime"

	"github.com/shirou/gopsutil/host"
)

// platformDetails adds what each system's identity holds beyond gopsutil's
// fields.
func platformDetails(o *OSInfo, info *host.InfoStat) error {
	switch runtime.GOOS {
	case "darwin":
		o.AdditionalInfo["ProductName"] = "MacOS"
	case "linux":
		o.AdditionalInfo["DistroFamily"] = info.PlatformFamily
	case "freebsd":
		o.AdditionalInfo["ProductName"] = "FreeBSD"
	default:
		o.AdditionalInfo["ProductName"] = "Unknown"
	}
	return nil
}

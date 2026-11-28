// internal/osfingerprint/osfingerprint_test.go

package osfingerprint

import (
	"strings"
	"testing"
)

// A host's target names it so that ParseTarget on another host reads back the
// operating system, platform, version, and architecture exactly as the host
// reports them, in the shapes each system reports them in.
func TestTargetReadsBack(t *testing.T) {
	for want, host := range map[string]OSInfo{
		"linux/ubuntu/22.04":       {OS: "linux", Platform: "ubuntu", PlatformVersion: "22.04"},
		"linux/ubuntu/22.04/arm64": {OS: "linux", Platform: "ubuntu", PlatformVersion: "22.04", Architecture: "arm64"},
		"windows/Microsoft Windows 11 Home/10.0.26300.10075/amd64": {OS: "windows", Platform: "Microsoft Windows 11 Home", PlatformVersion: "10.0.26300.10075", Architecture: "amd64"},
		"windows/Microsoft Windows 11 Home/10.0.26300 Build 26300": {OS: "windows", Platform: "Microsoft Windows 11 Home", PlatformVersion: "10.0.26300 Build 26300"},
		"freebsd/freebsd/14.1-release/386":                         {OS: "freebsd", Platform: "freebsd", PlatformVersion: "14.1-release", Architecture: "386"},
		"darwin/darwin/14.5":                                       {OS: "darwin", Platform: "darwin", PlatformVersion: "14.5"},
		"linux/alpine":                                             {OS: "linux", Platform: "alpine"},
		"linux":                                                    {OS: "linux"},
		"linux//6.1":                                               {OS: "linux", PlatformVersion: "6.1"},
		"linux/ubuntu//amd64":                                      {OS: "linux", Platform: "ubuntu", Architecture: "amd64"},
	} {
		got := host.Target()
		if got != want {
			t.Errorf("Target of %+v = %q, want %q", host, got, want)
			continue
		}
		back, err := ParseTarget(got)
		if err != nil || back.OS != host.OS || back.Platform != host.Platform || back.PlatformVersion != host.PlatformVersion ||
			back.Architecture != host.Architecture {
			t.Errorf("ParseTarget(%q) = %+v, %v, want %+v", got, back, err, host)
		}
	}
}

// A host that cannot be named as a target has none, rather than one that
// reads back as another host.
func TestTargetRefusesWhatCannotReadBack(t *testing.T) {
	for _, host := range []OSInfo{
		{OS: "plan9", Platform: "plan9", PlatformVersion: "4"},
		{OS: "", Platform: "ubuntu"},
		{OS: "linux", Platform: "a/b", PlatformVersion: "1"},
		{OS: "linux", Platform: "ubuntu", PlatformVersion: "22.04/1"},
		{OS: "linux", Platform: "ubuntu", PlatformVersion: "22.04", Architecture: "sparc64"},
	} {
		if got := host.Target(); got != "" {
			t.Errorf("Target of %+v = %q, want none", host, got)
		}
	}
}

// The operating system and architecture are read in any case; the platform
// and version are kept as given; what names no host is refused.
func TestParseTarget(t *testing.T) {
	got, err := ParseTarget("Windows/Microsoft Windows 11 Home")
	if err != nil || got.OS != "windows" || got.Platform != "Microsoft Windows 11 Home" || got.PlatformVersion != "" || got.Architecture != "" {
		t.Errorf("ParseTarget gave %+v, %v", got, err)
	}
	got, err = ParseTarget("windows/Microsoft Windows 11 Home/10.0.26300.10075/AMD64")
	if err != nil || got.PlatformVersion != "10.0.26300.10075" || got.Architecture != "amd64" {
		t.Errorf("ParseTarget gave %+v, %v", got, err)
	}
	for _, value := range []string{"", "plan9", "/ubuntu", "linux/ubuntu/22.04/1", "linux/ubuntu/22.04/sparc", "linux/ubuntu/22.04/amd64/1"} {
		if got, err := ParseTarget(value); err == nil {
			t.Errorf("ParseTarget(%q) = %+v, want a refusal", value, got)
		}
	}
}

// The text and the projection carry the target, and leave it out when the
// host has none.
func TestTargetIsRendered(t *testing.T) {
	var b strings.Builder
	host := &OSInfo{OS: "linux", Platform: "ubuntu", PlatformVersion: "22.04"}
	if err := WriteText(&b, host); err != nil || !strings.Contains(b.String(), "\nTarget: linux/ubuntu/22.04\n") {
		t.Errorf("WriteText wrote %q, %v", b.String(), err)
	}
	b.Reset()
	if err := WriteText(&b, &OSInfo{OS: "plan9"}); err != nil || strings.Contains(b.String(), "Target") {
		t.Errorf("WriteText of a host with no target wrote %q, %v", b.String(), err)
	}
}

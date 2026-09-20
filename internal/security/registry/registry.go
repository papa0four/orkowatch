// internal/security/registry/registry.go

// Package registry holds the finding definitions that checkers emit, indexed
// by platform and, on Linux and BSD hosts, by distribution family. Definitions
// are authored as YAML and embedded at build time, so a finding's title,
// severity, description, impact, resolution, and references live in one data
// file rather than spread through checker code.
package registry

import (
	"bufio"
	_ "embed"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/papa0four/orkowatch/internal/security/types"
)

type (
	// platformRegistry holds all indexed definitions
	platformRegistry map[Platform]map[FindingKey]FindingDefinition

	// familyRegistry holds finding definitions indexed by distro family,
	// used for platforms whose findings vary by family (Linux, Unix/BSD)
	familyRegistry map[Distro]map[FindingKey]FindingDefinition

	// Platform identifies the host OS family
	Platform string

	// Distro identifies a Unix or Linux distribution family. It is unused on
	// Windows and macOS, whose findings are indexed by platform alone.
	Distro string

	// FindingKey formatted <checker>.<finding_id> to join checker detection logic and registry data
	FindingKey string

	// OSContext obtains full platform and distro info to pass to auditor before registry lookups
	OSContext struct {
		Platform Platform
		Families []Distro
	}

	// FindingDefinition is the authored form of a finding: everything the
	// registry knows about a condition, independent of the host it is found
	// on. Title, Severity, Description, Impact, Resolution and References
	// are projected into types.Finding at emission. CVSSScore, CVSSVector
	// and CWE are not, and have no reader yet: they are the static baseline
	// the enrichment adapters in #89 through #93 consume, where CVSS becomes
	// the value a live score overrides through types.EffectiveSeverity, and
	// CWE becomes the structured lookup key that types.CWEReferences
	// currently recovers by parsing the reference list.
	FindingDefinition struct {
		Title       string   `yaml:"title"`
		Severity    string   `yaml:"severity"`
		CVSSScore   float64  `yaml:"cvss_score"`
		CVSSVector  string   `yaml:"cvss_vector"`
		CWE         string   `yaml:"cwe"`
		Description string   `yaml:"description"`
		Impact      string   `yaml:"impact"`
		Resolution  string   `yaml:"resolution"`
		References  []string `yaml:"references"`
	}
)

// Platform constants
const (
	PlatformWindows Platform = "windows"
	PlatformLinux   Platform = "linux"
	PlatformDarwin  Platform = "darwin"
	PlatformUnix    Platform = "unix"
	PlatformUnknown Platform = "unknown"

	// Distro family constants where derivatives resolve to parent family
	// Linux Families
	DistroDebian  Distro = "debian"
	DistroRHEL    Distro = "rhel"
	DistroFedora  Distro = "fedora"
	DistroArch    Distro = "arch"
	DistroSUSE    Distro = "suse"
	DistroAlpine  Distro = "alpine"
	DistroGeneric Distro = "generic"

	// Unix Families
	DistroFreeBSD Distro = "freebsd"
	DistroOpenBSD Distro = "openbsd"
	DistroNetBSD  Distro = "netbsd"

	// DistroUnknown is the resolution of an os-release identifier no family
	// claims.
	DistroUnknown Distro = "unknown"

	// Reference type classifications produced by ToReferences.
	RefTypeCVE   = "CVE"
	RefTypeCWE   = "CWE"
	RefTypeCIS   = "CIS"
	RefTypeNIST  = "NIST"
	RefTypeMITRE = "MITRE"
	RefTypeURL   = "URL"
	RefTypeOther = "OTHER"
)

var (
	//go:embed data/windows.yaml
	windowsData []byte

	//go:embed data/linux_common.yaml
	linuxCommonData []byte

	//go:embed data/linux_debian.yaml
	linuxDebianData []byte

	//go:embed data/linux_rhel.yaml
	linuxRHELData []byte

	//go:embed data/linux_arch.yaml
	linuxArchData []byte

	//go:embed data/linux_fedora.yaml
	linuxFedoraData []byte

	//go:embed data/linux_suse.yaml
	linuxSUSEData []byte

	//go:embed data/linux_alpine.yaml
	linuxAlpineData []byte

	//go:embed data/darwin.yaml
	darwinData []byte

	//go:embed data/unix_freebsd.yaml
	unixFreeBSDData []byte

	//go:embed data/unix_openbsd.yaml
	unixOpenBSDData []byte

	// nistFamilyPattern matches a NIST SP 800-53 Rev 5 control-family citation
	// and captures the two-letter family code. Enhancement suffixes such as
	// "(1)" and the trailing parenthetical control name are not part of the
	// capture and are not required to be present.
	nistFamilyPattern = regexp.MustCompile(`^NIST SP 800-53 Rev 5 ([A-Z]{2})-\d+`)

	// registry, linuxRegistry, and unixRegistry are the finding indexes built
	// from the embedded definition files. Lookup consults them in that order
	// of specificity; see loadRegistries for which file feeds which index.
	registry, linuxRegistry, unixRegistry = loadRegistries()
)

// Lookup retrieves a FindingDefinition for the given OSContenxt and key.
func Lookup(ctx OSContext, key FindingKey) (FindingDefinition, bool) {
	for _, defs := range definitionsFor(ctx) {
		if def, ok := defs[key]; ok {
			return def, true
		}
	}
	return FindingDefinition{}, false
}

// HasDefinitions reports whether any finding definitions are registered for
// ctx. A context with none makes every Lookup miss, so checkers would detect
// conditions and emit nothing, reporting clean because the registry is empty
// rather than because the host is. Callers must treat false as fatal.
func HasDefinitions(ctx OSContext) bool {
	for _, defs := range definitionsFor(ctx) {
		if len(defs) > 0 {
			return true
		}
	}
	return false
}

// definitionsFor returns the definition sets that apply to ctx, most specific
// first. Linux ends with the common set; other platforms have no fallback.
func definitionsFor(ctx OSContext) []map[FindingKey]FindingDefinition {
	var sets []map[FindingKey]FindingDefinition
	switch ctx.Platform {
	case PlatformLinux:
		for _, family := range ctx.Families {
			if fm, ok := linuxRegistry[family]; ok {
				sets = append(sets, fm)
			}
		}
		if fm, ok := linuxRegistry[DistroGeneric]; ok {
			sets = append(sets, fm)
		}
	case PlatformUnix:
		for _, family := range ctx.Families {
			if fm, ok := unixRegistry[family]; ok {
				sets = append(sets, fm)
			}
		}
	default:
		if pm, ok := registry[ctx.Platform]; ok {
			sets = append(sets, pm)
		}
	}
	return sets
}

// DetectOS identifies the current platform and, for Linux, resolves
// the full distribution family chain from /etc/os-release.
//
// Deliberately independent of internal/osfingerprint: this resolves which
// registry YAML files apply to the host (family-chain precision from
// ID/ID_LIKE), not host identity for reporting, and wiring it to
// osfingerprint would violate the pinned import direction (registry
// imports types only).
func DetectOS() OSContext {
	switch platform := detectPlatform(); platform {
	case PlatformLinux:
		return OSContext{
			Platform: PlatformLinux,
			Families: detectLinuxFamilies(),
		}
	case PlatformUnix:
		return OSContext{
			Platform: PlatformUnix,
			Families: []Distro{resolveDistro(runtime.GOOS)},
		}
	default:
		return OSContext{Platform: platform}
	}
}

// DisplayLabel returns the human-readable platform label used in check
// display names: the platform class for Windows, macOS, and Linux, and the
// specific BSD variant for Unix platforms
func (c OSContext) DisplayLabel() string {
	switch c.Platform {
	case PlatformWindows:
		return "Windows"
	case PlatformDarwin:
		return "macOS"
	case PlatformLinux:
		return "Linux"
	case PlatformUnix:
		if len(c.Families) > 0 {
			switch c.Families[0] {
			case DistroFreeBSD:
				return "FreeBSD"
			case DistroOpenBSD:
				return "OpenBSD"
			case DistroNetBSD:
				return "NetBSD"
			}
		}
		return "Unix"
	default:
		return "Host"
	}
}

// ToReferences classifies flat YAML reference strings into
// structured types.Reference entries by kind.
func (d FindingDefinition) ToReferences() []types.Reference {
	if len(d.References) == 0 {
		return nil
	}
	out := make([]types.Reference, 0, len(d.References))
	for _, raw := range d.References {
		out = append(out, classifyReference(raw))
	}
	return out
}

// ToCategories extracts deduplicated NIST SP 800-53 Rev 5 control-family
// codes from d's NIST-classified references, in alphabetical order.
// Every reference has already passed validateCategories at registry load
// time, so a pattern mismatch here indicates the two functions have gone
// out of sync with each other, not a data defect.
func (d FindingDefinition) ToCategories() []string {
	if len(d.References) == 0 {
		return nil
	}
	var out []string
	seen := make(map[string]struct{})
	for _, raw := range d.References {
		ref := classifyReference(raw)
		if ref.Type != RefTypeNIST {
			continue
		}
		match := nistFamilyPattern.FindStringSubmatch(ref.Title)
		if match == nil {
			panic("registry: NIST reference passed validateCategories but failed extraction: " + ref.Title)
		}
		family := match[1]
		if _, dup := seen[family]; dup {
			continue
		}
		seen[family] = struct{}{}
		out = append(out, family)
	}
	sort.Strings(out)
	return out
}

// loadRegistries parses the embedded definition files into the platform and
// family indexes. It panix on malformed YAML, halting startup rather than
// leaving the checker to look up a finding that silently does not exist.
func loadRegistries() (platformRegistry, familyRegistry, familyRegistry) {
	platform := platformRegistry{
		PlatformWindows: mustLoad("windows.yaml", windowsData),
		PlatformDarwin:  mustLoad("darwin.yaml", darwinData),
	}
	linux := familyRegistry{
		DistroGeneric: mustLoad("linux_common.yaml", linuxCommonData),
		DistroDebian:  mustLoad("linux_debian.yaml", linuxDebianData),
		DistroRHEL:    mustLoad("linux_rhel.yaml", linuxRHELData),
		DistroArch:    mustLoad("linux_arch.yaml", linuxArchData),
		DistroFedora:  mustLoad("linux_fedora.yaml", linuxFedoraData),
		DistroSUSE:    mustLoad("linux_suse.yaml", linuxSUSEData),
		DistroAlpine:  mustLoad("linux_alpine.yaml", linuxAlpineData),
	}
	unix := familyRegistry{
		DistroFreeBSD: mustLoad("unix_freebsd.yaml", unixFreeBSDData),
		DistroOpenBSD: mustLoad("unix_openbsd.yaml", unixOpenBSDData),
	}
	return platform, linux, unix
}

// mustLoad parses a byte slice into a finding map. name identifies the
// source YAML file in panic messages: //go:embed yields an unnamed []byte
// per file, so a bare parse or validation failure would give no indication
// which of the eleven embedded definition files is malformed.
func mustLoad(name string, data []byte) map[FindingKey]FindingDefinition {
	var raw map[string]FindingDefinition
	if err := yaml.Unmarshal(data, &raw); err != nil {
		panic("registry: failed to parse embedded YAML " + name + ": " + err.Error())
	}
	out := make(map[FindingKey]FindingDefinition, len(raw))
	for k, v := range raw {
		if err := v.validateCategories(); err != nil {
			panic("registry: " + name + ": finding \"" + k + "\": " + err.Error())
		}
		out[FindingKey(k)] = v
	}
	return out
}

// validateCategories confirms every NIST-classified reference in d resolves
// to a control-family code. Called once per finding at registry load time
// so ToCategories can extract categories at finding-construction sites
// without an error return: a malformed citation is a registry data defect
// and must halt startup, not silently produce a finding with no category
// or a wrong one.
func (d FindingDefinition) validateCategories() error {
	for _, raw := range d.References {
		ref := classifyReference(raw)
		if ref.Type != RefTypeNIST {
			continue
		}
		if !nistFamilyPattern.MatchString(ref.Title) {
			return fmt.Errorf("malformed NIST control-family reference: %q", ref.Title)
		}
	}
	return nil
}

// detectPlatform returns the Platform from runtime.GOOS. Compile-time truth
// cannot misidentify the host the way filesystem probes can (a Linux system
// without /etc/os-release is still Linux); /etc/os-release is consulted only
// for distro family resolution, never for platform identity.
func detectPlatform() Platform {
	switch runtime.GOOS {
	case "linux":
		return PlatformLinux
	case "darwin":
		return PlatformDarwin
	case "windows":
		return PlatformWindows
	case "freebsd", "openbsd", "netbsd":
		return PlatformUnix
	default:
		return PlatformUnknown
	}
}

// detectLinuxFamilies parses /etc/os-release and returns the
// distro family chain ordered from most specific to least specific.
func detectLinuxFamilies() []Distro {
	file, err := os.Open("/etc/os-release")
	if err != nil {
		return []Distro{DistroGeneric}
	}
	defer file.Close() //nolint:errcheck // read-only file; no data at risk

	var id, idLike string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "ID="):
			id = strings.Trim(strings.TrimPrefix(line, "ID="), `"`)
		case strings.HasPrefix(line, "ID_LIKE="):
			idLike = strings.Trim(strings.TrimPrefix(line, "ID_LIKE="), `"`)
		}
	}
	if err := scanner.Err(); err != nil {
		return []Distro{DistroGeneric}
	}

	var families []Distro

	// Resolve the specific ID to a known family
	if f := resolveDistro(id); f != DistroUnknown {
		families = append(families, f)
	}

	// Walk ID_LIKE parent families in declared order
	for _, parent := range strings.Fields(idLike) {
		if f := resolveDistro(parent); f != DistroUnknown {
			// avoid duplicates
			if !containsDistro(families, f) {
				families = append(families, f)
			}
		}
	}

	// Always terminate with generic as the final fallback
	if !containsDistro(families, DistroGeneric) {
		families = append(families, DistroGeneric)
	}

	return families
}

// resolveDistro maps a raw os-release ID or ID_LIKE token to a known Distro family constant.
func resolveDistro(id string) Distro {
	switch strings.ToLower(id) {
	case "debian", "ubuntu", "linuxmint", "pop", "kali", "parrot",
		"elementary", "raspbian", "zorin":
		return DistroDebian
	case "rhel", "centos", "rocky", "almalinux", "ol", "amzn":
		return DistroRHEL
	case "fedora":
		return DistroFedora
	case "arch", "manjaro", "endeavouros", "garuda", "artix":
		return DistroArch
	case "opensuse", "opensuse-leap", "opensuse-tumbleweed", "sles":
		return DistroSUSE
	case "alpine":
		return DistroAlpine
	case "freebsd":
		return DistroFreeBSD
	case "openbsd":
		return DistroOpenBSD
	case "netbsd":
		return DistroNetBSD
	default:
		return DistroUnknown
	}
}

// containsDistro reports whether d is present in families.
func containsDistro(families []Distro, d Distro) bool {
	for _, f := range families {
		if f == d {
			return true
		}
	}
	return false
}

func classifyReference(raw string) types.Reference {
	trimmed := strings.TrimSpace(raw)

	switch {
	case isCWEReference(trimmed):
		return types.Reference{Title: trimmed, URL: cweURL(trimmed), Type: RefTypeCWE}
	case isCVEReference(trimmed):
		return types.Reference{Title: trimmed, URL: cveURL(trimmed), Type: RefTypeCVE}
	case strings.HasPrefix(trimmed, "CIS "):
		return types.Reference{Title: trimmed, Type: RefTypeCIS}
	case strings.HasPrefix(trimmed, "NIST "):
		return types.Reference{Title: trimmed, Type: RefTypeNIST}
	case strings.HasPrefix(trimmed, "MITRE "):
		return types.Reference{Title: trimmed, Type: RefTypeMITRE}
	case strings.HasPrefix(trimmed, "https://") || strings.HasPrefix(trimmed, "http://"):
		return types.Reference{Title: trimmed, URL: trimmed, Type: RefTypeURL}
	default:
		return types.Reference{Title: trimmed, Type: RefTypeOther}
	}
}

func isCWEReference(s string) bool {
	return strings.HasPrefix(s, "CWE-") || strings.HasPrefix(s, "https://cwe.mitre.org/")
}

func isCVEReference(s string) bool {
	return strings.HasPrefix(s, "CVE-") || strings.HasPrefix(s, "https://nvd.nist.gov/vuln/detail/CVE-")
}

func cweURL(s string) string {
	if strings.HasPrefix(s, "https://") {
		return s
	}
	return "https://cwe.mitre.org/data/definitions/" + strings.TrimPrefix(s, "CWE-") + ".html"
}

func cveURL(s string) string {
	if strings.HasPrefix(s, "https://") {
		return s
	}
	return "https://nvd.nist.gov/vuln/detail/" + s
}

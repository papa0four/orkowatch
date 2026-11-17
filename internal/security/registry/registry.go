// internal/security/registry/registry.go

// Package registry holds the finding definitions that checkers emit, indexed
// by platform and, on Linux and BSD hosts, by distribution family. Definitions
// are authored as YAML and embedded at build time, so a finding's title,
// severity, description, impact, resolution, and references live in one data
// file rather than spread through checker code.
package registry

import (
	"bufio"
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"runtime"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	v4 "github.com/papa0four/orkowatch/internal/cvss/v4"
	"github.com/papa0four/orkowatch/internal/security/finding"
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
	// on. Finding projects everything but CVSSScore and CVSSVector, which load
	// validates and #87 shows: the vector gives the score, the score gives the
	// severity, and a definition in which the three disagree does not load.
	// They are the static baseline a live score overrides through
	// finding.EffectiveSeverity.
	//
	// Result is what the condition reports when a checker observes it. It
	// defaults to fail. A definition that describes a state the rule does
	// not apply to declares notapplicable instead, and only a definition
	// that can fail must name the weakness it maps to in CWE.
	FindingDefinition struct {
		Title       string          `yaml:"title"`
		Severity    string          `yaml:"severity"`
		Result      finding.Result  `yaml:"result"`
		CVSSScore   float64         `yaml:"cvss_score"`
		CVSSVector  string          `yaml:"cvss_vector"`
		CWE         finding.CWE     `yaml:"cwe"`
		NoWeakness  string          `yaml:"no_weakness"`
		Description string          `yaml:"description"`
		Impact      string          `yaml:"impact"`
		Resolution  string          `yaml:"resolution"`
		References  []ReferenceSpec `yaml:"references"`

		// AttackTechniques lists the ATT&CK techniques an adversary can use
		// because of the condition, each with what supports the link. Every
		// identifier must be in the bundled dataset in data/attack.yaml.
		AttackTechniques []AttackLink `yaml:"attack_techniques"`

		// Records declares what the condition's evidence carries, and
		// Environment the rules that derive Modified Base metrics from it.
		// A definition with no rules is scored by its baseline alone.
		Records     Records           `yaml:"records"`
		Environment []EnvironmentRule `yaml:"environment"`
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
// imports finding only).
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

// Finding returns the description of d a condition carries.
func (d FindingDefinition) Finding() *finding.Finding {
	return &finding.Finding{
		Title:       d.Title,
		Description: d.Description,
		Severity:    d.Severity,
		CWE:         d.CWE,
		Weakness:    d.weakness(),
		NoWeakness:  strings.TrimSpace(d.NoWeakness),
		CVSS:        d.cvssScore(),
		Categories:  d.ToCategories(),
		Impact:      d.Impact,
		Resolution:  d.Resolution,
		References:  d.ToReferences(),
		Techniques:  d.ToTechniques(),
	}
}

// ToTechniques returns the bundled ATT&CK technique for each link d lists, in
// the order listed, each carrying the basis its link states. Every identifier has already passed
// checkTechniques at registry load time, so a miss here would mean the data
// changed after loading, not that it was wrong.
func (d FindingDefinition) ToTechniques() []finding.Technique {
	if len(d.AttackTechniques) == 0 {
		return nil
	}
	out := make([]finding.Technique, 0, len(d.AttackTechniques))
	for _, link := range d.AttackTechniques {
		technique := techniques[link.ID]
		technique.Basis = slices.Clone(link.Basis)
		out = append(out, technique)
	}
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

	var sets []map[FindingKey]FindingDefinition
	for _, defs := range platform {
		sets = append(sets, defs)
	}
	for _, defs := range linux {
		sets = append(sets, defs)
	}
	for _, defs := range unix {
		sets = append(sets, defs)
	}
	checkTechniqueUse(sets...)
	return platform, linux, unix
}

// mustLoad parses a byte slice into a finding map. name identifies the
// source YAML file in panic messages: //go:embed yields an unnamed []byte
// per file, so a bare parse or validation failure would give no indication
// which of the eleven embedded definition files is malformed. Decoding is
// strict: a key the definition does not declare is a misspelling whose value
// would otherwise be dropped without a word. A file holding no definitions
// yet decodes to an empty set.
func mustLoad(name string, data []byte) map[FindingKey]FindingDefinition {
	var raw map[string]FindingDefinition
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&raw); err != nil && !errors.Is(err, io.EOF) {
		panic("registry: failed to parse embedded YAML " + name + ": " + err.Error())
	}
	out := make(map[FindingKey]FindingDefinition, len(raw))
	for k, v := range raw {
		def, err := v.validated()
		if err != nil {
			panic("registry: " + name + ": finding \"" + k + "\": " + err.Error())
		}
		out[FindingKey(k)] = def
	}
	return out
}

// validated returns d with its defaults applied, or the reason it cannot be
// used. A definition that can report fail names a weakness in the bundled CWE
// dataset, because that identifier is the key enrichment looks weaknesses up
// by, or says in no_weakness why none fits; one that cannot fail needs neither.
func (d FindingDefinition) validated() (FindingDefinition, error) {
	if err := d.validateReferences(); err != nil {
		return d, err
	}
	if err := checkTechniques(d.AttackTechniques); err != nil {
		return d, err
	}

	severity, ok := finding.NormalizeSeverity(d.Severity)
	if !ok {
		return d, fmt.Errorf("severity %q is not one of %s", d.Severity, finding.SeverityNames())
	}
	d.Severity = severity

	if err := d.validateCVSS(); err != nil {
		return d, err
	}
	if err := d.validateRecords(); err != nil {
		return d, err
	}
	if err := d.validateEnvironment(); err != nil {
		return d, err
	}

	switch d.Result {
	case "":
		d.Result = finding.ResultFail
	case finding.ResultFail, finding.ResultNotApplicable:
	default:
		return d, fmt.Errorf("result %q is not one a definition can declare", d.Result)
	}

	return d.validateWeakness()
}

// scoreTolerance is how far a stated score may sit from the one its vector
// computes. Scores are written to one decimal, so any real disagreement is a
// whole tenth or more.
const scoreTolerance = 0.05

// validateCVSS confirms the three values a definition states about severity
// agree: the vector is a CVSS v4.0 vector of Base metrics only, which is the
// baseline of the condition and not a score modified for a host, the score is the
// one that vector computes, and the severity is the band of that score. Severity is a
// property the registry authors, so a disagreement is a data defect and must
// halt startup, not surface later as a finding rated one way by its text and
// another by its numbers.
func (d FindingDefinition) validateCVSS() error {
	vector, err := v4.Parse(d.CVSSVector)
	if err != nil {
		return fmt.Errorf("cvss_vector: %w", err)
	}
	if label := vector.Nomenclature(); label != "CVSS-B" {
		return fmt.Errorf("cvss_vector is %s: a baseline states Base metrics only, and what a host modifies is computed for the host", label)
	}
	if computed := vector.Score(); math.Abs(computed-d.CVSSScore) >= scoreTolerance {
		return fmt.Errorf("cvss_score %.1f is not the %.1f that its cvss_vector computes", d.CVSSScore, computed)
	}
	if band := v4.Severity(d.CVSSScore); band != d.Severity {
		return fmt.Errorf("severity %s is not the %s band of cvss_score %.1f", d.Severity, band, d.CVSSScore)
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

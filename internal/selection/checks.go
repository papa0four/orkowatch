// internal/selection/checks.go

// Package selection defines the CheckMask type, category taxonomy, and registry
// used to identify which audit checks, modules, enrichment adapters, and
// composing flags are enabled for a given scan. The bitmask representation
// keeps check composition O(1) and scales to 64 discrete entries across four
// fixed bit ranges without structural changes.
package selection

import (
	"fmt"
	"strings"
)

type (
	// CheckMask is a bitmask of enabled audit checks, modules, enrichment
	// adapters, and composing flags. Each bit represents a single entry.
	// Callers compose a mask by OR-ing the constants defined in this package.
	// The 64-bit space is divided into four fixed ranges; see CheckCategory
	// for boundaries.
	CheckMask uint64

	// CheckCategory identifies which bit range a registry entry occupies.
	// The four categories map directly to the four fixed ranges in CheckMask.
	CheckCategory uint8

	// registryEntry is a single record in the canonical check registry. It binds
	// a CheckMask bit to its short filename code, canonical name, CLI flag name,
	// and category. Every derived lookup -- name resolution, Codes output,
	// EnabledChecks output -- reads this registry rather than maintaining
	// parallel data structures.
	//
	// name is the canonical registry identifier used in skip-* flags and internal
	// resolution. flag is the CLI flag name the analyst uses on the command line
	// (e.g. --fwall, --fperms). Where the two are identical, both fields carry
	// the same value. Neither field may be empty.
	registryEntry struct {
		bit      CheckMask
		code     byte
		name     string
		flag     string
		category CheckCategory
	}
)

const (
	// Module bits: 0-23.
	// One bit per independent output-producing module.

	// ModuleAudit identifies the security audit module. Skipping this module
	// disables all audit checks regardless of individual check flags. This
	// bit exists solely so "audit" resolves as a valid --skip-modules name;
	// it is deliberately never set into a CheckMask, since the presence or
	// absence of any CategoryCheck bit already indicates unambiguously
	// whether the audit module ran.
	ModuleAudit CheckMask = 1 << 0
	// ModuleHistory identifies the shell and terminal history module.
	// Reserved until history module lands.
	ModuleHistory CheckMask = 1 << 1
	// ModuleLogs identifies the system and application log capture module.
	// Reserved until log capture module lands.
	ModuleLogs CheckMask = 1 << 2
	// ModuleListeners identifies the local socket, port, and connection
	// state enumeration module. Reserved until listeners module lands.
	ModuleListeners CheckMask = 1 << 3
	// ModuleOS identifies the OS fingerprint module.
	ModuleOS CheckMask = 1 << 4
	// ModuleRemote identifies the remote network scanning module.
	// Reserved until remote scan lands and custom parser package is available.
	ModuleRemote CheckMask = 1 << 5
	// ModuleSoftware identifies the software inventory module.
	ModuleSoftware CheckMask = 1 << 6
	// Bits 7-23 reserved for future modules.

	// Audit check bits: 24-47.
	// One bit per logical check regardless of platform implementation.

	// CheckFirewall identifies the firewall configuration audit check.
	CheckFirewall CheckMask = 1 << 24
	// CheckPerms identifies the file permissions audit check.
	CheckPerms CheckMask = 1 << 25
	// CheckSSH identifies the SSH configuration audit check.
	CheckSSH CheckMask = 1 << 26
	// CheckUsers identifies the user account audit check.
	CheckUsers CheckMask = 1 << 27
	// Bits 28-47 reserved for future audit checks.

	// Enrichment bits: 48-61.
	// One bit per enrichment adapter.

	// EnrichGHSA enables GHSA advisory lookups against findings.
	// Reserved until GHSA adapter lands.
	EnrichGHSA CheckMask = 1 << 48
	// EnrichKEV enables CISA KEV cross-reference against findings.
	// Reserved until KEV adapter lands.
	EnrichKEV CheckMask = 1 << 49
	// EnrichNVD enables NVD CVE lookups against findings.
	// Reserved until NVD adapter lands.
	EnrichNVD CheckMask = 1 << 50
	// EnrichEPSS enables EPSS score lookups against findings.
	// Reserved until EPSS adapter lands.
	EnrichEPSS CheckMask = 1 << 51
	// Bits 52-61 reserved for future enrichment adapters.

	// Composing flag bits: 62-63.

	// FlagMITRE enables MITRE ATT&CK technique mapping across all enabled
	// checks and modules. Reserved until MITRE mapping lands.
	FlagMITRE CheckMask = 1 << 62
	// Bit 63 reserved.
)

const (
	// CategoryModule identifies a module bit (bits 0 - 23)
	CategoryModule CheckCategory = iota
	// CategoryCheck identifies an audit check bit (bits 24 - 47)
	CategoryCheck
	// CategoryEnrichment identifies an enrichment adapter bit (bits 48 - 61)
	CategoryEnrichment
	// CategoryMITRE identifies a composing flag bit (bits 62 - 63)
	CategoryMITRE

	// categoryCount bounds the segments slice in Codes. It is derived from
	// iota, so it tracks the const block automatically: it must remain the
	// final entry, and every category above it must remain contiguous.
	categoryCount
)

var (
	// registry is the canonical ordered list of all check, module, enrichment
	// adapter, and composing flag entries. Iteration order determines the
	// left-to-right code segment produced by Codes -- entries must remain ordered
	// alphabetically by code within each category. New entries append within their
	// category's reserved bit range. Existing entries must never be reordered or
	// renumbered; doing so silently changes generated filenames for existing
	// reports. Code characters are permanently bound to their bit within a
	// category -- a code assigned to one entry can never be reassigned to another,
	// even if the original entry is removed, as doing so breaks filename
	// compatibility with previously generated reports.
	registry = []registryEntry{
		// Modules -- alphabetical by code within category.
		// Modules have no individual CLI flags; name and flag are identical.
		// Reserved entries are wired now to lock in bit positions permanently;
		// implementation lands in a future branch.
		{bit: ModuleAudit, code: 'a', name: "audit", flag: "audit", category: CategoryModule},
		{bit: ModuleHistory, code: 'h', name: "history", flag: "history", category: CategoryModule},
		{bit: ModuleLogs, code: 'l', name: "logs", flag: "logs", category: CategoryModule},
		{bit: ModuleListeners, code: 'n', name: "listeners", flag: "listeners", category: CategoryModule},
		{bit: ModuleOS, code: 'o', name: "osinfo", flag: "osinfo", category: CategoryModule},
		{bit: ModuleRemote, code: 'r', name: "remote", flag: "remote", category: CategoryModule},
		{bit: ModuleSoftware, code: 's', name: "software", flag: "software", category: CategoryModule},

		// Audit checks -- alphabetical by code within category.
		// flag is the CLI flag name the analyst passes (e.g. --fwall, --fperms).
		// name is the canonical registry identifier used in --skip-checks resolution.
		{bit: CheckFirewall, code: 'f', name: "firewall", flag: "fwall", category: CategoryCheck},
		{bit: CheckPerms, code: 'p', name: "permissions", flag: "fperms", category: CategoryCheck},
		{bit: CheckSSH, code: 's', name: "ssh", flag: "ssh", category: CategoryCheck},
		{bit: CheckUsers, code: 'u', name: "users", flag: "users", category: CategoryCheck},

		// Enrichment adapters -- reserved until each adapter lands.
		// flag names will be assigned when each adapter is implemented.
		{bit: EnrichGHSA, code: 'g', name: "ghsa", flag: "ghsa", category: CategoryEnrichment},
		{bit: EnrichKEV, code: 'k', name: "kev", flag: "kev", category: CategoryEnrichment},
		{bit: EnrichNVD, code: 'n', name: "nvd", flag: "nvd", category: CategoryEnrichment},
		{bit: EnrichEPSS, code: 'p', name: "epss", flag: "epss", category: CategoryEnrichment},

		// Composing flags -- reserved until implementation lands.
		// -m is the short flag; mitre is the canonical name.
		{bit: FlagMITRE, code: 'm', name: "mitre", flag: "m", category: CategoryMITRE},
	}

	// checksByName is a derived lookup map built from the registry.
	// It maps both the canonical name and the CLI flag name of each entry to its
	// registry entry for O(1) resolution by either form. Entries where name and
	// flag are identical occupy one slot. Callers must use MaskFromNames rather
	// than referencing this map directly.
	checksByName = buildChecksByName()
)

// SkipHint returns the flag invocation that excludes names from a future run,
// or the empty string when names is empty or the category has no exclusion
// flag. Operator-facing messages embed it so the flag name has one definition.
func SkipHint(category CheckCategory, names []string) string {
	flag := category.skipFlag()
	if flag == "" || len(names) == 0 {
		return ""
	}
	return flag + " " + strings.Join(names, ",")
}

// Codes returns a filename-safe string encoding the enabled entries within
// mask. Entries are grouped into four segments -- modules, checks, enrichment,
// and composing flags -- separated by hyphens. Prefixed segments carry a
// single-byte category label followed by a dot (e.g. "m.os", "c.fpsu").
// The composing flag segment is unprefixed and always terminal. Empty segments
// are omitted entirely. The resulting string is stable across runs for a given
// mask value.
func Codes(mask CheckMask) string {
	segments := make([][]byte, categoryCount)

	for _, e := range registry {
		if mask&e.bit != 0 {
			segments[e.category] = append(segments[e.category], e.code)
		}
	}

	var parts []string
	for i, seg := range segments {
		if len(seg) == 0 {
			continue
		}
		cat := CheckCategory(i)
		p := cat.prefix()
		if p != 0 {
			// Prefixed segment: <prefix>.<codes>
			const prefixLen = 2
			prefixed := make([]byte, 0, prefixLen+len(seg))
			prefixed = append(prefixed, p, '.')
			prefixed = append(prefixed, seg...)
			parts = append(parts, string(prefixed))
		} else {
			// unprefixed segment
			parts = append(parts, string(seg))
		}
	}

	return strings.Join(parts, "-")
}

// EnabledChecks returns a slice of check names for the audit checks enabled
// in mask. Only CategoryCheck entries are considered; module, enrichment, and
// composing flag bits are ignored. The returned slice is used by the audit
// runner to select which checks to execute.
func EnabledChecks(mask CheckMask) []string {
	var checks []string
	for _, e := range registry {
		if e.category == CategoryCheck && mask&e.bit != 0 {
			checks = append(checks, e.name)
		}
	}
	return checks
}

// MaskFromNames resolves a slice of entry names into a single CheckMask by
// OR-ing the bits of all matching registry entries within category. Only
// entries whose category matches the supplied category are accepted; entries
// from other categories are rejected to prevent callers from accidentally
// setting bits outside the intended range. CLI flag aliases are deliberately
// accepted alongside canonical names (e.g. --skip-checks fwall resolves to
// firewall), so an analyst can skip a check by the same token used to enable
// it; error messages and help text advertise canonical names only. The valid
// name set is derived dynamically from the registry so the error message
// stays accurate as new entries are added. It returns an error naming the
// first unrecognized entry alongside the full valid set for that category.
func MaskFromNames(names []string, category CheckCategory) (CheckMask, error) {
	var mask CheckMask
	for _, name := range names {
		lower := strings.ToLower(name)
		e, ok := checksByName[lower]
		if !ok || e.category != category {
			return 0, fmt.Errorf("invalid name %q for category %s (valid: %s)",
				name, category, ValidNamesFor(category))
		}
		mask |= e.bit
	}
	return mask, nil
}

// String returns a human-readable label for the category, used in error
// messages produced by MaskFromNames.
func (c CheckCategory) String() string {
	switch c {
	case CategoryModule:
		return "module"
	case CategoryCheck:
		return "check"
	case CategoryEnrichment:
		return "enrichment"
	case CategoryMITRE:
		return "mitre"
	default:
		return "unknown"
	}
}

// prefix returns the single-byte segment label used in generated report
// filenames. The label precedes a dot and the category's code string
// (e.g. "m.os", "c.fpsu"). CategoryMITRE returns 0 because the composing
// flag segment is always terminal and carries no prefix by convention.
func (c CheckCategory) prefix() byte {
	switch c {
	case CategoryModule:
		return 'm'
	case CategoryCheck:
		return 'c'
	case CategoryEnrichment:
		return 'e'
	default:
		return 0
	}
}

// skipFlag returns the CLI flag that excludes entries in this category from a
// run, or the empty string for categories with no exclusion flag
func (c CheckCategory) skipFlag() string {
	switch c {
	case CategoryModule:
		return "--skip-modules"
	case CategoryCheck:
		return "--skip-checks"
	default:
		return ""
	}
}

// validateRegistry panics during package initialization if any registry entry
// within a category has a duplicate code or duplicate name, if any entry's
// code sorts out of ascending order relative to the prior entry in the same
// category, or if any bit is duplicated across the entire registry. This
// surfaces misconfiguration immediately on startup rather than producing
// silently wrong output. Ordering validation only constrains the registry
// slice's declared order; it has no bearing on bit values, which are assigned
// by availability and are never reordered once permanently bound to a code.
func validateRegistry() {
	codes := make(map[CheckCategory]map[byte]bool)
	names := make(map[CheckCategory]map[string]bool)
	bits := make(map[CheckMask]bool)
	lastCode := make(map[CheckCategory]byte)
	seenCategory := make(map[CheckCategory]bool)

	for _, e := range registry {
		if bits[e.bit] {
			panic(fmt.Sprintf("scan: registry duplicates bit 0x%x (name: %s)", e.bit, e.name))
		}
		bits[e.bit] = true

		if codes[e.category] == nil {
			codes[e.category] = make(map[byte]bool)
		}
		if codes[e.category][e.code] {
			panic(fmt.Sprintf("scan: registry duplicate code '%c' in category %d (name: %s)", e.code, e.category, e.name))
		}
		codes[e.category][e.code] = true

		if seenCategory[e.category] && e.code < lastCode[e.category] {
			panic(fmt.Sprintf(
				"scan: registry entry '%c' (name: %s) is out of alphabetical order in category %d; "+
					"expected code >= '%c'. Insert new entries in alphabetical position by code -- "+
					"do not renumber bits to match",
				e.code, e.name, e.category, lastCode[e.category]))
		}
		lastCode[e.category] = e.code
		seenCategory[e.category] = true

		if names[e.category] == nil {
			names[e.category] = make(map[string]bool)
		}
		if names[e.category][e.name] {
			panic(fmt.Sprintf("scan: registry duplicate name %q in category %d", e.name, e.category))
		}
		names[e.category][e.name] = true
	}
}

// buildChecksByName validates the registry and returns the name and flag
// lookup map. It panics on a malformed registry, halting the program at
// startup rather than resolving names against a registry known to be wrong.
func buildChecksByName() map[string]registryEntry {
	validateRegistry()

	const maxKeysPerEntry = 2
	byName := make(map[string]registryEntry, len(registry)*maxKeysPerEntry)
	for _, e := range registry {
		byName[e.name] = e
		byName[e.flag] = e
	}
	return byName
}

// ValidNamesFor returns a comma-separated string of all canonical names
// registered under category, in registry order. It is the single source for
// operator-facing name lists: MaskFromNames error messages and the help text
// of the flags that accept those names both derive from it, so neither can
// drift from the registry.
func ValidNamesFor(category CheckCategory) string {
	var names []string
	for _, e := range registry {
		if e.category == category {
			names = append(names, e.name)
		}
	}
	return strings.Join(names, ", ")
}

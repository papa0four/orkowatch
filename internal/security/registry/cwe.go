// internal/security/registry/cwe.go

package registry

import (
	"bytes"
	_ "embed"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/papa0four/orkowatch/internal/security/finding"
)

type (
	// cweFile is the bundled CWE dataset as authored. Version and CatalogDate
	// name the catalog release the entries were read from and Verified is the
	// date they were compared with MITRE's file.
	cweFile struct {
		Version     string              `yaml:"version"`
		CatalogDate string              `yaml:"catalog_date"`
		Verified    string              `yaml:"verified"`
		Weaknesses  map[string]cweEntry `yaml:"weaknesses"`
	}

	// cweEntry is one weakness as MITRE's catalog states it.
	cweEntry struct {
		Name        string `yaml:"name"`
		Abstraction string `yaml:"abstraction"`
		Usage       string `yaml:"usage"`
		Description string `yaml:"description"`
	}
)

// cweUsable lists the mapping usages MITRE gives an entry that a finding may
// map to. An entry MITRE marks Discouraged or Prohibited is refused, so the data
// cannot drift back to a weakness MITRE advises against.
var cweUsable = map[string]bool{"Allowed": true, "Allowed-with-Review": true}

var (
	//go:embed data/cwe.yaml
	cweData []byte

	// weaknesses is the bundled dataset keyed by identifier. Definitions are
	// validated against it as they load, so it is read first.
	weaknesses = mustLoadWeaknesses(cweData)
)

// mustLoadWeaknesses decodes the bundled dataset strictly and panics on a
// malformed entry, halting startup rather than letting a finding carry a
// weakness with no name or one MITRE advises against mapping to.
func mustLoadWeaknesses(data []byte) map[finding.CWE]finding.Weakness {
	var file cweFile
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&file); err != nil {
		panic("registry: failed to parse embedded YAML cwe.yaml: " + err.Error())
	}
	if file.Version == "" || file.Verified == "" {
		panic("registry: cwe.yaml names no catalog version or verification date")
	}
	out := make(map[finding.CWE]finding.Weakness, len(file.Weaknesses))
	for raw, e := range file.Weaknesses {
		id, err := finding.ParseCWE(raw)
		switch {
		case err != nil:
			panic("registry: cwe.yaml: " + err.Error())
		case strings.TrimSpace(e.Name) == "" || strings.TrimSpace(e.Description) == "":
			panic(fmt.Sprintf("registry: cwe.yaml: %s has no name or description", raw))
		case !cweUsable[e.Usage]:
			panic(fmt.Sprintf("registry: cwe.yaml: %s is %s for mapping by MITRE's guidance and cannot be used", raw, e.Usage))
		}
		out[id] = finding.Weakness{ID: id, Name: e.Name, Description: e.Description, Usage: e.Usage, URL: cweURL(raw)}
	}
	return out
}

// validateWeakness checks how d states its weakness. A definition that can fail
// maps to a weakness in the bundled dataset, or says in no_weakness why none
// fits, so the absence of one is a decision recorded in the data and not an
// omission. One that cannot fail needs neither. Naming both is refused.
func (d FindingDefinition) validateWeakness() (FindingDefinition, error) {
	reason := strings.TrimSpace(d.NoWeakness)
	switch {
	case d.CWE != "" && reason != "":
		return d, fmt.Errorf("names %s and also says no weakness applies", d.CWE)
	case d.CWE == "" && reason == "":
		if d.Result == finding.ResultFail {
			return d, fmt.Errorf("names no weakness and does not say why none applies (cwe or no_weakness)")
		}
		return d, nil
	case reason != "":
		return d, nil
	}
	cwe, err := finding.ParseCWE(string(d.CWE))
	if err != nil {
		return d, err
	}
	if _, ok := weaknesses[cwe]; !ok {
		return d, fmt.Errorf("%s is not in the bundled CWE dataset", cwe)
	}
	d.CWE = cwe
	return d, nil
}

// checkWeaknessUse panics when a bundled weakness is named by no definition,
// since an entry nothing cites is data with no reader.
func checkWeaknessUse(sets ...map[FindingKey]FindingDefinition) {
	used := make(map[finding.CWE]bool, len(weaknesses))
	for _, defs := range sets {
		for _, def := range defs {
			if def.CWE != "" {
				used[def.CWE] = true
			}
		}
	}
	var unused []string
	for id := range weaknesses {
		if !used[id] {
			unused = append(unused, string(id))
		}
	}
	if len(unused) > 0 {
		sort.Strings(unused)
		panic("registry: cwe.yaml holds weaknesses no definition names: " + strings.Join(unused, ", "))
	}
}

// weakness returns the bundled entry d maps to, or nil when it maps to none.
func (d FindingDefinition) weakness() *finding.Weakness {
	if d.CWE == "" {
		return nil
	}
	w := weaknesses[d.CWE]
	return &w
}

// cvssScore is the registry's CVSS value for d, labelled for what it is: a
// base score for the condition in general, written by review and checked by
// the registry against its vector, and not a measurement of the host the
// finding was raised on. It is nil for a definition with no vector.
func (d FindingDefinition) cvssScore() *finding.CVSSScore {
	if d.CVSSVector == "" {
		return nil
	}
	version, _, _ := strings.Cut(strings.TrimPrefix(d.CVSSVector, "CVSS:"), "/")
	return &finding.CVSSScore{
		Version:      version,
		Vector:       d.CVSSVector,
		BaseScore:    d.CVSSScore,
		Severity:     d.Severity,
		Source:       "registry",
		Nomenclature: "CVSS-B",
		Basis:        "baseline for the condition, not measured on this host",
	}
}

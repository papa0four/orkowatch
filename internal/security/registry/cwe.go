// internal/security/registry/cwe.go

package registry

import (
	"bytes"
	_ "embed"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	v4 "github.com/papa0four/orkowatch/internal/cvss/v4"
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

	// cweEntry is one weakness as MITRE's catalog states it. Parents are its
	// ChildOf relations in the Research Concepts view. Description is carried
	// only for the entries a definition maps to.
	cweEntry struct {
		Name        string   `yaml:"name"`
		Abstraction string   `yaml:"abstraction"`
		Usage       string   `yaml:"usage"`
		Parents     []string `yaml:"parents"`
		Description string   `yaml:"description"`
	}

	// weaknessRecord is a loaded entry. The parents are consumed by the NVD
	// enrichment adapter, which reaches the CVEs NVD files under a child of a
	// finding's weakness through them; until it exists the registry checks that
	// they form a hierarchy.
	weaknessRecord struct {
		name        string
		abstraction string
		usage       string
		description string
		parents     []finding.CWE
	}
)

// MITRE's vocabulary for an entry's mapping usage and abstraction. The loader
// refuses a value outside it, so a catalog release that adds one is noticed
// instead of read as something it is not.
var (
	cweUsages       = map[string]bool{"Allowed": true, "Allowed-with-Review": true, "Discouraged": true, "Prohibited": true}
	cweAbstractions = map[string]bool{"Pillar": true, "Class": true, "Base": true, "Variant": true, "Compound": true}

	// cweUsable lists the mapping usages MITRE gives an entry that a finding may
	// map to.
	cweUsable = map[string]bool{"Allowed": true, "Allowed-with-Review": true}
)

var (
	//go:embed data/cwe.yaml
	cweData []byte

	// weaknesses is the bundled catalog keyed by identifier. Definitions are
	// validated against it as they load, so it is read first.
	weaknesses = mustLoadWeaknesses(cweData)
)

// mustLoadWeaknesses decodes the bundled catalog strictly and panics on a
// malformed one, halting startup rather than letting a finding carry a weakness
// from a catalog with a broken hierarchy or a usage the registry does not
// understand.
func mustLoadWeaknesses(data []byte) map[finding.CWE]weaknessRecord {
	var file cweFile
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&file); err != nil {
		panic("registry: failed to parse embedded YAML cwe.yaml: " + err.Error())
	}
	if file.Version == "" || file.Verified == "" {
		panic("registry: cwe.yaml names no catalog version or verification date")
	}
	out := make(map[finding.CWE]weaknessRecord, len(file.Weaknesses))
	for raw, e := range file.Weaknesses {
		id, err := finding.ParseCWE(raw)
		switch {
		case err != nil:
			panic("registry: cwe.yaml: " + err.Error())
		case strings.TrimSpace(e.Name) == "":
			panic(fmt.Sprintf("registry: cwe.yaml: %s has no name", raw))
		case !cweUsages[e.Usage]:
			panic(fmt.Sprintf("registry: cwe.yaml: %s has usage %q, which is not one of MITRE's", raw, e.Usage))
		case !cweAbstractions[e.Abstraction]:
			panic(fmt.Sprintf("registry: cwe.yaml: %s has abstraction %q, which is not one of MITRE's", raw, e.Abstraction))
		}
		rec := weaknessRecord{name: e.Name, abstraction: e.Abstraction, usage: e.Usage, description: e.Description}
		for _, p := range e.Parents {
			parent, err := finding.ParseCWE(p)
			if err != nil {
				panic(fmt.Sprintf("registry: cwe.yaml: %s names parent %q: %v", raw, p, err))
			}
			rec.parents = append(rec.parents, parent)
		}
		out[id] = rec
	}
	checkHierarchy(out)
	return out
}

// checkHierarchy panics unless every parent is an entry of the catalog and the
// relations contain no cycle, which MITRE's hierarchy cannot, so one means the
// file was damaged.
func checkHierarchy(records map[finding.CWE]weaknessRecord) {
	const (
		unvisited = iota
		visiting
		done
	)
	state := make(map[finding.CWE]int, len(records))
	var visit func(id finding.CWE)
	visit = func(id finding.CWE) {
		state[id] = visiting
		for _, p := range records[id].parents {
			if _, ok := records[p]; !ok {
				panic(fmt.Sprintf("registry: cwe.yaml: %s names parent %s, which is not in the catalog", id, p))
			}
			switch state[p] {
			case visiting:
				panic(fmt.Sprintf("registry: cwe.yaml: %s and %s are each other's ancestor", id, p))
			case unvisited:
				visit(p)
			}
		}
		state[id] = done
	}
	for id := range records {
		if state[id] == unvisited {
			visit(id)
		}
	}
}

// validateWeakness checks how d states its weakness. A definition that can fail
// maps to a weakness MITRE allows for mapping, or says in no_weakness why none
// fits, so the absence of one is a decision recorded in the data and not an
// omission. One that cannot fail needs neither. Naming both is refused, as is a
// weakness MITRE marks Discouraged or Prohibited, one the catalog lacks, and one
// the finding could not describe because the file carries no description for it.
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
	rec, ok := weaknesses[cwe]
	switch {
	case !ok:
		return d, fmt.Errorf("%s is not a weakness in the bundled CWE catalog", cwe)
	case !cweUsable[rec.usage]:
		return d, fmt.Errorf("%s is %s for mapping by MITRE's guidance and cannot be used", cwe, rec.usage)
	case rec.description == "":
		return d, fmt.Errorf("%s has no description in the bundled CWE catalog, so a finding could not show it", cwe)
	}
	d.CWE = cwe
	return d, nil
}

// weakness returns the bundled entry d maps to, or nil when it maps to none.
func (d FindingDefinition) weakness() *finding.Weakness {
	if d.CWE == "" {
		return nil
	}
	rec := weaknesses[d.CWE]
	return &finding.Weakness{ID: d.CWE, Name: rec.name, Description: rec.description, Usage: rec.usage, URL: cweURL(string(d.CWE))}
}

// cvssScore is the registry's CVSS value for d, labelled for what it is: a
// base score for the condition in general, written by review and checked by
// the registry against its vector, and not a measurement of the host the
// finding was raised on. Load has refused a definition whose vector does not
// parse or whose score and severity disagree with it, so the score computed
// here is the one the definition states. It is nil for a definition with no
// usable vector.
func (d FindingDefinition) cvssScore() *finding.CVSSScore {
	vector, err := v4.Parse(d.CVSSVector)
	if err != nil {
		return nil
	}
	return labelledScore(vector, "registry", "baseline for the condition, not measured on this host")
}

// labelledScore is the score of vector with everything a displayed CVSS score
// states about itself: the version, the FIRST nomenclature label, the severity
// band, whose score it is, what it is a statement about, and the link that
// opens FIRST's calculator on it. The baseline and the host score are both
// built here, so the two cannot be labelled differently.
func labelledScore(vector v4.Vector, source, basis string) *finding.CVSSScore {
	text := vector.String()
	version, _, _ := strings.Cut(strings.TrimPrefix(text, "CVSS:"), "/")
	score := vector.Score()
	return &finding.CVSSScore{
		Version:       version,
		Vector:        text,
		Score:         score,
		Severity:      v4.Severity(score),
		Source:        source,
		Nomenclature:  vector.Nomenclature(),
		Basis:         basis,
		CalculatorURL: v4.CalculatorURL(text),
	}
}

// internal/security/registry/attack.go

package registry

import (
	"bytes"
	_ "embed"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/papa0four/orkowatch/internal/security/finding"
)

type (
	// attackFile is the bundled ATT&CK dataset as authored. Version is the
	// ATT&CK release the entries were read against; Mitigations maps each
	// mitigation identifier to its name.
	attackFile struct {
		Version     string                     `yaml:"version"`
		Mitigations map[string]string          `yaml:"mitigations"`
		Techniques  map[string]attackTechnique `yaml:"techniques"`
	}

	// attackTechnique is one technique as the ATT&CK site lists it, with the
	// identifiers of the mitigations its page lists.
	attackTechnique struct {
		Name        string   `yaml:"name"`
		Tactics     []string `yaml:"tactics"`
		Mitigations []string `yaml:"mitigations"`
	}
)

var (
	//go:embed data/attack.yaml
	attackData []byte

	// techniqueID matches a technique or sub-technique identifier, and
	// mitigationID a mitigation identifier.
	techniqueID  = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)
	mitigationID = regexp.MustCompile(`^M\d{4}$`)

	// techniques is the bundled dataset keyed by identifier. Definitions are
	// validated against it as they load, so it is read first.
	techniques = mustLoadTechniques(attackData)
)

// mustLoadTechniques decodes the bundled dataset strictly and panics on a
// malformed entry, halting startup rather than letting a definition cite a
// technique with no name or tactic, or a technique name a mitigation the
// dataset does not hold.
func mustLoadTechniques(data []byte) map[string]finding.Technique {
	var file attackFile
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&file); err != nil {
		panic("registry: failed to parse embedded YAML attack.yaml: " + err.Error())
	}
	if file.Version == "" {
		panic("registry: attack.yaml names no ATT&CK version")
	}

	mitigations := make(map[string]finding.Mitigation, len(file.Mitigations))
	for id, name := range file.Mitigations {
		switch {
		case !mitigationID.MatchString(id):
			panic(fmt.Sprintf("registry: attack.yaml: %q is not a mitigation identifier", id))
		case strings.TrimSpace(name) == "":
			panic(fmt.Sprintf("registry: attack.yaml: %s has no name", id))
		}
		mitigations[id] = finding.Mitigation{ID: id, Name: name, URL: "https://attack.mitre.org/mitigations/" + id + "/"}
	}

	used := make(map[string]bool, len(mitigations))
	out := make(map[string]finding.Technique, len(file.Techniques))
	for id, t := range file.Techniques {
		switch {
		case !techniqueID.MatchString(id):
			panic(fmt.Sprintf("registry: attack.yaml: %q is not a technique identifier", id))
		case strings.TrimSpace(t.Name) == "":
			panic(fmt.Sprintf("registry: attack.yaml: %s has no name", id))
		case len(t.Tactics) == 0:
			panic(fmt.Sprintf("registry: attack.yaml: %s lists no tactic", id))
		}

		technique := finding.Technique{ID: id, Name: t.Name, Tactics: t.Tactics, URL: techniqueURL(id)}
		listed := make(map[string]bool, len(t.Mitigations))
		for _, mid := range t.Mitigations {
			m, ok := mitigations[mid]
			switch {
			case !ok:
				panic(fmt.Sprintf("registry: attack.yaml: %s lists mitigation %s, which the dataset does not hold", id, mid))
			case listed[mid]:
				panic(fmt.Sprintf("registry: attack.yaml: %s lists mitigation %s twice", id, mid))
			}
			listed[mid] = true
			used[mid] = true
			technique.Mitigations = append(technique.Mitigations, m)
		}
		out[id] = technique
	}

	for id := range mitigations {
		if !used[id] {
			panic("registry: attack.yaml: mitigation " + id + " is listed by no technique")
		}
	}
	return out
}

// techniqueURL is the technique's page on the ATT&CK site, which spells a
// sub-technique's identifier as a path.
func techniqueURL(id string) string {
	return "https://attack.mitre.org/techniques/" + strings.ReplaceAll(id, ".", "/") + "/"
}

// checkTechniques returns the first identifier the bundled dataset does not
// hold, or a repeated one, as the reason a definition cannot be used.
func checkTechniques(ids []string) error {
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if _, ok := techniques[id]; !ok {
			return fmt.Errorf("attack technique %q is not in the bundled dataset", id)
		}
		if seen[id] {
			return fmt.Errorf("attack technique %q is listed twice", id)
		}
		seen[id] = true
	}
	return nil
}

// checkTechniqueUse panics when a bundled technique is referenced by no
// definition, since an entry nothing cites is data with no reader.
func checkTechniqueUse(sets ...map[FindingKey]FindingDefinition) {
	used := make(map[string]bool, len(techniques))
	for _, defs := range sets {
		for _, def := range defs {
			for _, id := range def.AttackTechniques {
				used[id] = true
			}
		}
	}
	var unused []string
	for id := range techniques {
		if !used[id] {
			unused = append(unused, id)
		}
	}
	if len(unused) > 0 {
		sort.Strings(unused)
		panic("registry: attack.yaml holds techniques no definition references: " + strings.Join(unused, ", "))
	}
}

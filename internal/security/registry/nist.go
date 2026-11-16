// internal/security/registry/nist.go

package registry

import (
	"bytes"
	_ "embed"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// nistFile is the bundled NIST SP 800-53 catalog as authored. Release names the
// edition it was read from and Verified is the date it was compared with
// NIST's own file; Controls maps each identifier to NIST's title for it.
type nistFile struct {
	Release         string            `yaml:"release"`
	CatalogModified string            `yaml:"catalog_modified"`
	Verified        string            `yaml:"verified"`
	Controls        map[string]string `yaml:"controls"`
}

var (
	//go:embed data/nist.yaml
	nistData []byte

	// nist is the bundled catalog. Definitions are validated against it as they
	// load, so it is read first.
	nist = mustLoadNIST(nistData)
)

// mustLoadNIST decodes the bundled catalog strictly and panics on a malformed
// one, halting startup rather than letting a citation resolve against a catalog
// with no release or a control with no title.
func mustLoadNIST(data []byte) nistFile {
	var file nistFile
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&file); err != nil {
		panic("registry: failed to parse embedded YAML nist.yaml: " + err.Error())
	}
	if file.Release == "" || file.Verified == "" {
		panic("registry: nist.yaml names no release or verification date")
	}
	for id, title := range file.Controls {
		switch {
		case !nistControlPattern.MatchString(id):
			panic(fmt.Sprintf("registry: nist.yaml: %q is not a control identifier", id))
		case strings.TrimSpace(title) == "":
			panic(fmt.Sprintf("registry: nist.yaml: %s has no title", id))
		}
	}
	return file
}

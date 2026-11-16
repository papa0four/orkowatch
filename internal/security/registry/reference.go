// internal/security/registry/reference.go

package registry

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/papa0four/orkowatch/internal/security/finding"
)

// Reference types. A ReferenceSpec names its source with one of these, and
// the finding.Reference built from it carries the same value.
const (
	RefTypeCWE  = "CWE"
	RefTypeCIS  = "CIS"
	RefTypeNIST = "NIST"
	RefTypeURL  = "URL"
)

// referenceRank orders the citations on a finding: the weakness, the controls,
// the benchmarks, then vendor and distribution documents.
var referenceRank = map[string]int{RefTypeCWE: 0, RefTypeNIST: 1, RefTypeCIS: 2, RefTypeURL: 3}

// verifiedLayout is the date format of a reference's verified field.
const verifiedLayout = "2006-01-02"

// nistControlPattern matches a NIST SP 800-53 control identifier, with or
// without an enhancement suffix, and captures the two-letter family code.
var nistControlPattern = regexp.MustCompile(`^([A-Z]{2})-\d+(\(\d+\))?$`)

// ReferenceSpec is one citation as a data file states it. Version names the
// edition of the source the entry was checked against, and Verified is the date
// it was checked. An entry with no Verified date has not been checked: it stays
// in the data, and no report, view or browser shows it, so a citation reaches a
// reader only after someone has compared it with its source.
//
// NIST entries carry only the control's ID: the title and the release come from
// the bundled catalog (data/nist.yaml), which load checks the ID against, so
// they cannot differ from NIST's. CIS entries carry Benchmark, Version and the
// recommendation ID. URL entries carry the page's Title and URL. CWE is not
// cited here: a definition's cwe field names the weakness, and its reference is
// built from that field.
type ReferenceSpec struct {
	Source    string `yaml:"source"`
	ID        string `yaml:"id"`
	Title     string `yaml:"title"`
	Benchmark string `yaml:"benchmark"`
	Version   string `yaml:"version"`
	URL       string `yaml:"url"`
	Verified  string `yaml:"verified"`
}

// report builds the reference a finding carries, or reports false for an entry
// that has not been verified.
func (r ReferenceSpec) report() (finding.Reference, bool) {
	if r.Source == RefTypeNIST {
		return finding.Reference{Title: "NIST " + nist.Release + " " + r.ID + " (" + nist.Controls[r.ID] + ")", Type: RefTypeNIST}, true
	}
	if r.Verified == "" {
		return finding.Reference{}, false
	}
	switch r.Source {
	case RefTypeCIS:
		return finding.Reference{Title: r.Benchmark + " " + r.Version + " " + r.ID, Type: RefTypeCIS}, true
	default:
		return finding.Reference{Title: r.Title, URL: r.URL, Type: RefTypeURL}, true
	}
}

// validate confirms r is well formed for its source. It runs once per
// definition at registry load, so a malformed citation halts startup rather than
// reaching a report.
func (r ReferenceSpec) validate() error {
	require := func(field, value string) error {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s reference needs %s", r.Source, field)
		}
		return nil
	}
	var checks []error
	switch r.Source {
	case RefTypeNIST:
		if _, ok := nist.Controls[r.ID]; !ok {
			return fmt.Errorf("NIST reference %q is not a control in the bundled %s catalog", r.ID, nist.Release)
		}
		if r.Title != "" || r.Version != "" || r.Verified != "" {
			return fmt.Errorf("NIST reference %s states a title, version or date; they come from the bundled catalog", r.ID)
		}
	case RefTypeCIS:
		checks = append(checks, require("benchmark", r.Benchmark), require("version", r.Version), require("id", r.ID))
	case RefTypeURL:
		checks = append(checks, require("title", r.Title), require("url", r.URL), require("version", r.Version))
		if !strings.HasPrefix(r.URL, "https://") {
			return fmt.Errorf("URL reference %q is not an https link", r.URL)
		}
	default:
		return fmt.Errorf("reference source %q is not one of %s, %s, %s", r.Source, RefTypeNIST, RefTypeCIS, RefTypeURL)
	}
	for _, err := range checks {
		if err != nil {
			return err
		}
	}
	if r.Verified != "" {
		if _, err := time.Parse(verifiedLayout, r.Verified); err != nil {
			return fmt.Errorf("%s reference %s: verified %q is not a YYYY-MM-DD date", r.Source, r.ID, r.Verified)
		}
	}
	return nil
}

// validateReferences checks every reference of d. It runs at load so
// ToCategories and ToReferences, which are called where a finding is built,
// need no error return.
func (d FindingDefinition) validateReferences() error {
	for _, ref := range d.References {
		if err := ref.validate(); err != nil {
			return err
		}
	}
	return nil
}

// ToReferences returns the citations a finding carries: the weakness the cwe
// field names and each verified entry, grouped by type and in the order the data
// lists them within a type.
func (d FindingDefinition) ToReferences() []finding.Reference {
	var out []finding.Reference
	if d.CWE != "" {
		out = append(out, finding.Reference{Title: string(d.CWE), URL: cweURL(string(d.CWE)), Type: RefTypeCWE})
	}
	for _, spec := range d.References {
		if ref, ok := spec.report(); ok {
			out = append(out, ref)
		}
	}
	slices.SortStableFunc(out, func(a, b finding.Reference) int {
		return referenceRank[a.Type] - referenceRank[b.Type]
	})
	return out
}

// ToCategories returns the NIST SP 800-53 control families the definition's
// NIST references belong to, deduplicated and in alphabetical order.
func (d FindingDefinition) ToCategories() []string {
	var out []string
	seen := make(map[string]struct{})
	for _, spec := range d.References {
		if spec.Source != RefTypeNIST {
			continue
		}
		family := nistControlPattern.FindStringSubmatch(spec.ID)[1]
		if _, dup := seen[family]; dup {
			continue
		}
		seen[family] = struct{}{}
		out = append(out, family)
	}
	sort.Strings(out)
	return out
}

func cweURL(id string) string {
	return "https://cwe.mitre.org/data/definitions/" + strings.TrimPrefix(id, "CWE-") + ".html"
}

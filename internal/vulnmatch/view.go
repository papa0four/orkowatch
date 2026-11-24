// internal/vulnmatch/view.go

package vulnmatch

import (
	"fmt"
	"io"
	"strings"

	"github.com/papa0four/orkowatch/internal/dataset/osv"
	"github.com/papa0four/orkowatch/internal/render"
)

// The status of a match.
const (
	// StatusFixAvailable is a package below the version that fixes the
	// vulnerability.
	StatusFixAvailable = "fix available"

	// StatusUnfixed is a package in a range no record gives a fixed version
	// for.
	StatusUnfixed = "unfixed"
)

// View is the serializable projection of a match of a host's packages: the
// dataset it was made against, or why none was made, then every match, every
// vulnerability and package that could not be judged, and the counts. This is
// the one shape the vulnerabilities section has in every report.
type View struct {
	Dataset  string `json:"dataset,omitempty" yaml:"dataset,omitempty"`
	Release  string `json:"release,omitempty" yaml:"release,omitempty"`
	Source   string `json:"source,omitempty" yaml:"source,omitempty"`
	DataDate string `json:"data_date,omitempty" yaml:"data_date,omitempty"`
	Fetched  string `json:"fetched,omitempty" yaml:"fetched,omitempty"`
	State    string `json:"state,omitempty" yaml:"state,omitempty"`

	// NotDone says why no match was made, and what to do; a view that has
	// it has nothing else of a match.
	NotDone string `json:"not_done,omitempty" yaml:"not_done,omitempty"`

	// Order is the version order the packages were compared in.
	Order string `json:"version_order,omitempty" yaml:"version_order,omitempty"`

	Counts     Counts       `json:"counts" yaml:"counts"`
	Matches    []Match      `json:"matches" yaml:"matches"`
	NotMatched []NotMatched `json:"not_matched,omitempty" yaml:"not_matched,omitempty"`

	// Installed is how many packages, as the records name them, were
	// matched, and NotCovered how many of those no record names.
	Installed  int `json:"-" yaml:"-"`
	NotCovered int `json:"-" yaml:"-"`
}

// Counts sums a match: the packages matched and those no record covers, the
// vulnerabilities with a fix available and unfixed and the packages each is
// in, and the pairs not matched.
type Counts struct {
	Packages            int `json:"packages" yaml:"packages"`
	NotCovered          int `json:"packages_not_covered" yaml:"packages_not_covered"`
	FixAvailable        int `json:"fix_available" yaml:"fix_available"`
	PackagesWithFix     int `json:"packages_with_fix_available" yaml:"packages_with_fix_available"`
	Unfixed             int `json:"unfixed" yaml:"unfixed"`
	PackagesWithUnfixed int `json:"packages_with_unfixed" yaml:"packages_with_unfixed"`
	NotMatched          int `json:"not_matched" yaml:"not_matched"`
}

// Match is one vulnerability of one installed package: its identifier, a CVE
// or, for a record that names none, the record's own; the package as the
// records name it, the installed packages built from it, and its version; the
// version that fixes it, or none; its scores as the records give them; and
// the records that name it.
type Match struct {
	ID        string         `json:"id" yaml:"id"`
	Package   string         `json:"package" yaml:"package"`
	Binaries  []string       `json:"binaries,omitempty" yaml:"binaries,omitempty"`
	Installed string         `json:"installed" yaml:"installed"`
	Status    string         `json:"status" yaml:"status"`
	Fixed     string         `json:"fixed,omitempty" yaml:"fixed,omitempty"`
	Severity  []osv.Severity `json:"severity,omitempty" yaml:"severity,omitempty"`
	Records   []string       `json:"records" yaml:"records"`
}

// NotMatched is a vulnerability of an installed package that could not be
// judged, and why.
type NotMatched struct {
	ID        string `json:"id" yaml:"id"`
	Package   string `json:"package" yaml:"package"`
	Installed string `json:"installed" yaml:"installed"`
	Reason    string `json:"reason" yaml:"reason"`
}

// count fills the counts from what the view holds.
func (v *View) count() {
	v.Counts = Counts{Packages: v.Installed, NotCovered: v.NotCovered, NotMatched: len(v.NotMatched)}
	withFix, withUnfixed := map[string]bool{}, map[string]bool{}
	for _, m := range v.Matches {
		key := m.Package + " " + m.Installed
		if m.Status == StatusFixAvailable {
			v.Counts.FixAvailable++
			withFix[key] = true
		} else {
			v.Counts.Unfixed++
			withUnfixed[key] = true
		}
	}
	v.Counts.PackagesWithFix, v.Counts.PackagesWithUnfixed = len(withFix), len(withUnfixed)
}

// WriteText writes v as the vulnerabilities section of a text report: the
// dataset, or why no match was made; the counts; every vulnerability with a
// fix available, one a line; and for the unfixed, a count for each package.
// Every match is in the JSON and YAML reports and the results browser; the
// unfixed are counted here, since a release can carry thousands. This is the
// one text renderer of a match.
func WriteText(w io.Writer, v View) error {
	ew := render.NewErrWriter(w)
	if v.NotDone != "" {
		ew.Printf("%s\n", render.HostText("Matching was not done: "+v.NotDone))
		return ew.Err()
	}
	ew.Printf("%s\n", render.HostText(fmt.Sprintf("Matched against %s, %s, data of %s, %s", v.Dataset, v.Release, v.DataDate, v.State)))
	c := v.Counts
	ew.Printf("%s\n", render.HostText(fmt.Sprintf("%s matched: %s with a fix available in %s, %s in %s, %s not matched, %s no record covers",
		render.Count(c.Packages, "package", "packages"),
		render.Count(c.FixAvailable, "vulnerability", "vulnerabilities"), render.Count(c.PackagesWithFix, "package", "packages"),
		render.Count(c.Unfixed, "unfixed", "unfixed"), render.Count(c.PackagesWithUnfixed, "package", "packages"),
		render.Count(c.NotMatched, "pair", "pairs"), render.Count(c.NotCovered, "package", "packages"))))

	if c.FixAvailable > 0 {
		ew.Printf("\nFix available:\n")
		for _, m := range v.Matches {
			if m.Status == StatusFixAvailable {
				ew.Printf("  %s\n", render.HostText(fmt.Sprintf("%-20s %s %s, fixed in %s%s", m.ID, m.Package, m.Installed, m.Fixed, scores(m.Severity))))
			}
		}
	}
	if c.Unfixed > 0 {
		ew.Printf("\nUnfixed, by package:\n")
		for _, line := range unfixedByPackage(v.Matches) {
			ew.Printf("  %s\n", render.HostText(line))
		}
	}
	if len(v.NotMatched) > 0 {
		ew.Printf("\nNot matched:\n")
		for _, n := range v.NotMatched {
			ew.Printf("  %s\n", render.HostText(fmt.Sprintf("%-20s %s %s: %s", n.ID, n.Package, n.Installed, n.Reason)))
		}
	}
	ew.Printf("\nEvery match, the unfixed included, is in the JSON and YAML reports and the results browser.\n")
	return ew.Err()
}

// unfixedByPackage counts the unfixed vulnerabilities of each package, in the
// order the matches are in.
func unfixedByPackage(matches []Match) []string {
	var lines []string
	var current string
	count := 0
	flush := func() {
		if count > 0 {
			lines = append(lines, fmt.Sprintf("%s: %s", current, render.Count(count, "unfixed", "unfixed")))
		}
	}
	for _, m := range matches {
		if m.Status != StatusUnfixed {
			continue
		}
		key := m.Package + " " + m.Installed
		if key != current {
			flush()
			current, count = key, 0
		}
		count++
	}
	flush()
	return lines
}

// scores writes a match's scores as the records give them, each labeled with
// its type.
func scores(severity []osv.Severity) string {
	if len(severity) == 0 {
		return ""
	}
	parts := make([]string, 0, len(severity))
	for _, s := range severity {
		parts = append(parts, s.Type+" "+s.Score)
	}
	return " [" + strings.Join(parts, "; ") + "]"
}

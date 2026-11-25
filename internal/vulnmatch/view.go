// internal/vulnmatch/view.go

package vulnmatch

import (
	"fmt"
	"io"

	"github.com/papa0four/orkowatch/internal/dataset"
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
// dataset it was made against, or why none was made, then every affected
// package with its vulnerabilities under it, every vulnerability and package
// that could not be judged, and the counts. This is the one shape the
// vulnerabilities section has in every report.
type View struct {
	// Provenance is the dataset matched against, whose version is the
	// release its records are of.
	dataset.Provenance `yaml:",inline"`

	// NotDone says why no match was made, and what to do; a view that has
	// it has nothing else of a match.
	NotDone string `json:"not_done,omitempty" yaml:"not_done,omitempty"`

	// Order is the version order the packages were compared in.
	Order string `json:"version_order,omitempty" yaml:"version_order,omitempty"`

	Counts     Counts           `json:"counts" yaml:"counts"`
	Packages   []PackageMatches `json:"packages" yaml:"packages"`
	NotMatched []NotMatched     `json:"not_matched,omitempty" yaml:"not_matched,omitempty"`

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

// PackageMatches is one affected package: the package as the records name it,
// its installed version, and the installed packages built from it, given
// once, with each of its vulnerabilities under it, those with a fix available
// first.
type PackageMatches struct {
	Package         string          `json:"package" yaml:"package"`
	Installed       string          `json:"installed" yaml:"installed"`
	Binaries        []string        `json:"binaries,omitempty" yaml:"binaries,omitempty"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities" yaml:"vulnerabilities"`
}

// Vulnerability is one vulnerability of a package: its identifier, a CVE or,
// for a record that names none, the record's own; whether a fix is available,
// and the version that fixes it; its severity and what that rests on; its
// scores as the records give them; and the records that name it.
type Vulnerability struct {
	ID       string         `json:"id" yaml:"id"`
	Status   string         `json:"status" yaml:"status"`
	Fixed    string         `json:"fixed,omitempty" yaml:"fixed,omitempty"`
	Severity Severity       `json:"severity" yaml:"severity"`
	Scores   []osv.Severity `json:"scores,omitempty" yaml:"scores,omitempty"`
	Records  []string       `json:"records" yaml:"records"`
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
	for _, pkg := range v.Packages {
		fixable, unfixed := pkg.counts()
		v.Counts.FixAvailable += fixable
		v.Counts.Unfixed += unfixed
		if fixable > 0 {
			v.Counts.PackagesWithFix++
		}
		if unfixed > 0 {
			v.Counts.PackagesWithUnfixed++
		}
	}
}

// counts is how many of the package's vulnerabilities have a fix available,
// and how many are unfixed.
func (p PackageMatches) counts() (fixable, unfixed int) {
	for _, found := range p.Vulnerabilities {
		if found.Status == StatusFixAvailable {
			fixable++
		} else {
			unfixed++
		}
	}
	return fixable, unfixed
}

// WriteText writes v as the vulnerabilities section of a text report: the
// dataset, or why no match was made; the counts; every vulnerability with a
// fix available, one a line led by its severity, the most severe of a package
// first; and for the unfixed, a count for each package.
// Every match is in the JSON and YAML reports and the results browser; the
// unfixed are counted here, since a release can carry thousands. This is the
// one text renderer of a match.
func WriteText(w io.Writer, v View) error {
	ew := render.NewErrWriter(w)
	if v.NotDone != "" {
		ew.Printf("%s\n", render.HostText("Matching was not done: "+v.NotDone))
		return ew.Err()
	}
	ew.Printf("%s\n", render.HostText(fmt.Sprintf("Matched against %s, %s, data of %s, %s", v.ID, v.Version, v.DataDate, v.State)))
	c := v.Counts
	ew.Printf("%s\n", render.HostText(fmt.Sprintf("%s matched: %s with a fix available in %s, %s in %s, %s not matched, %s no record covers",
		render.Count(c.Packages, "package", "packages"),
		render.Count(c.FixAvailable, "vulnerability", "vulnerabilities"), render.Count(c.PackagesWithFix, "package", "packages"),
		render.Count(c.Unfixed, "unfixed", "unfixed"), render.Count(c.PackagesWithUnfixed, "package", "packages"),
		render.Count(c.NotMatched, "pair", "pairs"), render.Count(c.NotCovered, "package", "packages"))))

	if c.FixAvailable > 0 {
		ew.Printf("\nFix available:\n")
		for _, pkg := range v.Packages {
			for _, found := range pkg.Vulnerabilities {
				if found.Status == StatusFixAvailable {
					ew.Printf("  %s\n", render.HostText(fmt.Sprintf("%-11s %-20s %s %s, fixed in %s", severityWord(found.Severity), found.ID, pkg.Package, pkg.Installed, found.Fixed)))
				}
			}
		}
	}
	if c.Unfixed > 0 {
		ew.Printf("\nUnfixed, by package:\n")
		for _, pkg := range v.Packages {
			if _, unfixed := pkg.counts(); unfixed > 0 {
				ew.Printf("  %s\n", render.HostText(fmt.Sprintf("%s %s: %s", pkg.Package, pkg.Installed, render.Count(unfixed, "unfixed", "unfixed"))))
			}
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

// severityWord is a severity as a line of the text report leads with it: the
// source's label, or a dash where none is stated.
func severityWord(s Severity) string {
	if s.Label == "" {
		return "-"
	}
	return s.Label
}

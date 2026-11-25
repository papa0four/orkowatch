// internal/vulnmatch/view.go

package vulnmatch

import (
	"fmt"
	"io"
	"slices"

	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/dataset/kev"
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
	// Use is the dataset matched against, whose version is the release its
	// records are of, or why no match was made and what to do; a view that
	// was not done has nothing else of a match.
	dataset.Use `yaml:",inline"`

	// Order is the version order the packages were compared in.
	Order string `json:"version_order,omitempty" yaml:"version_order,omitempty"`

	// KnownExploited is the catalog of known-exploited vulnerabilities the
	// match was marked from, or why it was not, for a match that was made.
	KnownExploited *dataset.Use `json:"known_exploited_data,omitempty" yaml:"known_exploited_data,omitempty"`

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
// in, those known to be exploited among them, and the pairs not matched.
type Counts struct {
	Packages            int `json:"packages" yaml:"packages"`
	NotCovered          int `json:"packages_not_covered" yaml:"packages_not_covered"`
	FixAvailable        int `json:"fix_available" yaml:"fix_available"`
	PackagesWithFix     int `json:"packages_with_fix_available" yaml:"packages_with_fix_available"`
	Unfixed             int `json:"unfixed" yaml:"unfixed"`
	PackagesWithUnfixed int `json:"packages_with_unfixed" yaml:"packages_with_unfixed"`
	KnownExploited      int `json:"known_exploited" yaml:"known_exploited"`
	NotMatched          int `json:"not_matched" yaml:"not_matched"`
}

// PackageMatches is one affected package: the package as the records name it,
// its installed version, and the installed packages built from it, given
// once, with each of its vulnerabilities under it in the order every view
// lists them.
type PackageMatches struct {
	Package         string          `json:"package" yaml:"package"`
	Installed       string          `json:"installed" yaml:"installed"`
	Binaries        []string        `json:"binaries,omitempty" yaml:"binaries,omitempty"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities" yaml:"vulnerabilities"`
}

// Vulnerability is one vulnerability of a package: its identifier, a CVE or,
// for a record that names none, the record's own; whether a fix is available,
// and the version that fixes it; its severity and what that rests on; its
// scores as the records give them; the records that name it; and, when CISA's
// catalog lists it as known to be exploited, the catalog's entry.
type Vulnerability struct {
	ID             string         `json:"id" yaml:"id"`
	Status         string         `json:"status" yaml:"status"`
	Fixed          string         `json:"fixed,omitempty" yaml:"fixed,omitempty"`
	Severity       Severity       `json:"severity" yaml:"severity"`
	Scores         []osv.Severity `json:"scores,omitempty" yaml:"scores,omitempty"`
	Records        []string       `json:"records" yaml:"records"`
	KnownExploited *kev.Entry     `json:"known_exploited,omitempty" yaml:"known_exploited,omitempty"`
}

// Exploited is a catalog of vulnerabilities known to be exploited, as a
// match is marked from it: the entry of each vulnerability it lists.
type Exploited interface {
	Entry(id string) (kev.Entry, bool)
}

// MarkExploited marks each vulnerability catalog lists with its entry, and
// orders each package's vulnerabilities with those known to be exploited
// first. use is the catalog's data, or why it was not read, in which case
// catalog lists nothing and the view says so.
func (v *View) MarkExploited(catalog Exploited, use dataset.Use) {
	v.KnownExploited = &use
	for i := range v.Packages {
		vulns := v.Packages[i].Vulnerabilities
		for j := range vulns {
			if entry, ok := catalog.Entry(vulns[j].ID); ok {
				vulns[j].KnownExploited = &entry
			}
		}
		slices.SortFunc(vulns, vulnerabilityOrder)
	}
	v.count()
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
		fixable, unfixed, known := pkg.counts()
		v.Counts.FixAvailable += fixable
		v.Counts.Unfixed += unfixed
		v.Counts.KnownExploited += known
		if fixable > 0 {
			v.Counts.PackagesWithFix++
		}
		if unfixed > 0 {
			v.Counts.PackagesWithUnfixed++
		}
	}
}

// counts is how many of the package's vulnerabilities have a fix available,
// how many are unfixed, and how many are known to be exploited.
func (p PackageMatches) counts() (fixable, unfixed, known int) {
	for _, found := range p.Vulnerabilities {
		if found.KnownExploited != nil {
			known++
		}
		if found.Status == StatusFixAvailable {
			fixable++
		} else {
			unfixed++
		}
	}
	return fixable, unfixed, known
}

// WriteText writes v as the vulnerabilities section of a text report: the
// dataset, or why no match was made; the counts; every vulnerability known to
// be exploited, fixed or not, or why that was not read; the rest of those with
// a fix available, one a line led by its severity; and for the unfixed, a
// count for each package. Both lists are in the order every view lists
// vulnerabilities.
// Every match is in the JSON and YAML reports and the results browser; the
// unfixed are counted here, since a release can carry thousands. This is the
// one text renderer of a match.
func WriteText(w io.Writer, v View) error {
	ew := render.NewErrWriter(w)
	if v.NotDone != "" {
		ew.Printf("%s\n", render.HostText("Matching was not done: "+v.NotDone))
		return ew.Err()
	}
	ew.Printf("%s\n", render.HostText("Matched against "+v.About()))
	c := v.Counts
	ew.Printf("%s\n", render.HostText(fmt.Sprintf("%s matched: %s with a fix available in %s, %s in %s, %s not matched, %s no record covers",
		render.Count(c.Packages, "package", "packages"),
		render.Count(c.FixAvailable, "vulnerability", "vulnerabilities"), render.Count(c.PackagesWithFix, "package", "packages"),
		render.Count(c.Unfixed, "unfixed", "unfixed"), render.Count(c.PackagesWithUnfixed, "package", "packages"),
		render.Count(c.NotMatched, "pair", "pairs"), render.Count(c.NotCovered, "package", "packages"))))

	writeKnownExploited(ew, v)
	writeFixAvailable(ew, v)
	if c.Unfixed > 0 {
		ew.Printf("\nUnfixed, by package:\n")
		for _, pkg := range v.Packages {
			if _, unfixed, _ := pkg.counts(); unfixed > 0 {
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

// Listed is one vulnerability of an affected package.
type Listed struct {
	Package       PackageMatches
	Vulnerability Vulnerability
}

// InOrder is every vulnerability of v's affected packages across packages,
// in the order a package lists its own; one named in several packages keeps
// the order of its packages.
func (v View) InOrder() []Listed {
	var all []Listed
	for _, pkg := range v.Packages {
		for _, found := range pkg.Vulnerabilities {
			all = append(all, Listed{pkg, found})
		}
	}
	slices.SortStableFunc(all, func(a, b Listed) int { return vulnerabilityOrder(a.Vulnerability, b.Vulnerability) })
	return all
}

// writeFixAvailable writes the vulnerabilities of v with a fix available that
// are not known to be exploited, which are listed before them, one a line led
// by its severity.
func writeFixAvailable(ew *render.ErrWriter, v View) {
	var lines []string
	for _, l := range v.InOrder() {
		if found := l.Vulnerability; found.Status == StatusFixAvailable && found.KnownExploited == nil {
			lines = append(lines, fmt.Sprintf("%-11s %-20s %s %s, fixed in %s", severityWord(found.Severity), found.ID, l.Package.Package, l.Package.Installed, found.Fixed))
		}
	}
	if len(lines) == 0 {
		return
	}
	ew.Printf("\nFix available:\n")
	for _, line := range lines {
		ew.Printf("  %s\n", render.HostText(line))
	}
}

// writeKnownExploited writes the vulnerabilities of v the catalog of
// known-exploited vulnerabilities lists, fixed or not, under the catalog's
// data and attribution; that none is listed; or why the
// catalog was not read.
func writeKnownExploited(ew *render.ErrWriter, v View) {
	catalog := v.KnownExploited
	switch {
	case catalog == nil:
		return
	case catalog.NotDone != "":
		ew.Printf("\n%s\n", render.HostText("Known exploitation was not read: "+catalog.NotDone))
		return
	case v.Counts.KnownExploited == 0:
		ew.Printf("\n%s\n", render.HostText("None is known to be exploited, by "+catalog.About()+"."))
		return
	}

	ew.Printf("\n%s\n", render.HostText(fmt.Sprintf("%s, by %s:",
		render.Count(v.Counts.KnownExploited, "vulnerability known to be exploited", "vulnerabilities known to be exploited"), catalog.About())))
	for _, l := range v.InOrder() {
		found := l.Vulnerability
		if found.KnownExploited == nil {
			break
		}
		state := "unfixed"
		if found.Status == StatusFixAvailable {
			state = "fixed in " + found.Fixed
		}
		ew.Printf("  %s\n", render.HostText(fmt.Sprintf("%-11s %-20s %s %s, %s; added %s, ransomware use %s",
			severityWord(found.Severity), found.ID, l.Package.Package, l.Package.Installed, state, found.KnownExploited.Added, found.KnownExploited.Ransomware)))
	}
	if catalog.Attribution != "" {
		ew.Printf("  %s\n", render.HostText(catalog.Attribution))
	}
}

// severityWord is a severity as a line of the text report leads with it: the
// source's label, or a dash where none is stated.
func severityWord(s Severity) string {
	if s.Label == "" {
		return "-"
	}
	return s.Label
}

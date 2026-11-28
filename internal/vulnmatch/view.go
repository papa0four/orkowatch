// internal/vulnmatch/view.go

package vulnmatch

import (
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/dataset/epss"
	"github.com/papa0four/orkowatch/internal/dataset/kev"
	"github.com/papa0four/orkowatch/internal/render"
	"github.com/papa0four/orkowatch/internal/vulnrecord"
)

// The status of a match.
const (
	// StatusFixAvailable is a package below the version that fixes the
	// vulnerability.
	StatusFixAvailable = "fix available"

	// StatusUnfixed is a package in a range no record gives a fixed version
	// for.
	StatusUnfixed = "unfixed"

	// StatusTracked is a package a record only tracks the vulnerability
	// against, as an open tracking bug does, which no other record affects
	// or clears: it says the vulnerability is tracked, not that the package
	// is affected.
	StatusTracked = "tracking bug open"
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

	// Also is each further dataset the match read records from beside the
	// one it is of, such as a release's tracking bugs, or why it read
	// nothing from one.
	Also []dataset.Use `json:"also_matched_against,omitempty" yaml:"also_matched_against,omitempty"`

	// KnownExploited is the catalog of known-exploited vulnerabilities the
	// match was marked from, or why it was not, for a match that was made.
	KnownExploited *dataset.Use `json:"known_exploited_data,omitempty" yaml:"known_exploited_data,omitempty"`

	// ExploitPrediction is the EPSS scores file the match was scored from, or
	// why it was not, for a match that was made.
	ExploitPrediction *dataset.Use `json:"exploit_prediction_data,omitempty" yaml:"exploit_prediction_data,omitempty"`

	// Systems are the units of the host's system the match judged, whether
	// or not any vulnerability was found in them, so a report says the
	// system was judged when nothing was found in it.
	Systems []System `json:"systems,omitempty" yaml:"systems,omitempty"`

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
	Tracked             int `json:"tracking_bugs_open,omitempty" yaml:"tracking_bugs_open,omitempty"`
	PackagesWithTracked int `json:"packages_with_tracking_bugs_open,omitempty" yaml:"packages_with_tracking_bugs_open,omitempty"`
	KnownExploited      int `json:"known_exploited" yaml:"known_exploited"`
	NotMatched          int `json:"not_matched" yaml:"not_matched"`
}

// PackageMatches is one affected package: the package as the records name it,
// its installed version, and the installed packages built from it, given
// once, with each of its vulnerabilities under it in the order every view
// lists them. System is set for a unit of the host's system, such as Windows
// at its build, which is not an installed package.
type PackageMatches struct {
	Package         string          `json:"package" yaml:"package"`
	Installed       string          `json:"installed" yaml:"installed"`
	System          bool            `json:"system,omitempty" yaml:"system,omitempty"`
	Binaries        []string        `json:"binaries,omitempty" yaml:"binaries,omitempty"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities" yaml:"vulnerabilities"`
}

// System is a unit of the host's system a match judged, such as Windows at
// its build, named as the records name it.
type System struct {
	Name      string `json:"name" yaml:"name"`
	Installed string `json:"installed" yaml:"installed"`
}

// Vulnerability is one vulnerability of a package: its identifier, a CVE or,
// for a record that names none, the record's own; whether a fix is available,
// and the version that fixes it; its severity and what that rests on; its
// scores as the records give them; the records that name it; when CISA's
// catalog lists it as known to be exploited, the catalog's entry; and when
// EPSS scores it, its score and percentile.
type Vulnerability struct {
	ID                string             `json:"id" yaml:"id"`
	Status            string             `json:"status" yaml:"status"`
	Fixed             string             `json:"fixed,omitempty" yaml:"fixed,omitempty"`
	Severity          Severity           `json:"severity" yaml:"severity"`
	Scores            []vulnrecord.Score `json:"scores,omitempty" yaml:"scores,omitempty"`
	Records           []string           `json:"records" yaml:"records"`
	KnownExploited    *kev.Entry         `json:"known_exploited,omitempty" yaml:"known_exploited,omitempty"`
	ExploitPrediction *epss.Prediction   `json:"exploit_prediction,omitempty" yaml:"exploit_prediction,omitempty"`
}

// Exploited is a catalog of vulnerabilities known to be exploited, as a
// match is marked from it: the entry of each vulnerability it lists.
type Exploited interface {
	Entry(id string) (kev.Entry, bool)
}

// Predictions is a file of exploit prediction scores, as a match is scored
// from it: the prediction of each vulnerability it scores.
type Predictions interface {
	Prediction(id string) (epss.Prediction, bool)
}

// MarkExploited marks each vulnerability catalog lists with its entry. use is
// the catalog's data, or why it was not read, in which case catalog lists
// nothing and the view says so.
func (v *View) MarkExploited(catalog Exploited, use dataset.Use) {
	v.KnownExploited = &use
	for i := range v.Packages {
		vulns := v.Packages[i].Vulnerabilities
		for j := range vulns {
			if entry, ok := catalog.Entry(vulns[j].ID); ok {
				vulns[j].KnownExploited = &entry
			}
		}
	}
	v.arrange()
}

// MarkPredicted gives each vulnerability scores holds its prediction. use is
// the file's data, or why it was not read, in which case scores holds nothing
// and the view says so.
func (v *View) MarkPredicted(scores Predictions, use dataset.Use) {
	v.ExploitPrediction = &use
	for i := range v.Packages {
		vulns := v.Packages[i].Vulnerabilities
		for j := range vulns {
			if p, ok := scores.Prediction(vulns[j].ID); ok {
				vulns[j].ExploitPrediction = &p
			}
		}
	}
	v.arrange()
}

// arrange puts each package's vulnerabilities in the order every view lists
// them and fills the counts, after a mark that changes either.
func (v *View) arrange() {
	for i := range v.Packages {
		slices.SortFunc(v.Packages[i].Vulnerabilities, vulnerabilityOrder)
	}
	v.count()
}

// NotMatched is a vulnerability of an installed package that could not be
// judged, and why. System is set for a unit of the host's system, such as
// Windows at its build, which is not an installed package.
type NotMatched struct {
	ID        string `json:"id" yaml:"id"`
	Package   string `json:"package" yaml:"package"`
	Installed string `json:"installed" yaml:"installed"`
	System    bool   `json:"system,omitempty" yaml:"system,omitempty"`
	Reason    string `json:"reason" yaml:"reason"`
}

// count fills the counts from what the view holds. The vulnerability totals
// count the host's system's; the package counts do not.
func (v *View) count() {
	v.Counts = Counts{Packages: v.Installed, NotCovered: v.NotCovered, NotMatched: len(v.NotMatched)}
	for _, pkg := range v.Packages {
		c := pkg.counts()
		v.Counts.FixAvailable += c.fixable
		v.Counts.Unfixed += c.unfixed
		v.Counts.Tracked += c.tracked
		v.Counts.KnownExploited += c.known
		if pkg.System {
			continue
		}
		if c.fixable > 0 {
			v.Counts.PackagesWithFix++
		}
		if c.unfixed > 0 {
			v.Counts.PackagesWithUnfixed++
		}
		if c.tracked > 0 {
			v.Counts.PackagesWithTracked++
		}
	}
}

// statusCounts is how many of a package's vulnerabilities have a fix
// available, are unfixed, or have a tracking bug open, and how many are known
// to be exploited.
type statusCounts struct {
	fixable, unfixed, tracked, known int
}

// counts counts the package's vulnerabilities by their status.
func (p PackageMatches) counts() statusCounts {
	var c statusCounts
	for _, found := range p.Vulnerabilities {
		if found.KnownExploited != nil {
			c.known++
		}
		switch found.Status {
		case StatusFixAvailable:
			c.fixable++
		case StatusTracked:
			c.tracked++
		default:
			c.unfixed++
		}
	}
	return c
}

// WriteText writes v as the vulnerabilities section of a text report: the
// dataset, or why no match was made; each unit of the host's system on its own
// line, and the packages' counts, left out when the match judged the system
// alone; the EPSS scores file, or why
// it was not read; every vulnerability known to be exploited, fixed or not, or
// why that was not read; the rest of those with a fix available, one a line
// led by its severity and, when the scores were read, its EPSS score; and for
// the unfixed, a count for each package. Both lists are in the order every
// view lists vulnerabilities.
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
	for _, also := range v.Also {
		if also.NotDone != "" {
			ew.Printf("%s\n", render.HostText("Also not read: "+also.NotDone))
			continue
		}
		ew.Printf("%s\n", render.HostText("Also matched against "+also.About()))
		if also.Attribution != "" {
			ew.Printf("  %s\n", render.HostText(also.Attribution))
		}
	}
	for _, s := range v.Systems {
		ew.Printf("%s\n", render.HostText(systemLine(v, s)))
	}
	c := v.Counts
	if c.Packages > 0 || len(v.Systems) == 0 {
		ew.Printf("%s\n", render.HostText(fmt.Sprintf("%s matched: %s with a fix available in %s, %s in %s, %s not matched, %s no record covers",
			render.Count(c.Packages, "package", "packages"),
			render.Count(c.FixAvailable, "vulnerability", "vulnerabilities"), render.Count(c.PackagesWithFix, "package", "packages"),
			render.Count(c.Unfixed, "unfixed", "unfixed"), render.Count(c.PackagesWithUnfixed, "package", "packages"),
			render.Count(c.NotMatched, "pair", "pairs"), render.Count(c.NotCovered, "package", "packages"))))
	}

	writePredicted(ew, v)
	writeKnownExploited(ew, v)
	writeFixAvailable(ew, v)
	if c.Unfixed > 0 {
		ew.Printf("\nUnfixed, by package:\n")
		for _, pkg := range v.Packages {
			if unfixed := pkg.counts().unfixed; unfixed > 0 {
				ew.Printf("  %s\n", render.HostText(fmt.Sprintf("%s %s: %s", pkg.Package, pkg.Installed, render.Count(unfixed, "unfixed", "unfixed"))))
			}
		}
	}
	writeTracked(ew, v)
	if len(v.NotMatched) > 0 {
		ew.Printf("\nNot matched:\n")
		for _, n := range v.NotMatched {
			ew.Printf("  %s\n", render.HostText(fmt.Sprintf("%-20s %s %s: %s", n.ID, n.Package, n.Installed, n.Reason)))
		}
	}
	ew.Printf("\nEvery match, the unfixed included, is in the JSON and YAML reports and the results browser.\n")
	return ew.Err()
}

// systemLine is a unit of the host's system on the line the text report gives
// it: what was found in it, or that nothing was, which does not say it has
// nothing.
func systemLine(v View, s System) string {
	for _, pkg := range v.Packages {
		if pkg.System && pkg.Package == s.Name && pkg.Installed == s.Installed {
			c := pkg.counts()
			found := render.Count(c.fixable, "vulnerability", "vulnerabilities") + " with a fix available, " + render.Count(c.unfixed, "unfixed", "unfixed")
			if c.tracked > 0 {
				found += ", " + render.Count(c.tracked, "tracking bug open", "tracking bugs open")
			}
			return fmt.Sprintf("The system, %s %s: %s", s.Name, s.Installed, found)
		}
	}
	return fmt.Sprintf("The system, %s %s: no vulnerability matched; this does not say it has none", s.Name, s.Installed)
}

// Summary is the match on one line, as a run's account of its modules states
// it: the dataset matched against and what was found, the known exploited
// counted only when the catalog was read; or why no match was made.
func (v View) Summary() string {
	if v.NotDone != "" {
		return "matching was not done: " + v.NotDone
	}
	c := v.Counts
	found := []string{
		render.Count(c.FixAvailable, "vulnerability", "vulnerabilities") + " with a fix available",
		render.Count(c.Unfixed, "unfixed", "unfixed"),
	}
	if c.Tracked > 0 {
		found = append(found, render.Count(c.Tracked, "tracking bug open", "tracking bugs open"))
	}
	if v.KnownExploited != nil && v.KnownExploited.NotDone == "" {
		found = append(found, render.Count(c.KnownExploited, "known exploited", "known exploited"))
	}
	return "matched against " + v.ID + ": " + strings.Join(found, ", ")
}

// writeTracked writes each vulnerability of v a tracking bug is open for,
// with the records that track it: that the vulnerability is tracked against
// the package, which does not say the package is affected.
func writeTracked(ew *render.ErrWriter, v View) {
	if v.Counts.Tracked == 0 {
		return
	}
	ew.Printf("\n%s\n", render.HostText(fmt.Sprintf("Tracking bugs open, %s in %s; a bug says a vulnerability is tracked against a package, not that the package is affected:",
		render.Count(v.Counts.Tracked, "vulnerability", "vulnerabilities"), render.Count(v.Counts.PackagesWithTracked, "package", "packages"))))
	for _, l := range v.InOrder() {
		if found := l.Vulnerability; found.Status == StatusTracked {
			ew.Printf("  %s\n", render.HostText(fmt.Sprintf("%-20s %s %s, %s", found.ID, l.Package.Package, l.Package.Installed, strings.Join(found.Records, ", "))))
		}
	}
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
			lines = append(lines, fmt.Sprintf("%-11s %s%-20s %s %s, fixed in %s", severityWord(found.Severity), predictionColumn(v, found), found.ID, l.Package.Package, l.Package.Installed, found.Fixed))
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
		state := found.Status
		if found.Status == StatusFixAvailable {
			state = "fixed in " + found.Fixed
		}
		ew.Printf("  %s\n", render.HostText(fmt.Sprintf("%-11s %s%-20s %s %s, %s; added %s, ransomware use %s",
			severityWord(found.Severity), predictionColumn(v, found), found.ID, l.Package.Package, l.Package.Installed, state, found.KnownExploited.Added, found.KnownExploited.Ransomware)))
	}
	if catalog.Attribution != "" {
		ew.Printf("  %s\n", render.HostText(catalog.Attribution))
	}
}

// writePredicted writes the EPSS scores file v was scored from, with the
// attribution FIRST asks for, or why it was not read.
func writePredicted(ew *render.ErrWriter, v View) {
	scores := v.ExploitPrediction
	switch {
	case scores == nil:
		return
	case scores.NotDone != "":
		ew.Printf("\n%s\n", render.HostText("Exploit prediction was not read: "+scores.NotDone))
		return
	}
	ew.Printf("\n%s\n", render.HostText("Exploit prediction scored by "+scores.About()+"."))
	if scores.Attribution != "" {
		ew.Printf("  %s\n", render.HostText(scores.Attribution))
	}
}

// PredictionWord is the EPSS score of found as every view puts it beside the
// severity, or a dash where the file gives none. It is empty when no scores
// were read, so that a file not read is not taken for one that scores
// nothing.
func (v View) PredictionWord(found Vulnerability) string {
	if v.ExploitPrediction == nil || v.ExploitPrediction.NotDone != "" {
		return ""
	}
	if found.ExploitPrediction == nil {
		return "EPSS -"
	}
	return "EPSS " + epss.Percent(found.ExploitPrediction.Score)
}

// predictionColumn is the EPSS column of a line of the text report, with its
// trailing space, or nothing when no scores were read.
func predictionColumn(v View, found Vulnerability) string {
	word := v.PredictionWord(found)
	if word == "" {
		return ""
	}
	return fmt.Sprintf("%-12s ", word)
}

// severityWord is a severity as a line of the text report leads with it: the
// source's label, or a dash where none is stated.
func severityWord(s Severity) string {
	if s.Label == "" {
		return "-"
	}
	return s.Label
}

// internal/vulnmatch/match.go

// Package vulnmatch matches the packages installed on a host against a
// distribution's security records, and states what it found: which packages
// are affected by which CVEs, with the version that fixes each or none, which
// it could not judge and why, and which no record covers. A package is never
// called clean: one no record names is not covered, which is not the same.
package vulnmatch

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/papa0four/orkowatch/internal/dataset/osv"
	"github.com/papa0four/orkowatch/internal/pkgversion"
	"github.com/papa0four/orkowatch/internal/softwarelist"
)

// moduleMarks are what the release of a package built for a module stream
// holds: .module_el on AlmaLinux and .module+el on Rocky Linux and Red Hat,
// as in 1:20.20.2-1.module_el9.7.0+226+88d36870. The records of several
// streams name one package, and do not say which stream each fix is for.
var moduleMarks = []string{".module_el", ".module+el"}

// versionOrders are the version orders of the managers whose packages
// distributions' records name.
var versionOrders = map[string]pkgversion.Compare{
	softwarelist.ManagerDpkg: pkgversion.Dpkg,
	softwarelist.ManagerRPM:  pkgversion.RPM,
	softwarelist.ManagerAPK:  pkgversion.APK,
}

// Matcher matches one manager's installed packages against records given one
// at a time, so the records are never held together.
type Matcher struct {
	manager   string
	compare   pkgversion.Compare
	installed map[string][]*unit
	pairs     map[pairKey]*pair
}

// unit is a package as the records name it, at one installed version: the
// source package on dpkg and apk, whose records name sources, and the binary
// package on rpm, whose records name binaries.
type unit struct {
	name     string
	version  string
	binaries []string
	covered  bool
}

// pairKey is one vulnerability and one installed unit.
type pairKey struct {
	id      string
	name    string
	version string
}

// pair is what every record naming one vulnerability and one unit said.
type pair struct {
	judgments []judgment
	fixes     []string
	records   []string
	severity  []osv.Severity
	ratings   []string
	err       string
}

// New returns a matcher of the packages in entries that manager installed. A
// manager whose version order is not known cannot be matched.
func New(manager string, entries []softwarelist.SoftwareEntry) (*Matcher, error) {
	compare, ok := versionOrders[manager]
	if !ok {
		return nil, fmt.Errorf("no version order is known for packages of %q", manager)
	}
	m := &Matcher{manager: manager, compare: compare, installed: map[string][]*unit{}, pairs: map[pairKey]*pair{}}
	for _, e := range entries {
		if e.Manager != manager {
			continue
		}
		name, version := Named(e)
		at := slices.IndexFunc(m.installed[name], func(u *unit) bool { return u.version == version })
		if at < 0 {
			m.installed[name] = append(m.installed[name], &unit{name: name, version: version})
			at = len(m.installed[name]) - 1
		}
		u := m.installed[name][at]
		if !slices.Contains(u.binaries, e.Name) {
			u.binaries = append(u.binaries, e.Name)
		}
	}
	return m, nil
}

// Named is the name and version of entry as its manager's records name it:
// the source package and its version where the manager states them, the
// entry's own otherwise. rpm's records name binary packages, and its entries
// state no source version.
func Named(e softwarelist.SoftwareEntry) (string, string) {
	if e.Manager == softwarelist.ManagerRPM {
		return e.Name, e.Version
	}
	name, version := e.Name, e.Version
	if e.Source != "" {
		name = e.Source
	}
	if e.SourceVersion != "" {
		version = e.SourceVersion
	}
	return name, version
}

// Add judges one record against the installed packages it names.
func (m *Matcher) Add(r osv.Record) error {
	ids := r.CVEs
	if len(ids) == 0 {
		ids = []string{r.ID}
	}
	for _, a := range r.Affected {
		for _, u := range m.installed[a.Package] {
			u.covered = true
			j, err := judge(u.version, a.Ranges, m.compare)
			for _, id := range ids {
				m.pair(pairKey{id: id, name: u.name, version: u.version}).note(r, a, j, err)
			}
		}
	}
	return nil
}

// note records what r said of the pair through its package a: the record,
// and its judgment, fixed versions, and scores, or that the versions could
// not be compared.
func (p *pair) note(r osv.Record, a osv.Affected, j judgment, err error) {
	if !slices.Contains(p.records, r.ID) {
		p.records = append(p.records, r.ID)
	}
	if err != nil {
		p.err = cmp.Or(p.err, err.Error())
		return
	}
	p.judgments = append(p.judgments, j)
	p.fixes = appendNew(p.fixes, fixedIn(a.Ranges)...)
	if r.Rating != "" {
		p.ratings = appendNew(p.ratings, r.Rating)
	}
	for _, s := range r.Severity {
		if !slices.Contains(p.severity, s) {
			p.severity = append(p.severity, s)
		}
	}
}

// pair returns the pair of key, made when it is new.
func (m *Matcher) pair(key pairKey) *pair {
	p, ok := m.pairs[key]
	if !ok {
		p = &pair{}
		m.pairs[key] = p
	}
	return p
}

// Result is what the records given said of the installed packages. For each
// vulnerability and package, a record whose fix is installed clears it: a
// package at or above the lowest fixed version any record gives is not
// affected. Otherwise one in a range of a record is affected, with the lowest
// fixed version above it, or unfixed when no record gives one. A version that
// cannot be ordered, and a module build whose records give more than one
// fixed version, are not matched, with the reason.
func (m *Matcher) Result() View {
	v := View{Order: m.manager, Packages: []PackageMatches{}}
	for _, units := range m.installed {
		for _, u := range units {
			v.Installed++
			if !u.covered {
				v.NotCovered++
			}
		}
	}
	affected := map[unitKey]*PackageMatches{}
	for key, p := range m.pairs {
		switch {
		case p.err != "":
			v.NotMatched = append(v.NotMatched, NotMatched{ID: key.id, Package: key.name, Installed: key.version, Reason: "the versions cannot be compared: " + p.err})
		case isModuleBuild(key.version) && len(p.fixes) > 1:
			v.NotMatched = append(v.NotMatched, NotMatched{ID: key.id, Package: key.name, Installed: key.version,
				Reason: fmt.Sprintf("a module build, and the records give %d fixed versions without saying which module stream each is for", len(p.fixes))})
		default:
			found, ok, err := m.decide(key, p)
			switch {
			case err != nil:
				v.NotMatched = append(v.NotMatched, NotMatched{ID: key.id, Package: key.name, Installed: key.version, Reason: "the versions cannot be compared: " + err.Error()})
			case ok:
				m.packageOf(affected, key).Vulnerabilities = append(m.packageOf(affected, key).Vulnerabilities, found)
			}
		}
	}
	for _, pkg := range affected {
		slices.SortFunc(pkg.Vulnerabilities, vulnerabilityOrder)
		v.Packages = append(v.Packages, *pkg)
	}
	slices.SortFunc(v.Packages, func(a, b PackageMatches) int {
		return cmp.Or(strings.Compare(a.Package, b.Package), strings.Compare(a.Installed, b.Installed))
	})
	slices.SortFunc(v.NotMatched, func(a, b NotMatched) int {
		return cmp.Or(strings.Compare(a.Package, b.Package), strings.Compare(a.Installed, b.Installed), strings.Compare(a.ID, b.ID))
	})
	v.count()
	return v
}

// statusOrder puts the vulnerabilities with a fix available ahead of the
// unfixed.
var statusOrder = map[string]string{StatusFixAvailable: "0", StatusUnfixed: "1"}

// vulnerabilityOrder is the order of a package's vulnerabilities. Those known
// to be exploited come first, the most severe of them first, since a
// vulnerability exploited now outranks its score. The rest follow, those with
// a fix available ahead of the unfixed and the most severe first within each.
func vulnerabilityOrder(a, b Vulnerability) int {
	known := func(v Vulnerability) int {
		if v.KnownExploited != nil {
			return 0
		}
		return 1
	}
	if c := cmp.Compare(known(a), known(b)); c != 0 {
		return c
	}
	severity := cmp.Compare(rank(a.Severity.Level), rank(b.Severity.Level))
	status := strings.Compare(statusOrder[a.Status], statusOrder[b.Status])
	if a.KnownExploited != nil {
		return cmp.Or(severity, status, strings.Compare(a.ID, b.ID))
	}
	return cmp.Or(status, severity, strings.Compare(a.ID, b.ID))
}

// unitKey is an installed package as the records name it, at one version.
type unitKey struct {
	name    string
	version string
}

// packageOf returns the affected package of key in affected, made with the
// binaries built from it when it is new.
func (m *Matcher) packageOf(affected map[unitKey]*PackageMatches, key pairKey) *PackageMatches {
	k := unitKey{name: key.name, version: key.version}
	pkg, ok := affected[k]
	if !ok {
		pkg = &PackageMatches{Package: key.name, Installed: key.version}
		if u := m.unit(key); u != nil {
			pkg.Binaries = u.binaries
		}
		affected[k] = pkg
	}
	return pkg
}

// decide is the vulnerability the judgments of one pair make, if they make
// one. Fixed versions that cannot be ordered among themselves are an error.
func (m *Matcher) decide(key pairKey, p *pair) (Vulnerability, bool, error) {
	var above []string
	in := false
	for _, j := range p.judgments {
		switch j.verdict {
		case cleared:
			return Vulnerability{}, false, nil
		case inside:
			in = true
			above = append(above, j.above...)
		}
	}
	if !in {
		return Vulnerability{}, false, nil
	}
	found := Vulnerability{ID: key.id, Status: StatusUnfixed, Severity: severityOf(p.severity, p.ratings), Scores: p.severity, Records: p.records}
	if len(above) > 0 {
		lowest, err := m.lowest(above)
		if err != nil {
			return Vulnerability{}, false, err
		}
		found.Fixed, found.Status = lowest, StatusFixAvailable
	}
	return found, true, nil
}

// lowest is the lowest of versions, which holds at least one.
func (m *Matcher) lowest(versions []string) (string, error) {
	low := versions[0]
	for _, v := range versions[1:] {
		at, err := order(v, low, m.compare)
		if err != nil {
			return "", err
		}
		if at < 0 {
			low = v
		}
	}
	return low, nil
}

// unit returns the installed unit of key.
func (m *Matcher) unit(key pairKey) *unit {
	for _, u := range m.installed[key.name] {
		if u.version == key.version {
			return u
		}
	}
	return nil
}

// isModuleBuild reports whether version is a package built for a module
// stream.
func isModuleBuild(version string) bool {
	return slices.ContainsFunc(moduleMarks, func(mark string) bool { return strings.Contains(version, mark) })
}

// fixedIn lists the fixed versions ranges give.
func fixedIn(ranges [][]osv.Event) []string {
	var fixes []string
	for _, events := range ranges {
		for _, e := range events {
			if v, ok := e[eventFixed]; ok {
				fixes = appendNew(fixes, v)
			}
		}
	}
	return fixes
}

// appendNew appends to list each of values it does not hold.
func appendNew(list []string, values ...string) []string {
	for _, v := range values {
		if !slices.Contains(list, v) {
			list = append(list, v)
		}
	}
	return list
}

// internal/dataset/vuxml/vuxml.go

// Package vuxml reads VuXML, the FreeBSD project's document of the
// vulnerabilities of the Ports Collection, which pkg audit reads, as the
// dataset a FreeBSD host's packages are matched against. The file is kept as
// fetched, the same bytes pkg audit reads, and read as a stream of entries on
// each run.
package vuxml

import (
	"compress/bzip2"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/dataset/xmldoc"
	"github.com/papa0four/orkowatch/internal/osfingerprint"
	"github.com/papa0four/orkowatch/internal/pkgversion"
	"github.com/papa0four/orkowatch/internal/softwarelist"
	"github.com/papa0four/orkowatch/internal/vulnrecord"
)

const (
	id      = "vuxml"
	address = "https://vuxml.freebsd.org/freebsd/vuln.xml.bz2"

	// maxBytes bounds the file fetched and kept. It was 1.4 MiB on
	// 2026-11-26.
	maxBytes = 8 << 20

	// maxExpanded bounds what the file may expand to. It was 10.1 MiB on
	// 2026-11-26.
	maxExpanded = 64 << 20

	// namespace is the namespace of VuXML's own elements.
	namespace = "http://www.vuxml.org/apps/vuxml-1"

	// release is what a match against VuXML is of: one document serves
	// every FreeBSD release, so every FreeBSD host's match carries it, and
	// a saved FreeBSD report is judged by it.
	release = "FreeBSD ports"

	// entryPage is where VuXML publishes each entry, the address pkg audit
	// prints for it.
	entryPage = "https://vuxml.FreeBSD.org/freebsd/"

	license     = "BSD 2-clause"
	attribution = "VuXML, the FreeBSD Ports Collection's vulnerability document, https://vuxml.freebsd.org, " +
		"copyright Jacques Vidrine and contributors"

	// day is how VuXML writes a date.
	day = "2006-01-02"
)

// vidPattern is an entry's identifier, a UUID, which the address of its page
// is built from.
var vidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// kinds are the bounds of a range each of VuXML's range elements states.
var kinds = map[string]vulnrecord.Kind{
	"ge": vulnrecord.From,
	"gt": vulnrecord.After,
	"lt": vulnrecord.Before,
	"le": vulnrecord.UpTo,
	"eq": vulnrecord.Exactly,
}

type (
	// Document is VuXML as a dataset.
	Document struct{}

	// entry is one vuln element: its identifier, whether it was
	// cancelled, the packages it affects, the CVEs it names, and its
	// dates. Its description is not kept.
	entry struct {
		VID       string     `xml:"vid,attr"`
		Cancelled *struct{}  `xml:"cancelled"`
		Packages  []packages `xml:"affects>package"`
		CVEs      []string   `xml:"references>cvename"`
		Discovery string     `xml:"dates>discovery"`
		Entered   string     `xml:"dates>entry"`
		Modified  string     `xml:"dates>modified"`
	}

	// packages is one package element: the names of the packages it
	// covers and their ranges.
	packages struct {
		Names  []string `xml:"name"`
		Ranges []bounds `xml:"range"`
	}

	// bounds is one range element and the bounds it holds, in their order.
	bounds struct {
		Bounds []bound `xml:",any"`
	}

	// bound is one bound of a range, as its element names it, and its
	// version.
	bound struct {
		XMLName xml.Name
		Version string `xml:",chardata"`
	}
)

// ID names the dataset.
func (Document) ID() string { return id }

// AppliesTo reports whether host runs FreeBSD, whose packages VuXML covers.
func (Document) AppliesTo(host *osfingerprint.OSInfo) bool {
	return host != nil && host.OS == "freebsd"
}

// Gives is what the document gives a run: the installed packages matched
// against the Ports Collection's vulnerabilities.
func (Document) Gives() string { return "matching of the installed packages" }

// MaxBytes is the most the file may hold.
func (Document) MaxBytes() int64 { return maxBytes }

// Origin is the document as vuxml.freebsd.org publishes it, compressed with
// bzip2, one for every FreeBSD release.
func (Document) Origin(*osfingerprint.OSInfo) dataset.Origin {
	return dataset.Origin{URL: address, License: license, Attribution: attribution}
}

// Manager is the package manager whose packages the document names, and so
// whose version order its ranges are in.
func (Document) Manager() string { return softwarelist.ManagerPkg }

// Combining is how the document's entries of one vulnerability combine: a
// version any entry's range holds is affected, as pkg audit judges it, since
// a later entry widens what an earlier one covered and one entry can name a
// package in two places.
func (Document) Combining() vulnrecord.Combining { return vulnrecord.AnyRange }

// Systems is none: the document names ports, not the base system, and no
// machine-readable source of the base system's vulnerabilities is chosen.
func (Document) Systems(*osfingerprint.OSInfo) []softwarelist.SoftwareEntry { return nil }

// Release is the name of what a match of host reads, the Version that match
// carries: the one document of every FreeBSD release.
func (d Document) Release(host *osfingerprint.OSInfo) (string, error) {
	if !d.AppliesTo(host) {
		return "", errors.New("vuxml is for FreeBSD hosts")
	}
	return release, nil
}

// Check reads the document whole and refuses it unless it is VuXML in the
// form vuxml.freebsd.org publishes. It gives the newest date the entries give
// as the data's date, and the document's release as its version.
func (d Document) Check(data io.Reader, host *osfingerprint.OSInfo) (dataset.Facts, error) {
	return d.Records(data, host, nil)
}

// Records is Check that gives each entry to each, in the form matching
// reads, as it is read, so the entries are read once and never held
// together. The entries are sound only when Records returns no error: one
// that fails after some were given means none of them may be used. An error
// each returns ends the read. A cancelled entry is not given.
func (d Document) Records(data io.Reader, host *osfingerprint.OSInfo, each func(vulnrecord.Record) error) (dataset.Facts, error) {
	if !d.AppliesTo(host) {
		return dataset.Facts{}, errors.New("vuxml is for FreeBSD hosts")
	}
	return read(bzip2.NewReader(data), maxExpanded, each)
}

// reader is one read of an expanded document: its decoder, what it has read,
// the most it may read, what each entry is given to, and what the entries so
// far say of the data.
type reader struct {
	dec     *xml.Decoder
	counted *dataset.Counted
	limit   int64
	each    func(vulnrecord.Record) error
	newest  time.Time
	given   int
	stopped error
}

// read reads the expanded document, refusing it when it expands past limit.
// An error each returns is returned as it is.
func read(expanded io.Reader, limit int64, each func(vulnrecord.Record) error) (dataset.Facts, error) {
	counted := dataset.Limited(expanded, limit)
	r := &reader{dec: xml.NewDecoder(counted), counted: counted, limit: limit, each: each}
	facts, err := r.entries()
	switch {
	case r.stopped != nil:
		return dataset.Facts{}, r.stopped
	case err != nil && counted.Past():
		return dataset.Facts{}, fmt.Errorf("the document expands past %d bytes", limit)
	}
	return facts, err
}

// entries reads the document from its root to its end, giving each entry as
// it is read.
func (r *reader) entries() (dataset.Facts, error) {
	if err := xmldoc.Root(r.dec, xml.Name{Space: namespace, Local: "vuxml"}, "VuXML"); err != nil {
		return dataset.Facts{}, err
	}
	for {
		tok, err := r.dec.Token()
		if err != nil {
			return dataset.Facts{}, fmt.Errorf("the document ends before its last entry: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if err := r.entry(t); err != nil {
				return dataset.Facts{}, err
			}
		case xml.EndElement:
			return r.finish()
		case xml.CharData:
			if len(strings.TrimSpace(string(t))) > 0 {
				return dataset.Facts{}, errors.New("the document holds text between its entries")
			}
		}
	}
}

// entry reads the entry that start opens and gives it, unless it was
// cancelled.
func (r *reader) entry(start xml.StartElement) error {
	if start.Name.Space != namespace || start.Name.Local != "vuln" {
		return fmt.Errorf("%s is not an entry of VuXML", dataset.Printable(start.Name.Local))
	}
	var e entry
	if err := r.dec.DecodeElement(&e, &start); err != nil {
		return fmt.Errorf("an entry cannot be read: %w", err)
	}
	rec, dated, err := e.record()
	switch {
	case err != nil:
		return fmt.Errorf("entry %s: %w", dataset.Printable(e.VID), err)
	case rec == nil:
		return nil
	}
	r.given++
	r.newest = later(r.newest, dated)
	if r.each != nil {
		if err := r.each(*rec); err != nil {
			r.stopped = err
			return err
		}
	}
	return nil
}

// finish reads past the root's end to the end of the file and gives what the
// entries say of the data: the newest date they give, and the release.
func (r *reader) finish() (dataset.Facts, error) {
	if err := xmldoc.End(r.dec); err != nil {
		return dataset.Facts{}, err
	}
	if r.given == 0 {
		return dataset.Facts{}, errors.New("the document holds no entry")
	}
	return dataset.Facts{Date: r.newest, Version: release}, nil
}

// record is the entry as matching reads it, and the newest date it gives,
// or nil for a cancelled entry, which affects nothing. A name in its
// references that is not a CVE, such as the CAN- names of 2005, is left out;
// an entry naming no CVE is matched by its identifier.
func (e entry) record() (*vulnrecord.Record, time.Time, error) {
	if !vidPattern.MatchString(e.VID) {
		return nil, time.Time{}, errors.New("its identifier is not a UUID")
	}
	if e.Cancelled != nil {
		return nil, time.Time{}, nil
	}
	dated, err := e.newest()
	if err != nil {
		return nil, time.Time{}, err
	}
	if len(e.Packages) == 0 {
		return nil, time.Time{}, errors.New("it names no package")
	}
	r := vulnrecord.Record{ID: e.VID, Advisory: entryPage + e.VID + ".html"}
	for _, cve := range e.CVEs {
		if dataset.ValidCVE(cve) && !slices.Contains(r.CVEs, cve) {
			r.CVEs = append(r.CVEs, cve)
		}
	}
	for _, p := range e.Packages {
		affected, err := p.affected()
		if err != nil {
			return nil, time.Time{}, err
		}
		r.Affected = append(r.Affected, affected...)
	}
	return &r, dated, nil
}

// newest is the newest of the entry's dates. It must give the date it was
// entered; the others are kept to when given.
func (e entry) newest() (time.Time, error) {
	if e.Entered == "" {
		return time.Time{}, errors.New("it gives no date it was entered")
	}
	var newest time.Time
	for _, value := range []string{e.Discovery, e.Entered, e.Modified} {
		if value == "" {
			continue
		}
		t, err := time.Parse(day, value)
		if err != nil {
			return time.Time{}, fmt.Errorf("%q is not a date", dataset.Printable(value))
		}
		newest = later(newest, t)
	}
	return newest, nil
}

// affected is each name the package element covers, once, with its ranges.
func (p packages) affected() ([]vulnrecord.Affected, error) {
	if len(p.Names) == 0 {
		return nil, errors.New("a package names no package")
	}
	if len(p.Ranges) == 0 {
		return nil, fmt.Errorf("%s has no range of versions", dataset.Printable(p.Names[0]))
	}
	var ranges [][]vulnrecord.Bound
	for _, r := range p.Ranges {
		converted, err := r.bounds()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", dataset.Printable(p.Names[0]), err)
		}
		if holdsNone(converted) {
			continue
		}
		ranges = append(ranges, converted)
	}
	if len(ranges) == 0 {
		return nil, nil
	}
	var out []vulnrecord.Affected
	var seen []string
	for _, name := range p.Names {
		if err := dataset.CheckText("a package's name", name); err != nil {
			return nil, err
		}
		if slices.Contains(seen, name) {
			continue
		}
		seen = append(seen, name)
		out = append(out, vulnrecord.Affected{Package: name, Ecosystem: release, Ranges: ranges})
	}
	return out, nil
}

// bounds is the range as matching reads it. A bare * is the first version,
// as pkg reads it: pkg audit takes >= * as every version and < * as none. A
// range that states no lower bound runs from the first version, which the
// walk that judges ranges needs to enter it.
func (r bounds) bounds() ([]vulnrecord.Bound, error) {
	if len(r.Bounds) == 0 {
		return nil, errors.New("a range has no bound")
	}
	var out []vulnrecord.Bound
	lower := false
	for _, b := range r.Bounds {
		kind, ok := kinds[b.XMLName.Local]
		if !ok || b.XMLName.Space != namespace {
			return nil, fmt.Errorf("%q is not a bound of a range", dataset.Printable(b.XMLName.Local))
		}
		if err := dataset.CheckText("a version", b.Version); err != nil {
			return nil, err
		}
		version := b.Version
		if version == "*" {
			version = vulnrecord.First
		}
		out = append(out, vulnrecord.Bound{Kind: kind, Version: version})
		lower = lower || kind == vulnrecord.From || kind == vulnrecord.After || kind == vulnrecord.Exactly
	}
	if !lower {
		out = append([]vulnrecord.Bound{{Kind: vulnrecord.From, Version: vulnrecord.First}}, out...)
	}
	return out, nil
}

// holdsNone reports whether a range holds no version: its lower bound is
// above its upper bound in pkg's order, or at it where either bound leaves
// that version out. pkg audit reads a range as both its bounds holding, so
// such a range, a slip in the document such as from 16.0.0 before 15.1.0, or
// an upper bound written without the epoch its lower bound has, matches
// nothing; the walk that judges ranges in their versions' order would read
// it as open above its lower bound. A range whose versions pkg cannot order
// is kept, for the matcher to report.
func holdsNone(bounds []vulnrecord.Bound) bool {
	var lower, upper *vulnrecord.Bound
	for i := range bounds {
		switch bounds[i].Kind {
		case vulnrecord.From, vulnrecord.After:
			lower = &bounds[i]
		case vulnrecord.Before, vulnrecord.UpTo:
			upper = &bounds[i]
		}
	}
	if lower == nil || upper == nil {
		return false
	}
	at, err := pkgversion.Pkg(lower.Version, upper.Version)
	if err != nil {
		return false
	}
	return at > 0 || at == 0 && (lower.Kind == vulnrecord.After || upper.Kind == vulnrecord.Before)
}

// later is the later of two times.
func later(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// internal/dataset/fedora/fedora.go

// Package fedora reads the security updates of a Fedora release from the
// updateinfo of its updates repository, the file dnf reads, as the dataset a
// Fedora host's packages are matched against. The file is fetched as Fedora
// serves it, compressed with zstd and checked against the checksum the
// repository's index states, and owatch keeps the release's security updates
// alone, each element as the file holds it, compressed with gzip: reading the
// whole file's XML took a second on each run, and its security updates are a
// sixth of it. The manifest records the file fetched beside what was kept.
package fedora

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/dataset/xmldoc"
	"github.com/papa0four/orkowatch/internal/osfingerprint"
	"github.com/papa0four/orkowatch/internal/softwarelist"
	"github.com/papa0four/orkowatch/internal/vulnrecord"
)

const (
	id = "fedora-updates"

	// repository is where a current release's updates repository is, and
	// archive where one is once Fedora archives the release. index is the
	// repository's index under either. The updateinfo is the same file in
	// every architecture's repository, so x86_64's serves every host.
	repository = "https://dl.fedoraproject.org/pub/fedora/linux/updates/"
	archive    = "https://dl.fedoraproject.org/pub/archive/fedora/linux/updates/"
	index      = "/Everything/x86_64/repodata/repomd.xml"

	// maxFetched bounds the file fetched. Fedora 44's was 2.5 MiB on
	// 2026-11-27, and the archived Fedora 42's 2.7 MiB. maxExpanded bounds
	// what it may expand to, which is held whole while what is kept is cut
	// from it: Fedora 44's was 52 MiB, and Fedora 42's 60 MiB.
	maxFetched  = 16 << 20
	maxExpanded = 128 << 20

	// maxKept bounds what is kept, compressed, and maxKeptExpanded what it
	// may expand to.
	maxKept         = 8 << 20
	maxKeptExpanded = 64 << 20

	// keptHead and keptTail open and close what is kept: the updates
	// element, holding the release's security updates as the file holds
	// them.
	keptHead = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<updates>\n"
	keptTail = "</updates>\n"

	// maxIndex bounds the repository's index. Fedora 44's was 7 KiB.
	maxIndex = 64 << 10

	// updatePage is where Bodhi publishes each update.
	updatePage = "https://bodhi.fedoraproject.org/updates/"

	license     = "CC BY-SA 4.0"
	attribution = "Fedora's updateinfo, https://fedoraproject.org, copyright Red Hat, Inc. and others"

	// stated is how updateinfo writes a time, in UTC.
	stated = "2006-01-02 15:04:05"

	// repoNamespace is the namespace of the repository index's elements.
	repoNamespace = "http://linux.duke.edu/metadata/repo"
)

var (
	// releasePattern is a Fedora release as a host names it.
	releasePattern = regexp.MustCompile(`^[1-9][0-9]{0,3}$`)

	// updatePattern is an update's identifier as Bodhi gives it.
	updatePattern = regexp.MustCompile(`^FEDORA-[0-9]{4}-[0-9a-f]{10}$`)

	// cvePattern finds the CVEs a reference's title names, which
	// dataset.ValidCVE then judges.
	cvePattern = regexp.MustCompile(`CVE-[0-9]{4}-[0-9]+`)

	// epochPattern is an epoch as a package element states it.
	epochPattern = regexp.MustCompile(`^[0-9]{1,10}$`)
)

type (
	// Updates is the updateinfo of a Fedora host's release as a dataset.
	Updates struct{}

	// update is one update element: its type, identifier, dates, release,
	// severity, references, and packages. Its description is not kept.
	update struct {
		Type       string      `xml:"type,attr"`
		ID         string      `xml:"id"`
		Issued     dated       `xml:"issued"`
		Updated    dated       `xml:"updated"`
		Release    string      `xml:"release"`
		Severity   string      `xml:"severity"`
		References []reference `xml:"references>reference"`
		Packages   []build     `xml:"pkglist>collection>package"`
	}

	// dated is an element that states a time.
	dated struct {
		Date string `xml:"date,attr"`
	}

	// reference is one reference of an update, whose title names the CVEs
	// of a bug it closes.
	reference struct {
		Title string `xml:"title,attr"`
	}

	// build is one package an update ships.
	build struct {
		Name    string `xml:"name,attr"`
		Epoch   string `xml:"epoch,attr"`
		Version string `xml:"version,attr"`
		Release string `xml:"release,attr"`
		Arch    string `xml:"arch,attr"`
	}

	// repomd is the repository's index: what it holds, each with its
	// location, checksum, and size.
	repomd struct {
		XMLName xml.Name `xml:"repomd"`
		Data    []struct {
			Type     string `xml:"type,attr"`
			Checksum struct {
				Type  string `xml:"type,attr"`
				Value string `xml:",chardata"`
			} `xml:"checksum"`
			Location struct {
				Href string `xml:"href,attr"`
			} `xml:"location"`
			Size int64 `xml:"size"`
		} `xml:"data"`
	}
)

// ID names the dataset.
func (Updates) ID() string { return id }

// AppliesTo reports whether host runs a release of Fedora, whose updates the
// dataset holds.
func (Updates) AppliesTo(host *osfingerprint.OSInfo) bool {
	return host != nil && host.OS == "linux" && host.Platform == "fedora" && releasePattern.MatchString(host.PlatformVersion)
}

// Gives is what the updates give a run: the installed packages matched
// against the release's security updates.
func (Updates) Gives() string { return "matching of the installed packages" }

// MaxBytes is the most what is kept may hold, compressed.
func (Updates) MaxBytes() int64 { return maxKept }

// FetchMaxBytes is the most the file Fedora serves may hold.
func (Updates) FetchMaxBytes() int64 { return maxFetched }

// Origin is the index of host's release's updates repository, which names
// the updateinfo by its checksum, and then the same index in Fedora's
// archive, where a release Fedora no longer updates is moved; the archive's
// standing says so. It is no origin at all for a host the dataset does not
// apply to, which a fetch refuses.
func (u Updates) Origin(host *osfingerprint.OSInfo) dataset.Origin {
	if !u.AppliesTo(host) {
		return dataset.Origin{License: license, Attribution: attribution}
	}
	n := host.PlatformVersion
	return dataset.Origin{
		URL: repository + n + index,
		Elsewhere: []dataset.Place{{
			URL:      archive + n + index,
			Standing: "Fedora " + n + " is archived and receives no updates",
		}},
		Index:       &dataset.Index{MaxBytes: maxIndex, Locate: locate},
		License:     license,
		Attribution: attribution,
	}
}

// Manager is the package manager whose packages the updates name, and so
// whose version order their builds are in.
func (Updates) Manager() string { return softwarelist.ManagerRPM }

// Combining is how the updates of one vulnerability combine: a version any
// update's build is above is affected, as dnf lists every advisory with a
// newer build of an installed package, since an update can name a CVE an
// earlier one named and ship a later build.
func (Updates) Combining() vulnrecord.Combining { return vulnrecord.AnyRange }

// Systems is none yet: the running kernel is a unit of the system the
// updates name, and it is given here by the work that matches the operating
// system release and kernel.
func (Updates) Systems(*osfingerprint.OSInfo) []softwarelist.SoftwareEntry { return nil }

// Release is the release a match of host reads, the Version that match
// carries.
func (u Updates) Release(host *osfingerprint.OSInfo) (string, error) {
	if !u.AppliesTo(host) {
		return "", errors.New("fedora-updates is for Fedora hosts")
	}
	return "Fedora " + host.PlatformVersion, nil
}

// locate reads the repository's index for where its updateinfo is: its
// address, resolved against the repository's root, its checksum, and its
// size. An index that names no updateinfo, or one that is not compressed
// with zstd, is refused.
func locate(r io.Reader, at *url.URL) (dataset.Location, error) {
	var md repomd
	dec := xml.NewDecoder(r)
	if err := dec.Decode(&md); err != nil {
		return dataset.Location{}, fmt.Errorf("not a repository's index: %w", err)
	}
	if md.XMLName.Space != repoNamespace {
		return dataset.Location{}, errors.New("not a repository's index")
	}
	at = at.ResolveReference(&url.URL{Path: "../"})
	for _, d := range md.Data {
		if d.Type != "updateinfo" {
			continue
		}
		href := d.Location.Href
		switch {
		case !strings.HasPrefix(href, "repodata/") || strings.Contains(href, "..") || !strings.HasSuffix(href, ".xml.zst"):
			return dataset.Location{}, fmt.Errorf("the updateinfo is at %q, not a zstd file in the repository's metadata", dataset.Printable(href))
		case d.Checksum.Type != "sha256":
			return dataset.Location{}, fmt.Errorf("the updateinfo's checksum is %q, not sha256", dataset.Printable(d.Checksum.Type))
		}
		return dataset.Location{URL: at.ResolveReference(&url.URL{Path: href}).String(), SHA256: d.Checksum.Value, Size: d.Size}, nil
	}
	return dataset.Location{}, errors.New("the index names no updateinfo")
}

// Keep reads the updateinfo Fedora serves, size bytes, and writes the
// security updates of host's release, each element as the file holds it,
// compressed with gzip. Updates of another release, which a release's file
// can hold, and updates that are not security updates are left out. A file
// that is not a Fedora updateinfo, or holds no security update of the
// release, is refused, so nothing is kept from it.
func (u Updates) Keep(fetched io.ReaderAt, size int64, host *osfingerprint.OSInfo, kept io.Writer) error {
	release, err := u.Release(host)
	if err != nil {
		return err
	}
	z, err := zstd.NewReader(io.NewSectionReader(fetched, 0, size), zstd.WithDecoderConcurrency(1), zstd.WithDecoderLowmem(true), zstd.WithDecoderMaxMemory(maxExpanded))
	if err != nil {
		return err
	}
	defer z.Close()
	counted := dataset.Limited(z, maxExpanded)
	expanded, err := io.ReadAll(counted)
	switch {
	case counted.Past():
		return fmt.Errorf("the updateinfo expands past %d bytes", maxExpanded)
	case err != nil:
		return fmt.Errorf("the updateinfo cannot be expanded: %w", err)
	}

	gz := gzip.NewWriter(kept)
	if _, err := io.WriteString(gz, keptHead); err != nil {
		return err
	}
	r := &reader{dec: xml.NewDecoder(bytes.NewReader(expanded)), release: release, keep: func(raw []byte) error {
		if _, err := gz.Write(raw); err != nil {
			return err
		}
		_, err := io.WriteString(gz, "\n")
		return err
	}}
	r.raw = expanded
	if _, err := r.read(); err != nil {
		return err
	}
	if _, err := io.WriteString(gz, keptTail); err != nil {
		return err
	}
	return gz.Close()
}

// Check reads what was kept whole and refuses it unless it is the security
// updates of host's release, as Keep writes them. It gives the latest time
// an update gives as the data's date, and the release as its version.
func (u Updates) Check(data io.Reader, host *osfingerprint.OSInfo) (dataset.Facts, error) {
	return u.Records(data, host, nil)
}

// Records is Check that gives each kept update to each, in the form matching
// reads, as it is read, so the updates are read once and never held
// together. The updates are sound only when Records returns no error: one
// that fails after some were given means none of them may be used. An error
// each returns ends the read. An update of another release, or one that is
// not a security update, refuses what was kept, which Keep would not have
// kept for this host.
func (u Updates) Records(data io.Reader, host *osfingerprint.OSInfo, each func(vulnrecord.Record) error) (dataset.Facts, error) {
	release, err := u.Release(host)
	if err != nil {
		return dataset.Facts{}, err
	}
	// gzip reads a byte at a time from a reader that allows it, so nothing
	// past the member's end is taken from compressed, and what follows it
	// can be refused.
	compressed := bufio.NewReader(data)
	gz, err := gzip.NewReader(compressed)
	if err != nil {
		return dataset.Facts{}, fmt.Errorf("not the updates kept: %w", err)
	}
	gz.Multistream(false)
	counted := dataset.Limited(gz, maxKeptExpanded)
	r := &reader{dec: xml.NewDecoder(counted), release: release, each: each, kept: true}
	facts, err := r.read()
	switch {
	case counted.Past() && r.stopped == nil:
		return dataset.Facts{}, fmt.Errorf("the updates kept expand past %d bytes", maxKeptExpanded)
	case err != nil:
		return dataset.Facts{}, err
	}
	if _, err := compressed.ReadByte(); !errors.Is(err, io.EOF) {
		return dataset.Facts{}, errors.New("data follows the updates kept")
	}
	return facts, nil
}

// reader is one read of an updateinfo: its decoder, the release whose
// security updates are read, and what each is given to. A read of what was
// kept refuses any other update; a read of the file Fedora serves passes
// them over, and gives keep each security update of the release as raw, the
// bytes of the file that hold it. newest is the latest time the updates read
// give, and given how many were read.
type reader struct {
	dec     *xml.Decoder
	release string
	kept    bool
	each    func(vulnrecord.Record) error
	keep    func(raw []byte) error
	raw     []byte
	newest  time.Time
	given   int
	stopped error
}

// read reads the updateinfo from its root to its end. An error each or keep
// returns is returned as it is.
func (r *reader) read() (dataset.Facts, error) {
	facts, err := r.updates()
	if r.stopped != nil {
		return dataset.Facts{}, r.stopped
	}
	return facts, err
}

// updates reads the updateinfo from its root to its end, giving each security
// update of the release as it is read.
func (r *reader) updates() (dataset.Facts, error) {
	if err := xmldoc.Root(r.dec, xml.Name{Local: "updates"}, "Fedora's updateinfo"); err != nil {
		return dataset.Facts{}, err
	}
	for {
		before := r.dec.InputOffset()
		tok, err := r.dec.Token()
		if err != nil {
			return dataset.Facts{}, fmt.Errorf("the updateinfo ends before its last update: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if err := r.update(t, before); err != nil {
				return dataset.Facts{}, err
			}
		case xml.EndElement:
			return r.finish()
		case xml.CharData:
			if len(strings.TrimSpace(string(t))) > 0 {
				return dataset.Facts{}, errors.New("the updateinfo holds text between its updates")
			}
		}
	}
}

// update reads the update that start opens, which begins at offset from in
// the file, and gives it when it is a security update of the release.
func (r *reader) update(start xml.StartElement, from int64) error {
	if start.Name.Space != "" || start.Name.Local != "update" {
		return fmt.Errorf("%s is not an update", dataset.Printable(start.Name.Local))
	}
	var u update
	if err := r.dec.DecodeElement(&u, &start); err != nil {
		return fmt.Errorf("an update cannot be read: %w", err)
	}
	if !r.kept && (u.Release != r.release || u.Type != "security") {
		return nil
	}
	rec, dated, err := u.record(r.release)
	if err != nil {
		return fmt.Errorf("update %s: %w", dataset.Printable(u.ID), err)
	}
	r.given++
	if dated.After(r.newest) {
		r.newest = dated
	}
	if r.keep != nil {
		err = r.keep(r.raw[from:r.dec.InputOffset()])
	} else if r.each != nil {
		err = r.each(*rec)
	}
	if err != nil {
		r.stopped = err
	}
	return err
}

// finish reads past the root's end to the end of the file and gives what the
// release's updates say of the data: the latest time they give, and the
// release.
func (r *reader) finish() (dataset.Facts, error) {
	if err := xmldoc.End(r.dec); err != nil {
		return dataset.Facts{}, err
	}
	if r.given == 0 {
		return dataset.Facts{}, fmt.Errorf("the updateinfo holds no security update of %s", r.release)
	}
	return dataset.Facts{Date: r.newest, Version: r.release}, nil
}

// record is the security update of release as matching reads it, and the
// latest time it gives. Its CVEs are those its references' titles name, each
// once; an update naming none is matched by its identifier. Each binary
// package it ships is affected before the build it ships; its source package
// is not installed and is left out. An update of another release, or one
// that is not a security update, is refused.
func (u update) record(release string) (*vulnrecord.Record, time.Time, error) {
	switch {
	case !updatePattern.MatchString(u.ID):
		return nil, time.Time{}, errors.New("its identifier is not an update's")
	case u.Release != release:
		return nil, time.Time{}, fmt.Errorf("it is an update of %s, not %s", dataset.Printable(u.Release), release)
	case u.Type != "security":
		return nil, time.Time{}, fmt.Errorf("it is a %s update, not a security update", dataset.Printable(u.Type))
	}
	issued, updated, err := u.times()
	if err != nil {
		return nil, time.Time{}, err
	}
	latest := issued
	if updated.After(latest) {
		latest = updated
	}
	r := vulnrecord.Record{
		ID:        u.ID,
		CVEs:      u.cves(),
		Published: issued.Format(time.RFC3339),
		Modified:  latest.Format(time.RFC3339),
		Advisory:  updatePage + u.ID,
	}
	if u.Severity != "None" && u.Severity != "" {
		if err := dataset.CheckText("its severity", u.Severity); err != nil {
			return nil, time.Time{}, err
		}
		r.Rating = u.Severity
	}
	if r.Affected, err = u.affected(); err != nil {
		return nil, time.Time{}, err
	}
	return &r, latest, nil
}

// times are when the update was issued, which it must state, and last
// updated, which is when it was issued when it states none.
func (u update) times() (issued, updated time.Time, err error) {
	if u.Issued.Date == "" {
		return time.Time{}, time.Time{}, errors.New("it gives no time it was issued")
	}
	if issued, err = time.Parse(stated, u.Issued.Date); err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("%q is not a time", dataset.Printable(u.Issued.Date))
	}
	if u.Updated.Date == "" {
		return issued, issued, nil
	}
	if updated, err = time.Parse(stated, u.Updated.Date); err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("%q is not a time", dataset.Printable(u.Updated.Date))
	}
	return issued, updated, nil
}

// cves are the CVEs the update's references name in their titles, each once
// and in the order they are named.
func (u update) cves() []string {
	var out []string
	for _, ref := range u.References {
		for _, cve := range cvePattern.FindAllString(ref.Title, -1) {
			if dataset.ValidCVE(cve) && !slices.Contains(out, cve) {
				out = append(out, cve)
			}
		}
	}
	return out
}

// affected is each binary package the update ships, once for each build, as
// affected from the first version to before that build. A security update
// that ships no binary package is refused.
func (u update) affected() ([]vulnrecord.Affected, error) {
	var out []vulnrecord.Affected
	for _, b := range u.Packages {
		if b.Arch == "src" {
			continue
		}
		fixed, err := b.version()
		if err != nil {
			return nil, err
		}
		if slices.ContainsFunc(out, func(a vulnrecord.Affected) bool { return a.Package == b.Name && a.Ranges[0][1].Version == fixed }) {
			continue
		}
		out = append(out, vulnrecord.Affected{
			Package:   b.Name,
			Ecosystem: u.Release,
			Ranges:    [][]vulnrecord.Bound{{{Kind: vulnrecord.From, Version: vulnrecord.First}, {Kind: vulnrecord.Before, Version: fixed}}},
		})
	}
	if len(out) == 0 {
		return nil, errors.New("it ships no binary package")
	}
	return out, nil
}

// version is the build as the inventory writes an installed package's
// version: the epoch and a colon ahead of the version when the epoch is not
// 0, and the release after a hyphen.
func (b build) version() (string, error) {
	for what, text := range map[string]string{"a package's name": b.Name, "a version": b.Version, "a release": b.Release, "an architecture": b.Arch} {
		if err := dataset.CheckText(what, text); err != nil {
			return "", err
		}
	}
	if !epochPattern.MatchString(b.Epoch) {
		return "", fmt.Errorf("%s gives the epoch %q", dataset.Printable(b.Name), dataset.Printable(b.Epoch))
	}
	evr := b.Version + "-" + b.Release
	if strings.TrimLeft(b.Epoch, "0") != "" {
		evr = b.Epoch + ":" + evr
	}
	return evr, nil
}

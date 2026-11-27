// internal/dataset/fedora/tracking.go

package fedora

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/osfingerprint"
	"github.com/papa0four/orkowatch/internal/softwarelist"
	"github.com/papa0four/orkowatch/internal/vulnrecord"
)

const (
	trackingID = "fedora-tracking-bugs"

	// bugzilla is Red Hat Bugzilla's REST interface to its bugs, bugPage
	// where it shows one, and versions where it states which of Fedora's
	// versions are active: those it files tracking bugs for.
	bugzilla = "https://bugzilla.redhat.com/rest/bug"
	bugPage  = "https://bugzilla.redhat.com/show_bug.cgi?id="
	versions = "https://bugzilla.redhat.com/rest/product?names=Fedora&include_fields=versions"

	// maxVersions bounds Bugzilla's answer of Fedora's versions: 2.6 KiB,
	// 47 versions, on 2026-11-27.
	maxVersions = 64 << 10

	// pageSize is how many bugs Bugzilla gives an anonymous request, so
	// how many each page asks for.
	pageSize = 20

	// bugFields are the fields each page asks for, and no other: none
	// names a person.
	bugFields = "id,component,version,status,summary,data_category,last_change_time"

	// maxListing bounds the listing of the bugs' identifiers: Fedora 44's
	// with rawhide's was about 6,500 identifiers, 110 KiB, on 2026-11-27.
	// maxPages bounds the pages it may name.
	maxListing = 1 << 20
	maxPages   = 2000

	// maxTrackingFetched bounds the pages together: about 320 of 6 KiB.
	// maxTrackingKept bounds what is kept, compressed, and
	// maxTrackingExpanded what it may expand to.
	maxTrackingFetched  = 16 << 20
	maxTrackingKept     = 4 << 20
	maxTrackingExpanded = 32 << 20

	// allReleases is what a tracking bug filed on rawhide names in its
	// summary when it applies to every current release.
	allReleases = "[fedora-all]"

	// closed is the status of a bug that is no longer open, which one
	// fetched by its identifier can have reached since it was listed.
	closed = "CLOSED"

	trackingLicense     = "No license stated for the bug data; owatch keeps facts of each bug alone"
	trackingAttribution = "Fedora's security tracking bugs, Red Hat Bugzilla, https://bugzilla.redhat.com"
)

type (
	// TrackingBugs is the open security tracking bugs of a Fedora host's
	// release in Red Hat Bugzilla as a dataset: what Fedora tracks and has
	// not fixed. A tracking bug says a vulnerability is tracked against a
	// package; whether the package is affected is its maintainer's to
	// establish.
	TrackingBugs struct{}

	// listing is Bugzilla's answer to a search for identifiers alone.
	listing struct {
		Error bool `json:"error"`
		Bugs  []struct {
			ID int `json:"id"`
		} `json:"bugs"`
	}

	// page is Bugzilla's answer to a request for bugs by identifier.
	page struct {
		Error bool  `json:"error"`
		Bugs  []bug `json:"bugs"`
	}

	// bug is one bug as a page gives it.
	bug struct {
		ID           int      `json:"id"`
		Component    []string `json:"component"`
		Version      []string `json:"version"`
		Status       string   `json:"status"`
		Summary      string   `json:"summary"`
		DataCategory string   `json:"data_category"`
		Changed      string   `json:"last_change_time"`
	}

	// trackedHeader opens what is kept: the release it was kept for,
	// whether Bugzilla named it an active version, and how many bugs
	// follow, none for a version that is not.
	trackedHeader struct {
		Release string `json:"release"`
		Active  *bool  `json:"active"`
		Bugs    int    `json:"bugs"`
	}

	// product is Bugzilla's answer of a product's versions, each named and
	// active or not.
	product struct {
		Error    bool `json:"error"`
		Products []struct {
			Versions []struct {
				Name   string `json:"name"`
				Active bool   `json:"is_active"`
			} `json:"versions"`
		} `json:"products"`
	}

	// tracked is a bug as owatch keeps it: its facts, and not its summary.
	tracked struct {
		ID        int      `json:"id"`
		Component string   `json:"component"`
		Status    string   `json:"status"`
		Changed   string   `json:"changed"`
		CVEs      []string `json:"cves"`
	}
)

// ID names the dataset.
func (TrackingBugs) ID() string { return trackingID }

// AppliesTo reports whether host runs a release of Fedora.
func (TrackingBugs) AppliesTo(host *osfingerprint.OSInfo) bool { return Updates{}.AppliesTo(host) }

// Gives is what the bugs give a run: the vulnerabilities tracked against the
// installed packages that no update has fixed.
func (TrackingBugs) Gives() string { return "the open tracking bugs of the installed packages" }

// MaxBytes is the most what is kept may hold, compressed.
func (TrackingBugs) MaxBytes() int64 { return maxTrackingKept }

// FetchMaxBytes is the most the pages may hold together.
func (TrackingBugs) FetchMaxBytes() int64 { return maxTrackingFetched }

// Manager is the package manager whose packages the bugs are filed against.
func (TrackingBugs) Manager() string { return softwarelist.ManagerRPM }

// Combining is how the records combine, which is the release's updates' way,
// since the two are matched together: an open tracking bug is cleared by a
// fix the updates give, whichever way records combine.
func (TrackingBugs) Combining() vulnrecord.Combining { return Updates{}.Combining() }

// Release is the release a match of host reads.
func (TrackingBugs) Release(host *osfingerprint.OSInfo) (string, error) {
	return Updates{}.Release(host)
}

// Origin is Bugzilla's listing of the identifiers of the open security
// tracking bugs of host's release and of rawhide, read anonymously, which
// names the pages they are fetched in, pageSize a page. Listing the
// identifiers first fixes the set however long the pages take. It is no
// origin at all for a host the dataset does not apply to, which a fetch
// refuses.
func (t TrackingBugs) Origin(host *osfingerprint.OSInfo) dataset.Origin {
	if !t.AppliesTo(host) {
		return dataset.Origin{License: trackingLicense, Attribution: trackingAttribution}
	}
	query := url.Values{
		"product":       {"Fedora"},
		"keywords":      {"SecurityTracking"},
		"keywords_type": {"allwords"},
		"bug_status":    {"__open__"},
		"version":       {host.PlatformVersion, "rawhide"},
		"ids_only":      {"1"},
	}
	release := host.PlatformVersion
	return dataset.Origin{
		URL: bugzilla + "?" + query.Encode(),
		Pages: &dataset.Pages{MaxBytes: maxListing, MaxPages: maxPages, List: list, Gate: &dataset.Gate{
			URL: versions, MaxBytes: maxVersions,
			Read: func(answer io.Reader) (string, error) {
				active, err := activeVersion(answer, release)
				if err != nil || active {
					return "", err
				}
				return inactiveStanding(release), nil
			},
		}},
		License:     trackingLicense,
		Attribution: trackingAttribution,
	}
}

// inactiveStanding is what a release Bugzilla does not name an active
// version is held with.
func inactiveStanding(release string) string {
	return "Fedora " + release + " is not an active version in Red Hat Bugzilla; no tracking bugs are filed for it"
}

// activeVersion reads Bugzilla's answer of Fedora's versions for whether
// release is one it names active.
func activeVersion(answer io.Reader, release string) (bool, error) {
	var p product
	if err := json.NewDecoder(answer).Decode(&p); err != nil {
		return false, fmt.Errorf("not Bugzilla's answer of Fedora's versions: %w", err)
	}
	return p.active(release)
}

// active reports whether the answer names release an active version,
// refusing an answer that is not Bugzilla's or does not name release.
func (p product) active(release string) (bool, error) {
	if p.Error || len(p.Products) != 1 {
		return false, errors.New("not Bugzilla's answer of Fedora's versions")
	}
	for _, v := range p.Products[0].Versions {
		if v.Name == release {
			return v.Active, nil
		}
	}
	return false, fmt.Errorf("no Fedora version %s is named in Red Hat Bugzilla", release)
}

// list reads the listing for the pages of its bugs, pageSize identifiers a
// page, each asking for bugFields alone. A listing that holds an error, or
// an identifier that is not one, is refused.
func list(r io.Reader, _ *url.URL) ([]string, error) {
	var l listing
	if err := json.NewDecoder(r).Decode(&l); err != nil {
		return nil, fmt.Errorf("not a listing of bugs: %w", err)
	}
	if l.Error {
		return nil, errors.New("the listing holds an error from Bugzilla")
	}
	var pages []string
	for start := 0; start < len(l.Bugs); start += pageSize {
		var ids []string
		for _, b := range l.Bugs[start:min(start+pageSize, len(l.Bugs))] {
			if b.ID <= 0 {
				return nil, fmt.Errorf("%d is not a bug's identifier", b.ID)
			}
			ids = append(ids, strconv.Itoa(b.ID))
		}
		pages = append(pages, bugzilla+"?"+url.Values{"id": {strings.Join(ids, ",")}, "include_fields": {bugFields}}.Encode())
	}
	return pages, nil
}

// Keep reads the pages as fetched, one answer after another, after the
// gate's answer of Fedora's versions. For a release that is not an active
// version, which is all that was fetched, it keeps none: a [fedora-all] bug
// is filed for the releases current when it is filed. Otherwise it writes the
// open bugs of host's release, and those of rawhide that apply to every
// release, as owatch keeps them: each bug's number, component, status, last
// change, and the CVEs its summary names, compressed with gzip. A bug that
// names no CVE, or has been closed since it was listed, is left out. A page
// that holds an error, or a bug that is not public, refuses the pages, so
// nothing is kept from them.
func (t TrackingBugs) Keep(fetched io.ReaderAt, size int64, host *osfingerprint.OSInfo, kept io.Writer) error {
	release, err := t.Release(host)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(io.NewSectionReader(fetched, 0, size))
	var p product
	if err := dec.Decode(&p); err != nil {
		return fmt.Errorf("the pages do not open with Bugzilla's answer of Fedora's versions: %w", err)
	}
	active, err := p.active(host.PlatformVersion)
	if err != nil {
		return err
	}
	if !active {
		if dec.More() {
			return fmt.Errorf("pages follow the answer that %s is not an active version", release)
		}
		return writeTracked(kept, release, false, nil)
	}
	keep, err := keptPages(dec, host.PlatformVersion)
	if err != nil {
		return err
	}
	if len(keep) == 0 {
		return fmt.Errorf("the pages hold no open tracking bug of %s", release)
	}
	return writeTracked(kept, release, true, keep)
}

// keptPages reads the pages from dec to their end and gives each bug of
// them as owatch keeps it for release, refusing a page that holds an error or
// is not Bugzilla's answer.
func keptPages(dec *json.Decoder, release string) ([]tracked, error) {
	var keep []tracked
	for {
		var p page
		err := dec.Decode(&p)
		switch {
		case errors.Is(err, io.EOF):
			return keep, nil
		case err != nil:
			return nil, fmt.Errorf("a page is not Bugzilla's answer: %w", err)
		case p.Error:
			return nil, errors.New("a page holds an error from Bugzilla")
		}
		for _, b := range p.Bugs {
			k, ok, err := b.kept(release)
			if err != nil {
				return nil, fmt.Errorf("bug %d: %w", b.ID, err)
			}
			if ok {
				keep = append(keep, k...)
			}
		}
	}
}

// kept is the bug as owatch keeps it, once for each component it is filed
// against, when it is an open tracking bug of release or applies to every
// release, and names a CVE.
func (b bug) kept(release string) ([]tracked, bool, error) {
	if b.DataCategory != "Public" {
		return nil, false, errors.New("it is not a public bug")
	}
	if b.ID <= 0 {
		return nil, false, errors.New("its identifier is not a bug's")
	}
	ofRelease := slices.Contains(b.Version, release) || slices.Contains(b.Version, "rawhide") && strings.Contains(b.Summary, allReleases)
	if !ofRelease || b.Status == closed {
		return nil, false, nil
	}
	cves := summaryCVEs(b.Summary)
	if len(cves) == 0 {
		return nil, false, nil
	}
	if _, err := time.Parse(time.RFC3339, b.Changed); err != nil {
		return nil, false, fmt.Errorf("%q is not a time", dataset.Printable(b.Changed))
	}
	if err := dataset.CheckText("its status", b.Status); err != nil {
		return nil, false, err
	}
	var out []tracked
	for _, c := range b.Component {
		if err := dataset.CheckText("its component", c); err != nil {
			return nil, false, err
		}
		out = append(out, tracked{ID: b.ID, Component: c, Status: b.Status, Changed: b.Changed, CVEs: cves})
	}
	if len(out) == 0 {
		return nil, false, errors.New("it names no component")
	}
	return out, true, nil
}

// summaryCVEs are the CVEs a tracking bug's summary opens with, each once,
// before the component it names.
func summaryCVEs(summary string) []string {
	var out []string
	for _, word := range strings.Fields(summary) {
		if !dataset.ValidCVE(word) {
			break
		}
		if !slices.Contains(out, word) {
			out = append(out, word)
		}
	}
	return out
}

// writeTracked writes the bugs kept for release, compressed with gzip: the
// release, whether it is an active version, and how many follow, then each
// bug, one JSON object a line.
func writeTracked(w io.Writer, release string, active bool, bugs []tracked) error {
	gz := gzip.NewWriter(w)
	enc := json.NewEncoder(gz)
	if err := enc.Encode(trackedHeader{Release: release, Active: &active, Bugs: len(bugs)}); err != nil {
		return err
	}
	for _, b := range bugs {
		if err := enc.Encode(b); err != nil {
			return err
		}
	}
	return gz.Close()
}

// Check reads what was kept whole and refuses it unless it is the bugs
// kept for host's release. It gives the latest change of a bug as the data's
// date, and the release as its version.
func (t TrackingBugs) Check(data io.Reader, host *osfingerprint.OSInfo) (dataset.Facts, error) {
	return t.Records(data, host, nil)
}

// Records is Check that gives each kept bug to each as an open record of the
// CVEs it tracks against its component, as a source package, at every
// version. The bugs are sound only when Records returns no error. An error
// each returns ends the read.
func (t TrackingBugs) Records(data io.Reader, host *osfingerprint.OSInfo, each func(vulnrecord.Record) error) (dataset.Facts, error) {
	release, err := t.Release(host)
	if err != nil {
		return dataset.Facts{}, err
	}
	compressed := bufio.NewReader(data)
	gz, err := gzip.NewReader(compressed)
	if err != nil {
		return dataset.Facts{}, fmt.Errorf("not the tracking bugs kept: %w", err)
	}
	gz.Multistream(false)
	counted := dataset.Limited(gz, maxTrackingExpanded)
	dec := json.NewDecoder(counted)
	dec.DisallowUnknownFields()
	var head trackedHeader
	if err := dec.Decode(&head); err != nil {
		return dataset.Facts{}, readError(counted, fmt.Errorf("not the tracking bugs kept: %w", err))
	}
	switch {
	case head.Release != release:
		return dataset.Facts{}, fmt.Errorf("the tracking bugs were kept for %s, not %s", dataset.Printable(head.Release), release)
	case head.Active == nil:
		return dataset.Facts{}, errors.New("the tracking bugs kept do not say whether the release is an active version")
	case !*head.Active && head.Bugs != 0:
		return dataset.Facts{}, fmt.Errorf("%d tracking bugs are kept for %s, which is not an active version", head.Bugs, release)
	}
	var newest time.Time
	for i := range head.Bugs {
		var b tracked
		if err := dec.Decode(&b); err != nil {
			return dataset.Facts{}, readError(counted, fmt.Errorf("bug %d of %d cannot be read: %w", i+1, head.Bugs, err))
		}
		changed, err := b.record(release, each)
		if err != nil {
			return dataset.Facts{}, err
		}
		if changed.After(newest) {
			newest = changed
		}
	}
	if err := trailing(dec, compressed, counted); err != nil {
		return dataset.Facts{}, err
	}
	if *head.Active && head.Bugs == 0 {
		return dataset.Facts{}, fmt.Errorf("no open tracking bug of %s is kept", release)
	}
	return dataset.Facts{Date: newest, Version: release}, nil
}

// record gives the kept bug to each, after judging it as Keep would have
// kept it, and returns when it last changed.
func (b tracked) record(release string, each func(vulnrecord.Record) error) (time.Time, error) {
	changed, err := time.Parse(time.RFC3339, b.Changed)
	switch {
	case b.ID <= 0:
		return time.Time{}, fmt.Errorf("%d is not a bug's identifier", b.ID)
	case err != nil:
		return time.Time{}, fmt.Errorf("bug %d: %q is not a time", b.ID, dataset.Printable(b.Changed))
	case len(b.CVEs) == 0 || slices.ContainsFunc(b.CVEs, func(c string) bool { return !dataset.ValidCVE(c) }):
		return time.Time{}, fmt.Errorf("bug %d names no CVE as one is written", b.ID)
	}
	for what, text := range map[string]string{"component": b.Component, "status": b.Status} {
		if err := dataset.CheckText(what, text); err != nil {
			return time.Time{}, fmt.Errorf("bug %d: %w", b.ID, err)
		}
	}
	if each == nil {
		return changed, nil
	}
	rec := vulnrecord.Record{
		ID:       fmt.Sprintf("rhbz#%d", b.ID),
		CVEs:     b.CVEs,
		Modified: changed.UTC().Format(time.RFC3339),
		Advisory: bugPage + strconv.Itoa(b.ID),
		Open:     true,
		Affected: []vulnrecord.Affected{{Package: b.Component, Ecosystem: release, Source: true,
			Ranges: [][]vulnrecord.Bound{{{Kind: vulnrecord.From, Version: vulnrecord.First}}}}},
	}
	return changed, each(rec)
}

// readError is err, or that the kept bugs expand past their limit when they
// ran past it.
func readError(counted *dataset.Counted, err error) error {
	if counted.Past() {
		return fmt.Errorf("the tracking bugs kept expand past %d bytes", maxTrackingExpanded)
	}
	return err
}

// trailing refuses anything after the bugs the header counts: more text,
// more than the limit, or data after the gzip member.
func trailing(dec *json.Decoder, compressed *bufio.Reader, counted *dataset.Counted) error {
	var extra json.RawMessage
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return readError(counted, errors.New("text follows the tracking bugs the header counts"))
	}
	if counted.Past() {
		return fmt.Errorf("the tracking bugs kept expand past %d bytes", maxTrackingExpanded)
	}
	if _, err := compressed.ReadByte(); !errors.Is(err, io.EOF) {
		return errors.New("data follows the tracking bugs kept")
	}
	return nil
}

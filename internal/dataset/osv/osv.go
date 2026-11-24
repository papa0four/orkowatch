// internal/dataset/osv/osv.go

// Package osv states OSV's data for a Linux distribution as a dataset: where
// each distribution's dump is published, the terms it comes under, which of
// its releases a host is, and how a dump is read and what of it is kept.
//
// OSV publishes one dump per distribution, a zip of JSON records holding
// every release. A host needs its own release's records, so a refresh reads
// the whole dump once, holds every record of the release to the OSV schema's
// form, and keeps those records alone, in owatch's own form: gzip of JSON
// lines, a header naming the release, one line per record, and a trailer
// with the count. The kept data is what the store holds and what every read
// checks.
package osv

import (
	"archive/zip"
	"bufio"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/osfingerprint"
)

const (
	// bucket is where OSV publishes its dumps, one per ecosystem directory.
	bucket = "https://storage.googleapis.com/osv-vulnerabilities/"

	// dumpName is the file in an ecosystem's directory that holds all its
	// records.
	dumpName = "all.zip"

	// attribution is what every dataset of OSV's data states with it.
	attribution = "Vulnerability data from OSV, https://osv.dev, as converted from the distribution's own security data"

	// maxEntries bounds the records one dump may hold, maxRecord the size
	// of one record, and maxExpanded what one dump may expand to. Ubuntu's
	// dump of 2026-11-24 held 75,722 records, the largest 5.9 MB, expanding
	// to 8.86 GB, the most of the five.
	maxEntries  = 1_000_000
	maxRecord   = 64 << 20
	maxExpanded = 64 << 30

	// maxKeptExpanded bounds what kept data may expand to. Ubuntu 22.04's
	// records expanded to 110 MB on 2026-11-24.
	maxKeptExpanded = 2 << 30

	// maxText bounds a string kept from a record: an identifier, a package
	// name, a version, a score, or an address.
	maxText = 1 << 10

	// maxEcosystemsNamed bounds how many releases a refusal names.
	maxEcosystemsNamed = 10

	// keptFormat is the version of the kept data this owatch writes and
	// reads.
	keptFormat = 1
)

// The events a range may hold, as the OSV schema names them.
const (
	eventIntroduced   = "introduced"
	eventFixed        = "fixed"
	eventLastAffected = "last_affected"
	eventLimit        = "limit"
)

// rangeEcosystem is the one range type kept: versions in the distribution's
// own order.
const rangeEcosystem = "ECOSYSTEM"

// identifier is what a record's identifier may be written with: OSV writes
// one as a prefix and a number, as ALSA-2024:1234 or UBUNTU-CVE-2024-1234.
var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// Dump is one distribution's OSV data as a dataset.
type Dump struct {
	id        string
	directory string
	platform  string
	license   string
	fetchMax  int64
	keptMax   int64
	release   func(version string) (release, error)
}

// Datasets returns the distributions whose OSV data owatch keeps, in name
// order.
func Datasets() []dataset.Dataset {
	return []dataset.Dataset{
		Dump{id: "osv-almalinux", directory: "AlmaLinux", platform: "almalinux", license: "MIT",
			fetchMax: 256 << 20, keptMax: 32 << 20, release: major("AlmaLinux")},
		Dump{id: "osv-alpine", directory: "Alpine", platform: "alpine", license: "CC-BY-SA 4.0",
			fetchMax: 256 << 20, keptMax: 32 << 20, release: alpine},
		Dump{id: "osv-redhat", directory: "Red Hat", platform: "redhat", license: "CC-BY 4.0",
			fetchMax: 512 << 20, keptMax: 32 << 20, release: redHat},
		Dump{id: "osv-rocky", directory: "Rocky Linux", platform: "rocky", license: "BSD",
			fetchMax: 256 << 20, keptMax: 32 << 20, release: major("Rocky Linux")},
		Dump{id: "osv-ubuntu", directory: "Ubuntu", platform: "ubuntu", license: "CC-BY-SA 4.0",
			fetchMax: 4 << 30, keptMax: 64 << 20, release: ubuntu},
	}
}

// ID names the dataset.
func (d Dump) ID() string { return d.id }

// AppliesTo reports whether host runs the distribution, as its fingerprint
// names it.
func (d Dump) AppliesTo(host *osfingerprint.OSInfo) bool {
	return host != nil && host.OS == "linux" && host.Platform == d.platform
}

// MaxBytes is the most the kept records may hold, compressed.
func (d Dump) MaxBytes() int64 { return d.keptMax }

// FetchMaxBytes is the most the distribution's dump may hold.
func (d Dump) FetchMaxBytes() int64 { return d.fetchMax }

// Origin is the distribution's dump in OSV's bucket, with the license OSV
// states for that distribution's data.
func (d Dump) Origin() dataset.Origin {
	return dataset.Origin{
		URL:         bucket + url.PathEscape(d.directory) + "/" + dumpName,
		License:     d.license,
		Attribution: attribution,
	}
}

// releaseOf is the release host runs.
func (d Dump) releaseOf(host *osfingerprint.OSInfo) (release, error) {
	if !d.AppliesTo(host) {
		return release{}, fmt.Errorf("%s is for %s hosts", d.id, d.platform)
	}
	return d.release(host.PlatformVersion)
}

// Keep reads the dump and writes the records of host's release, each held to
// the OSV schema's form. A withdrawn record is left out. A record of the
// release that is not in that form refuses the dump, naming it, so nothing
// is kept from a dump that would not pass whole. A dump with no record of the
// release is refused, naming the releases it holds.
func (d Dump) Keep(fetched io.ReaderAt, size int64, host *osfingerprint.OSInfo, kept io.Writer) error {
	rel, err := d.releaseOf(host)
	if err != nil {
		return err
	}
	archive, err := zip.NewReader(fetched, size)
	if err != nil {
		return fmt.Errorf("not a zip of OSV records: %w", err)
	}
	if len(archive.File) > maxEntries {
		return fmt.Errorf("the dump holds %d entries, more than the %d it may", len(archive.File), maxEntries)
	}

	gz := gzip.NewWriter(kept)
	enc := json.NewEncoder(gz)
	if err := enc.Encode(header{Format: keptFormat, Release: rel.name}); err != nil {
		return err
	}
	tally := trailer{}
	seen := map[string]bool{}
	var expanded int64
	for _, f := range archive.File {
		rec, n, err := readEntry(f, maxExpanded-expanded)
		expanded += n
		if err != nil {
			return err
		}
		if rec.Withdrawn != "" {
			continue
		}
		keep, err := rec.keptFor(rel, seen)
		if err != nil {
			return fmt.Errorf("record %s: %w", printable(rec.ID), err)
		}
		if keep == nil {
			continue
		}
		if err := enc.Encode(keep); err != nil {
			return err
		}
		tally.add(*keep)
	}
	if tally.Records == 0 {
		return fmt.Errorf("the dump holds no record of %s; it holds %s", rel.name, named(seen))
	}
	if err := enc.Encode(tally); err != nil {
		return err
	}
	return gz.Close()
}

// readEntry reads one entry of the dump as a record, with at most room bytes
// left of what the dump may expand to. Its name is never used. It returns
// what it read.
func readEntry(f *zip.File, room int64) (record, int64, error) {
	if !f.Mode().IsRegular() {
		return record{}, 0, errors.New("the dump holds an entry that is not a file")
	}
	r, err := f.Open()
	if err != nil {
		return record{}, 0, fmt.Errorf("the dump is damaged: %w", err)
	}
	defer r.Close() //nolint:errcheck // read in full or refused; what Close adds is nothing

	limit := min(room, maxRecord)
	counted := &counter{r: io.LimitReader(r, limit+1)}
	var rec record
	dec := json.NewDecoder(counted)
	if err := dec.Decode(&rec); err != nil {
		if counted.n > limit {
			return record{}, counted.n, fmt.Errorf("an entry of the dump expands past the %d bytes a record, or the dump, may", limit)
		}
		return record{}, counted.n, fmt.Errorf("the dump holds an entry that is not an OSV record: %w", err)
	}
	// What follows the record is read to its end, so the zip's own length
	// and checksum judge the entry, and must be nothing but white space.
	var rest onlySpace
	if _, err := io.Copy(&rest, io.MultiReader(dec.Buffered(), counted)); err != nil {
		return record{}, counted.n, fmt.Errorf("the dump is damaged: %w", err)
	}
	switch {
	case counted.n > limit:
		return record{}, counted.n, fmt.Errorf("an entry of the dump expands past the %d bytes a record, or the dump, may", limit)
	case rest.other:
		return record{}, counted.n, errors.New("the dump holds an entry with text after its record")
	}
	return rec, counted.n, nil
}

// Check reads kept records whole and refuses them unless every line is in
// the form Keep writes, the header names host's release, and the trailer
// counts what came before it. It gives the newest time a record was modified
// as the data's date, and the release as its version.
func (d Dump) Check(data io.Reader, host *osfingerprint.OSInfo) (dataset.Facts, error) {
	return d.Records(data, host, nil)
}

// Records is Check that gives each record to each as it is judged, so the
// records are read once and never held together. The records are sound only
// when Records returns no error: one that fails after some were given, as a
// trailer that does not count them, means none of them may be used. An error
// each returns ends the read.
func (d Dump) Records(data io.Reader, host *osfingerprint.OSInfo, each func(Record) error) (dataset.Facts, error) {
	rel, err := d.releaseOf(host)
	if err != nil {
		return dataset.Facts{}, err
	}
	gz, err := gzip.NewReader(data)
	if err != nil {
		return dataset.Facts{}, fmt.Errorf("not kept OSV records: %w", err)
	}
	gz.Multistream(false)
	counted := &counter{r: io.LimitReader(gz, maxKeptExpanded+1)}
	dec := json.NewDecoder(bufio.NewReader(counted))
	dec.DisallowUnknownFields()

	var head header
	if err := dec.Decode(&head); err != nil || head.Format != keptFormat {
		return dataset.Facts{}, fmt.Errorf("not kept OSV records of format %d: %v", keptFormat, err)
	}
	if head.Release != rel.name {
		return dataset.Facts{}, fmt.Errorf("the records are for %s, not this host's release, %s", printable(head.Release), rel.name)
	}

	got := trailer{}
	for {
		var line keptLine
		if err := dec.Decode(&line); err != nil {
			if counted.n > maxKeptExpanded {
				return dataset.Facts{}, fmt.Errorf("the records expand past %d bytes", maxKeptExpanded)
			}
			return dataset.Facts{}, fmt.Errorf("the records end before their trailer: %w", err)
		}
		if line.Records != nil {
			return finish(dec, gz, counted, got, line, rel)
		}
		if err := line.valid(rel); err != nil {
			return dataset.Facts{}, fmt.Errorf("record %s: %w", printable(line.ID), err)
		}
		got.add(line.Record)
		if each != nil {
			if err := each(line.Record); err != nil {
				return dataset.Facts{}, err
			}
		}
	}
}

// finish judges the trailer and what follows it, and gives the facts.
func finish(dec *json.Decoder, gz *gzip.Reader, counted *counter, got trailer, line keptLine, rel release) (dataset.Facts, error) {
	var rest onlySpace
	if _, err := io.Copy(&rest, io.MultiReader(dec.Buffered(), counted)); err != nil {
		return dataset.Facts{}, fmt.Errorf("the records are damaged: %w", err)
	}
	if err := gz.Close(); err != nil {
		return dataset.Facts{}, err
	}
	switch {
	case rest.other:
		return dataset.Facts{}, errors.New("text follows the records' trailer")
	case counted.n > maxKeptExpanded:
		return dataset.Facts{}, fmt.Errorf("the records expand past %d bytes", maxKeptExpanded)
	case *line.Records != got.Records:
		return dataset.Facts{}, fmt.Errorf("the trailer counts %d records where %d came before it", *line.Records, got.Records)
	case line.Modified != got.Modified:
		return dataset.Facts{}, fmt.Errorf("the trailer gives the newest change as %s where the records give %s", printable(line.Modified), got.Modified)
	case got.Records == 0:
		return dataset.Facts{}, fmt.Errorf("no record of %s is kept", rel.name)
	}
	date, err := time.Parse(time.RFC3339Nano, got.Modified)
	if err != nil {
		return dataset.Facts{}, err
	}
	return dataset.Facts{Date: date, Version: rel.name}, nil
}

// header opens kept records: the format and the release they are for.
type header struct {
	Format  int    `json:"format"`
	Release string `json:"release"`
}

// trailer ends kept records: how many there are, and the newest time one was
// modified, which no record after it can change.
type trailer struct {
	Records  int    `json:"records"`
	Modified string `json:"modified"`
}

// add counts r.
func (t *trailer) add(r Record) {
	t.Records++
	if r.Modified > t.Modified {
		t.Modified = r.Modified
	}
}

// keptLine is any line after the header: a record, or the trailer, which
// alone has a count.
type keptLine struct {
	Record
	Records *int `json:"records,omitempty"`
}

// named lists up to maxEcosystemsNamed of the releases seen, in order, and
// how many more there were.
func named(seen map[string]bool) string {
	if len(seen) == 0 {
		return "none"
	}
	all := make([]string, 0, len(seen))
	for eco := range seen {
		all = append(all, printable(eco))
	}
	slices.Sort(all)
	if len(all) <= maxEcosystemsNamed {
		return strings.Join(all, ", ")
	}
	return fmt.Sprintf("%s, and %d more", strings.Join(all[:maxEcosystemsNamed], ", "), len(all)-maxEcosystemsNamed)
}

// printable is text from a record as an error may show it: nothing a
// terminal would act on, and no longer than a record's text may be.
func printable(text string) string {
	text = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '?'
		}
		return r
	}, text)
	if len(text) > maxText {
		text = text[:maxText] + "..."
	}
	return text
}

// onlySpace takes what is written to it and notes anything but JSON's white
// space.
type onlySpace struct{ other bool }

func (o *onlySpace) Write(p []byte) (int, error) {
	for _, c := range p {
		if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
			o.other = true
		}
	}
	return len(p), nil
}

// counter counts what is read through it.
type counter struct {
	r io.Reader
	n int64
}

func (c *counter) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// internal/dataset/kev/kev.go

// Package kev states CISA's Known Exploited Vulnerabilities catalog as a
// dataset: where it is published, the terms it comes under, and how a file is
// told from anything that is not the catalog.
package kev

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/osfingerprint"
)

const (
	// id names the catalog in the store.
	id = "kev"

	// feed is the address CISA publishes the catalog's JSON at.
	feed = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

	// maxBytes is the most the catalog may hold. It held 1.8 MiB in late
	// 2026 and grows by a few hundred entries a year, so the bound leaves
	// years of room and still refuses a file that is plainly something else.
	maxBytes = 16 << 20

	// license and attribution are what CISA's license file for the catalog
	// states: the dedication it is under, and what use of it does not grant.
	license     = "CC0 1.0"
	attribution = "CISA Known Exploited Vulnerabilities Catalog. Use of this information does not authorize use of the CISA Logo or DHS Seal, and is not an endorsement by CISA or DHS."
)

// Catalog is the Known Exploited Vulnerabilities catalog as a dataset.
type Catalog struct{}

// Entry is what the catalog says of a CVE it lists: the date CISA added it,
// the date by which CISA directs US federal agencies to act on it, and
// whether its use in ransomware campaigns is known, each as the catalog
// writes it.
type Entry struct {
	Added      string `json:"date_added" yaml:"date_added"`
	Due        string `json:"due_date" yaml:"due_date"`
	Ransomware string `json:"known_ransomware_use" yaml:"known_ransomware_use"`
}

// Index is the catalog read whole: the entry of each CVE it lists, and how
// many of its entries name each CWE.
type Index struct {
	entries map[string]Entry
	classes map[string]int
}

// catalog is the part of the published file Read takes. A field it does not
// name is passed over, since CISA adds fields to the catalog and its entries.
type catalog struct {
	CatalogVersion  string  `json:"catalogVersion"`
	DateReleased    string  `json:"dateReleased"`
	Count           *int    `json:"count"`
	Vulnerabilities []entry `json:"vulnerabilities"`
}

// entry is the part of a catalog entry Read takes.
type entry struct {
	CVEID      string   `json:"cveID"`
	DateAdded  string   `json:"dateAdded"`
	DueDate    string   `json:"dueDate"`
	Ransomware string   `json:"knownRansomwareCampaignUse"`
	CWEs       []string `json:"cwes"`
}

// Entry is the catalog's entry for cve, and whether it lists cve.
func (x Index) Entry(cve string) (Entry, bool) {
	e, ok := x.entries[cve]
	return e, ok
}

// ClassCount is how many of the catalog's entries name cwe, each entry once.
// It counts the entries of that one weakness, not of the weaknesses beneath
// it.
func (x Index) ClassCount(cwe string) int { return x.classes[cwe] }

// ID names the catalog.
func (Catalog) ID() string { return id }

// AppliesTo reports true: the catalog lists vulnerabilities in the software
// of every system owatch runs on.
func (Catalog) AppliesTo(*osfingerprint.OSInfo) bool { return true }

// MaxBytes is the most the catalog may hold.
func (Catalog) MaxBytes() int64 { return maxBytes }

// Origin is CISA's own address for the catalog, which redirects nowhere, and
// the terms of its license file.
func (Catalog) Origin() dataset.Origin {
	return dataset.Origin{URL: feed, License: license, Attribution: attribution}
}

// Check refuses data that is not the catalog whole, as Read does.
func (c Catalog) Check(data io.Reader, host *osfingerprint.OSInfo) (dataset.Facts, error) {
	_, facts, err := c.Read(data, host)
	return facts, err
}

// Read reads the catalog whole into its index, refusing data that is not the
// catalog: one JSON object and nothing after it, with its version, the time
// it was released, and a count that is the number of entries present, each
// naming a CVE no other entry names. The count is what tells a catalog cut
// short at an entry's end from a whole one, and a CVE named twice would be
// counted twice under its weakness. It gives the release time as the data's
// date and the catalog version as its version. The catalog is the same for
// every host, so the host is not consulted.
func (Catalog) Read(data io.Reader, _ *osfingerprint.OSInfo) (Index, dataset.Facts, error) {
	var c catalog
	dec := json.NewDecoder(data)
	if err := dec.Decode(&c); err != nil {
		return Index{}, dataset.Facts{}, fmt.Errorf("not the catalog's JSON: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Index{}, dataset.Facts{}, errors.New("text follows the catalog")
	}

	if c.CatalogVersion == "" {
		return Index{}, dataset.Facts{}, errors.New("it states no catalog version")
	}
	released, err := time.Parse(time.RFC3339, c.DateReleased)
	if err != nil {
		return Index{}, dataset.Facts{}, fmt.Errorf("its release date %q is not a date and time", c.DateReleased)
	}
	switch {
	case c.Count == nil:
		return Index{}, dataset.Facts{}, errors.New("it states no count of entries")
	case *c.Count != len(c.Vulnerabilities):
		return Index{}, dataset.Facts{}, fmt.Errorf("it states %d entries and holds %d", *c.Count, len(c.Vulnerabilities))
	case *c.Count == 0:
		return Index{}, dataset.Facts{}, errors.New("it holds no entries")
	}

	x := Index{entries: make(map[string]Entry, len(c.Vulnerabilities)), classes: make(map[string]int)}
	// named holds the CWEs the entry being read has named, so an entry is
	// counted once under each in time linear in what it names, however many
	// an untrusted catalog gives it.
	named := make(map[string]bool)
	for i, e := range c.Vulnerabilities {
		if !dataset.ValidCVE(e.CVEID) {
			return Index{}, dataset.Facts{}, fmt.Errorf("entry %d names %q, which is not a CVE identifier", i+1, e.CVEID)
		}
		if _, seen := x.entries[e.CVEID]; seen {
			return Index{}, dataset.Facts{}, fmt.Errorf("entry %d names %s, which an earlier entry names", i+1, e.CVEID)
		}
		x.entries[e.CVEID] = Entry{Added: e.DateAdded, Due: e.DueDate, Ransomware: e.Ransomware}
		clear(named)
		for _, cwe := range e.CWEs {
			if !named[cwe] {
				named[cwe] = true
				x.classes[cwe]++
			}
		}
	}
	return x, dataset.Facts{Date: released, Version: c.CatalogVersion}, nil
}

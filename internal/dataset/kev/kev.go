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

// catalog is the part of the published file Check judges. A field it does not
// name is passed over, since CISA adds fields to the catalog and its entries.
type catalog struct {
	CatalogVersion  string  `json:"catalogVersion"`
	DateReleased    string  `json:"dateReleased"`
	Count           *int    `json:"count"`
	Vulnerabilities []entry `json:"vulnerabilities"`
}

// entry is the part of a catalog entry Check judges.
type entry struct {
	CVEID string `json:"cveID"`
}

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

// Check refuses data that is not the catalog whole: one JSON object and
// nothing after it, with its version, the time it was released, and a count
// that is the number of entries present, each naming a CVE. The count is what
// tells a catalog cut short at an entry's end from a whole one. It gives the
// release time as the data's date and the catalog version as its version.
func (Catalog) Check(data io.Reader) (dataset.Facts, error) {
	var c catalog
	dec := json.NewDecoder(data)
	if err := dec.Decode(&c); err != nil {
		return dataset.Facts{}, fmt.Errorf("not the catalog's JSON: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return dataset.Facts{}, errors.New("text follows the catalog")
	}

	if c.CatalogVersion == "" {
		return dataset.Facts{}, errors.New("it states no catalog version")
	}
	released, err := time.Parse(time.RFC3339, c.DateReleased)
	if err != nil {
		return dataset.Facts{}, fmt.Errorf("its release date %q is not a date and time", c.DateReleased)
	}
	switch {
	case c.Count == nil:
		return dataset.Facts{}, errors.New("it states no count of entries")
	case *c.Count != len(c.Vulnerabilities):
		return dataset.Facts{}, fmt.Errorf("it states %d entries and holds %d", *c.Count, len(c.Vulnerabilities))
	case *c.Count == 0:
		return dataset.Facts{}, errors.New("it holds no entries")
	}
	for i, e := range c.Vulnerabilities {
		if !dataset.ValidCVE(e.CVEID) {
			return dataset.Facts{}, fmt.Errorf("entry %d names %q, which is not a CVE identifier", i+1, e.CVEID)
		}
	}
	return dataset.Facts{Date: released, Version: c.CatalogVersion}, nil
}

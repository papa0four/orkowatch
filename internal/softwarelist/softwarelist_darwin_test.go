//go:build darwin

// internal/softwarelist/softwarelist_darwin_test.go

package softwarelist

import (
	"slices"
	"testing"
)

// The report is in the shape system_profiler wrote on a Mac: applications of
// one name at two paths with different versions, one bundle twice at one
// version, and one with no version.
func TestParseApplications(t *testing.T) {
	report := []byte(`{
  "SPApplicationsDataType" : [
    {
      "_name" : "Siri",
      "arch_kind" : "arch_arm_i64",
      "lastModified" : "2026-09-23T02:33:57Z",
      "obtained_from" : "apple",
      "path" : "/System/Library/CoreServices/Siri.app",
      "signed_by" : [
        "Software Signing",
        "Apple Code Signing Certification Authority",
        "Apple Root CA"
      ],
      "version" : "3406.12.1"
    },
    {
      "_name" : "Photos",
      "arch_kind" : "arch_arm_i64",
      "obtained_from" : "apple",
      "path" : "/System/Applications/Photos.app",
      "version" : "10.0"
    },
    {
      "_name" : "Siri",
      "obtained_from" : "apple",
      "path" : "/System/Applications/Siri.app",
      "version" : "1.0"
    },
    {
      "_name" : "Photos",
      "obtained_from" : "apple",
      "path" : "/Volumes/Backup/Applications/Photos.app",
      "version" : "10.0"
    },
    {
      "_name" : "Unversioned Helper",
      "arch_kind" : "arch_other",
      "obtained_from" : "unknown",
      "path" : "/Library/Application Support/Helper.app"
    }
  ]
}`)
	got, err := parseApplications(report)
	if err != nil {
		t.Fatal(err)
	}
	want := []SoftwareEntry{
		{Name: "Photos", Version: "10.0"},
		{Name: "Siri", Version: "1.0"},
		{Name: "Siri", Version: "3406.12.1"},
		{Name: "Unversioned Helper"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("parseApplications() =\n  %+v\nwant\n  %+v", got, want)
	}

	if _, err := parseApplications([]byte("Usage: system_profiler")); err == nil {
		t.Error("output that is not a report was read as an inventory")
	}
	if got, err := parseApplications([]byte(`{"SPApplicationsDataType":[]}`)); err != nil || len(got) != 0 {
		t.Errorf("an empty report read as %+v, %v", got, err)
	}
}

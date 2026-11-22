// internal/softwarelist/softwarelist_test.go

package softwarelist

import (
	"encoding/json"
	"testing"
)

// A report written before an entry said where it came from still reads, and
// an entry with nothing but a name and a version writes nothing more.
func TestEntryReadsAndWritesTheEarlierShape(t *testing.T) {
	earlier := `{"count":1,"packages":[{"name":"openssl","version":"3.0.11"}]}`
	var view SoftwareView
	if err := json.Unmarshal([]byte(earlier), &view); err != nil {
		t.Fatal(err)
	}
	want := SoftwareEntry{Name: "openssl", Version: "3.0.11"}
	if len(view.Packages) != 1 || view.Packages[0] != want {
		t.Errorf("read %+v, want one entry %+v", view.Packages, want)
	}

	written, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	if string(written) != earlier {
		t.Errorf("wrote %s, want %s", written, earlier)
	}
}

// An entry from a package manager writes every field it has under the names
// a report carries them by.
func TestEntryWritesWhatItsManagerStates(t *testing.T) {
	entry := SoftwareEntry{
		Name: "bash", Version: "5.2.15-2+b13", Manager: ManagerDpkg,
		Architecture: "amd64", Source: "bash", SourceVersion: "5.2.15-2",
	}
	written, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"name":"bash","version":"5.2.15-2+b13","manager":"dpkg","architecture":"amd64","source":"bash","source_version":"5.2.15-2"}`
	if string(written) != want {
		t.Errorf("wrote %s, want %s", written, want)
	}
}

// internal/dataset/view_test.go

package dataset

import (
	"encoding/json"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// A row's provenance is written among its own fields in JSON and YAML alike,
// as the keys status has always had.
func TestRowEncoding(t *testing.T) {
	row := Row{Provenance: Provenance{ID: "kev", State: StateCurrent, Version: "2026.11.20"}, Size: 1}
	asJSON, err := json.Marshal(row)
	if err != nil || string(asJSON) != `{"id":"kev","state":"current","version":"2026.11.20","size":1}` {
		t.Errorf("JSON %s, %v", asJSON, err)
	}
	asYAML, err := yaml.Marshal(row)
	if err != nil || string(asYAML) != "id: kev\nstate: current\nversion: 2026.11.20\nsize: 1\n" {
		t.Errorf("YAML %q, %v", asYAML, err)
	}
}

// A report names the data it read on one line, with the standing of the
// place it was fetched from when that place has one, and the provenance
// carries the standing in JSON beside the source, from its manifest.
func TestAboutStatesTheStanding(t *testing.T) {
	p := Provenance{ID: "fedora-updates", State: StateCurrent, Source: "https://archive.example/f42", DataDate: "2026-05-27", Version: "Fedora 42"}
	if got := p.About(); got != "fedora-updates, Fedora 42, data of 2026-05-27, current" {
		t.Errorf("with no standing: %q", got)
	}
	p.Standing = "Fedora 42 is archived and receives no updates"
	if got := (Use{Provenance: p}).Lines(); len(got) != 1 || got[0] != "fedora-updates, Fedora 42, data of 2026-05-27, current; Fedora 42 is archived and receives no updates" {
		t.Errorf("with a standing: %q", got)
	}
	asJSON, err := json.Marshal(p)
	if err != nil || !strings.Contains(string(asJSON), `"source":"https://archive.example/f42","standing":"Fedora 42 is archived and receives no updates"`) {
		t.Errorf("JSON %s, %v", asJSON, err)
	}
	m := Manifest{Source: p.Source, Standing: p.Standing}
	if got := ProvenanceOf("fedora-updates", m, Facts{}, now); got.Standing != p.Standing {
		t.Errorf("the provenance of a manifest with a standing has %q", got.Standing)
	}
}

// Each row is written with what bears on its state, a held dataset with its
// source, the standing of the place it was fetched from when it has one, and
// its license under it, and an empty store says so. A name holding a
// terminal escape is written quoted and escaped.
func TestWriteText(t *testing.T) {
	var b strings.Builder
	err := WriteText(&b, View{Store: "/store", Datasets: []Row{
		{Provenance: Provenance{ID: "kev", State: StateCurrent, Source: "https://data.example/kev", DataDate: "2026-11-20", Version: "2026.11.20",
			Fetched: "2026-11-22T11:00:00Z", License: "CC0 1.0", Attribution: "CISA"}, Size: 3 << 20},
		{Provenance: Provenance{ID: "epss", State: StateNotHeld}},
		{Provenance: Provenance{ID: "fedora", State: StateCurrent, Source: "https://archive.example/f42", Standing: "Fedora 42 is archived and receives no updates",
			DataDate: "2026-05-27", Version: "Fedora 42", Fetched: "2026-11-22T11:00:00Z", License: "CC BY-SA 4.0", Attribution: "Fedora"}, Size: 1 << 20},
		{Provenance: Provenance{ID: "bad", State: StateUnusable}, Reason: "checksum", Attention: "the import failed"},
		{Provenance: Provenance{ID: "old", State: StateNotApplicable}, Size: 512},
		{Provenance: Provenance{ID: "x\x1b[2J", State: StateUnknown}, Size: 1},
	}})
	if err != nil {
		t.Fatal(err)
	}
	want := `Store: /store

kev         current: data of 2026-11-20, version 2026.11.20, fetched 2026-11-22T11:00:00Z, 3.0 MiB
            source https://data.example/kev
            license CC0 1.0; CISA
epss        not held
fedora      current: data of 2026-05-27, version Fedora 42, fetched 2026-11-22T11:00:00Z, 1.0 MiB
            source https://archive.example/f42
            standing Fedora 42 is archived and receives no updates
            license CC BY-SA 4.0; Fedora
bad         unusable: checksum
            needs attention: the import failed
old         no longer applies, 512 B
"x\x1b[2J"  unknown to this version, 1 B
`
	if b.String() != want {
		t.Errorf("got\n%s\nwant\n%s", b.String(), want)
	}

	b.Reset()
	if err := WriteText(&b, View{Store: "/store"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "the store holds none") {
		t.Errorf("an empty store gave %q", b.String())
	}
}

// An elevated run's report says what it installed from the operator's store,
// what it left alone there and why, and the advice, with a blank line after;
// a run with no one behind it is given the advice alone, and one that did
// nothing is given nothing. Only advice asks the operator to act.
func TestWriteOperatorText(t *testing.T) {
	for name, tt := range map[string]struct {
		operator *Operator
		want     string
		act      bool
	}{
		"installed": {&Operator{Store: "/home/a/store", Installed: []string{"epss", "kev"}},
			"Installed from /home/a/store: epss and kev\n\n", false},
		"refused": {&Operator{Store: "/home/a/store", Refused: []Refusal{{ID: "kev", Reason: "it is a link"}}, Advice: "run import"},
			"Not installed from /home/a/store: kev: it is a link\nrun import\n\n", true},
		"no operator":  {&Operator{Advice: "fetch elsewhere"}, "fetch elsewhere\n\n", true},
		"not elevated": {nil, "", false},
	} {
		var b strings.Builder
		if err := WriteOperatorText(&b, tt.operator); err != nil {
			t.Fatal(err)
		}
		if b.String() != tt.want {
			t.Errorf("%s: got\n%s\nwant\n%s", name, b.String(), tt.want)
		}
		if tt.operator != nil && tt.operator.NeedsAction() != tt.act {
			t.Errorf("%s: needs action %v, want %v", name, !tt.act, tt.act)
		}
	}

	var b strings.Builder
	if err := WriteText(&b, View{Store: "/store", Datasets: []Row{{Provenance: Provenance{ID: "kev", State: StateNotHeld}}}}); err != nil || b.String() != "Store: /store\n\nkev  not held\n" {
		t.Errorf("the store's text is %q, %v", b.String(), err)
	}
}

func TestSize(t *testing.T) {
	for n, want := range map[int64]string{0: "0 B", 1023: "1023 B", 1024: "1.0 KiB", 1536: "1.5 KiB", 5 << 30: "5.0 GiB"} {
		if got := Size(n); got != want {
			t.Errorf("Size(%d) = %q, want %q", n, got, want)
		}
	}
}

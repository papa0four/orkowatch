// internal/dataset/xmldoc/xmldoc_test.go

package xmldoc

import (
	"encoding/xml"
	"strings"
	"testing"
)

// want is the root the tests' documents must have.
var want = xml.Name{Space: "urn:test", Local: "updates"}

// read reads document's root and its end.
func read(document string) error {
	dec := xml.NewDecoder(strings.NewReader(document))
	if err := Root(dec, want, "the test document"); err != nil {
		return err
	}
	if err := dec.Skip(); err != nil {
		return err
	}
	return End(dec)
}

// A document whose root is the one named, with only a declaration, comments,
// and space around it, is read; one with another root, another namespace,
// nothing, or anything after its end is refused, naming what it is not.
func TestRootAndEnd(t *testing.T) {
	for _, document := range []string{
		`<updates xmlns="urn:test"></updates>`,
		"<?xml version=\"1.0\"?>\n<!-- a comment -->\n<updates xmlns=\"urn:test\"><update/></updates>\n\n<!-- after -->\n",
	} {
		if err := read(document); err != nil {
			t.Errorf("%q was refused: %v", document, err)
		}
	}
	for document, what := range map[string]string{
		`<other xmlns="urn:test"/>`: "not the test document: the document is other",
		`<updates/>`:                "not the test document: the document is updates",
		``:                          "not the test document",
		`<updates xmlns="urn:test"/><updates xmlns="urn:test"/>`: "an element after its end",
		`<updates xmlns="urn:test"/>trailing`:                    "text after its end",
		`<updates xmlns="urn:test"/><`:                           "cannot be read to its end",
		"<\x1b[2J/>":                                             "not the test document",
	} {
		err := read(document)
		if err == nil || !strings.Contains(err.Error(), what) {
			t.Errorf("%q gave %v, want it refused: %s", document, err, what)
		}
		if err != nil && strings.Contains(err.Error(), "\x1b") {
			t.Errorf("%q: the refusal holds the escape: %q", document, err.Error())
		}
	}
}

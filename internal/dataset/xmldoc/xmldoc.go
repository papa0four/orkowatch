// internal/dataset/xmldoc/xmldoc.go

// Package xmldoc reads the ends of an XML document a dataset reads as a
// stream: up to its root element, which must be the one the source
// publishes, and past it to the end of the file, which must hold nothing
// more. Every dataset that reads a source's XML reads its ends here, so a
// document is refused alike whatever its source.
package xmldoc

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/papa0four/orkowatch/internal/dataset"
)

// Root reads dec up to the document's root element and refuses one that is
// not want, naming the document as what. The declaration, a DOCTYPE, and
// comments before it are passed over; no entity a DOCTYPE declares is read.
func Root(dec *xml.Decoder, want xml.Name, what string) error {
	for {
		tok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("not %s: %w", what, err)
		}
		if t, ok := tok.(xml.StartElement); ok {
			if t.Name != want {
				return fmt.Errorf("not %s: the document is %s", what, dataset.Printable(t.Name.Local))
			}
			return nil
		}
	}
}

// End reads what follows the root element to the end of the file, which
// must hold no element or text, so a document with anything after its end is
// refused, and a compressed stream under dec is read to its end, where it is
// checked.
func End(dec *xml.Decoder) error {
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("the document cannot be read to its end: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			return errors.New("the document holds an element after its end")
		case xml.CharData:
			if len(strings.TrimSpace(string(t))) > 0 {
				return errors.New("the document holds text after its end")
			}
		}
	}
}

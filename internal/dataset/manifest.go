// internal/dataset/manifest.go

package dataset

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"
	"unicode"
)

const (
	// ManifestFormat is the version of the manifest this owatch writes and
	// reads. A manifest of another version is refused rather than read in
	// part, since a field this version does not know could change what the
	// others mean.
	ManifestFormat = 1

	// maxManifestBytes bounds a manifest. Its fields are a few short lines;
	// the bound is far above them and refuses a file that would exhaust
	// memory before it was judged.
	maxManifestBytes = 64 << 10

	// maxTextLen bounds the source address, license, and attribution.
	maxTextLen = 2048

	// checksumLen is the length of a SHA-256 checksum in hexadecimal.
	checksumLen = 64
)

// ErrManifest means a manifest was refused. The error that carries it says
// why.
var ErrManifest = errors.New("manifest refused")

// Manifest is what is recorded about a dataset when it is fetched: where it
// came from and that place's standing, when, what its data must hash to, and the license and
// attribution its source asks for. For a dataset that keeps less than its
// origin serves, OriginSHA256 and OriginSize record the file that was
// fetched, which is not held, so what was kept can be traced to it.
type Manifest struct {
	Format       int       `json:"format"`
	ID           string    `json:"id"`
	Source       string    `json:"source"`
	Standing     string    `json:"standing,omitempty"`
	Fetched      time.Time `json:"fetched"`
	SHA256       string    `json:"sha256"`
	Size         int64     `json:"size"`
	OriginSHA256 string    `json:"origin_sha256,omitempty"`
	OriginSize   int64     `json:"origin_size,omitempty"`
	License      string    `json:"license"`
	Attribution  string    `json:"attribution"`
}

// DecodeManifest reads a manifest from r. It reads no more than a manifest
// may hold, and refuses a field it does not know or anything after the
// manifest, so what was read is exactly what is judged.
func DecodeManifest(r io.Reader) (Manifest, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxManifestBytes+1))
	if err != nil {
		return Manifest{}, fmt.Errorf("read manifest: %w", err)
	}
	if len(data) > maxManifestBytes {
		return Manifest{}, refuse("larger than %d KiB", maxManifestBytes>>10)
	}

	var m Manifest
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, refuse("not a manifest: %v", err)
	}
	if dec.More() {
		return Manifest{}, refuse("text follows the manifest")
	}
	return m, nil
}

// Encode writes m as a manifest DecodeManifest reads.
func (m Manifest) Encode(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(m)
}

// Validate refuses m unless it is a manifest of this version for d, fetched
// no later than now, whose checksum and size could describe d's data and
// whose text holds nothing a terminal would act on.
func (m Manifest) Validate(d Dataset, now time.Time) error {
	switch {
	case m.Format != ManifestFormat:
		return refuse("format %d, where this version of owatch reads %d", m.Format, ManifestFormat)
	case !ValidID(m.ID):
		return refuse("%q cannot name a dataset", m.ID)
	case m.ID != d.ID():
		return refuse("it is for %q, not %q", m.ID, d.ID())
	case m.Fetched.IsZero():
		return refuse("it does not say when the dataset was fetched")
	case m.Fetched.After(now):
		return refuse("it says the dataset was fetched at %s, which is later than now", m.Fetched.UTC().Format(time.RFC3339))
	case !validChecksum(m.SHA256):
		return refuse("%q is not a SHA-256 checksum in lower-case hexadecimal", m.SHA256)
	case m.Size <= 0:
		return refuse("it gives the size %d", m.Size)
	case m.Size > d.MaxBytes():
		return refuse("it gives the size %d bytes, more than %s may hold, %d", m.Size, d.ID(), d.MaxBytes())
	}
	if err := m.validOrigin(d); err != nil {
		return err
	}
	if err := validSource(m.Source); err != nil {
		return err
	}
	for name, text := range map[string]string{"standing": m.Standing, "license": m.License, "attribution": m.Attribution} {
		if err := validText(name, text); err != nil {
			return err
		}
	}
	return nil
}

// validOrigin refuses a record of the fetched file that could not describe
// one: a checksum that is not one, a size outside what the origin may serve,
// or one of the two without the other. A dataset kept whole records neither.
func (m Manifest) validOrigin(d Dataset) error {
	switch {
	case m.OriginSHA256 == "" && m.OriginSize == 0:
		return nil
	case !validChecksum(m.OriginSHA256):
		return refuse("%q is not a SHA-256 checksum of the fetched file in lower-case hexadecimal", m.OriginSHA256)
	case m.OriginSize <= 0 || m.OriginSize > FetchLimit(d):
		return refuse("it gives the fetched file's size as %d bytes, where %s's origin may serve 1 to %d", m.OriginSize, d.ID(), FetchLimit(d))
	}
	return nil
}

// validChecksum reports whether sum is a SHA-256 checksum as a manifest
// writes it.
func validChecksum(sum string) bool {
	if len(sum) != checksumLen || strings.ToLower(sum) != sum {
		return false
	}
	_, err := hex.DecodeString(sum)
	return err == nil
}

// validSource refuses a source address that is not an HTTPS address of a
// named host, which is the only kind owatch fetches from.
func validSource(source string) error {
	if err := validText("source", source); err != nil {
		return err
	}
	u, err := url.Parse(source)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return refuse("the source %q is not an HTTPS address of a host", source)
	}
	return nil
}

// validText refuses text that is too long or holds a control character,
// since a manifest's text is shown on a terminal.
func validText(name, text string) error {
	if len(text) > maxTextLen {
		return refuse("its %s is longer than %d bytes", name, maxTextLen)
	}
	if strings.IndexFunc(text, unicode.IsControl) >= 0 {
		return refuse("its %s holds a control character", name)
	}
	return nil
}

// refuse returns ErrManifest with the reason.
func refuse(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrManifest, fmt.Sprintf(format, args...))
}

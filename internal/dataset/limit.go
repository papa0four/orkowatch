// internal/dataset/limit.go

package dataset

import "io"

// Counted reads a source within a limit, and one byte past it, so that a
// source that ran past the limit can be told from one that ended at it, and
// counts what it read. Every dataset that bounds what its data expands to
// reads through it, so the bound is judged alike whatever the source.
type Counted struct {
	r     io.Reader
	limit int64
	n     int64
}

// Limited returns r read within limit.
func Limited(r io.Reader, limit int64) *Counted {
	return &Counted{r: io.LimitReader(r, limit+1), limit: limit}
}

func (c *Counted) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// N is how much has been read.
func (c *Counted) N() int64 { return c.n }

// Past reports whether the source ran past the limit.
func (c *Counted) Past() bool { return c.n > c.limit }

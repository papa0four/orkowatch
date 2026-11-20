// internal/security/checker/includes.go

package checker

import "slices"

// includeChain is the files a configuration reader is in the middle of
// reading, outermost first. Every reader that follows includes enters a file
// through it, so an include that leads back to a file already being read is
// refused in one way rather than followed without end.
type includeChain []string

// enter adds file to the chain and returns the function that takes it off
// again. It reports false, and adds nothing, when file is already being
// read.
func (c *includeChain) enter(file string) (leave func(), ok bool) {
	if slices.Contains(*c, file) {
		return nil, false
	}
	*c = append(*c, file)
	return func() { *c = (*c)[:len(*c)-1] }, true
}

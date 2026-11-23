// internal/render/count.go

package render

import "strconv"

// Count returns n followed by the noun in the form that agrees with it, so a
// message never reads "1 attempts" or "1 of 1 datasets".
func Count(n int, singular, plural string) string {
	if n == 1 {
		return "1 " + singular
	}
	return strconv.Itoa(n) + " " + plural
}

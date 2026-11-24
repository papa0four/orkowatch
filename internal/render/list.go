// internal/render/list.go

package render

import "strings"

// List joins items as a sentence lists them, with the serial comma: "a",
// "a and b", or "a, b, and c".
func List(items []string) string {
	switch len(items) {
	case 0, 1:
		return strings.Join(items, "")
	case 2:
		return items[0] + " and " + items[1]
	}
	return strings.Join(items[:len(items)-1], ", ") + ", and " + items[len(items)-1]
}

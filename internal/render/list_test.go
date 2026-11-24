// internal/render/list_test.go

package render

import "testing"

// One item stands alone, two are joined by and, and three or more take the
// serial comma.
func TestList(t *testing.T) {
	for _, tt := range []struct {
		items []string
		want  string
	}{
		{nil, ""},
		{[]string{"a"}, "a"},
		{[]string{"a", "b"}, "a and b"},
		{[]string{"a", "b", "c"}, "a, b, and c"},
	} {
		if got := List(tt.items); got != tt.want {
			t.Errorf("List(%q) = %q, want %q", tt.items, got, tt.want)
		}
	}
}

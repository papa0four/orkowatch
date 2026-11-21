// internal/treewalk/treewalk_test.go

package treewalk

import (
	"context"
	"slices"
	"testing"
)

// Every directory under every root is visited once, and each carries the
// state its own root started with.
func TestRunWalksEveryRoot(t *testing.T) {
	tree := map[string][]string{
		"/a":   {"/a/x", "/a/y"},
		"/a/x": {"/a/x/deep"},
		"/b":   {"/b/z"},
	}
	visit := func(_ context.Context, dir Dir[string]) ([]Dir[string], string) {
		var subdirs []Dir[string]
		for _, child := range tree[dir.Path] {
			subdirs = append(subdirs, Dir[string]{Path: child, State: dir.State})
		}
		return subdirs, dir.State + " " + dir.Path
	}

	var got []string
	roots := []Dir[string]{{Path: "/a", State: "first"}, {Path: "/b", State: "second"}}
	err := Run(context.Background(), 4, roots, visit, func(result string) { got = append(got, result) })
	if err != nil {
		t.Fatal(err)
	}

	slices.Sort(got)
	want := []string{"first /a", "first /a/x", "first /a/x/deep", "first /a/y", "second /b", "second /b/z"}
	if !slices.Equal(got, want) {
		t.Errorf("visited %v, want %v", got, want)
	}
	if len(roots) != 2 {
		t.Errorf("the caller's roots were changed: %v", roots)
	}
}

// With no root there is nothing to walk and Run returns.
func TestRunWithNoRoot(t *testing.T) {
	visit := func(context.Context, Dir[struct{}]) ([]Dir[struct{}], int) { return nil, 1 }
	var visits int
	if err := Run(context.Background(), 2, nil, visit, func(n int) { visits += n }); err != nil {
		t.Fatal(err)
	}
	if visits != 0 {
		t.Errorf("visited %d directories, want none", visits)
	}
}

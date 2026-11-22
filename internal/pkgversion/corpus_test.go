// internal/pkgversion/corpus_test.go

package pkgversion

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// recorded is one pair a package manager's own tool was asked to order, with
// its answer. refused is set where the tool would not compare the pair.
type recorded struct {
	a, b    string
	order   int
	refused bool
}

// corpus reads the pairs recorded for a scheme. A file's lines are the two
// versions and the tool's answer, tab-separated: -1, 0 or 1, or ! where the
// tool refused one of the two. Lines beginning with # say which tool
// answered.
func corpus(t testing.TB, scheme string) []recorded {
	t.Helper()
	file, err := os.Open(filepath.Join("testdata", scheme+".tsv"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close() //nolint:errcheck // read-only test data

	var pairs []recorded
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != corpusFields {
			t.Fatalf("%s: %q is not a pair and an answer", scheme, line)
		}
		pair := recorded{a: fields[0], b: fields[1]}
		switch fields[2] {
		case "-1":
			pair.order = -1
		case "0":
		case "1":
			pair.order = 1
		case "!":
			pair.refused = true
		default:
			t.Fatalf("%s: %q is not an answer", scheme, fields[2])
		}
		pairs = append(pairs, pair)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(pairs) == 0 {
		t.Fatalf("%s: no pairs recorded", scheme)
	}
	return pairs
}

const corpusFields = 3

// agrees checks a comparison against every pair recorded for its scheme: the
// order the tool gave where it gave one, and a refusal where it refused.
func agrees(t *testing.T, scheme string, compare Compare) {
	t.Helper()
	var wrong int
	for _, pair := range corpus(t, scheme) {
		got, err := compare(pair.a, pair.b)
		switch {
		case pair.refused && err == nil:
			wrong++
			t.Errorf("%q and %q were ordered %d; the tool refused them", pair.a, pair.b, got)
		case !pair.refused && err != nil:
			wrong++
			t.Errorf("%q and %q were refused (%v); the tool ordered them %d", pair.a, pair.b, err, pair.order)
		case !pair.refused && sign(got) != pair.order:
			wrong++
			t.Errorf("%q and %q were ordered %d; the tool ordered them %d", pair.a, pair.b, sign(got), pair.order)
		}
		if wrong >= corpusFailures {
			t.Fatalf("stopping after %d disagreements", wrong)
		}
	}
}

// corpusFailures bounds how many disagreements one run prints.
const corpusFailures = 25

// ordered checks what an order must satisfy, over the versions recorded for
// a scheme: a version is the same as itself, and swapping two versions
// reverses their order. Where the scheme's order is total, three versions in
// order also stay in order end to end; pacman's is not, since it counts a
// version with no release the same as that version at any release.
func ordered(t *testing.T, scheme string, compare Compare, total bool) {
	t.Helper()
	var versions []string
	seen := make(map[string]bool)
	for _, pair := range corpus(t, scheme) {
		if pair.refused {
			continue
		}
		for _, v := range []string{pair.a, pair.b} {
			if !seen[v] {
				seen[v] = true
				versions = append(versions, v)
			}
		}
	}

	must := func(a, b string) int {
		order, err := compare(a, b)
		if err != nil {
			t.Fatalf("%q and %q: %v", a, b, err)
		}
		return sign(order)
	}
	for i, a := range versions {
		if must(a, a) != 0 {
			t.Errorf("%q is not the same as itself", a)
		}
		b := versions[(i*orderStride+1)%len(versions)]
		c := versions[(i*orderStride*orderStride+2)%len(versions)]
		ab, ba := must(a, b), must(b, a)
		if ab != -ba {
			t.Errorf("%q against %q is %d and the reverse is %d", a, b, ab, ba)
		}
		if bc := must(b, c); total && ab <= 0 && bc <= 0 && must(a, c) > 0 {
			t.Errorf("%q, %q and %q are in order and the first is newer than the last", a, b, c)
		}
	}
}

// orderStride spreads the versions each one is checked against across the
// whole corpus.
const orderStride = 7919

// refusesUnusable checks that a comparison orders nothing against an empty
// string, whatever its package manager makes of one, nor against a string
// holding a NUL, which a package manager cannot be given.
func refusesUnusable(t *testing.T, compare Compare) {
	t.Helper()
	for _, pair := range [][2]string{{"", "1.0"}, {"1.0", ""}, {"", ""}, {"1.0\x00", "1.0"}, {"1.0", "\x001.0"}} {
		if order, err := compare(pair[0], pair[1]); err == nil {
			t.Errorf("%q and %q were ordered %d", pair[0], pair[1], order)
		}
	}
}

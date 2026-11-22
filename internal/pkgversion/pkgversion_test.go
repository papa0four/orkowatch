// internal/pkgversion/pkgversion_test.go

package pkgversion

import "testing"

// schemes are the comparisons with the name each one's recorded pairs are
// kept under. total says whether a scheme's order is total.
var schemes = []struct {
	name    string
	compare Compare
	total   bool
}{
	{"dpkg", Dpkg, true},
	{"rpm", RPM, true},
	{"apk", APK, true},
	{"pacman", Pacman, false},
	{"pkg", Pkg, true},
}

// Every recorded pair orders as the package manager's own tool ordered it,
// and a pair the tool refused is refused.
func TestAgreesWithThePackageManager(t *testing.T) {
	for _, scheme := range schemes {
		t.Run(scheme.name, func(t *testing.T) {
			agrees(t, scheme.name, scheme.compare)
		})
	}
}

func TestIsAnOrder(t *testing.T) {
	for _, scheme := range schemes {
		t.Run(scheme.name, func(t *testing.T) {
			ordered(t, scheme.name, scheme.compare, scheme.total)
		})
	}
}

func TestRefusesWhatNoSchemeCanOrder(t *testing.T) {
	for _, scheme := range schemes {
		t.Run(scheme.name, func(t *testing.T) {
			refusesUnusable(t, scheme.compare)
		})
	}
}

// Orders each manager's own documentation or source states, and a few that
// follow from the rules it gives: every version is older than the one after
// it.
func TestDocumentedOrders(t *testing.T) {
	tests := []struct {
		name    string
		compare Compare
		rising  []string
	}{
		// deb-version(7): "the following parts are in sorted order: '~~',
		// '~~a', '~', the empty part, 'a'".
		{"dpkg tilde", Dpkg, []string{"1~~", "1~~a", "1~", "1", "1a"}},
		{"dpkg revision", Dpkg, []string{"1.0", "1.0-1", "1.0-1+b1", "1.0-2", "1:0.9"}},

		// rpm-version(7).
		{"rpm tilde", RPM, []string{"1.0", "2.0~beta1", "2.0~rc1", "2.0"}},
		{"rpm caret", RPM, []string{"2.0", "2.0^150825", "2.0.1"}},
		{"rpm segments", RPM, []string{"1", "1.xyz", "1.0"}},
		{"rpm implicit segments", RPM, []string{"1c.f", "1.f"}},
		{"rpm epoch", RPM, []string{"4:6.0-1", "5:3.0-1", "5:3.1-1"}},
		{"rpm release", RPM, []string{"1.0", "1.0-1", "1.0-5", "1.0.1"}},

		// apk-tools' version.c: the suffixes in the order it ranks them,
		// then what its tokens give for a revision, a letter and a number
		// that begins with zeros.
		{"apk suffixes", APK, []string{
			"1.0_alpha", "1.0_beta", "1.0_pre", "1.0_rc", "1.0", "1.0_cvs", "1.0_svn", "1.0_git", "1.0_hg", "1.0_p",
		}},
		{"apk revision", APK, []string{"1.0", "1.0-r0", "1.0-r1", "1.0-r10", "1.0a", "1.1"}},
		{"apk leading zeros", APK, []string{"1.001", "1.01", "1.1"}},

		// vercmp(8): "1.0a < 1.0b < 1.0beta < 1.0p < 1.0pre < 1.0rc < 1.0 <
		// 1.0.a < 1.0.1", "1 < 1.0 < 1.1 < 1.1.1 < 1.2 < 2.0 < 3.0.0", and
		// "2:1.0-1 is always greater than 1:3.6-1".
		{"pacman letters", Pacman, []string{"1.0a", "1.0b", "1.0beta", "1.0p", "1.0pre", "1.0rc", "1.0", "1.0.a", "1.0.1"}},
		{"pacman numbers", Pacman, []string{"1", "1.0", "1.1", "1.1.1", "1.2", "2.0", "3.0.0"}},
		{"pacman epoch", Pacman, []string{"1.5-1", "1.5-2", "1:3.6-1", "2:1.0-1"}},

		// libpkg's pkg_version.c: "10 < 10a < 10b", "pl11 < alpha3 <
		// 0.1beta2 = 0.1.b2 < 0.1", and "2.* < 2pl1 < 2alpha3 < 2.9f7 <
		// 3.*".
		{"pkg letters", Pkg, []string{"10", "10a", "10b"}},
		{"pkg stages", Pkg, []string{"pl11", "alpha3", "0.1beta2", "0.1"}},
		{"pkg wildcard", Pkg, []string{"2.*", "2pl1", "2alpha3", "2.9f7", "3.*"}},
		{"pkg revision and epoch", Pkg, []string{"1.0", "1.0_1", "1.0_2", "1.1", "0.9,1"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for i := range tt.rising {
				for j := range tt.rising {
					got, err := tt.compare(tt.rising[i], tt.rising[j])
					if err != nil {
						t.Fatalf("%q and %q: %v", tt.rising[i], tt.rising[j], err)
					}
					if want := sign(i - j); sign(got) != want {
						t.Errorf("%q against %q is %d, want %d", tt.rising[i], tt.rising[j], sign(got), want)
					}
				}
			}
		})
	}
}

// Versions the documentation says are one and the same.
func TestDocumentedEqualities(t *testing.T) {
	tests := []struct {
		name    string
		compare Compare
		same    []string
	}{
		// rpm-version(7): "abc123 ... is equal to abc0123, abc.123 and
		// abc.000123", and "1.0 is equal to 1+0 and 1+.+0".
		{"rpm segments", RPM, []string{"abc123", "abc0123", "abc.123", "abc.000123"}},
		{"rpm separators", RPM, []string{"1.0", "1+0", "1+.+0"}},

		// libpkg: "10 = 10.0 = 10.0.0", "10..1 = 10.1", "10a1b2 =
		// 10a1.b2", "1.d2 = 1.dev2 = 1.Development2".
		{"pkg missing components", Pkg, []string{"10", "10.0", "10.0.0"}},
		{"pkg separators", Pkg, []string{"10..1", "10.1"}},
		{"pkg inserted separator", Pkg, []string{"10a1b2", "10a1.b2"}},
		{"pkg first letter", Pkg, []string{"1.d2", "1.dev2", "1.Development2"}},

		// vercmp(8): "comparing 1.5-1 and 1.5 will yield 0".
		{"pacman no release", Pacman, []string{"1.5", "1.5-1"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, a := range tt.same {
				for _, b := range tt.same {
					if got, err := tt.compare(a, b); err != nil || got != 0 {
						t.Errorf("%q against %q is %d, %v; want the same version", a, b, got, err)
					}
				}
			}
		})
	}
}

// No pair of strings makes a comparison panic, and whatever two strings a
// comparison orders it orders the other way round when they are swapped.
func FuzzCompare(f *testing.F) {
	for i, scheme := range schemes {
		for _, pair := range corpus(f, scheme.name)[:fuzzSeeds] {
			f.Add(uint8(i), pair.a, pair.b) // #nosec G115 -- five schemes
		}
	}
	f.Fuzz(func(t *testing.T, which uint8, a, b string) {
		scheme := schemes[int(which)%len(schemes)]
		forward, errForward := scheme.compare(a, b)
		backward, errBackward := scheme.compare(b, a)
		if (errForward == nil) != (errBackward == nil) {
			t.Fatalf("%s: %q and %q are refused one way round and ordered the other", scheme.name, a, b)
		}
		if errForward == nil && sign(forward) != -sign(backward) {
			t.Fatalf("%s: %q against %q is %d and the reverse is %d", scheme.name, a, b, forward, backward)
		}
		if same, err := scheme.compare(a, a); err == nil && same != 0 {
			t.Fatalf("%s: %q is not the same as itself", scheme.name, a)
		}
	})
}

// fuzzSeeds is how many recorded pairs of each scheme seed the fuzzing.
const fuzzSeeds = 40

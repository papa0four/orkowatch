// internal/pkgversion/windows.go

package pkgversion

import (
	"slices"
	"strconv"
	"strings"
)

const windowsScheme = "windows"

// windowsParts is how many numbers a Windows build is written with: the
// major and minor versions, the build, and the update revision, as
// 10.0.26100.9974.
const windowsParts = 4

// Windows orders two Windows builds as System.Version, Microsoft's type for
// them, orders four numbers: the first number that differs decides. It reads
// only what Windows writes, four numbers in digits, each one a DWORD as
// Windows states them, and refuses what System.Version also reads: fewer
// parts, spaces, and a plus sign.
func Windows(a, b string) (int, error) {
	if err := unusable(windowsScheme, a, b); err != nil {
		return 0, err
	}
	na, err := windowsBuild(a)
	if err != nil {
		return 0, err
	}
	nb, err := windowsBuild(b)
	if err != nil {
		return 0, err
	}
	return slices.Compare(na[:], nb[:]), nil
}

// windowsBuild reads the four numbers of build.
func windowsBuild(build string) ([windowsParts]uint64, error) {
	var numbers [windowsParts]uint64
	parts := strings.Split(build, ".")
	if len(parts) != windowsParts {
		return numbers, notVersion(windowsScheme, build, "it is not four numbers")
	}
	for i, part := range parts {
		n, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return numbers, notVersion(windowsScheme, build, "a part is not a 32-bit number in digits")
		}
		numbers[i] = n
	}
	return numbers, nil
}

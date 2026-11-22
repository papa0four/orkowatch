//go:build openbsd || netbsd

// internal/softwarelist/softwarelist_otherbsd.go

package softwarelist

import (
	"context"
	"fmt"
	"runtime"
)

// getPlatformSoftwareList reports that the inventory is not read here. Both
// platforms use pkg_info, and the module reports the gap rather than
// enumerating with a reading that no host of either has confirmed.
func getPlatformSoftwareList(context.Context) ([]SoftwareEntry, error) {
	return nil, fmt.Errorf("software enumeration is not yet implemented for %s", runtime.GOOS)
}

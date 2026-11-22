//go:build windows

// internal/elevation/operator_windows.go

package elevation

import "github.com/papa0four/orkowatch/internal/winfolder"

// Operator is the account the process runs as: the identity an elevated run
// acts for on Windows, the way the user behind sudo is on Unix.
type Operator struct {
	Home string
}

// InvokingOperator returns the account running the process, with its profile
// folder as Windows records it for the account, not as USERPROFILE states it,
// so the environment a run was started with cannot change whose space it acts
// in. It reports false when the profile cannot be resolved.
func InvokingOperator() (Operator, bool) {
	home, err := winfolder.Profile()
	if err != nil {
		return Operator{}, false
	}
	return Operator{Home: home}, true
}

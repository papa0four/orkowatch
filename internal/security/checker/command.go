// internal/security/checker/command.go

package checker

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// execError attaches the captured stderr to a command failure. Commands report
// why they failed on stderr, and that text is the difference between an
// actionable diagnostic and "exit status 1". It requires the command to have
// been run with Output rather than CombinedOutput, which discards the
// distinction by folding stderr into the parsed data.
func execError(err error) error {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(exitErr.Stderr)))
	}
	return err
}

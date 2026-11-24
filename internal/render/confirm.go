// internal/render/confirm.go

package render

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Confirm asks the operator question on out, followed by [y/N], and reports
// whether the answer read from in is yes. Anything but y or yes, an empty
// line or the end of input included, is no, so a question that goes
// unanswered never acts. The caller asks only when a person is at the
// terminal to answer.
func Confirm(in io.Reader, out io.Writer, question string) (bool, error) {
	if _, err := fmt.Fprint(out, question+" [y/N] "); err != nil {
		return false, fmt.Errorf("ask for confirmation: %w", err)
	}
	answer, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, fmt.Errorf("read confirmation: %w", err)
	}
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "y", "yes":
		return true, nil
	default:
		return false, nil
	}
}

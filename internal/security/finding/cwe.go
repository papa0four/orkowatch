// internal/security/finding/cwe.go

package finding

import (
	"errors"
	"fmt"
	"strings"
)

// CWE is a weakness identifier in its canonical CWE-N form. ParseCWE is the
// only constructor from authored text, so a non-empty CWE is well formed.
type CWE string

// ErrInvalidCWEID indicates a CWE identifier failed format validation
// Returned when input does not match CWE-N+
var ErrInvalidCWEID = errors.New("invalid CWE identifier")

const (
	cweIDPrefix    = "CWE-"
	cweIDMinLength = len(cweIDPrefix) + 1 // the prefix plus at least one digit
)

// ParseCWE validates an identifier authored in canonical CWE-N form. It
// returns an error wrapping ErrInvalidCWEID for anything else.
func ParseCWE(id string) (CWE, error) {
	if len(id) < cweIDMinLength {
		return "", fmt.Errorf("%w: length %d below minimum %d: %q", ErrInvalidCWEID, len(id), cweIDMinLength, id)
	}
	if !strings.HasPrefix(id, cweIDPrefix) {
		return "", fmt.Errorf("%w: missing %q prefix: %q", ErrInvalidCWEID, cweIDPrefix, id)
	}
	for i := len(cweIDPrefix); i < len(id); i++ {
		if id[i] < '0' || id[i] > '9' {
			return "", fmt.Errorf("%w: non-digit byte 0x%02x at position %d: %q", ErrInvalidCWEID, id[i], i, id)
		}
	}
	return CWE(id), nil
}

// internal/account/id.go

package account

import "strconv"

const (
	// IDField is the colon-delimited field holding the identifier in passwd
	// and group alike.
	IDField = 2

	// decimalBase and idBitSize describe an identifier as the databases
	// write it: base-10 text, the width of uid_t and gid_t.
	decimalBase = 10
	idBitSize   = 32
)

// ParseID reads a numeric identifier from an account database, reporting
// whether it was well formed. uid_t and gid_t are unsigned 32-bit on every
// supported platform, so a negative or oversized field is a malformed record
// rather than an account: accepting one would place it below the
// regular-user minimum, mark it a system account, and drop it from a report.
func ParseID(field string) (uint32, bool) {
	id, err := strconv.ParseUint(field, decimalBase, idBitSize)
	if err != nil {
		return 0, false
	}
	return uint32(id), true
}

// FormatID writes an identifier as the account databases do.
func FormatID(id uint32) string {
	return strconv.FormatUint(uint64(id), decimalBase)
}

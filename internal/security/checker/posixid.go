// internal/security/checker/posixid.go

// The numeric identifiers of a POSIX account database, read and written in
// one way. The file is built on every platform because a Linux host's files
// are also read from a file system a test supplies.

package checker

import "strconv"

const (
	// decimalBase and idBitSize describe the numeric identifiers in a POSIX
	// account database: base-10 text, uid_t and gid_t width. unixIDField is
	// the colon-delimited field holding one in passwd and group alike.
	decimalBase = 10
	idBitSize   = 32
	unixIDField = 2
)

// parseUnixID converts a numeric identifier field from a POSIX account
// database to its native width, reporting whether the field was well formed.
// uid_t and gid_t are unsigned 32-bit on every supported platform, so a
// negative or oversized field is a malformed record rather than an account:
// accepting one would place it below the regular-user minimum, mark it a
// system account, and drop it from the report.
func parseUnixID(field string) (uint32, bool) {
	id, err := strconv.ParseUint(field, decimalBase, idBitSize)
	if err != nil {
		return 0, false
	}
	return uint32(id), true
}

// formatUnixID writes an identifier as the account databases do. Evidence
// keeps identifiers numeric: when one failed to resolve it is the number that
// failed, and a name would be misleading.
func formatUnixID(id uint32) string {
	return strconv.FormatUint(uint64(id), decimalBase)
}

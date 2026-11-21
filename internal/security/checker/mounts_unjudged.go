//go:build darwin || openbsd || netbsd

// internal/security/checker/mounts_unjudged.go

package checker

// readMounts reads no mount table: how these platforms say which filesystems
// are local has not been observed on a host of each, so the scan keeps to the
// scan root's filesystem there and names each directory where another begins.
// A platform leaves this file when it gains a reading of its own.
func readMounts() (mounts []mount, judged bool, err error) {
	return nil, false, nil
}

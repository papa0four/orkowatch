//go:build freebsd || openbsd || netbsd

// internal/dataset/store/sysdata_bsd.go

package store

// systemData is where the BSDs keep the data their programs generate for the
// system, which hier(7) on each gives as /var/db. FreeBSD's /var/lib is for
// ported Linux applications, and OpenBSD and NetBSD have none.
func systemData() (string, error) { return "/var/db", nil }

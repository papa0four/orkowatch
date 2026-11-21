//go:build freebsd

// internal/security/checker/permissions_freebsd.go

package checker

// platformLocations adds none: hier(7) puts home directories under /home and
// root's under /root, and temporary files under /tmp and /var/tmp, which the
// common locations already name.
func platformLocations() []pathLocation { return nil }

// criticalPaths lists FreeBSD's own paths rather than adding to the common
// ones, which name files FreeBSD does not have and expect modes stricter than
// the ones it installs. Each expectation is the mode FreeBSD 15.1 installs.
// The password hashes are in master.passwd and spwd.db, which passwd(5) and
// pwd_mkdb(8) leave readable by root alone, and passwd and pwd.db are their
// copies with the hashes removed. sudo is a package, so its configuration is
// under /usr/local/etc.
func criticalPaths() []criticalPath {
	return []criticalPath{
		{"/etc/passwd", "Password file", permStandardFile},
		{"/etc/master.passwd", "Password file with password hashes", permOwnerReadWrite},
		{"/etc/pwd.db", "Password database", permStandardFile},
		{"/etc/spwd.db", "Password database with password hashes", permOwnerReadWrite},
		{"/etc/group", "Group file", permStandardFile},
		{"/usr/local/etc/sudoers", "Sudo configuration", permSudoers},
		{"/etc/ssh/sshd_config", "SSH daemon configuration", permStandardFile},
		{"/var/log", "Log directory", permStandardDir},
		{"/home", "User home directories", permStandardDir},
		{"/root", "Root user directory", permGroupReadDir},
		{"/boot", "Boot directory", permStandardDir},
		{"/usr/local/etc", "Local configuration", permStandardDir},
	}
}

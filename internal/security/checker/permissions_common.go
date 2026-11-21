//go:build linux || darwin || openbsd || netbsd

// internal/security/checker/permissions_common.go

package checker

// commonCriticalPaths lists the paths the platforms other than FreeBSD start
// their critical paths from. FreeBSD lists its own.
func commonCriticalPaths() []criticalPath {
	return []criticalPath{
		{"/etc/passwd", "Password file", permStandardFile},
		{"/etc/shadow", "Shadow password file", permOwnerWriteGroupRead},
		{"/etc/group", "Group file", permStandardFile},
		{"/etc/sudoers", "Sudo configuration", permSudoers},
		{"/etc/ssh/sshd_config", "SSH daemon configuration", permOwnerReadWrite},
		{"/var/log", "Log directory", permGroupWritableDir},
		{"/home", "User home directories", permStandardDir},
	}
}

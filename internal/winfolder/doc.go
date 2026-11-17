// internal/winfolder/doc.go

// Package winfolder resolves the Windows folders owatch reads or protects, the
// system, program, data, profile and Startup folders, through the known-folder
// API and the account's profile as Windows records it. A folder is wherever
// Windows has put it on this host, not a drive letter written into the code
// and not an environment variable read from the process. The known-folder API
// does expand environment variables in the Startup folders, so
// StartupFolders also gives their locations derived from folders the
// environment does not move. It is used only on Windows.
package winfolder

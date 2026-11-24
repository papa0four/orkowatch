//go:build windows

// internal/dataset/store/sysdata_windows.go

package store

import "github.com/papa0four/orkowatch/internal/winfolder"

// systemData is the ProgramData folder, where Windows keeps what an
// application holds for every user, as Windows resolves it and not as the
// ProgramData variable states it.
func systemData() (string, error) { return winfolder.ProgramData.Path() }

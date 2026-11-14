//go:build windows

// internal/security/checker/powershell.go

package checker

import (
	"bytes"
	"encoding/csv"
	"fmt"
)

// parsePowershellCSV parses ConvertTo-Csv output into data records, dropping
// the header row. PowerShell emits RFC 4180 CSV terminated with CRLF, so
// fields are quoted and may contain commas; splitting on "," and "\n" corrupts
// the last field of every row and any field holding a comma. fields is the
// expected column count, enforced on every record so a changed projection
// fails here rather than silently shifting values into the wrong struct
// members.
func parsePowershellCSV(output []byte, fields int) ([][]string, error) {
	reader := csv.NewReader(bytes.NewReader(output))
	reader.FieldsPerRecord = fields

	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parse CSV output: %w", err)
	}
	if len(records) == 0 {
		return nil, nil
	}

	return records[1:], nil
}

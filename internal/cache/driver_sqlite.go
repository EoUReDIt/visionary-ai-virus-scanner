//go:build sqlite

package cache

// Build with `-tags sqlite` (after `go get modernc.org/sqlite`) to compile the
// pure-Go embedded SQLite driver (CGO_ENABLED=0) into Visionary binaries.
import _ "modernc.org/sqlite"

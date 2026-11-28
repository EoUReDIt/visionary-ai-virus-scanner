//go:build sqlite

package cache

// Build with `-tags sqlite` (the dependency is already in go.mod) to compile the
// pure-Go embedded SQLite driver (CGO_ENABLED=0) into Visionary binaries.
import _ "modernc.org/sqlite"

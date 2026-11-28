// Package plat isolates everything that differs between Windows (the target)
// and other systems (used for development and tests).
package plat

import (
	"os"
	"path/filepath"
	"time"
)

// Proc is one running process.
type Proc struct {
	PID     int
	PPID    int
	Name    string
	Exe     string
	Cmdline string
}

// Event is a file-system change reported by a Watcher.
type Event struct {
	Path string
	Time time.Time
}

// Watcher delivers changed file paths under a set of roots.
type Watcher interface {
	Events() <-chan Event
	Close()
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func existing(paths ...string) []string {
	var out []string
	seen := map[string]bool{}
	for _, p := range paths {
		if p == "" || seen[p] || !exists(p) {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// SelfDir is the directory holding the running executable.
func SelfDir() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Dir(exe)
}

// SameBoot reports whether two boot timestamps describe the same boot.
func SameBoot(a, b time.Time) bool {
	d := a.Sub(b)
	if d < 0 {
		d = -d
	}
	return d < 2*time.Minute
}

// Conn is one established outbound IPv4 TCP connection.
type Conn struct {
	PID        int    // owning process, 0 when unknown
	RemoteIP   string // dotted-quad remote address
	RemotePort int
}

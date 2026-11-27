//go:build !windows

package plat

import (
	"bufio"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var ErrUnsupported = errors.New("only available on Windows")

func BootTime() time.Time {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return time.Time{}
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "btime "); ok {
			n, _ := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			return time.Unix(n, 0)
		}
	}
	return time.Time{}
}

func IsAdmin() bool { return os.Geteuid() == 0 }

func home() string { h, _ := os.UserHomeDir(); return h }

func DefaultWatchPaths() []string {
	h := home()
	return existing(filepath.Join(h, "Downloads"), filepath.Join(h, "Desktop"))
}

func QuickScanTargets() []string {
	h := home()
	t := existing(filepath.Join(h, "Downloads"), filepath.Join(h, "Desktop"),
		filepath.Join(h, ".config", "autostart"), os.TempDir())
	return t
}

func BootScanTargets() []string {
	h := home()
	return existing(filepath.Join(h, ".config", "autostart"), "/etc/init.d", "/etc/cron.d",
		"/etc/systemd/system", filepath.Join(h, ".config", "systemd", "user"))
}

func ListProcesses() ([]Proc, error) {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var out []Proc
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		p := Proc{PID: pid}
		if st, err := os.ReadFile(filepath.Join("/proc", e.Name(), "stat")); err == nil {
			// pid (comm) state ppid ...; comm may contain spaces and parens.
			s := string(st)
			if i, j := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')'); i >= 0 && j > i {
				p.Name = s[i+1 : j]
				f := strings.Fields(s[j+1:])
				if len(f) > 1 {
					p.PPID, _ = strconv.Atoi(f[1])
				}
			}
		}
		p.Exe, _ = os.Readlink(filepath.Join("/proc", e.Name(), "exe"))
		p.Exe = strings.TrimSuffix(p.Exe, " (deleted)")
		if cl, err := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline")); err == nil {
			p.Cmdline = strings.TrimSpace(strings.ReplaceAll(string(cl), "\x00", " "))
		}
		if p.Exe != "" {
			p.Name = filepath.Base(p.Exe)
		}
		out = append(out, p)
	}
	return out, nil
}

func FullscreenAppActive() bool     { return false }
func SetBackgroundPriority(bool)    {}
func AutorunBinaries() []string     { return nil }
func ScheduleBootTask(string) error { return ErrUnsupported }
func RemoveBootTask() error         { return ErrUnsupported }
func BootTaskScheduled() bool       { return false }
func Reboot() error                 { return ErrUnsupported }

func OpenBrowser(url string) error {
	return exec.Command("xdg-open", url).Start()
}

// pollWatcher is the development stand-in for ReadDirectoryChangesW: it walks
// the roots every two seconds and reports files whose size or mtime changed.
type pollWatcher struct {
	ch   chan Event
	done chan struct{}
}

func NewWatcher(roots []string) (Watcher, error) {
	w := &pollWatcher{ch: make(chan Event, 1024), done: make(chan struct{})}
	go w.loop(roots)
	return w, nil
}

func (w *pollWatcher) Events() <-chan Event { return w.ch }
func (w *pollWatcher) Close()               { close(w.done) }

func (w *pollWatcher) loop(roots []string) {
	type sig struct {
		size int64
		mod  int64
	}
	seen := map[string]sig{}
	first := true
	for {
		for _, root := range roots {
			_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return nil
				}
				info, err := d.Info()
				if err != nil || !info.Mode().IsRegular() {
					return nil
				}
				s := sig{info.Size(), info.ModTime().UnixNano()}
				if old, ok := seen[p]; !ok || old != s {
					seen[p] = s
					if !first {
						select {
						case w.ch <- Event{Path: p, Time: time.Now()}:
						default:
						}
					}
				}
				return nil
			})
		}
		first = false
		select {
		case <-w.done:
			close(w.ch)
			return
		case <-time.After(2 * time.Second):
		}
	}
}

// EnableANSI reports whether the terminal understands colour escapes.
func EnableANSI() bool { return true }

// UpdateSystemPath is Windows-only.
func UpdateSystemPath(string, bool) error { return ErrUnsupported }

// LaunchedFromExplorer is Windows-only.
func LaunchedFromExplorer() bool { return false }

// AcquireUILock is a no-op on non-Windows; ui.Serve also verifies live TCP listeners.
func AcquireUILock() (release func(), alreadyRunning bool) { return func() {}, false }

// ShowAlreadyRunningDialog prints the warning to stderr on non-Windows systems.
func ShowAlreadyRunningDialog(title, message string) bool {
	_, _ = os.Stderr.WriteString(title + ": " + message + "\n")
	return false
}

// EnsureSharedDataDir ensures the data directory exists on non-Windows systems.
func EnsureSharedDataDir(dir string) error {
	if dir == "" {
		return nil
	}
	return os.MkdirAll(dir, 0o755)
}

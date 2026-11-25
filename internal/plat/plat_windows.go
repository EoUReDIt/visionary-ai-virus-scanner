//go:build windows

package plat

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var ErrUnsupported = errors.New("not supported on this system")

const bootTaskName = `VisionaryAV\BootScan`

func BootTime() time.Time { return time.Now().Add(-windows.DurationSinceBoot()) }

func IsAdmin() bool { return windows.GetCurrentProcessToken().IsElevated() }

func userProfiles() []string {
	root := filepath.Join(os.Getenv("SystemDrive")+`\`, "Users")
	ents, err := os.ReadDir(root)
	if err != nil {
		if h, err := os.UserHomeDir(); err == nil {
			return []string{h}
		}
		return nil
	}
	var out []string
	for _, e := range ents {
		switch strings.ToLower(e.Name()) {
		case "public", "default", "default user", "all users", "defaultapppool":
			continue
		}
		if e.IsDir() {
			out = append(out, filepath.Join(root, e.Name()))
		}
	}
	return out
}

func startupDirs() []string {
	dirs := []string{filepath.Join(os.Getenv("ProgramData"), `Microsoft\Windows\Start Menu\Programs\StartUp`)}
	for _, u := range userProfiles() {
		dirs = append(dirs, filepath.Join(u, `AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`))
	}
	return dirs
}

// DefaultWatchPaths covers where new code normally lands. It enumerates every
// profile so the guard works the same as a service (LocalSystem) or as a user.
func DefaultWatchPaths() []string {
	var p []string
	for _, u := range userProfiles() {
		p = append(p, filepath.Join(u, "Downloads"), filepath.Join(u, "Desktop"),
			filepath.Join(u, "Documents"), filepath.Join(u, `AppData\Local\Temp`),
			filepath.Join(u, `AppData\Roaming`))
	}
	p = append(p, startupDirs()...)
	p = append(p, filepath.Join(os.Getenv("SystemRoot"), "Temp"))
	return existing(p...)
}

func QuickScanTargets() []string {
	var p []string
	for _, u := range userProfiles() {
		p = append(p, filepath.Join(u, "Downloads"), filepath.Join(u, "Desktop"),
			filepath.Join(u, `AppData\Local\Temp`))
	}
	p = append(p, startupDirs()...)
	p = append(p, filepath.Join(os.Getenv("SystemRoot"), "Temp"),
		filepath.Join(os.Getenv("SystemRoot"), `System32\Tasks`))
	p = append(p, AutorunBinaries()...)
	return existing(p...)
}

// BootScanTargets are the places that decide what runs before a user logs in.
func BootScanTargets() []string {
	sr := os.Getenv("SystemRoot")
	p := []string{filepath.Join(sr, `System32\drivers`), filepath.Join(sr, `System32\Tasks`)}
	p = append(p, startupDirs()...)
	p = append(p, AutorunBinaries()...)
	return existing(p...)
}

// cmdToExe pulls the executable path out of an autorun command line.
func cmdToExe(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return ""
	}
	if exp, err := registry.ExpandString(cmd); err == nil {
		cmd = exp
	}
	sr := os.Getenv("SystemRoot")
	cmd = strings.TrimPrefix(cmd, `\??\`)
	low := strings.ToLower(cmd)
	switch {
	case strings.HasPrefix(low, `\systemroot\`):
		cmd = filepath.Join(sr, cmd[len(`\systemroot\`):])
	case strings.HasPrefix(low, `system32\`), strings.HasPrefix(low, `syswow64\`):
		cmd = filepath.Join(sr, cmd)
	}
	if strings.HasPrefix(cmd, `"`) {
		if i := strings.IndexByte(cmd[1:], '"'); i >= 0 {
			return cmd[1 : 1+i]
		}
	}
	low = strings.ToLower(cmd)
	for _, ext := range []string{".exe", ".sys", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js"} {
		if i := strings.Index(low, ext); i >= 0 {
			return cmd[:i+len(ext)]
		}
	}
	return cmd
}

func regValues(root registry.Key, path string, names ...string) []string {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer k.Close()
	if len(names) == 0 {
		names, _ = k.ReadValueNames(-1)
	}
	var out []string
	for _, n := range names {
		if v, _, err := k.GetStringValue(n); err == nil {
			// Winlogon values may list several programs separated by commas.
			for _, part := range strings.Split(v, ",") {
				out = append(out, part)
			}
		}
	}
	return out
}

// AutorunBinaries lists executables referenced by the common persistence
// points: Run keys, Winlogon and services/drivers.
func AutorunBinaries() []string {
	var cmds []string
	run := []string{
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
		`SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`,
	}
	for _, r := range run {
		cmds = append(cmds, regValues(registry.LOCAL_MACHINE, r)...)
		cmds = append(cmds, regValues(registry.CURRENT_USER, r)...)
	}
	cmds = append(cmds, regValues(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, "Shell", "Userinit")...)
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services`,
		registry.ENUMERATE_SUB_KEYS); err == nil {
		subs, _ := k.ReadSubKeyNames(-1)
		k.Close()
		for _, s := range subs {
			cmds = append(cmds, regValues(registry.LOCAL_MACHINE,
				`SYSTEM\CurrentControlSet\Services\`+s, "ImagePath")...)
		}
	}
	seen := map[string]bool{}
	var out []string
	for _, c := range cmds {
		exe := cmdToExe(c)
		key := strings.ToLower(exe)
		if exe == "" || seen[key] {
			continue
		}
		seen[key] = true
		if st, err := os.Stat(exe); err == nil && !st.IsDir() {
			out = append(out, exe)
		}
	}
	return out
}

func ListProcesses() ([]Proc, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	var out []Proc
	for err = windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		p := Proc{PID: int(pe.ProcessID), PPID: int(pe.ParentProcessID),
			Name: windows.UTF16ToString(pe.ExeFile[:])}
		if pe.ProcessID > 4 {
			p.Exe, p.Cmdline = procDetails(pe.ProcessID)
		}
		out = append(out, p)
	}
	return out, nil
}

const processCommandLineInformation = 60

func procDetails(pid uint32) (exe, cmdline string) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", ""
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, 1024)
	n := uint32(len(buf))
	if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) == nil {
		exe = windows.UTF16ToString(buf[:n])
	}
	raw := make([]byte, 16*1024)
	var ret uint32
	if windows.NtQueryInformationProcess(h, processCommandLineInformation,
		unsafe.Pointer(&raw[0]), uint32(len(raw)), &ret) == nil {
		us := (*windows.NTUnicodeString)(unsafe.Pointer(&raw[0]))
		cmdline = us.String()
	}
	return exe, cmdline
}

var (
	shell32                          = windows.NewLazySystemDLL("shell32.dll")
	procSHQueryUserNotificationState = shell32.NewProc("SHQueryUserNotificationState")
)

// FullscreenAppActive is true while a Direct3D full-screen app or
// presentation mode owns the screen. It reflects the calling session, so it
// only works from a process in the user's session (not session 0).
func FullscreenAppActive() bool {
	var state uint32
	hr, _, _ := procSHQueryUserNotificationState.Call(uintptr(unsafe.Pointer(&state)))
	return hr == 0 && (state == 3 || state == 4)
}

// SetBackgroundPriority drops CPU and I/O priority so scans never compete
// with a game or a build.
func SetBackgroundPriority(on bool) {
	const begin, end = 0x00100000, 0x00200000
	mode := uint32(end)
	if on {
		mode = begin
	}
	_ = windows.SetPriorityClass(windows.CurrentProcess(), mode)
}

func schtasks(args ...string) error {
	out, err := exec.Command("schtasks.exe", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("schtasks: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ScheduleBootTask registers a one-shot task that runs as SYSTEM at startup,
// before anyone logs in.
func ScheduleBootTask(command string) error {
	return schtasks("/Create", "/TN", bootTaskName, "/SC", "ONSTART", "/RU", "SYSTEM",
		"/RL", "HIGHEST", "/TR", command, "/F")
}

func RemoveBootTask() error { return schtasks("/Delete", "/TN", bootTaskName, "/F") }

func BootTaskScheduled() bool { return schtasks("/Query", "/TN", bootTaskName) == nil }

func Reboot() error {
	return exec.Command("shutdown.exe", "/r", "/t", "10", "/c", "Visionary boot-time scan").Run()
}

func OpenBrowser(url string) error {
	// An app-mode Edge window makes the dashboard feel like a native app.
	for _, edge := range []string{
		filepath.Join(os.Getenv("ProgramFiles(x86)"), `Microsoft\Edge\Application\msedge.exe`),
		filepath.Join(os.Getenv("ProgramFiles"), `Microsoft\Edge\Application\msedge.exe`),
	} {
		if exists(edge) {
			return exec.Command(edge, "--app="+url, "--window-size=1180,820").Start()
		}
	}
	return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
}

type winWatcher struct {
	ch      chan Event
	handles []windows.Handle
	done    chan struct{}
}

// NewWatcher watches whole directory trees with ReadDirectoryChangesW.
func NewWatcher(roots []string) (Watcher, error) {
	w := &winWatcher{ch: make(chan Event, 4096), done: make(chan struct{})}
	for _, root := range roots {
		p, err := windows.UTF16PtrFromString(root)
		if err != nil {
			continue
		}
		h, err := windows.CreateFile(p, windows.FILE_LIST_DIRECTORY,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
			nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
		if err != nil {
			continue
		}
		w.handles = append(w.handles, h)
		go w.read(h, root)
	}
	if len(w.handles) == 0 {
		return nil, errors.New("no watchable directories")
	}
	return w, nil
}

func (w *winWatcher) Events() <-chan Event { return w.ch }

func (w *winWatcher) Close() {
	close(w.done)
	for _, h := range w.handles {
		_ = windows.CancelIoEx(h, nil)
		_ = windows.CloseHandle(h)
	}
}

func (w *winWatcher) read(h windows.Handle, root string) {
	const mask = windows.FILE_NOTIFY_CHANGE_FILE_NAME | windows.FILE_NOTIFY_CHANGE_LAST_WRITE |
		windows.FILE_NOTIFY_CHANGE_SIZE
	buf := make([]byte, 64*1024)
	for {
		var n uint32
		err := windows.ReadDirectoryChanges(h, &buf[0], uint32(len(buf)), true, mask, &n, nil, 0)
		select {
		case <-w.done:
			return
		default:
		}
		if err != nil {
			return
		}
		for off := uint32(0); off+12 <= n; {
			info := (*windows.FileNotifyInformation)(unsafe.Pointer(&buf[off]))
			nameLen := info.FileNameLength / 2
			if off+12+info.FileNameLength > n {
				break
			}
			name := windows.UTF16ToString(unsafe.Slice(&info.FileName, nameLen))
			// Removals have nothing left to scan.
			if info.Action != windows.FILE_ACTION_REMOVED && info.Action != windows.FILE_ACTION_RENAMED_OLD_NAME {
				select {
				case w.ch <- Event{Path: filepath.Join(root, name), Time: time.Now()}:
				default:
				}
			}
			if info.NextEntryOffset == 0 {
				break
			}
			off += info.NextEntryOffset
		}
	}
}

// EnableANSI switches the console to virtual-terminal mode so colour escape
// sequences render instead of printing as garbage.
func EnableANSI() bool {
	h, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
	if err != nil {
		return false
	}
	var mode uint32
	if windows.GetConsoleMode(h, &mode) != nil {
		return false
	}
	return windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING) == nil
}

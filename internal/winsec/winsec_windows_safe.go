//go:build windows && safe

package winsec

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var errSafeEdition = errors.New("not included in Visionary Safe edition (install Core or Lite edition for automated Microsoft Defender changes, or adjust Windows Security manually)")

// GetStatus returns a read-only summary in Safe edition without spawning
// PowerShell or querying/modifying Defender configuration.
func GetStatus() *Status {
	return &Status{
		Available:   true,
		RunningMode: "Managed by Windows",
		RealTime:    true,
		Role:        "Safe edition: runs cleanly alongside Microsoft Defender (read-only integration; no PowerShell or Defender setting modifications)",
	}
}

// Coexist is intentionally omitted in Safe edition so the binary contains no
// Defender exclusion modification calls.
func Coexist(...string) error { return errSafeEdition }

// SetPassive is intentionally omitted in Safe edition so the binary contains no
// Defender passive-mode registry policy calls.
func SetPassive(bool) (string, error) { return "", errSafeEdition }

// OfflineScan is intentionally omitted in Safe edition so the binary contains
// no PowerShell Defender invocation calls.
func OfflineScan() error { return errSafeEdition }

// Defender implements engine.SecondOpinion using read-only Windows APIs only.
type Defender struct{}

// New returns the read-only Defender bridge.
func New() *Defender { return &Defender{} }

func mpCmdRun() string {
	matches, _ := filepath.Glob(filepath.Join(os.Getenv("ProgramData"), `Microsoft\Windows Defender\Platform\*\MpCmdRun.exe`))
	if len(matches) > 0 {
		sort.Strings(matches)
		return matches[len(matches)-1]
	}
	p := filepath.Join(os.Getenv("ProgramFiles"), `Windows Defender\MpCmdRun.exe`)
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return ""
}

// ScanFile runs a read-only Defender custom scan on one file without remediation.
func (*Defender) ScanFile(path string) (string, bool, error) {
	exe := mpCmdRun()
	if exe == "" {
		return "", false, errors.New("MpCmdRun.exe not found")
	}
	cmd := exec.Command(exe, "-Scan", "-ScanType", "3", "-File", path, "-DisableRemediation")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.ExitCode() == 2 {
		name := "threat"
		for _, line := range strings.Split(string(out), "\n") {
			if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "Threat"); ok {
				if _, v, ok := strings.Cut(rest, ":"); ok {
					name = strings.TrimSpace(v)
					break
				}
			}
		}
		return name, true, nil
	}
	return "", false, err
}

var (
	amsi               = windows.NewLazySystemDLL("amsi.dll")
	procAmsiInitialize = amsi.NewProc("AmsiInitialize")
	procAmsiScanBuffer = amsi.NewProc("AmsiScanBuffer")
	amsiOnce           sync.Once
	amsiCtx            uintptr
	amsiErr            error
)

// ScanBuffer hands content to Windows AMSI for a read-only second opinion.
func (*Defender) ScanBuffer(data []byte, name string) (bool, error) {
	amsiOnce.Do(func() {
		if amsiErr = amsi.Load(); amsiErr != nil {
			return
		}
		app, _ := windows.UTF16PtrFromString("Visionary")
		if hr, _, _ := procAmsiInitialize.Call(uintptr(unsafe.Pointer(app)), uintptr(unsafe.Pointer(&amsiCtx))); hr != 0 {
			amsiErr = fmt.Errorf("AmsiInitialize failed: 0x%x", hr)
		}
	})
	if amsiErr != nil || len(data) == 0 {
		return false, amsiErr
	}
	cname, _ := windows.UTF16PtrFromString(name)
	var result uint32
	hr, _, _ := procAmsiScanBuffer.Call(amsiCtx, uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)),
		uintptr(unsafe.Pointer(cname)), 0, uintptr(unsafe.Pointer(&result)))
	if hr != 0 {
		return false, fmt.Errorf("AmsiScanBuffer failed: 0x%x", hr)
	}
	return result >= 32768, nil
}

// VerifyTrust reports whether Windows trusts the file's Authenticode chain.
func (*Defender) VerifyTrust(path string) (bool, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false, err
	}
	fi := &windows.WinTrustFileInfo{Size: uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})), FilePath: p}
	data := &windows.WinTrustData{
		Size:                            uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice:                        windows.WTD_UI_NONE,
		RevocationChecks:                windows.WTD_REVOKE_NONE,
		UnionChoice:                     windows.WTD_CHOICE_FILE,
		StateAction:                     windows.WTD_STATEACTION_VERIFY,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(fi),
	}
	verifyErr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	_ = windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	return verifyErr == nil, nil
}

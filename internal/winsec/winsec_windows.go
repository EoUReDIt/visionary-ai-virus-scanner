//go:build windows

package winsec

import (
	"encoding/json"
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
	"golang.org/x/sys/windows/registry"
)

const policyKey = `SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection`

func ps(script string) ([]byte, error) {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(ee.Stderr) > 0 {
			return out, errors.New(firstLine(string(ee.Stderr)))
		}
		return out, err
	}
	return out, nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i > 0 {
		s = s[:i]
	}
	return s
}

func forcePassive() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, policyKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue("ForceDefenderPassiveMode")
	return err == nil && v == 1
}

// GetStatus reads Defender's state and the Security Center product list.
func GetStatus() *Status {
	s := &Status{ForcePassive: forcePassive()}
	out, err := ps(`$s = Get-MpComputerStatus -ErrorAction Stop; [pscustomobject]@{` +
		`mode=[string]$s.AMRunningMode; rt=[bool]$s.RealTimeProtectionEnabled; tp=[bool]$s.IsTamperProtected; ` +
		`sig=$s.AntivirusSignatureLastUpdated.ToString('yyyy-MM-dd HH:mm')} | ConvertTo-Json -Compress`)
	if err == nil {
		var v struct {
			Mode string `json:"mode"`
			RT   bool   `json:"rt"`
			TP   bool   `json:"tp"`
			Sig  string `json:"sig"`
		}
		if json.Unmarshal(out, &v) == nil {
			s.Available, s.RunningMode, s.RealTime, s.TamperProtected, s.SignatureDate = true, v.Mode, v.RT, v.TP, v.Sig
		}
	} else {
		s.Notes = append(s.Notes, "Could not query Microsoft Defender: "+err.Error())
	}
	out, err = ps(`ConvertTo-Json -Compress -InputObject @(Get-CimInstance -Namespace root/SecurityCenter2 ` +
		`-ClassName AntiVirusProduct -ErrorAction Stop | Select-Object displayName,productState)`)
	if err == nil {
		var ps []struct {
			Name  string `json:"displayName"`
			State uint32 `json:"productState"`
		}
		if json.Unmarshal(out, &ps) == nil {
			for _, p := range ps {
				// productState: 0x00XXYYZZ, YY=0x10 means enabled, ZZ=0x00 means up to date.
				s.Products = append(s.Products, Product{Name: p.Name,
					Enabled: (p.State>>8)&0xF0 == 0x10, UpToDate: p.State&0xFF == 0})
			}
		}
	}
	s.describe()
	return s
}

// Coexist tells Defender to leave Visionary's data alone (the quarantine
// vault holds neutralised malware) so the two scanners do not fight.
func Coexist(dirs ...string) error {
	var quoted []string
	for _, d := range dirs {
		quoted = append(quoted, "'"+strings.ReplaceAll(d, "'", "''")+"'")
	}
	_, err := ps("Add-MpPreference -ExclusionPath " + strings.Join(quoted, ",") + " -ErrorAction Stop")
	if err != nil {
		return fmt.Errorf("adding Defender exclusions (run as administrator): %w", err)
	}
	return nil
}

// SetPassive writes the documented ForceDefenderPassiveMode policy and
// reports what Defender actually did.
func SetPassive(on bool) (string, error) {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, policyKey, registry.SET_VALUE)
	if err != nil {
		return "", fmt.Errorf("writing the policy needs administrator rights: %w", err)
	}
	defer k.Close()
	if on {
		err = k.SetDWordValue("ForceDefenderPassiveMode", 1)
	} else {
		err = k.DeleteValue("ForceDefenderPassiveMode")
		if errors.Is(err, registry.ErrNotExist) {
			err = nil
		}
	}
	if err != nil {
		return "", err
	}
	s := GetStatus()
	switch {
	case !on:
		return "Passive-mode policy removed. Defender running mode: " + s.RunningMode + ".", nil
	case s.RunningMode == "Passive":
		return "Defender is now in passive mode; Visionary is the primary real-time scanner.", nil
	}
	return "Policy written, but Defender reports running mode \"" + s.RunningMode + "\". A restart may be needed; " +
		"if it stays active: " + passiveExplainer + " Visionary keeps working alongside Defender in the meantime.", nil
}

// OfflineScan asks Windows to reboot into Microsoft Defender Offline, which
// scans from the recovery environment before Windows itself starts.
func OfflineScan() error {
	_, err := ps("Start-MpWDOScan -ErrorAction Stop")
	return err
}

// Defender implements engine.SecondOpinion.
type Defender struct{}

// New returns the Defender bridge.
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

// ScanFile runs a Defender custom scan on one file without remediation, so
// the decision about what happens to the file stays in one place.
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

// ScanBuffer hands content to the registered antimalware provider through
// AMSI: the same interface PowerShell uses to have scripts checked.
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
	return result >= 32768, nil // AMSI_RESULT_DETECTED
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

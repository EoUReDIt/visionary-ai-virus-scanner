//go:build windows

package tray

import (
	"context"
	"math"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modUser32   = windows.NewLazySystemDLL("user32.dll")
	modShell32  = windows.NewLazySystemDLL("shell32.dll")
	modGdi32    = windows.NewLazySystemDLL("gdi32.dll")
	modKernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procGetModuleHandleW      = modKernel32.NewProc("GetModuleHandleW")
	procRegisterClassExW      = modUser32.NewProc("RegisterClassExW")
	procCreateWindowExW       = modUser32.NewProc("CreateWindowExW")
	procDestroyWindow         = modUser32.NewProc("DestroyWindow")
	procDefWindowProcW        = modUser32.NewProc("DefWindowProcW")
	procGetMessageW           = modUser32.NewProc("GetMessageW")
	procTranslateMessage      = modUser32.NewProc("TranslateMessage")
	procDispatchMessageW      = modUser32.NewProc("DispatchMessageW")
	procPostMessageW          = modUser32.NewProc("PostMessageW")
	procPostQuitMessage       = modUser32.NewProc("PostQuitMessage")
	procRegisterWindowMessage = modUser32.NewProc("RegisterWindowMessageW")
	procCreatePopupMenu       = modUser32.NewProc("CreatePopupMenu")
	procAppendMenuW           = modUser32.NewProc("AppendMenuW")
	procSetMenuDefaultItem    = modUser32.NewProc("SetMenuDefaultItem")
	procTrackPopupMenu        = modUser32.NewProc("TrackPopupMenu")
	procDestroyMenu           = modUser32.NewProc("DestroyMenu")
	procGetCursorPos          = modUser32.NewProc("GetCursorPos")
	procSetForegroundWindow   = modUser32.NewProc("SetForegroundWindow")
	procCreateIconIndirect    = modUser32.NewProc("CreateIconIndirect")
	procDestroyIcon           = modUser32.NewProc("DestroyIcon")
	procShellNotifyIconW      = modShell32.NewProc("Shell_NotifyIconW")
	procCreateDIBSection      = modGdi32.NewProc("CreateDIBSection")
	procCreateBitmap          = modGdi32.NewProc("CreateBitmap")
	procDeleteObject          = modGdi32.NewProc("DeleteObject")
)

const (
	wmNull          = 0x0000
	wmDestroy       = 0x0002
	wmClose         = 0x0010
	wmContextMenu   = 0x007B
	wmLButtonUp     = 0x0202
	wmLButtonDblClk = 0x0203
	wmRButtonUp     = 0x0205
	wmApp           = 0x8000
	wmTrayCallback  = wmApp + 1
	wmTrayRefresh   = wmApp + 2

	nimAdd    = 0x00000000
	nimModify = 0x00000001
	nimDelete = 0x00000002

	nifMessage = 0x00000001
	nifIcon    = 0x00000002
	nifTip     = 0x00000004
	nifInfo    = 0x00000010

	niifWarning = 0x00000002

	mfString    = 0x0000
	mfGrayed    = 0x0001
	mfDisabled  = 0x0002
	mfChecked   = 0x0008
	mfSeparator = 0x0800

	tpmRightButton = 0x0002
	tpmNoNotify    = 0x0080
	tpmReturnCmd   = 0x0100

	cmdOpen      = 1001
	cmdQuickScan = 1002
	cmdPause15m  = 1003
	cmdPause1h   = 1004
	cmdResume    = 1005
	cmdGameMode  = 1006
	cmdQuit      = 1007
)

type wndClassExW struct {
	cbSize        uint32
	style         uint32
	lpfnWndProc   uintptr
	cbClsExtra    int32
	cbWndExtra    int32
	hInstance     uintptr
	hIcon         uintptr
	hCursor       uintptr
	hbrBackground uintptr
	lpszMenuName  *uint16
	lpszClassName *uint16
	hIconSm       uintptr
}

type point struct {
	x, y int32
}

type winMsg struct {
	hwnd     uintptr
	message  uint32
	wParam   uintptr
	lParam   uintptr
	time     uint32
	pt       point
	lPrivate uint32
}

// notifyIconDataW matches Win32 NOTIFYICONDATAW (Vista+ / Windows 10 & 11).
type notifyIconDataW struct {
	cbSize           uint32
	hWnd             uintptr
	uID              uint32
	uFlags           uint32
	uCallbackMessage uint32
	hIcon            uintptr
	szTip            [128]uint16
	dwState          uint32
	dwStateMask      uint32
	szInfo           [256]uint16
	uVersion         uint32
	szInfoTitle      [64]uint16
	dwInfoFlags      uint32
	guidItem         windows.GUID
	hBalloonIcon     uintptr
}

type bitmapInfoHeader struct {
	biSize          uint32
	biWidth         int32
	biHeight        int32
	biPlanes        uint16
	biBitCount      uint16
	biCompression   uint32
	biSizeImage     uint32
	biXPelsPerMeter int32
	biYPelsPerMeter int32
	biClrUsed       uint32
	biClrImportant  uint32
}

type iconInfo struct {
	fIcon    uint32
	xHotspot uint32
	yHotspot uint32
	hbmMask  uintptr
	hbmColor uintptr
}

var (
	trayRegistryMu sync.RWMutex
	trayRegistry   = map[uintptr]*Controller{}
	trayWndProcPtr = syscall.NewCallback(trayWndProc)
	classOnce      sync.Once
	classNamePtr   *uint16
	taskbarMsgID   uint32
)

// Controller manages the lifecycle and live updates of a Windows system tray
// icon.
type Controller struct {
	cb      Callbacks
	mu      sync.Mutex
	hwnd    uintptr
	closed  bool
	icons   map[State]uintptr
	last    Info
	hasIcon bool
	ready   chan struct{}
	done    chan struct{}
}

// Start launches the native Windows system tray icon on a dedicated OS thread
// and keeps its visual state synced until ctx is cancelled or Close is called.
func Start(ctx context.Context, cb Callbacks) *Controller {
	c := &Controller{
		cb:    cb,
		icons: map[State]uintptr{},
		ready: make(chan struct{}),
		done:  make(chan struct{}),
	}
	go c.run(ctx)
	return c
}

// Refresh asks the tray thread to immediately re-evaluate protection status
// and redraw its icon and tooltip.
func (c *Controller) Refresh() {
	if c == nil {
		return
	}
	c.mu.Lock()
	hwnd := c.hwnd
	closed := c.closed
	c.mu.Unlock()
	if hwnd != 0 && !closed {
		_, _, _ = procPostMessageW.Call(hwnd, wmTrayRefresh, 0, 0)
	}
}

// Close removes the system tray icon and stops its Win32 message loop.
func (c *Controller) Close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	hwnd := c.hwnd
	closed := c.closed
	c.closed = true
	c.mu.Unlock()
	if hwnd != 0 && !closed {
		_, _, _ = procPostMessageW.Call(hwnd, wmClose, 0, 0)
	}
	<-c.done
}

func (c *Controller) run(ctx context.Context) {
	defer close(c.done)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	hInst, _, _ := procGetModuleHandleW.Call(0)
	classOnce.Do(func() {
		classNamePtr, _ = windows.UTF16PtrFromString("VisionaryTrayWindowClass")
		wc := wndClassExW{
			cbSize:        uint32(unsafe.Sizeof(wndClassExW{})),
			lpfnWndProc:   trayWndProcPtr,
			hInstance:     hInst,
			lpszClassName: classNamePtr,
		}
		_, _, _ = procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
		tbName, _ := windows.UTF16PtrFromString("TaskbarCreated")
		id, _, _ := procRegisterWindowMessage.Call(uintptr(unsafe.Pointer(tbName)))
		taskbarMsgID = uint32(id)
	})

	title, _ := windows.UTF16PtrFromString("Visionary Tray")
	// Use a hidden top-level window (parent = 0, not HWND_MESSAGE) so Explorer
	// broadcasts of TaskbarCreated reach us if Explorer restarts.
	hwnd, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(classNamePtr)),
		uintptr(unsafe.Pointer(title)),
		0, 0, 0, 0, 0,
		0, 0, hInst, 0,
	)
	if hwnd == 0 {
		close(c.ready)
		return
	}

	c.icons[StateActive] = makeShieldIcon(StateActive)
	c.icons[StatePaused] = makeShieldIcon(StatePaused)
	c.icons[StateWarning] = makeShieldIcon(StateWarning)

	trayRegistryMu.Lock()
	trayRegistry[hwnd] = c
	trayRegistryMu.Unlock()

	c.mu.Lock()
	c.hwnd = hwnd
	alreadyClosed := c.closed
	c.mu.Unlock()
	close(c.ready)

	if alreadyClosed {
		_, _, _ = procDestroyWindow.Call(hwnd)
		c.cleanup(hwnd)
		return
	}

	c.addOrUpdate(true, false)

	// Periodic refresh keeps the icon synced with CLI or background service
	// changes, and stops the message loop cleanly when ctx is cancelled.
	go func() {
		t := time.NewTicker(3 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				c.mu.Lock()
				h := c.hwnd
				c.closed = true
				c.mu.Unlock()
				if h != 0 {
					_, _, _ = procPostMessageW.Call(h, wmClose, 0, 0)
				}
				return
			case <-c.done:
				return
			case <-t.C:
				c.Refresh()
			}
		}
	}()

	var m winMsg
	for {
		ret, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(ret) <= 0 {
			break
		}
		_, _, _ = procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		_, _, _ = procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}

	c.cleanup(hwnd)
}

func (c *Controller) cleanup(hwnd uintptr) {
	c.removeIcon(hwnd)
	trayRegistryMu.Lock()
	delete(trayRegistry, hwnd)
	trayRegistryMu.Unlock()
	for _, h := range c.icons {
		if h != 0 {
			_, _, _ = procDestroyIcon.Call(h)
		}
	}
	c.icons = nil
}

func (c *Controller) iconFor(st State) uintptr {
	if h := c.icons[st]; h != 0 {
		return h
	}
	return c.icons[StateActive]
}

func copyUTF16(dst []uint16, s string) {
	u, err := windows.UTF16FromString(s)
	if err != nil {
		return
	}
	if len(u) > len(dst) {
		u = u[:len(dst)]
		u[len(dst)-1] = 0
	}
	copy(dst, u)
}

func (c *Controller) addOrUpdate(add bool, allowBalloon bool) {
	c.mu.Lock()
	hwnd := c.hwnd
	c.mu.Unlock()
	if hwnd == 0 {
		return
	}
	var info Info
	if c.cb.Status != nil {
		info = c.cb.Status()
	} else {
		info = Compute(nil)
	}

	prev := c.last
	if !add && c.hasIcon && prev.State == info.State && prev.Tooltip == info.Tooltip {
		return
	}

	var nid notifyIconDataW
	nid.cbSize = uint32(unsafe.Sizeof(nid))
	nid.hWnd = hwnd
	nid.uID = 1
	nid.uCallbackMessage = wmTrayCallback
	nid.hIcon = c.iconFor(info.State)
	nid.uFlags = nifMessage | nifIcon | nifTip
	copyUTF16(nid.szTip[:], info.Tooltip)

	// Show a non-spammy Windows notification only on a fresh transition into Warning.
	if allowBalloon && prev.State != "" && prev.State != StateWarning && info.State == StateWarning {
		nid.uFlags |= nifInfo
		nid.dwInfoFlags = niifWarning
		copyUTF16(nid.szInfoTitle[:], info.Edition+" — "+info.Label)
		copyUTF16(nid.szInfo[:], info.Detail)
	}

	op := uintptr(nimModify)
	if add || !c.hasIcon {
		op = nimAdd
	}
	r, _, _ := procShellNotifyIconW.Call(op, uintptr(unsafe.Pointer(&nid)))
	if r != 0 {
		c.hasIcon = true
		c.last = info
	}
}

func (c *Controller) removeIcon(hwnd uintptr) {
	if hwnd == 0 || !c.hasIcon {
		return
	}
	var nid notifyIconDataW
	nid.cbSize = uint32(unsafe.Sizeof(nid))
	nid.hWnd = hwnd
	nid.uID = 1
	_, _, _ = procShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&nid)))
	c.hasIcon = false
}

func appendMenuItem(hMenu uintptr, flags uint32, id uintptr, label string) {
	var ptr uintptr
	if label != "" {
		p, _ := windows.UTF16PtrFromString(label)
		ptr = uintptr(unsafe.Pointer(p))
	}
	_, _, _ = procAppendMenuW.Call(hMenu, uintptr(flags), id, ptr)
}

func (c *Controller) showContextMenu(hwnd uintptr) {
	info := c.last
	if c.cb.Status != nil {
		info = c.cb.Status()
		c.addOrUpdate(false, false)
	}

	hMenu, _, _ := procCreatePopupMenu.Call()
	if hMenu == 0 {
		return
	}
	defer procDestroyMenu.Call(hMenu)

	header := info.Edition + " — " + info.Label
	appendMenuItem(hMenu, mfString|mfGrayed|mfDisabled, 0, header)
	appendMenuItem(hMenu, mfSeparator, 0, "")
	openLabel := "Open Visionary Web UI"
	if info.Host != "" {
		openLabel += " (" + info.Host + ")"
	}
	appendMenuItem(hMenu, mfString, cmdOpen, openLabel)
	appendMenuItem(hMenu, mfString, cmdQuickScan, "Run Quick Scan")
	appendMenuItem(hMenu, mfSeparator, 0, "")

	if info.Protection {
		appendMenuItem(hMenu, mfString, cmdPause15m, "Pause Protection (15 min)")
		appendMenuItem(hMenu, mfString, cmdPause1h, "Pause Protection (1 hour)")
	} else {
		appendMenuItem(hMenu, mfString, cmdResume, "Resume Protection")
	}

	gmFlags := uint32(mfString)
	if info.GameMode {
		gmFlags |= mfChecked
	}
	appendMenuItem(hMenu, gmFlags, cmdGameMode, "Game Mode")
	appendMenuItem(hMenu, mfSeparator, 0, "")
	appendMenuItem(hMenu, mfString, cmdQuit, "Quit Visionary Tray")

	// Make "Open Visionary Dashboard" bold as the default double-click action.
	_, _, _ = procSetMenuDefaultItem.Call(hMenu, cmdOpen, 0)

	var pt point
	_, _, _ = procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	_, _, _ = procSetForegroundWindow.Call(hwnd)

	cmd, _, _ := procTrackPopupMenu.Call(
		hMenu,
		tpmRightButton|tpmNoNotify|tpmReturnCmd,
		uintptr(pt.x), uintptr(pt.y),
		0, hwnd, 0,
	)
	// Required by Win32 Shell_NotifyIcon documentation so clicking outside the
	// popup menu always dismisses it cleanly.
	_, _, _ = procPostMessageW.Call(hwnd, wmNull, 0, 0)

	switch cmd {
	case cmdOpen:
		if c.cb.OnOpen != nil {
			go c.cb.OnOpen()
		}
	case cmdQuickScan:
		if c.cb.OnQuickScan != nil {
			go c.cb.OnQuickScan()
		}
	case cmdPause15m:
		if c.cb.OnPause != nil {
			go func() {
				if err := c.cb.OnPause("15m"); err != nil && c.cb.OnOpen != nil {
					c.cb.OnOpen()
				}
				c.Refresh()
			}()
		}
	case cmdPause1h:
		if c.cb.OnPause != nil {
			go func() {
				if err := c.cb.OnPause("1h"); err != nil && c.cb.OnOpen != nil {
					c.cb.OnOpen()
				}
				c.Refresh()
			}()
		}
	case cmdResume:
		if c.cb.OnResume != nil {
			go func() {
				_ = c.cb.OnResume()
				c.Refresh()
			}()
		}
	case cmdGameMode:
		if c.cb.OnToggleGameMode != nil {
			go func() {
				_ = c.cb.OnToggleGameMode()
				c.Refresh()
			}()
		}
	case cmdQuit:
		if c.cb.OnQuit != nil {
			go c.cb.OnQuit()
		}
		_, _, _ = procPostMessageW.Call(hwnd, wmClose, 0, 0)
	}
}

func trayWndProc(hwnd, msg, wParam, lParam uintptr) uintptr {
	trayRegistryMu.RLock()
	c := trayRegistry[hwnd]
	trayRegistryMu.RUnlock()

	if c != nil {
		if taskbarMsgID != 0 && uint32(msg) == taskbarMsgID {
			// Explorer restarted: re-register our notification icon.
			c.hasIcon = false
			c.addOrUpdate(true, false)
			return 0
		}
		switch uint32(msg) {
		case wmTrayCallback:
			switch uint32(lParam & 0xffff) {
			case wmLButtonUp, wmLButtonDblClk:
				if c.cb.OnOpen != nil {
					go c.cb.OnOpen()
				}
			case wmRButtonUp, wmContextMenu:
				c.showContextMenu(hwnd)
			}
			return 0
		case wmTrayRefresh:
			c.addOrUpdate(false, true)
			return 0
		case wmClose:
			c.removeIcon(hwnd)
			_, _, _ = procDestroyWindow.Call(hwnd)
			return 0
		case wmDestroy:
			_, _, _ = procPostQuitMessage.Call(0)
			return 0
		}
	}
	ret, _, _ := procDefWindowProcW.Call(hwnd, msg, wParam, lParam)
	return ret
}

// makeShieldIcon synthesizes a crisp 32x32 32-bit BGRA shield HICON for the
// given protection state so Visionary needs no external .ico files on disk.
func makeShieldIcon(state State) uintptr {
	const size = 32
	pixels := make([]byte, size*size*4)

	// Palette: fill (R,G,B), dark outline (R,G,B), glyph (R,G,B)
	var fr, fg, fb byte
	var br, bg, bb byte
	var gr, gg, gb byte
	switch state {
	case StatePaused:
		fr, fg, fb = 0xF5, 0x9E, 0x0B // Amber
		br, bg, bb = 0x78, 0x35, 0x0F
		gr, gg, gb = 0x1E, 0x13, 0x04
	case StateWarning:
		fr, fg, fb = 0xEF, 0x44, 0x44 // Crimson
		br, bg, bb = 0x7F, 0x1D, 0x1D
		gr, gg, gb = 0xFF, 0xFF, 0xFF
	default:
		fr, fg, fb = 0x10, 0xB9, 0x81 // Emerald
		br, bg, bb = 0x06, 0x4E, 0x3B
		gr, gg, gb = 0xFF, 0xFF, 0xFF
	}

	// Signed distance inside a shield polygon/curve in normalized [-1,1] space.
	shieldDist := func(x, y float64) float64 {
		// Map pixel center (0..31) to [-1, 1]
		nx := (x - 15.5) / 13.5
		ny := (y - 15.5) / 13.5
		ax := math.Abs(nx)
		// Top slanted shoulders from (0, -0.96) to (+/-0.88, -0.62)
		topY := -0.96 + 0.38*ax
		if ny < topY {
			return topY - ny
		}
		// Side width tapers smoothly below y = -0.10 down to point (0, 0.98)
		var maxX float64
		if ny <= -0.10 {
			maxX = 0.88
		} else {
			t := (ny + 0.10) / 1.08
			if t >= 1 {
				return (ny - 0.98)
			}
			maxX = 0.88 * math.Sqrt(1-t*t)
		}
		dx := ax - maxX
		if ny > 0.98 {
			return math.Hypot(math.Max(dx, 0), ny-0.98)
		}
		return dx
	}

	// Segment distance helper for crisp anti-aliased checkmark / pause / warning glyph.
	segDist := func(px, py, ax, ay, bx, by float64) float64 {
		vx, vy := bx-ax, by-ay
		wx, wy := px-ax, py-ay
		c1 := vx*wx + vy*wy
		if c1 <= 0 {
			return math.Hypot(px-ax, py-ay)
		}
		c2 := vx*vx + vy*vy
		if c2 <= c1 {
			return math.Hypot(px-bx, py-by)
		}
		t := c1 / c2
		return math.Hypot(px-(ax+t*vx), py-(ay+t*vy))
	}

	glyphDist := func(x, y float64) float64 {
		switch state {
		case StatePaused:
			d1 := segDist(x, y, 12.2, 10.5, 12.2, 20.5) - 1.9
			d2 := segDist(x, y, 19.8, 10.5, 19.8, 20.5) - 1.9
			return math.Min(d1, d2)
		case StateWarning:
			dBar := segDist(x, y, 16.0, 9.2, 16.0, 17.6) - 1.75
			dDot := math.Hypot(x-16.0, y-22.2) - 1.85
			return math.Min(dBar, dDot)
		default:
			d1 := segDist(x, y, 10.2, 16.0, 14.3, 20.2) - 1.85
			d2 := segDist(x, y, 14.3, 20.2, 22.0, 11.4) - 1.85
			return math.Min(d1, d2)
		}
	}

	clamp01 := func(v float64) float64 {
		if v < 0 {
			return 0
		}
		if v > 1 {
			return 1
		}
		return v
	}

	for py := 0; py < size; py++ {
		for px := 0; px < size; px++ {
			fx, fy := float64(px)+0.5, float64(py)+0.5
			sd := shieldDist(fx, fy)
			// Outer alpha coverage (~1.5px AA edge)
			alpha := clamp01((0.06 - sd) / 0.12)
			if alpha <= 0 {
				continue
			}
			// Subtle darker border near outer edge of shield
			borderMix := clamp01((sd + 0.16) / 0.11)
			r := float64(fr)*(1-borderMix) + float64(br)*borderMix
			g := float64(fg)*(1-borderMix) + float64(bg)*borderMix
			b := float64(fb)*(1-borderMix) + float64(bb)*borderMix

			// Blend foreground glyph
			gd := glyphDist(fx, fy)
			gCov := clamp01((0.6 - gd) / 1.1)
			r = r*(1-gCov) + float64(gr)*gCov
			g = g*(1-gCov) + float64(gg)*gCov
			b = b*(1-gCov) + float64(gb)*gCov

			// Premultiplied BGRA for Windows 32bpp alpha icons
			off := (py*size + px) * 4
			pixels[off+0] = byte(b * alpha)
			pixels[off+1] = byte(g * alpha)
			pixels[off+2] = byte(r * alpha)
			pixels[off+3] = byte(255 * alpha)
		}
	}

	bmi := bitmapInfoHeader{
		biSize:        uint32(unsafe.Sizeof(bitmapInfoHeader{})),
		biWidth:       size,
		biHeight:      -size, // top-down DIB
		biPlanes:      1,
		biBitCount:    32,
		biCompression: 0, // BI_RGB
	}
	var bits unsafe.Pointer
	hbmColor, _, _ := procCreateDIBSection.Call(
		0,
		uintptr(unsafe.Pointer(&bmi)),
		0, // DIB_RGB_COLORS
		uintptr(unsafe.Pointer(&bits)),
		0, 0,
	)
	if hbmColor == 0 || bits == nil {
		if hbmColor != 0 {
			_, _, _ = procDeleteObject.Call(hbmColor)
		}
		return 0
	}
	dst := unsafe.Slice((*byte)(bits), len(pixels))
	copy(dst, pixels)

	hbmMask, _, _ := procCreateBitmap.Call(size, size, 1, 1, 0)
	if hbmMask == 0 {
		_, _, _ = procDeleteObject.Call(hbmColor)
		return 0
	}

	ii := iconInfo{
		fIcon:    1,
		hbmMask:  hbmMask,
		hbmColor: hbmColor,
	}
	hIcon, _, _ := procCreateIconIndirect.Call(uintptr(unsafe.Pointer(&ii)))
	_, _, _ = procDeleteObject.Call(hbmColor)
	_, _, _ = procDeleteObject.Call(hbmMask)
	return hIcon
}

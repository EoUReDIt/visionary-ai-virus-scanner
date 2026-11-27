// Package tray implements Visionary's native system tray icon. It displays the
// live protection state (active, paused, or warning) and provides quick access
// to the dashboard, quick scan, pause/resume controls, game mode, and clean
// shutdown.
package tray

import (
	"fmt"
	"strings"

	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/app"
)

// State represents the three visual indicator states of the system tray icon.
type State string

const (
	StateActive  State = "active"
	StatePaused  State = "paused"
	StateWarning State = "warning"
)

// Info is a snapshot of the protection status rendered by the tray icon and
// its context menu.
type Info struct {
	State       State  `json:"state"`
	Label       string `json:"label"`
	Detail      string `json:"detail"`
	Tooltip     string `json:"tooltip"`
	Edition     string `json:"edition"`
	Host        string `json:"host,omitempty"`
	Protection  bool   `json:"protection"`
	GameMode    bool   `json:"game_mode"`
	Quarantined int    `json:"quarantined"`
}

// WithHost attaches the active local web UI host:port (e.g. 127.0.0.1:7878)
// and includes it in the hover tooltip.
func (i Info) WithHost(host string) Info {
	i.Host = host
	if host == "" {
		return i
	}
	tip := i.Edition + " — " + i.Label + "\nhttp://" + host
	if len(tip) > 124 {
		tip = tip[:121] + "..."
	}
	i.Tooltip = tip
	return i
}

// Callbacks wires tray user actions back into the dashboard host process.
type Callbacks struct {
	Status           func() Info
	OnOpen           func()
	OnQuickScan      func()
	OnPause          func(forArg string) error
	OnResume         func() error
	OnToggleGameMode func() error
	OnQuit           func()
}

// Compute derives the tray state, short label, detail text, and Win32 tooltip
// from an app.Status snapshot.
func Compute(s *app.Status) Info {
	if s == nil {
		return Info{
			State:   StateWarning,
			Label:   "Warning: Status Unavailable",
			Detail:  "Unable to read protection status",
			Tooltip: "Visionary — Status unavailable",
		}
	}

	ed := "Visionary"
	switch strings.ToLower(s.Edition) {
	case "core":
		ed = "Visionary Core"
	case "safe":
		ed = "Visionary Safe"
	case "lite":
		ed = "Visionary Lite"
	}

	info := Info{
		Edition:     ed,
		Protection:  s.Protection,
		GameMode:    s.GameMode,
		Quarantined: s.Quarantine,
	}

	lowReason := strings.ToLower(s.ProtReason)
	switch {
	case !s.Protection && strings.Contains(lowReason, "re-enabled"):
		info.State = StateWarning
		info.Label = "Warning: Protection Off"
		info.Detail = "Real-time protection is turned off"
	case !s.Protection:
		info.State = StatePaused
		info.Label = "Protection Paused"
		if s.ProtReason != "" {
			info.Detail = strings.ToUpper(s.ProtReason[:1]) + s.ProtReason[1:]
		} else {
			info.Detail = "Real-time protection is temporarily paused"
		}
	case !s.GuardAlive:
		info.State = StateWarning
		info.Label = "Warning: Guard Offline"
		info.Detail = "Real-time protection service is not running"
	case s.Quarantine > 0:
		info.State = StateWarning
		if s.Quarantine == 1 {
			info.Label = "Warning: 1 Threat Quarantined"
			info.Detail = "1 quarantined file awaiting review"
		} else {
			info.Label = fmt.Sprintf("Warning: %d Threats Quarantined", s.Quarantine)
			info.Detail = fmt.Sprintf("%d quarantined files awaiting review", s.Quarantine)
		}
	case len(s.Warnings) > 0:
		info.State = StateWarning
		info.Label = "Warning: Attention Needed"
		info.Detail = s.Warnings[0]
	default:
		info.State = StateActive
		if s.GameMode {
			info.Label = "Protected (Game Mode)"
			info.Detail = "Real-time protection active at background priority"
		} else {
			info.Label = "Protected"
			info.Detail = "Real-time AI protection is active"
		}
	}

	tip := ed + " — " + info.Label
	if info.Detail != "" {
		tip += "\n" + info.Detail
	}
	if len(tip) > 124 {
		tip = tip[:121] + "..."
	}
	info.Tooltip = tip
	return info
}

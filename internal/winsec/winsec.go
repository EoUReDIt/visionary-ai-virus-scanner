// Package winsec is the bridge to Windows Security: reading Microsoft
// Defender's state, co-existing with it, asking it for a second opinion, and
// the documented switches for passive mode and the offline (pre-boot) scan.
//
// Everything here uses supported interfaces only (PowerShell Defender
// cmdlets, Security Center WMI, AMSI, MpCmdRun, WinVerifyTrust and one
// documented policy value). It deliberately does not register itself with
// Windows Security Center through undocumented APIs.
package winsec

// Product is an antivirus registered with Windows Security Center.
type Product struct {
	Name     string `json:"name"`
	Enabled  bool   `json:"enabled"`
	UpToDate bool   `json:"up_to_date"`
}

// Status is the view of Windows Security the app shows and reasons about.
type Status struct {
	Available       bool      `json:"available"`
	RunningMode     string    `json:"running_mode"` // Normal | Passive | EDR Block Mode | SxS Passive Mode | Not running
	RealTime        bool      `json:"realtime_enabled"`
	TamperProtected bool      `json:"tamper_protected"`
	SignatureDate   string    `json:"signature_updated,omitempty"`
	ForcePassive    bool      `json:"force_passive_policy"`
	Products        []Product `json:"products,omitempty"`
	Role            string    `json:"visionary_role"`
	Notes           []string  `json:"notes,omitempty"`
}

const passiveExplainer = "On Windows 10/11 Home and Pro, Defender only switches itself to passive (disabled) mode when another " +
	"antivirus is registered with Windows Security Center. That registration is reserved for vendors in the Microsoft Virus " +
	"Initiative with a signed protected service, so an independent app cannot perform it. The ForceDefenderPassiveMode policy " +
	"is honoured on Windows Server and on devices onboarded to Microsoft Defender for Endpoint."

// describe fills in the role Visionary plays next to Defender.
func (s *Status) describe() {
	switch {
	case !s.Available:
		s.Role = "primary scanner (Windows Security not available on this system)"
	case s.RunningMode == "Passive" || s.RunningMode == "SxS Passive Mode" || s.RunningMode == "EDR Block Mode":
		s.Role = "primary real-time scanner (Defender is passive: it still scans on demand and keeps its definitions current)"
	case !s.RealTime:
		s.Role = "primary real-time scanner (Defender real-time protection is off)"
	default:
		s.Role = "second layer alongside Defender (both active; Visionary's folders are excluded in Defender to avoid double work)"
	}
	if s.ForcePassive && s.RunningMode == "Normal" {
		s.Notes = append(s.Notes, "ForceDefenderPassiveMode is set but Defender is still active. "+passiveExplainer)
	}
	if s.TamperProtected {
		s.Notes = append(s.Notes, "Tamper Protection is on: Defender settings can only be changed from the Windows Security app.")
	}
}

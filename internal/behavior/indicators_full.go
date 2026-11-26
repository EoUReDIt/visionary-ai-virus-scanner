//go:build !safe

package behavior

import "regexp"

var shells = map[string]bool{"powershell": true, "pwsh": true, "cmd": true, "wscript": true, "cscript": true,
	"mshta": true, "rundll32": true, "regsvr32": true, "certutil": true, "bitsadmin": true, "wmic": true,
	"schtasks": true, "bash": true, "sh": true, "curl": true}

var cmdIndicators = []cmdIndicator{
	{regexp.MustCompile(`(?i)\s-e(nc(odedcommand)?)?\s+[a-z0-9+/=]{40,}`), 30, "encoded PowerShell command"},
	{regexp.MustCompile(`(?i)-w(in(dowstyle)?)?\s+hidden`), 15, "hidden window"},
	{regexp.MustCompile(`(?i)downloadstring|downloadfile|frombase64string|invoke-expression|\biex\b`), 25, "download/decode-and-run"},
	{regexp.MustCompile(`(?i)/i:https?://|javascript:|vbscript:|-urlcache`), 30, "remote scriptlet execution"},
	{regexp.MustCompile(`(?i)vssadmin\s+delete|wbadmin\s+delete|recoveryenabled\s+no|wevtutil\s+cl`), 45, "destroys backups or logs"},
	{regexp.MustCompile(`(?i)add-mppreference|disablerealtimemonitoring|set-mppreference`), 35, "changes antivirus settings"},
}

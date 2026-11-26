//go:build safe

package behavior

// Safe edition omits plaintext Defender-tampering, backup-deletion and LOLBin
// command-line signature regexes from the compiled binary. Normal baseline
// anomaly scoring (never-seen programs, risky folder execution, unfamiliar
// parent-child chains, and file-change bursts) remains active.
var shells = map[string]bool{}

var cmdIndicators []cmdIndicator

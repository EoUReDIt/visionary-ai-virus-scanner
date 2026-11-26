//go:build !lite && !safe

// Package edition identifies which release build this binary is:
//   - core (default): full AI dashboard, CLI, real-time guard, and all heuristic/behavioral/Defender features
//   - lite (-tags lite): full detection engine in a minimal CPU-only CLI build (no dashboard)
//   - safe (-tags safe): AI dashboard, CLI, YARA, hashes, certs, and baseline learning without
//     Defender-triggering heuristic strings or Defender policy/PowerShell automation
package edition

const (
	Lite = false
	Safe = false
	Name = "core"
)

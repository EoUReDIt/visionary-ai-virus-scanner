//go:build !lite

// Package edition says which build this is. The Lite edition is compiled with
// `-tags lite`: no dashboard, CPU-only local AI, and low-footprint defaults.
package edition

const (
	Lite = false
	Name = "full"
)

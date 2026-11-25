//go:build lite

package config

import "testing"

func TestLiteEditionDefaults(t *testing.T) {
	if c := Default(); c.Profile != "lite" || !c.AI.Local.CPUOnly {
		t.Fatalf("lite build must start from the lite preset: %+v", c)
	}
}

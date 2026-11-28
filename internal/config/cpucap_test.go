package config

import "testing"

func TestGuardCPUCap(t *testing.T) {
	cases := []struct {
		name    string
		profile string
		set     int
		want    int
	}{
		{"core default is uncapped", "", 0, 0},
		{"lite default", "lite", 0, LiteCPUCap},
		{"explicit value wins", "lite", 6, 6},
		{"explicit value on core", "", 20, 20},
		{"negative turns it off", "lite", -1, 0},
		{"clamped to 100", "", 500, 100},
	}
	for _, c := range cases {
		cfg := Default()
		cfg.Profile = c.profile
		cfg.Realtime.CPUCapPercent = c.set
		if got := cfg.GuardCPUCap(); got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
	lite := Default()
	ApplyLite(lite)
	if lite.GuardCPUCap() != LiteCPUCap {
		t.Errorf("ApplyLite should leave the Lite default cap, got %d", lite.GuardCPUCap())
	}
}

package config

import "testing"

func TestApplyLite(t *testing.T) {
	c := defaults()
	ApplyLite(c)
	if c.Profile != "lite" || c.Scan.Workers != 1 || c.Realtime.Workers != 1 || !c.AI.Local.CPUOnly || c.AI.Local.MaxParamsB > 2 {
		t.Fatalf("lite preset wrong: %+v", c)
	}
	if c.AI.Local.Model != "gemma3:1b" || c.Behavior.PollMS <= 1500 || c.Realtime.SettleMS <= 700 {
		t.Fatalf("lite timings/model wrong: %+v", c.AI.Local)
	}
	// The full edition's defaults stay GPU-capable.
	if d := defaults(); d.AI.Local.CPUOnly || d.Scan.Workers != 0 {
		t.Errorf("full defaults changed: %+v", d)
	}
}

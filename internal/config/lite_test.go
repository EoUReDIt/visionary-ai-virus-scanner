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

func TestGPUModeMigration(t *testing.T) {
	cases := []struct {
		in   LocalAI
		want string
	}{
		{LocalAI{}, "auto"},                       // old Core config, no setting
		{LocalAI{CPUOnly: true}, "off"},           // old Lite config: cpu_only maps to off
		{LocalAI{GPU: "on", CPUOnly: true}, "on"}, // explicit value wins
		{LocalAI{GPU: "bogus"}, "auto"},
	}
	for _, c := range cases {
		if got := c.in.GPUMode(); got != c.want {
			t.Errorf("%+v: got %s want %s", c.in, got, c.want)
		}
	}
	var l LocalAI
	l.SetGPU("off")
	if !l.CPUOnly {
		t.Error("SetGPU(off) must keep the cpu_only alias true")
	}
	l.SetGPU("auto")
	if l.CPUOnly {
		t.Error("SetGPU(auto) must clear cpu_only")
	}
	c := defaults()
	ApplyLite(c)
	if c.AI.Local.GPUMode() != "off" {
		t.Errorf("Lite must default to gpu=off, got %s", c.AI.Local.GPUMode())
	}
}

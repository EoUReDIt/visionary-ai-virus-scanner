package behavior

import (
	"testing"

	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/plat"
)

func TestProcessScoring(t *testing.T) {
	t.Setenv("VISIONARY_HOME", t.TempDir())
	m := NewMonitor()
	explorer := &plat.Proc{PID: 1, Exe: `C:\Windows\explorer.exe`}
	code := plat.Proc{PID: 2, Exe: `C:\Users\sam\AppData\Local\Programs\VS Code\Code.exe`}
	ps := plat.Proc{PID: 3, Exe: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, Cmdline: "powershell -NoLogo"}

	// Learning: a developer's normal day.
	for i := 0; i < 6; i++ {
		if an := m.Observe(code, explorer, true, 50); an != nil {
			t.Fatalf("learning flagged normal start: %+v", an)
		}
		if an := m.Observe(ps, &code, true, 50); an != nil {
			t.Fatalf("learning flagged editor shell: %+v", an)
		}
	}
	// After learning the same activity stays quiet, for any user name.
	code2 := code
	code2.Exe = `C:\Users\alex\AppData\Local\Programs\VS Code\Code.exe`
	if an := m.Observe(ps, &code2, false, 50); an != nil {
		t.Errorf("known pattern flagged: %+v", an)
	}
	// A never-seen program from Temp is an anomaly.
	drop := plat.Proc{PID: 9, Exe: `C:\Users\sam\AppData\Local\Temp\svch0st.exe`}
	if an := m.Observe(drop, explorer, false, 50); an == nil || an.Score < 50 {
		t.Errorf("temp dropper not flagged: %+v", an)
	}
	// ...and is not learned by repetition.
	if an := m.Observe(drop, explorer, false, 50); an == nil {
		t.Error("anomaly became normal after one repeat")
	}
	// Universal rule: works even while learning.
	discord := &plat.Proc{PID: 5, Exe: `C:\Users\sam\AppData\Local\Discord\Discord.exe`}
	enc := plat.Proc{PID: 6, Exe: ps.Exe, Cmdline: "powershell -w hidden -enc " + "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9w"}
	if an := m.Observe(enc, discord, true, 50); an == nil || an.Score < 80 {
		t.Errorf("chat app spawning encoded PowerShell: %+v", an)
	}
}

func TestFileBurst(t *testing.T) {
	t.Setenv("VISIONARY_HOME", t.TempDir())
	m := NewMonitor()
	for i := 0; i < 60; i++ {
		if an := m.ObserveFileRate(3+i%4, false); an != nil {
			t.Fatalf("normal rate flagged at window %d", i)
		}
	}
	if an := m.ObserveFileRate(900, false); an == nil {
		t.Error("burst not flagged")
	}
	if an := m.ObserveFileRate(900, true); an != nil {
		t.Error("burst flagged while learning")
	}
}

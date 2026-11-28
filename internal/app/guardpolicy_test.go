package app

import (
	"context"
	"testing"
	"time"

	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/config"
)

func TestRescanBackoffGrowsAndResets(t *testing.T) {
	b := newRescanBackoff(5 * time.Second)
	t0 := time.Unix(1000, 0)
	if !b.allow("a", t0) {
		t.Fatal("first scan must be allowed")
	}
	if b.allow("a", t0.Add(4*time.Second)) {
		t.Fatal("rescan inside 5s must wait")
	}
	if !b.allow("a", t0.Add(5*time.Second)) { // level 0 -> 1
		t.Fatal("rescan after 5s must be allowed")
	}
	if b.allow("a", t0.Add(5*time.Second+14*time.Second)) {
		t.Fatal("second rescan must wait 15s")
	}
	if !b.allow("a", t0.Add(5*time.Second+15*time.Second)) { // level 1 -> 2
		t.Fatal("rescan after 15s must be allowed")
	}
	last := t0.Add(20 * time.Second)
	if b.allow("a", last.Add(59*time.Second)) {
		t.Fatal("third rescan must wait 60s")
	}
	if !b.allow("a", last.Add(60*time.Second)) {
		t.Fatal("rescan after 60s must be allowed")
	}
	// Other paths are independent.
	if !b.allow("b", t0.Add(time.Second)) {
		t.Fatal("independent path must be allowed")
	}
	// Quiet for long enough: starts over.
	quiet := last.Add(60*time.Second + 130*time.Second)
	if !b.allow("a", quiet) || b.allow("a", quiet.Add(4*time.Second)) {
		t.Fatal("quiet path must start over at the base wait")
	}
	b.prune(quiet.Add(time.Hour))
	if len(b.state) != 0 {
		t.Fatalf("prune left %d entries", len(b.state))
	}
}

func TestSkippedExt(t *testing.T) {
	list := []string{".log", ".mp4"}
	for p, want := range map[string]bool{
		`C:\Users\a\Downloads\app.LOG`: true, "movie.mp4": true,
		"setup.exe": false, "run.ps1": false, "noext": false, "report.docx": false,
	} {
		if got := skippedExt(p, list); got != want {
			t.Errorf("skippedExt(%q) = %v, want %v", p, got, want)
		}
	}
	if skippedExt("x.log", nil) {
		t.Error("empty list must skip nothing")
	}
}

func TestLiteSkipListNeverHidesRunnableTypes(t *testing.T) {
	for _, e := range config.LiteSkipExtensions {
		switch e {
		case ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".msi", ".lnk",
			".zip", ".rar", ".7z", ".iso", ".doc", ".docx", ".xls", ".xlsm", ".pdf", ".hta", ".wsf":
			t.Errorf("skip list must not contain %s", e)
		}
	}
}

func TestThrottle(t *testing.T) {
	start := time.Now()
	throttle(context.Background(), 20*time.Millisecond, 50) // sleeps ~20ms
	if d := time.Since(start); d < 15*time.Millisecond {
		t.Errorf("throttle slept only %v", d)
	}
	start = time.Now()
	throttle(context.Background(), time.Second, 0)
	throttle(context.Background(), time.Second, 100)
	if time.Since(start) > 50*time.Millisecond {
		t.Error("throttle must be a no-op at 0 and 100")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start = time.Now()
	throttle(ctx, time.Second, 10)
	if time.Since(start) > 50*time.Millisecond {
		t.Error("throttle must return when ctx is cancelled")
	}
}

func TestSplitList(t *testing.T) {
	if got := splitList("a, b"); len(got) != 2 || got[1] != "b" {
		t.Errorf("comma list: %v", got)
	}
	if got := splitList(`C:\a b;D:\c`); len(got) != 2 || got[0] != `C:\a b` {
		t.Errorf("path list: %v", got)
	}
	if splitList("default") != nil || splitList("") != nil {
		t.Error("default/empty must clear the list")
	}
	if got := normalizeExts([]string{"LOG", " .Tmp "}); got[0] != ".log" || got[1] != ".tmp" {
		t.Errorf("normalizeExts: %v", got)
	}
}

func TestLitePresetRealtime(t *testing.T) {
	c := &config.Config{}
	config.ApplyLite(c)
	if c.Realtime.CPUPercent != 15 || len(c.Realtime.SkipExtensions) == 0 {
		t.Errorf("lite realtime preset: %+v", c.Realtime)
	}
}

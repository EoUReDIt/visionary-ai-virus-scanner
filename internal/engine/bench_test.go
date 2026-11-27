package engine

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/config"
	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/defs"
)

func TestTimingLargePE(t *testing.T) {
	p := os.Getenv("VISIONARY_BENCH_FILE")
	if p == "" {
		t.Skip("set VISIONARY_BENCH_FILE to time a scan")
	}
	e, _ := setup(t)
	data, _ := os.ReadFile(p)
	t0 := time.Now()
	e.DB.Rules.Scan(data)
	t.Logf("rules: %v", time.Since(t0))
	t0 = time.Now()
	interestingStrings(data, 40)
	t.Logf("strings: %v", time.Since(t0))
	t0 = time.Now()
	analyzePE(data)
	t.Logf("pe: %v", time.Since(t0))
	t0 = time.Now()
	e.ScanFile(context.Background(), p, Options{NoCache: true})
	t.Logf("total: %v", time.Since(t0))
}

func benchEngine(b *testing.B) (*Engine, string) {
	b.Helper()
	b.Setenv("VISIONARY_HOME", b.TempDir())
	db, err := defs.Open()
	if err != nil {
		b.Fatal(err)
	}
	return New(config.Default(), db), b.TempDir()
}

func BenchmarkScanFileSmall(b *testing.B) {
	e, dir := benchEngine(b)
	p := filepath.Join(dir, "sample.txt")
	if err := os.WriteFile(p, bytes.Repeat([]byte("hello visionary scanner\n"), 256), 0o644); err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if r := e.ScanFile(ctx, p, Options{NoCache: true}); r.Verdict != Clean {
			b.Fatalf("unexpected verdict: %s", r.Verdict)
		}
	}
}

func BenchmarkScanFileLarge8MB(b *testing.B) {
	e, dir := benchEngine(b)
	p := filepath.Join(dir, "large.bin")
	payload := bytes.Repeat([]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}, 1<<20) // 8 MiB
	if err := os.WriteFile(p, payload, 0o644); err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if r := e.ScanFile(ctx, p, Options{NoCache: true}); r.Verdict != Clean {
			b.Fatalf("unexpected verdict: %s", r.Verdict)
		}
	}
}

func BenchmarkScanFileCached(b *testing.B) {
	e, dir := benchEngine(b)
	p := filepath.Join(dir, "cached.txt")
	if err := os.WriteFile(p, []byte("clean cached file"), 0o644); err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	e.ScanFile(ctx, p, Options{})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if r := e.ScanFile(ctx, p, Options{}); !r.Cached {
			b.Fatal("expected cache hit")
		}
	}
}

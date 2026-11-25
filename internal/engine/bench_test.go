package engine

import (
	"context"
	"os"
	"testing"
	"time"
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

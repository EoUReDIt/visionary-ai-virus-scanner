package reputation

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type ctxProvider struct{ calls int }

func (p *ctxProvider) ProviderName() string { return "ctx" }

func (p *ctxProvider) Lookup(ctx context.Context, s string) (int, int, string, bool, error) {
	m, t, l, _, f, e := p.LookupDetail(ctx, s)
	return m, t, l, f, e
}
func (p *ctxProvider) LookupDetail(ctx context.Context, s string) (int, int, string, string, bool, error) {
	p.calls++
	return 0, 0, "", "", false, nil
}
func (p *ctxProvider) LookupBatch(ctx context.Context, h []string) map[string]LookupResult {
	return nil
}

func TestMultiStopsOnCancelledContext(t *testing.T) {
	a, b := &ctxProvider{}, &ctxProvider{}
	m := NewMulti(a, b)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, _, _, found, err := m.LookupDetail(ctx, testSHA256)
	if found || err == nil {
		t.Fatalf("want error on cancelled ctx, got found=%v err=%v", found, err)
	}
	if a.calls+b.calls != 0 {
		t.Fatalf("providers called after cancellation: %d", a.calls+b.calls)
	}
}

func TestDiskCacheConcurrentFlushKeepsLatest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rep.json")
	c := OpenCache(path)
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c.Put("p", fmt.Sprintf("hash%02d", i), cacheRecord{Found: true, ExpiresAt: time.Now().Add(time.Hour)})
			c.Flush()
		}(i)
	}
	wg.Wait()
	c.Flush()
	re := OpenCache(path)
	for i := 0; i < 40; i++ {
		if _, ok := re.Get("p", fmt.Sprintf("hash%02d", i)); !ok {
			t.Fatalf("entry %d missing after concurrent flushes", i)
		}
	}
}

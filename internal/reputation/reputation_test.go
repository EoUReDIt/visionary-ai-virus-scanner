package reputation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testSHA256 = "464535ead01ac837e1329effb49e4d8074b466eb70fe0949410e75b68c2a61e6"

func TestOTXLookupAndPersistentCache(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("X-OTX-API-KEY") != "otx-secret" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if !strings.HasSuffix(r.URL.Path, "/indicators/file/"+testSHA256+"/general") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{
			"pulse_info": {
				"count": 4,
				"pulses": [
					{"name": "AgentTesla Campaign", "malware_families": ["AgentTesla"]}
				]
			}
		}`))
	}))
	defer srv.Close()

	cachePath := filepath.Join(t.TempDir(), "reputation_cache.json")
	o1 := NewOTXWithCache("otx-secret", OpenCache(cachePath))
	o1.BaseURL = srv.URL

	mal, tot, lbl, det, found, err := o1.LookupDetail(context.Background(), testSHA256)
	if err != nil || !found {
		t.Fatalf("expected hit, got found=%v err=%v", found, err)
	}
	if mal < 5 || tot < 4 || lbl != "OTX.AgentTesla" || !strings.Contains(det, "AlienVault OTX") {
		t.Fatalf("unexpected OTX result: mal=%d tot=%d lbl=%q det=%q", mal, tot, lbl, det)
	}

	// Reload disk cache into a brand-new OTX client: should hit cache with 0 API calls.
	o2 := NewOTXWithCache("otx-secret", OpenCache(cachePath))
	o2.BaseURL = srv.URL
	mal2, _, lbl2, _, found2, err2 := o2.LookupDetail(context.Background(), testSHA256)
	if err2 != nil || !found2 || mal2 != mal || lbl2 != lbl {
		t.Fatalf("cached lookup mismatch: mal=%d lbl=%q found=%v err=%v", mal2, lbl2, found2, err2)
	}
	if hits.Load() != 1 {
		t.Fatalf("expected exactly 1 HTTP request thanks to persistent cache, got %d", hits.Load())
	}
}

func TestOTXExportSHA256CompactFeed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-OTX-API-KEY") != "k" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/indicators/export" || r.URL.Query().Get("types") != "FileHash-SHA256" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.URL.Query().Get("modified_since") == "" {
			t.Errorf("expected modified_since query param")
		}
		_, _ = w.Write([]byte(`{
			"results": [
				{"indicator": "` + testSHA256 + `", "type": "FileHash-SHA256", "title": "RedLine Stealer"},
				{"indicator": "` + strings.ToUpper(testSHA256) + `", "type": "FileHash-SHA256", "title": "Duplicate"},
				{"indicator": "not-a-sha256", "type": "FileHash-SHA256", "title": "Bad"}
			],
			"next": ""
		}`))
	}))
	defer srv.Close()

	o := NewOTX("k")
	o.BaseURL = srv.URL
	items, err := o.ExportSHA256(context.Background(), time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].SHA256 != testSHA256 || items[0].Label != "OTX.RedLine Stealer" {
		t.Fatalf("unexpected export result: %+v", items)
	}
}

func TestMultiSkipsVirusTotalWhenOTXConvicts(t *testing.T) {
	var vtHits atomic.Int32
	vtSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vtHits.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer vtSrv.Close()

	otxSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"pulse_info":{"count":5,"pulses":[{"name":"Ransom"}]}}`))
	}))
	defer otxSrv.Close()

	o := NewOTX("k")
	o.BaseURL = otxSrv.URL
	v := NewVirusTotal("k")
	v.BaseURL = vtSrv.URL

	m := NewMulti(o, v)
	mal, _, lbl, _, found, err := m.LookupDetail(context.Background(), testSHA256)
	if err != nil || !found || mal < 5 || lbl != "OTX.Ransom" {
		t.Fatalf("expected OTX hit, got mal=%d lbl=%q found=%v err=%v", mal, lbl, found, err)
	}
	if vtHits.Load() != 0 {
		t.Fatalf("expected VirusTotal to be skipped after OTX conviction, got %d VT calls", vtHits.Load())
	}
}

func TestMultiLookupBatchRespectsPacingAndBatchFlush(t *testing.T) {
	const (
		convictedHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		cleanHashA    = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		cleanHashB    = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	)
	var vtCalled []string
	vtSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		h := parts[len(parts)-1]
		vtCalled = append(vtCalled, h)
		_, _ = w.Write([]byte(`{"data":{"attributes":{"last_analysis_stats":{"harmless":60,"malicious":0}}}}`))
	}))
	defer vtSrv.Close()

	otxSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, convictedHash) {
			_, _ = w.Write([]byte(`{"pulse_info":{"count":6,"pulses":[{"name":"Stealer"}]}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer otxSrv.Close()

	cachePath := filepath.Join(t.TempDir(), "reputation_cache.json")
	cache := OpenCache(cachePath)
	o := NewOTXWithCache("k", cache)
	o.BaseURL = otxSrv.URL
	v := NewVirusTotalWithCache("k", cache)
	v.BaseURL = vtSrv.URL
	v.PaceDelay = 15 * time.Millisecond

	start := time.Now()
	m := NewMulti(o, v)
	res := m.LookupBatch(context.Background(), []string{convictedHash, cleanHashA, cleanHashB, cleanHashA})
	elapsed := time.Since(start)

	if len(vtCalled) != 2 {
		t.Fatalf("expected VirusTotal to receive only 2 non-convicted unique hashes, got %d (%v)", len(vtCalled), vtCalled)
	}
	if elapsed < 12*time.Millisecond {
		t.Fatalf("expected Multi.LookupBatch to honor VirusTotal PaceDelay, finished in %v", elapsed)
	}
	if r := res[convictedHash]; !r.Found || r.Malicious < 5 || r.Label != "OTX.Stealer" {
		t.Fatalf("unexpected convicted result: %+v", r)
	}
	if r := res[cleanHashA]; !r.Found || r.Malicious != 0 || r.Total != 60 {
		t.Fatalf("unexpected clean result A: %+v", r)
	}
	// Reload disk cache: batch flush must have persisted all entries.
	reloaded := OpenCache(cachePath)
	if _, ok := reloaded.Get("virustotal", cleanHashB); !ok {
		t.Fatalf("expected batch flush to persist %s to disk cache", cleanHashB)
	}
}

func TestCIRCLHashlookup(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if strings.HasSuffix(r.URL.Path, "/lookup/sha256/"+testSHA256) {
			_, _ = w.Write([]byte(`{"FileName":"notepad.exe","ProductName":"Microsoft Windows","source":"NSRL"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := NewCIRCLWithCache(OpenCache(filepath.Join(t.TempDir(), "circl.json")))
	c.BaseURL = srv.URL

	mal, tot, lbl, det, found, err := c.LookupDetail(context.Background(), testSHA256)
	if err != nil || !found || mal != 0 || tot < 40 || lbl != "notepad.exe" || !strings.Contains(det, "CIRCL") {
		t.Fatalf("unexpected CIRCL known-good result: mal=%d tot=%d lbl=%q det=%q found=%v err=%v", mal, tot, lbl, det, found, err)
	}
	// Repeat lookup must hit cache with 0 extra HTTP requests.
	if _, _, _, _, found2, err2 := c.LookupDetail(context.Background(), testSHA256); err2 != nil || !found2 || hits.Load() != 1 {
		t.Fatalf("expected cached hit, got found=%v err=%v hits=%d", found2, err2, hits.Load())
	}
	// Unknown hash returns found=false without error.
	unknown := strings.Repeat("d", 64)
	if _, _, _, _, found3, err3 := c.LookupDetail(context.Background(), unknown); err3 != nil || found3 {
		t.Fatalf("expected not-found for unknown hash, got found=%v err=%v", found3, err3)
	}
}

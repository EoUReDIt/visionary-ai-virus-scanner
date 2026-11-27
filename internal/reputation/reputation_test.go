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

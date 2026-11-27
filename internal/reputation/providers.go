// Package reputation queries hash-only Threat Exchange APIs (VirusTotal and
// AlienVault OTX) with persistent on-disk caching to minimize API quota usage.
// Only SHA-256 digests ever leave the machine; files are never uploaded.
package reputation

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/config"
)

// ProviderInfo describes one Threat Exchange provider for the UI and CLI picker.
type ProviderInfo struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	SecretName       string `json:"secret_name"`
	DocsURL          string `json:"docs_url"`
	DocsHint         string `json:"docs_hint"`
	SupportsBulkSync bool   `json:"supports_bulk_sync"`
}

// Providers lists the Threat Exchange options shown in the picker.
var Providers = []ProviderInfo{
	{
		ID:               "virustotal",
		Name:             "VirusTotal",
		SecretName:       "virustotal",
		DocsURL:          "https://www.virustotal.com/gui/my-apikey",
		DocsHint:         "Multi-engine SHA-256 hash lookups via VirusTotal API v3 (x-apikey). Cached on disk to save daily quota.",
		SupportsBulkSync: false,
	},
	{
		ID:               "otx",
		Name:             "AlienVault OTX",
		SecretName:       "otx",
		DocsURL:          "https://otx.alienvault.com/api",
		DocsHint:         "Open Threat Exchange DirectConnect API v1 (X-OTX-API-KEY). Supports compact per-hash pulse lookups and bulk SHA-256 feed sync.",
		SupportsBulkSync: true,
	},
	{
		ID:               "both",
		Name:             "VirusTotal + AlienVault OTX",
		SecretName:       "",
		DocsURL:          "https://otx.alienvault.com/api",
		DocsHint:         "Checks AlienVault OTX first (higher rate limit) and falls back to VirusTotal only when needed, stopping on the first confirmed threat.",
		SupportsBulkSync: true,
	},
}

// NormalizeProvider maps user input to canonical provider IDs.
func NormalizeProvider(p string) string {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "virustotal", "vt":
		return "virustotal"
	case "otx", "alienvault", "alienvault-otx", "alienvault_otx":
		return "otx"
	case "both", "all":
		return "both"
	default:
		return ""
	}
}

// SecretName returns the vault key name for a single Threat Exchange provider.
func SecretName(provider string) string {
	if NormalizeProvider(provider) == "otx" {
		return "otx"
	}
	return "virustotal"
}

// DisplayName returns a human-readable provider label.
func DisplayName(provider string) string {
	switch NormalizeProvider(provider) {
	case "otx":
		return "AlienVault OTX"
	case "both":
		return "VirusTotal + AlienVault OTX"
	default:
		return "VirusTotal"
	}
}

// LookupResult holds a single hash reputation verdict.
type LookupResult struct {
	Malicious int
	Total     int
	Label     string
	Detail    string
	Found     bool
	Err       error
}

// Provider is implemented by every Threat Exchange client.
type Provider interface {
	ProviderName() string
	Lookup(ctx context.Context, sha256 string) (malicious, total int, label string, found bool, err error)
	LookupDetail(ctx context.Context, sha256 string) (malicious, total int, label, detail string, found bool, err error)
	LookupBatch(ctx context.Context, hashes []string) map[string]LookupResult
}

func validSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

func normalizeHash(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

var client = &http.Client{Timeout: 30 * time.Second}

// ---- Persistent disk cache ----

const (
	cacheMaxEntries   = 50000
	cacheCleanTTL     = 24 * time.Hour
	cacheMaliciousTTL = 7 * 24 * time.Hour
)

type cacheRecord struct {
	Mal       int       `json:"m"`
	Total     int       `json:"t"`
	Label     string    `json:"l,omitempty"`
	Detail    string    `json:"d,omitempty"`
	Found     bool      `json:"f"`
	ExpiresAt time.Time `json:"e"`
}

// DiskCache persists hash lookup results across scans and restarts so the same
// SHA-256 is never re-queried against rate-limited Threat Exchange APIs.
type DiskCache struct {
	path    string
	mu      sync.Mutex
	entries map[string]cacheRecord
}

// OpenCache loads a persistent reputation cache from disk (or creates an
// in-memory-only cache if path is empty).
func OpenCache(path string) *DiskCache {
	c := &DiskCache{path: path, entries: map[string]cacheRecord{}}
	if path == "" {
		return c
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return c
	}
	var disk map[string]cacheRecord
	if json.Unmarshal(b, &disk) == nil {
		now := time.Now()
		for k, v := range disk {
			if now.Before(v.ExpiresAt) {
				c.entries[k] = v
			}
		}
	}
	return c
}

func (c *DiskCache) Get(provider, sha256 string) (cacheRecord, bool) {
	if c == nil {
		return cacheRecord{}, false
	}
	key := provider + ":" + sha256
	c.mu.Lock()
	rec, ok := c.entries[key]
	if ok && time.Now().After(rec.ExpiresAt) {
		delete(c.entries, key)
		ok = false
	}
	c.mu.Unlock()
	return rec, ok
}

func (c *DiskCache) Put(provider, sha256 string, rec cacheRecord) {
	if c == nil {
		return
	}
	ttl := cacheCleanTTL
	if rec.Mal > 0 {
		ttl = cacheMaliciousTTL
	}
	rec.ExpiresAt = time.Now().Add(ttl)
	key := provider + ":" + sha256
	c.mu.Lock()
	if len(c.entries) >= cacheMaxEntries {
		now := time.Now()
		for k, v := range c.entries {
			if now.After(v.ExpiresAt) {
				delete(c.entries, k)
			}
		}
		if len(c.entries) >= cacheMaxEntries {
			// Evict oldest-expiring slice when full.
			removed := 0
			for k := range c.entries {
				delete(c.entries, k)
				removed++
				if removed >= cacheMaxEntries/10 {
					break
				}
			}
		}
	}
	c.entries[key] = rec
	var snapshot []byte
	if c.path != "" {
		snapshot, _ = json.Marshal(c.entries)
	}
	c.mu.Unlock()
	if c.path != "" && len(snapshot) > 0 {
		_ = config.WriteAtomic(c.path, snapshot, 0o644)
	}
}

// ---- Multi-provider composite ----

// Multi queries Threat Exchange providers in priority order, stopping on the
// first high-confidence malicious hit to preserve quota on stricter providers.
type Multi struct {
	Providers []Provider
}

func NewMulti(providers ...Provider) *Multi {
	var list []Provider
	for _, p := range providers {
		if p != nil {
			list = append(list, p)
		}
	}
	return &Multi{Providers: list}
}

func (m *Multi) ProviderName() string {
	var names []string
	for _, p := range m.Providers {
		names = append(names, p.ProviderName())
	}
	return strings.Join(names, " + ")
}

func (m *Multi) Lookup(ctx context.Context, sha256 string) (malicious, total int, label string, found bool, err error) {
	mal, tot, lbl, _, ok, e := m.LookupDetail(ctx, sha256)
	return mal, tot, lbl, ok, e
}

func (m *Multi) LookupDetail(ctx context.Context, sha256 string) (malicious, total int, label, detail string, found bool, err error) {
	var best LookupResult
	var firstErr error
	for _, p := range m.Providers {
		mal, tot, lbl, det, ok, e := p.LookupDetail(ctx, sha256)
		if e != nil {
			if firstErr == nil {
				firstErr = e
			}
			continue
		}
		if !ok {
			continue
		}
		// High-confidence threat hit: stop immediately so downstream providers
		// (like VirusTotal's strict 4 req/min quota) aren't spent unnecessarily.
		if mal >= 5 {
			return mal, tot, lbl, det, true, nil
		}
		if !best.Found || mal > best.Malicious || (mal == best.Malicious && tot > best.Total) {
			best = LookupResult{Malicious: mal, Total: tot, Label: lbl, Detail: det, Found: true}
		}
	}
	if best.Found {
		return best.Malicious, best.Total, best.Label, best.Detail, true, nil
	}
	return 0, 0, "", "", false, firstErr
}

func (m *Multi) LookupBatch(ctx context.Context, hashes []string) map[string]LookupResult {
	out := make(map[string]LookupResult, len(hashes))
	seen := map[string]bool{}
	for _, raw := range hashes {
		h := normalizeHash(raw)
		if !validSHA256(h) || seen[h] {
			continue
		}
		seen[h] = true
		mal, tot, lbl, det, ok, err := m.LookupDetail(ctx, h)
		out[h] = LookupResult{Malicious: mal, Total: tot, Label: lbl, Detail: det, Found: ok, Err: err}
	}
	return out
}

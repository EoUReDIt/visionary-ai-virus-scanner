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

	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/cache"
	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/config"
)

// ProviderInfo describes one Threat Exchange provider for the UI and CLI picker.
type ProviderInfo struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	SecretName       string `json:"secret_name"`
	KeyRequired      bool   `json:"key_required"`
	KeyBadge         string `json:"key_badge"`
	DocsURL          string `json:"docs_url"`
	DocsHint         string `json:"docs_hint"`
	SupportsBulkSync bool   `json:"supports_bulk_sync"`
}

// Providers lists the Threat Exchange options shown in the picker.
var Providers = []ProviderInfo{
	{
		ID:               "circl",
		Name:             "CIRCL hashlookup (Free · No Key)",
		SecretName:       "",
		KeyRequired:      false,
		KeyBadge:         "No key required",
		DocsURL:          "https://hashlookup.circl.lu/",
		DocsHint:         "Keyless NSRL/RDS known-good SHA-256 reference lookups via hashlookup.circl.lu to suppress false positives out of the box.",
		SupportsBulkSync: false,
	},
	{
		ID:               "virustotal",
		Name:             "VirusTotal",
		SecretName:       "virustotal",
		KeyRequired:      true,
		KeyBadge:         "Free API key required",
		DocsURL:          "https://www.virustotal.com/gui/my-apikey",
		DocsHint:         "Multi-engine SHA-256 hash lookups via VirusTotal API v3 (x-apikey). Cached locally to save daily quota.",
		SupportsBulkSync: false,
	},
	{
		ID:               "otx",
		Name:             "AlienVault OTX",
		SecretName:       "otx",
		KeyRequired:      true,
		KeyBadge:         "Free API key required",
		DocsURL:          "https://otx.alienvault.com/api",
		DocsHint:         "Open Threat Exchange DirectConnect API v1 (X-OTX-API-KEY). Supports compact per-hash pulse lookups and bulk SHA-256 feed sync.",
		SupportsBulkSync: true,
	},
	{
		ID:               "both",
		Name:             "VirusTotal + AlienVault OTX",
		SecretName:       "",
		KeyRequired:      true,
		KeyBadge:         "Free API keys required",
		DocsURL:          "https://otx.alienvault.com/api",
		DocsHint:         "Checks AlienVault OTX first (higher rate limit) and falls back to VirusTotal only when needed, stopping on the first confirmed threat.",
		SupportsBulkSync: true,
	},
}

// NormalizeProvider maps user input to canonical provider IDs.
func NormalizeProvider(p string) string {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "circl", "hashlookup", "nsrl", "free":
		return "circl"
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
	switch NormalizeProvider(provider) {
	case "otx":
		return "otx"
	case "circl":
		return ""
	default:
		return "virustotal"
	}
}

// DisplayName returns a human-readable provider label.
func DisplayName(provider string) string {
	switch NormalizeProvider(provider) {
	case "circl":
		return "CIRCL hashlookup (No Key)"
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
	path       string
	store      cache.Store
	writeMu    sync.Mutex // serialises snapshot+write so an older snapshot never lands after a newer one
	mu         sync.Mutex
	entries    map[string]cacheRecord
	dirty      bool
	batchDepth int
	debounce   time.Duration
	flushTimer *time.Timer
}

// OpenCacheWithStore wraps a unified cache.Store (SQLite WAL or atomic JSON).
func OpenCacheWithStore(st cache.Store) *DiskCache {
	return &DiskCache{store: st, entries: map[string]cacheRecord{}}
}

// SetDebounce configures a delay before non-batch Put calls flush to disk.
// A zero duration (default) flushes immediately outside BeginBatch/EndBatch.
func (c *DiskCache) SetDebounce(d time.Duration) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.debounce = d
	c.mu.Unlock()
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
	if c.store != nil {
		rec, ok := c.store.GetReputation(provider, sha256)
		if !ok {
			return cacheRecord{}, false
		}
		return cacheRecord{
			Mal:       rec.Malicious,
			Total:     rec.Total,
			Label:     rec.Label,
			Detail:    rec.Detail,
			Found:     rec.Found,
			ExpiresAt: rec.ExpiresAt,
		}, true
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
	if c.store != nil {
		_ = c.store.PutReputation(cache.RepRecord{
			Provider:  provider,
			SHA256:    sha256,
			Malicious: rec.Mal,
			Total:     rec.Total,
			Label:     rec.Label,
			Detail:    rec.Detail,
			Found:     rec.Found,
			ExpiresAt: rec.ExpiresAt,
		})
		return
	}
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
	c.dirty = true
	if c.batchDepth > 0 || c.path == "" {
		c.mu.Unlock()
		return
	}
	if c.debounce > 0 {
		if c.flushTimer == nil {
			c.flushTimer = time.AfterFunc(c.debounce, c.Flush)
		}
		c.mu.Unlock()
		return
	}
	c.mu.Unlock()
	c.writeSnapshot()
}

// writeSnapshot serialises the current entries to disk. Writers are
// serialised and the snapshot is taken inside the write lock, so concurrent
// flushes cannot persist stale data over newer data.
func (c *DiskCache) writeSnapshot() {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.mu.Lock()
	if !c.dirty || c.path == "" {
		c.mu.Unlock()
		return
	}
	snapshot, _ := json.Marshal(c.entries)
	c.dirty = false
	c.mu.Unlock()
	if len(snapshot) > 0 {
		_ = config.WriteAtomic(c.path, snapshot, 0o644)
	}
}

// BeginBatch defers disk writes until the matching EndBatch call so batch hash
// scans persist all new records in one atomic write instead of rewriting the
// entire JSON file after every single lookup.
func (c *DiskCache) BeginBatch() {
	if c == nil || c.store != nil {
		return
	}
	c.mu.Lock()
	c.batchDepth++
	c.mu.Unlock()
}

// EndBatch completes a batch started with BeginBatch and flushes any dirty
// entries to disk once the outermost batch finishes.
func (c *DiskCache) EndBatch() {
	if c == nil {
		return
	}
	if c.store != nil {
		_ = c.store.Flush()
		return
	}
	c.mu.Lock()
	if c.batchDepth > 0 {
		c.batchDepth--
	}
	shouldFlush := c.batchDepth == 0 && c.dirty && c.path != ""
	if shouldFlush && c.flushTimer != nil {
		c.flushTimer.Stop()
		c.flushTimer = nil
	}
	c.mu.Unlock()
	if shouldFlush {
		c.writeSnapshot()
	}
}

// Flush writes any pending in-memory cache updates to disk immediately.
func (c *DiskCache) Flush() {
	if c == nil {
		return
	}
	if c.store != nil {
		_ = c.store.Flush()
		return
	}
	c.mu.Lock()
	if c.flushTimer != nil {
		c.flushTimer.Stop()
		c.flushTimer = nil
	}
	c.mu.Unlock()
	c.writeSnapshot()
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
		if err := ctx.Err(); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			break
		}
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

// LookupBatch runs providers in priority order using each provider's own
// LookupBatch (so VirusTotal's 4 req/min pacing and 429 handling are always
// honored in "both" mode), forwarding only hashes not already convicted by an
// earlier provider.
func (m *Multi) LookupBatch(ctx context.Context, hashes []string) map[string]LookupResult {
	out := make(map[string]LookupResult, len(hashes))
	pending := make([]string, 0, len(hashes))
	seen := map[string]bool{}
	for _, raw := range hashes {
		h := normalizeHash(raw)
		if !validSHA256(h) || seen[h] {
			continue
		}
		seen[h] = true
		pending = append(pending, h)
	}
	if len(pending) == 0 || len(m.Providers) == 0 {
		return out
	}

	firstErr := map[string]error{}
	for _, p := range m.Providers {
		if len(pending) == 0 || ctx.Err() != nil {
			break
		}
		res := p.LookupBatch(ctx, pending)
		nextPending := make([]string, 0, len(pending))
		for _, h := range pending {
			r, ok := res[h]
			if !ok {
				nextPending = append(nextPending, h)
				continue
			}
			if r.Err != nil {
				if _, has := firstErr[h]; !has {
					firstErr[h] = r.Err
				}
				nextPending = append(nextPending, h)
				continue
			}
			if r.Found {
				prev, hasPrev := out[h]
				if r.Malicious >= 5 {
					out[h] = r
					continue // High-confidence conviction: skip downstream providers.
				}
				if !hasPrev || !prev.Found || r.Malicious > prev.Malicious || (r.Malicious == prev.Malicious && r.Total > prev.Total) {
					out[h] = r
				}
			}
			nextPending = append(nextPending, h)
		}
		pending = nextPending
	}

	for _, h := range pending {
		if _, ok := out[h]; !ok {
			out[h] = LookupResult{Err: firstErr[h]}
		}
	}
	return out
}

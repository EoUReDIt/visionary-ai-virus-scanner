// Package cache provides a unified persistent cache store for Threat Exchange
// hash lookups, Shodan InternetDB public IP exposure lookups, and Risk Exchange
// vulnerability advisories.
//
// When built with `-tags sqlite` (after `go get modernc.org/sqlite`), Open
// automatically uses an embedded WAL-mode SQLite database (`visionary_cache.db`)
// via Go's standard database/sql package. In zero-extra-dependency builds, Open
// falls back seamlessly to a transactional atomic JSON store (`visionary_cache.json`)
// with identical semantics and automatic one-time migration from legacy files.
package cache

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/config"
)

// RepRecord is one cached Threat Exchange hash verdict.
type RepRecord struct {
	Provider  string    `json:"p"`
	SHA256    string    `json:"h"`
	Malicious int       `json:"m"`
	Total     int       `json:"t"`
	Label     string    `json:"l,omitempty"`
	Detail    string    `json:"d,omitempty"`
	Found     bool      `json:"f"`
	ExpiresAt time.Time `json:"e"`
}

// IPRecord is one cached Shodan InternetDB public IPv4 exposure lookup.
type IPRecord struct {
	IP        string    `json:"ip"`
	Source    string    `json:"source"`
	Ports     []int     `json:"ports,omitempty"`
	CPEs      []string  `json:"cpes,omitempty"`
	Tags      []string  `json:"tags,omitempty"`
	Vulns     []string  `json:"vulns,omitempty"`
	Hostnames []string  `json:"hostnames,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
}

// RiskRecord mirrors one normalized vulnerability advisory for storage.
type RiskRecord struct {
	ID        string   `json:"id"`
	Source    string   `json:"source"`
	Severity  string   `json:"severity"`
	CVSS      float64  `json:"cvss"`
	KEV       bool     `json:"kev"`
	KEVName   string   `json:"kev_name,omitempty"`
	Summary   string   `json:"summary"`
	Products  []string `json:"products,omitempty"`
	CWEs      []string `json:"cwes,omitempty"`
	ScanHints []string `json:"scan_hints,omitempty"`
	Published string   `json:"published,omitempty"`
	Modified  string   `json:"modified,omitempty"`
	URL       string   `json:"url,omitempty"`
}

// RiskSnapshot is a persisted Risk Exchange sync snapshot.
type RiskSnapshot struct {
	SyncedAt   string       `json:"synced_at,omitempty"`
	Provider   string       `json:"provider,omitempty"`
	TotalMatch int          `json:"total_match,omitempty"`
	Advisories []RiskRecord `json:"advisories,omitempty"`
}

// Store is the unified cache interface backed by either embedded SQLite (WAL)
// or the zero-dependency atomic JSON fallback.
type Store interface {
	Backend() string
	Path() string
	GetReputation(provider, sha256 string) (RepRecord, bool)
	PutReputation(rec RepRecord) error
	GetIPReputation(ip string) (IPRecord, bool)
	PutIPReputation(rec IPRecord) error
	LoadRisk() RiskSnapshot
	SaveRisk(snap RiskSnapshot) error
	PruneExpired(now time.Time) error
	Flush() error
	Close() error
}

// sqliteDriverName returns the registered database/sql driver name if an
// embedded SQLite driver (such as modernc.org/sqlite via -tags sqlite) is linked.
func sqliteDriverName() string {
	for _, d := range sql.Drivers() {
		if d == "sqlite" || d == "sqlite3" {
			return d
		}
	}
	return ""
}

// Open opens the best available persistent cache inside dir (SQLite WAL when a
// SQLite driver is linked, otherwise the zero-dependency JSONStore) and runs
// automatic one-time migration from legacy reputation_cache.json / risk_exchange.json.
func Open(dir string) Store {
	if dir == "" {
		dir = config.Dir()
	}
	_ = os.MkdirAll(dir, 0o755)
	if drv := sqliteDriverName(); drv != "" {
		dbPath := filepath.Join(dir, "visionary_cache.db")
		if st, err := OpenSQLite(drv, dbPath); err == nil {
			_ = MigrateLegacyJSON(dir, st)
			return st
		}
	}
	st := OpenJSON(filepath.Join(dir, "visionary_cache.json"))
	_ = MigrateLegacyJSON(dir, st)
	return st
}

// ---- Zero-dependency atomic JSONStore fallback ----

type jsonDisk struct {
	Version    int                  `json:"version"`
	Reputation map[string]RepRecord `json:"reputation,omitempty"`
	IPs        map[string]IPRecord  `json:"ips,omitempty"`
	Risk       RiskSnapshot         `json:"risk,omitempty"`
}

// JSONStore implements Store using a single atomic JSON file for builds without
// an embedded SQLite driver linked.
type JSONStore struct {
	path  string
	mu    sync.Mutex
	data  jsonDisk
	dirty bool
}

// OpenJSON opens (or initializes) a JSONStore at path.
func OpenJSON(path string) *JSONStore {
	s := &JSONStore{
		path: path,
		data: jsonDisk{
			Version:    1,
			Reputation: map[string]RepRecord{},
			IPs:        map[string]IPRecord{},
		},
	}
	if path == "" {
		return s
	}
	if b, err := os.ReadFile(path); err == nil {
		var disk jsonDisk
		if json.Unmarshal(b, &disk) == nil {
			if disk.Reputation == nil {
				disk.Reputation = map[string]RepRecord{}
			}
			if disk.IPs == nil {
				disk.IPs = map[string]IPRecord{}
			}
			now := time.Now()
			for k, v := range disk.Reputation {
				if now.After(v.ExpiresAt) {
					delete(disk.Reputation, k)
				}
			}
			for k, v := range disk.IPs {
				if now.After(v.ExpiresAt) {
					delete(disk.IPs, k)
				}
			}
			s.data = disk
		}
	}
	return s
}

func (s *JSONStore) Backend() string { return "json" }
func (s *JSONStore) Path() string    { return s.path }

func (s *JSONStore) GetReputation(provider, sha256 string) (RepRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := provider + ":" + sha256
	rec, ok := s.data.Reputation[key]
	if ok && time.Now().After(rec.ExpiresAt) {
		delete(s.data.Reputation, key)
		return RepRecord{}, false
	}
	return rec, ok
}

func (s *JSONStore) PutReputation(rec RepRecord) error {
	s.mu.Lock()
	key := rec.Provider + ":" + rec.SHA256
	s.data.Reputation[key] = rec
	s.dirty = true
	s.mu.Unlock()
	return s.Flush()
}

func (s *JSONStore) GetIPReputation(ip string) (IPRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.data.IPs[ip]
	if ok && time.Now().After(rec.ExpiresAt) {
		delete(s.data.IPs, ip)
		return IPRecord{}, false
	}
	return rec, ok
}

func (s *JSONStore) PutIPReputation(rec IPRecord) error {
	s.mu.Lock()
	s.data.IPs[rec.IP] = rec
	s.dirty = true
	s.mu.Unlock()
	return s.Flush()
}

func (s *JSONStore) LoadRisk() RiskSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data.Risk
}

func (s *JSONStore) SaveRisk(snap RiskSnapshot) error {
	s.mu.Lock()
	s.data.Risk = snap
	s.dirty = true
	s.mu.Unlock()
	return s.Flush()
}

func (s *JSONStore) PruneExpired(now time.Time) error {
	s.mu.Lock()
	changed := false
	for k, v := range s.data.Reputation {
		if now.After(v.ExpiresAt) {
			delete(s.data.Reputation, k)
			changed = true
		}
	}
	for k, v := range s.data.IPs {
		if now.After(v.ExpiresAt) {
			delete(s.data.IPs, k)
			changed = true
		}
	}
	if changed {
		s.dirty = true
	}
	s.mu.Unlock()
	if changed {
		return s.Flush()
	}
	return nil
}

func (s *JSONStore) Flush() error {
	s.mu.Lock()
	if !s.dirty || s.path == "" {
		s.mu.Unlock()
		return nil
	}
	b, err := json.Marshal(s.data)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	s.dirty = false
	s.mu.Unlock()
	return config.WriteAtomic(s.path, b, 0o644)
}

func (s *JSONStore) Close() error { return s.Flush() }

// MigrateLegacyJSON imports non-expired entries from legacy reputation_cache.json
// and risk_exchange.json into st once, renaming migrated files to *.migrated.bak.
func MigrateLegacyJSON(dir string, st Store) error {
	if dir == "" || st == nil {
		return nil
	}
	now := time.Now()

	// 1. Legacy reputation_cache.json
	repFile := filepath.Join(dir, "reputation_cache.json")
	if b, err := os.ReadFile(repFile); err == nil {
		var legacy map[string]struct {
			Mal       int       `json:"m"`
			Total     int       `json:"t"`
			Label     string    `json:"l"`
			Detail    string    `json:"d"`
			Found     bool      `json:"f"`
			ExpiresAt time.Time `json:"e"`
		}
		if json.Unmarshal(b, &legacy) == nil {
			for k, v := range legacy {
				if now.After(v.ExpiresAt) {
					continue
				}
				prov, hash := splitProviderHash(k)
				if prov == "" || hash == "" {
					continue
				}
				if _, exists := st.GetReputation(prov, hash); !exists {
					_ = st.PutReputation(RepRecord{
						Provider:  prov,
						SHA256:    hash,
						Malicious: v.Mal,
						Total:     v.Total,
						Label:     v.Label,
						Detail:    v.Detail,
						Found:     v.Found,
						ExpiresAt: v.ExpiresAt,
					})
				}
			}
			_ = os.Rename(repFile, repFile+".migrated.bak")
		}
	}

	// 2. Legacy risk_exchange.json
	riskFile := filepath.Join(dir, "risk_exchange.json")
	if b, err := os.ReadFile(riskFile); err == nil {
		var legacy RiskSnapshot
		if json.Unmarshal(b, &legacy) == nil && len(legacy.Advisories) > 0 {
			if cur := st.LoadRisk(); len(cur.Advisories) == 0 {
				_ = st.SaveRisk(legacy)
			}
			_ = os.Rename(riskFile, riskFile+".migrated.bak")
		}
	}
	return st.Flush()
}

func splitProviderHash(key string) (string, string) {
	for i := 0; i < len(key); i++ {
		if key[i] == ':' {
			return key[:i], key[i+1:]
		}
	}
	return "", ""
}

package cache

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// PragmasSQL configures SQLite for safe concurrent Guard + Web UI + CLI access
// with a bounded 4 MiB page cache suitable for Lite edition.
var PragmasSQL = []string{
	`PRAGMA journal_mode = WAL`,
	`PRAGMA synchronous = NORMAL`,
	`PRAGMA busy_timeout = 5000`,
	`PRAGMA temp_store = MEMORY`,
	`PRAGMA cache_size = -4000`,
}

// SchemaSQL defines the embedded SQLite cache schema from PR #01.
var SchemaSQL = []string{
	`CREATE TABLE IF NOT EXISTS meta (
		key   TEXT PRIMARY KEY,
		value TEXT NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS reputation_cache (
		provider   TEXT    NOT NULL,
		sha256     TEXT    NOT NULL,
		malicious  INTEGER NOT NULL DEFAULT 0,
		total      INTEGER NOT NULL DEFAULT 0,
		label      TEXT    NOT NULL DEFAULT '',
		detail     TEXT    NOT NULL DEFAULT '',
		found      INTEGER NOT NULL DEFAULT 0,
		expires_at INTEGER NOT NULL,
		PRIMARY KEY (provider, sha256)
	)`,
	`CREATE INDEX IF NOT EXISTS idx_rep_expires ON reputation_cache(expires_at)`,
	`CREATE TABLE IF NOT EXISTS ip_reputation_cache (
		ip         TEXT    PRIMARY KEY,
		source     TEXT    NOT NULL,
		ports_json TEXT    NOT NULL DEFAULT '[]',
		cpes_json  TEXT    NOT NULL DEFAULT '[]',
		tags_json  TEXT    NOT NULL DEFAULT '[]',
		vulns_json TEXT    NOT NULL DEFAULT '[]',
		hostnames  TEXT    NOT NULL DEFAULT '[]',
		expires_at INTEGER NOT NULL
	)`,
	`CREATE INDEX IF NOT EXISTS idx_ip_expires ON ip_reputation_cache(expires_at)`,
	`CREATE TABLE IF NOT EXISTS risk_advisories (
		id         TEXT    PRIMARY KEY,
		source     TEXT    NOT NULL,
		severity   TEXT    NOT NULL,
		cvss       REAL    NOT NULL DEFAULT 0,
		kev        INTEGER NOT NULL DEFAULT 0,
		kev_name   TEXT    NOT NULL DEFAULT '',
		summary    TEXT    NOT NULL DEFAULT '',
		products   TEXT    NOT NULL DEFAULT '[]',
		cwes       TEXT    NOT NULL DEFAULT '[]',
		scan_hints TEXT    NOT NULL DEFAULT '[]',
		published  TEXT    NOT NULL DEFAULT '',
		modified   TEXT    NOT NULL DEFAULT '',
		url        TEXT    NOT NULL DEFAULT ''
	)`,
	`CREATE INDEX IF NOT EXISTS idx_risk_kev_sev ON risk_advisories(kev DESC, cvss DESC)`,
	`CREATE TABLE IF NOT EXISTS scan_clean_cache (
		path_key   TEXT    PRIMARY KEY,
		size       INTEGER NOT NULL,
		mod_ns     INTEGER NOT NULL,
		def_rev    INTEGER NOT NULL,
		updated_at INTEGER NOT NULL
	)`,
	`CREATE INDEX IF NOT EXISTS idx_scan_rev ON scan_clean_cache(def_rev)`,
}

// SQLStore implements Store over any registered SQLite database/sql driver
// (such as pure-Go modernc.org/sqlite when compiled with -tags sqlite).
type SQLStore struct {
	db   *sql.DB
	path string
}

// OpenSQLite opens a SQLite database at path using driverName, applies WAL and
// Lite-friendly pragmas, and creates all tables and indexes idempotently.
func OpenSQLite(driverName, path string) (*SQLStore, error) {
	db, err := sql.Open(driverName, path)
	if err != nil {
		return nil, err
	}
	// Single writer pool avoids SQLITE_BUSY under parallel Go goroutines while
	// WAL mode allows concurrent readers from separate CLI/UI/Guard processes.
	db.SetMaxOpenConns(1)
	for _, p := range PragmasSQL {
		if _, err := db.Exec(p); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("sqlite pragma %q: %w", p, err)
		}
	}
	for _, stmt := range SchemaSQL {
		if _, err := db.Exec(stmt); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("sqlite schema: %w", err)
		}
	}
	return &SQLStore{db: db, path: path}, nil
}

func (s *SQLStore) Backend() string { return "sqlite" }
func (s *SQLStore) Path() string    { return s.path }

func (s *SQLStore) GetReputation(provider, sha256 string) (RepRecord, bool) {
	var rec RepRecord
	var foundInt int
	var expUnix int64
	err := s.db.QueryRow(
		`SELECT provider, sha256, malicious, total, label, detail, found, expires_at
		 FROM reputation_cache WHERE provider = ? AND sha256 = ?`,
		provider, sha256,
	).Scan(&rec.Provider, &rec.SHA256, &rec.Malicious, &rec.Total, &rec.Label, &rec.Detail, &foundInt, &expUnix)
	if err != nil {
		return RepRecord{}, false
	}
	rec.Found = foundInt != 0
	rec.ExpiresAt = time.Unix(expUnix, 0)
	if time.Now().After(rec.ExpiresAt) {
		_, _ = s.db.Exec(`DELETE FROM reputation_cache WHERE provider = ? AND sha256 = ?`, provider, sha256)
		return RepRecord{}, false
	}
	return rec, true
}

func (s *SQLStore) PutReputation(rec RepRecord) error {
	foundInt := 0
	if rec.Found {
		foundInt = 1
	}
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO reputation_cache
		 (provider, sha256, malicious, total, label, detail, found, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.Provider, rec.SHA256, rec.Malicious, rec.Total, rec.Label, rec.Detail, foundInt, rec.ExpiresAt.Unix(),
	)
	return err
}

func (s *SQLStore) GetIPReputation(ip string) (IPRecord, bool) {
	var rec IPRecord
	var portsJ, cpesJ, tagsJ, vulnsJ, hostsJ string
	var expUnix int64
	err := s.db.QueryRow(
		`SELECT ip, source, ports_json, cpes_json, tags_json, vulns_json, hostnames, expires_at
		 FROM ip_reputation_cache WHERE ip = ?`,
		ip,
	).Scan(&rec.IP, &rec.Source, &portsJ, &cpesJ, &tagsJ, &vulnsJ, &hostsJ, &expUnix)
	if err != nil {
		return IPRecord{}, false
	}
	rec.ExpiresAt = time.Unix(expUnix, 0)
	if time.Now().After(rec.ExpiresAt) {
		_, _ = s.db.Exec(`DELETE FROM ip_reputation_cache WHERE ip = ?`, ip)
		return IPRecord{}, false
	}
	_ = json.Unmarshal([]byte(portsJ), &rec.Ports)
	_ = json.Unmarshal([]byte(cpesJ), &rec.CPEs)
	_ = json.Unmarshal([]byte(tagsJ), &rec.Tags)
	_ = json.Unmarshal([]byte(vulnsJ), &rec.Vulns)
	_ = json.Unmarshal([]byte(hostsJ), &rec.Hostnames)
	return rec, true
}

func (s *SQLStore) PutIPReputation(rec IPRecord) error {
	portsJ := marshalOrEmpty(rec.Ports)
	cpesJ := marshalOrEmpty(rec.CPEs)
	tagsJ := marshalOrEmpty(rec.Tags)
	vulnsJ := marshalOrEmpty(rec.Vulns)
	hostsJ := marshalOrEmpty(rec.Hostnames)
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO ip_reputation_cache
		 (ip, source, ports_json, cpes_json, tags_json, vulns_json, hostnames, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.IP, rec.Source, portsJ, cpesJ, tagsJ, vulnsJ, hostsJ, rec.ExpiresAt.Unix(),
	)
	return err
}

func (s *SQLStore) LoadRisk() RiskSnapshot {
	var snap RiskSnapshot
	_ = s.db.QueryRow(`SELECT value FROM meta WHERE key = 'risk.synced_at'`).Scan(&snap.SyncedAt)
	_ = s.db.QueryRow(`SELECT value FROM meta WHERE key = 'risk.provider'`).Scan(&snap.Provider)
	var totalStr string
	if s.db.QueryRow(`SELECT value FROM meta WHERE key = 'risk.total_match'`).Scan(&totalStr) == nil {
		_, _ = fmt.Sscanf(totalStr, "%d", &snap.TotalMatch)
	}
	rows, err := s.db.Query(
		`SELECT id, source, severity, cvss, kev, kev_name, summary, products, cwes, scan_hints, published, modified, url
		 FROM risk_advisories ORDER BY kev DESC, cvss DESC`,
	)
	if err != nil {
		return snap
	}
	defer rows.Close()
	for rows.Next() {
		var r RiskRecord
		var kevInt int
		var prodsJ, cwesJ, hintsJ string
		if rows.Scan(&r.ID, &r.Source, &r.Severity, &r.CVSS, &kevInt, &r.KEVName, &r.Summary,
			&prodsJ, &cwesJ, &hintsJ, &r.Published, &r.Modified, &r.URL) == nil {
			r.KEV = kevInt != 0
			_ = json.Unmarshal([]byte(prodsJ), &r.Products)
			_ = json.Unmarshal([]byte(cwesJ), &r.CWEs)
			_ = json.Unmarshal([]byte(hintsJ), &r.ScanHints)
			snap.Advisories = append(snap.Advisories, r)
		}
	}
	return snap
}

func (s *SQLStore) SaveRisk(snap RiskSnapshot) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`DELETE FROM risk_advisories`); err != nil {
		return err
	}
	stmt, err := tx.Prepare(
		`INSERT OR REPLACE INTO risk_advisories
		 (id, source, severity, cvss, kev, kev_name, summary, products, cwes, scan_hints, published, modified, url)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
	)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, r := range snap.Advisories {
		kevInt := 0
		if r.KEV {
			kevInt = 1
		}
		if _, err := stmt.Exec(
			r.ID, r.Source, r.Severity, r.CVSS, kevInt, r.KEVName, r.Summary,
			marshalOrEmpty(r.Products), marshalOrEmpty(r.CWEs), marshalOrEmpty(r.ScanHints),
			r.Published, r.Modified, r.URL,
		); err != nil {
			return err
		}
	}
	for k, v := range map[string]string{
		"risk.synced_at":   snap.SyncedAt,
		"risk.provider":    snap.Provider,
		"risk.total_match": fmt.Sprintf("%d", snap.TotalMatch),
	} {
		if _, err := tx.Exec(`INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)`, k, v); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLStore) PruneExpired(now time.Time) error {
	cutoff := now.Unix()
	if _, err := s.db.Exec(`DELETE FROM reputation_cache WHERE expires_at < ?`, cutoff); err != nil {
		return err
	}
	_, err := s.db.Exec(`DELETE FROM ip_reputation_cache WHERE expires_at < ?`, cutoff)
	return err
}

func (s *SQLStore) Flush() error { return nil }
func (s *SQLStore) Close() error { return s.db.Close() }

func marshalOrEmpty(v any) string {
	b, err := json.Marshal(v)
	if err != nil || string(b) == "null" {
		return "[]"
	}
	return string(b)
}

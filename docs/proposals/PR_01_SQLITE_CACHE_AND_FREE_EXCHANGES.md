# PR Proposal #01: Embedded SQLite Cache & Keyless Default Threat/Risk Exchanges

- **Proposed Branch:** `feat/sqlite-cache-and-keyless-exchanges`
- **Target Branch:** `main`
- **Status:** Proposal (Baseline currently runs on atomic JSON caches: `reputation_cache.json` and `risk_exchange.json`)
- **Editions Affected:** Core, Lite, Safe

---

## 1. Summary

Today Visionary persists Threat Exchange lookups (`reputation_cache.json`), Risk Exchange advisories (`risk_exchange.json`), and clean-file scan caches (`cache.gob`) as whole-file snapshots. While JSON is ideal to validate the feature set right now, scaling to larger hash/CVE/IP caches or running the Windows `VisionaryAV` guard service concurrently with `VisionaryUI.exe` introduces whole-file rewrite overhead and occasional Windows rename contention.

This PR proposes:
1. Migrating persistent caches from whole-file JSON/gob snapshots to a **single embedded pure-Go SQLite database** (`visionary_cache.db`, WAL mode, `CGO_ENABLED=0`) — **never** requiring PostgreSQL or any external database server.
2. Adding **zero-API-key default providers** across both **Risk Exchange** and **Threat Exchange**, while keeping VirusTotal and AlienVault OTX as seamless free-key upgrades.

---

## 2. Why Embedded SQLite (and Why Not PostgreSQL)

| Criteria | Current JSON Files | Embedded SQLite (`modernc.org/sqlite`) | PostgreSQL |
|----------|--------------------|----------------------------------------|------------|
| Deployment | Zero dependency | Zero dependency (single local `.db` file, `CGO_ENABLED=0`) | Requires installing & managing a server daemon |
| Concurrent Guard + Web UI + CLI | Whole-file rewrite + Windows `os.Rename` retry | Native multi-reader / single-writer via **WAL mode** + `busy_timeout=5000` | Overkill for single-PC desktop AV |
| Write cost per hash lookup | Re-marshals up to 50,000 entries on every `Put()` | O(log N) single-row indexed `INSERT OR REPLACE` | Network roundtrip |
| TTL expiration & pruning | Full-map scan in RAM | Indexed `DELETE FROM ... WHERE expires_at < ?` | Indexed SQL |
| Suitable for Lite/Safe? | Yes (small scale) | **Yes** (single binary, low memory) | **No** (breaks lightweight/portable goal) |

> **Rule of thumb:** Keep JSON while validating features and small caches (<5k entries). Adopt embedded SQLite when scaling caches or eliminating concurrent file-rename locks on Windows. Reserve PostgreSQL exclusively for a future multi-endpoint central management server.

---

## 3. Proposed SQLite Schema (`%ProgramData%\VisionaryAV\visionary_cache.db`)

Pragmas on open:
```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA busy_timeout = 5000;
PRAGMA temp_store = MEMORY;
PRAGMA cache_size = -4000; -- cap SQLite page cache at ~4 MB (Lite-friendly)
```

Tables:
```sql
CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS reputation_cache (
  provider   TEXT    NOT NULL, -- 'virustotal' | 'otx' | 'circl'
  sha256     TEXT    NOT NULL,
  malicious  INTEGER NOT NULL DEFAULT 0,
  total      INTEGER NOT NULL DEFAULT 0,
  label      TEXT    NOT NULL DEFAULT '',
  detail     TEXT    NOT NULL DEFAULT '',
  found      INTEGER NOT NULL DEFAULT 0,
  expires_at INTEGER NOT NULL, -- Unix seconds
  PRIMARY KEY (provider, sha256)
);
CREATE INDEX IF NOT EXISTS idx_rep_expires ON reputation_cache(expires_at);

CREATE TABLE IF NOT EXISTS ip_reputation_cache (
  ip         TEXT    PRIMARY KEY, -- public IPv4 only (RFC 1918 rejected)
  source     TEXT    NOT NULL,    -- 'internetdb'
  ports_json TEXT    NOT NULL DEFAULT '[]',
  cpes_json  TEXT    NOT NULL DEFAULT '[]',
  tags_json  TEXT    NOT NULL DEFAULT '[]',
  vulns_json TEXT    NOT NULL DEFAULT '[]',
  hostnames  TEXT    NOT NULL DEFAULT '[]',
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ip_expires ON ip_reputation_cache(expires_at);

CREATE TABLE IF NOT EXISTS risk_advisories (
  id         TEXT    PRIMARY KEY, -- e.g. 'CVE-2025-0411'
  source     TEXT    NOT NULL,    -- 'nvd' | 'cisa-kev' | 'custom'
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
);
CREATE INDEX IF NOT EXISTS idx_risk_kev_sev ON risk_advisories(kev DESC, cvss DESC);

CREATE TABLE IF NOT EXISTS scan_clean_cache (
  path_key   TEXT    PRIMARY KEY,
  size       INTEGER NOT NULL,
  mod_ns     INTEGER NOT NULL,
  def_rev    INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scan_rev ON scan_clean_cache(def_rev);
```

### Automatic One-Time Migration (Zero User Friction)
- On startup, if `visionary_cache.db` is newly created and legacy `reputation_cache.json` / `risk_exchange.json` exist, import non-expired records inside one transaction and rename legacy files to `*.migrated.bak`.
- Keep a clean `CacheStore` interface in `internal/cache/` so unit tests can use `:memory:` SQLite or JSON seamlessly.

---

## 4. Keyless Default Providers for Risk Exchange & Threat Exchange

### Risk Exchange (Works Out of the Box — No API Key)
1. **NIST NVD CVE 2.0** *(already default)*: 250,000+ CVEs, free without key (5 req/30s), optional free NIST key lifts to 50 req/30s.
2. **CISA KEV Static JSON Feed** *(new keyless companion)*: Direct download of CISA's Known Exploited Vulnerabilities JSON catalog — zero API key, zero rate limit, cached locally for 12 hours.
3. **Shodan InternetDB (Home-Perimeter Opt-In)** *(new keyless provider)*:
   - Endpoint: `GET https://internetdb.shodan.io/{ip}` (free for non-commercial use, no API key, weekly refresh).
   - **Strict Home-Network Scope Guard:** Reject all private/RFC 1918/loopback/link-local IPs (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`) before making any network request.
   - **Two narrow, user-controlled purposes:**
     1. *Risk Exchange — Own Router WAN Check (opt-in):* Inspects only the user's own public IP for accidentally exposed ports (RDP 3389, SMB 445, UPnP, admin panels) and router CVEs to adjust local scan posture.
     2. *Threat Exchange — Outbound Public IP Context:* Enriches suspicious remote public IPs contacted by flagged local processes (`tags`, `ports`, `vulns`).

### Threat Exchange (Works Out of the Box — Optional Free Keys)
- **Keyless defaults:**
  - **CIRCL hashlookup** (`https://hashlookup.circl.lu/lookup/sha256/{hash}`, free, no key) to confirm known-good OS/NSRL files and suppress heuristic false positives.
  - **Shodan InternetDB** (free, no key) for outbound public IP context.
  - Built-in offline definitions channels.
- **Optional free-key upgrades (already implemented):**
  - **VirusTotal v3** (SHA-256 only, 4 req/min paced batch scanner).
  - **AlienVault OTX v1** (per-hash pulses + compact bulk SHA-256 export).

---

## 5. Rollout & Verification Plan

- [ ] Benchmark binary size delta of `modernc.org/sqlite` across Core, Lite, and Safe (confirm Lite idle RSS stays well below the 40 MB Linux / 100 MB Windows budget in CI).
- [ ] Implement `internal/cache/` store with WAL mode, `busy_timeout`, automatic JSON migration, and unit tests for concurrent reader/writer access.
- [ ] Add `internal/risk/internetdb.go` with strict RFC 1918 blocklist tests (`192.168.1.1`, `10.0.0.1`, `127.0.0.1` must never leave the host).
- [ ] Add `internal/reputation/circl.go` keyless known-good hash lookup.
- [ ] Update Web UI and CLI pickers to clearly badge **No key required** vs **Free API key optional/required**.

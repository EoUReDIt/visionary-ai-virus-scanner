package cache

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestJSONStoreReputationIPRiskAndMigration(t *testing.T) {
	dir := t.TempDir()

	// Seed legacy JSON files to verify automatic one-time migration.
	legacyRep := map[string]any{
		"circl:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": map[string]any{
			"m": 0, "t": 100, "l": "kernel32.dll", "d": "Known-good NSRL", "f": true,
			"e": time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339),
		},
		"virustotal:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": map[string]any{
			"m": 10, "t": 70, "l": "Old", "f": true,
			"e": time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339), // expired
		},
	}
	b, _ := json.Marshal(legacyRep)
	if err := os.WriteFile(filepath.Join(dir, "reputation_cache.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	legacyRisk := RiskSnapshot{
		SyncedAt:   "2026-11-27T12:00:00Z",
		Provider:   "nvd",
		TotalMatch: 1,
		Advisories: []RiskRecord{{ID: "CVE-2025-0411", Source: "nvd", Severity: "CRITICAL", CVSS: 9.1, KEV: true}},
	}
	rb, _ := json.Marshal(legacyRisk)
	if err := os.WriteFile(filepath.Join(dir, "risk_exchange.json"), rb, 0o644); err != nil {
		t.Fatal(err)
	}

	st := Open(dir)
	defer st.Close()

	// Legacy files must have been backed up after migration.
	if _, err := os.Stat(filepath.Join(dir, "reputation_cache.json.migrated.bak")); err != nil {
		t.Fatalf("expected legacy reputation backup: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "risk_exchange.json.migrated.bak")); err != nil {
		t.Fatalf("expected legacy risk backup: %v", err)
	}

	// Non-expired entry migrated; expired entry skipped.
	if rec, ok := st.GetReputation("circl", strings.Repeat("a", 64)); !ok || rec.Label != "kernel32.dll" {
		t.Fatalf("migrated reputation entry missing: ok=%v rec=%+v", ok, rec)
	}
	if _, ok := st.GetReputation("virustotal", strings.Repeat("b", 64)); ok {
		t.Fatal("expired legacy reputation entry should not migrate")
	}

	// Risk snapshot migrated.
	if rs := st.LoadRisk(); len(rs.Advisories) != 1 || rs.Advisories[0].ID != "CVE-2025-0411" {
		t.Fatalf("migrated risk snapshot mismatch: %+v", rs)
	}

	// IP reputation roundtrip + concurrent safety.
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = st.PutIPReputation(IPRecord{
				IP:        "1.1.1.1",
				Source:    "internetdb",
				Ports:     []int{53, 443},
				Tags:      []string{"cdn"},
				ExpiresAt: time.Now().Add(time.Hour),
			})
			_, _ = st.GetIPReputation("1.1.1.1")
		}()
	}
	wg.Wait()

	ipRec, ok := st.GetIPReputation("1.1.1.1")
	if !ok || len(ipRec.Ports) != 2 || ipRec.Source != "internetdb" {
		t.Fatalf("IP reputation roundtrip failed: ok=%v rec=%+v", ok, ipRec)
	}
}

// stubDriver validates that OpenSQLite runs every WAL pragma and schema DDL
// statement cleanly against Go's database/sql interface even in builds without
// an external SQLite driver linked.
type stubDriver struct {
	mu      sync.Mutex
	queries []string
}

func (d *stubDriver) Open(string) (driver.Conn, error) { return &stubConn{d: d}, nil }

type stubConn struct{ d *stubDriver }

func (c *stubConn) Prepare(query string) (driver.Stmt, error) {
	return &stubStmt{d: c.d, q: query}, nil
}
func (c *stubConn) Close() error              { return nil }
func (c *stubConn) Begin() (driver.Tx, error) { return &stubTx{}, nil }
func (c *stubConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	c.d.mu.Lock()
	c.d.queries = append(c.d.queries, query)
	c.d.mu.Unlock()
	return driver.RowsAffected(1), nil
}

type stubTx struct{}

func (t *stubTx) Commit() error   { return nil }
func (t *stubTx) Rollback() error { return nil }

type stubStmt struct {
	d *stubDriver
	q string
}

func (s *stubStmt) Close() error  { return nil }
func (s *stubStmt) NumInput() int { return -1 }
func (s *stubStmt) Exec(_ []driver.Value) (driver.Result, error) {
	s.d.mu.Lock()
	s.d.queries = append(s.d.queries, s.q)
	s.d.mu.Unlock()
	return driver.RowsAffected(1), nil
}
func (s *stubStmt) Query(_ []driver.Value) (driver.Rows, error) { return &emptyRows{}, nil }

type emptyRows struct{}

func (r *emptyRows) Columns() []string           { return []string{"v"} }
func (r *emptyRows) Close() error                { return nil }
func (r *emptyRows) Next(_ []driver.Value) error { return io.EOF }

func TestSQLStorePragmasAndSchema(t *testing.T) {
	drv := &stubDriver{}
	sql.Register("visionary_stub_sqlite", drv)
	st, err := OpenSQLite("visionary_stub_sqlite", ":memory:")
	if err != nil {
		t.Fatalf("OpenSQLite failed: %v", err)
	}
	defer st.Close()
	if st.Backend() != "sqlite" {
		t.Fatalf("expected sqlite backend, got %s", st.Backend())
	}
	if err := st.PutReputation(RepRecord{Provider: "circl", SHA256: strings.Repeat("c", 64), Found: true, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatalf("PutReputation failed: %v", err)
	}
	if err := st.PutIPReputation(IPRecord{IP: "8.8.8.8", Source: "internetdb", Ports: []int{53}, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatalf("PutIPReputation failed: %v", err)
	}
	if err := st.PruneExpired(time.Now()); err != nil {
		t.Fatalf("PruneExpired failed: %v", err)
	}
	if len(drv.queries) < len(PragmasSQL)+len(SchemaSQL)+4 {
		t.Fatalf("expected pragmas + schema + DML queries, got %d", len(drv.queries))
	}
}

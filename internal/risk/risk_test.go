package risk

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestNVDSearchAndGuidance(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("apiKey") != "nist-free-key" {
			t.Errorf("expected apiKey header, got %q", r.Header.Get("apiKey"))
		}
		if !strings.Contains(r.URL.RawQuery, "hasKev") || r.URL.Query().Get("cvssV3Severity") != "CRITICAL" {
			t.Errorf("unexpected query: %s", r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`{
			"totalResults": 2,
			"vulnerabilities": [
				{
					"cve": {
						"id": "CVE-2025-0411",
						"published": "2025-01-19T12:00:00.000",
						"cisaExploitAdd": "2025-02-04",
						"cisaVulnerabilityName": "7-Zip Mark-of-the-Web Bypass Vulnerability",
						"descriptions": [
							{"lang": "en", "value": "7-Zip before 24.09 allows crafted archives to bypass Mark-of-the-Web protection."}
						],
						"metrics": {
							"cvssMetricV31": [{"cvssData": {"baseScore": 9.1, "baseSeverity": "CRITICAL"}}]
						},
						"weaknesses": [
							{"description": [{"lang": "en", "value": "CWE-693"}]}
						],
						"configurations": [
							{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:7-zip:7-zip:24.08:*:*:*:*:*:*:*", "vulnerable": true}]}]}
						]
					}
				},
				{
					"cve": {
						"id": "CVE-2025-2783",
						"published": "2025-03-25T15:00:00.000",
						"cisaExploitAdd": "2025-03-27",
						"cisaVulnerabilityName": "Google Chrome Sandbox Escape",
						"descriptions": [
							{"lang": "en", "value": "Incorrect handle in Mojo in Google Chrome on Windows allowed sandbox escape."}
						],
						"metrics": {
							"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]
						},
						"configurations": [
							{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:google:chrome:134.0:*:*:*:*:*:*:*", "vulnerable": true}]}]}
						]
					}
				}
			]
		}`))
	}))
	defer srv.Close()

	client := NewNVD("nist-free-key", srv.URL, false)
	advs, total, err := client.Search(context.Background(), SearchOptions{
		Severity: "CRITICAL",
		KEVOnly:  true,
		Limit:    25,
	})
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(advs) != 2 {
		t.Fatalf("expected 2 advisories, got total=%d len=%d", total, len(advs))
	}
	if !advs[0].KEV || advs[0].CVSS != 9.1 || advs[0].Severity != "CRITICAL" {
		t.Fatalf("unexpected advisory[0]: %+v", advs[0])
	}
	if len(advs[0].Products) == 0 || advs[0].Products[0] != "7-zip" {
		t.Fatalf("expected CPE product 7-zip, got %v", advs[0].Products)
	}

	st := State{SyncedAt: "2026-11-27T12:00:00Z", Provider: "nvd", Advisories: advs}
	g := ComputeGuidance(st)
	if g.Posture != "critical" || !g.RecommendDeep || !g.RecommendArchives || g.KEVCount != 2 {
		t.Fatalf("unexpected guidance: %+v", g)
	}
	if len(g.PriorityTargets) < 2 {
		t.Fatalf("expected at least 2 priority targets (7-Zip & Chrome), got %+v", g.PriorityTargets)
	}

	// Verify disk persistence roundtrip.
	p := filepath.Join(t.TempDir(), "risk_exchange.json")
	if err := SaveState(p, st); err != nil {
		t.Fatal(err)
	}
	loaded := LoadState(p)
	if len(loaded.Advisories) != 2 || loaded.Advisories[0].ID != "CVE-2025-0411" {
		t.Fatalf("state roundtrip failed: %+v", loaded)
	}
}

func TestNVDCVEIDLookup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("cveId") != "CVE-2021-44228" {
			t.Errorf("expected cveId=CVE-2021-44228, got %s", r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2021-44228","descriptions":[{"lang":"en","value":"Apache Log4j2 JNDI RCE"}],"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":10.0,"baseSeverity":"CRITICAL"}}]}}}]}`))
	}))
	defer srv.Close()

	client := NewNVD("", srv.URL, false)
	advs, _, err := client.Search(context.Background(), SearchOptions{Query: "cve-2021-44228"})
	if err != nil {
		t.Fatal(err)
	}
	if len(advs) != 1 || advs[0].ID != "CVE-2021-44228" || advs[0].CVSS != 10.0 {
		t.Fatalf("unexpected CVE lookup: %+v", advs)
	}
}

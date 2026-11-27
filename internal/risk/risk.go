// Package risk implements the Risk Exchange: pluggable HTTP/API vulnerability
// providers (starting with NIST NVD CVE 2.0) that fetch CVE advisories and
// turn them into actionable scan guidance — telling Visionary where to look
// and how aggressively to scan.
package risk

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/config"
)

// ProviderInfo describes one Risk Exchange HTTP/API provider for the picker.
type ProviderInfo struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Endpoint      string `json:"endpoint"`
	KeyOptional   bool   `json:"key_optional"`
	RateLimitHint string `json:"rate_limit_hint"`
	DocsURL       string `json:"docs_url"`
	DocsHint      string `json:"docs_hint"`
}

// Providers lists all supported Risk Exchange HTTP/API providers.
var Providers = []ProviderInfo{
	{
		ID:            "nvd",
		Name:          "NIST NVD CVE 2.0",
		Endpoint:      DefaultNVDEndpoint,
		KeyOptional:   true,
		RateLimitHint: "Free without key (5 req/30s) · Free NIST API key lifts limit to 50 req/30s",
		DocsURL:       "https://nvd.nist.gov/developers/vulnerabilities",
		DocsHint:      "Search 250,000+ CVEs and CISA Known Exploited Vulnerabilities (KEV) for free via services.nvd.nist.gov/rest/json/cves/2.0.",
	},
	{
		ID:            "custom",
		Name:          "Custom HTTP/JSON Risk Feed",
		Endpoint:      "",
		KeyOptional:   true,
		RateLimitHint: "Accepts NVD 2.0 JSON or a compact JSON advisory list from any HTTPS endpoint",
		DocsURL:       "https://nvd.nist.gov/developers/vulnerabilities",
		DocsHint:      "Point Visionary at an internal or third-party HTTP/API vulnerability feed to guide where and how scans run.",
	},
}

// NormalizeProvider maps user input to a canonical Risk Exchange provider ID.
func NormalizeProvider(p string) string {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "", "nvd", "nist", "nvd-cve":
		return "nvd"
	case "custom", "http", "json":
		return "custom"
	default:
		return ""
	}
}

// Advisory is one normalized vulnerability record returned by a Risk Exchange provider.
type Advisory struct {
	ID        string   `json:"id"`
	Source    string   `json:"source"`
	Severity  string   `json:"severity"` // CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN
	CVSS      float64  `json:"cvss"`
	KEV       bool     `json:"kev"`
	KEVName   string   `json:"kev_name,omitempty"`
	Summary   string   `json:"summary"`
	Published string   `json:"published,omitempty"`
	Modified  string   `json:"modified,omitempty"`
	Products  []string `json:"products,omitempty"`
	CWEs      []string `json:"cwes,omitempty"`
	ScanHints []string `json:"scan_hints,omitempty"`
	URL       string   `json:"url,omitempty"`
}

// SearchOptions controls a Risk Exchange query.
type SearchOptions struct {
	Query    string
	CVEID    string
	Severity string // CRITICAL | HIGH | MEDIUM | LOW
	KEVOnly  bool
	Limit    int
}

// Provider is implemented by every Risk Exchange HTTP/API backend.
type Provider interface {
	ID() string
	Name() string
	Search(ctx context.Context, opts SearchOptions) ([]Advisory, int, error)
}

// PriorityTarget is one software/location focus derived from active CVEs.
type PriorityTarget struct {
	Product  string   `json:"product"`
	Reason   string   `json:"reason"`
	Paths    []string `json:"paths"`
	CVEs     []string `json:"cves"`
	Severity string   `json:"severity"`
	KEV      bool     `json:"kev"`
}

// Guidance translates Risk Exchange advisories into concrete scan decisions:
// where to check (PriorityTargets) and how to scan (Posture / Deep / Archives).
type Guidance struct {
	Posture           string           `json:"posture"` // standard | elevated | critical
	RecommendDeep     bool             `json:"recommend_deep"`
	RecommendArchives bool             `json:"recommend_archives"`
	Reason            string           `json:"reason"`
	PriorityTargets   []PriorityTarget `json:"priority_targets"`
	AdvisoryCount     int              `json:"advisory_count"`
	KEVCount          int              `json:"kev_count"`
	CriticalCount     int              `json:"critical_count"`
	HighCount         int              `json:"high_count"`
	SyncedAt          string           `json:"synced_at,omitempty"`
}

// State is persisted on disk at config.Path("risk_exchange.json").
type State struct {
	SyncedAt   string     `json:"synced_at,omitempty"`
	Provider   string     `json:"provider,omitempty"`
	TotalMatch int        `json:"total_match,omitempty"`
	Advisories []Advisory `json:"advisories,omitempty"`
}

func StatePath() string { return config.Path("risk_exchange.json") }

// LoadState reads previously synced Risk Exchange advisories from disk.
func LoadState(path string) State {
	var st State
	if path == "" {
		path = StatePath()
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return st
	}
	_ = json.Unmarshal(b, &st)
	return st
}

// SaveState persists synced Risk Exchange advisories atomically.
func SaveState(path string, st State) error {
	if path == "" {
		path = StatePath()
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return config.WriteAtomic(path, b, 0o644)
}

// ---- CVE -> Windows scan target mapping ----

type targetRule struct {
	product      string
	keywords     []string
	archiveRisk  bool
	resolvePaths func() []string
}

var targetRules = []targetRule{
	{
		product:  "Google Chrome / Chromium",
		keywords: []string{"chrome", "chromium", "v8"},
		resolvePaths: func() []string {
			return envPaths(
				[]string{"ProgramFiles", `Google\Chrome\Application`},
				[]string{"ProgramFiles(x86)", `Google\Chrome\Application`},
				[]string{"LOCALAPPDATA", `Google\Chrome\User Data\Default\Extensions`},
				[]string{"USERPROFILE", "Downloads"},
			)
		},
	},
	{
		product:  "Microsoft Edge",
		keywords: []string{"microsoft_edge", "edge_chromium", "msedge"},
		resolvePaths: func() []string {
			return envPaths(
				[]string{"ProgramFiles(x86)", `Microsoft\Edge\Application`},
				[]string{"ProgramFiles", `Microsoft\Edge\Application`},
				[]string{"USERPROFILE", "Downloads"},
			)
		},
	},
	{
		product:  "Mozilla Firefox",
		keywords: []string{"firefox", "mozilla"},
		resolvePaths: func() []string {
			return envPaths(
				[]string{"ProgramFiles", "Mozilla Firefox"},
				[]string{"ProgramFiles(x86)", "Mozilla Firefox"},
				[]string{"USERPROFILE", "Downloads"},
			)
		},
	},
	{
		product:     "Archive Utilities (7-Zip / WinRAR)",
		keywords:    []string{"7-zip", "7zip", "winrar", "rarlab", "winzip", "libarchive"},
		archiveRisk: true,
		resolvePaths: func() []string {
			return envPaths(
				[]string{"ProgramFiles", "7-Zip"},
				[]string{"ProgramFiles", "WinRAR"},
				[]string{"USERPROFILE", "Downloads"},
				[]string{"TEMP", ""},
			)
		},
	},
	{
		product:  "Microsoft Office & PDF Readers",
		keywords: []string{"office", "word", "excel", "outlook", "acrobat", "foxit", "pdf"},
		resolvePaths: func() []string {
			return envPaths(
				[]string{"ProgramFiles", `Microsoft Office`},
				[]string{"ProgramFiles", `Adobe`},
				[]string{"USERPROFILE", "Downloads"},
				[]string{"USERPROFILE", "Documents"},
			)
		},
	},
	{
		product:  "PowerShell & Windows Scripting",
		keywords: []string{"powershell", "mshta", "wscript", "cscript", "vbscript", "windows_script"},
		resolvePaths: func() []string {
			return envPaths(
				[]string{"TEMP", ""},
				[]string{"USERPROFILE", "Downloads"},
				[]string{"APPDATA", `Microsoft\Windows\Start Menu\Programs\Startup`},
			)
		},
	},
	{
		product:  "Developer Runtimes (Python / Node / Java / Git)",
		keywords: []string{"python", "node.js", "nodejs", "java", "jdk", "jre", "log4j", "openssl", "git", "visual_studio", "vscode"},
		resolvePaths: func() []string {
			return envPaths(
				[]string{"LOCALAPPDATA", "Programs"},
				[]string{"ProgramFiles", "Git"},
				[]string{"ProgramFiles", "nodejs"},
				[]string{"ProgramFiles", "Java"},
			)
		},
	},
	{
		product:  "Windows Core & Remote Services",
		keywords: []string{"windows", "smb", "rdp", "win32k", "ntfs", "kernel", "openssh", "defender", "exchange"},
		resolvePaths: func() []string {
			return envPaths(
				[]string{"TEMP", ""},
				[]string{"USERPROFILE", "Downloads"},
				[]string{"ProgramData", `Microsoft\Windows\Start Menu\Programs\Startup`},
			)
		},
	},
}

func envPaths(specs ...[]string) []string {
	var out []string
	seen := map[string]bool{}
	for _, sp := range specs {
		base := os.Getenv(sp[0])
		if base == "" {
			continue
		}
		p := base
		if len(sp) > 1 && sp[1] != "" {
			p = filepath.Join(base, sp[1])
		}
		key := strings.ToLower(p)
		if seen[key] {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			seen[key] = true
			out = append(out, p)
		}
	}
	return out
}

// MatchHints returns human-readable scan-target hints for one advisory.
func MatchHints(a Advisory) []string {
	haystack := strings.ToLower(a.Summary + " " + a.KEVName + " " + strings.Join(a.Products, " "))
	var hints []string
	for _, r := range targetRules {
		for _, kw := range r.keywords {
			if strings.Contains(haystack, kw) {
				hints = append(hints, r.product)
				break
			}
		}
	}
	return hints
}

// ComputeGuidance evaluates synced CVE advisories and produces a concrete scan
// plan: which paths to prioritize and whether Deep/Archive inspection should run.
func ComputeGuidance(st State) Guidance {
	g := Guidance{
		Posture:       "standard",
		AdvisoryCount: len(st.Advisories),
		SyncedAt:      st.SyncedAt,
	}
	if len(st.Advisories) == 0 {
		g.Reason = "No Risk Exchange advisories synced yet — sync NIST NVD to auto-prioritize scans."
		return g
	}

	type acc struct {
		rule     targetRule
		cves     []string
		cveSet   map[string]bool
		sevRank  int
		severity string
		kev      bool
	}
	buckets := map[string]*acc{}
	archiveTriggered := false

	for _, a := range st.Advisories {
		if a.KEV {
			g.KEVCount++
		}
		switch strings.ToUpper(a.Severity) {
		case "CRITICAL":
			g.CriticalCount++
		case "HIGH":
			g.HighCount++
		}
		haystack := strings.ToLower(a.Summary + " " + a.KEVName + " " + strings.Join(a.Products, " "))
		if strings.Contains(haystack, "archive") || strings.Contains(haystack, "zip") || strings.Contains(haystack, "rar") || strings.Contains(haystack, "extraction") {
			archiveTriggered = true
		}
		for _, r := range targetRules {
			matched := false
			for _, kw := range r.keywords {
				if strings.Contains(haystack, kw) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
			if r.archiveRisk {
				archiveTriggered = true
			}
			b, ok := buckets[r.product]
			if !ok {
				b = &acc{rule: r, cveSet: map[string]bool{}, severity: "LOW"}
				buckets[r.product] = b
			}
			if !b.cveSet[a.ID] {
				b.cveSet[a.ID] = true
				b.cves = append(b.cves, a.ID)
			}
			if a.KEV {
				b.kev = true
			}
			if rank := severityRank(a.Severity); rank > b.sevRank {
				b.sevRank = rank
				b.severity = strings.ToUpper(a.Severity)
			}
		}
	}

	var list []*acc
	for _, b := range buckets {
		list = append(list, b)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].kev != list[j].kev {
			return list[i].kev
		}
		if list[i].sevRank != list[j].sevRank {
			return list[i].sevRank > list[j].sevRank
		}
		return len(list[i].cves) > len(list[j].cves)
	})

	for _, b := range list {
		paths := b.rule.resolvePaths()
		if len(b.cves) > 5 {
			b.cves = b.cves[:5]
		}
		reason := fmt.Sprintf("%d matched %s", len(b.cveSet), plural(len(b.cveSet), "CVE", "CVEs"))
		if b.kev {
			reason += " (includes CISA KEV actively exploited)"
		}
		g.PriorityTargets = append(g.PriorityTargets, PriorityTarget{
			Product:  b.rule.product,
			Reason:   reason,
			Paths:    paths,
			CVEs:     b.cves,
			Severity: b.severity,
			KEV:      b.kev,
		})
	}

	switch {
	case g.KEVCount > 0:
		g.Posture = "critical"
		g.RecommendDeep = true
		g.RecommendArchives = true
		g.Reason = fmt.Sprintf("%d actively exploited CISA KEV %s in feed — recommend Deep scan with Archive inspection & Threat Exchange escalation.",
			g.KEVCount, plural(g.KEVCount, "advisory", "advisories"))
	case g.CriticalCount > 0:
		g.Posture = "elevated"
		g.RecommendDeep = true
		g.RecommendArchives = archiveTriggered
		g.Reason = fmt.Sprintf("%d CRITICAL CVEs synced — recommend Deep scan on priority software & Downloads/Temp folders.", g.CriticalCount)
	case g.HighCount > 0:
		g.Posture = "elevated"
		g.RecommendDeep = false
		g.RecommendArchives = archiveTriggered
		g.Reason = fmt.Sprintf("%d HIGH CVEs synced — prioritizing affected application folders during Quick Scan.", g.HighCount)
	default:
		g.Posture = "standard"
		g.Reason = fmt.Sprintf("%d advisories synced; standard scan posture is sufficient.", g.AdvisoryCount)
	}
	return g
}

// ExistingPaths flattens all resolved local filesystem paths from Guidance.
func (g Guidance) ExistingPaths() []string {
	var out []string
	seen := map[string]bool{}
	for _, t := range g.PriorityTargets {
		for _, p := range t.Paths {
			k := strings.ToLower(p)
			if !seen[k] {
				seen[k] = true
				out = append(out, p)
			}
		}
	}
	return out
}

func severityRank(s string) int {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

func plural(n int, singular, pl string) string {
	if n == 1 {
		return singular
	}
	return pl
}

// IsFresh reports whether the synced state is newer than maxAge.
func (st State) IsFresh(maxAge time.Duration) bool {
	if st.SyncedAt == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, st.SyncedAt)
	return err == nil && time.Since(t) < maxAge
}

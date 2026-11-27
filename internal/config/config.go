// Package config holds persisted settings and the data-directory layout.
// Everything the CLI, the guard and the UI share goes through this file, so
// a change made by one front end is picked up by the others.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/edition"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

const AppName = "Visionary"

// Version is stamped by the build (-ldflags "-X .../config.Version=1.2.3").
var Version = "0.1.0-dev"

type Protection struct {
	Enabled bool `json:"enabled"`
	// DisabledUntil re-enables protection automatically once reached.
	DisabledUntil time.Time `json:"disabled_until,omitempty"`
	// DisabledBoot is set for "until restart": protection comes back when
	// the machine's boot time no longer matches.
	DisabledBoot time.Time `json:"disabled_boot,omitempty"`
	DisabledAt   time.Time `json:"disabled_at,omitempty"`
	DisabledMode string    `json:"disabled_mode,omitempty"` // timed | restart | permanent
}

type Realtime struct {
	WatchPaths     []string `json:"watch_paths"` // empty = platform defaults
	AutoQuarantine bool     `json:"auto_quarantine"`
	Excludes       []string `json:"excludes"`
	Workers        int      `json:"workers"`   // scan workers for the guard; 0 = 2
	SettleMS       int      `json:"settle_ms"` // wait for a file to stop changing; 0 = 700
}

type Scan struct {
	MaxFileSizeMB int      `json:"max_file_size_mb"`
	Workers       int      `json:"workers"` // 0 = auto
	Excludes      []string `json:"excludes"`
	ScanArchives  bool     `json:"scan_archives"`
	UseCache      bool     `json:"use_cache"`
	AIBudget      int      `json:"ai_budget"` // max AI escalations per scan
}

type LocalAI struct {
	Provider   string  `json:"provider"` // ollama | llama-server
	Endpoint   string  `json:"endpoint"`
	Model      string  `json:"model"`
	MaxParamsB float64 `json:"max_params_b"` // parameter ceiling, in billions
	ServerPath string  `json:"server_path,omitempty"`
	ModelPath  string  `json:"model_path,omitempty"` // GGUF for llama-server
	// CPUOnly keeps the model off the GPU (Ollama num_gpu=0, llama.cpp -ngl 0)
	// and unloads it after KeepAlive of idleness, so a game or an old laptop
	// never loses VRAM or RAM to the scanner.
	CPUOnly   bool   `json:"cpu_only"`
	Threads   int    `json:"threads"`              // 0 = half the cores
	KeepAlive string `json:"keep_alive,omitempty"` // Ollama keep_alive, e.g. "2m"
}

type CloudAI struct {
	Provider      string `json:"provider"`           // gemini | claude | openai
	Model         string `json:"model"`
	Endpoint      string `json:"endpoint,omitempty"` // optional custom OpenAI-compatible base URL
	Effort        string `json:"effort,omitempty"`
	ShareSnippets bool   `json:"share_snippets"` // send script excerpts, never whole files
}

type AI struct {
	Mode                string  `json:"mode"`                 // off | local | cloud | hybrid
	Sensitivity         string  `json:"sensitivity"`          // conservative | balanced | proactive
	ConfidenceThreshold float64 `json:"confidence_threshold"` // min confidence (0.5..0.99) to convict or clear; 0 = 0.80
	Local               LocalAI `json:"local"`
	Cloud               CloudAI `json:"cloud"`
}

type Reputation struct {
	Provider    string `json:"provider,omitempty"`      // virustotal | otx | both
	VirusTotal  bool   `json:"virustotal"`
	OTX         bool   `json:"otx,omitempty"`
	OTXLastSync string `json:"otx_last_sync,omitempty"` // RFC3339 cursor for compact incremental OTX feed export
}

// Enabled reports whether any Threat Exchange hash reputation provider is active.
func (r Reputation) Enabled() bool {
	return r.VirusTotal || r.OTX
}

// RiskExchange configures HTTP/API vulnerability feeds (such as NIST NVD CVE 2.0)
// that guide where Visionary checks and how aggressively it scans.
type RiskExchange struct {
	Enabled        bool   `json:"enabled"`
	Provider       string `json:"provider,omitempty"`      // nvd | custom
	Endpoint       string `json:"endpoint,omitempty"`      // optional custom HTTP/JSON endpoint
	KEVOnly        bool   `json:"kev_only"`                // focus on CISA Known Exploited Vulnerabilities
	MinSeverity    string `json:"min_severity,omitempty"`  // CRITICAL | HIGH | MEDIUM | LOW
	AutoPrioritize bool   `json:"auto_prioritize"`         // merge high-risk CVE targets into Quick Scans
}

type Channel struct {
	Name          string    `json:"name"`
	URL           string    `json:"url"`
	Kind          string    `json:"kind"` // auto | hashes | yara | certs | cvd
	IntervalHours int       `json:"interval_hours"`
	Headers       []string  `json:"headers,omitempty"`
	Enabled       bool      `json:"enabled"`
	ETag          string    `json:"etag,omitempty"`
	LastModified  string    `json:"last_modified,omitempty"`
	LastChecked   time.Time `json:"last_checked,omitempty"`
	LastStatus    string    `json:"last_status,omitempty"`
}

type Behavior struct {
	Enabled       bool      `json:"enabled"`
	LearningUntil time.Time `json:"learning_until,omitempty"`
	LearnDays     int       `json:"learn_days"`
	Threshold     int       `json:"threshold"` // anomaly score that raises an alert
	PollMS        int       `json:"poll_ms"`   // process poll interval; 0 = 1500
}

type Security struct {
	RequirePasswordToDisable bool `json:"require_password_to_disable"`
}

type GameMode struct {
	Auto   bool `json:"auto"`   // detect fullscreen apps
	Forced bool `json:"forced"` // manual override
}

type Allow struct {
	Hashes []string `json:"hashes"`
	Paths  []string `json:"paths"`
}

type Windows struct {
	// DefenderSecondOpinion asks Microsoft Defender (AMSI / MpCmdRun) about
	// gray-zone files.
	DefenderSecondOpinion bool `json:"defender_second_opinion"`
}

type Config struct {
	Profile    string     `json:"profile"` // balanced | gamer | dev
	Protection Protection `json:"protection"`
	Realtime   Realtime   `json:"realtime"`
	Scan       Scan       `json:"scan"`
	AI         AI           `json:"ai"`
	Reputation Reputation   `json:"reputation"`
	Risk       RiskExchange `json:"risk"`
	Channels   []Channel    `json:"channels"`
	Behavior   Behavior   `json:"behavior"`
	Security   Security   `json:"security"`
	GameMode   GameMode   `json:"game_mode"`
	Allow      Allow      `json:"allow"`
	Windows    Windows    `json:"windows"`
	UI         UISettings `json:"ui"`
}

type UISettings struct {
	Port int `json:"port"`
}

// ApplyLite sets the low-footprint preset: one scan worker, slower polling,
// smaller files and archives, a tighter AI budget and CPU-only local AI with a
// 2B ceiling. The Lite edition starts from it; any edition can switch to it
// with `visionary profile lite`.
func ApplyLite(c *Config) {
	c.Profile = "lite"
	c.Scan.Workers = 1
	c.Scan.MaxFileSizeMB = 32
	c.Scan.AIBudget = 5
	c.Realtime.Workers = 1
	c.Realtime.SettleMS = 2000
	c.Behavior.PollMS = 3000
	c.GameMode.Auto = true
	c.AI.Local.CPUOnly = true
	c.AI.Local.KeepAlive = "2m"
	c.AI.Local.MaxParamsB = 2.0
	if c.AI.Local.Model == "" || c.AI.Local.Model == "qwen3:1.7b" {
		c.AI.Local.Model = "gemma3:1b"
	}
}

func Default() *Config {
	c := defaults()
	if edition.Lite {
		ApplyLite(c)
	}
	return c
}

func defaults() *Config {
	return &Config{
		Profile:    "balanced",
		Protection: Protection{Enabled: true},
		Realtime:   Realtime{AutoQuarantine: true},
		Scan:       Scan{MaxFileSizeMB: 64, ScanArchives: true, UseCache: true, AIBudget: 20},
		AI: AI{
			Mode:                "off",
			Sensitivity:         "balanced",
			ConfidenceThreshold: 0.80,
			Local: LocalAI{
				Provider: "ollama", Endpoint: "http://127.0.0.1:11434",
				Model: "qwen3:1.7b", MaxParamsB: 3.0,
			},
			Cloud: CloudAI{Provider: "gemini", Model: "gemini-2.5-flash"},
		},
		Risk: RiskExchange{
			Enabled:        true,
			Provider:       "nvd",
			KEVOnly:        true,
			MinSeverity:    "HIGH",
			AutoPrioritize: true,
		},
		Behavior: Behavior{Enabled: true, LearnDays: 3, Threshold: 50},
		Security: Security{RequirePasswordToDisable: false},
		GameMode: GameMode{Auto: true},
		Windows:  Windows{DefenderSecondOpinion: true},
		UI:       UISettings{Port: 7878},
	}
}

// ProfileExcludes returns the real-time excludes a profile adds. They only
// apply to real-time scanning: an on-demand scan still looks at everything.
func ProfileExcludes(profile string) []string {
	switch profile {
	case "dev":
		// Build churn: thousands of short-lived writes that are regenerated
		// from source. Dependencies (node_modules, site-packages) stay in.
		return []string{"/.git/", "/target/debug/", "/target/release/", "/obj/", "/bin/debug/",
			"/.gradle/", "/__pycache__/", "/.next/", "/cmakefiles/", "*.pdb", "*.ilk", "*.o", "*.obj"}
	case "gamer":
		return []string{"/steamapps/shadercache/", "/steamapps/downloading/", "/steamapps/temp/",
			"/epic games/launcher/", "/riot games/", "*.pak.tmp", "/dxcache/", "/glcache/"}
	}
	return nil
}

// Dir is the data directory. VISIONARY_HOME overrides it.
func Dir() string {
	if d := os.Getenv("VISIONARY_HOME"); d != "" {
		return d
	}
	if runtime.GOOS == "windows" {
		pd := os.Getenv("ProgramData")
		if pd == "" {
			pd = `C:\ProgramData`
		}
		return filepath.Join(pd, "VisionaryAV")
	}
	if d := os.Getenv("XDG_DATA_HOME"); d != "" {
		return filepath.Join(d, "visionary")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "share", "visionary")
}

// Path joins parts under the data directory and creates the parent.
func Path(parts ...string) string {
	p := filepath.Join(append([]string{Dir()}, parts...)...)
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	return p
}

var mu sync.Mutex

func file() string { return Path("config.json") }

// Load reads the config, falling back to defaults when it is missing.
func Load() (*Config, error) {
	mu.Lock()
	defer mu.Unlock()
	c := Default()
	b, err := os.ReadFile(file())
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, c); err != nil {
		return Default(), err
	}
	return c, nil
}

func Save(c *Config) error {
	mu.Lock()
	defer mu.Unlock()
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return WriteAtomic(file(), b, 0o644)
}

// Update loads, mutates and saves in one step.
func Update(fn func(*Config) error) (*Config, error) {
	c, err := Load()
	if err != nil {
		return nil, err
	}
	if err := fn(c); err != nil {
		return nil, err
	}
	return c, Save(c)
}

// ModTime lets long-running processes notice edits made elsewhere.
func ModTime() time.Time {
	st, err := os.Stat(file())
	if err != nil {
		return time.Time{}
	}
	return st.ModTime()
}

func WriteAtomic(path string, b []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		_ = os.Chmod(tmp, mode)
	}

	// On Windows, a concurrent reader (e.g. the background guard service
	// reloading config.json) can briefly cause os.Rename to return Access
	// Denied or Sharing Violation. Retry briefly before falling back.
	var renameErr error
	for attempt := 0; attempt < 8; attempt++ {
		if renameErr = os.Rename(tmp, path); renameErr == nil {
			cleanup = false
			return nil
		}
		if runtime.GOOS != "windows" {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}

	// Windows fallback: if replacing via rename is blocked by an active reader
	// handle or legacy file ACL, attempt an in-place write.
	if runtime.GOOS == "windows" {
		if err := os.WriteFile(path, b, mode); err == nil {
			return nil
		}
		if errors.Is(renameErr, os.ErrPermission) {
			return fmt.Errorf("%w (folder permissions need repair: restart the Visionary service or run Visionary once as Administrator)", renameErr)
		}
	}
	return renameErr
}

// Active reports whether protection is on right now, applying the automatic
// re-enable rules. boot is the current boot time.
func (p Protection) Active(now, boot time.Time) (bool, string) {
	if p.Enabled {
		return true, "enabled"
	}
	switch p.DisabledMode {
	case "timed":
		if !p.DisabledUntil.IsZero() && !now.Before(p.DisabledUntil) {
			return true, "re-enabled: timer expired"
		}
		return false, "disabled until " + p.DisabledUntil.Local().Format("15:04:05")
	case "restart":
		d := boot.Sub(p.DisabledBoot)
		if d < 0 {
			d = -d
		}
		if !p.DisabledBoot.IsZero() && d > 2*time.Minute {
			return true, "re-enabled: computer restarted"
		}
		return false, "disabled until restart"
	}
	return false, "disabled until re-enabled by the user"
}

// Excluded matches a path against exclude patterns. A pattern containing '*'
// is a glob on the file name; anything else is a case-insensitive substring
// of the slash-normalised path.
func Excluded(path string, patterns []string) bool {
	if len(patterns) == 0 {
		return false
	}
	norm := strings.ToLower(filepath.ToSlash(path))
	base := filepath.Base(norm)
	for _, p := range patterns {
		p = strings.ToLower(filepath.ToSlash(strings.TrimSpace(p)))
		if p == "" {
			continue
		}
		if strings.Contains(p, "*") {
			if ok, _ := filepath.Match(p, base); ok {
				return true
			}
			continue
		}
		if strings.Contains(norm, p) || strings.Contains(norm+"/", p) {
			return true
		}
	}
	return false
}

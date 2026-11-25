// Package config holds persisted settings and the data-directory layout.
// Everything the CLI, the guard and the UI share goes through this file, so
// a change made by one front end is picked up by the others.
package config

import (
	"encoding/json"
	"errors"
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
}

type CloudAI struct {
	Model         string `json:"model"`
	Effort        string `json:"effort,omitempty"`
	ShareSnippets bool   `json:"share_snippets"` // send script excerpts, never whole files
}

type AI struct {
	Mode  string  `json:"mode"` // off | local | cloud | hybrid
	Local LocalAI `json:"local"`
	Cloud CloudAI `json:"cloud"`
}

type Reputation struct {
	VirusTotal bool `json:"virustotal"`
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
	AI         AI         `json:"ai"`
	Reputation Reputation `json:"reputation"`
	Channels   []Channel  `json:"channels"`
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

func Default() *Config {
	return &Config{
		Profile:    "balanced",
		Protection: Protection{Enabled: true},
		Realtime:   Realtime{AutoQuarantine: true},
		Scan:       Scan{MaxFileSizeMB: 64, ScanArchives: true, UseCache: true, AIBudget: 20},
		AI: AI{
			Mode: "off",
			Local: LocalAI{
				Provider: "ollama", Endpoint: "http://127.0.0.1:11434",
				Model: "qwen3:1.7b", MaxParamsB: 3.0,
			},
			Cloud: CloudAI{Model: "claude-opus-5-5"},
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
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
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

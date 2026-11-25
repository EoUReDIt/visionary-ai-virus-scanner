// Package app is the one implementation of every feature. The command line
// calls these functions directly and the dashboard calls them over a local
// HTTP API, so nothing exists in the UI that does not work from a terminal.
package app

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/edition"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/ai"
	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/behavior"
	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/config"
	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/defs"
	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/engine"
	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/plat"
	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/reputation"
	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/secure"
	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/winsec"
)

type App struct {
	mu       sync.Mutex
	cfg      *config.Config
	cfgMod   time.Time
	db       *defs.DB
	eng      atomic.Pointer[engine.Engine]
	triage   *ai.Triage
	Warnings []string

	gameAt time.Time
	gameOn bool
	gameMu sync.Mutex
}

// Open loads settings and definitions and wires the layers together.
func Open() (*App, error) {
	a := &App{}
	return a, a.load()
}

func (a *App) load() error {
	cfg, err := config.Load()
	if err != nil {
		a.Warnings = append(a.Warnings, "settings file is unreadable, using defaults: "+err.Error())
	}
	db, err := defs.Open()
	if err != nil {
		a.Warnings = append(a.Warnings, err.Error())
	}
	eng := engine.New(cfg, db)
	eng.GameMode = a.GameMode
	if d := winsec.New(); d != nil {
		eng.Defender = d
	}
	if key := secure.Secret("virustotal"); key != "" && cfg.Reputation.VirusTotal {
		eng.Rep = reputation.NewVirusTotal(key)
	}
	triage := ai.NewTriage(cfg, secure.Secret("anthropic"))
	if triage.Enabled() {
		eng.AI = triage.Assess
	}
	a.mu.Lock()
	a.cfg, a.db, a.triage, a.cfgMod = cfg, db, triage, config.ModTime()
	a.mu.Unlock()
	if old := a.eng.Swap(eng); old != nil {
		old.Flush()
	}
	return nil
}

// Reload picks up changes made by another process (CLI, UI or guard).
func (a *App) Reload() bool {
	a.mu.Lock()
	stale := !config.ModTime().Equal(a.cfgMod) || defs.LoadManifest().Revision != a.db.Manifest.Revision
	a.mu.Unlock()
	if stale {
		_ = a.load()
	}
	return stale
}

func (a *App) Config() *config.Config {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cfg
}

func (a *App) Engine() *engine.Engine { return a.eng.Load() }

func (a *App) Triage() *ai.Triage {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.triage
}

// update changes settings and rebuilds the engine around them.
func (a *App) update(fn func(*config.Config) error) error {
	if _, err := config.Update(fn); err != nil {
		return err
	}
	return a.load()
}

// ---- events ----

type Event struct {
	Time     time.Time       `json:"time"`
	Type     string          `json:"type"`     // detection | anomaly | protection | definitions | scan | system
	Severity string          `json:"severity"` // info | warn | high
	Message  string          `json:"message"`
	Data     json.RawMessage `json:"data,omitempty"`
}

var eventMu sync.Mutex

func eventsPath() string { return config.Path("events.jsonl") }

// Log appends to the shared event log read by `visionary events` and the UI.
func (a *App) Log(typ, severity, msg string, data any) {
	ev := Event{Time: time.Now(), Type: typ, Severity: severity, Message: msg}
	if data != nil {
		ev.Data, _ = json.Marshal(data)
	}
	line, _ := json.Marshal(ev)
	eventMu.Lock()
	defer eventMu.Unlock()
	p := eventsPath()
	if st, err := os.Stat(p); err == nil && st.Size() > 8<<20 {
		// Keep the newer half.
		if b, err := os.ReadFile(p); err == nil {
			b = b[len(b)/2:]
			if i := strings.IndexByte(string(b), '\n'); i >= 0 {
				_ = os.WriteFile(p, b[i+1:], 0o644)
			}
		}
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(line, '\n'))
}

// Events returns the newest n events, newest first.
func (a *App) Events(n int) []Event {
	f, err := os.Open(eventsPath())
	if err != nil {
		return nil
	}
	defer f.Close()
	var all []Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4<<20)
	for sc.Scan() {
		var ev Event
		if json.Unmarshal(sc.Bytes(), &ev) == nil {
			all = append(all, ev)
		}
	}
	if n > 0 && len(all) > n {
		all = all[len(all)-n:]
	}
	for i, j := 0, len(all)-1; i < j; i, j = i+1, j-1 {
		all[i], all[j] = all[j], all[i]
	}
	return all
}

// ---- game mode ----

func gameFlag() string { return config.Path("gamemode.flag") }

// GameMode is true while a full-screen game (or presentation) is running, or
// when forced. A process in the user's session detects full screen and
// touches a flag file, which is how a guard running as a service (session 0,
// no desktop) learns about it.
func (a *App) GameMode() bool {
	cfg := a.Config()
	if cfg.GameMode.Forced {
		return true
	}
	if !cfg.GameMode.Auto {
		return false
	}
	a.gameMu.Lock()
	defer a.gameMu.Unlock()
	if time.Since(a.gameAt) < 5*time.Second {
		return a.gameOn
	}
	a.gameAt = time.Now()
	if plat.FullscreenAppActive() {
		now := time.Now()
		if os.Chtimes(gameFlag(), now, now) != nil {
			_ = os.WriteFile(gameFlag(), nil, 0o644)
		}
		a.gameOn = true
	} else if st, err := os.Stat(gameFlag()); err == nil && time.Since(st.ModTime()) < 20*time.Second {
		a.gameOn = true
	} else {
		a.gameOn = false
	}
	return a.gameOn
}

func (a *App) SetGameMode(mode string) error {
	return a.update(func(c *config.Config) error {
		switch mode {
		case "on":
			c.GameMode.Forced = true
		case "off":
			c.GameMode.Forced, c.GameMode.Auto = false, false
		case "auto":
			c.GameMode.Forced, c.GameMode.Auto = false, true
		default:
			return errors.New("game mode must be on, off or auto")
		}
		return nil
	})
}

// ---- protection ----

// ProtectionActive applies the automatic re-enable rules and persists the
// result when a timer or a restart has brought protection back.
func (a *App) ProtectionActive() (bool, string) {
	cfg := a.Config()
	on, why := cfg.Protection.Active(time.Now(), plat.BootTime())
	if on && !cfg.Protection.Enabled {
		_ = a.update(func(c *config.Config) error {
			c.Protection = config.Protection{Enabled: true}
			return nil
		})
		a.Log("protection", "info", "Real-time protection "+why, nil)
	}
	return on, why
}

// Disable turns real-time protection off. mode is "timed" (with d),
// "restart" or "permanent"; every mode leaves a way back on.
func (a *App) Disable(mode string, d time.Duration, password string) error {
	cfg := a.Config()
	if cfg.Security.RequirePasswordToDisable {
		if err := secure.VerifyPassword(password); err != nil {
			return fmt.Errorf("computer password required to disable protection: %w", err)
		}
	}
	p := config.Protection{Enabled: false, DisabledMode: mode, DisabledAt: time.Now()}
	msg := ""
	switch mode {
	case "timed":
		if d < time.Minute || d > 30*24*time.Hour {
			return errors.New("duration must be between 1 minute and 30 days")
		}
		p.DisabledUntil = time.Now().Add(d)
		msg = "Real-time protection disabled for " + d.String()
	case "restart":
		p.DisabledBoot = plat.BootTime()
		msg = "Real-time protection disabled until the computer restarts"
	case "permanent":
		msg = "Real-time protection disabled until re-enabled"
	default:
		return errors.New("mode must be timed, restart or permanent")
	}
	if err := a.update(func(c *config.Config) error { c.Protection = p; return nil }); err != nil {
		return err
	}
	a.Log("protection", "warn", msg, nil)
	return nil
}

func (a *App) Enable() error {
	if err := a.update(func(c *config.Config) error {
		c.Protection = config.Protection{Enabled: true}
		return nil
	}); err != nil {
		return err
	}
	a.Log("protection", "info", "Real-time protection enabled", nil)
	return nil
}

// ---- status ----

type Status struct {
	Version    string           `json:"version"`
	Edition    string           `json:"edition"`
	Protection bool             `json:"protection"`
	ProtReason string           `json:"protection_reason"`
	GuardAlive bool             `json:"guard_running"`
	GameMode   bool             `json:"game_mode"`
	Profile    string           `json:"profile"`
	Defs       defs.Stats       `json:"definitions"`
	Channels   int              `json:"channels"`
	AIMode     string           `json:"ai_mode"`
	LocalModel string           `json:"local_model,omitempty"`
	CloudModel string           `json:"cloud_model,omitempty"`
	CloudKey   bool             `json:"cloud_key_set"`
	VTKey      bool             `json:"virustotal_key_set"`
	Quarantine int              `json:"quarantined"`
	Learning   bool             `json:"behavior_learning"`
	Behavior   behavior.Summary `json:"behavior"`
	BootScan   bool             `json:"boot_scan_scheduled"`
	Admin      bool             `json:"admin"`
	DataDir    string           `json:"data_dir"`
	Windows    *winsec.Status   `json:"windows_security,omitempty"`
	Warnings   []string         `json:"warnings,omitempty"`
}

func heartbeat() string { return config.Path("guard.heartbeat") }

// GuardAlive reports whether a guard process has checked in recently.
func GuardAlive() bool {
	st, err := os.Stat(heartbeat())
	return err == nil && time.Since(st.ModTime()) < 15*time.Second
}

func (a *App) Learning() bool {
	b := a.Config().Behavior
	return b.Enabled && time.Now().Before(b.LearningUntil)
}

func (a *App) Status(withWindows bool) *Status {
	cfg := a.Config()
	on, why := a.ProtectionActive()
	s := &Status{
		Version: config.Version, Edition: edition.Name, Protection: on, ProtReason: why, GuardAlive: GuardAlive(),
		GameMode: a.GameMode(), Profile: cfg.Profile, Defs: a.db.Stats(), Channels: len(cfg.Channels),
		AIMode: cfg.AI.Mode, CloudKey: secure.Secret("anthropic") != "", VTKey: secure.Secret("virustotal") != "",
		Quarantine: len(engine.QuarantineList()), Learning: a.Learning(),
		Behavior: behavior.Summarize(behavior.Load()), BootScan: BootScanPending(),
		Admin: plat.IsAdmin(), DataDir: config.Dir(), Warnings: a.Warnings,
	}
	if cfg.AI.Mode == "local" || cfg.AI.Mode == "hybrid" {
		s.LocalModel = cfg.AI.Local.Model
	}
	if cfg.AI.Mode == "cloud" || cfg.AI.Mode == "hybrid" {
		s.CloudModel = cfg.AI.Cloud.Model
	}
	if withWindows {
		s.Windows = winsec.GetStatus()
	}
	return s
}

// ---- scans ----

type ScanOptions struct {
	Deep       bool // escalate gray-zone files to Defender / reputation / AI
	Quarantine bool
	NoCache    bool
}

func (a *App) engineOpts(o ScanOptions) engine.Options {
	return engine.Options{Escalate: o.Deep, Quarantine: o.Quarantine, NoCache: o.NoCache}
}

func (a *App) finish(kind string, sum *engine.Summary) *engine.Summary {
	sev := "info"
	if sum.Suspicious > 0 {
		sev = "warn"
	}
	if sum.Malicious > 0 {
		sev = "high"
	}
	a.Log("scan", sev, fmt.Sprintf("%s scan: %d files, %d malicious, %d suspicious, %.1fs",
		kind, sum.Files, sum.Malicious, sum.Suspicious, sum.Seconds), nil)
	for _, d := range sum.Detections {
		a.logDetection(kind+" scan", d)
	}
	return sum
}

func (a *App) logDetection(origin string, r *engine.Result) {
	sev := "warn"
	if r.Verdict == engine.Malicious {
		sev = "high"
	}
	msg := fmt.Sprintf("%s: %s — %s (score %d)", origin, r.Path, r.Threat, r.Score)
	if r.Action != "" {
		msg += " — " + r.Action
	}
	slim := *r
	slim.Features.Snippet = ""
	a.Log("detection", sev, msg, slim)
}

// QuickScan covers where malware lives and starts: running programs,
// autoruns, startup folders, temp and download folders.
func (a *App) QuickScan(ctx context.Context, o ScanOptions, progress func(*engine.Result)) *engine.Summary {
	targets := plat.QuickScanTargets()
	if procs, err := plat.ListProcesses(); err == nil {
		seen := map[string]bool{}
		for _, p := range procs {
			if p.Exe != "" && !seen[p.Exe] {
				seen[p.Exe] = true
				targets = append(targets, p.Exe)
			}
		}
	}
	return a.finish("quick", a.Engine().ScanPaths(ctx, targets, a.engineOpts(o), progress))
}

// TargetedScan scans exactly the files and folders given.
func (a *App) TargetedScan(ctx context.Context, paths []string, o ScanOptions, progress func(*engine.Result)) (*engine.Summary, error) {
	if len(paths) == 0 {
		return nil, errors.New("nothing to scan: give at least one file or folder")
	}
	var abs []string
	for _, p := range paths {
		q, err := filepath.Abs(p)
		if err != nil {
			return nil, err
		}
		abs = append(abs, q)
	}
	return a.finish("targeted", a.Engine().ScanPaths(ctx, abs, a.engineOpts(o), progress)), nil
}

// ---- boot-time scan ----

func bootFlag() string { return config.Path("bootscan.pending") }

func BootScanPending() bool {
	_, err := os.Stat(bootFlag())
	return err == nil
}

// ScheduleBootScan arranges a scan of boot-critical locations at the next
// startup, as SYSTEM, before anyone logs in.
func (a *App) ScheduleBootScan() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if err := plat.ScheduleBootTask(fmt.Sprintf(`"%s" scan boot --once`, exe)); err != nil {
		if errors.Is(err, plat.ErrUnsupported) {
			return errors.New("boot-time scans are scheduled through Windows Task Scheduler; here, run `visionary scan boot` directly")
		}
		return fmt.Errorf("could not schedule the boot scan (administrator rights are required): %w", err)
	}
	if err := os.WriteFile(bootFlag(), []byte(time.Now().Format(time.RFC3339)), 0o644); err != nil {
		return err
	}
	a.Log("system", "info", "Boot-time scan scheduled for the next restart", nil)
	return nil
}

func (a *App) CancelBootScan() error {
	_ = os.Remove(bootFlag())
	if err := plat.RemoveBootTask(); err != nil && !errors.Is(err, plat.ErrUnsupported) {
		return err
	}
	return nil
}

// BootScan scans drivers, services, autoruns and scheduled tasks, always
// with every layer and no cache, and saves a report for the next login.
func (a *App) BootScan(ctx context.Context, once bool, progress func(*engine.Result)) *engine.Summary {
	sum := a.Engine().ScanPaths(ctx, plat.BootScanTargets(),
		engine.Options{Escalate: true, Quarantine: true, NoCache: true}, progress)
	a.finish("boot", sum)
	if b, err := json.MarshalIndent(sum, "", "  "); err == nil {
		_ = os.WriteFile(config.Path("reports", "boot-"+time.Now().Format("20060102-150405")+".json"), b, 0o644)
	}
	_ = os.Remove(bootFlag())
	if once {
		_ = plat.RemoveBootTask()
	}
	return sum
}

// ---- settings ----

// ResetSettings restores default settings and clears cached state. It always
// requires the computer password: a reset is how protection would be
// weakened quietly. all also removes API keys, the behaviour baseline and
// the event log; definitions and quarantine are never touched.
func (a *App) ResetSettings(password string, all bool) error {
	if err := secure.VerifyPassword(password); err != nil {
		return err
	}
	a.Engine().Flush()
	if err := config.Save(config.Default()); err != nil {
		return err
	}
	_ = engine.ClearCache()
	_ = os.Remove(gameFlag())
	if all {
		_ = secure.ClearSecrets()
		_ = behavior.Reset()
		_ = os.Remove(eventsPath())
	}
	a.Warnings = nil
	if err := a.load(); err != nil {
		return err
	}
	what := "Settings and scan cache reset to defaults"
	if all {
		what += " (API keys, behaviour baseline and event log cleared)"
	}
	a.Log("system", "warn", what+" by "+secure.CurrentUser(), nil)
	return nil
}

func (a *App) SetProfile(p string) error {
	if p != "balanced" && p != "gamer" && p != "dev" && p != "lite" {
		return errors.New("profile must be balanced, gamer, dev or lite")
	}
	return a.update(func(c *config.Config) error {
		c.Profile = p
		switch p {
		case "lite":
			config.ApplyLite(c)
		case "gamer":
			c.GameMode.Auto = true
		case "dev":
			// Developers want supply-chain findings explained, not just flagged.
			c.Scan.ScanArchives = true
		}
		return nil
	})
}

// Set changes one setting by its dotted name.
func (a *App) Set(key, value string) error {
	b, err := parseBool(value)
	n, nerr := parseInt(value)
	return a.update(func(c *config.Config) error {
		needBool := func(dst *bool) error {
			if err != nil {
				return fmt.Errorf("%s expects true or false", key)
			}
			*dst = b
			return nil
		}
		needInt := func(dst *int, lo, hi int) error {
			if nerr != nil || n < lo || n > hi {
				return fmt.Errorf("%s expects a number between %d and %d", key, lo, hi)
			}
			*dst = n
			return nil
		}
		switch key {
		case "realtime.auto_quarantine":
			return needBool(&c.Realtime.AutoQuarantine)
		case "scan.max_file_size_mb":
			return needInt(&c.Scan.MaxFileSizeMB, 1, 4096)
		case "scan.workers":
			return needInt(&c.Scan.Workers, 0, 64)
		case "scan.scan_archives":
			return needBool(&c.Scan.ScanArchives)
		case "scan.use_cache":
			return needBool(&c.Scan.UseCache)
		case "scan.ai_budget":
			return needInt(&c.Scan.AIBudget, 1, 1000)
		case "behavior.enabled":
			return needBool(&c.Behavior.Enabled)
		case "behavior.threshold":
			return needInt(&c.Behavior.Threshold, 20, 100)
		case "security.require_password_to_disable":
			return needBool(&c.Security.RequirePasswordToDisable)
		case "windows.defender_second_opinion":
			return needBool(&c.Windows.DefenderSecondOpinion)
		case "reputation.virustotal":
			return needBool(&c.Reputation.VirusTotal)
		case "ai.cloud.share_snippets":
			return needBool(&c.AI.Cloud.ShareSnippets)
		case "ai.cloud.model":
			c.AI.Cloud.Model = value
		case "ai.cloud.effort":
			switch value {
			case "", "low", "medium", "high", "xhigh", "max":
				c.AI.Cloud.Effort = value
			default:
				return errors.New("effort must be low, medium, high, xhigh or max")
			}
		case "ai.local.endpoint":
			c.AI.Local.Endpoint = value
		case "ai.local.provider":
			if value != "ollama" && value != "llama-server" {
				return errors.New("provider must be ollama or llama-server")
			}
			c.AI.Local.Provider = value
		case "ai.local.server_path":
			c.AI.Local.ServerPath = value
		case "ai.local.max_params_b":
			var f float64
			if _, e := fmt.Sscanf(value, "%g", &f); e != nil || f <= 0 || f > 3 {
				return errors.New("ai.local.max_params_b must be between 0 and 3 (billions of parameters)")
			}
			c.AI.Local.MaxParamsB = f
		case "ai.local.cpu_only":
			return needBool(&c.AI.Local.CPUOnly)
		case "ai.local.threads":
			return needInt(&c.AI.Local.Threads, 0, 256)
		case "ai.local.keep_alive":
			c.AI.Local.KeepAlive = value
		case "realtime.workers":
			return needInt(&c.Realtime.Workers, 0, 16)
		case "realtime.settle_ms":
			return needInt(&c.Realtime.SettleMS, 0, 60000)
		case "behavior.poll_ms":
			return needInt(&c.Behavior.PollMS, 0, 60000)
		case "ui.port":
			return needInt(&c.UI.Port, 1024, 65535)
		default:
			return fmt.Errorf("unknown setting %q (see: visionary settings show)", key)
		}
		return nil
	})
}

func parseBool(s string) (bool, error) {
	switch strings.ToLower(s) {
	case "true", "on", "yes", "1":
		return true, nil
	case "false", "off", "no", "0":
		return false, nil
	}
	return false, errors.New("not a boolean")
}

func parseInt(s string) (int, error) {
	var n int
	_, err := fmt.Sscanf(s, "%d", &n)
	return n, err
}

// AddExclude / RemoveExclude manage scan and real-time excludes.
func (a *App) Exclude(pattern string, add bool) error {
	return a.update(func(c *config.Config) error {
		c.Scan.Excludes = editList(c.Scan.Excludes, pattern, add)
		return nil
	})
}

func editList(list []string, item string, add bool) []string {
	var out []string
	for _, x := range list {
		if !strings.EqualFold(x, item) {
			out = append(out, x)
		}
	}
	if add {
		out = append(out, item)
	}
	return out
}

// Allow adds a file (by SHA-256) or a path prefix to the allowlist.
func (a *App) Allow(item string, add bool) error {
	isHash := len(item) == 64 && strings.Trim(strings.ToLower(item), "0123456789abcdef") == ""
	if !isHash && add {
		abs, err := filepath.Abs(item)
		if err != nil {
			return err
		}
		item = abs
	}
	return a.update(func(c *config.Config) error {
		if isHash {
			c.Allow.Hashes = editList(c.Allow.Hashes, strings.ToLower(item), add)
		} else {
			c.Allow.Paths = editList(c.Allow.Paths, item, add)
		}
		return nil
	})
}

// Restore returns a quarantined file and, when asked, allowlists its hash so
// it is not taken again.
func (a *App) Restore(id, dest string, allow bool) (engine.QItem, error) {
	it, err := engine.QuarantineRestore(id, dest)
	if err != nil {
		return it, err
	}
	if allow && it.SHA256 != "" {
		_ = a.Allow(it.SHA256, true)
	}
	a.Log("system", "warn", "Restored from quarantine: "+it.Original, nil)
	return it, nil
}

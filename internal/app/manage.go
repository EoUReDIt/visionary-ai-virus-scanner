package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/ai"
	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/behavior"
	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/config"
	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/defs"
	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/engine"
	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/reputation"
	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/secure"
	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/winsec"
)

// ---- definitions ----

func (a *App) ImportDefs(path, name, kind string) (defs.Source, error) {
	src, err := defs.Import(path, name, kind, "", "")
	if err != nil {
		return src, err
	}
	msg := fmt.Sprintf("Imported %d %s definitions as %q", src.Count, src.Kind, src.Name)
	if src.Skipped > 0 {
		msg += fmt.Sprintf(" (%d entries not usable)", src.Skipped)
	}
	a.Log("definitions", "info", msg, nil)
	return src, a.load()
}

func (a *App) RemoveDefs(name string) error {
	if err := defs.Remove(name); err != nil {
		return err
	}
	a.Log("definitions", "info", "Removed definitions source "+name, nil)
	return a.load()
}

func (a *App) DefSources() []defs.Source { return defs.LoadManifest().Sources }

// ChannelAdd subscribes to a definitions feed. A preset name can stand in
// for the URL.
func (a *App) ChannelAdd(name, url, kind string, hours int, headers []string) error {
	if url == "" {
		for _, p := range defs.Presets {
			if p.Name == name {
				url, kind, hours = p.URL, p.Kind, p.Hours
			}
		}
		if url == "" {
			return fmt.Errorf("%q is not a preset: give a URL (see: visionary defs channel presets)", name)
		}
	}
	if err := defs.ValidateChannelURL(url); err != nil {
		return err
	}
	if kind == "" {
		kind = "auto"
	}
	if hours <= 0 {
		hours = 6
	}
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" || strings.ContainsAny(name, ` /\`) {
		return errors.New("channel name must be a single word")
	}
	return a.update(func(c *config.Config) error {
		for _, ch := range c.Channels {
			if ch.Name == name {
				return fmt.Errorf("channel %q already exists", name)
			}
		}
		c.Channels = append(c.Channels, config.Channel{Name: name, URL: url, Kind: kind,
			IntervalHours: hours, Headers: headers, Enabled: true})
		return nil
	})
}

func (a *App) ChannelRemove(name string) error {
	found := false
	err := a.update(func(c *config.Config) error {
		var keep []config.Channel
		for _, ch := range c.Channels {
			if ch.Name == name {
				found = true
				continue
			}
			keep = append(keep, ch)
		}
		c.Channels = keep
		return nil
	})
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("no channel named %q", name)
	}
	_ = defs.Remove("ch-" + name) // its definitions go with it
	return a.load()
}

type ChannelResult struct {
	Name    string `json:"name"`
	Changed bool   `json:"changed"`
	Status  string `json:"status"`
}

// ChannelUpdate polls channels: one by name, every due one, or (force) all.
func (a *App) ChannelUpdate(name string, force bool) ([]ChannelResult, error) {
	cfg := a.Config()
	var results []ChannelResult
	updated := map[string]config.Channel{}
	for _, ch := range cfg.Channels {
		if name != "" && ch.Name != name {
			continue
		}
		if name == "" && !force && !defs.Due(ch, time.Now()) {
			continue
		}
		changed, _, _ := defs.UpdateChannel(&ch)
		updated[ch.Name] = ch
		results = append(results, ChannelResult{ch.Name, changed, ch.LastStatus})
		sev := "info"
		if strings.HasPrefix(ch.LastStatus, "error") {
			sev = "warn"
		}
		if changed || sev == "warn" {
			a.Log("definitions", sev, fmt.Sprintf("Channel %s: %s", ch.Name, ch.LastStatus), nil)
		}
	}
	if name != "" && len(results) == 0 {
		return nil, fmt.Errorf("no channel named %q", name)
	}
	if len(updated) == 0 {
		return results, nil
	}
	return results, a.update(func(c *config.Config) error {
		for i := range c.Channels {
			if u, ok := updated[c.Channels[i].Name]; ok {
				c.Channels[i] = u
			}
		}
		return nil
	})
}

// ---- AI ----

func (a *App) SetAIMode(mode string) error {
	switch mode {
	case "off", "local", "cloud", "hybrid":
	default:
		return errors.New("AI mode must be off, local, cloud or hybrid")
	}
	if (mode == "cloud" || mode == "hybrid") && !a.HasCloudKey() {
		return fmt.Errorf("no %s API key yet: run `visionary ai cloud set-key` first", a.ActiveCloudProvider())
	}
	return a.update(func(c *config.Config) error { c.AI.Mode = mode; return nil })
}

func (a *App) ollama() *ai.Ollama {
	c := a.Config().AI.Local
	ep := strings.TrimRight(c.Endpoint, "/")
	if ep == "" || c.Provider == "llama-server" {
		ep = "http://127.0.0.1:11434"
	}
	return &ai.Ollama{Endpoint: ep, ModelName: c.Model, Cfg: c}
}

func (a *App) LocalModels(ctx context.Context) ([]ai.LocalModel, error) { return a.ollama().List(ctx) }

// UseLocalModel selects an Ollama model after verifying its real parameter
// count against the limit.
func (a *App) UseLocalModel(ctx context.Context, model string) (float64, error) {
	o := a.ollama()
	params, err := o.ParamsB(ctx, model)
	if err != nil {
		return 0, fmt.Errorf("cannot inspect %s (is it pulled? `visionary ai local pull %s`): %w", model, model, err)
	}
	if err := ai.CheckParams(params, a.Config().AI.Local.MaxParamsB, model); err != nil {
		return params, err
	}
	return params, a.update(func(c *config.Config) error {
		c.AI.Local.Provider, c.AI.Local.Model, c.AI.Local.Endpoint = "ollama", model, o.Endpoint
		if c.AI.Mode == "off" {
			c.AI.Mode = "local"
		} else if c.AI.Mode == "cloud" {
			c.AI.Mode = "hybrid"
		}
		return nil
	})
}

func (a *App) PullLocalModel(ctx context.Context, model string, progress func(string)) (float64, error) {
	if err := a.ollama().Pull(ctx, model, progress); err != nil {
		return 0, err
	}
	return a.UseLocalModel(ctx, model)
}

func (a *App) LoadLocalModel(ctx context.Context, load bool) error {
	c := a.Config().AI.Local
	if c.Provider == "llama-server" {
		t := a.Triage()
		if !load {
			if t != nil {
				t.UnloadLocal()
			}
			return nil
		}
		if t != nil {
			if ls, ok := t.Local.(*ai.LlamaServer); ok {
				return ls.Ensure(ctx)
			}
		}
		ls, ok := ai.NewLocal(c).(*ai.LlamaServer)
		if !ok {
			return errors.New("llama-server is not configured")
		}
		return ls.Ensure(ctx)
	}
	if c.Model == "" {
		return errors.New("no local model selected")
	}
	return a.ollama().Load(ctx, c.Model, load)
}

// UseGGUF points the local provider at a GGUF file served by llama.cpp's
// server, after counting the file's parameters.
func (a *App) UseGGUF(path, serverPath string) (float64, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return 0, err
	}
	n, err := ai.GGUFParams(abs)
	if err != nil {
		return 0, err
	}
	params := float64(n) / 1e9
	if err := ai.CheckParams(params, a.Config().AI.Local.MaxParamsB, filepath.Base(abs)); err != nil {
		return params, err
	}
	return params, a.update(func(c *config.Config) error {
		c.AI.Local.Provider, c.AI.Local.ModelPath = "llama-server", abs
		c.AI.Local.Model = strings.TrimSuffix(filepath.Base(abs), ".gguf")
		c.AI.Local.Endpoint = "http://127.0.0.1:8089"
		if serverPath != "" {
			c.AI.Local.ServerPath = serverPath
		}
		if c.AI.Mode == "off" {
			c.AI.Mode = "local"
		} else if c.AI.Mode == "cloud" {
			c.AI.Mode = "hybrid"
		}
		return nil
	})
}

// SetSecret stores or clears an API key ("gemini", "anthropic", "openai",
// "virustotal", "otx", or "huggingface").
func (a *App) SetSecret(name, value string) error {
	value = strings.TrimSpace(value)
	if err := secure.SetSecret(name, value); err != nil {
		return err
	}
	return a.update(func(c *config.Config) error {
		switch name {
		case "virustotal":
			c.Reputation.VirusTotal = value != ""
			if value != "" {
				if c.Reputation.Provider == "" || c.Reputation.Provider == "circl" {
					c.Reputation.Provider = "virustotal"
				} else if c.Reputation.Provider == "otx" && c.Reputation.OTX {
					c.Reputation.Provider = "both"
				}
			}
		case "otx":
			c.Reputation.OTX = value != ""
			if value != "" {
				if c.Reputation.Provider == "" || c.Reputation.Provider == "circl" {
					c.Reputation.Provider = "otx"
				} else if c.Reputation.Provider == "virustotal" && c.Reputation.VirusTotal {
					c.Reputation.Provider = "both"
				}
			}
		case "gemini", "anthropic", "openai":
			prov := name
			if prov == "anthropic" {
				prov = "claude"
			}
			if value == "" {
				if strings.EqualFold(c.AI.Cloud.Provider, prov) || (c.AI.Cloud.Provider == "" && prov == "claude") {
					if c.AI.Mode == "cloud" {
						c.AI.Mode = "off"
					} else if c.AI.Mode == "hybrid" {
						c.AI.Mode = "local"
					}
				}
			} else {
				if c.AI.Cloud.Provider != prov {
					c.AI.Cloud.Provider = prov
					c.AI.Cloud.Model = ai.DefaultCloudModel(prov)
				}
				if c.AI.Mode == "off" {
					c.AI.Mode = "cloud"
				} else if c.AI.Mode == "local" {
					c.AI.Mode = "hybrid"
				}
			}
		}
		return nil
	})
}

// SyncOTXFeed downloads a compact bulk list of SHA-256 threat indicators from
// AlienVault OTX (/api/v1/indicators/export?types=FileHash-SHA256) and merges
// them into the local definitions database so matching files are detected
// offline with zero per-file API calls.
func (a *App) SyncOTXFeed(ctx context.Context) (int, error) {
	key := secure.Secret("otx")
	if key == "" {
		return 0, errors.New("no AlienVault OTX API key stored yet")
	}
	otxListPath := config.Path("defs", "otx-subscribed.hsb")
	existing := map[string]string{}
	if prev, err := os.ReadFile(otxListPath); err == nil {
		for _, line := range strings.Split(string(prev), "\n") {
			line = strings.TrimSpace(line)
			if parts := strings.SplitN(line, ":", 3); len(parts) == 3 && len(parts[0]) == 64 {
				existing[strings.ToLower(parts[0])] = parts[2]
			}
		}
	}
	var since time.Time
	if len(existing) > 0 {
		if raw := strings.TrimSpace(a.Config().Reputation.OTXLastSync); raw != "" {
			if t, err := time.Parse(time.RFC3339, raw); err == nil {
				since = t
			}
		}
	}
	otx := reputation.NewOTX(key)
	items, err := otx.ExportSHA256(ctx, since, 5)
	if err != nil {
		return 0, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if len(items) == 0 {
		_ = a.update(func(c *config.Config) error {
			c.Reputation.OTXLastSync = now
			return nil
		})
		return 0, nil
	}
	for _, it := range items {
		existing[it.SHA256] = it.Label
	}
	var b strings.Builder
	for h, lbl := range existing {
		b.WriteString(h)
		b.WriteString(":0:")
		b.WriteString(lbl)
		b.WriteByte('\n')
	}
	if err := config.WriteAtomic(otxListPath, []byte(b.String()), 0o644); err != nil {
		return 0, err
	}
	src, err := defs.Import(otxListPath, "otx-subscribed", "hashes", "otx.alienvault.com/api/v1/indicators/export", "otx")
	if err != nil {
		return 0, err
	}
	a.Log("definitions", "info", fmt.Sprintf("Synced %d new (%d total) SHA-256 indicators from AlienVault OTX bulk feed", len(items), src.Count), nil)
	if err := a.update(func(c *config.Config) error {
		c.Reputation.OTXLastSync = now
		return nil
	}); err != nil {
		return len(items), err
	}
	return len(items), nil
}

// HashScanItem is one file result from a hash-only Download or Batch Folder scan.
type HashScanItem struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size"`
	Verdict   string `json:"verdict"` // malicious | suspicious | clean | unknown | skipped
	Malicious int    `json:"malicious"`
	Total     int    `json:"total"`
	Label     string `json:"label,omitempty"`
	Detail    string `json:"detail,omitempty"`
	Cached    bool   `json:"cached,omitempty"`
}

// HashScanReport summarizes a Download or Batch Folder hash-only Threat Exchange scan.
type HashScanReport struct {
	Target      string         `json:"target"`
	Provider    string         `json:"provider"`
	Files       int            `json:"files"`
	UniqueHash  int            `json:"unique_hashes"`
	CacheHits   int            `json:"cache_hits"`
	LiveQueries int            `json:"live_queries"`
	Malicious   int            `json:"malicious"`
	Suspicious  int            `json:"suspicious"`
	Clean       int            `json:"clean"`
	Unknown     int            `json:"unknown"`
	Truncated   bool           `json:"truncated,omitempty"`
	RateLimited bool           `json:"rate_limited,omitempty"`
	Items       []HashScanItem `json:"items"`
}

var hashBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 32<<10)
		return &b
	},
}

func sha256File(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	bufp := hashBufPool.Get().(*[]byte)
	n, err := io.CopyBuffer(h, io.LimitReader(f, 256<<20), *bufp)
	hashBufPool.Put(bufp)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// DefaultDownloadsDir returns the current user's Downloads folder.
func DefaultDownloadsDir() string {
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, "Downloads")
	}
	return ""
}

// BatchHashScan hashes one file or recursively walks a folder (defaulting to
// Downloads when target is empty), checks the persistent disk cache first so
// previously checked files cost zero API calls, and queries the active Threat
// Exchange provider (VirusTotal, AlienVault OTX, or Both) using SHA-256 only.
// Files are never uploaded.
func (a *App) BatchHashScan(ctx context.Context, target string, maxFiles int) (*HashScanReport, error) {
	defer debug.FreeOSMemory()
	target = strings.TrimSpace(target)
	if target == "" {
		target = DefaultDownloadsDir()
	}
	if target == "" {
		return nil, errors.New("enter a file or folder path to hash-scan")
	}
	abs, err := filepath.Abs(target)
	if err != nil {
		return nil, err
	}
	st, err := os.Stat(abs)
	if err != nil {
		return nil, err
	}
	if maxFiles <= 0 {
		maxFiles = 50
	}
	if maxFiles > 500 {
		maxFiles = 500
	}

	repCache := a.reputationCache()
	provName := a.ActiveReputationProvider()
	var repList []reputation.Provider
	if provName == "circl" {
		repList = append(repList, reputation.NewCIRCLWithCache(repCache))
	}
	if provName == "otx" || provName == "both" {
		if key := secure.Secret("otx"); key != "" {
			repList = append(repList, reputation.NewOTXWithCache(key, repCache))
		}
	}
	if provName == "virustotal" || provName == "both" {
		if key := secure.Secret("virustotal"); key != "" {
			repList = append(repList, reputation.NewVirusTotalWithCache(key, repCache))
		}
	}
	if len(repList) == 0 {
		return nil, errors.New("no Threat Exchange API key configured yet (switch to free keyless 'circl' or add a VirusTotal / AlienVault OTX key)")
	}
	var provider reputation.Provider
	if len(repList) == 1 {
		provider = repList[0]
	} else {
		provider = reputation.NewMulti(repList...)
	}

	type fileRef struct {
		path   string
		sha256 string
		size   int64
	}
	var files []fileRef
	truncated := false
	addFile := func(p string) {
		if len(files) >= maxFiles {
			truncated = true
			return
		}
		h, sz, err := sha256File(p)
		if err != nil || sz == 0 {
			return
		}
		files = append(files, fileRef{path: p, sha256: h, size: sz})
	}

	if !st.IsDir() {
		addFile(abs)
	} else {
		_ = filepath.WalkDir(abs, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if len(files) >= maxFiles {
				truncated = true
				return filepath.SkipAll
			}
			addFile(p)
			return nil
		})
	}

	rep := &HashScanReport{
		Target:    abs,
		Provider:  provider.ProviderName(),
		Files:     len(files),
		Truncated: truncated,
	}
	if len(files) == 0 {
		return rep, nil
	}

	// Deduplicate SHA-256 hashes and detect cache hits before making live calls.
	unique := make([]string, 0, len(files))
	seen := map[string]bool{}
	wasCached := map[string]bool{}
	for _, f := range files {
		if seen[f.sha256] {
			continue
		}
		seen[f.sha256] = true
		unique = append(unique, f.sha256)
		if _, ok := repCache.Get("circl", f.sha256); ok && provName == "circl" {
			wasCached[f.sha256] = true
		} else if _, ok := repCache.Get("otx", f.sha256); ok && (provName == "otx" || provName == "both") {
			wasCached[f.sha256] = true
		} else if _, ok := repCache.Get("virustotal", f.sha256); ok && (provName == "virustotal" || provName == "both") {
			wasCached[f.sha256] = true
		}
	}
	rep.UniqueHash = len(unique)
	repCache.BeginBatch()
	results := provider.LookupBatch(ctx, unique)
	repCache.EndBatch()

	for h, r := range results {
		if wasCached[h] {
			rep.CacheHits++
		} else {
			rep.LiveQueries++
		}
		if r.Err != nil && strings.Contains(r.Err.Error(), "rate limit") {
			rep.RateLimited = true
		}
	}

	for _, f := range files {
		r, ok := results[f.sha256]
		item := HashScanItem{
			Path:   f.path,
			SHA256: f.sha256,
			Size:   f.size,
			Cached: wasCached[f.sha256],
		}
		switch {
		case !ok || r.Err != nil:
			item.Verdict = "skipped"
			if r.Err != nil {
				item.Detail = r.Err.Error()
			} else {
				item.Detail = "skipped (rate limit or cancelled)"
			}
		case !r.Found:
			item.Verdict = "unknown"
			item.Detail = "hash not seen on " + provider.ProviderName()
			rep.Unknown++
		case r.Malicious >= 5:
			item.Verdict = "malicious"
			item.Malicious, item.Total, item.Label, item.Detail = r.Malicious, r.Total, r.Label, r.Detail
			rep.Malicious++
		case r.Malicious > 0:
			item.Verdict = "suspicious"
			item.Malicious, item.Total, item.Label, item.Detail = r.Malicious, r.Total, r.Label, r.Detail
			rep.Suspicious++
		default:
			item.Verdict = "clean"
			item.Total, item.Detail = r.Total, r.Detail
			rep.Clean++
		}
		rep.Items = append(rep.Items, item)
	}
	a.Log("scan", map[bool]string{true: "high", false: "info"}[rep.Malicious > 0],
		fmt.Sprintf("batch hash scan (%s): %d files (%d unique, %d cached, %d live), %d malicious, %d suspicious",
			rep.Provider, rep.Files, rep.UniqueHash, rep.CacheHits, rep.LiveQueries, rep.Malicious, rep.Suspicious), nil)
	return rep, nil
}

// QuarantinePath moves a suspicious or malicious file into the encoded vault.
func (a *App) QuarantinePath(ctx context.Context, path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	res := a.Engine().ScanFile(ctx, abs, engine.Options{NoCache: true})
	if res.Verdict == engine.Failed {
		return "", errors.New(res.Error)
	}
	if res.Threat == "" {
		res.Threat = "Manual.Quarantine"
	}
	id, err := engine.Quarantine(abs, res)
	if err != nil {
		return "", err
	}
	a.Log("system", "warn", fmt.Sprintf("Quarantined %s as %s", abs, id), nil)
	return id, nil
}

type AITest struct {
	Provider string            `json:"provider"`
	Model    string            `json:"model"`
	OK       bool              `json:"ok"`
	Verdict  *engine.AIVerdict `json:"verdict,omitempty"`
	Error    string            `json:"error,omitempty"`
	Seconds  float64           `json:"seconds"`
}

// TestAI sends a small, obviously suspicious report to each configured
// provider so a broken setup is found now and not during an incident.
func (a *App) TestAI(ctx context.Context) []AITest {
	rep := &engine.Report{FileName: "invoice.pdf.exe", Location: "downloads folder", Size: 48128,
		SHA256: strings.Repeat("0", 64), Score: 65,
		Findings: []engine.Finding{
			{Layer: "heuristic", Name: "double-extension", Score: 35, Detail: "looks like .pdf but runs as .exe"},
			{Layer: "heuristic", Name: "capability:process-injection", Score: 30,
				Detail: "allocates and writes memory in another process, then starts a thread there"}},
		Features: engine.Features{Type: "pe", Entropy: 7.4}}
	t := a.Triage()
	var out []AITest
	for _, p := range []ai.Provider{t.Local, t.Cloud} {
		if p == nil {
			continue
		}
		start := time.Now()
		single := &ai.Triage{Local: p}
		v, err := single.Assess(ctx, rep)
		r := AITest{Provider: p.Name(), Model: p.Model(), OK: err == nil, Verdict: v,
			Seconds: float64(time.Since(start).Milliseconds()) / 1000}
		if err != nil {
			r.Error = err.Error()
		}
		out = append(out, r)
	}
	return out
}

// Explain scans one file and asks the AI layer to explain the result.
func (a *App) Explain(ctx context.Context, path string) (*engine.Result, string, string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, "", "", err
	}
	eng := a.Engine()
	res := eng.ScanFile(ctx, abs, engine.Options{NoCache: true, Describe: true})
	if res.Verdict == engine.Failed {
		return res, "", "", errors.New(res.Error)
	}
	text, model, err := a.Triage().Explain(ctx, eng.BuildReport(abs, res))
	return res, text, model, err
}

// ---- behaviour ----

func (a *App) LearnStart(days int) error {
	if days <= 0 {
		days = a.Config().Behavior.LearnDays
	}
	if days <= 0 || days > 60 {
		days = 3
	}
	until := time.Now().Add(time.Duration(days) * 24 * time.Hour)
	if err := a.update(func(c *config.Config) error {
		c.Behavior.Enabled, c.Behavior.LearningUntil, c.Behavior.LearnDays = true, until, days
		return nil
	}); err != nil {
		return err
	}
	a.Log("system", "info", fmt.Sprintf("Behaviour learning started for %d days", days), nil)
	return nil
}

func (a *App) LearnStop() error {
	return a.update(func(c *config.Config) error { c.Behavior.LearningUntil = time.Time{}; return nil })
}

func (a *App) BehaviorReset() error { return behavior.Reset() }

// ---- Windows Security ----

func (a *App) WindowsStatus() *winsec.Status { return winsec.GetStatus() }

// Coexist sets Visionary up next to Defender: Defender skips Visionary's
// data (the quarantine vault), and Visionary asks Defender for second
// opinions.
func (a *App) Coexist() error {
	dirs := []string{config.Dir()}
	if err := winsec.Coexist(dirs...); err != nil {
		return err
	}
	a.Log("system", "info", "Added Visionary's data folder to Microsoft Defender exclusions", nil)
	return a.update(func(c *config.Config) error { c.Windows.DefenderSecondOpinion = true; return nil })
}

func (a *App) DefenderPassive(on bool) (string, error) {
	msg, err := winsec.SetPassive(on)
	if err == nil {
		a.Log("system", "warn", "Defender passive-mode policy: "+msg, nil)
	}
	return msg, err
}

func (a *App) DefenderOfflineScan() error {
	if err := winsec.OfflineScan(); err != nil {
		return err
	}
	a.Log("system", "info", "Microsoft Defender Offline scan requested; Windows will restart", nil)
	return nil
}

// ---- model store: Hugging Face downloads and bring-your-own GGUF ----

// ModelDir is where downloaded and imported GGUF models live.
func ModelDir() string { return filepath.Join(config.Dir(), "models") }

func (a *App) StoredModels() ([]ai.StoredModel, error) { return ai.ListStore(ModelDir()) }

// HFSearch finds GGUF repositories on Hugging Face.
func (a *App) HFSearch(ctx context.Context, query string) ([]ai.HFModel, error) {
	return ai.HFSearch(ctx, secure.Secret("huggingface"), query, 15)
}

// HFFiles lists the GGUF files (and quantisations) of a repository.
func (a *App) HFFiles(ctx context.Context, repo string) ([]ai.HFFile, error) {
	return ai.HFFiles(ctx, secure.Secret("huggingface"), repo)
}

// HFGet downloads a model into the store and, unless use is false, selects it.
// ref is owner/repo, owner/repo:QUANT, owner/repo/file.gguf or a huggingface.co link.
func (a *App) HFGet(ctx context.Context, ref, quant string, use bool, progress func(done, total int64)) (ai.StoredModel, error) {
	r, err := ai.ParseHFRef(ref)
	if err != nil {
		return ai.StoredModel{}, err
	}
	if quant != "" {
		r.File = quant
	}
	m, err := ai.HFDownload(ctx, ai.HFDownloadOptions{
		Repo: r.Repo, File: r.File, Token: secure.Secret("huggingface"), Dir: ModelDir(),
		MaxParamsB: a.Config().AI.Local.MaxParamsB, Progress: progress})
	if err != nil {
		return m, err
	}
	if use {
		_, err = a.UseGGUF(m.Path, "")
	}
	return m, err
}

// ImportModel brings the user's own GGUF into the store.
func (a *App) ImportModel(path string, use bool) (ai.StoredModel, error) {
	m, err := ai.ImportGGUF(path, ModelDir(), a.Config().AI.Local.MaxParamsB)
	if err != nil {
		return m, err
	}
	if use {
		_, err = a.UseGGUF(m.Path, "")
	}
	return m, err
}

// UseStoredModel selects a model from the store.
func (a *App) UseStoredModel(name string) (ai.StoredModel, error) {
	m, err := ai.FindStored(ModelDir(), name)
	if err != nil {
		return m, err
	}
	_, err = a.UseGGUF(m.Path, "")
	return m, err
}

// RemoveStoredModel deletes a stored model; if it is the one in use the local
// provider is cleared.
func (a *App) RemoveStoredModel(name string) error {
	m, err := ai.FindStored(ModelDir(), name)
	if err != nil {
		return err
	}
	if err := ai.RemoveStored(ModelDir(), name); err != nil {
		return err
	}
	return a.update(func(c *config.Config) error {
		if c.AI.Local.ModelPath == m.Path {
			c.AI.Local.ModelPath, c.AI.Local.Model = "", ""
			if c.AI.Mode == "local" {
				c.AI.Mode = "off"
			} else if c.AI.Mode == "hybrid" {
				c.AI.Mode = "cloud"
			}
		}
		return nil
	})
}

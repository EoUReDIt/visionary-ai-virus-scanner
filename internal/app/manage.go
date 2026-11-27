package app

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/ai"
	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/behavior"
	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/config"
	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/defs"
	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/engine"
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
// "virustotal", or "huggingface").
func (a *App) SetSecret(name, value string) error {
	value = strings.TrimSpace(value)
	if err := secure.SetSecret(name, value); err != nil {
		return err
	}
	return a.update(func(c *config.Config) error {
		switch name {
		case "virustotal":
			c.Reputation.VirusTotal = value != ""
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

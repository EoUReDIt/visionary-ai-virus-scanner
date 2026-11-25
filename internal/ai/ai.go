// Package ai is the reasoning layer. A small local model (under 3B
// parameters) triages gray-zone files on the machine; an optional cloud model
// is consulted when the local one is unsure. Models only ever see a feature
// report produced by the engine, never the file itself.
package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/config"
	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/engine"
)

// Provider is one model endpoint.
type Provider interface {
	Name() string
	Model() string
	Complete(ctx context.Context, system, user string, wantJSON bool) (string, error)
}

const triageSystem = `You are a malware triage analyst inside an antivirus engine for Windows PCs used by developers and gamers.
You receive a JSON report describing one file: where it lives, static features, and what the engine's signature and heuristic layers found. You never see the file itself.

Judge whether the file is malicious. Weigh the evidence the way an experienced analyst would:
- Developer tools, compilers, debuggers, game launchers, anti-cheat, DRM-protected and packed game binaries, mod loaders and installers legitimately use process memory APIs, packers, hooks and downloads. Those alone are not malice.
- Malice shows in combinations and intent: hidden execution plus a remote payload, credential or token theft plus exfiltration, tampering with security tools, destroying backups, disguised file names, persistence for something that hides.
- A file's location matters (a "pdf.exe" in Downloads is not the same as a signed binary in Program Files).
- If the evidence is thin or ambiguous, say "suspicious" or "unknown" with low confidence instead of guessing.

Answer with one JSON object and nothing else:
{"verdict": "malicious" | "suspicious" | "benign" | "unknown", "confidence": <number 0..1>, "reasons": ["short reason", ...]}
Give at most four reasons, each under 20 words, each grounded in the report.`

const explainSystem = `You explain antivirus scan results to the person who owns the computer: a developer or gamer, technical but not a malware analyst.
You receive a JSON report describing one file and what the scanner's layers found. You never see the file itself.
Write a short plain-language explanation: what the file appears to be, what each notable finding means in practice, how worried they should be, and what to do next (delete, keep, upload the hash to VirusTotal, restore from quarantine). Be direct about uncertainty. Do not invent details that are not in the report. Keep it under 200 words, no headings.`

// ParseVerdict tolerates the ways small models wrap JSON (code fences,
// preamble, trailing chatter).
func ParseVerdict(raw string) (*engine.AIVerdict, error) {
	start := strings.IndexByte(raw, '{')
	end := strings.LastIndexByte(raw, '}')
	if start < 0 || end <= start {
		return nil, fmt.Errorf("model did not return JSON: %.80q", raw)
	}
	var v struct {
		Verdict    string          `json:"verdict"`
		Confidence json.RawMessage `json:"confidence"`
		Reasons    json.RawMessage `json:"reasons"`
	}
	if err := json.Unmarshal([]byte(raw[start:end+1]), &v); err != nil {
		return nil, fmt.Errorf("model returned malformed JSON: %w", err)
	}
	out := &engine.AIVerdict{Verdict: strings.ToLower(strings.TrimSpace(v.Verdict))}
	switch out.Verdict {
	case "malicious", "suspicious", "benign", "unknown":
	case "clean", "safe", "legitimate":
		out.Verdict = "benign"
	default:
		return nil, fmt.Errorf("model returned an unknown verdict %q", v.Verdict)
	}
	var conf float64
	if json.Unmarshal(v.Confidence, &conf) != nil {
		var s string
		if json.Unmarshal(v.Confidence, &s) == nil {
			fmt.Sscanf(strings.TrimSuffix(s, "%"), "%g", &conf)
		}
	}
	if conf > 1 {
		conf /= 100 // "85" meaning 85%
	}
	out.Confidence = max(0, min(1, conf))
	if json.Unmarshal(v.Reasons, &out.Reasons) != nil {
		var s string
		if json.Unmarshal(v.Reasons, &s) == nil && s != "" {
			out.Reasons = []string{s}
		}
	}
	if len(out.Reasons) > 4 {
		out.Reasons = out.Reasons[:4]
	}
	return out, nil
}

// Triage routes a report through the configured providers.
type Triage struct {
	Mode  string
	Local Provider
	Cloud Provider
	// ShareSnippets controls whether script excerpts leave the machine.
	ShareSnippets bool
}

// NewTriage builds providers from config. A missing piece (no API key, no
// model) simply leaves that provider nil; Assess reports it when asked.
func NewTriage(cfg *config.Config, anthropicKey string) *Triage {
	t := &Triage{Mode: cfg.AI.Mode, ShareSnippets: cfg.AI.Cloud.ShareSnippets}
	if (t.Mode == "local" || t.Mode == "hybrid") && cfg.AI.Local.Model != "" {
		t.Local = NewLocal(cfg.AI.Local)
	}
	if (t.Mode == "cloud" || t.Mode == "hybrid") && anthropicKey != "" {
		t.Cloud = NewClaude(anthropicKey, cfg.AI.Cloud.Model, cfg.AI.Cloud.Effort)
	}
	return t
}

func (t *Triage) Enabled() bool { return t != nil && (t.Local != nil || t.Cloud != nil) }

func marshalReport(rep *engine.Report, withSnippet bool) string {
	cp := *rep
	if !withSnippet {
		cp.Features.Snippet = ""
	}
	b, _ := json.MarshalIndent(cp, "", " ")
	return string(b)
}

func ask(ctx context.Context, p Provider, report string) (*engine.AIVerdict, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	raw, err := p.Complete(ctx, triageSystem, "File report:\n"+report, true)
	if err != nil {
		return nil, err
	}
	v, err := ParseVerdict(raw)
	if err != nil {
		return nil, err
	}
	v.Provider, v.Model = p.Name(), p.Model()
	return v, nil
}

// Assess is the hybrid policy: the local model answers first and for free;
// the cloud model is asked only when the local one is missing, failed, or
// not confident. Its answer then replaces the local one.
func (t *Triage) Assess(ctx context.Context, rep *engine.Report) (*engine.AIVerdict, error) {
	if !t.Enabled() {
		return nil, errors.New("no AI provider is configured")
	}
	var local *engine.AIVerdict
	var localErr error
	if t.Local != nil {
		local, localErr = ask(ctx, t.Local, marshalReport(rep, true))
		if localErr == nil && (local.Confidence >= 0.8 && local.Verdict != "unknown" || t.Cloud == nil) {
			return local, nil
		}
	}
	if t.Cloud != nil {
		cloud, err := ask(ctx, t.Cloud, marshalReport(rep, t.ShareSnippets))
		if err == nil {
			return cloud, nil
		}
		if local != nil {
			return local, nil
		}
		return nil, err
	}
	return nil, localErr
}

// Explain produces a plain-language explanation of a scan result, preferring
// the cloud model when one is available.
func (t *Triage) Explain(ctx context.Context, rep *engine.Report) (text, model string, err error) {
	if !t.Enabled() {
		return "", "", errors.New("no AI provider is configured (see: visionary ai mode)")
	}
	p, snippet := t.Cloud, t.ShareSnippets
	if p == nil {
		p, snippet = t.Local, true
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	text, err = p.Complete(ctx, explainSystem, "Scan report:\n"+marshalReport(rep, snippet), false)
	return strings.TrimSpace(text), p.Model(), err
}

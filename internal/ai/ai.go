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

const triageSystem = `You are a malware triage analyst inside Visionary, a Windows antivirus engine built for developers and gamers.
You receive a JSON report describing one file (and optional runtime process lineage/command-line context): where it lives, static features, and what the signature, heuristic, and behaviour layers found. You never see the file itself.

Judge whether the file or execution is malicious. Weigh evidence like a senior threat analyst:
- Developer tools, compilers, debuggers, game launchers, anti-cheat, DRM-protected/packed game binaries, mod loaders, and installers legitimately use process memory APIs, packers, hooks, and downloads. Those alone are not malice.
- Malice shows in combinations and intent: hidden execution plus a remote payload, credential/token theft plus exfiltration, disabling security tools, destroying shadow copies/backups, disguised filenames, or persistence for hidden payloads.
- Living-off-the-land (LOLBin) attacks execute trusted Windows binaries (powershell, mshta, cmd, rundll32, wscript) with suspicious parents (Office, browsers, chat apps) or obfuscated command lines. Weigh the runtime process context heavily when present.
- File location matters (a "pdf.exe" in Downloads or Temp is very different from a signed binary in Program Files).
- If evidence is thin or ambiguous, return "suspicious" or "unknown" with low confidence instead of guessing.

Answer with one JSON object and nothing else:
{
  "verdict": "malicious" | "suspicious" | "benign" | "unknown",
  "confidence": <number 0..1>,
  "category": "trojan" | "ransomware" | "infostealer" | "dropper" | "lolbin" | "pup" | "dual-use-tool" | "benign" | "unknown",
  "recommended_action": "quarantine" | "review" | "monitor" | "allow",
  "summary": "<one concise plain-English sentence under 25 words>",
  "reasons": ["short grounded reason", ...]
}
Give at most four reasons, each under 20 words, each strictly grounded in the report.`

const explainSystem = `You explain antivirus scan results to the person who owns the computer: a developer or gamer, technical but not a malware analyst.
You receive a JSON report describing one file (and optional process context) and what Visionary's detection layers found. You never see the file itself.
Write a clear, plain-language briefing covering: what the file appears to be, what each notable finding means in practice, how worried they should be, and the concrete next step (quarantine/delete, keep and allowlist, check hash on VirusTotal, or monitor). Be direct about uncertainty. Do not invent details that are not in the report. Keep it under 220 words, concise paragraphs, no markdown headers.`

// ParseVerdict tolerates the ways small models wrap JSON (code fences,
// preamble, trailing chatter) and parses optional rich fields.
func ParseVerdict(raw string) (*engine.AIVerdict, error) {
	start := strings.IndexByte(raw, '{')
	end := strings.LastIndexByte(raw, '}')
	if start < 0 || end <= start {
		return nil, fmt.Errorf("model did not return JSON: %.80q", raw)
	}
	var v struct {
		Verdict           string          `json:"verdict"`
		Confidence        json.RawMessage `json:"confidence"`
		Category          string          `json:"category"`
		RecommendedAction string          `json:"recommended_action"`
		Summary           string          `json:"summary"`
		Reasons           json.RawMessage `json:"reasons"`
	}
	if err := json.Unmarshal([]byte(raw[start:end+1]), &v); err != nil {
		return nil, fmt.Errorf("model returned malformed JSON: %w", err)
	}
	out := &engine.AIVerdict{
		Verdict:           strings.ToLower(strings.TrimSpace(v.Verdict)),
		Category:          strings.ToLower(strings.TrimSpace(v.Category)),
		RecommendedAction: strings.ToLower(strings.TrimSpace(v.RecommendedAction)),
		Summary:           strings.TrimSpace(v.Summary),
	}
	switch out.Verdict {
	case "malicious", "suspicious", "benign", "unknown":
	case "clean", "safe", "legitimate":
		out.Verdict = "benign"
	default:
		return nil, fmt.Errorf("model returned an unknown verdict %q", v.Verdict)
	}
	switch out.RecommendedAction {
	case "quarantine", "review", "monitor", "allow":
	default:
		out.RecommendedAction = ""
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
	// Threshold is the confidence level at which the local model settles
	// without escalating to the cloud (default 0.80).
	Threshold float64
}

// NewTriage builds providers from config using an Anthropic key (kept for
// backward compatibility with callers and tests).
func NewTriage(cfg *config.Config, anthropicKey string) *Triage {
	return NewTriageWithSecrets(cfg, map[string]string{"anthropic": anthropicKey})
}

// NewTriageWithSecrets builds local and cloud providers from config and a map
// of stored secrets ("gemini", "anthropic", "openai").
func NewTriageWithSecrets(cfg *config.Config, secrets map[string]string) *Triage {
	thr := cfg.AI.ConfidenceThreshold
	if thr < 0.5 || thr > 0.99 {
		thr = 0.80
	}
	t := &Triage{
		Mode:          cfg.AI.Mode,
		ShareSnippets: cfg.AI.Cloud.ShareSnippets,
		Threshold:     thr,
	}
	if (t.Mode == "local" || t.Mode == "hybrid") && cfg.AI.Local.Model != "" {
		t.Local = NewLocal(cfg.AI.Local)
	}
	if t.Mode == "cloud" || t.Mode == "hybrid" {
		prov := strings.ToLower(strings.TrimSpace(cfg.AI.Cloud.Provider))
		if prov == "" {
			// Preserve backward compatibility for configs created before multi-provider support.
			if secrets["anthropic"] != "" {
				prov = "claude"
			} else if secrets["gemini"] != "" {
				prov = "gemini"
			} else if secrets["openai"] != "" {
				prov = "openai"
			} else {
				prov = "gemini"
			}
		}
		switch prov {
		case "gemini":
			if k := secrets["gemini"]; k != "" {
				t.Cloud = NewGemini(k, cfg.AI.Cloud.Model, cfg.AI.Cloud.Endpoint)
			}
		case "openai":
			if k := secrets["openai"]; k != "" {
				t.Cloud = NewOpenAICompat(k, cfg.AI.Cloud.Model, cfg.AI.Cloud.Endpoint)
			}
		case "claude":
			if k := secrets["anthropic"]; k != "" {
				t.Cloud = NewClaude(k, cfg.AI.Cloud.Model, cfg.AI.Cloud.Effort)
			}
		}
	}
	return t
}

func (t *Triage) Enabled() bool { return t != nil && (t.Local != nil || t.Cloud != nil) }

func (t *Triage) threshold() float64 {
	if t.Threshold >= 0.5 && t.Threshold <= 0.99 {
		return t.Threshold
	}
	return 0.80
}

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
	thr := t.threshold()
	var local *engine.AIVerdict
	var localErr error
	if t.Local != nil {
		local, localErr = ask(ctx, t.Local, marshalReport(rep, true))
		if localErr == nil && (local.Confidence >= thr && local.Verdict != "unknown" || t.Cloud == nil) {
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

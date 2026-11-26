package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// CloudProviderInfo describes a supported cloud AI backend and its defaults.
type CloudProviderInfo struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	SecretName   string   `json:"secret_name"`
	DefaultModel string   `json:"default_model"`
	Models       []string `json:"models"`
	DocsHint     string   `json:"docs_hint"`
}

// CloudProviders lists the built-in cloud providers Visionary supports.
var CloudProviders = []CloudProviderInfo{
	{
		ID:           "gemini",
		Name:         "Google Gemini",
		SecretName:   "gemini",
		DefaultModel: "gemini-2.5-flash",
		Models:       []string{"gemini-2.5-flash", "gemini-2.5-pro", "gemini-2.5-flash-lite"},
		DocsHint:     "Fast structured JSON triage via Google AI Studio API key",
	},
	{
		ID:           "claude",
		Name:         "Anthropic Claude",
		SecretName:   "anthropic",
		DefaultModel: "claude-sonnet-4-5",
		Models:       []string{"claude-sonnet-4-5", "claude-opus-4-5", "claude-haiku-4-5"},
		DocsHint:     "Deep malware reasoning via Anthropic API key",
	},
	{
		ID:           "openai",
		Name:         "OpenAI / Compatible",
		SecretName:   "openai",
		DefaultModel: "gpt-4.1-mini",
		Models:       []string{"gpt-4.1-mini", "gpt-4.1", "o4-mini"},
		DocsHint:     "Works with OpenAI, OpenRouter, Groq or any /v1/chat/completions endpoint",
	},
}

// CloudSecretName returns the secure secret key name for a cloud provider ID.
func CloudSecretName(provider string) string {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "gemini":
		return "gemini"
	case "openai":
		return "openai"
	default:
		return "anthropic"
	}
}

// DefaultCloudModel returns the recommended default model for a cloud provider.
func DefaultCloudModel(provider string) string {
	for _, p := range CloudProviders {
		if p.ID == strings.ToLower(strings.TrimSpace(provider)) {
			return p.DefaultModel
		}
	}
	return "gemini-2.5-flash"
}

// ---- Google Gemini REST provider (zero external SDK dependency) ----

type Gemini struct {
	apiKey   string
	model    string
	endpoint string
}

func NewGemini(apiKey, model, endpoint string) *Gemini {
	if strings.TrimSpace(model) == "" {
		model = "gemini-2.5-flash"
	}
	ep := strings.TrimRight(strings.TrimSpace(endpoint), "/")
	if ep == "" {
		ep = "https://generativelanguage.googleapis.com"
	}
	return &Gemini{apiKey: apiKey, model: model, endpoint: ep}
}

func (g *Gemini) Name() string  { return "gemini" }
func (g *Gemini) Model() string { return g.model }

func (g *Gemini) Complete(ctx context.Context, system, user string, wantJSON bool) (string, error) {
	genCfg := map[string]any{
		"temperature":     0.1,
		"maxOutputTokens": 2048,
	}
	if wantJSON {
		genCfg["responseMimeType"] = "application/json"
	}
	payload := map[string]any{
		"systemInstruction": map[string]any{
			"parts": []map[string]string{{"text": system}},
		},
		"contents": []map[string]any{
			{
				"role":  "user",
				"parts": []map[string]string{{"text": user}},
			},
		},
		"generationConfig": genCfg,
	}
	b, _ := json.Marshal(payload)
	url := fmt.Sprintf("%s/v1beta/models/%s:generateContent", g.endpoint, g.model)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-goog-api-key", g.apiKey)
	resp, err := httpc.Do(req)
	if err != nil {
		return "", fmt.Errorf("gemini: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			return "", errors.New("gemini: the API key was rejected (visionary ai cloud set-key)")
		case http.StatusNotFound:
			return "", fmt.Errorf("gemini: model %q is not available to this key", g.model)
		case http.StatusTooManyRequests:
			return "", errors.New("gemini: rate limited, try again shortly")
		default:
			return "", fmt.Errorf("gemini: API error %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
		}
	}
	var out struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
			FinishReason string `json:"finishReason"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", fmt.Errorf("gemini: invalid response JSON: %w", err)
	}
	if len(out.Candidates) == 0 {
		return "", errors.New("gemini: empty response (no candidates)")
	}
	var sb strings.Builder
	for _, part := range out.Candidates[0].Content.Parts {
		sb.WriteString(part.Text)
	}
	if sb.Len() == 0 {
		return "", fmt.Errorf("gemini: empty content (finishReason=%s)", out.Candidates[0].FinishReason)
	}
	return sb.String(), nil
}

// ---- OpenAI / OpenAI-compatible Chat Completions provider ----

type OpenAICompat struct {
	apiKey   string
	model    string
	endpoint string
}

func NewOpenAICompat(apiKey, model, endpoint string) *OpenAICompat {
	if strings.TrimSpace(model) == "" {
		model = "gpt-4.1-mini"
	}
	ep := strings.TrimRight(strings.TrimSpace(endpoint), "/")
	if ep == "" {
		ep = "https://api.openai.com/v1"
	}
	return &OpenAICompat{apiKey: apiKey, model: model, endpoint: ep}
}

func (o *OpenAICompat) Name() string  { return "openai" }
func (o *OpenAICompat) Model() string { return o.model }

func (o *OpenAICompat) Complete(ctx context.Context, system, user string, wantJSON bool) (string, error) {
	payload := map[string]any{
		"model":       o.model,
		"temperature": 0.1,
		"messages": []map[string]string{
			{"role": "system", "content": system},
			{"role": "user", "content": user},
		},
	}
	if wantJSON {
		payload["response_format"] = map[string]string{"type": "json_object"}
	}
	b, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.endpoint+"/chat/completions", bytes.NewReader(b))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+o.apiKey)
	resp, err := httpc.Do(req)
	if err != nil {
		return "", fmt.Errorf("openai: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			return "", errors.New("openai: the API key was rejected (visionary ai cloud set-key)")
		case http.StatusNotFound:
			return "", fmt.Errorf("openai: model %q is not available", o.model)
		case http.StatusTooManyRequests:
			return "", errors.New("openai: rate limited, try again shortly")
		default:
			return "", fmt.Errorf("openai: API error %d", resp.StatusCode)
		}
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", fmt.Errorf("openai: invalid response JSON: %w", err)
	}
	if len(out.Choices) == 0 || strings.TrimSpace(out.Choices[0].Message.Content) == "" {
		return "", errors.New("openai: empty response")
	}
	return out.Choices[0].Message.Content, nil
}

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

const (
	defaultAnthropicEndpoint = "https://api.anthropic.com"
	anthropicAPIVersion      = "2023-06-01"
	anthropicFallbackBeta    = "server-side-fallback-2026-07-01"
)

// Claude is the Anthropic Messages API cloud provider, reached with the user's
// own API key over the standard-library HTTP client (zero external SDK deps).
type Claude struct {
	apiKey   string
	model    string
	effort   string
	endpoint string
}

func NewClaude(apiKey, model, effort string) *Claude {
	if strings.TrimSpace(model) == "" {
		model = DefaultCloudModel("claude")
	}
	return &Claude{
		apiKey:   apiKey,
		model:    model,
		effort:   strings.TrimSpace(effort),
		endpoint: defaultAnthropicEndpoint,
	}
}

func (c *Claude) Name() string  { return "claude" }
func (c *Claude) Model() string { return c.model }

func (c *Claude) baseURL() string {
	ep := strings.TrimRight(strings.TrimSpace(c.endpoint), "/")
	if ep == "" {
		return defaultAnthropicEndpoint
	}
	return ep
}

func (c *Claude) Complete(ctx context.Context, system, user string, _ bool) (string, error) {
	payload := map[string]any{
		"model":      c.model,
		"max_tokens": 8000,
		"system":     system,
		"messages": []map[string]string{
			{"role": "user", "content": user},
		},
	}
	if c.effort != "" {
		payload["output_config"] = map[string]string{"effort": c.effort}
	}
	// Malware triage is security content, which a model's safety classifier
	// can decline. Server-side fallbacks re-serve a declined request on
	// another model inside the same call. Haiku has no server-side fallback.
	useFallback := !strings.Contains(strings.ToLower(c.model), "haiku")
	if useFallback {
		payload["fallbacks"] = map[string]string{"type": "default"}
	}

	b, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("claude: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL()+"/v1/messages", bytes.NewReader(b))
	if err != nil {
		return "", fmt.Errorf("claude: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.apiKey)
	req.Header.Set("anthropic-version", anthropicAPIVersion)
	if useFallback {
		req.Header.Set("anthropic-beta", anthropicFallbackBeta)
	}

	resp, err := httpc.Do(req)
	if err != nil {
		return "", fmt.Errorf("claude: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			return "", errors.New("claude: the API key was rejected (visionary ai cloud set-key)")
		case http.StatusNotFound:
			return "", fmt.Errorf("claude: model %q is not available to this key", c.model)
		case http.StatusTooManyRequests:
			return "", errors.New("claude: rate limited, try again shortly")
		default:
			return "", fmt.Errorf("claude: API error %d", resp.StatusCode)
		}
	}

	var out struct {
		StopReason string `json:"stop_reason"`
		Content    []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", fmt.Errorf("claude: invalid response JSON: %w", err)
	}
	if out.StopReason == "refusal" {
		return "", errors.New("claude: the request was declined by the model's safety system")
	}
	var sb strings.Builder
	for _, block := range out.Content {
		if block.Type == "text" {
			sb.WriteString(block.Text)
		}
	}
	if sb.Len() == 0 {
		return "", errors.New("claude: empty response")
	}
	return sb.String(), nil
}

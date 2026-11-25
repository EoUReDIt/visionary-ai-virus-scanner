package ai

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/anthropics/anthropic-sdk-go/v2"
	"github.com/anthropics/anthropic-sdk-go/v2/option"
)

// Claude is the cloud provider, reached with the user's own API key.
type Claude struct {
	client anthropic.Client
	model  string
	effort string
}

func NewClaude(apiKey, model, effort string) *Claude {
	if model == "" {
		model = "claude-opus-5-5"
	}
	return &Claude{client: anthropic.NewClient(option.WithAPIKey(apiKey)), model: model, effort: effort}
}

func (c *Claude) Name() string  { return "claude" }
func (c *Claude) Model() string { return c.model }

func (c *Claude) Complete(ctx context.Context, system, user string, _ bool) (string, error) {
	params := anthropic.BetaMessageNewParams{
		Model:     c.model,
		MaxTokens: 8000,
		System:    []anthropic.BetaTextBlockParam{{Text: system}},
		Messages: []anthropic.BetaMessageParam{
			anthropic.NewBetaUserMessage(anthropic.NewBetaTextBlock(user)),
		},
	}
	if c.effort != "" {
		params.OutputConfig = anthropic.BetaOutputConfigParam{Effort: anthropic.BetaOutputConfigEffort(c.effort)}
	}
	// Malware triage is security content, which a model's safety classifier
	// can decline. Server-side fallbacks re-serve a declined request on
	// another model inside the same call. Haiku has no server-side fallback.
	if !strings.Contains(c.model, "haiku") {
		params.Betas = []anthropic.AnthropicBeta{anthropic.AnthropicBetaServerSideFallback2026_07_01}
		params.Fallbacks = anthropic.BetaFallbacksParamOfDefault()
	}
	resp, err := c.client.Beta.Messages.New(ctx, params)
	if err != nil {
		var apiErr *anthropic.Error
		if errors.As(err, &apiErr) {
			switch apiErr.StatusCode {
			case 401, 403:
				return "", errors.New("claude: the API key was rejected (visionary ai cloud set-key)")
			case 404:
				return "", fmt.Errorf("claude: model %q is not available to this key", c.model)
			case 429:
				return "", errors.New("claude: rate limited, try again shortly")
			default:
				return "", fmt.Errorf("claude: API error %d", apiErr.StatusCode)
			}
		}
		return "", fmt.Errorf("claude: %w", err)
	}
	if resp.StopReason == anthropic.BetaStopReasonRefusal {
		return "", errors.New("claude: the request was declined by the model's safety system")
	}
	var sb strings.Builder
	for _, block := range resp.Content {
		if t, ok := block.AsAny().(anthropic.BetaTextBlock); ok {
			sb.WriteString(t.Text)
		}
	}
	if sb.Len() == 0 {
		return "", errors.New("claude: empty response")
	}
	return sb.String(), nil
}

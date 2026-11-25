package ai

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/config"
)

// Recommended models stay under the 3B ceiling and run on a laptop CPU or a
// few GB of VRAM alongside a game.
var Recommended = []struct {
	Model, Params, About string
}{
	{"qwen3:1.7b", "1.7B", "default: reliable JSON answers for its size"},
	{"qwen2.5-coder:1.5b", "1.5B", "strongest on scripts and source code"},
	{"gemma3:1b", "1.0B", "fastest; fine for script triage on old hardware"},
	{"llama3.2:1b", "1.2B", "small and widely tested"},
	{"smollm2:1.7b", "1.7B", "permissive licence, light on RAM"},
	{"gemma2:2b", "2.6B", "largest that still fits under the limit"},
}

var httpc = &http.Client{Timeout: 5 * time.Minute}

func postJSON(ctx context.Context, url string, body, out any) error {
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(raw)))
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}

// NewLocal returns the provider for the configured local runtime.
func NewLocal(c config.LocalAI) Provider {
	ep := strings.TrimRight(c.Endpoint, "/")
	if c.Provider == "llama-server" {
		if ep == "" || strings.HasSuffix(ep, ":11434") {
			ep = "http://127.0.0.1:8089"
		}
		return &LlamaServer{Endpoint: ep, Cfg: c}
	}
	if ep == "" {
		ep = "http://127.0.0.1:11434"
	}
	return &Ollama{Endpoint: ep, ModelName: c.Model}
}

// ---- Ollama ----

type Ollama struct {
	Endpoint  string
	ModelName string
}

func (o *Ollama) Name() string  { return "ollama" }
func (o *Ollama) Model() string { return o.ModelName }

func (o *Ollama) Complete(ctx context.Context, system, user string, wantJSON bool) (string, error) {
	body := map[string]any{
		"model":  o.ModelName,
		"stream": false,
		"think":  false,
		"messages": []map[string]string{
			{"role": "system", "content": system},
			{"role": "user", "content": user},
		},
		"options":    map[string]any{"temperature": 0, "num_ctx": 8192},
		"keep_alive": "15m",
	}
	if wantJSON {
		body["format"] = "json"
	}
	var out struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	}
	err := postJSON(ctx, o.Endpoint+"/api/chat", body, &out)
	if err != nil && strings.Contains(err.Error(), "think") {
		// Older Ollama builds and non-reasoning models reject the flag.
		delete(body, "think")
		err = postJSON(ctx, o.Endpoint+"/api/chat", body, &out)
	}
	if err != nil {
		return "", fmt.Errorf("ollama: %w", err)
	}
	return out.Message.Content, nil
}

type LocalModel struct {
	Name    string  `json:"name"`
	Params  string  `json:"params"`
	ParamsB float64 `json:"params_b"`
	SizeMB  int64   `json:"size_mb"`
	Loaded  bool    `json:"loaded"`
}

// List returns installed models and which are loaded in memory.
func (o *Ollama) List(ctx context.Context) ([]LocalModel, error) {
	var tags struct {
		Models []struct {
			Name    string `json:"name"`
			Size    int64  `json:"size"`
			Details struct {
				ParameterSize string `json:"parameter_size"`
			} `json:"details"`
		} `json:"models"`
	}
	if err := getJSON(ctx, o.Endpoint+"/api/tags", &tags); err != nil {
		return nil, fmt.Errorf("ollama is not reachable at %s: %w", o.Endpoint, err)
	}
	var ps struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	_ = getJSON(ctx, o.Endpoint+"/api/ps", &ps)
	loaded := map[string]bool{}
	for _, m := range ps.Models {
		loaded[m.Name] = true
	}
	var out []LocalModel
	for _, m := range tags.Models {
		out = append(out, LocalModel{Name: m.Name, Params: m.Details.ParameterSize,
			ParamsB: ParseParamSize(m.Details.ParameterSize), SizeMB: m.Size >> 20, Loaded: loaded[m.Name]})
	}
	return out, nil
}

func getJSON(ctx context.Context, url string, out any) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := httpc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New(resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// ParseParamSize turns "1.7B" / "494.03M" into billions.
func ParseParamSize(s string) float64 {
	s = strings.ToUpper(strings.TrimSpace(s))
	if s == "" {
		return 0
	}
	mult := 1.0
	switch s[len(s)-1] {
	case 'B':
		s = s[:len(s)-1]
	case 'M':
		mult, s = 1e-3, s[:len(s)-1]
	case 'K':
		mult, s = 1e-6, s[:len(s)-1]
	}
	f, _ := strconv.ParseFloat(s, 64)
	return f * mult
}

// ParamsB asks Ollama how many parameters a model has (in billions).
func (o *Ollama) ParamsB(ctx context.Context, model string) (float64, error) {
	var show struct {
		Details struct {
			ParameterSize string `json:"parameter_size"`
		} `json:"details"`
		ModelInfo map[string]any `json:"model_info"`
	}
	if err := postJSON(ctx, o.Endpoint+"/api/show", map[string]any{"model": model}, &show); err != nil {
		return 0, err
	}
	if n, ok := show.ModelInfo["general.parameter_count"].(float64); ok && n > 0 {
		return n / 1e9, nil
	}
	if b := ParseParamSize(show.Details.ParameterSize); b > 0 {
		return b, nil
	}
	return 0, errors.New("the runtime did not report a parameter count")
}

// Pull downloads a model, reporting progress lines.
func (o *Ollama) Pull(ctx context.Context, model string, progress func(string)) error {
	b, _ := json.Marshal(map[string]any{"model": model, "stream": true})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, o.Endpoint+"/api/pull", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return fmt.Errorf("ollama is not reachable at %s: %w", o.Endpoint, err)
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	last := ""
	for sc.Scan() {
		var ev struct {
			Status    string `json:"status"`
			Error     string `json:"error"`
			Total     int64  `json:"total"`
			Completed int64  `json:"completed"`
		}
		if json.Unmarshal(sc.Bytes(), &ev) != nil {
			continue
		}
		if ev.Error != "" {
			return errors.New(ev.Error)
		}
		line := ev.Status
		if ev.Total > 0 {
			line = fmt.Sprintf("%s %d%%", ev.Status, ev.Completed*100/ev.Total)
		}
		if line != last && progress != nil {
			progress(line)
			last = line
		}
	}
	return sc.Err()
}

// Load keeps a model in memory (or unloads it) so the first triage is fast.
func (o *Ollama) Load(ctx context.Context, model string, load bool) error {
	keep := any("30m")
	if !load {
		keep = 0
	}
	return postJSON(ctx, o.Endpoint+"/api/generate", map[string]any{"model": model, "keep_alive": keep}, nil)
}

// ---- llama.cpp server (GGUF files) ----

// LlamaServer talks to llama.cpp's OpenAI-compatible server, starting it on
// demand when a server binary and a GGUF path are configured.
type LlamaServer struct {
	Endpoint string
	Cfg      config.LocalAI
	cmd      *exec.Cmd
}

func (l *LlamaServer) Name() string { return "llama-server" }
func (l *LlamaServer) Model() string {
	if l.Cfg.Model != "" {
		return l.Cfg.Model
	}
	return l.Cfg.ModelPath
}

func (l *LlamaServer) healthy(ctx context.Context) bool {
	var v map[string]any
	return getJSON(ctx, l.Endpoint+"/health", &v) == nil
}

// Ensure starts the server if it is not already answering.
func (l *LlamaServer) Ensure(ctx context.Context) error {
	if l.healthy(ctx) {
		return nil
	}
	if l.Cfg.ServerPath == "" || l.Cfg.ModelPath == "" {
		return fmt.Errorf("llama-server is not running at %s and no server_path/model_path is configured", l.Endpoint)
	}
	if err := CheckGGUF(l.Cfg.ModelPath, l.Cfg.MaxParamsB); err != nil {
		return err
	}
	port := l.Endpoint[strings.LastIndexByte(l.Endpoint, ':')+1:]
	l.cmd = exec.Command(l.Cfg.ServerPath, "-m", l.Cfg.ModelPath, "--host", "127.0.0.1", "--port", port, "-c", "8192")
	if err := l.cmd.Start(); err != nil {
		return fmt.Errorf("starting llama-server: %w", err)
	}
	for i := 0; i < 120; i++ {
		if l.healthy(ctx) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return errors.New("llama-server did not become ready within two minutes")
}

func (l *LlamaServer) Stop() {
	if l.cmd != nil && l.cmd.Process != nil {
		_ = l.cmd.Process.Kill()
	}
}

func (l *LlamaServer) Complete(ctx context.Context, system, user string, wantJSON bool) (string, error) {
	if err := l.Ensure(ctx); err != nil {
		return "", err
	}
	body := map[string]any{
		"model":       l.Model(),
		"temperature": 0,
		"messages": []map[string]string{
			{"role": "system", "content": system},
			{"role": "user", "content": user},
		},
	}
	if wantJSON {
		body["response_format"] = map[string]string{"type": "json_object"}
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := postJSON(ctx, l.Endpoint+"/v1/chat/completions", body, &out); err != nil {
		return "", fmt.Errorf("llama-server: %w", err)
	}
	if len(out.Choices) == 0 {
		return "", errors.New("llama-server returned no choices")
	}
	return out.Choices[0].Message.Content, nil
}

// ---- GGUF inspection ----

// GGUFParams counts a GGUF model's parameters by summing its tensor shapes,
// so the size limit is enforced on what the file is, not on what it is named.
func GGUFParams(path string) (uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 1<<20)
	le := binary.LittleEndian
	u32 := func() (uint32, error) { var v uint32; err := binary.Read(r, le, &v); return v, err }
	u64 := func() (uint64, error) { var v uint64; err := binary.Read(r, le, &v); return v, err }
	skip := func(n uint64) error { _, err := io.CopyN(io.Discard, r, int64(n)); return err }
	str := func() (string, error) {
		n, err := u64()
		if err != nil || n > 1<<20 {
			return "", errors.New("corrupt GGUF string")
		}
		b := make([]byte, n)
		_, err = io.ReadFull(r, b)
		return string(b), err
	}
	magic := make([]byte, 4)
	if _, err := io.ReadFull(r, magic); err != nil || string(magic) != "GGUF" {
		return 0, errors.New("not a GGUF model file")
	}
	if _, err := u32(); err != nil { // version
		return 0, err
	}
	tensors, err := u64()
	if err != nil {
		return 0, err
	}
	kvs, err := u64()
	if err != nil || tensors > 1<<20 || kvs > 1<<20 {
		return 0, errors.New("corrupt GGUF header")
	}
	sizes := map[uint32]uint64{0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1, 10: 8, 11: 8, 12: 8}
	var skipValue func(t uint32) error
	skipValue = func(t uint32) error {
		switch t {
		case 8:
			n, err := u64()
			if err != nil {
				return err
			}
			return skip(n)
		case 9:
			et, err := u32()
			if err != nil {
				return err
			}
			n, err := u64()
			if err != nil {
				return err
			}
			if sz, ok := sizes[et]; ok {
				return skip(sz * n)
			}
			for i := uint64(0); i < n; i++ {
				if err := skipValue(et); err != nil {
					return err
				}
			}
			return nil
		}
		sz, ok := sizes[t]
		if !ok {
			return fmt.Errorf("unknown GGUF value type %d", t)
		}
		return skip(sz)
	}
	var declared uint64
	for i := uint64(0); i < kvs; i++ {
		key, err := str()
		if err != nil {
			return 0, err
		}
		t, err := u32()
		if err != nil {
			return 0, err
		}
		if key == "general.parameter_count" && (t == 10 || t == 4) {
			if t == 10 {
				declared, err = u64()
			} else {
				var v uint32
				v, err = u32()
				declared = uint64(v)
			}
			if err != nil {
				return 0, err
			}
			continue
		}
		if err := skipValue(t); err != nil {
			return 0, err
		}
	}
	var total uint64
	for i := uint64(0); i < tensors; i++ {
		if _, err := str(); err != nil {
			return 0, err
		}
		dims, err := u32()
		if err != nil || dims > 8 {
			return 0, errors.New("corrupt GGUF tensor info")
		}
		n := uint64(1)
		for d := uint32(0); d < dims; d++ {
			v, err := u64()
			if err != nil {
				return 0, err
			}
			n *= v
		}
		if err := skip(12); err != nil { // type + offset
			return 0, err
		}
		total += n
	}
	if total == 0 {
		total = declared
	}
	return total, nil
}

// CheckGGUF enforces the parameter ceiling on a GGUF file.
func CheckGGUF(path string, maxB float64) error {
	n, err := GGUFParams(path)
	if err != nil {
		return err
	}
	return CheckParams(float64(n)/1e9, maxB, path)
}

// CheckParams is the single place the "under 3B" rule lives.
func CheckParams(paramsB, maxB float64, model string) error {
	if maxB <= 0 {
		maxB = 3.0
	}
	if paramsB > maxB {
		return fmt.Errorf("%s has %.2fB parameters, over the %.1fB local-model limit (ai.local.max_params_b)", model, paramsB, maxB)
	}
	return nil
}

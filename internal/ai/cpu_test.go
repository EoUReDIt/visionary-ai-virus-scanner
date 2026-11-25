package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/config"
)

func TestOllamaCPUOnlyRequest(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"message":{"content":"{}"}}`))
	}))
	defer srv.Close()
	o := NewLocal(config.LocalAI{Provider: "ollama", Endpoint: srv.URL, Model: "m", CPUOnly: true, Threads: 3, KeepAlive: "2m"})
	if _, err := o.Complete(context.Background(), "s", "u", true); err != nil {
		t.Fatal(err)
	}
	opts := got["options"].(map[string]any)
	if opts["num_gpu"] != float64(0) || opts["num_thread"] != float64(3) || got["keep_alive"] != "2m" {
		t.Fatalf("cpu-only options not applied: %v / %v", opts, got["keep_alive"])
	}
	// Default (GPU allowed) sends no num_gpu override.
	got = nil
	o = NewLocal(config.LocalAI{Provider: "ollama", Endpoint: srv.URL, Model: "m"})
	_, _ = o.Complete(context.Background(), "s", "u", true)
	if _, has := got["options"].(map[string]any)["num_gpu"]; has || got["keep_alive"] != "15m" {
		t.Fatalf("default request changed: %v", got)
	}
}

func TestLlamaServerCPUOnlyArgs(t *testing.T) {
	l := &LlamaServer{Cfg: config.LocalAI{ModelPath: "m.gguf", CPUOnly: true, Threads: 2}}
	a := strings.Join(l.args("8089"), " ")
	for _, want := range []string{"-ngl 0", "-t 2", "-c 4096", "-m m.gguf"} {
		if !strings.Contains(a, want) {
			t.Errorf("args %q missing %q", a, want)
		}
	}
	if full := strings.Join((&LlamaServer{Cfg: config.LocalAI{ModelPath: "m.gguf"}}).args("8089"), " "); strings.Contains(full, "-ngl") {
		t.Errorf("default args force CPU: %s", full)
	}
	if cpuThreads(0) < 1 {
		t.Error("thread budget below one")
	}
}

func TestRecommendedFor(t *testing.T) {
	for _, m := range RecommendedFor(2.0) {
		if ParseParamSize(m.Params) > 2.0 {
			t.Errorf("%s exceeds the ceiling", m.Model)
		}
	}
	if len(RecommendedFor(2.0)) == 0 || len(RecommendedFor(2.0)) >= len(Recommended) {
		t.Errorf("filter ineffective: %d of %d", len(RecommendedFor(2.0)), len(Recommended))
	}
}

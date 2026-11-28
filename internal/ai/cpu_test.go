package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
	// Immediate unload ("0s" / "0") sends numeric 0 so Ollama evicts right away.
	got = nil
	o = NewLocal(config.LocalAI{Provider: "ollama", Endpoint: srv.URL, Model: "m", KeepAlive: "0s"})
	if _, err := o.Complete(context.Background(), "s", "u", true); err != nil {
		t.Fatal(err)
	}
	if got["keep_alive"] != float64(0) {
		t.Fatalf("expected numeric 0 keep_alive for immediate unload, got %#v", got["keep_alive"])
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
	if d := (&LlamaServer{Cfg: config.LocalAI{KeepAlive: "0s"}}).idleDuration(); d != 0 {
		t.Errorf("expected 0 idle duration for 0s, got %v", d)
	}
	if d := (&LlamaServer{Cfg: config.LocalAI{CPUOnly: true}}).idleDuration(); d != 2*time.Minute {
		t.Errorf("expected 2m default idle duration in CPU-only mode, got %v", d)
	}
	if d := (&LlamaServer{Cfg: config.LocalAI{}}).idleDuration(); d != 15*time.Minute {
		t.Errorf("expected 15m default idle duration, got %v", d)
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

func TestGPUPolicyOptions(t *testing.T) {
	mk := func(c config.LocalAI, force func() bool) *Ollama {
		return &Ollama{Cfg: c, ForceCPU: force}
	}
	// off: pinned to the CPU, same as cpu_only.
	if o := mk(config.LocalAI{GPU: "off"}, nil).options(); o["num_gpu"] != 0 {
		t.Errorf("off must send num_gpu=0: %v", o)
	}
	// auto: no override.
	if o := mk(config.LocalAI{GPU: "auto", GPULayers: 20}, nil).options(); o["num_gpu"] != nil {
		t.Errorf("auto must not override: %v", o)
	}
	// on without layers: runtime decides. on with layers: partial offload.
	if o := mk(config.LocalAI{GPU: "on"}, nil).options(); o["num_gpu"] != nil {
		t.Errorf("on without layers must not override: %v", o)
	}
	if o := mk(config.LocalAI{GPU: "on", GPULayers: 18}, nil).options(); o["num_gpu"] != 18 {
		t.Errorf("on+layers must offload 18: %v", o)
	}
	// game mode forces the CPU even when the GPU is on.
	if o := mk(config.LocalAI{GPU: "on", GPULayers: 18}, func() bool { return true }).options(); o["num_gpu"] != 0 {
		t.Errorf("game mode must force CPU: %v", o)
	}
	// legacy cpu_only still means off.
	if o := mk(config.LocalAI{CPUOnly: true}, nil).options(); o["num_gpu"] != 0 {
		t.Errorf("cpu_only alias lost: %v", o)
	}
}

func TestLlamaServerGPUArgs(t *testing.T) {
	join := func(c config.LocalAI, f func() bool) string {
		c.ModelPath = "m.gguf"
		return strings.Join((&LlamaServer{Cfg: c, ForceCPU: f}).args("8089"), " ")
	}
	if a := join(config.LocalAI{GPU: "on", GPULayers: 12}, nil); !strings.Contains(a, "-ngl 12") || strings.Contains(a, "-ngl 0") {
		t.Errorf("on+layers: %s", a)
	}
	if a := join(config.LocalAI{GPU: "auto"}, nil); strings.Contains(a, "-ngl") {
		t.Errorf("auto must leave -ngl to the runtime: %s", a)
	}
	if a := join(config.LocalAI{GPU: "off"}, nil); !strings.Contains(a, "-ngl 0") {
		t.Errorf("off: %s", a)
	}
	if a := join(config.LocalAI{GPU: "on", GPULayers: 12}, func() bool { return true }); !strings.Contains(a, "-ngl 0") {
		t.Errorf("game mode must force -ngl 0: %s", a)
	}
}

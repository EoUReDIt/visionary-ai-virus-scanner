package gpu

import (
	"context"
	"errors"
	"testing"
)

func fake(m map[string]string) Runner {
	return func(_ context.Context, name string, _ ...string) (string, error) {
		if out, ok := m[name]; ok {
			return out, nil
		}
		return "", errors.New("not found")
	}
}

func TestProbeNvidia(t *testing.T) {
	gs := Probe(context.Background(), fake(map[string]string{"nvidia-smi": "NVIDIA GeForce GTX 1650, 4096\nNVIDIA T400, 2048\n"}))
	if len(gs) != 2 || gs[0].Name != "NVIDIA GeForce GTX 1650" || gs[0].VRAMMB != 4096 || gs[0].AtLeast {
		t.Fatalf("got %+v", gs)
	}
}

func TestProbeWin32FourGBIsAtLeast(t *testing.T) {
	out := "Microsoft Basic Render Driver|0\r\nAMD Radeon RX 6600|4293918720\r\nIntel(R) UHD Graphics|1073741824\r\n"
	gs := Probe(context.Background(), fake(map[string]string{"powershell.exe": out}))
	if len(gs) != 2 || gs[0].Name != "AMD Radeon RX 6600" || !gs[0].AtLeast || gs[1].AtLeast || gs[1].VRAMMB != 1024 {
		t.Fatalf("got %+v", gs)
	}
}

func TestProbeNone(t *testing.T) {
	if gs := Probe(context.Background(), fake(nil)); len(gs) != 0 {
		t.Fatalf("expected none, got %+v", gs)
	}
}

func TestSuggestLayers(t *testing.T) {
	model := EstimateModelMB(1) // ~920 MB
	if n := SuggestLayers(4096, 0, model, 26); n != 26 {
		t.Errorf("model fits 4 GB: want all 26 layers, got %d", n)
	}
	if n := SuggestLayers(1024, 0, model, 26); n <= 0 || n >= 26 {
		t.Errorf("1 GB card should partially offload, got %d", n)
	}
	if n := SuggestLayers(8192, 400, model, 26); n >= 26 || n <= 0 {
		t.Errorf("a 400 MB cap must limit offload, got %d", n)
	}
	if SuggestLayers(0, 0, model, 26) != 0 {
		t.Error("unknown VRAM must not suggest offload")
	}
}

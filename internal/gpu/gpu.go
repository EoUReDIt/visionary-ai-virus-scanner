// Package gpu finds the machine's GPU without any native dependency, so Lite
// can offer partial offload to a budget card while linking nothing. It asks
// nvidia-smi when present, then PowerShell's Win32_VideoController.
package gpu

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Runner runs a command and returns its stdout. Tests inject a fake.
type Runner func(ctx context.Context, name string, args ...string) (string, error)

// ExecRunner is the real runner.
func ExecRunner(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	return string(out), err
}

// Info describes one adapter.
type Info struct {
	Name   string `json:"name"`
	VRAMMB int    `json:"vram_mb"`
	// AtLeast is true when VRAMMB is only a lower bound: Win32 AdapterRAM is a
	// 32-bit field and reads 4 GB for any larger card.
	AtLeast bool   `json:"at_least,omitempty"`
	Source  string `json:"source"` // nvidia-smi | win32
}

// Probe returns the adapters found, best first (most VRAM). An empty result
// with a nil error means no GPU could be identified.
func Probe(ctx context.Context, run Runner) []Info {
	if run == nil {
		run = ExecRunner
	}
	if out, err := run(ctx, "nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader,nounits"); err == nil {
		if gs := parseNvidia(out); len(gs) > 0 {
			return gs
		}
	}
	out, err := run(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		"Get-CimInstance Win32_VideoController | ForEach-Object { $_.Name + '|' + $_.AdapterRAM }")
	if err != nil {
		return nil
	}
	return parseWin32(out)
}

func parseNvidia(out string) []Info {
	var gs []Info
	for _, ln := range strings.Split(out, "\n") {
		i := strings.LastIndex(ln, ",")
		if i < 0 {
			continue
		}
		mb, err := strconv.Atoi(strings.TrimSpace(ln[i+1:]))
		name := strings.TrimSpace(ln[:i])
		if err != nil || name == "" {
			continue
		}
		gs = append(gs, Info{Name: name, VRAMMB: mb, Source: "nvidia-smi"})
	}
	return sortBest(gs)
}

func parseWin32(out string) []Info {
	var gs []Info
	for _, ln := range strings.Split(out, "\n") {
		ln = strings.TrimSpace(ln)
		i := strings.LastIndex(ln, "|")
		if i < 0 {
			continue
		}
		name := strings.TrimSpace(ln[:i])
		if name == "" || strings.Contains(strings.ToLower(name), "basic render") ||
			strings.Contains(strings.ToLower(name), "remote display") {
			continue
		}
		b, err := strconv.ParseInt(strings.TrimSpace(ln[i+1:]), 10, 64)
		if err != nil {
			b = 0
		}
		mb := int(b >> 20)
		// AdapterRAM saturates near 4 GB: report "at least", never guess higher.
		gs = append(gs, Info{Name: name, VRAMMB: mb, AtLeast: mb >= 4000, Source: "win32"})
	}
	return sortBest(gs)
}

func sortBest(gs []Info) []Info {
	for i := 1; i < len(gs); i++ {
		for j := i; j > 0 && gs[j].VRAMMB > gs[j-1].VRAMMB; j-- {
			gs[j], gs[j-1] = gs[j-1], gs[j]
		}
	}
	return gs
}

// EstimateModelMB is a rough footprint for a 4-bit quantised model of
// paramsB billion parameters, including the small context Lite uses.
func EstimateModelMB(paramsB float64) int {
	if paramsB <= 0 {
		paramsB = 1
	}
	return int(paramsB*620) + 300
}

// SuggestLayers returns how many layers to offload so the model fits the VRAM
// budget with headroom: 70% of vram, or capMB when that is lower and set.
// totalLayers <= 0 assumes 32, a typical small model. It returns 0 when
// nothing useful fits and totalLayers when the whole model does.
func SuggestLayers(vramMB, capMB, modelMB, totalLayers int) int {
	if totalLayers <= 0 {
		totalLayers = 32
	}
	if vramMB <= 0 || modelMB <= 0 {
		return 0
	}
	budget := vramMB * 70 / 100
	if capMB > 0 && capMB < budget {
		budget = capMB
	}
	if budget >= modelMB {
		return totalLayers
	}
	return totalLayers * budget / modelMB
}

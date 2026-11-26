package app

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/behavior"
	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/config"
	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/engine"
	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/plat"
)

const (
	defaultSettle  = 700 * time.Millisecond // wait for a file to stop changing
	defaultWorkers = 2
	defaultPoll    = 1500 * time.Millisecond // process monitor interval
)

func msOr(ms int, def time.Duration) time.Duration {
	if ms > 0 {
		return time.Duration(ms) * time.Millisecond
	}
	return def
}

// RunGuard is real-time protection. It runs until ctx is cancelled and is
// the same loop whether started from a terminal (`visionary guard`), by the
// Windows service, or inside the dashboard process.
//
// Three sensors feed one engine:
//   - a file watcher: anything written to a watched folder is scanned once
//     it settles, and quarantined if malicious
//   - a process monitor: every newly started program has its image scanned
//     (scan-on-execute) and its start scored by the behaviour model
//   - a file-change rate meter: bursts are reported as possible ransomware
//
// It also keeps definition channels fresh and honours disable/enable and
// game mode decided anywhere else, by re-reading shared settings.
func (a *App) RunGuard(ctx context.Context, verbose func(string)) error {
	say := func(format string, args ...any) {
		if verbose != nil {
			verbose(fmt.Sprintf(format, args...))
		}
	}
	mon := behavior.NewMonitor()
	defer mon.Save()
	defer func() { a.Engine().Flush() }()

	var (
		watcher  plat.Watcher
		watching string
		events   <-chan plat.Event
		pendMu   sync.Mutex
		pending  = map[string]time.Time{}
		burst    int
		wasOn    = true
		gaming   bool
	)
	closeWatcher := func() {
		if watcher != nil {
			watcher.Close()
			watcher, events, watching = nil, nil, ""
		}
	}
	defer closeWatcher()

	jobs := make(chan string, 512)
	var wg sync.WaitGroup
	workers := a.Config().Realtime.Workers
	if workers <= 0 {
		workers = defaultWorkers
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				a.guardScan(ctx, p, "real-time", nil, nil, say)
			}
		}()
	}
	defer func() { close(jobs); wg.Wait() }()

	a.Log("system", "info", "Real-time guard started", nil)
	say("guard started (data: %s)", config.Dir())
	defer a.Log("system", "info", "Real-time guard stopped", nil)
	defer os.Remove(heartbeat())

	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	var lastProc, lastCfg, lastSlow, lastBurst time.Time

	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-events:
			if !ok {
				closeWatcher()
				continue
			}
			cfg := a.Config()
			if config.Excluded(ev.Path, cfg.Realtime.Excludes) || config.Excluded(ev.Path, cfg.Scan.Excludes) ||
				config.Excluded(ev.Path, config.ProfileExcludes(cfg.Profile)) {
				continue
			}
			if !strings.Contains(strings.ToLower(ev.Path), "temp") && !strings.Contains(strings.ToLower(ev.Path), "appdata") {
				burst++
			}
			pendMu.Lock()
			pending[ev.Path] = ev.Time
			pendMu.Unlock()
		case now := <-tick.C:
			// Shared settings: another process may have disabled protection,
			// changed the profile or imported definitions.
			if now.Sub(lastCfg) >= 2*time.Second {
				lastCfg = now
				if a.Reload() {
					say("settings or definitions changed, reloaded")
				}
				_ = os.WriteFile(heartbeat(), []byte(now.Format(time.RFC3339)), 0o644)
				on, why := a.ProtectionActive()
				if on != wasOn {
					say("protection %s", why)
					wasOn = on
				}
				if g := a.GameMode(); g != gaming {
					gaming = g
					plat.SetBackgroundPriority(g)
					if g {
						say("game mode on: background work deferred")
					} else {
						say("game mode off")
					}
				}
				if !on {
					closeWatcher()
					pendMu.Lock()
					clear(pending)
					pendMu.Unlock()
					continue
				}
				cfg := a.Config()
				roots := cfg.Realtime.WatchPaths
				if len(roots) == 0 {
					roots = plat.DefaultWatchPaths()
				}
				sort.Strings(roots)
				if key := strings.Join(roots, "|"); key != watching || watcher == nil && watching == "" {
					closeWatcher()
					if len(roots) == 0 {
						say("no folders to watch: set realtime.watch_paths in settings")
						watching = "-"
					} else if w, err := plat.NewWatcher(roots); err == nil {
						watcher, events, watching = w, w.Events(), key
						say("watching %d folders", len(roots))
					} else {
						say("cannot watch folders: %v", err)
						watching = key // do not retry every two seconds
					}
				}
			}
			if !wasOn {
				continue
			}
			// Hand settled files to the scan workers.
			settle := msOr(a.Config().Realtime.SettleMS, defaultSettle)
			pendMu.Lock()
			for p, t := range pending {
				if now.Sub(t) >= settle {
					select {
					case jobs <- p:
						delete(pending, p)
					default: // workers are busy; try again next tick
					}
				}
			}
			pendMu.Unlock()

			cfg := a.Config()
			if cfg.Behavior.Enabled && now.Sub(lastProc) >= msOr(cfg.Behavior.PollMS, defaultPoll) {
				lastProc = now
				learning := a.Learning()
				anomalies, started := mon.Poll(learning, cfg.Behavior.Threshold)
				flagged := map[int]*behavior.Anomaly{}
				for i := range anomalies {
					an := &anomalies[i]
					flagged[an.PID] = an
					a.Log("anomaly", "warn", fmt.Sprintf("Unusual activity: %s (%s)", an.Exe, strings.Join(an.Reasons, "; ")), an)
					say("anomaly %d: %s — %s", an.Score, an.Exe, strings.Join(an.Reasons, "; "))
				}
				for _, p := range started {
					if p.Exe == "" {
						continue
					}
					var ctxFindings []engine.Finding
					var procCtx *engine.ProcessContext
					if an := flagged[p.PID]; an != nil {
						// The anomaly and runtime command line travel with the
						// file as evidence, so rules, Defender and the AI layer
						// can catch fileless LOLBin abuse even on signed tools.
						ctxFindings = []engine.Finding{{Layer: "behavior", Name: "anomalous-start",
							Score: an.Score / 2, Detail: strings.Join(an.Reasons, "; ")}}
						procCtx = &engine.ProcessContext{PID: an.PID, Parent: an.Parent, Cmdline: an.Cmdline}
					}
					go a.guardScan(ctx, p.Exe, "on-execute", ctxFindings, procCtx, say)
				}
			}
			if cfg.Behavior.Enabled && now.Sub(lastBurst) >= 10*time.Second {
				lastBurst = now
				if an := mon.ObserveFileRate(burst, a.Learning()); an != nil {
					a.Log("anomaly", "high", "Unusual activity: "+strings.Join(an.Reasons, "; "), an)
					say("anomaly: %s", strings.Join(an.Reasons, "; "))
				}
				burst = 0
			}
			if now.Sub(lastSlow) >= time.Minute {
				lastSlow = now
				mon.Save()
				a.Engine().Flush()
				if !gaming {
					if res, err := a.ChannelUpdate("", false); err == nil {
						for _, r := range res {
							say("channel %s: %s", r.Name, r.Status)
						}
					}
				}
			}
		}
	}
}

// guardScan scans one file for the guard and reports anything found.
func (a *App) guardScan(ctx context.Context, path, origin string, evidence []engine.Finding, proc *engine.ProcessContext, say func(string, ...any)) {
	cfg := a.Config()
	res := a.Engine().ScanFile(ctx, path, engine.Options{
		Escalate: true, Quarantine: cfg.Realtime.AutoQuarantine, Context: evidence, Process: proc})
	switch res.Verdict {
	case engine.Malicious, engine.Suspicious:
		a.logDetection(origin, res)
		say("%s %s: %s — %s (score %d) %s", origin, res.Verdict, path, res.Threat, res.Score, res.Action)
	}
}

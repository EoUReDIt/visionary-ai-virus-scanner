# Plan: Visionary Lite (lightweight, CPU-only edition)

Status: first implementation (this PR). Items marked *later* are not done yet.

## Goal
A build that runs well on old laptops, handhelds and low-end gaming PCs: small binary, low idle
RAM/CPU, no GPU use, no background model server. Same CLI-first rule: every Lite feature works
from the CLI before the dashboard.

## What is already CPU-only
The whole detection engine (hashes, rules, heuristics, cert blocklist, behaviour model) is
plain CPU Go code. Only the optional local-AI layer can touch a GPU (via Ollama/llama.cpp).

## What the Lite edition is (implemented)
Build: `go build -tags lite ./cmd/visionary` or `scripts/build.sh` -> `dist/visionary-lite.exe` and
`Visionary-Lite-Setup-<ver>.exe`. `visionary version|status` print `lite edition`.

1. **No dashboard**: `internal/ui` and its embedded page are not linked; `visionary ui` explains this.
   Everything is a command (the CLI-first rule).
2. **`lite` profile / defaults** (`config.ApplyLite`, also `visionary profile lite` on the full edition):
   1 scan worker, 1 real-time worker, 2 s settle delay, 3 s process poll, 32 MB file cap,
   AI budget 5, game mode auto.
3. **CPU-only local AI** (`ai.local.cpu_only`, `threads`, `keep_alive`): Ollama gets `num_gpu=0`,
   `num_thread`, a 4096 context and `keep_alive 2m` (unloads when idle); llama-server is started
   with `-ngl 0 -t N -c 4096`. Threads default to half the cores. Lite default ceiling 2B and
   default model `gemma3:1b`; `ai recommend` lists only models under the ceiling.
4. **Budget check**: `scripts/idle-budget.sh` fails CI if the idle guard exceeds 40 MB RSS or 3% CPU
   (Linux); a Windows working-set check runs on the Windows job.
5. **Installer**: `makensis -DLITE ...` builds a Lite installer (no dashboard, no UI shortcuts). Lite and
   full share one install location and uninstaller.

New tunables (also `visionary settings set`): `realtime.workers`, `realtime.settle_ms`, `behavior.poll_ms`.

## Measured so far (Linux build, empty data dir)
- Idle guard: ~16 MB resident, ~0.5% CPU (full edition ~17 MB).
- Windows binary: 14.3 MB vs 14.8 MB. The saving is small because the Anthropic SDK (cloud AI)
  dominates the size; see "Later".

## Later (not done)
- Shrink the binary: replace the cloud SDK with a minimal HTTP client in Lite, or make cloud AI optional.
- Cheaper real-time path: coalesce watcher events, longer settle on battery, persist the clean cache.
- Compact/delta definitions and a `--lite` rule subset that drops the costliest regexes.
- Verify idle numbers and the "no GPU libraries loaded" criterion on real Windows hardware.
- Measure scan throughput per commit in CI.

## Open questions
- Keep cloud AI in Lite or make it opt-in at install time?
- Minimum supported hardware (e.g. 2 cores / 4 GB RAM)?
- Ship pre-quantised model recommendations or only point to the registry?

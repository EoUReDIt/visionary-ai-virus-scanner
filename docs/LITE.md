# Plan: Visionary Lite (lightweight, CPU-only edition)

Status: proposal, not implemented. Target: a later release after v0.1.0.

## Goal
A build that runs well on old laptops, handhelds and low-end gaming PCs: small binary, low idle
RAM/CPU, no GPU use, no background model server. Same CLI-first rule: every Lite feature works
from the CLI before the dashboard.

## What is already CPU-only
The whole detection engine (hashes, rules, heuristics, cert blocklist, behaviour model) is
plain CPU Go code. Only the optional local-AI layer can touch a GPU (via Ollama/llama.cpp).

## Proposed work
1. **Build variant**: Go build tag `lite` -> `visionary-lite.exe`. Excludes the dashboard assets and
   the local-AI providers; keeps cloud AI (HTTP only, no extra cost at idle).
2. **CPU-only AI option**: when local AI is enabled, force CPU (`num_gpu=0` for Ollama,
   `-ngl 0` for llama-server), cap threads (default: cores/2), and offer only <=1.5B quantised
   models (e.g. qwen3:1.7b Q4, gemma3:1b, llama3.2:1b). Load on demand and unload after idle
   (Ollama `keep_alive`), never at boot.
3. **Resource budget** (measured, enforced in CI): idle guard < 40 MB RSS and < 1% CPU; quick scan
   throttled to one worker below a configurable CPU ceiling; reuse game mode's background priority.
4. **Cheaper real-time path**: coalesce watcher events, raise the settle delay on battery, skip
   heuristics for files under trusted signatures, extend the clean-cache across restarts.
5. **Definition size**: compact `.vdb` (delta updates over channels, optional hash truncation) and a
   `--lite` rule set that drops the costliest regex rules.
6. **Config**: `profile lite` preset plus `ai.local.cpu_only=true` and `ai.local.threads`.
7. **Installer**: separate NSIS target `Visionary-Lite-Setup`, no service-wide model downloads.

## Acceptance criteria
- `visionary status` reports `edition: lite` and CPU-only AI state.
- Benchmarks in CI: scan throughput, idle RSS and CPU recorded per commit; regressions fail.
- No GPU libraries loaded (verified by process module list on Windows).
- Existing CLI exit codes and settings stay compatible with the full edition.

## Open questions
- Keep cloud AI in Lite or make it opt-in at install time?
- Minimum supported hardware (e.g. 2 cores / 4 GB RAM)?
- Ship pre-quantised model recommendations or only point to the registry?

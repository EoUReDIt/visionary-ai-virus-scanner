# PR Proposal #02: Performance, Binary Size & Memory Optimization

- **Proposed Branch:** `perf/memory-and-runtime-optimizations`
- **Target Branch:** `main`
- **Status:** Proposal
- **Editions Affected:** Core, Lite (highest impact), Safe

---

## 1. Summary

An audit of Visionary's scanning pipeline, caches, event log, and Go dependencies identified six concrete CPU, memory, disk-I/O, and binary-size bottlenecks. Fixing them significantly lowers peak RAM during scans (especially in **Lite** edition on 4–8 GB laptops/handhelds), eliminates Windows file-write churn, and trims executable size across all three editions.

---

## 2. Measured & Audited Bottlenecks

### Optimization 1 — Eliminate Full-File Heap Allocations in `ScanFile` (Biggest Peak-RAM Win)
- **Current code (`internal/engine/engine.go:399-407`):**
  ```go
  data, err := io.ReadAll(io.TeeReader(io.LimitReader(f, limit), hashes))
  ```
  Every scan worker allocates up to `Scan.MaxFileSizeMB` (**64 MB in Core/Safe, 32 MB in Lite**) via `io.ReadAll`, which dynamically grows/copies the slice (peaking at ~2x allocation during growth). With 4 scan workers on a multi-core CPU, peak heap easily spikes **250–500 MB** on large installers or archives.
- **Proposed fix:**
  1. Introduce a `sync.Pool` of reusable streaming read buffers (`64 KB`) for full-file hashing (`MD5`/`SHA1`/`SHA256`).
  2. Use a two-tier content budget: read a bounded head window (e.g., `2 MB` for PEs/scripts, `4 MB` for YARA) into a pooled buffer for static/PE/script analysis; only read larger payloads when inspecting an archive entry or when a rule explicitly requires deeper offset scanning.
  3. Release/zero the `data` buffer before slow escalation steps (`Defender`, `Threat Exchange`, `AI`), so multi-megabyte byte slices are never pinned in RAM while waiting on HTTP/LLM responses!
- **Expected impact:** **60–80% reduction in peak scan RAM** and dramatically lower Go GC pause frequency during Quick/Full scans.

### Optimization 2 — Debounced / Batched Writes for JSON `DiskCache` (Disk I/O & Windows Lock Win)
- **Current code (`internal/reputation/providers.go:220-228`):**
  `DiskCache.Put()` marshals the **entire** `entries` map (up to 50,000 records) to JSON and executes `config.WriteAtomic()` on **every single cache insert**. During a 50-file batch hash scan, this rewrites the entire file 50 times in a row — magnifying CPU/JSON allocation churn and Windows `os.Rename` lock contention.
- **Proposed fix (works immediately with JSON before SQLite):**
  1. Add a `dirty` flag and a debounced background flush (`Flush()` called at end of `LookupBatch` / `BatchHashScan`, or every 5 seconds while dirty).
  2. Cap `BatchHashScan` file hashing with a pooled `32 KB` buffer (`io.CopyBuffer`) instead of `io.Copy` allocating a new 32 KB buffer per file (`internal/app/manage.go:430`).
- **Expected impact:** Cuts reputation disk writes by **10x–50x** during batch scans and removes redundant JSON heap spikes.

### Optimization 3 — Bound In-Memory Clean Cache & Stream `events.jsonl` Tail
- **Current code (`internal/engine/engine.go:227, 465` & `internal/app/app.go:180-202`):**
  1. `Engine.cache` (`map[string]cacheEntry`) grows without an upper bound in long-running `visionary guard` sessions; when flushed to `cache.gob`, the entire map is re-encoded.
  2. `App.Events(n int)` reads and unmarshals **every line** of `events.jsonl` (up to **8 MB**) into a slice just to return the newest 30 events to the Web UI every few seconds!
- **Proposed fix:**
  1. Cap `Engine.cache` at `100,000` entries (Lite: `25,000`) with LRU/oldest-revision eviction on `Flush()`.
  2. Implement a reverse-chunk tail reader for `App.Events(n)` (seek to `max(0, size - 256KB)` and parse only the trailing window when `n <= 200`), cutting Web UI polling allocations by **>95%**.

### Optimization 4 — Go Runtime Memory Ceiling for Lite Edition (`GOMEMLIMIT` + `debug.FreeOSMemory`)
- **Current code:** Neither `visionary` nor `visionary-lite` configures a soft heap limit, so Go's default `GOGC=100` lets RSS double after a Quick Scan and hold onto freed pages for minutes.
- **Proposed fix:**
  1. In `Lite` builds (or when `profile == "lite"`), call `debug.SetMemoryLimit(64 << 20)` (64 MiB soft ceiling) and `debug.SetGCPercent(50)` at startup when `GOMEMLIMIT` is not overridden by the user.
  2. Call `debug.FreeOSMemory()` at the end of `QuickScan`, `TargetedScan`, `BootScan`, and `BatchHashScan` so resident working set returns to baseline (~14–18 MB) immediately after scans complete.
- **Expected impact:** Keeps Windows working set and Linux RSS well under CI budgets even immediately after heavy scans.

### Optimization 5 — Drop Heavy `anthropic-sdk-go/v2` Dependency (~4–6 MB Smaller Binaries)
- **Current code (`internal/ai/claude.go`, `go.mod:6-24`):**
  As noted in `docs/LITE.md`, `github.com/anthropics/anthropic-sdk-go/v2` pulls in OpenTelemetry (`go.opentelemetry.io/otel/*`), `invopop/jsonschema`, `tidwall/*`, `yaml/v4`, and `standard-webhooks` — adding ~4–6 MB to every Windows `.exe`, even though `Gemini` and `OpenAI` (`internal/ai/cloud.go`) already use a clean ~45-line standard-library `net/http` client.
- **Proposed fix:**
  Replace the SDK in `internal/ai/claude.go` with a direct standard-library `net/http` POST to `https://api.anthropic.com/v1/messages` (preserving `x-api-key`, `anthropic-version`, `output_config`/effort, refusal handling, and error mapping).
- **Expected impact:** **~30% smaller binaries** across Core, Lite, and Safe (~14.8 MB → ~9–10 MB), faster CI builds, and fewer transitive dependencies to audit.

### Optimization 6 — Real-Time Guard Watcher Coalescing & Local AI Memory Hygiene
- **Current code (`internal/app/guard.go`, `internal/ai/local.go`):**
  1. During game updates, browser downloads, or `npm`/`cargo` builds, Windows fires dozens of `ReadDirectoryChangesW` events per file. Extending per-path debounce coalescing and honoring `ai.local.keep_alive` (`0s` / `2m`) prevents redundant rescans and keeps local LLM RAM/VRAM at zero when idle.
  2. Add a `visionary bench` / `go test -bench=. -benchmem ./internal/engine` benchmark gate in CI to track `B/op` and `allocs/op` per commit.

---

## 3. Target Budget Improvements

| Metric | Current (Measured / Audited) | Target After PR #02 |
|--------|------------------------------|---------------------|
| Peak heap during 4-worker Quick Scan | ~250–500 MB (large files) | **< 80 MB** (Lite: **< 45 MB**) |
| Idle guard RSS (Linux / Windows) | ~16 MB / ~35–60 MB | **< 14 MB / < 30 MB** |
| `App.Events(30)` memory per UI poll | Up to 8 MB file parse | **< 256 KB** tail read |
| Windows binary size (`visionary-lite.exe`) | ~14.3 MB | **< 10 MB** |
| Reputation JSON writes per 50-file batch | 50 full-file rewrites | **1 batched flush** (or SQLite WAL in PR #01) |

---

## 4. Verification Plan

- [ ] Run `go test -bench=. -benchmem ./internal/engine` before and after to verify `B/op` and `allocs/op` drop.
- [ ] Run `scripts/idle-budget.sh ./visionary-lite 40 3` (Linux) and Windows working-set check after a forced Quick Scan.
- [ ] Verify Claude cloud AI triage (`internal/ai/ai_test.go` with `httptest.NewServer`) passes identically without `anthropic-sdk-go/v2`.
- [ ] Confirm `go vet` and `go test` pass across default (`core`), `-tags lite`, and `-tags safe`.

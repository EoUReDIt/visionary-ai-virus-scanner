# PR Proposal #03: Codebase Build-Breaking Audit & Fix Plan

- **Proposed Branch:** `fix/build-audit-and-ci-hardening`
- **Target Branch:** `main`
- **Status:** Implemented
- **Audit Scope:** All Go packages (`cmd/`, `internal/`), build tags (`core`, `lite`, `safe`, `windows`, `!windows`), `go.mod`, NSIS installer (`installer/visionary.nsi`), CI workflows (`.github/workflows/`), embedded Web UI (`internal/ui/index.html`), and TypeScript live preview (`preview/server.ts`).

---

## 1. Executive Summary

A static audit across all editions and platforms found **1 guaranteed P0 compile failure** that breaks `go build`, `go vet`, and GitHub Actions CI across **all three editions**, plus **4 P1 module/runtime defects** and **3 P2 polish/CI gaps**. The TypeScript preview server (`tsc --noEmit`) and embedded Web UI JavaScript (`internal/ui/index.html`) passed syntax and DOM-selector checks with zero errors.

---

## 2. Findings Ranked by Severity

### P0 — Critical (Breaks Build & CI on All Editions)

#### 1. Undefined function `row(...)` in `cmd/visionary/main.go:1191-1193`
- **Location:** `cmd/visionary/main.go`, inside `func cmdRisk(...)` lines 1191–1193:
  ```go
  row("Provider", a.ActiveRiskProvider())
  row("Scan posture", g.Posture)
  row("Guidance", g.Reason)
  ```
- **Root Cause:** `row` is declared as a **local closure** inside `cmdStatus` (`cmd/visionary/main.go:368`: `row := func(k, v string) { fmt.Printf("  %-22s %s\n", k, v) }`), not as a package-level helper.
- **Impact:** Hard compiler error (`undefined: row`) on `go build`, `go vet`, and `go test` for **Core**, **Lite**, and **Safe** on both Linux and Windows.
- **Fix:** Promote `func row(k, v string) { fmt.Printf("  %-22s %s\n", k, v) }` to package scope in `cmd/visionary/main.go` and remove the local closure in `cmdStatus` (or define it cleanly once and share across `cmdStatus` and `cmdRisk`).

---

### P1 — High (Module Hygiene, Secret Parity & Rate-Limit Safety)

#### 2. `go.mod` marks all direct dependencies as `// indirect`
- **Location:** `go.mod:5-27`.
- **Root Cause:** Direct imports (`github.com/anthropics/anthropic-sdk-go/v2`, `github.com/smallstep/pkcs7`, `golang.org/x/sys`, `golang.org/x/term`) are all annotated `// indirect` in one block.
- **Impact:** Fails `go mod tidy` cleanliness checks and can cause tooling/IDE/CI dependency resolution warnings.
- **Fix:** Split `go.mod` into separate direct `require (...)` and `// indirect` `require (...)` blocks and verify with `go mod tidy` in CI.

#### 3. Missing `GEMINI_API_KEY` and `OPENAI_API_KEY` environment overrides in `internal/secure/secure.go`
- **Location:** `internal/secure/secure.go:100-106`.
- **Root Cause:** `envNames` maps `anthropic`, `virustotal`, `otx`, `nvd`, and `huggingface`, omitting `"gemini": "GEMINI_API_KEY"` and `"openai": "OPENAI_API_KEY"`.
- **Impact:** Users running headless CLI or CI scripts cannot override Gemini or OpenAI keys via standard environment variables even though `internal/app/app.go:84-88` reads `secure.Secret("gemini")` and `secure.Secret("openai")`.
- **Fix:** Add `"gemini": "GEMINI_API_KEY"` and `"openai": "OPENAI_API_KEY"` to `envNames`.

#### 4. `Multi.LookupBatch` bypasses VirusTotal's 4 req/min free-tier pacing
- **Location:** `internal/reputation/providers.go:291-304`.
- **Root Cause:** `VirusTotal.LookupBatch` paces uncached live calls with `PaceDelay` (`15s`), whereas `Multi.LookupBatch` (used whenever Threat Exchange is set to **`both`** — OTX + VirusTotal) loops over hashes calling `m.LookupDetail` back-to-back with **zero delay** between live VirusTotal requests.
- **Impact:** Running a Downloads or folder batch hash scan while Threat Exchange is set to **Both** immediately triggers HTTP 429 rate-limit errors from VirusTotal after the 4th uncached hash.
- **Fix:** Update `Multi.LookupBatch` to run providers stage-by-stage: query OTX first via `LookupBatch`, collect only hashes that were not convicted (`mal < 5`), and pass the remaining list to `VirusTotal.LookupBatch` so VirusTotal's 15s pacing and 429 stop-early behavior are always honored.

#### 5. `reputation` CLI usage string omits `scan [path]`
- **Location:** `cmd/visionary/main.go:57`.
- **Root Cause:** `const usage` lists `set-key|clear-key|sync-otx` but omits `scan [path] [--limit N]`.
- **Fix:** Update `usage` line 57 so `visionary help` documents the Download / Batch Hash Scanner.

---

### P2 — Medium (Windows Lock Contention & CI Coverage)

#### 6. `DiskCache.Put` rewrites `reputation_cache.json` on every single insert
- **Location:** `internal/reputation/providers.go:220-228`.
- **Impact:** Increases Windows `os.Rename` contention and disk churn during batch hash scans (same failure class as the earlier `config.json.tmp` lock).
- **Fix:** Add `Flush()` and defer disk writes during `LookupBatch` until the batch finishes (or every 5s), with immediate flush preserved for single `LookupDetail` calls.

#### 7. CI smoke tests do not exercise new Risk Exchange & Threat Exchange CLI paths
- **Location:** `.github/workflows/build.yml:54-78` and `.github/workflows/release.yml:82-108`.
- **Fix:** Add non-network smoke checks (`visionary risk guidance --json`, `visionary reputation provider`, `visionary settings show --json`) to Core, Lite, and Safe smoke steps, plus a `go mod tidy` diff check on Linux CI.

#### 8. Build-Tag Parity & Web UI Checks (Verified Clean)
- **Verified OK:**
  - OS build-tag pairs (`plat_windows.go`/`plat_other.go`, `secure_windows.go`/`secure_other.go`, `tray_windows.go`/`tray_other.go`, `service_windows.go`/`service_other.go`) have matching exported/internal signatures.
  - Edition build-tag pairs (`edition/full.go`, `lite.go`, `safe.go`; `winsec_windows.go`/`winsec_windows_safe.go`; `static_heuristics_full.go`/`safe.go`; `indicators_full.go`/`safe.go`) have matching symbols.
  - All `App` methods called from `cmd/visionary/main.go` and `internal/ui/ui.go` exist (66 defined, 0 missing).
  - Embedded `internal/ui/index.html` JavaScript parses cleanly (965 lines, 0 syntax errors, all 149 `$()` selectors resolved).
  - Preview server (`preview/server.ts`) compiles and lints cleanly (`tsc --noEmit`, 0 errors).

---

## 3. Step-by-Step Fix Execution Plan

1. **Step 1 (Unblock Compilation — P0):** Promote `row(k, v string)` to package scope in `cmd/visionary/main.go` and update `usage` help text (Issue #1 & #5).
2. **Step 2 (Module & Secret Hygiene — P1):** Fix direct vs `// indirect` dependency grouping in `go.mod` and add `GEMINI_API_KEY` / `OPENAI_API_KEY` to `internal/secure/secure.go` (Issue #2 & #3).
3. **Step 3 (Batch Rate-Limit & Cache Flush Hardening — P1/P2):** Stage `Multi.LookupBatch` through each provider's `LookupBatch` so VirusTotal pacing is respected in `Both` mode, add a unit test in `internal/reputation/reputation_test.go`, and debounce `DiskCache` flushes during batch scans (Issue #4 & #6).
4. **Step 4 (CI Hardening — P2):** Add `risk guidance --json` and `reputation provider` smoke checks to `.github/workflows/build.yml` and `.github/workflows/release.yml` (Issue #7).
5. **Step 5 (Verification):** Run `go vet`, `go test` across `default`, `-tags lite`, and `-tags safe`, plus `GOOS=windows go vet`, and `npm run build` / `npm run lint`.

# Visionary AI Virus Scanner

A Windows antivirus for solo developers and gamers. One binary, CLI first, dashboard second.
It layers fast local detection (hashes, YARA-subset rules, static heuristics, certificate
blocklist) with optional AI triage: a local model under 3B parameters (Ollama or llama.cpp)
and/or a cloud model through your own API key.

> Status: v0.1.0. Built and `go vet`-checked for Windows from Linux; the Windows-only code
> has **not** yet been run on a real Windows machine. Treat it as a second layer next to
> Microsoft Defender, not a replacement.

## Features (all work from the CLI first)

| # | Feature | CLI |
|---|---------|-----|
| 1 | Windows Security integration | `visionary windows status`, `windows coexist` |
| 2 | Defender passive mode | `visionary windows passive on` (see limits) |
| 3 | Real-time protection | `visionary guard`, `visionary service install` |
| 4 | Import definitions | `visionary defs import <file>` (hash lists, CSV, ClamAV hdb/hsb/cvd, .yar, cert lists) |
| 5 | Definition channels | `visionary defs channel add <name> <url>` / `update` |
| 6 | Local AI (<3B) | `visionary ai local ...`, `ai recommend` |
| 7 | Cloud AI by API key | `visionary ai cloud ...` (key stored with DPAPI) |
| 8 | Pre-boot scan | `visionary preboot schedule`, `windows offline-scan` |
| 9 | Quick scan | `visionary scan quick` |
| 10 | Targeted scan | `visionary scan <path>` |
| 11 | Behaviour learning | `visionary behavior learn start/stop`, anomalies in `events` |
| 12 | Disable / re-enable | `visionary protection disable --for 30m\|--until-restart\|--permanent`, `protection enable` |
| 13 | Password-gated settings reset | `visionary settings reset [--all]` |
| 14 | Installer | `installer/visionary.nsi` -> `Visionary-Setup-<ver>.exe` |

Run `visionary help` for the full command list. Exit codes: 0 clean, 1 malicious, 2 suspicious, 3 error.
Add `--json` where offered for scripting.

## How detection works

allowlist -> clean cache -> hash definitions -> YARA-subset rules -> static heuristics
(PE parsing, imports, packers, entropy, name tricks, scripts, archives with bomb limits)
-> Authenticode certificate blocklist -> **only for gray-zone files**: Defender (AMSI),
VirusTotal hash lookup, local AI, cloud AI.

- Score >= 80 malicious, >= 40 suspicious. Heuristics are capped at 75 and can never convict alone.
- A trusted signature discounts heuristics. AI can clear heuristic-only suspicion, never hard evidence.
- AI models see a feature report (hashes, imports, strings, rule hits), never the file.
  Cloud snippet sharing is off by default.
- Local model size ceiling is enforced from real metadata (Ollama parameter count / GGUF tensors),
  not the model name. Hybrid mode asks the cloud only when the local model is unsure.
- Behaviour model: per-program baseline, parent->child edges, file-change burst rate
  (ransomware-like), plus universal rules (Office/browser/chat spawning shells, encoded PowerShell).
  Anomalies travel with the file as evidence into the engine.

Gamer/dev synergy: `profile gamer|dev|balanced`, automatic game mode (fullscreen detection) defers
background work and lowers priority; dev profile excludes build/cache folders from real-time only.

## Dashboard

`VisionaryUI.exe` (or `visionary ui`) serves a local page on 127.0.0.1 guarded by a per-launch
token and Host check. Every control shows the CLI command it runs.

## Build

```sh
go test ./...
GOOS=windows go vet ./...
sh scripts/build.sh 0.1.0      # dist/visionary.exe, VisionaryUI.exe, Visionary-Setup-0.1.0.exe (needs makensis)
```
On Windows: `scripts/build.ps1`. CI: `.github/workflows/build.yml`.

## What was learned from the reference repos

- **Hypatia / ScanCore / Malware-Scanner-System**: signature + hash scanning loop and quarantine flow -> our layered engine and vault.
- **aws-s3-virusscan**: scan-on-arrival event model -> scan-on-settle watcher, scan-on-execute.
- **mcp-virustotal**: hash-only reputation lookups (privacy-preserving) -> `reputation` layer.
- **CertVerify**: certificate-based trust/blocklisting -> Authenticode layer.
- **awesome_anti_virus_engine**: engine architecture survey -> multi-stage design, no kernel code assumed.
- **Spectrum-Security / SpyCore / atomdrift scan / topics**: behaviour and process-monitoring ideas; offensive code (SpyCore) was studied for what to detect, not reused.
- Outside sources: Microsoft Defender compatibility and passive-mode docs; sub-3B model roundups (qwen3:1.7b default).

## Honest limitations

- Not run on real Windows yet; CI smoke-tests the build there.
- Independent apps cannot register with Windows Security Center. Defender goes passive automatically only
  when a registered AV exists; the documented `ForceDefenderPassiveMode` policy is honoured only on
  Server / Defender-for-Endpoint-onboarded machines. Otherwise Visionary coexists (adds exclusions) as a second layer.
- No kernel/minifilter driver: the watcher is user-mode and detects after write.
- Pre-boot = SYSTEM boot-time task plus Defender Offline scan, not a custom boot environment.
- ClamAV body/logical signatures (.ndb/.ldb) and YARA modules/loops are unsupported (reported, skipped).
- Password reset checks the account password (not a Windows Hello PIN).
- Executables are unsigned; SmartScreen will warn.
- Small AI models are advisory; they can be wrong.

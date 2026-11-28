# Visionary AI Virus Scanner

A lightweight Windows antivirus built for solo developers, power users, and gamers — **one binary, CLI first, local Web UI second**.

Visionary layers fast local detection (packed SHA-256/SHA-1/MD5 hash sets, YARA-subset rules, static PE/script heuristics, Authenticode certificate verification, and behavioural/LOLBin monitoring) with optional **local AI** (models under 3B parameters via Ollama or `llama.cpp`), optional **cloud AI** (Google Gemini, Anthropic Claude, or OpenAI-compatible APIs via your own key), a hash-only **Threat Exchange** (keyless CIRCL hashlookup by default, plus optional VirusTotal and AlienVault OTX), and a keyless **Risk Exchange** (NIST NVD CVE 2.0, CISA KEV catalog, and Shodan InternetDB home-perimeter IP check) that tells the scanner where to check and how aggressively to scan.

> **Status:** v0.2.0. Built and `go vet` / `go test` verified across all three editions (**Safe**, **Lite**, **Core**) in GitHub Actions on Ubuntu and Windows runners. Treat Visionary as a second layer alongside Microsoft Defender, not a replacement.

---

## Quick Start (Neurodiverse-Friendly)

Short, predictable, no surprise popups. Pick **one** starting step:

1. **Install one file:** Download `Visionary-Lite-Setup` (quietest, lowest RAM) or `Visionary-Safe-Setup` (fewest Windows alerts) from **Releases** and run it.
2. **Open the dashboard:** Launch **Visionary** from the Start menu (or run `visionary ui`). Everything stays in one local browser tab (`127.0.0.1`) — no accounts, no banners, no upsells.
3. **Run one scan:** Click **Quick Scan** (or run `visionary scan quick`). Wait for the summary:
   - **Clean** — nothing to do.
   - **Suspicious** — nothing is deleted automatically; click **Explain with AI** (or `visionary ai explain <file>`) for a plain-English summary before deciding.
   - **Malicious** — moved safely to **Quarantine** where you can restore it anytime.
4. **Need zero interruptions?** Click **Pause Protection** (15m / 1h / until restart) or switch to the **Lite** or **Gamer** profile (`visionary profile lite`).
5. **Everything else is optional:** Local AI, Cloud AI, Threat Exchange, and Risk Exchange are all opt-in. You can ignore them until you want them.

---

## Editions (Safe, Lite, Core)

All three editions share one install directory (`%ProgramFiles%\Visionary`), one data directory (`%ProgramData%\VisionaryAV`), and one uninstaller so switching editions upgrades cleanly:

| Edition | Web UI & Tray | Detection Engine | Local (<3B) & Cloud AI | Threat & Risk Exchange | Best for |
|---------|---------------|------------------|------------------------|------------------------|----------|
| **Safe** | Yes | Hashes, YARA, Certs, Baseline Learning (omits Defender-triggering PE/script heuristic tables & Defender changes) | Yes | Yes | Lowest Windows Security / Defender friction |
| **Lite** | On-demand Web UI (zero RAM/CPU when closed; tray opt-in) | Full detection + heuristics + LOLBin guard | Yes (CPU-only default, opt-in budget GPU via `ai.local.gpu`, 2B ceiling, auto-unloads after idle) | Yes | Gamers, laptops, low-RAM PCs, background service |
| **Core** | Yes (with sign-in tray) | Full detection + heuristics + LOLBin guard + Defender coexistence | Yes (up to 3B local + cloud hybrid) | Yes | Full real-time AI & LOLBin protection |

See [docs/LITE.md](docs/LITE.md) and [docs/DISTRIBUTION.md](docs/DISTRIBUTION.md) for packaging and resource budgets.

---

## Key Features (CLI-First + Local Web UI)

| # | Feature | CLI Command |
|---|---------|-------------|
| 1 | Local Web Dashboard & System Tray | `visionary ui` (or `VisionaryUI.exe`; binds `127.0.0.1` with per-launch token) |
| 2 | Real-time protection & Windows Service | `visionary guard`, `visionary service install\|start\|stop\|status` |
| 3 | Quick, Targeted & Boot-time scans | `visionary scan quick`, `visionary scan <path>`, `visionary scan boot` |
| 4 | Windows Security & Defender coexistence | `visionary windows status`, `visionary windows coexist`, `windows offline-scan` |
| 5 | Import definitions & auto-update channels | `visionary defs import <file>`, `visionary defs channel presets\|add\|update` |
| 6 | Local AI (<3B) with auto-unload | `visionary ai local pull\|use\|gguf\|load\|unload`, `settings set ai.local.keep_alive 0s\|2m` |
| 7 | Cloud AI (Gemini / Claude / OpenAI) | `visionary ai cloud provider gemini\|claude\|openai`, `ai cloud set-key` (DPAPI encrypted) |
| 8 | AI Sensitivity & LOLBin Triage | `visionary ai sensitivity conservative\|balanced\|proactive`, `ai explain <file>` |
| 9 | Threat Exchange (CIRCL keyless / VT / OTX) | `visionary reputation provider circl\|virustotal\|otx\|both`, `set-key`, `sync-otx` |
| 10 | Download & Batch Folder Hash Scanner | `visionary reputation scan [path] [--limit 50]` (SHA-256 only, never uploads files) |
| 11 | Risk Exchange (NVD / CISA KEV / InternetDB) | `visionary risk sync\|guidance\|search <query>\|ip <public-ipv4>\|provider nvd\|cisa-kev\|custom` |
| 12 | Behaviour baseline learning | `visionary behavior learn [--days 3]`, `stop-learning`, `status` |
| 13 | Pause / resume protection | `visionary protection disable --for 15m\|1h\|restart\|permanent`, `enable` |
| 14 | Gamer / Dev / Lite profiles & Game Mode | `visionary profile balanced\|gamer\|dev\|lite`, `visionary gamemode auto\|on\|off` |
| 15 | Password-gated settings reset | `visionary settings reset [--all]` |

Run `visionary help` for the complete command reference. Exit codes: `0` clean, `1` malicious, `2` suspicious, `3` error. Most commands accept `--json` for scripting.

---

## Install

- **NSIS Windows Installers (Recommended):** Download `Visionary-Safe-Setup-<ver>.exe`, `Visionary-Lite-Setup-<ver>.exe`, or `Visionary-Core-Setup-<ver>.exe` from GitHub **Releases**. Installers register the optional Windows Service, configure Defender coexistence (Core/Lite), add `visionary` to machine `PATH`, and include a clean uninstaller.
- **Portable / Zero-Install:** Download the portable `.zip` bundle or standalone `.exe` files (`VisionaryUI-*.exe`, `visionary-*.exe`) and verify against `SHA256SUMS.txt`.
- **SmartScreen note:** Unsigned releases may display a Windows SmartScreen prompt on first launch (**More info -> Run anyway**).

---

## How Detection Works

```text
allowlist -> clean cache -> hash definitions -> YARA-subset rules
  -> static heuristics (PE, imports, packers, entropy, scripts, archives with bomb limits)
  -> Authenticode certificate check
  -> [gray-zone files only] Microsoft Defender (AMSI) -> Threat Exchange (SHA-256 hash)
     -> Local AI (<3B) -> Cloud AI (hybrid fallback) -> verdict / quarantine
```

- **Conservative scoring:** Score `>= 80` is malicious, `>= 40` is suspicious. Heuristics are capped at `75` and can never convict alone.
- **Privacy first:**
  - **Threat Exchange** defaults to keyless **CIRCL hashlookup** (NSRL/RDS known-good SHA-256 reference lookups) and upgrades seamlessly to **VirusTotal** or **AlienVault OTX** when you add a free key. It sends **SHA-256 hashes only** — user files are never uploaded. Lookups are cached locally in the unified cache store (`visionary_cache.db` with `-tags sqlite`, or atomic `visionary_cache.json` by default) so known hashes cost zero API calls, and batch scans pace live VirusTotal queries to stay within the free 4 req/min limit.
  - **AI models** receive a structured feature report (metadata, imports, findings, process lineage), never the raw file. Cloud script-snippet sharing is off by default.
- **Risk-Guided Scanning & Home Perimeter Check:** **Risk Exchange** syncs active CVEs and CISA Known Exploited Vulnerabilities (KEV) from **NIST NVD CVE 2.0** (free without an API key at 5 req/30s; optional free NIST key lifts to 50 req/30s) or directly from **CISA's static KEV JSON catalog** (zero key, zero rate limit), translating them into scan posture and priority Windows software/folder targets. An opt-in **Shodan InternetDB** lookup (`visionary risk ip <public-ipv4>`) checks a router WAN or outbound public IP with zero key while strictly blocking all private LAN / RFC 1918 / loopback addresses locally.
- **Local AI Memory Control:** Set `ai.local.keep_alive` to `0s` (unload immediately after each triage), `30s`, `1m`, `2m` (Lite default), or `15m`, or trigger an immediate **Unload model now** from the Web UI or CLI (`visionary ai local unload`). Applies to both Ollama and managed `llama-server` processes.

---

## Local Models: Ollama, Hugging Face, or Your Own GGUF

```sh
visionary ai local pull qwen3:1.7b                      # Ollama registry
visionary ai local hf search qwen3 1.7b                 # Hugging Face GGUF repos
visionary ai local hf files unsloth/Qwen3-1.7B-GGUF     # list quantisations
visionary ai local hf get unsloth/Qwen3-1.7B-GGUF --quant Q4_K_M
visionary ai local import C:\models\mine.gguf           # bring your own GGUF
visionary ai local models | remove <name> | use ...     # manage local store
visionary settings set ai.local.keep_alive 0s           # unload immediately after use
```

Downloads resume, verify hub SHA-256 checksums, inspect actual GGUF tensor counts (never trusting filenames), and enforce `ai.local.max_params_b` (`3.0` default, `2.0` in Lite).

---

## Build & Development

```sh
# Go verification & cross-compilation (Core, Lite, Safe)
go vet ./... && go test ./...
go vet -tags lite ./... && go test -tags lite ./...
go vet -tags safe ./... && go test -tags safe ./...
# Optional: enable embedded pure-Go WAL SQLite cache (visionary_cache.db)
go get modernc.org/sqlite && go build -tags sqlite ./cmd/visionary

sh scripts/build.sh 0.2.0

# On Windows (builds PE metadata, binaries, portable ZIPs, NSIS installers & SHA256SUMS.txt)
.\scripts\build.ps1 -Version 0.2.0

# Interactive Web UI preview server (Node.js / TypeScript)
npm install
npm run dev
```

---

## Providers, References & Credits

Visionary integrates with and builds upon ideas from the following providers, API guides, and open-source projects:

### Threat Exchange & Risk Exchange Providers
- **CIRCL hashlookup** — Keyless NSRL/RDS known-good SHA-256 lookup (`https://hashlookup.circl.lu/lookup/sha256/{sha256}`) enabled as the zero-key Threat Exchange default to suppress heuristic false positives.
- **NIST National Vulnerability Database (NVD CVE 2.0 API)** — Free vulnerability & CISA KEV search (`https://services.nvd.nist.gov/rest/json/cves/2.0`; 250,000+ CVEs, free without an API key at 5 req/30s or 50 req/30s with a free NIST API key). Docs: `https://nvd.nist.gov/developers/vulnerabilities`.
- **CISA Known Exploited Vulnerabilities (KEV) Catalog** — Direct static JSON download (`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`, zero key, zero rate limit) as well as KEV flags inside NVD advisories.
- **Shodan InternetDB** — Keyless public IPv4 exposure & CVE lookup (`https://internetdb.shodan.io/{ip}`) for opt-in home-router WAN perimeter and outbound public IP checks, with a strict local RFC 1918 / private-IP guard.
- **VirusTotal API v3** — Optional free-key hash-only multi-engine file reputation lookups (`GET /api/v3/files/{sha256}`), Download Scanner, and rate-limit-paced Batch Folder Hash Scanner (`https://www.virustotal.com/`).
- **LevelBlue / AlienVault Open Threat Exchange (OTX)** — Optional free-key DirectConnect API v1 (`https://otx.alienvault.com/api`) for per-hash pulse lookups and compact incremental SHA-256 bulk feed export (`/api/v1/indicators/export`).

### Articles & Technical Guides Referenced
- **NVD Free CVE 2.0 API Guide** — [NVD Has a Free API: Search 250,000+ Vulnerabilities Programmatically (dev.to / 0012303)](https://dev.to/0012303/nvd-has-a-free-api-search-250000-vulnerabilities-programmatically-4aem) — informed the Risk Exchange NIST NVD 2.0 client, `cveId`/`keywordSearch`/`cvssV3Severity`/`hasKev` filters, and keyless rate-limit guidance.
- **VirusTotal Free API Guide** — [VirusTotal Has a Free API: Scan Files and URLs Against 70+ Antivirus Engines (dev.to / 0012303)](https://dev.to/0012303/virustotal-has-a-free-api-scan-files-and-urls-against-70-antivirus-engines-n5k) — informed the hash-only Download Scanner, Batch Folder Hash Scanner, deduplication/caching strategy, and 4 req/min free-tier pacing.
- **InternetDB Free API Guide** — [InternetDB Has a Free API: Shodan Data for Any IP in One Call, No Key Needed (dev.to / 0012303)](https://dev.to/0012303/internetdb-has-a-free-api-shodan-data-for-any-ip-in-one-call-no-key-needed-42ep) — informed the home-perimeter scoping and upgrade proposal.
- **AlienVault OTX API Reference** — [OTX DirectConnect API Documentation](https://otx.alienvault.com/api) — informed the OTX provider, header auth, and bulk export endpoint.

### AI Runtimes, Security APIs & Formats
- **Local AI:** [Ollama](https://ollama.com/), [llama.cpp (`llama-server`)](https://github.com/ggml-org/llama.cpp), and [Hugging Face Hub](https://huggingface.co/) (GGUF model discovery and verified downloads).
- **Cloud AI (BYOK):** Google Gemini API, Anthropic Claude (Messages API), and OpenAI-compatible Chat Completions endpoints.
- **Windows & Signatures:** Microsoft Defender AMSI / `MpCmdRun` coexistence documentation, [ClamAV](https://www.clamav.net/) `.hdb`/`.hsb`/`.cvd` signature formats, and [YARA](https://virustotal.github.io/yara/) rule syntax.

### Reference Repositories Studied
- **Hypatia / ScanCore / Malware-Scanner-System** — Layered signature + hash scanning loops and quarantine vault design.
- **aws-s3-virusscan** — Scan-on-arrival event flow adapted into Visionary's scan-on-settle file watcher and scan-on-execute hooks.
- **mcp-virustotal** — Privacy-preserving, hash-only reputation lookup patterns.
- **CertVerify** — Authenticode certificate trust and blocklist checks.
- **awesome_anti_virus_engine** — User-mode, multi-stage antivirus architecture without kernel drivers.
- **Spectrum-Security / SpyCore / atomdrift** — Process lineage and behavioural anomaly detection ideas (offensive techniques studied strictly for detection, never reused).

---

## Upgrade & Audit Proposals

Planned architecture upgrades, performance/memory optimizations, and codebase build audits are tracked as PR proposals under `docs/proposals/`:
- [PR #01 — Embedded SQLite Cache & Keyless Default Exchanges](docs/proposals/PR_01_SQLITE_CACHE_AND_FREE_EXCHANGES.md)
- [PR #02 — Performance, Binary Size & Memory Optimization](docs/proposals/PR_02_PERFORMANCE_AND_MEMORY_OPTIMIZATION.md)
- [PR #03 — Codebase Build-Breaking Audit & Fix Plan](docs/proposals/PR_03_BUILD_AUDIT_AND_FIX_PLAN.md)

---

## Honest Limitations

- Independent applications cannot register with Windows Security Center; Microsoft Defender only enters automatic passive mode when a WSC-registered AV is present (`ForceDefenderPassiveMode` is honoured only on Server / Defender-for-Endpoint devices). Otherwise Visionary coexists cleanly as a second layer.
- No kernel/minifilter driver: the real-time guard runs in user mode and scans files after write/settle.
- Pre-boot scans use a SYSTEM startup task plus Microsoft Defender Offline scan rather than a custom boot environment.
- ClamAV body/logical signatures (`.ndb`/`.ldb`) and YARA modules/loops are unsupported and skipped with a count.
- Password-gated resets check the Windows account password (not a Windows Hello PIN).
- Unsigned binaries trigger Windows SmartScreen on first download unless Authenticode signing secrets are configured.
- Small (<3B) AI models are advisory triage assistants and can make mistakes; heuristics and AI never override hard hash/certificate evidence.

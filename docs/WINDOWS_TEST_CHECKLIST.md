# Windows test checklist (v0.1.0)

The Windows-only code has only been compile/vet-checked. Run this on a real machine, ideally a
disposable VM snapshot (Windows 10/11 x64), before trusting a build. Record result and notes per item.

Setup: copy `visionary.exe` (or install `Visionary-Setup-*.exe`). Use an **elevated** PowerShell unless noted.
Safe test file: the EICAR string (`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`) saved
as `eicar.com`. Defender may quarantine it first: add a test-folder exclusion or temporarily disable Defender real-time.

Legend: [ ] not run, PASS / FAIL / N/A.

## 0. Install / uninstall
- [ ] Installer runs (SmartScreen warning expected: unsigned). Components page shows core, service, Defender coexist, PATH, shortcut.
- [ ] `visionary version` works from a new terminal (PATH added).
- [ ] Desktop shortcut opens the dashboard in the default browser.
- [ ] Uninstall removes files, service, boot task, PATH entry; data in `C:\ProgramData\VisionaryAV` handling matches the prompt.
- [ ] Per-user (non-admin) run of `visionary status` works and reports "not elevated" where relevant.

## 1. Scanning (CLI)
- [ ] `visionary scan <folder with eicar.com>` exit code 1, file quarantined only if `--quarantine`/auto setting says so.
- [ ] Clean folder (e.g. `C:\Windows\System32`) exit 0, no false positives on signed MS binaries; note duration.
- [ ] `visionary scan quick` covers Downloads, Desktop, Temp, startup folders, running process images, autoruns.
- [ ] Targeted scan of a zip containing eicar; zip bomb (nested/huge) is limited, not hung.
- [ ] Long paths (>260), unicode names, locked files, network share: no crash, reported cleanly.
- [ ] `--json` output parses; exit codes 0/1/2/3 correct.
- [ ] `visionary quarantine list/restore/delete` round trip; restored file hash matches original.

## 2. Real-time protection
- [ ] `visionary guard -v` starts; heartbeat file updates every 2 s.
- [ ] Drop eicar.com into Downloads: detected within ~2 s, quarantined.
- [ ] Copy a large clean file: scanned once after settling, no repeated rescans.
- [ ] Start a new unknown exe: scan-on-execute entry appears in `events`.
- [ ] Office -> cmd/powershell spawn (e.g. VBA `Shell`) is flagged as anomaly.
- [ ] Bulk rename/encrypt of ~500 files in a test folder triggers the file-burst anomaly.
- [ ] CPU/RAM at idle (Task Manager): note values (target < 1% CPU).
- [ ] Watcher survives folder deletion/recreation and drive removal.

## 3. Service
- [ ] `visionary service install/start/stop/uninstall` works; service survives reboot and starts as automatic.
- [ ] Guard runs in the service (session 0): detections appear in `events` and the dashboard.
- [ ] Stopping the service removes the heartbeat; `status` shows guard not running.

## 4. Disable / re-enable
- [ ] `protection disable --for 1m` re-enables itself after a minute.
- [ ] `--until-restart` stays off until reboot then re-enables (boot-time comparison).
- [ ] `--permanent` stays off across reboot until `protection enable`.
- [ ] With "password required" on, disable/enable prompts for the account password; wrong password rejected.
- [ ] Dashboard and CLI agree on state within 2 s.

## 5. Settings reset and password
- [ ] `settings reset` asks for the Windows account password; correct password resets cached settings.
- [ ] `settings reset --all` also clears secrets (API key) and definitions as documented.
- [ ] 5 wrong passwords lock out for 5 minutes.
- [ ] Works for a Microsoft-account user (password) and a local account; note Windows Hello PIN is not accepted.
- [ ] Secrets are unreadable by another user account (DPAPI machine scope: confirm what that implies and document).

## 6. Windows Security / Defender
- [ ] `windows status` shows the same values as Windows Security (real-time, tamper protection, engine/signature versions).
- [ ] `windows coexist` adds Visionary paths to Defender exclusions (check `Get-MpPreference`); fails gracefully when Tamper Protection blocks it.
- [ ] `windows passive` on Home/Pro: record the actual result (expected: not honoured unless Server/MDE). Message must be honest.
- [ ] Defender layer: AMSI scan of eicar buffer returns detection; WinVerifyTrust marks signed MS files trusted.
- [ ] `windows offline-scan` triggers Defender Offline and the machine reboots only after confirmation.
- [ ] No two-AV slowdown: copy a large folder with both active, compare timing.

## 7. Pre-boot scan
- [ ] `preboot schedule` creates a SYSTEM boot task (`schtasks /query`).
- [ ] After reboot the scan runs before login, writes a report visible in `events`, and removes/keeps the task as documented.
- [ ] `preboot cancel` removes the task.

## 8. Definitions and channels
- [ ] Import: plain hash list, CSV, ClamAV `.hdb/.hsb/.cvd`, `.yar`, cert list; `defs stats` counts match.
- [ ] Unsupported rules (modules, loops, `.ndb/.ldb`) are skipped and reported, not fatal.
- [ ] Channel add (https), `update` honours ETag/If-Modified-Since; plain http (non-localhost) refused; `file://` works.
- [ ] MalwareBazaar preset downloads and imports.
- [ ] Corrupt/oversized download is rejected and previous definitions stay intact.
- [ ] Guard refreshes channels hourly and not while game mode is on.

## 9. AI
- [ ] Ollama installed: `ai local list/pull/use`; models over 3B are refused (try a 7B).
- [ ] llama-server + GGUF: `ai local gguf <file>`; over-limit GGUF refused; server auto-start with `--server`.
- [ ] `ai local hf search/files/get` downloads a small GGUF (e.g. a 1B Q4_K_M); progress shown, file lands in `C:\ProgramData\VisionaryAV\models`.
- [ ] Interrupt a download (Ctrl+C), rerun the same command: it resumes; final checksum passes.
- [ ] A >3B GGUF (e.g. a 7B Q4) is refused and nothing is left in the store; gated model without token gives the clear message.
- [ ] `ai local import <your.gguf>` copies the file; `models`, `use`, `remove` work; removing the in-use model clears the selection.
- [ ] Dashboard AI tab: search, pick, download with progress, cancel, import, delete.
- [ ] `ai test` passes for local and cloud providers.
- [ ] Cloud: `ai cloud set-key` stores key (not echoed, not in settings.json); bad key gives a clear error.
- [ ] Hybrid: cloud is contacted only when the local model is unsure (check with a proxy/Fiddler).
- [ ] Snippet sharing off by default: confirm no script excerpts leave the machine.
- [ ] VirusTotal lookup sends hash only (check traffic).
- [ ] `ai explain <file>` returns a readable explanation.

## 10. Behaviour learning
- [ ] `behavior learn start`, use the PC for a while, `learn stop`: baseline file written.
- [ ] After learning, a never-seen exe spawning a shell scores higher than a known one.
- [ ] Dev workflow (VS Code, git, node, Go builds) produces no alerts on the `dev` profile.
- [ ] Typical game launch (Steam/Epic, anti-cheat, launchers) produces no alerts on the `gamer` profile.

## 11. Game mode and profiles
- [ ] Fullscreen game: game mode turns on, background scans/channel updates pause, process priority drops.
- [ ] Exiting the game turns it off; borderless-windowed behaviour recorded.
- [ ] Profile `gamer` / `dev` excludes apply to real-time only, not manual scans.

## 12. Dashboard
- [ ] `VisionaryUI.exe` opens without a console window.
- [ ] Every tab loads; each action matches its shown CLI equivalent.
- [ ] Requests without the token or with a foreign Host header are rejected.
- [ ] Works in Edge and Chrome; dark mode readable.

## 13. Robustness
- [ ] Run as Standard user and as Administrator; no crash on denied paths.
- [ ] Sleep/resume and fast-user-switching keep the guard alive.
- [ ] 100k-file folder scan: memory stays bounded, scan cancels on Ctrl+C.
- [ ] Antivirus self-detection: Defender does not flag `visionary.exe` (note SmartScreen/Defender verdict).

## 14. Lite edition
- [ ] `Visionary-Lite-Setup` installs `visionary.exe` (lite): `visionary version` says "lite edition", no dashboard shortcut, `visionary ui` explains it is not included.
- [ ] Idle `visionary guard`: working set well under 60 MB and ~0% CPU (CI records it; confirm on real hardware, incl. a low-end laptop).
- [ ] With Ollama: `ai mode local`, `ai test`; Task Manager shows no GPU use for the model (num_gpu=0) and the model unloads after ~2 minutes idle.
- [ ] With llama-server: process command line contains `-ngl 0 -t N`; no GPU memory allocated.
- [ ] `ai recommend` lists only models at or under 2B; a 2.6B model is refused.
- [ ] `visionary profile lite` on the full edition applies the same settings; `profile balanced` leaves AI settings as they were.
- [ ] Game mode still defers work with the lite settings; a full quick scan completes on a 2-core / 4 GB machine without freezing the desktop.

## Reporting
For each FAIL record: Windows build, elevation, exact command, `visionary events --json` excerpt, and
`%ProgramData%\VisionaryAV\*.log` if present. File issues with the label `windows-validation`.

# Distribution, code signing and SmartScreen

## The honest picture
SmartScreen and Smart App Control judge a download by its **signature and reputation**, not by how it
was compiled. An unsigned `.exe` downloaded in a browser carries a "Mark of the Web" and will show
"Windows protected your PC" until it has enough reputation. No build flag removes that. Signing changes
the warning from "Unknown publisher" to your name, and reputation then accumulates per certificate and
per file over weeks. Microsoft documents this in
[SmartScreen reputation](https://learn.microsoft.com/windows/apps/package-and-deploy/smartscreen-reputation) and
[code signing options](https://learn.microsoft.com/windows/apps/package-and-deploy/code-signing-options).
EV certificates no longer give an instant pass.

## Why other GitHub apps did not trigger it
Usually because they were obtained without the Mark of the Web: `go install` / building from source,
`winget`, `scoop` or Chocolatey, a `.zip` extracted by a tool that does not propagate the mark, or a
signed release that already had reputation. A browser-downloaded unsigned installer will still warn.

## Three Release Editions (Safe, Core, Lite)
`scripts/build.ps1` and `.github/workflows/release.yml` build and publish three distinct Windows editions
(configurable via `edition: all | safe | core | lite` and `package_format: both | nsis | exe` in `workflow_dispatch`):
- **Safe (`-tags safe`)** — *Lowest Windows Security / Defender friction*: Dashboard + CLI + AI triage
  (local `<3B` & multi-provider cloud) + gzipped YARA + hashes + Authenticode checks + baseline learning,
  **without** plaintext malware-API/UAC-bypass/Defender-exclusion heuristic tables, LOLBin command regexes,
  or Defender setting/PowerShell automation (`Visionary-Safe-Setup-x.y.z.exe`, `visionary-safe-x.y.z-windows-amd64.zip`).
- **Core (default)** — *All features enabled*: Full AI Protection Dashboard + CLI + complete PE/script
  heuristics + full LOLBin/behaviour guard + Microsoft Defender co-existence & passive-mode tools
  (`Visionary-Core-Setup-x.y.z.exe`, `visionary-core-x.y.z-windows-amd64.zip`).
- **Lite (`-tags lite`)** — *All detection features, minimal CPU/RAM*: Same full heuristic, LOLBin,
  and Defender co-existence engine as Core in a CLI-only build with CPU-only local AI defaults
  (`Visionary-Lite-Setup-x.y.z.exe`, `visionary-lite-x.y.z-windows-amd64.zip`).

## What every build does to minimize Windows Security / Defender false positives
- **Preserves Go symbols** (avoids `-s -w` stripping) and embeds genuine Windows PE `VERSIONINFO` metadata
  plus a Windows 10/11 `asInvoker` application manifest into every `.exe` (`scripts/build.ps1`).
- **Standard `zlib` NSIS compression** instead of `/SOLID lzma`, PowerShell-free native Win32 `PATH`
  updates (`visionary path add|remove`), and upgrade-only `taskkill` guards (`installer/visionary.nsi`).
- **Pre-release Microsoft Defender check:** `release.yml` scans `dist/` with `MpCmdRun.exe` on the
  Windows runner so any static detection is surfaced immediately in the workflow log.
- **Authenticode signing ready:** `scripts/sign.ps1` signs raw binaries before packaging and signs
  all installers when a certificate is supplied, plus generates `SHA256SUMS.txt`.

## Options to get a real signature (pick one)
| Option | Cost | Notes |
|---|---|---|
| [SignPath Foundation](https://signpath.org/) | free for qualifying open source | public repo, OSI licence, GitHub Actions builds; certificate is in SignPath's name. Check their eligibility page. |
| Azure Artifact Signing (was Trusted Signing) | about $10/month | individuals only in the US and Canada; organisations also in the EU and UK. Use Microsoft's signing action instead of `sign.ps1`. Microsoft's docs say it does not grant instant SmartScreen trust. |
| OV code-signing certificate | roughly $150-300/year | works anywhere; put the PFX in the repo secrets below. |

To use a PFX certificate add repository secrets `CODESIGN_PFX_BASE64` (base64 of the .pfx) and
`CODESIGN_PFX_PASSWORD`, then push a tag. Optional `CODESIGN_TIMESTAMP_URL`.

## Reduce friction regardless of signing
1. Offer a package-manager install (winget / scoop manifest) once releases exist: installs through them
   skip the browser's Mark of the Web.
2. Submit each release to Microsoft as a false-positive / clean-file report
   (<https://www.microsoft.com/wdsi/filesubmission>). Do this especially because a security tool contains
   malware-like strings and APIs, which attract heuristic detections.
3. Keep file names, version numbers and the publisher name stable between releases so reputation carries over.
4. Never pack the executables (UPX etc.): packers raise detection rates.
5. Document the warning in the release notes: "More info -> Run anyway", and publish the checksum.

## When the repository becomes private
- Releases keep working; assets are visible only to people with repository access, so public downloads
  need another host (a public releases-only repository, a website, a package manager).
- SignPath Foundation requires a public repository; Azure Artifact Signing and your own OV certificate do not.
- GitHub-hosted Windows runners bill at a higher rate than Linux on private repositories (free minutes are
  limited), so the Windows jobs will count against your quota.
- Check any secrets, personal paths or session links in docs and commit history before switching, since
  the history stays with the repository.

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

## What this repository does
- Builds with `-trimpath` and stripped symbols; releases publish `SHA256SUMS.txt` and a GitHub
  **build provenance attestation** (verify with `gh attestation verify <file> -R EoUReDIt/visionary-ai-virus-scanner`).
- `scripts/sign.ps1` Authenticode-signs the binaries *before* they are packed into the installer, then
  signs the installer, when a certificate is supplied. Without one it does nothing. CI proves the
  pipeline with a throwaway self-signed certificate on every run.
- `release.yml` is **manual**: Actions -> release -> Run workflow, pick the branch and a version
  (for example `0.2.0`). It builds, signs if the secrets below exist, writes `SHA256SUMS.txt` and creates the
  release and its `v0.2.0` tag on that commit. It creates a **draft** by default so you can review the
  assets before publishing, refuses to overwrite an existing release, and needs the workflow file on the
  default branch for the button to appear.

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
- Build provenance attestations need GitHub Enterprise Cloud on private repositories; the release
  workflow skips that step automatically when the repo is private. Checksums and signing still work.
- SignPath Foundation requires a public repository; Azure Artifact Signing and your own OV certificate do not.
- GitHub-hosted Windows runners bill at a higher rate than Linux on private repositories (free minutes are
  limited), so the Windows jobs will count against your quota.
- Check any secrets, personal paths or session links in docs and commit history before switching, since
  the history stays with the repository.

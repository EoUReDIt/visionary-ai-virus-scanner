# Builds the Windows standalone portable executables, NSIS installers, and SHA256SUMS.txt.
#   .\scripts\build.ps1 -Version 0.2.0
#   .\scripts\build.ps1 -Version 0.2.0 -PackageFormat both|nsis|exe
param(
  [string]$Version = "0.2.0",
  [ValidateSet("both", "nsis", "exe")]
  [string]$PackageFormat = "both"
)
$ErrorActionPreference = "Stop"
# A failing native command must stop the build (PowerShell does not by default).
function Check($what) { if ($LASTEXITCODE -ne 0) { throw "$what failed (exit code $LASTEXITCODE)" } }
Set-Location (Join-Path $PSScriptRoot "..")
$pkg = "github.com/EoUReDIt/visionary-ai-virus-scanner/internal/config"
New-Item -ItemType Directory -Force dist | Out-Null

# Normalize 4-part numeric version for NSIS VIProductVersion (strips -rc1/-dev suffixes).
$viVersion = ($Version -replace '-.*$', '')
if ($viVersion -match '^\d+\.\d+\.\d+$') { $viVersion = "$viVersion.0" }
elseif ($viVersion -notmatch '^\d+\.\d+\.\d+\.\d+$') { $viVersion = "0.2.0.0" }

go vet ./...
Check "go vet"
go test ./...
Check "go test"

$env:CGO_ENABLED = "0"
go build -trimpath -ldflags "-s -w -X $pkg.Version=$Version" -o dist\visionary.exe .\cmd\visionary
Check "build visionary.exe"
go build -trimpath -ldflags "-s -w -H=windowsgui -X $pkg.Version=$Version" -o dist\VisionaryUI.exe .\cmd\visionary
Check "build VisionaryUI.exe"

go vet -tags lite ./...
Check "go vet (lite)"
go test -tags lite ./internal/config ./internal/ai ./internal/app
Check "go test (lite)"
go build -trimpath -tags lite -ldflags "-s -w -X $pkg.Version=$Version" -o dist\visionary-lite.exe .\cmd\visionary
Check "build visionary-lite.exe"

# Sign raw binaries BEFORE packaging so both portable .exe downloads and NSIS installers carry signatures.
& "$PSScriptRoot\sign.ps1" dist\visionary.exe dist\VisionaryUI.exe dist\visionary-lite.exe

if ($PackageFormat -eq "both" -or $PackageFormat -eq "exe") {
  Copy-Item dist\visionary.exe "dist\visionary-$Version-windows-amd64.exe" -Force
  Copy-Item dist\VisionaryUI.exe "dist\VisionaryUI-$Version-windows-amd64.exe" -Force
  Copy-Item dist\visionary-lite.exe "dist\visionary-lite-$Version-windows-amd64.exe" -Force
}

if ($PackageFormat -eq "both" -or $PackageFormat -eq "nsis") {
  $nsis = (Get-Command makensis -ErrorAction SilentlyContinue).Source
  if (-not $nsis) { $nsis = "${env:ProgramFiles(x86)}\NSIS\makensis.exe" }
  if (Test-Path $nsis) {
    & $nsis /V2 "/DVERSION=$Version" "/DVI_VERSION=$viVersion" "/DBINDIR=..\dist" "/DOUTFILE=..\dist\Visionary-Setup-$Version.exe" installer\visionary.nsi
    Check "makensis"
    & $nsis /V2 /DLITE "/DVERSION=$Version" "/DVI_VERSION=$viVersion" "/DBINDIR=..\dist" "/DOUTFILE=..\dist\Visionary-Lite-Setup-$Version.exe" installer\visionary.nsi
    Check "makensis (lite)"
  } else {
    Write-Warning "NSIS not found: install it (winget install NSIS.NSIS) to build the installer."
  }
  $setups = @(Get-ChildItem dist -Filter "Visionary*Setup-*.exe" | ForEach-Object FullName)
  if ($setups.Count -gt 0) { & "$PSScriptRoot\sign.ps1" @setups }
}

# Generate SHA256SUMS.txt for all release artifacts.
$releaseFiles = @()
if ($PackageFormat -eq "both" -or $PackageFormat -eq "nsis") {
  $releaseFiles += Get-ChildItem dist -Filter "Visionary*Setup-$Version.exe" -ErrorAction SilentlyContinue
}
if ($PackageFormat -eq "both" -or $PackageFormat -eq "exe") {
  $releaseFiles += Get-ChildItem dist -Filter "*-$Version-windows-amd64.exe" -ErrorAction SilentlyContinue
}
if ($releaseFiles.Count -gt 0) {
  $lines = foreach ($f in ($releaseFiles | Sort-Object Name)) {
    $h = (Get-FileHash $f.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    "$h  $($f.Name)"
  }
  Set-Content -Path dist\SHA256SUMS.txt -Value $lines -Encoding ascii
}

Get-ChildItem dist

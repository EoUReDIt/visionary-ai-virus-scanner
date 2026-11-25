# Builds the Windows binaries and the NSIS installer on Windows.
#   .\scripts\build.ps1 -Version 1.0.0
param([string]$Version = "0.1.0")
$ErrorActionPreference = "Stop"
# A failing native command must stop the build (PowerShell does not by default).
function Check($what) { if ($LASTEXITCODE -ne 0) { throw "$what failed (exit code $LASTEXITCODE)" } }
Set-Location (Join-Path $PSScriptRoot "..")
$pkg = "github.com/EoUReDIt/visionary-ai-virus-scanner/internal/config"
New-Item -ItemType Directory -Force dist | Out-Null
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
# Sign before packaging so the installers carry signed binaries (no-op without a certificate).
& "$PSScriptRoot\sign.ps1" dist\visionary.exe dist\VisionaryUI.exe dist\visionary-lite.exe
$nsis = (Get-Command makensis -ErrorAction SilentlyContinue).Source
if (-not $nsis) { $nsis = "${env:ProgramFiles(x86)}\NSIS\makensis.exe" }
if (Test-Path $nsis) {
  & $nsis /V2 "/DVERSION=$Version" "/DBINDIR=..\dist" "/DOUTFILE=..\dist\Visionary-Setup-$Version.exe" installer\visionary.nsi
  Check "makensis"
  & $nsis /V2 /DLITE "/DVERSION=$Version" "/DBINDIR=..\dist" "/DOUTFILE=..\dist\Visionary-Lite-Setup-$Version.exe" installer\visionary.nsi
  Check "makensis (lite)"
} else {
  Write-Warning "NSIS not found: install it (winget install NSIS.NSIS) to build the installer."
}
$setups = @(Get-ChildItem dist -Filter "Visionary*Setup-*.exe" | ForEach-Object FullName)
if ($setups.Count -gt 0) { & "$PSScriptRoot\sign.ps1" @setups }
Get-ChildItem dist

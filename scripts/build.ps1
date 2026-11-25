# Builds the Windows binaries and the NSIS installer on Windows.
#   .\scripts\build.ps1 -Version 1.0.0
param([string]$Version = "0.1.0")
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
$pkg = "github.com/EoUReDIt/visionary-ai-virus-scanner/internal/config"
New-Item -ItemType Directory -Force dist | Out-Null
go vet ./...
go test ./...
$env:CGO_ENABLED = "0"
go build -trimpath -ldflags "-s -w -X $pkg.Version=$Version" -o dist\visionary.exe .\cmd\visionary
go build -trimpath -ldflags "-s -w -H=windowsgui -X $pkg.Version=$Version" -o dist\VisionaryUI.exe .\cmd\visionary
# Sign before packaging so the installer carries signed binaries (no-op without a certificate).
& "$PSScriptRoot\sign.ps1" dist\visionary.exe dist\VisionaryUI.exe
$nsis = (Get-Command makensis -ErrorAction SilentlyContinue).Source
if (-not $nsis) { $nsis = "${env:ProgramFiles(x86)}\NSIS\makensis.exe" }
if (Test-Path $nsis) {
  & $nsis /V2 "/DVERSION=$Version" "/DBINDIR=..\dist" "/DOUTFILE=..\dist\Visionary-Setup-$Version.exe" installer\visionary.nsi
} else {
  Write-Warning "NSIS not found: install it (winget install NSIS.NSIS) to build the installer."
}
$setups = @(Get-ChildItem dist -Filter "Visionary-Setup-*.exe" | ForEach-Object FullName)
if ($setups.Count -gt 0) { & "$PSScriptRoot\sign.ps1" @setups }
Get-ChildItem dist

# Builds Windows releases for all three Visionary editions (Core, Lite, Safe):
#   .\scripts\build.ps1 -Version 0.2.0
#   .\scripts\build.ps1 -Version 0.2.0 -PackageFormat both|nsis|exe -Edition all|core|lite|safe
param(
  [string]$Version = "0.2.0",
  [ValidateSet("both", "nsis", "exe")]
  [string]$PackageFormat = "both",
  [ValidateSet("all", "core", "lite", "safe")]
  [string]$Edition = "all"
)
$ErrorActionPreference = "Stop"
# A failing native command must stop the build (PowerShell does not by default).
function Check($what) { if ($LASTEXITCODE -ne 0) { throw "$what failed (exit code $LASTEXITCODE)" } }
Set-Location (Join-Path $PSScriptRoot "..")
$pkg = "github.com/EoUReDIt/visionary-ai-virus-scanner/internal/config"
New-Item -ItemType Directory -Force dist | Out-Null

$buildCore = ($Edition -eq "all" -or $Edition -eq "core")
$buildLite = ($Edition -eq "all" -or $Edition -eq "lite")
$buildSafe = ($Edition -eq "all" -or $Edition -eq "safe")

# Normalize 4-part numeric version for Windows VERSIONINFO and NSIS VIProductVersion.
$viVersion = ($Version -replace '-.*$', '')
if ($viVersion -match '^\d+\.\d+\.\d+$') { $viVersion = "$viVersion.0" }
elseif ($viVersion -notmatch '^\d+\.\d+\.\d+\.\d+$') { $viVersion = "0.2.0.0" }
$viComma = $viVersion -replace '\.', ','

# Locate windres (MinGW/MSYS2/Strawberry Perl) so every .exe carries proper
# Windows VERSIONINFO and a Windows 10/11 asInvoker application manifest.
$windres = (Get-Command windres.exe -ErrorAction SilentlyContinue).Source
if (-not $windres) {
  foreach ($cand in @(
    "C:\msys64\mingw64\bin\windres.exe",
    "C:\ProgramData\mingw64\mingw64\bin\windres.exe",
    "C:\Strawberry\c\bin\windres.exe"
  )) {
    if (Test-Path $cand) { $windres = $cand; break }
  }
}

$sysoPath = Join-Path (Get-Location) "cmd\visionary\rsrc_windows_amd64.syso"

function New-WinResource {
  param(
    [string]$InternalName,
    [string]$OriginalFilename,
    [string]$FileDescription,
    [string]$ProductName
  )
  Remove-Item $sysoPath -Force -ErrorAction SilentlyContinue
  if (-not $windres) {
    Write-Warning "windres.exe not found: skipping Windows VERSIONINFO/manifest resource for $OriginalFilename."
    return
  }
  $tmp = Join-Path ([IO.Path]::GetTempPath()) ("visionary-rsrc-" + [guid]::NewGuid().ToString("N"))
  New-Item -ItemType Directory -Force $tmp | Out-Null
  try {
    $manifestPath = Join-Path $tmp "app.manifest"
    $rcPath = Join-Path $tmp "app.rc"
    $manifest = @"
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity version="$viVersion" processorArchitecture="amd64" name="Visionary.$InternalName" type="win32"/>
  <description>$FileDescription</description>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
      <supportedOS Id="{1f676c76-80e1-4239-95bb-83d0f6d0da78}"/>
    </application>
  </compatibility>
</assembly>
"@
    Set-Content -Path $manifestPath -Value $manifest -Encoding ascii

    $rc = @"
1 24 "app.manifest"

1 VERSIONINFO
FILEVERSION $viComma
PRODUCTVERSION $viComma
FILEFLAGSMASK 0x3fL
FILEFLAGS 0x0L
FILEOS 0x40004L
FILETYPE 0x1L
FILESUBTYPE 0x0L
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "040904B0"
    BEGIN
      VALUE "CompanyName", "Visionary\0"
      VALUE "FileDescription", "$FileDescription\0"
      VALUE "FileVersion", "$Version\0"
      VALUE "InternalName", "$InternalName\0"
      VALUE "LegalCopyright", "Visionary Contributors\0"
      VALUE "OriginalFilename", "$OriginalFilename\0"
      VALUE "ProductName", "$ProductName\0"
      VALUE "ProductVersion", "$Version\0"
    END
  END
  BLOCK "VarFileInfo"
  BEGIN
    VALUE "Translation", 0x0409, 1200
  END
END
"@
    Set-Content -Path $rcPath -Value $rc -Encoding ascii

    Push-Location $tmp
    try {
      & $windres -O coff -F pe-x86-64 -i $rcPath -o $sysoPath
      Check "windres ($OriginalFilename)"
    } finally {
      Pop-Location
    }
  } finally {
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
  }
}

function New-PortableZip {
  param([string]$ZipPath, [string[]]$SourceFiles)
  $zipStage = Join-Path $env:TEMP ("visionary-zip-" + [guid]::NewGuid().ToString("N"))
  New-Item -ItemType Directory -Force $zipStage | Out-Null
  try {
    foreach ($f in $SourceFiles) { Copy-Item $f $zipStage -Force }
    Remove-Item $ZipPath -Force -ErrorAction SilentlyContinue
    Compress-Archive -Path "$zipStage\*" -DestinationPath $ZipPath -CompressionLevel Optimal
  } finally {
    Remove-Item $zipStage -Recurse -Force -ErrorAction SilentlyContinue
  }
}

$env:CGO_ENABLED = "0"
$rawBinaries = @()
# Note: intentionally avoid `-s -w` symbol stripping — stripped unsigned Go PE
# files trigger significantly higher Microsoft Defender ML false-positive rates.
try {
  if ($buildCore) {
    Remove-Item $sysoPath -Force -ErrorAction SilentlyContinue
    go vet ./...
    Check "go vet (core)"
    go test ./...
    Check "go test (core)"

    New-WinResource -InternalName "visionary" -OriginalFilename "visionary.exe" -FileDescription "Visionary Core AI Antivirus CLI" -ProductName "Visionary Core"
    go build -trimpath -ldflags "-X $pkg.Version=$Version" -o dist\visionary.exe .\cmd\visionary
    Check "build visionary.exe (core)"

    New-WinResource -InternalName "VisionaryUI" -OriginalFilename "VisionaryUI.exe" -FileDescription "Visionary Core AI Protection Dashboard" -ProductName "Visionary Core"
    go build -trimpath -ldflags "-H=windowsgui -X $pkg.Version=$Version" -o dist\VisionaryUI.exe .\cmd\visionary
    Check "build VisionaryUI.exe (core)"
    $rawBinaries += "dist\visionary.exe", "dist\VisionaryUI.exe"
  }

  if ($buildLite) {
    Remove-Item $sysoPath -Force -ErrorAction SilentlyContinue
    go vet -tags lite ./...
    Check "go vet (lite)"
    go test -tags lite ./...
    Check "go test (lite)"

    New-WinResource -InternalName "visionary-lite" -OriginalFilename "visionary-lite.exe" -FileDescription "Visionary Lite AI Antivirus CLI" -ProductName "Visionary Lite"
    go build -trimpath -tags lite -ldflags "-X $pkg.Version=$Version" -o dist\visionary-lite.exe .\cmd\visionary
    Check "build visionary-lite.exe"

    New-WinResource -InternalName "VisionaryUI-Lite" -OriginalFilename "VisionaryUI-Lite.exe" -FileDescription "Visionary Lite AI Protection Web Dashboard" -ProductName "Visionary Lite"
    go build -trimpath -tags lite -ldflags "-H=windowsgui -X $pkg.Version=$Version" -o dist\VisionaryUI-Lite.exe .\cmd\visionary
    Check "build VisionaryUI-Lite.exe"
    $rawBinaries += "dist\visionary-lite.exe", "dist\VisionaryUI-Lite.exe"
  }

  if ($buildSafe) {
    Remove-Item $sysoPath -Force -ErrorAction SilentlyContinue
    go vet -tags safe ./...
    Check "go vet (safe)"
    go test -tags safe ./...
    Check "go test (safe)"

    New-WinResource -InternalName "visionary-safe" -OriginalFilename "visionary-safe.exe" -FileDescription "Visionary Safe AI Protection CLI" -ProductName "Visionary Safe"
    go build -trimpath -tags safe -ldflags "-X $pkg.Version=$Version" -o dist\visionary-safe.exe .\cmd\visionary
    Check "build visionary-safe.exe"

    New-WinResource -InternalName "VisionaryUI-Safe" -OriginalFilename "VisionaryUI-Safe.exe" -FileDescription "Visionary Safe AI Protection Dashboard" -ProductName "Visionary Safe"
    go build -trimpath -tags safe -ldflags "-H=windowsgui -X $pkg.Version=$Version" -o dist\VisionaryUI-Safe.exe .\cmd\visionary
    Check "build VisionaryUI-Safe.exe"
    $rawBinaries += "dist\visionary-safe.exe", "dist\VisionaryUI-Safe.exe"
  }
} finally {
  Remove-Item $sysoPath -Force -ErrorAction SilentlyContinue
}

# Sign raw binaries BEFORE packaging so portable downloads and NSIS installers carry signatures.
if ($rawBinaries.Count -gt 0) {
  & "$PSScriptRoot\sign.ps1" @rawBinaries
}

$releaseFiles = @()

if ($PackageFormat -eq "both" -or $PackageFormat -eq "exe") {
  if ($buildCore) {
    $cCli = "dist\visionary-core-$Version-windows-amd64.exe"
    $cUi  = "dist\VisionaryUI-Core-$Version-windows-amd64.exe"
    $cZip = "dist\visionary-core-$Version-windows-amd64.zip"
    Copy-Item dist\visionary.exe $cCli -Force
    Copy-Item dist\VisionaryUI.exe $cUi -Force
    New-PortableZip -ZipPath $cZip -SourceFiles @("dist\visionary.exe", "dist\VisionaryUI.exe", "README.md")
    $releaseFiles += $cCli, $cUi, $cZip
  }
  if ($buildLite) {
    $lCli = "dist\visionary-lite-$Version-windows-amd64.exe"
    $lUi  = "dist\VisionaryUI-Lite-$Version-windows-amd64.exe"
    $lZip = "dist\visionary-lite-$Version-windows-amd64.zip"
    Copy-Item dist\visionary-lite.exe $lCli -Force
    Copy-Item dist\VisionaryUI-Lite.exe $lUi -Force
    New-PortableZip -ZipPath $lZip -SourceFiles @("dist\visionary-lite.exe", "dist\VisionaryUI-Lite.exe", "README.md")
    $releaseFiles += $lCli, $lUi, $lZip
  }
  if ($buildSafe) {
    $sCli = "dist\visionary-safe-$Version-windows-amd64.exe"
    $sUi  = "dist\VisionaryUI-Safe-$Version-windows-amd64.exe"
    $sZip = "dist\visionary-safe-$Version-windows-amd64.zip"
    Copy-Item dist\visionary-safe.exe $sCli -Force
    Copy-Item dist\VisionaryUI-Safe.exe $sUi -Force
    New-PortableZip -ZipPath $sZip -SourceFiles @("dist\visionary-safe.exe", "dist\VisionaryUI-Safe.exe", "README.md")
    $releaseFiles += $sCli, $sUi, $sZip
  }
}

if ($PackageFormat -eq "both" -or $PackageFormat -eq "nsis") {
  $nsis = (Get-Command makensis -ErrorAction SilentlyContinue).Source
  if (-not $nsis) { $nsis = "${env:ProgramFiles(x86)}\NSIS\makensis.exe" }
  $setups = @()
  if (Test-Path $nsis) {
    if ($buildCore) {
      $out = "dist\Visionary-Core-Setup-$Version.exe"
      & $nsis /V2 "/DVERSION=$Version" "/DVI_VERSION=$viVersion" "/DBINDIR=..\dist" "/DOUTFILE=..\$out" installer\visionary.nsi
      Check "makensis (core)"
      $setups += $out
    }
    if ($buildLite) {
      $out = "dist\Visionary-Lite-Setup-$Version.exe"
      & $nsis /V2 /DLITE "/DVERSION=$Version" "/DVI_VERSION=$viVersion" "/DBINDIR=..\dist" "/DOUTFILE=..\$out" installer\visionary.nsi
      Check "makensis (lite)"
      $setups += $out
    }
    if ($buildSafe) {
      $out = "dist\Visionary-Safe-Setup-$Version.exe"
      & $nsis /V2 /DSAFE "/DVERSION=$Version" "/DVI_VERSION=$viVersion" "/DBINDIR=..\dist" "/DOUTFILE=..\$out" installer\visionary.nsi
      Check "makensis (safe)"
      $setups += $out
    }
  } else {
    Write-Warning "NSIS not found: install it (winget install NSIS.NSIS) to build the installers."
  }
  if ($setups.Count -gt 0) {
    & "$PSScriptRoot\sign.ps1" @setups
    $releaseFiles += $setups
  }
}

# Generate SHA256SUMS.txt for all produced release artifacts.
$resolved = $releaseFiles | Where-Object { Test-Path $_ } | ForEach-Object { Get-Item $_ } | Sort-Object Name -Unique
if ($resolved.Count -gt 0) {
  $lines = foreach ($f in $resolved) {
    $h = (Get-FileHash $f.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    "$h  $($f.Name)"
  }
  Set-Content -Path dist\SHA256SUMS.txt -Value $lines -Encoding ascii
}

Get-ChildItem dist

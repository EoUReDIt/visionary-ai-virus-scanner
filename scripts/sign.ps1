# Authenticode-signs the given files when a certificate is provided through
# the environment; otherwise does nothing (local and fork builds stay unsigned).
#
#   CODESIGN_PFX_BASE64    base64 of a .pfx (OV/EV certificate from any CA)
#   CODESIGN_PFX_PASSWORD  its password
#   CODESIGN_TIMESTAMP_URL optional RFC 3161 server (default DigiCert)
#
# Azure Artifact Signing and SignPath sign through their own CI actions
# instead; see docs/DISTRIBUTION.md. Usage: scripts\sign.ps1 file1.exe file2.exe
param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Files)
$ErrorActionPreference = "Stop"
if (-not $env:CODESIGN_PFX_BASE64) { Write-Host "sign: no certificate configured, leaving files unsigned"; exit 0 }

$signtool = (Get-Command signtool.exe -ErrorAction SilentlyContinue).Source
if (-not $signtool) {
  $signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
    Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
}
if (-not $signtool) { throw "signtool.exe not found (install the Windows SDK)" }

$pfx = Join-Path ([IO.Path]::GetTempPath()) ("codesign-" + [guid]::NewGuid().ToString("N") + ".pfx")
[IO.File]::WriteAllBytes($pfx, [Convert]::FromBase64String($env:CODESIGN_PFX_BASE64))
$ts = if ($env:CODESIGN_TIMESTAMP_URL) { $env:CODESIGN_TIMESTAMP_URL } else { "http://timestamp.digicert.com" }
try {
  foreach ($f in $Files) {
    if (-not (Test-Path $f)) { continue }
    & $signtool sign /f $pfx /p $env:CODESIGN_PFX_PASSWORD /fd SHA256 /tr $ts /td SHA256 /d "Visionary AV" $f
    if ($LASTEXITCODE -ne 0) { throw "signing $f failed" }
    $sig = Get-AuthenticodeSignature $f
    if (-not $sig.SignerCertificate) { throw "$f has no signature after signing" }
    Write-Host "signed $f by $($sig.SignerCertificate.Subject) (status $($sig.Status))"
  }
} finally {
  Remove-Item $pfx -Force -ErrorAction SilentlyContinue
}

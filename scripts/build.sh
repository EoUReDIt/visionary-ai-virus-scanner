#!/usr/bin/env sh
# Cross-compiles the Windows binaries, portable release executables, and (when
# makensis is on PATH) the NSIS installers. Works on Linux, macOS and Git Bash.
#   scripts/build.sh [version]
set -eu
cd "$(dirname "$0")/.."
VERSION="${1:-0.2.0}"
VI_VERSION="$(printf '%s' "$VERSION" | sed -E 's/-.*$//').0"
PKG=github.com/EoUReDIt/visionary-ai-virus-scanner/internal/config
mkdir -p dist
go generate ./internal/defs
go vet ./...
go test ./...
go vet -tags lite ./...
go test -tags lite ./internal/config ./internal/ai ./internal/app
export GOOS=windows GOARCH=amd64 CGO_ENABLED=0
go build -trimpath -ldflags "-s -w -X $PKG.Version=$VERSION" -o dist/visionary.exe ./cmd/visionary
# Same program linked for the GUI subsystem: no console window for the dashboard.
go build -trimpath -ldflags "-s -w -H=windowsgui -X $PKG.Version=$VERSION" -o dist/VisionaryUI.exe ./cmd/visionary
# Lite edition: no dashboard, CPU-only local AI, low-footprint defaults.
go build -trimpath -tags lite -ldflags "-s -w -X $PKG.Version=$VERSION" -o dist/visionary-lite.exe ./cmd/visionary

cp dist/visionary.exe "dist/visionary-$VERSION-windows-amd64.exe"
cp dist/VisionaryUI.exe "dist/VisionaryUI-$VERSION-windows-amd64.exe"
cp dist/visionary-lite.exe "dist/visionary-lite-$VERSION-windows-amd64.exe"

if command -v makensis >/dev/null 2>&1; then
  makensis -V2 -DLITE -DVERSION="$VERSION" -DVI_VERSION="$VI_VERSION" -DBINDIR=../dist -DOUTFILE="../dist/Visionary-Lite-Setup-$VERSION.exe" installer/visionary.nsi
  makensis -V2 -DVERSION="$VERSION" -DVI_VERSION="$VI_VERSION" -DBINDIR=../dist -DOUTFILE="../dist/Visionary-Setup-$VERSION.exe" installer/visionary.nsi
fi

if command -v sha256sum >/dev/null 2>&1; then
  (cd dist && sha256sum *"-$VERSION"*.exe > SHA256SUMS.txt 2>/dev/null || true)
fi
ls -l dist

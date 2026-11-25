#!/usr/bin/env sh
# Cross-compiles the Windows binaries and, when makensis is on PATH, the
# installer. Works on Linux, macOS and Git Bash.   scripts/build.sh [version]
set -eu
cd "$(dirname "$0")/.."
VERSION="${1:-0.1.0}"
PKG=github.com/EoUReDIt/visionary-ai-virus-scanner/internal/config
mkdir -p dist
go generate ./internal/defs
go vet ./...
go test ./...
export GOOS=windows GOARCH=amd64 CGO_ENABLED=0
go build -trimpath -ldflags "-s -w -X $PKG.Version=$VERSION" -o dist/visionary.exe ./cmd/visionary
# Same program linked for the GUI subsystem: no console window for the dashboard.
go build -trimpath -ldflags "-s -w -H=windowsgui -X $PKG.Version=$VERSION" -o dist/VisionaryUI.exe ./cmd/visionary
if command -v makensis >/dev/null 2>&1; then
  makensis -V2 -DVERSION="$VERSION" -DBINDIR=../dist -DOUTFILE="../dist/Visionary-Setup-$VERSION.exe" installer/visionary.nsi
fi
ls -l dist

#!/usr/bin/env bash
# Cross-compiles the three Windows editions (Core, Lite, Safe) from Linux/macOS.
# Produces NSIS installers too if makensis is installed.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${1:-0.2.0}"
VI_VERSION="${VERSION%%-*}"
if [[ "$VI_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  VI_VERSION="${VI_VERSION}.0"
elif [[ ! "$VI_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  VI_VERSION="0.2.0.0"
fi
PKG="github.com/EoUReDIt/visionary-ai-virus-scanner/internal/config"
mkdir -p dist

go vet ./... && go test ./...
go vet -tags lite ./... && go test -tags lite ./internal/config ./internal/ai ./internal/app
go vet -tags safe ./... && go test -tags safe ./...

export GOOS=windows GOARCH=amd64 CGO_ENABLED=0
# Avoid `-s -w` stripping to reduce Defender ML false positives.
go build -trimpath -ldflags "-X $PKG.Version=$VERSION" -o dist/visionary.exe ./cmd/visionary
go build -trimpath -ldflags "-H=windowsgui -X $PKG.Version=$VERSION" -o dist/VisionaryUI.exe ./cmd/visionary
go build -trimpath -tags lite -ldflags "-X $PKG.Version=$VERSION" -o dist/visionary-lite.exe ./cmd/visionary
go build -trimpath -tags safe -ldflags "-X $PKG.Version=$VERSION" -o dist/visionary-safe.exe ./cmd/visionary
go build -trimpath -tags safe -ldflags "-H=windowsgui -X $PKG.Version=$VERSION" -o dist/VisionaryUI-Safe.exe ./cmd/visionary

cp dist/visionary.exe "dist/visionary-core-${VERSION}-windows-amd64.exe"
cp dist/VisionaryUI.exe "dist/VisionaryUI-Core-${VERSION}-windows-amd64.exe"
cp dist/visionary-lite.exe "dist/visionary-lite-${VERSION}-windows-amd64.exe"
cp dist/visionary-safe.exe "dist/visionary-safe-${VERSION}-windows-amd64.exe"
cp dist/VisionaryUI-Safe.exe "dist/VisionaryUI-Safe-${VERSION}-windows-amd64.exe"

if command -v makensis >/dev/null; then
  makensis -V2 -DVERSION="$VERSION" -DVI_VERSION="$VI_VERSION" -DBINDIR=../dist -DOUTFILE="../dist/Visionary-Core-Setup-${VERSION}.exe" installer/visionary.nsi
  makensis -V2 -DLITE -DVERSION="$VERSION" -DVI_VERSION="$VI_VERSION" -DBINDIR=../dist -DOUTFILE="../dist/Visionary-Lite-Setup-${VERSION}.exe" installer/visionary.nsi
  makensis -V2 -DSAFE -DVERSION="$VERSION" -DVI_VERSION="$VI_VERSION" -DBINDIR=../dist -DOUTFILE="../dist/Visionary-Safe-Setup-${VERSION}.exe" installer/visionary.nsi
else
  echo "note: install nsis (makensis) to also build the Windows installers"
fi

if command -v sha256sum >/dev/null; then
  (cd dist && sha256sum Visionary-*-Setup-"${VERSION}".exe *-"${VERSION}"-windows-amd64.exe 2>/dev/null > SHA256SUMS.txt || true)
fi

ls -lh dist/

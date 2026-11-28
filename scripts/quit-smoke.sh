#!/usr/bin/env sh
# Quit-mode smoke test (Linux, used in CI).
#   scripts/quit-smoke.sh <visionary binary>
# Starts a guard, runs `visionary quit`, and fails unless the guard exits on
# its own, which is how the service, dashboard and tray stop too.
set -eu
BIN="$1"
HOME_DIR="$(mktemp -d)"
export VISIONARY_HOME="$HOME_DIR"
"$BIN" guard >/dev/null 2>&1 &
PID=$!
cleanup() { kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; rm -rf "$HOME_DIR" 2>/dev/null || true; }
trap cleanup EXIT
sleep 4
kill -0 "$PID" || { echo "guard did not start"; exit 1; }
"$BIN" quit
i=0
while kill -0 "$PID" 2>/dev/null; do
  i=$((i+1)); [ "$i" -gt 20 ] && { echo "guard still running 10s after quit"; exit 1; }
  sleep 0.5
done
echo "guard exited after quit"
# A guard started after the request must run normally (stale request ignored).
"$BIN" guard >/dev/null 2>&1 &
PID=$!
sleep 4
kill -0 "$PID" || { echo "guard exited because of a stale quit request"; exit 1; }
echo "stale quit request ignored"

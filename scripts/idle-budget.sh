#!/usr/bin/env sh
# Resource budget check for the real-time guard (Linux; used in CI).
#   scripts/idle-budget.sh <visionary binary> [max RSS MB] [max avg CPU %]
# Starts the guard on an empty data dir, lets it idle, and fails if resident
# memory or average CPU exceeds the budget.
set -eu
BIN="$1"; MAX_RSS_MB="${2:-40}"; MAX_CPU="${3:-3}"
HOME_DIR="$(mktemp -d)"
export VISIONARY_HOME="$HOME_DIR"
"$BIN" guard >/dev/null 2>&1 &
PID=$!
trap 'kill $PID 2>/dev/null || true; rm -rf "$HOME_DIR"' EXIT
sleep 10
RSS_KB=$(awk '/VmRSS/ {print $2}' /proc/$PID/status)
TICKS=$(awk '{print $14+$15}' /proc/$PID/stat)
HZ=$(getconf CLK_TCK)
UP=$(awk '{print $1}' /proc/uptime)
START=$(awk '{print $22}' /proc/$PID/stat)
ELAPSED=$(awk -v u="$UP" -v s="$START" -v h="$HZ" 'BEGIN{print u - s/h}')
CPU=$(awk -v t="$TICKS" -v h="$HZ" -v e="$ELAPSED" 'BEGIN{printf "%.2f", (t/h)/e*100}')
RSS_MB=$(awk -v k="$RSS_KB" 'BEGIN{printf "%.1f", k/1024}')
echo "idle guard: ${RSS_MB} MB resident, ${CPU}% CPU (budget ${MAX_RSS_MB} MB, ${MAX_CPU}%)"
awk -v r="$RSS_MB" -v m="$MAX_RSS_MB" 'BEGIN{exit !(r>m)}' && { echo "memory budget exceeded"; exit 1; }
awk -v c="$CPU" -v m="$MAX_CPU" 'BEGIN{exit !(c>m)}' && { echo "CPU budget exceeded"; exit 1; }
exit 0

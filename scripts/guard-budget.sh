#!/usr/bin/env sh
# Hot-file CPU budget for the real-time guard (Linux; used in CI).
#   scripts/guard-budget.sh <visionary binary> [max avg CPU %] [seconds]
# Watches a folder holding a 20 MB file of a type the guard scans and appends
# to it every 0.3 s, the way a busy log or database does. Fails if the guard's
# average CPU over the run exceeds the budget. Idle cost is measured
# separately by idle-budget.sh.
set -eu
BIN="$1"; MAX_CPU="${2:-3}"; SECS="${3:-20}"
HOME_DIR="$(mktemp -d)"; WATCH="$(mktemp -d)"
export VISIONARY_HOME="$HOME_DIR"
"$BIN" settings set realtime.watch_paths "$WATCH" >/dev/null
head -c 20971520 /dev/urandom > "$WATCH/busy.dat"
"$BIN" guard >/dev/null 2>&1 &
PID=$!
trap 'kill $PID 2>/dev/null || true; rm -rf "$HOME_DIR" "$WATCH"' EXIT
sleep 4
ticks() { awk '{print $14+$15}' /proc/$PID/stat; }
T0=$(ticks); S0=$(date +%s.%N)
END=$(( $(date +%s) + SECS ))
while [ "$(date +%s)" -lt "$END" ]; do
  head -c 4096 /dev/urandom >> "$WATCH/busy.dat"
  sleep 0.3
done
T1=$(ticks); S1=$(date +%s.%N)
HZ=$(getconf CLK_TCK)
CPU=$(awk -v a="$T0" -v b="$T1" -v h="$HZ" -v s="$S0" -v e="$S1" 'BEGIN{printf "%.2f", ((b-a)/h)/(e-s)*100}')
echo "hot-file guard: ${CPU}% CPU over ${SECS}s (budget ${MAX_CPU}%)"
awk -v c="$CPU" -v m="$MAX_CPU" 'BEGIN{exit !(c>m)}' && { echo "CPU budget exceeded"; exit 1; }
exit 0

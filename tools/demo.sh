#!/usr/bin/env bash
# Single-command demo of Wespe's table support (docs/PLAN-TABLES.md
# Phase 14) against tools/dev_agent/dev_agent.c -- no ESP32 hardware
# needed. Walks the standard ifTable/ifXTable, GETBULK-walks it, SETs a
# wespeSensorTable label, shows a Counter64 genuinely climbing between
# two polls, and shows wespeSensorTable's row set genuinely changing
# between two polls (dev_agent.c's wsensor_row_count() cycles 1 <-> 2 on
# a fixed short clock specifically so this script doesn't need to wait
# long to see it). This is the pitch artifact: everything printed below
# is real output from real code, not illustration.
#
# Usage: tools/demo.sh [port]   (default 1161)
set -euo pipefail

PORT="${1:-1161}"
HOST="127.0.0.1"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$REPO_ROOT/host_tests/build"

section() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
run() { printf '\n\033[2m$ %s\033[0m\n' "$*"; "$@"; }

if [ ! -x "$BUILD_DIR/dev_agent" ]; then
    section "Building host_tests (dev_agent not found)"
    cmake -S "$REPO_ROOT/host_tests" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Debug
    cmake --build "$BUILD_DIR" -j"$(nproc 2>/dev/null || echo 4)"
fi

"$BUILD_DIR/dev_agent" "$PORT" &
AGENT_PID=$!
cleanup() { kill "$AGENT_PID" 2>/dev/null || true; }
trap cleanup EXIT
sleep 1

section "1. ifTable (standard IF-MIB, real column numbers) -- snmpwalk"
run snmpwalk -v2c -c public -O n "udp:$HOST:$PORT" 1.3.6.1.2.1.2.2

section "2. Same table via GETBULK (snmpbulkwalk) -- confirms it matches the plain walk"
run snmpbulkwalk -v2c -c public -O n "udp:$HOST:$PORT" 1.3.6.1.2.1.2.2

section "3. ifXTable's Counter64 pair, climbing -- two GETs a few seconds apart"
run snmpget -v2c -c public -O n "udp:$HOST:$PORT" 1.3.6.1.2.1.31.1.1.1.6.1
sleep 3
run snmpget -v2c -c public -O n "udp:$HOST:$PORT" 1.3.6.1.2.1.31.1.1.1.6.1

section "4. v1 manager: same Counter64 cell is invisible (RFC2089/RFC3584) -- noSuchName"
run snmpget -v1 -c public -O n "udp:$HOST:$PORT" 1.3.6.1.2.1.31.1.1.1.6.1 || true

section "5. wespeSensorTable -- SET a label through a table cell"
run snmpget -v2c -c public -O n "udp:$HOST:$PORT" 1.3.6.1.4.1.99999.2.6.1.2.1
run snmpset -v2c -c private -O n "udp:$HOST:$PORT" 1.3.6.1.4.1.99999.2.6.1.2.1 s "attic"
run snmpget -v2c -c public -O n "udp:$HOST:$PORT" 1.3.6.1.4.1.99999.2.6.1.2.1

section "6. wespeSensorTable's row set changing -- two walks a few seconds apart"
run snmpwalk -v2c -c public -O n "udp:$HOST:$PORT" 1.3.6.1.4.1.99999.2.6
sleep 4
run snmpwalk -v2c -c public -O n "udp:$HOST:$PORT" 1.3.6.1.4.1.99999.2.6

section "Done"
echo "A polling engine walking wespeSensorTable across steps 6's two polls has to"
echo "tolerate a row it saw a moment ago no longer being there -- that's the point."

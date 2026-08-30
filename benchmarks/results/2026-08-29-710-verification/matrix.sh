#!/usr/bin/env bash
set -uo pipefail
RUN=/root/bench/run/run_row.sh
BEFORE=/root/bench/tardi-before
AFTER=/root/bench/tardi-after

run() { echo ">>> $*"; bash "$RUN" "$@"; echo; }

# Core matrix: default workers (nproc=4)
run before-off-keepalive    "$BEFORE" off      0 keepalive 15
run before-off-close        "$BEFORE" off      0 close     15
run before-response-keepalive "$BEFORE" response 0 keepalive 15
run before-response-close   "$BEFORE" response 0 close     15
run before-static           "$BEFORE" off      0 keepalive 10 /health

run after-off-keepalive     "$AFTER"  off      0 keepalive 15
run after-off-close         "$AFTER"  off      0 close     15
run after-response-keepalive-r1 "$AFTER" response 0 keepalive 15
run after-response-keepalive-r2 "$AFTER" response 0 keepalive 15
run after-response-keepalive-r3 "$AFTER" response 0 keepalive 15
run after-response-close    "$AFTER"  response 0 close     15
run after-static            "$AFTER"  off      0 keepalive 10 /health

# Worker-count sensitivity (workers=32, matching original concurrency)
run before-response-keepalive-w32 "$BEFORE" response 32 keepalive 15
run before-response-close-w32     "$BEFORE" response 32 close     15
run after-response-keepalive-w32  "$AFTER"  response 32 keepalive 15
run after-response-close-w32      "$AFTER"  response 32 close     15

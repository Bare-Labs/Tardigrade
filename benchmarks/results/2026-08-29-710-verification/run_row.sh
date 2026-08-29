#!/usr/bin/env bash
# Drives one benchmark row: starts upstream_server.py + tardi (given binary),
# runs wrk (or a close-header variant), samples /status/metrics concurrently,
# tears both down, and writes labeled artifacts into $OUT_DIR.
#
# Usage: run_row.sh <label> <binary> <streaming_mode: off|response> \
#          <workers> <client_mode: keepalive|close> [duration_s] [path]
set -euo pipefail

LABEL="$1"; BINARY="$2"; STREAMING_MODE="$3"; WORKERS="$4"; CLIENT_MODE="$5"
DURATION="${6:-15}"
WRK_PATH="${7:-/proxy/health}"

REPO=/home/user/Tardigrade
OUT_DIR=/root/bench/artifacts
RUN_DIR=/root/bench/run
UPSTREAM_PORT=18080
LISTEN_PORT=8069
PID_FILE=/root/bench/run/tardi.pid

mkdir -p "$OUT_DIR"

# Drain any stale TIME_WAIT from a previous churn-heavy row before starting,
# matching the #709 diagnosis methodology (contaminated rows were the one
# documented false-positive in that report).
for _ in $(seq 1 100); do
  tw=$(ss -tan state time-wait 2>/dev/null | grep -c ":$LISTEN_PORT " || true)
  [[ "$tw" -lt 50 ]] && break
  sleep 0.2
done

python3 "$REPO/benchmarks/fixtures/upstream_server.py" --port "$UPSTREAM_PORT" \
  >"$OUT_DIR/${LABEL}-upstream.log" 2>&1 &
UPSTREAM_PID=$!

sed -e "s#__PID_FILE__#$PID_FILE#" -e "s#__LISTEN_PORT__#$LISTEN_PORT#" \
    -e "s#__UPSTREAM_PORT__#$UPSTREAM_PORT#" \
    "$RUN_DIR/tardi.conf.tmpl" > "$RUN_DIR/tardi-${LABEL}.conf"

for _ in $(seq 1 50); do
  curl -fsS "http://127.0.0.1:$UPSTREAM_PORT/health" >/dev/null 2>&1 && break
  sleep 0.1
done

env TARDIGRADE_RATE_LIMIT_RPS=0 TARDIGRADE_PROXY_STREAMING_MODE="$STREAMING_MODE" \
    TARDIGRADE_WORKER_THREADS="$WORKERS" \
    "$BINARY" run -c "$RUN_DIR/tardi-${LABEL}.conf" \
    >"$OUT_DIR/${LABEL}-service.log" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 100); do
  curl -fsS "http://127.0.0.1:$LISTEN_PORT/health" >/dev/null 2>&1 && break
  if ! kill -0 "$SERVER_PID" >/dev/null 2>&1; then
    echo "server exited early" >&2
    cat "$OUT_DIR/${LABEL}-service.log" >&2
    kill "$UPSTREAM_PID" >/dev/null 2>&1 || true
    exit 1
  fi
  sleep 0.1
done

# Prove the response Connection header and streaming path before load.
curl -sS -D - -o /dev/null "http://127.0.0.1:$LISTEN_PORT/proxy/health" \
  > "$OUT_DIR/${LABEL}-single-request-headers.txt" 2>&1 || true

# accepts_total baseline
curl -sS "http://127.0.0.1:$LISTEN_PORT/status/metrics" > "$OUT_DIR/${LABEL}-metrics-before.txt" 2>&1 || true

python3 "$REPO/benchmarks/results/2026-08-29-709-diagnosis/metrics_sampler.py" \
  --host 127.0.0.1 --port "$LISTEN_PORT" --duration "$DURATION" --interval 0.1 --json \
  > "$OUT_DIR/${LABEL}-metrics.json" 2>"$OUT_DIR/${LABEL}-metrics.err" &
SAMPLER_PID=$!

if [[ "$CLIENT_MODE" == "close" ]]; then
  wrk -t4 -c32 -d"${DURATION}s" --latency -H 'Connection: close' \
    "http://127.0.0.1:$LISTEN_PORT$WRK_PATH" \
    > "$OUT_DIR/wrk-${LABEL}.txt" 2>&1 || true
else
  wrk -t4 -c32 -d"${DURATION}s" --latency "http://127.0.0.1:$LISTEN_PORT$WRK_PATH" \
    > "$OUT_DIR/wrk-${LABEL}.txt" 2>&1 || true
fi

wait "$SAMPLER_PID" 2>/dev/null || true

curl -sS "http://127.0.0.1:$LISTEN_PORT/status/metrics" > "$OUT_DIR/${LABEL}-metrics-after.txt" 2>&1 || true

kill "$SERVER_PID" >/dev/null 2>&1 || true
for _ in $(seq 1 50); do kill -0 "$SERVER_PID" >/dev/null 2>&1 || break; sleep 0.1; done
kill -9 "$SERVER_PID" >/dev/null 2>&1 || true
kill "$UPSTREAM_PID" >/dev/null 2>&1 || true

echo "=== $LABEL done ==="
tail -20 "$OUT_DIR/wrk-${LABEL}.txt"

#!/usr/bin/env bash
# Permanent regression coverage for #708/#714: the client-RTT-sensitive small
# HTTP/1 streaming reverse-proxy case.
#
# #708 found that Tardigrade's streaming proxy path (`proxy_streaming_mode
# response`) collapsed ~8x under real client-facing network RTT because it
# forced downstream `Connection: close` and wrote response output in many
# small fragmented syscalls. #710/#711 fixed the downstream keep-alive and
# write-coalescing defects. This script reproduces the original failure
# shape on demand so a future regression in either fix is caught, without
# requiring the maintainer's exact physical network: it colocates the load
# generator and Tardigrade on one Linux host and uses `tc netem` on the
# loopback interface to inject controlled client-facing RTT, the same
# technique `benchmarks/competitive/netem-impair.sh` already established for
# #256-G.
#
# Linux-only (tc netem) and manual/scheduled by design (see the repo's
# non-goal: this must not gate every PR on privileged tc/dedicated
# hardware). Run it by hand or from a workflow_dispatch/scheduled job.
#
# Usage:
#   sudo benchmarks/competitive/rtt-streaming-regression.sh \
#       --delays 0,1,2,5 --duration 10 --connections 32 --threads 4 --reps 3
#
# Options:
#   --delays LIST       Comma-separated added RTT values in ms (default: 0,1,2,5)
#   --duration SECONDS  wrk duration per row (default: 10)
#   --connections N     wrk -c (default: 32)
#   --threads N         wrk -t (default: 4)
#   --reps N            Repetitions per (delay, scenario) cell (default: 3)
#   --upstream-workers N  Prefork workers for the origin fixture (default: 4)
#   --tardigrade-bin PATH  Pre-built binary (default: build ReleaseFast via zig)
#   --out-dir DIR        Output directory (default: benchmarks/competitive/results/<ts>-rtt-streaming-regression)
#   --smoke              Minimal one-delay, one-rep run for CI sanity checking
#   --help
#
# Scenarios run at every delay point:
#   normal      - streaming response, ordinary client, keep-alive eligible (the
#                 exact #708 failing case: proxy_streaming_mode=response)
#   close       - same route, explicit `Connection: close` (churn control,
#                 proves the normal row is actually reusing connections when
#                 compared against it)
#   buffered    - same origin route, proxy_streaming_mode=off (buffered
#                 control, must be flat regardless of RTT)
#   static      - tiny in-process static response (host/network sanity control)
#   large       - streaming response, 1 MiB upstream body (regression check
#                 for #711's write coalescing under RTT)
#   slow        - streaming response, upstream `/slow?ms=200` (regression
#                 check for correctness when the upstream is slow; #712/#713
#                 were closed not planned, so this does not assert an
#                 event-driven claim, only that nothing regresses)
#
# Each row captures: req/s, p50/p95/p99/p999, client/socket errors,
# tardigrade_accepts_total/tardigrade_requests_total churn (downstream
# connection reuse proof), and upstream new/reused connection counts.
#
# Output: one JSON file per (delay, scenario, rep) compatible with the
# WRK_SUMMARY schema emitted by benchmarks/wrk-summary.lua (same fields
# benchmarks/report.sh already knows how to read), plus a REPORT.md summary
# table aggregating all reps per (delay, scenario).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BENCH_DIR="${REPO_ROOT}/benchmarks"

DELAYS="0,1,2,5"
DURATION=10
CONNECTIONS=32
THREADS=4
REPS=3
UPSTREAM_WORKERS=4
TARDIGRADE_BIN=""
OUT_DIR=""
SMOKE=false

usage() { sed -n '2,52p' "$0" | sed 's/^# \{0,1\}//'; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --delays) DELAYS="$2"; shift 2 ;;
        --duration) DURATION="$2"; shift 2 ;;
        --connections) CONNECTIONS="$2"; shift 2 ;;
        --threads) THREADS="$2"; shift 2 ;;
        --reps) REPS="$2"; shift 2 ;;
        --upstream-workers) UPSTREAM_WORKERS="$2"; shift 2 ;;
        --tardigrade-bin) TARDIGRADE_BIN="$2"; shift 2 ;;
        --out-dir) OUT_DIR="$2"; shift 2 ;;
        --smoke) SMOKE=true; shift ;;
        --help) usage; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; usage >&2; exit 1 ;;
    esac
done

if $SMOKE; then
    DELAYS="0"
    DURATION=2
    REPS=1
fi

if [[ "$(uname -s 2>/dev/null || true)" != "Linux" ]]; then
    echo "rtt-streaming-regression.sh is Linux-only (tc netem); this host is $(uname -s 2>/dev/null || echo unknown)." >&2
    echo "SCENARIO NOT EXECUTED." >&2
    exit 1
fi

for tool in wrk curl jq python3 tc; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Required tool '${tool}' not found. SCENARIO NOT EXECUTED." >&2
        exit 1
    fi
done

if [[ $EUID -ne 0 ]] && ! command -v sudo >/dev/null 2>&1; then
    echo "Root or sudo is required to apply tc netem. SCENARIO NOT EXECUTED." >&2
    exit 1
fi

OUT_DIR="${OUT_DIR:-${BENCH_DIR}/competitive/results/$(date -u +%Y%m%d-%H%M%S)-rtt-streaming-regression}"
mkdir -p "$OUT_DIR"

UPSTREAM_PORT=28079
LISTEN_PORT=28180
CONF_FILE="${OUT_DIR}/tardi.conf"
PID_FILE="${OUT_DIR}/tardi.pid"
TARDI_LOG="${OUT_DIR}/tardi.log"
UPSTREAM_LOG="${OUT_DIR}/upstream.log"

TARDI_PID=""
UPSTREAM_PID=""

cleanup() {
    local status=$?
    [[ -n "$TARDI_PID" ]] && kill "$TARDI_PID" 2>/dev/null || true
    [[ -n "$UPSTREAM_PID" ]] && kill "$UPSTREAM_PID" 2>/dev/null || true
    wait "$TARDI_PID" 2>/dev/null || true
    wait "$UPSTREAM_PID" 2>/dev/null || true
    exit "$status"
}
trap cleanup EXIT INT TERM

if [[ -z "$TARDIGRADE_BIN" ]]; then
    echo "==> Building tardi (ReleaseFast) from $(cd "$REPO_ROOT" && git rev-parse HEAD)"
    (cd "$REPO_ROOT" && zig build -Doptimize=ReleaseFast) >>"${OUT_DIR}/build.log" 2>&1
    TARDIGRADE_BIN="${REPO_ROOT}/zig-out/bin/tardi"
fi
[[ -x "$TARDIGRADE_BIN" ]] || { echo "Tardigrade binary not found/executable: ${TARDIGRADE_BIN}" >&2; exit 1; }

GIT_SHA="$(cd "$REPO_ROOT" && git rev-parse HEAD)"
BIN_SHA256="$(shasum -a 256 "$TARDIGRADE_BIN" 2>/dev/null | awk '{print $1}' || sha256sum "$TARDIGRADE_BIN" | awk '{print $1}')"

echo "==> Starting origin fixture (prefork, ${UPSTREAM_WORKERS} workers) on 127.0.0.1:${UPSTREAM_PORT}"
python3 "${BENCH_DIR}/fixtures/upstream_server.py" --port "$UPSTREAM_PORT" --workers "$UPSTREAM_WORKERS" >"$UPSTREAM_LOG" 2>&1 &
UPSTREAM_PID=$!

cat >"$CONF_FILE" <<EOF
pid ${PID_FILE};
listen ${LISTEN_PORT};
metrics_path /status/metrics;
proxy_streaming_mode response;

location = /health {
    return 200 ok;
}

location = /proxy/health {
    proxy_pass http://127.0.0.1:${UPSTREAM_PORT}/health;
}

location = /proxy/buffered/health {
    proxy_pass http://127.0.0.1:${UPSTREAM_PORT}/health;
    proxy_streaming off;
}

location = /proxy/payload-1m.bin {
    proxy_pass http://127.0.0.1:${UPSTREAM_PORT}/payload-1m.bin;
}

location = /proxy/slow {
    proxy_pass http://127.0.0.1:${UPSTREAM_PORT}/slow;
}
EOF

wait_for_http() {
    local url="$1" attempts=60 i
    for ((i = 0; i < attempts; i += 1)); do
        curl -fsS "$url" >/dev/null 2>&1 && return 0
        sleep 0.2
    done
    echo "Timed out waiting for ${url}" >&2
    return 1
}

wait_for_http "http://127.0.0.1:${UPSTREAM_PORT}/health"

echo "==> Starting tardi (${GIT_SHA}, sha256 ${BIN_SHA256}) on 127.0.0.1:${LISTEN_PORT}"
TARDIGRADE_RATE_LIMIT_RPS=0 "$TARDIGRADE_BIN" -c "$CONF_FILE" >"$TARDI_LOG" 2>&1 &
TARDI_PID=$!
wait_for_http "http://127.0.0.1:${LISTEN_PORT}/health"

metrics_snapshot() {
    curl -fsS "http://127.0.0.1:${LISTEN_PORT}/status/metrics" 2>/dev/null || true
}

metric_sum() {
    # sum all series (across shard/upstream labels) matching a metric name prefix
    local name="$1" text="$2"
    awk -v name="$name" '
        $0 ~ "^" name "(\\{|[ ]|$)" {
            v = $NF
            if (v ~ /^[0-9.eE+-]+$/) sum += v
        }
        END { printf "%.0f", sum + 0 }
    ' <<<"$text"
}

run_row() {
    local scenario="$1" delay="$2" rep="$3" path="$4"
    local out_json="${OUT_DIR}/delay${delay}ms-${scenario}-rep${rep}.json"
    local before after raw summary_json
    before="$(metrics_snapshot)"
    local extra_hdr=()
    [[ "$scenario" == "close" ]] && extra_hdr=(-H "Connection: close")

    raw=$(wrk --latency -s "${BENCH_DIR}/wrk-summary.lua" \
        -t"${THREADS}" -c"${CONNECTIONS}" -d"${DURATION}s" \
        "${extra_hdr[@]}" \
        "http://127.0.0.1:${LISTEN_PORT}${path}" 2>&1) || true
    after="$(metrics_snapshot)"

    summary_json=$(printf '%s\n' "$raw" | sed -n 's/^WRK_SUMMARY //p' | tail -1)
    if [[ -z "$summary_json" ]]; then
        echo "wrk did not emit a summary for ${scenario} @ ${delay}ms rep ${rep}:" >&2
        echo "$raw" >&2
        return 1
    fi

    local accepts_before accepts_after requests_before requests_after
    local up_new_before up_new_after up_reused_before up_reused_after
    accepts_before="$(metric_sum tardigrade_accepts_total "$before")"
    accepts_after="$(metric_sum tardigrade_accepts_total "$after")"
    requests_before="$(metric_sum tardigrade_requests_total "$before")"
    requests_after="$(metric_sum tardigrade_requests_total "$after")"
    up_new_before="$(metric_sum tardigrade_upstream_pool_connections_new_total "$before")"
    up_new_after="$(metric_sum tardigrade_upstream_pool_connections_new_total "$after")"
    up_reused_before="$(metric_sum tardigrade_upstream_pool_connections_reused_total "$before")"
    up_reused_after="$(metric_sum tardigrade_upstream_pool_connections_reused_total "$after")"

    jq -n \
        --arg scenario "$scenario" \
        --argjson delay_ms "$delay" \
        --argjson rep "$rep" \
        --argjson summary "$summary_json" \
        --argjson accepts_delta "$((accepts_after - accepts_before))" \
        --argjson requests_delta "$((requests_after - requests_before))" \
        --argjson upstream_new_delta "$((up_new_after - up_new_before))" \
        --argjson upstream_reused_delta "$((up_reused_after - up_reused_before))" \
        '{
            scenario: $scenario,
            delay_ms: $delay_ms,
            rep: $rep,
            rps: $summary.rps,
            p50_ms: $summary.p50_ms,
            p95_ms: $summary.p95_ms,
            p99_ms: $summary.p99_ms,
            p999_ms: $summary.p999_ms,
            errors: $summary.errors,
            throughput_mbps: $summary.throughput_mbps,
            downstream_accepts_delta: $accepts_delta,
            downstream_requests_delta: $requests_delta,
            downstream_churn_pct: (if $requests_delta > 0 then ($accepts_delta / $requests_delta * 100) else null end),
            upstream_connections_new_delta: $upstream_new_delta,
            upstream_connections_reused_delta: $upstream_reused_delta
        }' >"$out_json"
    echo "    ${scenario} @ ${delay}ms rep ${rep}: $(jq -r '"\(.rps) req/s, p99=\(.p99_ms)ms, errors=\(.errors), churn=\(.downstream_churn_pct)%"' "$out_json")"
}

IFS=',' read -r -a DELAY_LIST <<<"$DELAYS"

for delay in "${DELAY_LIST[@]}"; do
    echo "==> Delay: ${delay}ms"
    TC_APPLIED=false
    if [[ "$delay" != "0" ]]; then
        TC_ADD=(tc qdisc add dev lo root netem delay "${delay}ms")
        if [[ $EUID -ne 0 ]]; then TC_ADD=(sudo "${TC_ADD[@]}"); fi
        if ! "${TC_ADD[@]}" 2>"${OUT_DIR}/tc-err-${delay}.log"; then
            echo "Failed to apply tc netem delay=${delay}ms (need root/CAP_NET_ADMIN):" >&2
            cat "${OUT_DIR}/tc-err-${delay}.log" >&2
            echo "SCENARIO NOT EXECUTED for delay=${delay}ms." >&2
            continue
        fi
        TC_APPLIED=true
    fi

    for rep in $(seq 1 "$REPS"); do
        run_row normal   "$delay" "$rep" "/proxy/health"
        run_row close    "$delay" "$rep" "/proxy/health"
        run_row buffered "$delay" "$rep" "/proxy/buffered/health"
        run_row static   "$delay" "$rep" "/health"
        run_row large    "$delay" "$rep" "/proxy/payload-1m.bin"
        run_row slow     "$delay" "$rep" "/proxy/slow?ms=200"
    done

    if $TC_APPLIED; then
        TC_DEL=(tc qdisc del dev lo root netem)
        if [[ $EUID -ne 0 ]]; then TC_DEL=(sudo "${TC_DEL[@]}"); fi
        "${TC_DEL[@]}" >/dev/null 2>&1 || echo "WARNING: failed to remove netem qdisc from lo after delay=${delay}ms" >&2
    fi
done

# ── Aggregate REPORT.md ──────────────────────────────────────────────────
REPORT="${OUT_DIR}/REPORT.md"
{
    echo "# RTT-sensitive streaming proxy regression report"
    echo
    echo "Generated $(date -u +%Y-%m-%dT%H:%M:%SZ) by \`benchmarks/competitive/rtt-streaming-regression.sh\`."
    echo
    echo "- commit: \`${GIT_SHA}\`"
    echo "- binary sha256: \`${BIN_SHA256}\`"
    echo "- wrk: \`-t${THREADS} -c${CONNECTIONS} -d${DURATION}s\`, ${REPS} rep(s) per cell"
    echo
    echo "| delay (ms) | scenario | req/s (mean) | p50 (ms) | p99 (ms) | errors (sum) | downstream churn % (mean) |"
    echo "|---:|---|---:|---:|---:|---:|---:|"
    for delay in "${DELAY_LIST[@]}"; do
        for scenario in normal close buffered static large slow; do
            files=("${OUT_DIR}/delay${delay}ms-${scenario}-rep"*.json)
            [[ -e "${files[0]}" ]] || continue
            jq -s '{
                rps: (map(.rps) | add / length),
                p50: (map(.p50_ms) | add / length),
                p99: (map(.p99_ms) | add / length),
                errors: (map(.errors) | add),
                churn: (map(.downstream_churn_pct // 0) | add / length)
            }' "${files[@]}" | jq -r --arg d "$delay" --arg s "$scenario" \
                '"| \($d) | \($s) | \(.rps|round) | \((.p50*10|round)/10) | \((.p99*10|round)/10) | \(.errors) | \((.churn*10|round)/10) |"'
        done
    done
} >"$REPORT"

echo "==> Report written to ${REPORT}"

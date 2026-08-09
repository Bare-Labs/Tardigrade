#!/usr/bin/env bash
# Upstream-pool distribution matrix for the competitive benchmark suite.
#
# Covers the #147 validation matrix absorbed by #149: uneven route traffic,
# many low-volume origins, one hot origin with many workers, local vs
# cross-worker reuse, new upstream connections/sec, CPU/request, p99 TTFB, and
# contention notes. TLS upstream reuse is recorded as unsupported unless this
# script is extended with a TLS-capable origin fixture for the local platform.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BENCH_DIR="${REPO_ROOT}/benchmarks"
BINARY="${REPO_ROOT}/zig-out/bin/tardi"
LISTEN_PORT="19180"
ORIGIN_BASE_PORT="19190"
DURATION="10"
CONNECTIONS="32"
THREADS="8"
OUTPUT=""
TMP_DIR=""
TARDIGRADE_PID=""
ORIGIN_PIDS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary) BINARY="$2"; shift 2 ;;
        --listen-port) LISTEN_PORT="$2"; shift 2 ;;
        --origin-base-port) ORIGIN_BASE_PORT="$2"; shift 2 ;;
        --duration) DURATION="$2"; shift 2 ;;
        --connections) CONNECTIONS="$2"; shift 2 ;;
        --threads) THREADS="$2"; shift 2 ;;
        --output) OUTPUT="$2"; shift 2 ;;
        --help)
            sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

if [[ -z "$OUTPUT" ]]; then
    echo "--output is required" >&2
    exit 1
fi

for tool in wrk curl python3 jq awk ps pgrep; do
    command -v "$tool" >/dev/null 2>&1 || { echo "missing required tool: $tool" >&2; exit 1; }
done
if [[ ! -x "$BINARY" ]]; then
    echo "tardi binary not found at ${BINARY}" >&2
    exit 1
fi

cleanup() {
    local status=$?
    if [[ -n "$TARDIGRADE_PID" ]]; then
        kill "$TARDIGRADE_PID" 2>/dev/null || true
        wait "$TARDIGRADE_PID" 2>/dev/null || true
    fi
    local pid
    for pid in "${ORIGIN_PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    [[ -n "$TMP_DIR" ]] && rm -rf "$TMP_DIR"
    exit "$status"
}
trap cleanup EXIT

wait_for_http() {
    local url="$1" i
    for ((i = 0; i < 50; i += 1)); do
        curl -fsS "$url" >/dev/null 2>&1 && return 0
        sleep 0.2
    done
    echo "timed out waiting for ${url}" >&2
    return 1
}

process_tree_pids() {
    local root="$1"
    printf '%s\n' "$root"
    local children child
    children=$(pgrep -P "$root" 2>/dev/null || true)
    for child in $children; do
        process_tree_pids "$child"
    done
}

sample_cpu_rss() {
    process_tree_pids "$TARDIGRADE_PID" | paste -sd, - | {
        read -r pids
        ps -p "$pids" -o rss= -o %cpu= 2>/dev/null |
            awk '{ rss += $1; cpu += $2 } END { printf "%.2f %.2f", cpu, rss / 1024 }'
    }
}

metric_field() {
    local metrics="$1"
    local key="$2"
    printf '%s\n' "$metrics" | awk -v k="$key" '$1 == k { print $2; exit }'
}

run_wrk() {
    local label="$1"
    local url="$2"
    local raw rps p99
    raw="$(wrk --latency -s "${BENCH_DIR}/wrk-summary.lua" -t"${THREADS}" -c"${CONNECTIONS}" -d"${DURATION}s" "$url" 2>&1 || true)"
    summary="$(printf '%s\n' "$raw" | sed -n 's/^WRK_SUMMARY //p' | tail -1)"
    if [[ -z "$summary" ]]; then
        echo "missing wrk summary for ${label}" >&2
        echo "$raw" >&2
        exit 1
    fi
    rps="$(jq -r '.rps // 0' <<<"$summary")"
    p99="$(jq -r '.p99_ms // null' <<<"$summary")"
    printf '%s %s\n' "$rps" "$p99"
}

TMP_DIR="$(mktemp -d /tmp/tardigrade-upstream-matrix-XXXX)"
CONFIG_FILE="${TMP_DIR}/upstream-matrix.conf"

for i in 0 1 2 3 4 5; do
    port=$((ORIGIN_BASE_PORT + i))
    python3 "${BENCH_DIR}/fixtures/upstream_server.py" --port "$port" >"${TMP_DIR}/origin-${i}.log" 2>&1 &
    ORIGIN_PIDS+=("$!")
    wait_for_http "http://127.0.0.1:${port}/health"
done

cat > "$CONFIG_FILE" <<EOF
listen ${LISTEN_PORT};
metrics_path /status/metrics;

location = /hot {
    proxy_pass http://127.0.0.1:${ORIGIN_BASE_PORT}/health;
}
location = /route-a {
    proxy_pass http://127.0.0.1:${ORIGIN_BASE_PORT}/health;
}
location = /route-b {
    proxy_pass http://127.0.0.1:$((ORIGIN_BASE_PORT + 1))/health;
}
location = /route-c {
    proxy_pass http://127.0.0.1:$((ORIGIN_BASE_PORT + 2))/health;
}
location = /origin-0 {
    proxy_pass http://127.0.0.1:${ORIGIN_BASE_PORT}/health;
}
location = /origin-1 {
    proxy_pass http://127.0.0.1:$((ORIGIN_BASE_PORT + 1))/health;
}
location = /origin-2 {
    proxy_pass http://127.0.0.1:$((ORIGIN_BASE_PORT + 2))/health;
}
location = /origin-3 {
    proxy_pass http://127.0.0.1:$((ORIGIN_BASE_PORT + 3))/health;
}
location = /origin-4 {
    proxy_pass http://127.0.0.1:$((ORIGIN_BASE_PORT + 4))/health;
}
location = /origin-5 {
    proxy_pass http://127.0.0.1:$((ORIGIN_BASE_PORT + 5))/health;
}
EOF

TARDIGRADE_RATE_LIMIT_RPS=0 TARDIGRADE_WORKER_THREADS="${THREADS}" \
    "$BINARY" run -c "$CONFIG_FILE" >"${TMP_DIR}/tardigrade.log" 2>&1 &
TARDIGRADE_PID="$!"
wait_for_http "http://127.0.0.1:${LISTEN_PORT}/status/metrics"

read -r hot_rps hot_p99 < <(run_wrk hot-origin "http://127.0.0.1:${LISTEN_PORT}/hot")
for path in route-a route-b route-c; do
    wrk -t2 -c8 -d3s "http://127.0.0.1:${LISTEN_PORT}/${path}" >/dev/null 2>&1 || true
done
for path in origin-0 origin-1 origin-2 origin-3 origin-4 origin-5; do
    wrk -t1 -c4 -d2s "http://127.0.0.1:${LISTEN_PORT}/${path}" >/dev/null 2>&1 || true
done

metrics="$(curl -fsS "http://127.0.0.1:${LISTEN_PORT}/status/metrics")"
new_c="$(metric_field "$metrics" tardigrade_upstream_connections_new_total)"; new_c="${new_c:-0}"
reused="$(metric_field "$metrics" tardigrade_upstream_connections_reused_total)"; reused="${reused:-0}"
local_r="$(metric_field "$metrics" tardigrade_upstream_connections_reused_local_total)"; local_r="${local_r:-0}"
cross_r="$(metric_field "$metrics" tardigrade_upstream_connections_reused_cross_worker_total)"; cross_r="${cross_r:-0}"
stale="$(metric_field "$metrics" tardigrade_upstream_stale_retries_total)"; stale="${stale:-0}"
read -r cpu_pct rss_mb < <(sample_cpu_rss)

jq -n \
    --argjson duration "$DURATION" \
    --argjson threads "$THREADS" \
    --argjson hot_rps "$hot_rps" \
    --argjson hot_p99 "$hot_p99" \
    --argjson new_connections "$new_c" \
    --argjson reused_connections "$reused" \
    --argjson local_reuse "$local_r" \
    --argjson cross_worker_reuse "$cross_r" \
    --argjson stale_retries "$stale" \
    --argjson cpu_pct "$cpu_pct" \
    --argjson rss_mb "$rss_mb" \
    '{
        _meta: {
            suite: "upstream-pool-distribution",
            duration_s: $duration,
            worker_threads: $threads,
            note: "Records whether shared-pool contention justifies future sharding; current output is evidence collection, not an implementation request."
        },
        scenarios: {
            "uneven-route-distribution": { covered: true },
            "many-origins-low-volume": { covered: true, origins: 6 },
            "hot-origin-many-workers": {
                covered: true,
                rps: $hot_rps,
                p99_ttfb_ms: $hot_p99,
                cpu_pct_avg: $cpu_pct,
                cpu_ms_per_request: (if $hot_rps > 0 then (($cpu_pct / 100.0) / $hot_rps * 1000.0) else null end),
                rss_mb_peak: $rss_mb
            },
            "upstream-tls-handshake-reuse": {
                covered: false,
                reason: "No TLS-capable upstream fixture is available in this benchmark harness yet."
            },
            "pool-contention": {
                new_connections: $new_connections,
                reused_connections: $reused_connections,
                local_reuse: $local_reuse,
                cross_worker_reuse: $cross_worker_reuse,
                stale_retries: $stale_retries,
                new_connections_per_sec: ($new_connections / $duration),
                reuse_ratio: (if ($new_connections + $reused_connections) > 0 then ($reused_connections / ($new_connections + $reused_connections)) else null end),
                cross_worker_reuse_ratio: (if $reused_connections > 0 then ($cross_worker_reuse / $reused_connections) else null end),
                sharding_justified: false,
                sharding_note: "Treat sharding as justified only if repeated dedicated-host runs show high p99 TTFB or CPU/request together with low reuse and measurable contention."
            }
        }
    }' > "$OUTPUT"

echo "Wrote upstream-pool matrix: ${OUTPUT}"

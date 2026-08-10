#!/usr/bin/env bash
# Reusable listener-sharding benchmark suite (#137).
#
# Starts the gateway twice from the same command, first with
# TARDIGRADE_LISTENER_SHARDS=1 and then with =N, runs the same workloads against
# both profiles, scrapes accept/worker metrics, and saves comparable artifacts.
#
# Usage:
#   ./benchmarks/listener-sharding.sh --start-command './zig-out/bin/tardigrade -c ./edge.conf'
#
# The start command must run the gateway in the foreground. This wrapper supplies
# TARDIGRADE_LISTENER_SHARDS, TARDIGRADE_RATE_LIMIT_RPS=0, and
# TARDIGRADE_PID_FILE for each profile.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BENCH_DIR="${REPO_ROOT}/benchmarks"

HOST="127.0.0.1"
PORT="8069"
HOST_HEADER=""
SHARDS="4"
DURATION="30"
CONNECTIONS="50"
THREADS="4"
STATIC_PATH="/health"
PROXY_PATH="/proxy/health"
KEEPALIVE_PATH="/health"
SCENARIOS="static-http1,proxy-http1,keepalive"
TOOL="wrk"
START_COMMAND=""
SAVE_DIR=""
WAIT_SECONDS="10"
SAMPLE_INTERVAL_MS="500"

usage() {
    sed -n '/^# Usage:/,/^$/p' "$0"
    cat <<'EOF'
Options:
  --start-command CMD    Foreground gateway command to run for each profile (required)
  --host HOST            Target host (default: 127.0.0.1)
  --port PORT            Target port (default: 8069)
  --host-header NAME     Override Host header for benchmark requests
  --shards N             Sharded profile count (default: 4)
  --duration SECS        Seconds per workload (default: 30)
  --connections N        Concurrent wrk connections (default: 50)
  --threads N            wrk worker threads (default: 4)
  --static-path PATH     Static workload path (default: /health)
  --proxy-path PATH      Proxy workload path (default: /proxy/health)
  --keepalive-path PATH  Keepalive workload path (default: /health)
  --scenarios LIST       Standard run.sh scenarios (default: static-http1,proxy-http1,keepalive)
  --save-dir DIR         Artifact directory (default: benchmarks/results/<date>/listener-sharding-<timestamp>)
  --wait-seconds N       Startup wait timeout (default: 10)
  --sample-interval-ms N CPU/RSS sample interval passed to run.sh (default: 500)
  --help                 Show this help

Saved artifacts:
  summary.json                        Combined 1-vs-N summary
  <profile>-run.json                  benchmarks/run.sh output
  <profile>-metrics.prom              Full Prometheus scrape after workloads
  <profile>-connection-churn.wrk.txt  Raw Connection: close wrk output
  <profile>-mixed-static-proxy.wrk.txt Raw mixed static/proxy wrk output
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --start-command) START_COMMAND="$2"; shift 2 ;;
        --host) HOST="$2"; shift 2 ;;
        --port) PORT="$2"; shift 2 ;;
        --host-header) HOST_HEADER="$2"; shift 2 ;;
        --shards) SHARDS="$2"; shift 2 ;;
        --duration) DURATION="$2"; shift 2 ;;
        --connections) CONNECTIONS="$2"; shift 2 ;;
        --threads) THREADS="$2"; shift 2 ;;
        --static-path) STATIC_PATH="$2"; shift 2 ;;
        --proxy-path) PROXY_PATH="$2"; shift 2 ;;
        --keepalive-path) KEEPALIVE_PATH="$2"; shift 2 ;;
        --scenarios) SCENARIOS="$2"; shift 2 ;;
        --save-dir) SAVE_DIR="$2"; shift 2 ;;
        --wait-seconds) WAIT_SECONDS="$2"; shift 2 ;;
        --sample-interval-ms) SAMPLE_INTERVAL_MS="$2"; shift 2 ;;
        --help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
    esac
done

if [[ -z "$START_COMMAND" ]]; then
    echo "--start-command is required so the wrapper can restart the gateway with each shard count." >&2
    exit 1
fi

for tool in curl jq wrk; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Required tool not found: $tool" >&2
        exit 1
    fi
done

if [[ -z "$SAVE_DIR" ]]; then
    SAVE_DIR="${BENCH_DIR}/results/$(date -u +%Y-%m-%d)/listener-sharding-$(date -u +%Y%m%dT%H%M%SZ)"
fi
mkdir -p "$SAVE_DIR"

BASE_URL="http://${HOST}:${PORT}"
HEADER_ARGS=()
if [[ -n "$HOST_HEADER" ]]; then
    HEADER_ARGS=(-H "Host: ${HOST_HEADER}")
fi

gateway_pid=""
profile_tmp=""

cleanup_gateway() {
    if [[ -n "${gateway_pid}" ]] && kill -0 "$gateway_pid" >/dev/null 2>&1; then
        kill "$gateway_pid" >/dev/null 2>&1 || true
        wait "$gateway_pid" >/dev/null 2>&1 || true
    fi
    gateway_pid=""
    if [[ -n "${profile_tmp}" && -d "${profile_tmp}" ]]; then
        rm -rf "$profile_tmp"
    fi
    profile_tmp=""
}
trap cleanup_gateway EXIT

wait_for_ready() {
    local deadline=$((SECONDS + WAIT_SECONDS))
    until curl -fsS --max-time 1 "${HEADER_ARGS[@]}" "${BASE_URL}/status/metrics" >/dev/null 2>&1; do
        if (( SECONDS >= deadline )); then
            echo "Gateway did not become ready at ${BASE_URL}/status/metrics within ${WAIT_SECONDS}s" >&2
            return 1
        fi
        sleep 0.2
    done
}

wrk_error_count() {
    awk '
        /Socket errors:/ {
            for (i = 1; i <= NF; i++) {
                if ($i ~ /[0-9]+/) {
                    gsub(/[^0-9]/, "", $i);
                    total += $i;
                }
            }
        }
        /Non-2xx or 3xx responses:/ { total += $NF }
        END { print total + 0 }
    '
}

wrk_latency_ms() {
    local percentile="$1"
    awk -v pct="$percentile" '
        $1 == pct {
            v = $2
            if (v ~ /us$/) { sub(/us$/, "", v); printf "%.3f\n", v / 1000; exit }
            if (v ~ /ms$/) { sub(/ms$/, "", v); printf "%.3f\n", v; exit }
            if (v ~ /s$/) { sub(/s$/, "", v); printf "%.3f\n", v * 1000; exit }
            printf "%.3f\n", v; exit
        }
    '
}

wrk_result_json() {
    local raw_file="$1"
    local rps p50 p95 p99 p999 errors
    rps="$(awk '/Requests\/sec:/ { gsub(/,/, "", $2); print $2; exit }' "$raw_file")"
    p50="$(wrk_latency_ms "50%" < "$raw_file")"
    p95="$(wrk_latency_ms "95%" < "$raw_file")"
    p99="$(wrk_latency_ms "99%" < "$raw_file")"
    p999="$(wrk_latency_ms "99.9%" < "$raw_file")"
    errors="$(wrk_error_count < "$raw_file")"
    jq -n \
        --argjson rps "${rps:-0}" \
        --argjson p50 "${p50:-0}" \
        --argjson p95 "${p95:-0}" \
        --argjson p99 "${p99:-0}" \
        --argjson p999 "${p999:-0}" \
        --argjson errors "${errors:-0}" \
        '{rps: $rps, p50_ms: $p50, p95_ms: $p95, p99_ms: $p99, p999_ms: $p999, errors: $errors}'
}

metrics_json() {
    local metrics_file="$1"
    jq -Rn '
        def num: tonumber? // 0;
        reduce inputs as $line ({
            listener_shards: 0,
            accepts_total: [],
            accept_errors_total: [],
            worker_queued_jobs: 0,
            worker_queue_wait_us_count: 0,
            worker_queue_wait_us_sum: 0
        };
            if ($line | test("^tardigrade_listener_shards ")) then
                .listener_shards = ($line | split(" ")[1] | num)
            elif ($line | test("^tardigrade_accepts_total\\{")) then
                .accepts_total += [{
                    shard: ($line | capture("shard=\"(?<shard>[0-9]+)\"").shard | tonumber),
                    value: ($line | split(" ")[1] | num)
                }]
            elif ($line | test("^tardigrade_accept_errors_total\\{")) then
                .accept_errors_total += [{
                    shard: ($line | capture("shard=\"(?<shard>[0-9]+)\"").shard | tonumber),
                    reason: ($line | capture("reason=\"(?<reason>[^\"]+)\"").reason),
                    value: ($line | split(" ")[1] | num)
                }]
            elif ($line | test("^tardigrade_worker_queued_jobs ")) then
                .worker_queued_jobs = ($line | split(" ")[1] | num)
            elif ($line | test("^tardigrade_worker_queue_wait_us_count ")) then
                .worker_queue_wait_us_count = ($line | split(" ")[1] | num)
            elif ($line | test("^tardigrade_worker_queue_wait_us_sum ")) then
                .worker_queue_wait_us_sum = ($line | split(" ")[1] | num)
            else . end
        )
    ' < "$metrics_file"
}

run_wrk_workload() {
    local label="$1"
    local output="$2"
    shift 2
    wrk --latency -t"${THREADS}" -c"${CONNECTIONS}" -d"${DURATION}s" "$@" >"$output" 2>&1 || true
    echo "  ${label}: $(awk '/Requests\/sec:/ {print $2; exit}' "$output") req/s, p99=$(wrk_latency_ms "99%" < "$output")ms, errors=$(wrk_error_count < "$output")" >&2
}

run_profile() {
    local label="$1"
    local shard_count="$2"
    local pid_file="${SAVE_DIR}/${label}.pid"
    local run_json="${SAVE_DIR}/${label}-run.json"
    local run_log="${SAVE_DIR}/${label}-run.log"
    local metrics_file="${SAVE_DIR}/${label}-metrics.prom"
    local churn_raw="${SAVE_DIR}/${label}-connection-churn.wrk.txt"
    local mixed_raw="${SAVE_DIR}/${label}-mixed-static-proxy.wrk.txt"
    local mixed_lua="${SAVE_DIR}/${label}-mixed-static-proxy.lua"

    cleanup_gateway
    profile_tmp="$(mktemp -d)"

    echo "==> Starting ${label} profile with TARDIGRADE_LISTENER_SHARDS=${shard_count}" >&2
    (
        export TARDIGRADE_LISTENER_SHARDS="${shard_count}"
        export TARDIGRADE_RATE_LIMIT_RPS="0"
        export TARDIGRADE_PID_FILE="${pid_file}"
        export TMPDIR="${profile_tmp}"
        exec sh -c "$START_COMMAND"
    ) &
    gateway_pid="$!"
    echo "$gateway_pid" > "$pid_file"
    wait_for_ready

    echo "==> ${label}: standard scenarios (${SCENARIOS})" >&2
    local -a run_args=(
        --host "$HOST" \
        --port "$PORT" \
        --driver "listener-sharding-${label}" \
        --worker-count "${TARDIGRADE_WORKER_THREADS:-}" \
        --config-label "listener-sharding ${label} (${shard_count} shards)" \
        --pid "$gateway_pid" \
        --tool "$TOOL" \
        --duration "$DURATION" \
        --connections "$CONNECTIONS" \
        --threads "$THREADS" \
        --static-path "$STATIC_PATH" \
        --proxy-path "$PROXY_PATH" \
        --keepalive-path "$KEEPALIVE_PATH" \
        --scenarios "$SCENARIOS" \
        --sample-interval-ms "$SAMPLE_INTERVAL_MS" \
        --save "$run_json"
    )
    if [[ -n "$HOST_HEADER" ]]; then
        run_args+=(--host-header "$HOST_HEADER")
    fi
    "${BENCH_DIR}/run.sh" "${run_args[@]}" >"$run_log" 2>&1

    echo "==> ${label}: high connection churn (${STATIC_PATH}, Connection: close)" >&2
    run_wrk_workload "connection-churn-http1" "$churn_raw" "${HEADER_ARGS[@]}" -H "Connection: close" "${BASE_URL}${STATIC_PATH}"

    cat > "$mixed_lua" <<EOF
local static_path = "${STATIC_PATH}"
local proxy_path = "${PROXY_PATH}"
local counter = 0
request = function()
  counter = counter + 1
  if counter % 2 == 0 then
    return wrk.format("GET", static_path)
  end
  return wrk.format("GET", proxy_path)
end
EOF

    echo "==> ${label}: mixed short static/proxy (${STATIC_PATH} + ${PROXY_PATH}, Connection: close)" >&2
    run_wrk_workload "mixed-short-static-proxy" "$mixed_raw" -s "$mixed_lua" "${HEADER_ARGS[@]}" -H "Connection: close" "${BASE_URL}${STATIC_PATH}"

    curl -fsS "${HEADER_ARGS[@]}" "${BASE_URL}/status/metrics" > "$metrics_file"

    local standard_json churn_json mixed_json metric_json
    standard_json="$(cat "$run_json")"
    churn_json="$(wrk_result_json "$churn_raw")"
    mixed_json="$(wrk_result_json "$mixed_raw")"
    metric_json="$(metrics_json "$metrics_file")"

    jq -n \
        --arg label "$label" \
        --argjson shards "$shard_count" \
        --arg run_json "$run_json" \
        --arg run_log "$run_log" \
        --arg metrics_file "$metrics_file" \
        --arg churn_raw "$churn_raw" \
        --arg mixed_raw "$mixed_raw" \
        --argjson standard "$standard_json" \
        --argjson churn "$churn_json" \
        --argjson mixed "$mixed_json" \
        --argjson metrics "$metric_json" \
        '{label: $label, shards: $shards, artifacts: {standard_json: $run_json, standard_log: $run_log, metrics_prom: $metrics_file, connection_churn_wrk: $churn_raw, mixed_static_proxy_wrk: $mixed_raw}, standard: $standard, "connection-churn-http1": $churn, "mixed-short-static-proxy": $mixed, metrics: $metrics}'

    cleanup_gateway
}

single_json="$(run_profile "single" 1)"
sharded_json="$(run_profile "sharded" "$SHARDS")"

summary_file="${SAVE_DIR}/summary.json"
jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg tag "$(git -C "$REPO_ROOT" describe --tags --always --dirty 2>/dev/null || echo unknown)" \
    --arg host "$HOST" \
    --argjson port "$PORT" \
    --argjson duration "$DURATION" \
    --argjson connections "$CONNECTIONS" \
    --argjson threads "$THREADS" \
    --arg static_path "$STATIC_PATH" \
    --arg proxy_path "$PROXY_PATH" \
    --arg keepalive_path "$KEEPALIVE_PATH" \
    --arg save_dir "$SAVE_DIR" \
    --argjson single "$single_json" \
    --argjson sharded "$sharded_json" \
    '{
        _meta: {
            generated_at: $generated_at,
            tag: $tag,
            suite: "listener-sharding",
            host: $host,
            port: $port,
            duration_s: $duration,
            connections: $connections,
            threads: $threads,
            static_path: $static_path,
            proxy_path: $proxy_path,
            keepalive_path: $keepalive_path,
            save_dir: $save_dir,
            workloads: ["static-http1", "proxy-http1", "keepalive", "connection-churn-http1", "mixed-short-static-proxy"],
            metrics: ["req/s", "p50_ms", "p95_ms", "p99_ms", "p999_ms", "cpu_pct_avg", "rss_mb_peak", "accept_errors_total", "worker_queued_jobs", "worker_queue_wait_us_count", "worker_queue_wait_us_sum", "per-shard accepts_total"]
        },
        single: $single,
        sharded: $sharded
    }' > "$summary_file"

echo ""
echo "Listener-sharding benchmark artifacts saved under: ${SAVE_DIR}"
echo "Combined summary: ${summary_file}"

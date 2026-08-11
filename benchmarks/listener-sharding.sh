#!/usr/bin/env bash
# Reusable listener-sharding / accept-batching benchmark suite (#137, #146).
#
# Starts the gateway for comparable listener/accept profiles, runs the same
# workloads against each profile, scrapes accept/worker metrics, and saves
# comparable artifacts.
#
# Usage:
#   ./benchmarks/listener-sharding.sh --start-command './zig-out/bin/tardigrade -c ./edge.conf'
#
# The start command must run the gateway in the foreground. This wrapper supplies
# TARDIGRADE_LISTENER_SHARDS, TARDIGRADE_ACCEPT_BATCH_LIMIT,
# TARDIGRADE_ACCEPT_FAIRNESS_YIELD_EVERY, TARDIGRADE_RATE_LIMIT_RPS=0, and
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
BURST_CONNECTIONS=""
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
RECOVERY_SECONDS="5"

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
  --burst-connections N  Concurrent connections for burst workload (default: 4x --connections)
  --threads N            wrk worker threads (default: 4)
  --static-path PATH     Static workload path (default: /health)
  --proxy-path PATH      Proxy workload path (default: /proxy/health)
  --keepalive-path PATH  Keepalive workload path (default: /health)
  --scenarios LIST       Standard run.sh scenarios (default: static-http1,proxy-http1,keepalive)
  --save-dir DIR         Artifact directory (default: benchmarks/results/<date>/listener-sharding-<timestamp>)
  --wait-seconds N       Startup wait timeout (default: 10)
  --sample-interval-ms N CPU/RSS sample interval passed to run.sh (default: 500)
  --recovery-seconds N   Pause after close-connection workloads (default: 5)
  --help                 Show this help

Saved artifacts:
  summary.json                        Combined accept-batching summary
  <profile>-run.json                  benchmarks/run.sh output
  <profile>-startup-metrics.prom      Metrics scrape used to verify shard topology
  <profile>-metrics.prom              Full Prometheus scrape after workloads
  <profile>-connection-churn.wrk.txt  Raw Connection: close wrk output
  <profile>-connection-churn-queue.samples  Worker queue samples during churn
  <profile>-connection-burst.wrk.txt  Raw high-concurrency Connection: close burst output
  <profile>-connection-burst-queue.samples Worker queue samples during burst
  <profile>-mixed-keepalive-churn-keepalive.wrk.txt Background keepalive half of mixed workload
  <profile>-mixed-keepalive-churn-churn.wrk.txt Connection-churn half of mixed workload
  <profile>-mixed-keepalive-churn-queue.samples Worker queue samples during mixed load
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
        --burst-connections) BURST_CONNECTIONS="$2"; shift 2 ;;
        --threads) THREADS="$2"; shift 2 ;;
        --static-path) STATIC_PATH="$2"; shift 2 ;;
        --proxy-path) PROXY_PATH="$2"; shift 2 ;;
        --keepalive-path) KEEPALIVE_PATH="$2"; shift 2 ;;
        --scenarios) SCENARIOS="$2"; shift 2 ;;
        --save-dir) SAVE_DIR="$2"; shift 2 ;;
        --wait-seconds) WAIT_SECONDS="$2"; shift 2 ;;
        --sample-interval-ms) SAMPLE_INTERVAL_MS="$2"; shift 2 ;;
        --recovery-seconds) RECOVERY_SECONDS="$2"; shift 2 ;;
        --help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
    esac
done

if [[ -z "$START_COMMAND" ]]; then
    echo "--start-command is required so the wrapper can restart the gateway with each shard count." >&2
    exit 1
fi

if ! [[ "$SHARDS" =~ ^[0-9]+$ ]] || (( SHARDS < 2 || SHARDS > 64 )); then
    echo "--shards must be an integer in the range 2..64; got '${SHARDS}'." >&2
    echo "The listener-sharding suite compares the default 1-shard profile against a meaningful N-shard profile." >&2
    exit 1
fi

if [[ -z "$BURST_CONNECTIONS" ]]; then
    BURST_CONNECTIONS=$((CONNECTIONS * 4))
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
resource_monitor_pid=""
resource_monitor_file=""
resource_cpu_before="null"
resource_monitor_start_ns="null"
queue_monitor_pid=""

cleanup_gateway() {
    if [[ -n "${queue_monitor_pid}" ]]; then
        kill "$queue_monitor_pid" >/dev/null 2>&1 || true
        wait "$queue_monitor_pid" >/dev/null 2>&1 || true
        queue_monitor_pid=""
    fi
    if [[ -n "${resource_monitor_pid}" ]]; then
        kill "$resource_monitor_pid" >/dev/null 2>&1 || true
        wait "$resource_monitor_pid" >/dev/null 2>&1 || true
        resource_monitor_pid=""
    fi
    if [[ -n "${resource_monitor_file}" && -f "${resource_monitor_file}" ]]; then
        rm -f "$resource_monitor_file"
        resource_monitor_file=""
    fi
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

monotonic_ns() {
    python3 -c 'import time; print(time.monotonic_ns())'
}

cpu_time_to_seconds() {
    awk '
        function part_seconds(v, n, p) {
            n = split(v, p, ":")
            if (n == 3) return (p[1] * 3600) + (p[2] * 60) + p[3]
            if (n == 2) return (p[1] * 60) + p[2]
            return v + 0
        }
        {
            v = $1
            days = 0
            if (index(v, "-") > 0) {
                split(v, d, "-")
                days = d[1] + 0
                v = d[2]
            }
            total += days * 86400 + part_seconds(v)
        }
        END { printf "%.6f", total }
    '
}

process_cpu_seconds() {
    ps -p "$1" -o time= 2>/dev/null | cpu_time_to_seconds
}

count_open_fds() {
    local pid="$1"
    if [[ -d "/proc/${pid}/fd" ]]; then
        find "/proc/${pid}/fd" -maxdepth 1 -type l 2>/dev/null | wc -l | tr -d ' '
    elif command -v lsof >/dev/null 2>&1; then
        lsof -n -P -p "$pid" 2>/dev/null | awk 'NR > 1 { count += 1 } END { print count + 0 }'
    else
        printf 'null\n'
    fi
}

resource_sample_loop() {
    local pid="$1" outfile="$2" interval_s="$3"
    while kill -0 "$pid" >/dev/null 2>&1; do
        local rss_kb open_fds
        rss_kb="$(ps -p "$pid" -o rss= 2>/dev/null | awk 'NF >= 1 { print $1; exit }')"
        open_fds="$(count_open_fds "$pid")"
        if [[ -n "$rss_kb" ]]; then
            printf '%s %s\n' "$rss_kb" "$open_fds" >> "$outfile"
        fi
        sleep "$interval_s"
    done
}

start_resource_monitor() {
    resource_monitor_file="$(mktemp /tmp/tardigrade-listener-sharding-resource-XXXXXX)"
    resource_cpu_before="$(process_cpu_seconds "$gateway_pid")"
    resource_monitor_start_ns="$(monotonic_ns)"
    local interval_s
    interval_s="$(awk -v ms="$SAMPLE_INTERVAL_MS" 'BEGIN { printf "%.3f", ms / 1000 }')"
    resource_sample_loop "$gateway_pid" "$resource_monitor_file" "$interval_s" &
    resource_monitor_pid="$!"
}

stop_resource_monitor_json() {
    if [[ -n "$resource_monitor_pid" ]]; then
        kill "$resource_monitor_pid" >/dev/null 2>&1 || true
        wait "$resource_monitor_pid" >/dev/null 2>&1 || true
        resource_monitor_pid=""
    fi

    local cpu_after end_ns cpu_pct rss_mb open_fds
    cpu_after="$(process_cpu_seconds "$gateway_pid")"
    end_ns="$(monotonic_ns)"
    cpu_pct="$(awk -v before="$resource_cpu_before" -v after="$cpu_after" -v start="$resource_monitor_start_ns" -v end="$end_ns" '
        BEGIN {
            elapsed = (end - start) / 1000000000
            if (before != "null" && elapsed > 0) printf "%.2f", ((after - before) / elapsed) * 100
            else printf "null"
        }')"
    rss_mb="$(awk 'NF >= 1 && $1 > max { max = $1 } END { if (max > 0) printf "%.2f", max / 1024; else printf "null" }' "$resource_monitor_file")"
    open_fds="$(awk 'NF >= 2 && $2 ~ /^[0-9]+$/ && $2 > max { max = $2 } END { if (max > 0) printf "%d", max; else printf "null" }' "$resource_monitor_file")"
    rm -f "$resource_monitor_file"
    resource_monitor_file=""

    jq -n \
        --argjson cpu "$cpu_pct" \
        --argjson rss "$rss_mb" \
        --argjson fds "$open_fds" \
        '{cpu_pct_avg: $cpu, rss_mb_peak: $rss, open_fds_peak: $fds}'
}

metric_value_from_file() {
    local file="$1" metric="$2"
    awk -v metric="$metric" '$1 == metric { print $2; found = 1; exit } END { if (!found) print "null" }' "$file"
}

scrape_metrics() {
    curl -fsS "${HEADER_ARGS[@]}" "${BASE_URL}/status/metrics"
}

verify_listener_shards() {
    local expected="$1" metrics_file="$2"
    scrape_metrics > "$metrics_file"
    local actual
    actual="$(metric_value_from_file "$metrics_file" "tardigrade_listener_shards")"
    if [[ "$actual" != "$expected" ]]; then
        echo "Requested TARDIGRADE_LISTENER_SHARDS=${expected}, but gateway reports tardigrade_listener_shards=${actual}." >&2
        echo "Refusing to record this as a ${expected}-shard benchmark run." >&2
        return 1
    fi
}

queue_sample_loop() {
    local outfile="$1" interval_s="$2"
    while true; do
        local metrics queued count sum
        metrics="$(scrape_metrics 2>/dev/null || true)"
        if [[ -n "$metrics" ]]; then
            queued="$(printf '%s\n' "$metrics" | awk '$1 == "tardigrade_worker_queued_jobs" { print $2; found = 1; exit } END { if (!found) print "null" }')"
            count="$(printf '%s\n' "$metrics" | awk '$1 == "tardigrade_worker_queue_wait_us_count" { print $2; found = 1; exit } END { if (!found) print "null" }')"
            sum="$(printf '%s\n' "$metrics" | awk '$1 == "tardigrade_worker_queue_wait_us_sum" { print $2; found = 1; exit } END { if (!found) print "null" }')"
            printf '%s %s %s %s\n' "$(date -u +%s)" "$queued" "$count" "$sum" >> "$outfile"
        fi
        sleep "$interval_s"
    done
}

start_queue_monitor() {
    local outfile="$1"
    local interval_s
    interval_s="$(awk -v ms="$SAMPLE_INTERVAL_MS" 'BEGIN { printf "%.3f", ms / 1000 }')"
    queue_sample_loop "$outfile" "$interval_s" &
    queue_monitor_pid="$!"
}

stop_queue_monitor() {
    if [[ -n "$queue_monitor_pid" ]]; then
        kill "$queue_monitor_pid" >/dev/null 2>&1 || true
        wait "$queue_monitor_pid" >/dev/null 2>&1 || true
        queue_monitor_pid=""
    fi
}

queue_summary_json() {
    local samples_file="$1" before_file="$2" after_file="$3"
    local before_count before_sum after_count after_sum
    before_count="$(metric_value_from_file "$before_file" "tardigrade_worker_queue_wait_us_count")"
    before_sum="$(metric_value_from_file "$before_file" "tardigrade_worker_queue_wait_us_sum")"
    after_count="$(metric_value_from_file "$after_file" "tardigrade_worker_queue_wait_us_count")"
    after_sum="$(metric_value_from_file "$after_file" "tardigrade_worker_queue_wait_us_sum")"

    local peak
    peak="$(awk 'NF >= 2 && $2 ~ /^[0-9]+$/ && $2 > max { max = $2 } END { if (max > 0) printf "%d", max; else printf "0" }' "$samples_file")"

    jq -n \
        --argjson peak "$peak" \
        --argjson before_count "$before_count" \
        --argjson after_count "$after_count" \
        --argjson before_sum "$before_sum" \
        --argjson after_sum "$after_sum" \
        '{
            worker_queued_jobs_peak: $peak,
            worker_queue_wait_us_count_delta: ($after_count - $before_count),
            worker_queue_wait_us_sum_delta: ($after_sum - $before_sum)
        }'
}

metrics_json() {
    local metrics_file="$1"
    jq -Rn '
        def num: tonumber? // 0;
        reduce inputs as $line ({
            listener_shards: 0,
            accepts_total: [],
            accept_errors_total: [],
            accept_batch_size_count: [],
            accept_batch_size_sum: [],
            accept_batches_total: [],
            accept_fairness_yields_total: [],
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
            elif ($line | test("^tardigrade_accept_batch_size_count\\{")) then
                .accept_batch_size_count += [{
                    shard: ($line | capture("shard=\"(?<shard>[0-9]+)\"").shard | tonumber),
                    value: ($line | split(" ")[1] | num)
                }]
            elif ($line | test("^tardigrade_accept_batch_size_sum\\{")) then
                .accept_batch_size_sum += [{
                    shard: ($line | capture("shard=\"(?<shard>[0-9]+)\"").shard | tonumber),
                    value: ($line | split(" ")[1] | num)
                }]
            elif ($line | test("^tardigrade_accept_batches_total\\{")) then
                .accept_batches_total += [{
                    shard: ($line | capture("shard=\"(?<shard>[0-9]+)\"").shard | tonumber),
                    value: ($line | split(" ")[1] | num)
                }]
            elif ($line | test("^tardigrade_accept_fairness_yields_total\\{")) then
                .accept_fairness_yields_total += [{
                    shard: ($line | capture("shard=\"(?<shard>[0-9]+)\"").shard | tonumber),
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

accept_delta_json() {
    local before_file="$1" after_file="$2"
    jq -n \
        --slurpfile before <(metrics_json "$before_file") \
        --slurpfile after <(metrics_json "$after_file") \
        '
        def keyed_accepts($items):
            reduce ($items // [])[] as $item ({}; .[($item.shard | tostring)] = $item.value);
        def keyed_errors($items):
            reduce ($items // [])[] as $item ({}; .[($item.shard | tostring) + ":" + $item.reason] = $item.value);
        def keyed_values($items):
            reduce ($items // [])[] as $item ({}; .[($item.shard | tostring)] = $item.value);
        def accept_delta($before; $after):
            (keyed_accepts($before.accepts_total)) as $b |
            (keyed_accepts($after.accepts_total)) as $a |
            [($a | keys_unsorted[]) as $key | {
                shard: ($key | tonumber),
                value: (($a[$key] // 0) - ($b[$key] // 0))
            }] | sort_by(.shard);
        def value_delta($before; $after; $field):
            (keyed_values($before[$field])) as $b |
            (keyed_values($after[$field])) as $a |
            [($a | keys_unsorted[]) as $key | {
                shard: ($key | tonumber),
                value: (($a[$key] // 0) - ($b[$key] // 0))
            }] | sort_by(.shard);
        def error_delta($before; $after):
            (keyed_errors($before.accept_errors_total)) as $b |
            (keyed_errors($after.accept_errors_total)) as $a |
            [($a | keys_unsorted[]) as $key |
                ($key | split(":")) as $parts |
                {
                    shard: ($parts[0] | tonumber),
                    reason: $parts[1],
                    value: (($a[$key] // 0) - ($b[$key] // 0))
                }
            ] | sort_by(.shard, .reason);

        ($before[0]) as $b |
        ($after[0]) as $a |
        {
            listener_shards: $a.listener_shards,
            accepts_total_delta: accept_delta($b; $a),
            accept_errors_total_delta: error_delta($b; $a),
            accept_batch_size_count_delta: value_delta($b; $a; "accept_batch_size_count"),
            accept_batch_size_sum_delta: value_delta($b; $a; "accept_batch_size_sum"),
            accept_batches_total_delta: value_delta($b; $a; "accept_batches_total"),
            accept_fairness_yields_total_delta: value_delta($b; $a; "accept_fairness_yields_total")
        }
        '
}

wrk_summary_json_from_file() {
    local label="$1" output="$2"
    local summary_json
    summary_json="$(sed -n 's/^WRK_SUMMARY //p' "$output" | tail -1)"
    if [[ -z "$summary_json" ]]; then
        echo "wrk summary hook did not emit percentile JSON for ${label}; raw output saved to ${output}" >&2
        return 1
    fi
    if ! jq -e '.rps and .p50_ms and .p95_ms and .p99_ms and .p999_ms and .errors and .throughput_mbps' >/dev/null <<<"$summary_json"; then
        echo "wrk summary JSON is missing required fields for ${label}; raw output saved to ${output}" >&2
        return 1
    fi
    printf '%s\n' "$summary_json"
}

validate_wrk_sample() {
    local label="$1" summary_json="$2" output="$3"
    if ! jq -e '.rps > 0 and .errors == 0' >/dev/null <<<"$summary_json"; then
        echo "${label}: invalid benchmark sample (zero throughput or client/socket errors); raw output saved to ${output}" >&2
        return 1
    fi
}

recover_after_close_workload() {
    local label="$1"
    if (( RECOVERY_SECONDS > 0 )); then
        echo "==> ${label}: waiting ${RECOVERY_SECONDS}s for close-connection recovery" >&2
        sleep "$RECOVERY_SECONDS"
    fi
}

validate_profile_accept_batching() {
    local label="$1" batch_limit="$2" fairness_yield_every="$3"
    shift 3

    local accepted batches yields
    accepted="$(printf '%s\n' "$@" | jq -s '[.[].accept_metrics.accept_batch_size_sum_delta[]?.value] | add // 0')" || return 1
    batches="$(printf '%s\n' "$@" | jq -s '[.[].accept_metrics.accept_batch_size_count_delta[]?.value] | add // 0')" || return 1
    yields="$(printf '%s\n' "$@" | jq -s '[.[].accept_metrics.accept_fairness_yields_total_delta[]?.value] | add // 0')" || return 1

    if (( batch_limit > 1 )) && (( accepted <= batches )); then
        echo "${label}: invalid benchmark sample; no readiness turn accepted more than one connection (accepted=${accepted}, batches=${batches})" >&2
        return 1
    fi
    if (( fairness_yield_every > 0 )) && (( yields <= 0 )); then
        echo "${label}: invalid benchmark sample; fairness cutoff was never exercised" >&2
        return 1
    fi
}

require_nonempty_file() {
    local path="$1"
    if [[ ! -s "$path" ]]; then
        echo "Required benchmark artifact is empty or missing: ${path}" >&2
        return 1
    fi
}

validate_profile_artifacts() {
    local file
    for file in "$@"; do
        require_nonempty_file "$file" || return 1
    done
}

run_wrk_workload() {
    local label="$1"
    local output="$2"
    local script="$3"
    local queue_samples="$4"
    shift 4
    local before_metrics="${output%.wrk.txt}-before.prom"
    local after_metrics="${output%.wrk.txt}-after.prom"
    local wrk_connections="${WRK_CONNECTIONS:-$CONNECTIONS}"

    scrape_metrics > "$before_metrics" || return 1
    start_resource_monitor || return 1
    start_queue_monitor "$queue_samples"
    if ! wrk --latency -s "$script" -t"${THREADS}" -c"${wrk_connections}" -d"${DURATION}s" "$@" >"$output" 2>&1; then
        stop_queue_monitor
        local resource_json
        resource_json="$(stop_resource_monitor_json)" || return 1
        echo "wrk failed for ${label}; raw output saved to ${output}" >&2
        jq -n --arg label "$label" --arg output "$output" --argjson resources "$resource_json" '{label: $label, raw_output: $output, resources: $resources}' >&2
        return 1
    fi
    stop_queue_monitor
    local resource_json
    resource_json="$(stop_resource_monitor_json)" || return 1
    scrape_metrics > "$after_metrics" || return 1

    local summary_json
    summary_json="$(wrk_summary_json_from_file "$label" "$output")" || return 1
    validate_wrk_sample "$label" "$summary_json" "$output" || return 1

    local queue_json
    queue_json="$(queue_summary_json "$queue_samples" "$before_metrics" "$after_metrics")" || return 1
    local accept_json
    accept_json="$(accept_delta_json "$before_metrics" "$after_metrics")" || return 1

    echo "  ${label}: $(jq -r '.rps' <<<"$summary_json") req/s, p99=$(jq -r '.p99_ms' <<<"$summary_json")ms, errors=$(jq -r '.errors' <<<"$summary_json")" >&2
    jq -n \
        --argjson summary "$summary_json" \
        --argjson resources "$resource_json" \
        --argjson queue "$queue_json" \
        --argjson accepts "$accept_json" \
        '$summary + $resources + $queue + {accept_metrics: $accepts}'
}

run_mixed_keepalive_churn_workload() {
    local label="$1"
    local keepalive_output="$2"
    local churn_output="$3"
    local queue_samples="$4"
    local before_metrics="${churn_output%.wrk.txt}-before.prom"
    local after_metrics="${churn_output%.wrk.txt}-after.prom"

    scrape_metrics > "$before_metrics" || return 1
    start_resource_monitor || return 1
    start_queue_monitor "$queue_samples"

    wrk --latency -s "${BENCH_DIR}/wrk-summary.lua" -t"${THREADS}" -c"${CONNECTIONS}" -d"${DURATION}s" "${HEADER_ARGS[@]}" "${BASE_URL}${KEEPALIVE_PATH}" >"$keepalive_output" 2>&1 &
    local keepalive_pid="$!"

    local churn_status=0
    wrk --latency -s "${BENCH_DIR}/wrk-summary.lua" -t"${THREADS}" -c"${CONNECTIONS}" -d"${DURATION}s" "${HEADER_ARGS[@]}" -H "Connection: close" "${BASE_URL}${STATIC_PATH}" >"$churn_output" 2>&1 || churn_status=$?

    local keepalive_status=0
    wait "$keepalive_pid" || keepalive_status=$?

    stop_queue_monitor
    local resource_json
    resource_json="$(stop_resource_monitor_json)" || return 1
    scrape_metrics > "$after_metrics" || return 1

    if (( churn_status != 0 || keepalive_status != 0 )); then
        echo "wrk failed for ${label}; raw output saved to ${keepalive_output} and ${churn_output}" >&2
        jq -n \
            --arg label "$label" \
            --arg keepalive_output "$keepalive_output" \
            --arg churn_output "$churn_output" \
            --argjson resources "$resource_json" \
            '{label: $label, keepalive_raw_output: $keepalive_output, churn_raw_output: $churn_output, resources: $resources}' >&2
        return 1
    fi

    local keepalive_json churn_json queue_json accept_json
    keepalive_json="$(wrk_summary_json_from_file "${label}-keepalive" "$keepalive_output")" || return 1
    churn_json="$(wrk_summary_json_from_file "${label}-churn" "$churn_output")" || return 1
    validate_wrk_sample "${label}-keepalive" "$keepalive_json" "$keepalive_output" || return 1
    validate_wrk_sample "${label}-churn" "$churn_json" "$churn_output" || return 1
    queue_json="$(queue_summary_json "$queue_samples" "$before_metrics" "$after_metrics")" || return 1
    accept_json="$(accept_delta_json "$before_metrics" "$after_metrics")" || return 1

    echo "  ${label}: keepalive $(jq -r '.rps' <<<"$keepalive_json") req/s p99=$(jq -r '.p99_ms' <<<"$keepalive_json")ms; churn $(jq -r '.rps' <<<"$churn_json") req/s p99=$(jq -r '.p99_ms' <<<"$churn_json")ms" >&2
    jq -n \
        --argjson keepalive "$keepalive_json" \
        --argjson churn "$churn_json" \
        --argjson resources "$resource_json" \
        --argjson queue "$queue_json" \
        --argjson accepts "$accept_json" \
        '{keepalive: $keepalive, connection_churn: $churn, resources: $resources, queue: $queue, accept_metrics: $accepts}'
}

run_profile() {
    local label="$1"
    local shard_count="$2"
    local batch_limit="$3"
    local fairness_yield_every="$4"
    local pid_file="${SAVE_DIR}/${label}.pid"
    local run_json="${SAVE_DIR}/${label}-run.json"
    local run_log="${SAVE_DIR}/${label}-run.log"
    local startup_metrics_file="${SAVE_DIR}/${label}-startup-metrics.prom"
    local metrics_file="${SAVE_DIR}/${label}-metrics.prom"
    local churn_raw="${SAVE_DIR}/${label}-connection-churn.wrk.txt"
    local churn_queue_samples="${SAVE_DIR}/${label}-connection-churn-queue.samples"
    local burst_raw="${SAVE_DIR}/${label}-connection-burst.wrk.txt"
    local burst_queue_samples="${SAVE_DIR}/${label}-connection-burst-queue.samples"
    local mixed_keepalive_raw="${SAVE_DIR}/${label}-mixed-keepalive-churn-keepalive.wrk.txt"
    local mixed_churn_raw="${SAVE_DIR}/${label}-mixed-keepalive-churn-churn.wrk.txt"
    local mixed_queue_samples="${SAVE_DIR}/${label}-mixed-keepalive-churn-queue.samples"

    cleanup_gateway
    profile_tmp="$(mktemp -d)"

    echo "==> Starting ${label} profile with TARDIGRADE_LISTENER_SHARDS=${shard_count}, TARDIGRADE_ACCEPT_BATCH_LIMIT=${batch_limit}, TARDIGRADE_ACCEPT_FAIRNESS_YIELD_EVERY=${fairness_yield_every}" >&2
    (
        export TARDIGRADE_LISTENER_SHARDS="${shard_count}"
        export TARDIGRADE_ACCEPT_BATCH_LIMIT="${batch_limit}"
        export TARDIGRADE_ACCEPT_FAIRNESS_YIELD_EVERY="${fairness_yield_every}"
        export TARDIGRADE_RATE_LIMIT_RPS="0"
        export TARDIGRADE_PID_FILE="${pid_file}"
        export TMPDIR="${profile_tmp}"
        exec sh -c "$START_COMMAND"
    ) &
    gateway_pid="$!"
    echo "$gateway_pid" > "$pid_file"
    wait_for_ready || return 1
    verify_listener_shards "$shard_count" "$startup_metrics_file" || return 1

    echo "==> ${label}: standard scenarios (${SCENARIOS})" >&2
    local -a run_args=(
        --host "$HOST" \
        --port "$PORT" \
        --driver "listener-accept-${label}" \
        --worker-count "${TARDIGRADE_WORKER_THREADS:-}" \
        --config-label "listener/accept ${label} (${shard_count} shards, batch ${batch_limit}, fairness ${fairness_yield_every})" \
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
    "${BENCH_DIR}/run.sh" "${run_args[@]}" >"$run_log" 2>&1 || return 1

    echo "==> ${label}: high connection churn (${STATIC_PATH}, Connection: close)" >&2
    local churn_json
    churn_json="$(run_wrk_workload "connection-churn-http1" "$churn_raw" "${BENCH_DIR}/wrk-summary.lua" "$churn_queue_samples" "${HEADER_ARGS[@]}" -H "Connection: close" "${BASE_URL}${STATIC_PATH}")" || return 1
    recover_after_close_workload "${label}: post-churn"

    echo "==> ${label}: high connection burst (${STATIC_PATH}, Connection: close, ${BURST_CONNECTIONS} connections)" >&2
    local burst_json
    burst_json="$(WRK_CONNECTIONS="$BURST_CONNECTIONS" run_wrk_workload "connection-burst-http1" "$burst_raw" "${BENCH_DIR}/wrk-summary.lua" "$burst_queue_samples" "${HEADER_ARGS[@]}" -H "Connection: close" "${BASE_URL}${STATIC_PATH}")" || return 1
    recover_after_close_workload "${label}: post-burst"

    echo "==> ${label}: mixed active keepalive + new connection churn (${KEEPALIVE_PATH} keepalive + ${STATIC_PATH} close)" >&2
    local mixed_json
    mixed_json="$(run_mixed_keepalive_churn_workload "mixed-keepalive-churn" "$mixed_keepalive_raw" "$mixed_churn_raw" "$mixed_queue_samples")" || return 1
    recover_after_close_workload "${label}: post-mixed"
    validate_profile_accept_batching "$label" "$batch_limit" "$fairness_yield_every" "$churn_json" "$burst_json" "$mixed_json" || return 1

    scrape_metrics > "$metrics_file" || return 1
    validate_profile_artifacts \
        "$run_json" \
        "$run_log" \
        "$startup_metrics_file" \
        "$metrics_file" \
        "$churn_raw" \
        "$churn_queue_samples" \
        "$burst_raw" \
        "$burst_queue_samples" \
        "$mixed_keepalive_raw" \
        "$mixed_churn_raw" \
        "$mixed_queue_samples" || return 1

    local standard_json metric_json
    standard_json="$(cat "$run_json")" || return 1
    metric_json="$(metrics_json "$metrics_file")" || return 1

    local profile_json
    profile_json="$(jq -n \
        --arg label "$label" \
        --argjson shards "$shard_count" \
        --arg run_json "$run_json" \
        --arg run_log "$run_log" \
        --arg startup_metrics_file "$startup_metrics_file" \
        --arg metrics_file "$metrics_file" \
        --arg churn_raw "$churn_raw" \
        --arg churn_queue_samples "$churn_queue_samples" \
        --arg burst_raw "$burst_raw" \
        --arg burst_queue_samples "$burst_queue_samples" \
        --arg mixed_keepalive_raw "$mixed_keepalive_raw" \
        --arg mixed_churn_raw "$mixed_churn_raw" \
        --arg mixed_queue_samples "$mixed_queue_samples" \
        --argjson standard "$standard_json" \
        --argjson churn "$churn_json" \
        --argjson burst "$burst_json" \
        --argjson mixed "$mixed_json" \
        --argjson metrics "$metric_json" \
        --argjson batch_limit "$batch_limit" \
        --argjson fairness_yield_every "$fairness_yield_every" \
        '{label: $label, requested_shards: $shards, actual_shards: $metrics.listener_shards, accept_batch_limit: $batch_limit, accept_fairness_yield_every: $fairness_yield_every, artifacts: {standard_json: $run_json, standard_log: $run_log, startup_metrics_prom: $startup_metrics_file, metrics_prom: $metrics_file, connection_churn_wrk: $churn_raw, connection_churn_queue_samples: $churn_queue_samples, connection_burst_wrk: $burst_raw, connection_burst_queue_samples: $burst_queue_samples, mixed_keepalive_churn_keepalive_wrk: $mixed_keepalive_raw, mixed_keepalive_churn_churn_wrk: $mixed_churn_raw, mixed_keepalive_churn_queue_samples: $mixed_queue_samples}, standard: $standard, "connection-churn-http1": $churn, "connection-burst-http1": $burst, "mixed-keepalive-churn": $mixed, metrics: $metrics}')" || return 1

    cleanup_gateway
    printf '%s\n' "$profile_json"
}

batch_1_json="$(run_profile "batch-1" 1 1 0)" || exit 1
batch_64_json="$(run_profile "batch-64" 1 64 0)" || exit 1
batch_64_fair_8_json="$(run_profile "batch-64-fair-8" 1 64 8)" || exit 1
sharded_json="$(run_profile "sharded-batch-64" "$SHARDS" 64 0)" || exit 1

summary_file="${SAVE_DIR}/summary.json"
summary_tmp="${summary_file}.tmp"
jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg tag "$(git -C "$REPO_ROOT" describe --tags --always --dirty 2>/dev/null || echo unknown)" \
    --arg host "$HOST" \
    --argjson port "$PORT" \
    --argjson duration "$DURATION" \
    --argjson connections "$CONNECTIONS" \
    --argjson burst_connections "$BURST_CONNECTIONS" \
    --argjson threads "$THREADS" \
    --argjson recovery_seconds "$RECOVERY_SECONDS" \
    --arg static_path "$STATIC_PATH" \
    --arg proxy_path "$PROXY_PATH" \
    --arg keepalive_path "$KEEPALIVE_PATH" \
    --arg save_dir "$SAVE_DIR" \
    --argjson batch_1 "$batch_1_json" \
    --argjson batch_64 "$batch_64_json" \
    --argjson batch_64_fair_8 "$batch_64_fair_8_json" \
    --argjson sharded "$sharded_json" \
    '{
        _meta: {
            generated_at: $generated_at,
            tag: $tag,
            suite: "listener-sharding-accept-batching",
            host: $host,
            port: $port,
            duration_s: $duration,
            connections: $connections,
            burst_connections: $burst_connections,
            threads: $threads,
            recovery_seconds: $recovery_seconds,
            static_path: $static_path,
            proxy_path: $proxy_path,
            keepalive_path: $keepalive_path,
            save_dir: $save_dir,
            profiles: [
                {label: "batch-1", listener_shards: 1, accept_batch_limit: 1, accept_fairness_yield_every: 0},
                {label: "batch-64", listener_shards: 1, accept_batch_limit: 64, accept_fairness_yield_every: 0},
                {label: "batch-64-fair-8", listener_shards: 1, accept_batch_limit: 64, accept_fairness_yield_every: 8},
                {label: "sharded-batch-64", listener_shards: $sharded.requested_shards, accept_batch_limit: 64, accept_fairness_yield_every: 0}
            ],
            workloads: ["static-http1", "proxy-http1", "keepalive", "connection-churn-http1", "connection-burst-http1", "mixed-keepalive-churn"],
            metrics: ["req/s", "p50_ms", "p95_ms", "p99_ms", "p999_ms", "cpu_pct_avg", "rss_mb_peak", "accept_errors_total", "accept_batch_size_count", "accept_batch_size_sum", "accept_batches_total", "accept_fairness_yields_total", "worker_queued_jobs", "worker_queue_wait_us_count", "worker_queue_wait_us_sum", "per-shard accepts_total"]
        },
        "batch-1": $batch_1,
        "batch-64": $batch_64,
        "batch-64-fair-8": $batch_64_fair_8,
        "sharded-batch-64": $sharded
    }' > "$summary_tmp" || exit 1
require_nonempty_file "$summary_tmp" || exit 1
jq empty "$summary_tmp" || exit 1
mv "$summary_tmp" "$summary_file" || exit 1

echo ""
echo "Listener-sharding benchmark artifacts saved under: ${SAVE_DIR}"
echo "Combined summary: ${summary_file}"

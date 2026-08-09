#!/usr/bin/env bash
# Upstream-pool distribution matrix for the competitive benchmark suite.
#
# Covers the #147 validation matrix absorbed by #149: uneven route traffic,
# many low-volume origins, one hot origin with many workers, upstream TLS
# handshake/reuse, local vs cross-worker reuse, new upstream connections/sec,
# CPU/request, p99 latency, and higher-worker contention evidence. The gateway
# does not currently expose a direct pool-lock wait counter, so the sharding
# decision is reported as undetermined with measured sweep data.

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
TLS_ORIGIN_PID=""
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
            sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

if [[ -z "$OUTPUT" ]]; then
    echo "--output is required" >&2
    exit 1
fi

for tool in wrk curl python3 jq awk ps pgrep openssl nghttpd; do
    command -v "$tool" >/dev/null 2>&1 || { echo "missing required tool: $tool" >&2; exit 1; }
done
if [[ ! -x "$BINARY" ]]; then
    echo "tardi binary not found at ${BINARY}" >&2
    exit 1
fi

cleanup() {
    local status=$?
    if [[ "$status" -ne 0 && -n "$TMP_DIR" ]]; then
        if [[ -f "${TMP_DIR}/tardigrade.log" ]]; then
            echo ""
            echo "---- upstream-matrix tardigrade.log ----" >&2
            tail -n 120 "${TMP_DIR}/tardigrade.log" >&2
        fi
        if [[ -f "${TMP_DIR}/tls-origin.log" ]]; then
            echo ""
            echo "---- upstream-matrix tls-origin.log ----" >&2
            tail -n 80 "${TMP_DIR}/tls-origin.log" >&2
        fi
    fi
    if [[ -n "$TARDIGRADE_PID" ]]; then
        kill "$TARDIGRADE_PID" 2>/dev/null || true
        wait "$TARDIGRADE_PID" 2>/dev/null || true
    fi
    local pid
    for pid in "${ORIGIN_PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    if [[ -n "$TLS_ORIGIN_PID" ]]; then
        kill "$TLS_ORIGIN_PID" 2>/dev/null || true
        wait "$TLS_ORIGIN_PID" 2>/dev/null || true
    fi
    [[ -n "$TMP_DIR" ]] && rm -rf "$TMP_DIR"
    exit "$status"
}
trap cleanup EXIT

wait_for_http() {
    local url="$1" attempts="${2:-50}" i
    for ((i = 0; i < attempts; i += 1)); do
        curl -fsSk "$url" >/dev/null 2>&1 && return 0
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

count_open_fds_for_pids() {
    local pids_csv="$1"
    local total=0 pid count
    IFS=, read -ra _fd_pids <<< "$pids_csv"
    for pid in "${_fd_pids[@]}"; do
        [[ -n "$pid" ]] || continue
        if [[ -d "/proc/${pid}/fd" ]]; then
            count=$(find "/proc/${pid}/fd" -maxdepth 1 -type l 2>/dev/null | wc -l | tr -d ' ')
        elif command -v lsof >/dev/null 2>&1; then
            count=$(lsof -n -P -p "$pid" 2>/dev/null | awk 'NR > 1 { count += 1 } END { print count + 0 }')
        else
            count=""
        fi
        [[ "$count" =~ ^[0-9]+$ ]] && total=$((total + count))
    done
    if [[ "$total" -gt 0 ]]; then
        printf '%s\n' "$total"
    else
        printf 'null\n'
    fi
}

monitor_process_tree() {
    local pid="$1" sample_interval_s="$2" outfile="$3"
    while kill -0 "$pid" 2>/dev/null; do
        process_tree_pids "$pid" | paste -sd, - | {
            read -r pids
            [[ -n "$pids" ]] || pids="$pid"
            local fds
            fds="$(count_open_fds_for_pids "$pids")"
            ps -p "$pids" -o rss= -o %cpu= 2>/dev/null |
                awk -v fds="$fds" '{ rss += $1; cpu += $2 } END { if (rss > 0 || cpu > 0) print rss, cpu, fds }' >> "$outfile"
        }
        sleep "$sample_interval_s"
    done
}

start_monitor() {
    local file
    file="$(mktemp /tmp/tardigrade-upstream-monitor-XXXXXX)"
    monitor_process_tree "$TARDIGRADE_PID" "0.500" "$file" &
    printf '%s %s\n' "$!" "$file"
}

stop_monitor() {
    local pid="$1" file="$2"
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    awk '
        NF >= 2 {
            rss = $1; cpu = $2
            cpu_sum += cpu; cpu_count += 1
            if (rss > rss_max) rss_max = rss
        }
        NF >= 3 && $3 ~ /^[0-9]+$/ && $3 > fd_max { fd_max = $3 }
        END {
            if (cpu_count > 0) printf "%.2f %.2f ", cpu_sum / cpu_count, rss_max / 1024; else printf "null null ";
            if (fd_max > 0) printf "%d\n", fd_max; else printf "null\n";
        }
    ' "$file"
    rm -f "$file"
}

current_metrics() {
    curl -fsS "http://127.0.0.1:${LISTEN_PORT}/status/metrics"
}

metric_from_file() {
    local file="$1" key="$2"
    awk -v k="$key" '$1 == k { print $2; exit }' "$file"
}

metric_delta() {
    local before="$1" after="$2" key="$3"
    local b a
    b="$(metric_from_file "$before" "$key")"; b="${b:-0}"
    a="$(metric_from_file "$after" "$key")"; a="${a:-0}"
    awk -v a="$a" -v b="$b" 'BEGIN { print a - b }'
}

wrk_error_count() {
    awk '
        /Non-2xx/ {
            for (i = 1; i <= NF; i++) if ($i ~ /^[0-9]+$/) total += $i
        }
        /Socket errors:/ {
            for (i = 1; i <= NF; i++) {
                gsub(/,/, "", $i)
                if ($i ~ /^[0-9]+$/) total += $i
            }
        }
        END { print total + 0 }
    '
}

preflight_path() {
    local path="$1"
    curl -fsS "http://127.0.0.1:${LISTEN_PORT}/${path}" | grep -qx 'ok'
}

scenario_json() {
    local rps="$1" p99="$2" errors="$3" cpu_pct="$4" rss_mb="$5" open_fds="$6" before="$7" after="$8" elapsed="$9"
    local new_c reused local_r cross_r stale
    new_c="$(metric_delta "$before" "$after" tardigrade_upstream_connections_new_total)"
    reused="$(metric_delta "$before" "$after" tardigrade_upstream_connections_reused_total)"
    local_r="$(metric_delta "$before" "$after" tardigrade_upstream_connections_reused_local_total)"
    cross_r="$(metric_delta "$before" "$after" tardigrade_upstream_connections_reused_cross_worker_total)"
    stale="$(metric_delta "$before" "$after" tardigrade_upstream_stale_retries_total)"
    jq -n \
        --argjson rps "$rps" \
        --argjson p99 "$p99" \
        --argjson errors "$errors" \
        --argjson cpu "$cpu_pct" \
        --argjson rss "$rss_mb" \
        --argjson fds "$open_fds" \
        --argjson elapsed "$elapsed" \
        --argjson new_connections "$new_c" \
        --argjson reused_connections "$reused" \
        --argjson local_reuse "$local_r" \
        --argjson cross_worker_reuse "$cross_r" \
        --argjson stale_retries "$stale" \
        '{
            covered: true,
            rps: $rps,
            p99_ms: $p99,
            p99_ttfb_ms: null,
            errors: $errors,
            elapsed_s: $elapsed,
            cpu_pct_avg: $cpu,
            cpu_ms_per_request: (if $rps > 0 and $cpu != null then (($cpu / 100.0) / $rps * 1000.0) else null end),
            rss_mb_peak: $rss,
            open_fds_peak: $fds,
            new_connections: $new_connections,
            reused_connections: $reused_connections,
            local_reuse: $local_reuse,
            cross_worker_reuse: $cross_worker_reuse,
            stale_retries: $stale_retries,
            new_connections_per_sec: (if $elapsed > 0 then ($new_connections / $elapsed) else null end),
            reuse_ratio: (if ($new_connections + $reused_connections) > 0 then ($reused_connections / ($new_connections + $reused_connections)) else null end),
            cross_worker_reuse_ratio: (if $reused_connections > 0 then ($cross_worker_reuse / $reused_connections) else null end)
        }'
}

run_measured_wrk() {
    local label="$1" path="$2" duration="$3" connections="$4" threads="$5"
    local before after mon_pid mon_file raw summary rps p99 errors start_ns end_ns elapsed cpu_pct rss_mb open_fds
    before="${TMP_DIR}/${label}-before.metrics"
    after="${TMP_DIR}/${label}-after.metrics"
    current_metrics > "$before"
    read -r mon_pid mon_file < <(start_monitor)
    start_ns="$(date +%s%N)"
    raw="$(wrk --latency -s "${BENCH_DIR}/wrk-summary.lua" -t"${threads}" -c"${connections}" -d"${duration}s" "http://127.0.0.1:${LISTEN_PORT}/${path}" 2>&1 || true)"
    end_ns="$(date +%s%N)"
    read -r cpu_pct rss_mb open_fds < <(stop_monitor "$mon_pid" "$mon_file")
    current_metrics > "$after"
    summary="$(printf '%s\n' "$raw" | sed -n 's/^WRK_SUMMARY //p' | tail -1)"
    if [[ -z "$summary" ]]; then
        echo "missing wrk summary for ${label}" >&2
        echo "$raw" >&2
        exit 1
    fi
    rps="$(jq -r '.rps // 0' <<<"$summary")"
    p99="$(jq -r '.p99_ms // null' <<<"$summary")"
    errors="$(printf '%s\n' "$raw" | wrk_error_count)"
    if [[ "$errors" != "0" ]]; then
        echo "wrk reported ${errors} errors for ${label}" >&2
        echo "$raw" >&2
        exit 1
    fi
    elapsed="$(awk -v s="$start_ns" -v e="$end_ns" 'BEGIN { printf "%.3f", (e - s) / 1000000000 }')"
    scenario_json "$rps" "$p99" "$errors" "$cpu_pct" "$rss_mb" "$open_fds" "$before" "$after" "$elapsed"
}

worker_sweep_json() {
    local cpus max workers result row
    cpus="$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 1)"
    max="$cpus"
    [[ "$max" -gt 8 ]] && max=8
    result='[]'
    workers=1
    while [[ "$workers" -le "$max" ]]; do
        local sweep_connections="$CONNECTIONS"
        [[ "$sweep_connections" -lt "$workers" ]] && sweep_connections="$workers"
        row="$(run_measured_wrk "pool-contention-${workers}w" hot 2 "$sweep_connections" "$workers")"
        result="$(jq --argjson row "$row" --argjson workers "$workers" '. + [($row + {worker_threads: $workers})]' <<<"$result")"
        workers=$((workers * 2))
    done
    jq -n --argjson rows "$result" '{
        covered: true,
        sharding_justified: "undetermined",
        reason: "No direct pool-lock wait/contention counter is currently exported; throughput, p99, CPU/request, reuse, and FD data are recorded by worker-count sweep.",
        measurements: $rows
    }'
}

TMP_DIR="$(mktemp -d /tmp/tardigrade-upstream-matrix-XXXX)"
CONFIG_FILE="${TMP_DIR}/upstream-matrix.conf"
TLS_ORIGIN_PORT=$((ORIGIN_BASE_PORT + 20))

for i in 0 1 2 3 4 5; do
    port=$((ORIGIN_BASE_PORT + i))
    python3 "${BENCH_DIR}/fixtures/upstream_server.py" --port "$port" >"${TMP_DIR}/origin-${i}.log" 2>&1 &
    ORIGIN_PIDS+=("$!")
    wait_for_http "http://127.0.0.1:${port}/health"
done

openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=localhost" \
    -keyout "${TMP_DIR}/tls-origin.key" -out "${TMP_DIR}/tls-origin.crt" >/dev/null 2>&1
mkdir -p "${TMP_DIR}/tls-docroot"
printf 'ok\n' > "${TMP_DIR}/tls-docroot/health"
nghttpd -d "${TMP_DIR}/tls-docroot" "${TLS_ORIGIN_PORT}" "${TMP_DIR}/tls-origin.key" "${TMP_DIR}/tls-origin.crt" \
    >"${TMP_DIR}/tls-origin.log" 2>&1 &
TLS_ORIGIN_PID="$!"
wait_for_http "https://127.0.0.1:${TLS_ORIGIN_PORT}/health"

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
location = /tls-origin {
    proxy_pass https://127.0.0.1:${TLS_ORIGIN_PORT}/health;
}
EOF

TARDIGRADE_RATE_LIMIT_RPS=0 \
TARDIGRADE_WORKER_THREADS="${THREADS}" \
TARDIGRADE_MAX_REQUESTS_PER_CONNECTION=0 \
TARDIGRADE_UPSTREAM_PROTOCOL=auto \
TARDIGRADE_UPSTREAM_TLS_VERIFY=false \
    "$BINARY" run -c "$CONFIG_FILE" >"${TMP_DIR}/tardigrade.log" 2>&1 &
TARDIGRADE_PID="$!"
wait_for_http "http://127.0.0.1:${LISTEN_PORT}/status/metrics" 150

for path in hot route-a route-b route-c origin-0 origin-1 origin-2 origin-3 origin-4 origin-5 tls-origin; do
    preflight_path "$path" || { echo "preflight failed for /${path}" >&2; exit 1; }
done

hot_json="$(run_measured_wrk hot-origin hot "$DURATION" "$CONNECTIONS" "$THREADS")"
route_a_json="$(run_measured_wrk route-a route-a 3 8 2)"
route_b_json="$(run_measured_wrk route-b route-b 3 8 2)"
route_c_json="$(run_measured_wrk route-c route-c 3 8 2)"
origins_json='[]'
for path in origin-0 origin-1 origin-2 origin-3 origin-4 origin-5; do
    row="$(run_measured_wrk "$path" "$path" 2 4 1)"
    origins_json="$(jq --arg path "$path" --argjson row "$row" '. + [($row + {origin: $path})]' <<<"$origins_json")"
done
tls_json="$(run_measured_wrk tls-origin tls-origin "$DURATION" "$CONNECTIONS" "$THREADS")"
contention_json="$(worker_sweep_json)"

jq -n \
    --argjson duration "$DURATION" \
    --argjson threads "$THREADS" \
    --argjson hot "$hot_json" \
    --argjson route_a "$route_a_json" \
    --argjson route_b "$route_b_json" \
    --argjson route_c "$route_c_json" \
    --argjson origins "$origins_json" \
    --argjson tls "$tls_json" \
    --argjson contention "$contention_json" \
    '{
        _meta: {
            suite: "upstream-pool-distribution",
            duration_s: $duration,
            worker_threads: $threads,
            note: "p99_ms is end-to-end latency. p99_ttfb_ms remains null until a first-byte load tool is wired into this matrix."
        },
        scenarios: {
            "uneven-route-distribution": {
                covered: true,
                routes: { "route-a": $route_a, "route-b": $route_b, "route-c": $route_c },
                errors: (($route_a.errors // 0) + ($route_b.errors // 0) + ($route_c.errors // 0))
            },
            "many-origins-low-volume": {
                covered: true,
                origins: 6,
                measurements: $origins,
                errors: ($origins | map(.errors // 0) | add)
            },
            "hot-origin-many-workers": $hot,
            "upstream-tls-handshake-reuse": $tls,
            "pool-contention": $contention
        }
    }' > "$OUTPUT"

echo "Wrote upstream-pool matrix: ${OUTPUT}"

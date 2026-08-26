#!/usr/bin/env bash
# Upstream-pool distribution matrix for the competitive benchmark suite.
#
# Covers the #147 validation matrix absorbed by #149: uneven route traffic,
# many low-volume origins, one hot origin with many workers, upstream TLS
# handshake/reuse, local vs cross-worker reuse, new upstream connections/sec,
# CPU/request, p99 TTFB, and higher-worker contention evidence.

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
LOCK_METRICS=false

cleanup() {
    local status=$?
    if [[ "$status" -ne 0 && -n "$TMP_DIR" && -f "${TMP_DIR}/tardigrade.log" ]]; then
        if [[ -f "${TMP_DIR}/upstream-matrix.conf" ]]; then
            echo "" >&2
            echo "---- upstream-matrix config ----" >&2
            cat "${TMP_DIR}/upstream-matrix.conf" >&2
        fi
        echo "" >&2
        echo "---- upstream-matrix tardigrade.log ----" >&2
        tail -n 120 "${TMP_DIR}/tardigrade.log" >&2
    fi
    [[ -n "$TARDIGRADE_PID" ]] && { kill "$TARDIGRADE_PID" 2>/dev/null || true; wait "$TARDIGRADE_PID" 2>/dev/null || true; }
    local pid
    for pid in "${ORIGIN_PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    [[ -n "$TLS_ORIGIN_PID" ]] && { kill "$TLS_ORIGIN_PID" 2>/dev/null || true; wait "$TLS_ORIGIN_PID" 2>/dev/null || true; }
    [[ -n "$TMP_DIR" ]] && rm -rf "$TMP_DIR"
    exit "$status"
}
monotonic_ns() {
    python3 -c 'import time; print(time.monotonic_ns())'
}

wait_for_http() {
    local url="$1" attempts="${2:-50}" i
    for ((i = 0; i < attempts; i += 1)); do
        curl --max-time 1 -fsSk "$url" >/dev/null 2>&1 && return 0
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

process_tree_cpu_seconds() {
    local pids clk total_ticks pid
    pids="$(process_tree_pids "$TARDIGRADE_PID" | paste -sd, -)"
    [[ -n "$pids" ]] || pids="$TARDIGRADE_PID"
    if [[ "$(uname -s 2>/dev/null || true)" == "Linux" ]]; then
        clk="$(getconf CLK_TCK 2>/dev/null || true)"
        if [[ "$clk" =~ ^[0-9]+$ && "$clk" -gt 0 ]]; then
            total_ticks=0
            IFS=, read -ra _cpu_pids <<< "$pids"
            for pid in "${_cpu_pids[@]}"; do
                [[ -r "/proc/${pid}/stat" ]] || continue
                total_ticks=$((total_ticks + $(awk '{
                    paren_idx = match($0, /\) /)
                    rest = substr($0, paren_idx + 2)
                    split(rest, f, " ")
                    print (f[12] + f[13])
                }' "/proc/${pid}/stat")))
            done
            awk -v ticks="$total_ticks" -v clk="$clk" 'BEGIN { printf "%.6f", ticks / clk }'
            return
        fi
    fi
    ps -p "$pids" -o time= 2>/dev/null | cpu_time_to_seconds
}

count_open_fds_for_pids() {
    local pids_csv="$1" total=0 pid count
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
    [[ "$total" -gt 0 ]] && printf '%s\n' "$total" || printf 'null\n'
}

monitor_process_tree() {
    local outfile="$1"
    while kill -0 "$TARDIGRADE_PID" 2>/dev/null; do
        process_tree_pids "$TARDIGRADE_PID" | paste -sd, - | {
            read -r pids
            [[ -n "$pids" ]] || pids="$TARDIGRADE_PID"
            local fds
            fds="$(count_open_fds_for_pids "$pids")"
            ps -p "$pids" -o rss= 2>/dev/null |
                awk -v fds="$fds" '{ rss += $1 } END { if (rss > 0) print rss, fds }' >> "$outfile"
        }
        sleep 0.5
    done
}

start_monitor() {
    local file cpu_before start_ns
    file="$(mktemp /tmp/tardigrade-upstream-monitor-XXXXXX)"
    cpu_before="$(process_tree_cpu_seconds)"
    start_ns="$(monotonic_ns)"
    monitor_process_tree "$file" &
    printf '%s %s %s %s\n' "$!" "$file" "$cpu_before" "$start_ns"
}

stop_monitor() {
    local pid="$1" file="$2" cpu_before="$3" start_ns="$4"
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    local cpu_after end_ns cpu_pct
    cpu_after="$(process_tree_cpu_seconds)"
    end_ns="$(monotonic_ns)"
    cpu_pct="$(awk -v before="$cpu_before" -v after="$cpu_after" -v start="$start_ns" -v end="$end_ns" '
        BEGIN {
            elapsed = (end - start) / 1000000000
            if (elapsed > 0) printf "%.2f", ((after - before) / elapsed) * 100
            else printf "null"
        }')"
    awk -v cpu="$cpu_pct" '
        NF >= 1 && $1 > rss_max { rss_max = $1 }
        NF >= 2 && $2 ~ /^[0-9]+$/ && $2 > fd_max { fd_max = $2 }
        END {
            printf "%s ", cpu
            if (rss_max > 0) printf "%.2f ", rss_max / 1024; else printf "null "
            if (fd_max > 0) printf "%d\n", fd_max; else printf "null\n"
        }
    ' "$file"
    rm -f "$file"
}

current_metrics() {
    curl --max-time 2 -fsS "http://127.0.0.1:${LISTEN_PORT}/status/metrics"
}

metric_from_file() {
    local file="$1" key="$2"
    awk -v k="$key" '$1 == k { print $2; exit }' "$file"
}

metric_delta() {
    local before="$1" after="$2" key="$3" b a
    b="$(metric_from_file "$before" "$key")"; b="${b:-0}"
    a="$(metric_from_file "$after" "$key")"; a="${a:-0}"
    awk -v a="$a" -v b="$b" 'BEGIN { print a - b }'
}

wrk_error_count() {
    awk '
        /Non-2xx/ { for (i = 1; i <= NF; i++) if ($i ~ /^[0-9]+$/) total += $i }
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
    curl --max-time 2 -fsS "http://127.0.0.1:${LISTEN_PORT}/${path}" | grep -qx 'ok'
}

run_k6_ttfb() {
    local label="$1" path="$2" duration="$3" vus="$4" script summary
    script="${TMP_DIR}/${label}-ttfb.js"
    summary="${TMP_DIR}/${label}-ttfb.json"
    cat > "$script" <<EOF
import http from 'k6/http';
export const options = { vus: ${vus}, duration: '${duration}s', summaryTrendStats: ['min', 'avg', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'] };
export default function () { http.get('http://127.0.0.1:${LISTEN_PORT}/${path}'); }
EOF
    k6 run --quiet --summary-export "$summary" "$script" >/dev/null
    jq -e -r '
        (.metrics.http_req_failed.values.rate // .metrics.http_req_failed.rate // .metrics.http_req_failed.value // 0) as $failed
        | if $failed != 0 then error("k6 http_req_failed was non-zero: \($failed)") else
            (.metrics.http_req_waiting.values["p(99)"] // .metrics.http_req_waiting["p(99)"] // error("k6 summary is missing http_req_waiting p(99)"))
          end
    ' "$summary"
}

scenario_json() {
    local rps="$1" p99="$2" p99_ttfb="$3" errors="$4" cpu_pct="$5" rss_mb="$6" open_fds="$7" before="$8" after="$9" elapsed="${10}"
    local new_c reused local_r cross_r stale lock_wait_ns lock_acquires request_count
    new_c="$(metric_delta "$before" "$after" tardigrade_upstream_connections_new_total)"
    reused="$(metric_delta "$before" "$after" tardigrade_upstream_connections_reused_total)"
    local_r="$(metric_delta "$before" "$after" tardigrade_upstream_connections_reused_local_total)"
    cross_r="$(metric_delta "$before" "$after" tardigrade_upstream_connections_reused_cross_worker_total)"
    stale="$(metric_delta "$before" "$after" tardigrade_upstream_stale_retries_total)"
    lock_wait_ns="$(metric_delta "$before" "$after" tardigrade_upstream_pool_lock_wait_ns_total)"
    lock_acquires="$(metric_delta "$before" "$after" tardigrade_upstream_pool_lock_acquires_total)"
    request_count="$(awk -v rps="$rps" -v elapsed="$elapsed" 'BEGIN { if (rps > 0 && elapsed > 0) printf "%.0f", rps * elapsed; else print 0 }')"
    jq -n \
        --argjson rps "$rps" --argjson p99 "$p99" --argjson p99_ttfb "$p99_ttfb" --argjson errors "$errors" \
        --argjson cpu "$cpu_pct" --argjson rss "$rss_mb" --argjson fds "$open_fds" --argjson elapsed "$elapsed" \
        --argjson new_connections "$new_c" --argjson reused_connections "$reused" \
        --argjson local_reuse "$local_r" --argjson cross_worker_reuse "$cross_r" --argjson stale_retries "$stale" \
        --argjson lock_wait_ns "$lock_wait_ns" --argjson lock_acquires "$lock_acquires" --argjson request_count "$request_count" \
        '{
            covered: true,
            rps: $rps,
            p99_ms: $p99,
            p99_ttfb_ms: $p99_ttfb,
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
            pool_lock_wait_ns_total: (if $lock_acquires > 0 then $lock_wait_ns else null end),
            pool_lock_acquires_total: (if $lock_acquires > 0 then $lock_acquires else null end),
            pool_lock_wait_ns_per_request: (if $lock_acquires > 0 and $request_count > 0 then ($lock_wait_ns / $request_count) else null end),
            pool_lock_wait_ns_per_acquire: (if $lock_acquires > 0 then ($lock_wait_ns / $lock_acquires) else null end),
            new_connections_per_sec: (if $elapsed > 0 then ($new_connections / $elapsed) else null end),
            reuse_ratio: (if ($new_connections + $reused_connections) > 0 then ($reused_connections / ($new_connections + $reused_connections)) else null end),
            cross_worker_reuse_ratio: (if $reused_connections > 0 then ($cross_worker_reuse / $reused_connections) else null end)
        }'
}

run_measured_wrk() {
    local label="$1" path="$2" duration="$3" connections="$4" threads="$5" with_ttfb="${6:-false}"
    local before after mon_pid mon_file cpu_before start_ns raw summary rps p99 errors end_ns elapsed cpu_pct rss_mb open_fds p99_ttfb
    before="${TMP_DIR}/${label}-before.metrics"
    after="${TMP_DIR}/${label}-after.metrics"
    current_metrics > "$before"
    read -r mon_pid mon_file cpu_before start_ns < <(start_monitor)
    raw="$(wrk --latency -s "${BENCH_DIR}/wrk-summary.lua" -t"${threads}" -c"${connections}" -d"${duration}s" "http://127.0.0.1:${LISTEN_PORT}/${path}" 2>&1 || true)"
    end_ns="$(monotonic_ns)"
    read -r cpu_pct rss_mb open_fds < <(stop_monitor "$mon_pid" "$mon_file" "$cpu_before" "$start_ns")
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
    if [[ "$with_ttfb" == true ]]; then
        p99_ttfb="$(run_k6_ttfb "$label" "$path" "$duration" "$connections")"
    else
        p99_ttfb="null"
    fi
    scenario_json "$rps" "$p99" "$p99_ttfb" "$errors" "$cpu_pct" "$rss_mb" "$open_fds" "$before" "$after" "$elapsed"
}

route_result_json() {
    local label="$1" raw_file="$2" duration="$3" connections="$4" threads="$5" requested_share="$6" total_rps="$7" elapsed="$8"
    local raw summary rps p99 errors request_count achieved_share
    raw="$(cat "$raw_file")"
    summary="$(printf '%s\n' "$raw" | sed -n 's/^WRK_SUMMARY //p' | tail -1)"
    if [[ -z "$summary" ]]; then
        echo "missing wrk summary for ${label}" >&2
        echo "$raw" >&2
        return 1
    fi
    rps="$(jq -r '.rps // 0' <<<"$summary")"
    p99="$(jq -r '.p99_ms // null' <<<"$summary")"
    errors="$(printf '%s\n' "$raw" | wrk_error_count)"
    if ! awk -v rps="$rps" 'BEGIN { exit !(rps > 0) }'; then
        echo "wrk reported non-positive rps for ${label}: ${rps}" >&2
        echo "$raw" >&2
        return 1
    fi
    if [[ "$errors" != "0" ]]; then
        echo "wrk reported ${errors} errors for ${label}" >&2
        echo "$raw" >&2
        return 1
    fi
    request_count="$(awk -v rps="$rps" -v elapsed="$elapsed" 'BEGIN { if (rps > 0 && elapsed > 0) printf "%.0f", rps * elapsed; else print 0 }')"
    achieved_share="$(awk -v rps="$rps" -v total="$total_rps" 'BEGIN { if (total > 0) printf "%.6f", rps / total; else print 0 }')"
    jq -n \
        --argjson requested_share "$requested_share" \
        --argjson achieved_share "$achieved_share" \
        --argjson rps "$rps" \
        --argjson p99 "$p99" \
        --argjson errors "$errors" \
        --argjson duration "$duration" \
        --argjson connections "$connections" \
        --argjson threads "$threads" \
        --argjson request_count "$request_count" \
        '{
            requested_share: $requested_share,
            achieved_share: $achieved_share,
            rps: $rps,
            p99_ms: $p99,
            errors: $errors,
            configured_duration_s: $duration,
            configured_connections: $connections,
            configured_threads: $threads,
            achieved_request_count: $request_count
        }'
}

run_concurrent_uneven_routes() {
    local label="uneven-route-distribution"
    local duration="$DURATION"
    local route_a_connections=16 route_a_threads=4 route_a_share=0.80
    local route_b_connections=3 route_b_threads=1 route_b_share=0.15
    local route_c_connections=1 route_c_threads=1 route_c_share=0.05
    local before after mon_pid mon_file cpu_before start_ns end_ns elapsed cpu_pct rss_mb open_fds
    local route_a_raw route_b_raw route_c_raw route_a_status_file route_b_status_file route_c_status_file
    local route_a_pid route_b_pid route_c_pid route_a_done=false route_b_done=false route_c_done=false remaining=3 failed=0
    local route_a_status=0 route_b_status=0 route_c_status=0 route_a_summary route_b_summary route_c_summary
    local route_a_rps route_b_rps route_c_rps total_rps total_errors combined route_a route_b route_c
    before="${TMP_DIR}/${label}-before.metrics"
    after="${TMP_DIR}/${label}-after.metrics"
    route_a_raw="${TMP_DIR}/${label}-route-a.wrk"
    route_b_raw="${TMP_DIR}/${label}-route-b.wrk"
    route_c_raw="${TMP_DIR}/${label}-route-c.wrk"
    route_a_status_file="${TMP_DIR}/${label}-route-a.status"
    route_b_status_file="${TMP_DIR}/${label}-route-b.status"
    route_c_status_file="${TMP_DIR}/${label}-route-c.status"

    current_metrics > "$before"
    read -r mon_pid mon_file cpu_before start_ns < <(start_monitor)

    (
        wrk --latency -s "${BENCH_DIR}/wrk-summary.lua" -t"${route_a_threads}" -c"${route_a_connections}" -d"${duration}s" "http://127.0.0.1:${LISTEN_PORT}/route-a" >"$route_a_raw" 2>&1 &
        child_pid="$!"
        trap 'kill "$child_pid" 2>/dev/null || true; wait "$child_pid" 2>/dev/null || true; exit 143' TERM INT
        wait "$child_pid"
        printf '%s\n' "$?" > "$route_a_status_file"
    ) &
    route_a_pid="$!"
    (
        wrk --latency -s "${BENCH_DIR}/wrk-summary.lua" -t"${route_b_threads}" -c"${route_b_connections}" -d"${duration}s" "http://127.0.0.1:${LISTEN_PORT}/route-b" >"$route_b_raw" 2>&1 &
        child_pid="$!"
        trap 'kill "$child_pid" 2>/dev/null || true; wait "$child_pid" 2>/dev/null || true; exit 143' TERM INT
        wait "$child_pid"
        printf '%s\n' "$?" > "$route_b_status_file"
    ) &
    route_b_pid="$!"
    (
        wrk --latency -s "${BENCH_DIR}/wrk-summary.lua" -t"${route_c_threads}" -c"${route_c_connections}" -d"${duration}s" "http://127.0.0.1:${LISTEN_PORT}/route-c" >"$route_c_raw" 2>&1 &
        child_pid="$!"
        trap 'kill "$child_pid" 2>/dev/null || true; wait "$child_pid" 2>/dev/null || true; exit 143' TERM INT
        wait "$child_pid"
        printf '%s\n' "$?" > "$route_c_status_file"
    ) &
    route_c_pid="$!"

    while [[ "$remaining" -gt 0 ]]; do
        if ! $route_a_done && [[ -f "$route_a_status_file" ]]; then
            route_a_status="$(cat "$route_a_status_file")"
            route_a_done=true
            remaining=$((remaining - 1))
            if [[ "$route_a_status" -ne 0 ]]; then
                failed=1
                if ! $route_b_done; then
                    kill "$route_b_pid" 2>/dev/null || true
                    route_b_status=143
                    route_b_done=true
                    remaining=$((remaining - 1))
                fi
                if ! $route_c_done; then
                    kill "$route_c_pid" 2>/dev/null || true
                    route_c_status=143
                    route_c_done=true
                    remaining=$((remaining - 1))
                fi
            fi
        fi
        if ! $route_b_done && [[ -f "$route_b_status_file" ]]; then
            route_b_status="$(cat "$route_b_status_file")"
            route_b_done=true
            remaining=$((remaining - 1))
            if [[ "$route_b_status" -ne 0 ]]; then
                failed=1
                if ! $route_a_done; then
                    kill "$route_a_pid" 2>/dev/null || true
                    route_a_status=143
                    route_a_done=true
                    remaining=$((remaining - 1))
                fi
                if ! $route_c_done; then
                    kill "$route_c_pid" 2>/dev/null || true
                    route_c_status=143
                    route_c_done=true
                    remaining=$((remaining - 1))
                fi
            fi
        fi
        if ! $route_c_done && [[ -f "$route_c_status_file" ]]; then
            route_c_status="$(cat "$route_c_status_file")"
            route_c_done=true
            remaining=$((remaining - 1))
            if [[ "$route_c_status" -ne 0 ]]; then
                failed=1
                if ! $route_a_done; then
                    kill "$route_a_pid" 2>/dev/null || true
                    route_a_status=143
                    route_a_done=true
                    remaining=$((remaining - 1))
                fi
                if ! $route_b_done; then
                    kill "$route_b_pid" 2>/dev/null || true
                    route_b_status=143
                    route_b_done=true
                    remaining=$((remaining - 1))
                fi
            fi
        fi
        [[ "$remaining" -eq 0 ]] || sleep 0.05
    done
    wait "$route_a_pid" 2>/dev/null || true
    wait "$route_b_pid" 2>/dev/null || true
    wait "$route_c_pid" 2>/dev/null || true
    end_ns="$(monotonic_ns)"
    read -r cpu_pct rss_mb open_fds < <(stop_monitor "$mon_pid" "$mon_file" "$cpu_before" "$start_ns")
    current_metrics > "$after"

    if [[ "$failed" -ne 0 || "$route_a_status" -ne 0 || "$route_b_status" -ne 0 || "$route_c_status" -ne 0 ]]; then
        echo "concurrent uneven route wrk failed: route-a=${route_a_status} route-b=${route_b_status} route-c=${route_c_status}" >&2
        echo "---- route-a wrk output ----" >&2
        cat "$route_a_raw" >&2
        echo "---- route-b wrk output ----" >&2
        cat "$route_b_raw" >&2
        echo "---- route-c wrk output ----" >&2
        cat "$route_c_raw" >&2
        return 1
    fi

    route_a_summary="$(sed -n 's/^WRK_SUMMARY //p' "$route_a_raw" | tail -1)"
    route_b_summary="$(sed -n 's/^WRK_SUMMARY //p' "$route_b_raw" | tail -1)"
    route_c_summary="$(sed -n 's/^WRK_SUMMARY //p' "$route_c_raw" | tail -1)"
    if [[ -z "$route_a_summary" || -z "$route_b_summary" || -z "$route_c_summary" ]]; then
        [[ -n "$route_a_summary" ]] || { echo "missing wrk summary for route-a" >&2; cat "$route_a_raw" >&2; }
        [[ -n "$route_b_summary" ]] || { echo "missing wrk summary for route-b" >&2; cat "$route_b_raw" >&2; }
        [[ -n "$route_c_summary" ]] || { echo "missing wrk summary for route-c" >&2; cat "$route_c_raw" >&2; }
        return 1
    fi
    route_a_rps="$(jq -r '.rps // 0' <<<"$route_a_summary")"
    route_b_rps="$(jq -r '.rps // 0' <<<"$route_b_summary")"
    route_c_rps="$(jq -r '.rps // 0' <<<"$route_c_summary")"
    total_rps="$(awk -v a="$route_a_rps" -v b="$route_b_rps" -v c="$route_c_rps" 'BEGIN { printf "%.3f", a + b + c }')"
    elapsed="$(awk -v s="$start_ns" -v e="$end_ns" 'BEGIN { printf "%.3f", (e - s) / 1000000000 }')"

    route_a="$(route_result_json route-a "$route_a_raw" "$duration" "$route_a_connections" "$route_a_threads" "$route_a_share" "$total_rps" "$elapsed")"
    route_b="$(route_result_json route-b "$route_b_raw" "$duration" "$route_b_connections" "$route_b_threads" "$route_b_share" "$total_rps" "$elapsed")"
    route_c="$(route_result_json route-c "$route_c_raw" "$duration" "$route_c_connections" "$route_c_threads" "$route_c_share" "$total_rps" "$elapsed")"
    total_errors="$(jq -n --argjson a "$route_a" --argjson b "$route_b" --argjson c "$route_c" '($a.errors // 0) + ($b.errors // 0) + ($c.errors // 0)')"
    combined="$(scenario_json "$total_rps" null null "$total_errors" "$cpu_pct" "$rss_mb" "$open_fds" "$before" "$after" "$elapsed")"

    jq -n \
        --argjson route_a "$route_a" \
        --argjson route_b "$route_b" \
        --argjson route_c "$route_c" \
        --argjson combined "$combined" \
        '{
            covered: true,
            concurrent: true,
            note: "Routes were measured under one concurrent wrk window. Route-local rps, p99, errors, and achieved shares come from each wrk process; CPU, RSS, fd, upstream reuse, and lock-wait metrics are process-wide combined-window measurements.",
            routes: {
                route_a: $route_a,
                route_b: $route_b,
                route_c: $route_c
            },
            combined: $combined,
            errors: (($route_a.errors // 0) + ($route_b.errors // 0) + ($route_c.errors // 0))
        }'
}

start_gateway() {
    local workers="$1"
    [[ -n "$TARDIGRADE_PID" ]] && { kill "$TARDIGRADE_PID" 2>/dev/null || true; wait "$TARDIGRADE_PID" 2>/dev/null || true; }
    TARDIGRADE_RATE_LIMIT_RPS=0 \
    TARDIGRADE_WORKER_THREADS="$workers" \
    TARDIGRADE_MAX_REQUESTS_PER_CONNECTION=1000000 \
    TARDIGRADE_UPSTREAM_POOL_LOCK_METRICS="$LOCK_METRICS" \
    TARDIGRADE_UPSTREAM_PROTOCOL=http1 \
    TARDIGRADE_UPSTREAM_TLS_VERIFY=false \
        "$BINARY" run -c "$CONFIG_FILE" >"${TMP_DIR}/tardigrade.log" 2>&1 &
    TARDIGRADE_PID="$!"
    wait_for_http "http://127.0.0.1:${LISTEN_PORT}/status/metrics" 150
}

worker_sweep_json() {
    local cpus max workers result row sweep_connections
    cpus="$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 1)"
    max="$cpus"
    result='[]'
    workers=1
    LOCK_METRICS=true
    while [[ "$workers" -le "$max" ]]; do
        start_gateway "$workers"
        sweep_connections="$CONNECTIONS"
        [[ "$sweep_connections" -lt "$workers" ]] && sweep_connections="$workers"
        row="$(run_measured_wrk "pool-contention-${workers}w" hot 2 "$sweep_connections" "$THREADS" true)"
        result="$(jq --argjson row "$row" --argjson workers "$workers" '. + [($row + {worker_threads: $workers})]' <<<"$result")"
        workers=$((workers * 2))
    done
    LOCK_METRICS=false
    jq -n --argjson rows "$result" '
    def lower_peak($rows; $idx):
        if $idx <= 0 then null
        else ($rows[0:$idx] | map(.rps // 0) | max)
        end;
    ($rows | to_entries | map(.value as $row | lower_peak($rows; .key) as $peak | $row + {
        pool_lock_wait_fraction_of_p99: (
            if ($row.p99_ms // 0) > 0 and ($row.pool_lock_wait_ns_per_request // null) != null
            then ($row.pool_lock_wait_ns_per_request / ($row.p99_ms * 1000000.0))
            else null
            end
        ),
        lower_core_peak_rps: $peak,
        throughput_drop_from_lower_core_peak: (
            if ($peak // 0) > 0 and ($row.worker_threads // 1) > 1 and ($row.rps // 0) < $peak
            then (($peak - ($row.rps // 0)) / $peak)
            else 0
            end
        )
    })) as $annotated |
    ($annotated | map(.pool_lock_wait_fraction_of_p99 // 0) | max) as $max_lock_fraction |
    ($annotated | map(.throughput_drop_from_lower_core_peak // 0) | max) as $max_throughput_drop |
    {
        covered: true,
        sharding_justified: any($annotated[]; ((.worker_threads // 1) > 1) and ((.pool_lock_wait_fraction_of_p99 // 0) >= 0.05) and ((.throughput_drop_from_lower_core_peak // 0) >= 0.10)),
        sharding_decision_rule: "Shard only when the same higher-worker row shows pool-lock wait at least 5% of p99 latency and at least 10% throughput regression from the best lower-worker throughput.",
        max_pool_lock_wait_fraction_of_p99: $max_lock_fraction,
        max_throughput_drop_from_lower_core_peak: $max_throughput_drop,
        reason: "Derived from opt-in shared upstream-pool mutex wait counters correlated on the same worker-count row with throughput regression from the lower-core peak.",
        measurements: $annotated
    }'
}

main() {
while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary) BINARY="$2"; shift 2 ;;
        --listen-port) LISTEN_PORT="$2"; shift 2 ;;
        --origin-base-port) ORIGIN_BASE_PORT="$2"; shift 2 ;;
        --duration) DURATION="$2"; shift 2 ;;
        --connections) CONNECTIONS="$2"; shift 2 ;;
        --threads) THREADS="$2"; shift 2 ;;
        --output) OUTPUT="$2"; shift 2 ;;
        --help) sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

[[ -n "$OUTPUT" ]] || { echo "--output is required" >&2; exit 1; }
for tool in wrk curl python3 jq awk ps pgrep openssl k6; do
    command -v "$tool" >/dev/null 2>&1 || { echo "missing required tool: $tool" >&2; exit 1; }
done
[[ -x "$BINARY" ]] || { echo "tardi binary not found at ${BINARY}" >&2; exit 1; }
trap cleanup EXIT

TMP_DIR="$(mktemp -d /tmp/tardigrade-upstream-matrix-XXXXXX)"
CONFIG_FILE="${TMP_DIR}/upstream-matrix.conf"
TLS_ORIGIN_PORT=$((ORIGIN_BASE_PORT + 40))
ORIGIN_COUNT=16

for ((i = 0; i < ORIGIN_COUNT; i += 1)); do
    port=$((ORIGIN_BASE_PORT + i))
    python3 "${BENCH_DIR}/fixtures/upstream_server.py" --port "$port" >"${TMP_DIR}/origin-${i}.log" 2>&1 &
    ORIGIN_PIDS+=("$!")
    wait_for_http "http://127.0.0.1:${port}/health"
done

openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=localhost" \
    -keyout "${TMP_DIR}/tls-origin.key" -out "${TMP_DIR}/tls-origin.crt" >/dev/null 2>&1
cat > "${TMP_DIR}/tls_origin.py" <<'PY'
import http.server, ssl, sys
port = int(sys.argv[1])
cert, key = sys.argv[2], sys.argv[3]
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        body = b"ok\n"
        self.send_response(200)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass
server = http.server.ThreadingHTTPServer(("127.0.0.1", port), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)
ctx.set_alpn_protocols(["http/1.1"])
server.socket = ctx.wrap_socket(server.socket, server_side=True)
server.serve_forever()
PY
python3 "${TMP_DIR}/tls_origin.py" "$TLS_ORIGIN_PORT" "${TMP_DIR}/tls-origin.crt" "${TMP_DIR}/tls-origin.key" >"${TMP_DIR}/tls-origin.log" 2>&1 &
TLS_ORIGIN_PID="$!"
wait_for_http "https://127.0.0.1:${TLS_ORIGIN_PORT}/health"

{
    echo "listen ${LISTEN_PORT};"
    echo "metrics_path /status/metrics;"
    printf 'location = /hot {\n    proxy_pass http://127.0.0.1:%s/health;\n}\n' "${ORIGIN_BASE_PORT}"
    printf 'location = /route-a {\n    proxy_pass http://127.0.0.1:%s/health;\n}\n' "${ORIGIN_BASE_PORT}"
    printf 'location = /route-b {\n    proxy_pass http://127.0.0.1:%s/health;\n}\n' "$((ORIGIN_BASE_PORT + 1))"
    printf 'location = /route-c {\n    proxy_pass http://127.0.0.1:%s/health;\n}\n' "$((ORIGIN_BASE_PORT + 2))"
    for ((i = 0; i < ORIGIN_COUNT; i += 1)); do
        printf 'location = /origin-%s {\n    proxy_pass http://127.0.0.1:%s/health;\n}\n' "$i" "$((ORIGIN_BASE_PORT + i))"
    done
    printf 'location = /tls-origin {\n    proxy_pass https://127.0.0.1:%s/health;\n}\n' "${TLS_ORIGIN_PORT}"
} > "$CONFIG_FILE"

start_gateway "$THREADS"
for path in hot route-a route-b route-c; do
    preflight_path "$path" || { echo "preflight failed for /${path}" >&2; exit 1; }
done
for ((i = 0; i < ORIGIN_COUNT; i += 1)); do
    preflight_path "origin-${i}" || { echo "preflight failed for /origin-${i}" >&2; exit 1; }
done

hot_json="$(run_measured_wrk hot-origin hot "$DURATION" "$CONNECTIONS" "$THREADS" true)"
uneven_routes_json="$(run_concurrent_uneven_routes)"

origins_before="${TMP_DIR}/origins-before.metrics"
origins_after="${TMP_DIR}/origins-after.metrics"
current_metrics > "$origins_before"
read -r origins_mon_pid origins_mon_file origins_cpu_before origins_start_ns < <(start_monitor)
origin_counts='[]'
for ((i = 0; i < ORIGIN_COUNT; i += 1)); do
    success=0
    failures=0
    for _ in 1 2 3 4 5; do
        if curl --max-time 2 -fsS "http://127.0.0.1:${LISTEN_PORT}/origin-${i}" >/dev/null; then
            success=$((success + 1))
        else
            failures=$((failures + 1))
        fi
    done
    origin_counts="$(jq --arg origin "origin-${i}" --argjson requested 5 --argjson successes "$success" --argjson failures "$failures" \
        '. + [{origin: $origin, requested: $requested, successes: $successes, failures: $failures}]' <<<"$origin_counts")"
done
origins_end_ns="$(monotonic_ns)"
read -r origins_cpu_pct origins_rss_mb origins_open_fds < <(stop_monitor "$origins_mon_pid" "$origins_mon_file" "$origins_cpu_before" "$origins_start_ns")
current_metrics > "$origins_after"
origins_elapsed="$(awk -v s="$origins_start_ns" -v e="$origins_end_ns" 'BEGIN { printf "%.3f", (e - s) / 1000000000 }')"
origins_successes="$(jq '[.[].successes] | add' <<<"$origin_counts")"
origins_failures="$(jq '[.[].failures] | add' <<<"$origin_counts")"
origins_rps="$(awk -v successes="$origins_successes" -v elapsed="$origins_elapsed" 'BEGIN { if (elapsed > 0) printf "%.3f", successes / elapsed; else print 0 }')"
origins_aggregate="$(scenario_json "$origins_rps" null null "$origins_failures" "$origins_cpu_pct" "$origins_rss_mb" "$origins_open_fds" "$origins_before" "$origins_after" "$origins_elapsed")"
origins_json="$(jq --argjson elapsed "$origins_elapsed" '
    map({
        origin: .origin,
        requested: .requested,
        successes: .successes,
        failures: .failures,
        covered: (.failures == 0),
        rps: (if $elapsed > 0 then (.successes / $elapsed) else 0 end),
        elapsed_s: $elapsed,
        errors: .failures,
        p99_ms: null,
        p99_ttfb_ms: null
    })
' <<<"$origin_counts")"

start_gateway "$THREADS"
tls_json="$(run_measured_wrk tls-origin tls-origin "$DURATION" "$CONNECTIONS" "$THREADS" true)"
contention_file="${TMP_DIR}/pool-contention.json"
worker_sweep_json > "$contention_file"
contention_json="$(cat "$contention_file")"

jq -n \
    --argjson duration "$DURATION" \
    --argjson threads "$THREADS" \
    --argjson hot "$hot_json" \
    --argjson uneven_routes "$uneven_routes_json" \
    --argjson origins_aggregate "$origins_aggregate" \
    --argjson origins "$origins_json" \
    --argjson tls "$tls_json" \
    --argjson contention "$contention_json" \
    '{
        _meta: {
            suite: "upstream-pool-distribution",
            duration_s: $duration,
            worker_threads: $threads,
            note: "p99_ttfb_ms is measured from k6 http_req_waiting where present; p99_ms is wrk end-to-end latency."
        },
        scenarios: {
            "uneven-route-distribution": $uneven_routes,
            "many-origins-low-volume": ($origins_aggregate + {
                covered: (($origins | map(.errors // 0) | add) == 0),
                origins: ($origins | length),
                requests_per_origin: 5,
                measurements: $origins,
                errors: ($origins | map(.errors // 0) | add)
            }),
            "hot-origin-many-workers": $hot,
            "upstream-tls-handshake-reuse": $tls,
            "pool-contention": $contention
        }
    }' > "$OUTPUT"

echo "Wrote upstream-pool matrix: ${OUTPUT}"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi

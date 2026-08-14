#!/usr/bin/env bash
# Tardigrade benchmark runner.
# Runs configurable scenarios against a live Tardigrade instance and
# produces a JSON summary suitable for baseline comparison.
#
# Usage:
#   ./benchmarks/run.sh [OPTIONS]
#
# Options:
#   --host HOST         Target host (default: 127.0.0.1)
#   --port PORT         Target port (default: 8069)
#   --host-header NAME  Override the HTTP Host header / :authority
#   --driver LABEL      Load-driver label recorded in metadata
#   --worker-count N    Tardigrade worker count recorded in metadata
#   --config-label STR  Config/profile label recorded in metadata
#   --pid PID           Target Tardigrade process ID for CPU/RSS sampling
#   --pid-file FILE     File containing the target Tardigrade PID for CPU/RSS sampling
#   --pid-tree          Include child processes when sampling CPU/RSS/open FDs
#   --tls               Use HTTPS (default: plain HTTP)
#   --insecure          Skip TLS certificate verification (for self-signed certs)
#   --duration SECS     Benchmark duration per scenario (default: 30)
#   --connections N     Concurrent connections (default: 50)
#   --threads N         Worker threads for wrk (default: 4)
#   --static-path PATH  Path for static-http1 and reload-under-load (default: /health)
#   --proxy-path PATH   Path for proxy-http1/proxy-http2/proxy-http3 (default: /proxy/health)
#   --keepalive-path PATH  Path for keepalive (default: /health)
#   --proxy-payload-64k-path PATH  Path for 64 KiB proxied payload benchmark (default: /proxy/payload-64k.bin)
#   --proxy-payload-256k-path PATH  Path for 256 KiB proxied payload benchmark (default: /proxy/payload-256k.bin)
#   --proxy-payload-1m-path PATH    Path for 1 MiB proxied payload benchmark (default: /proxy/payload-1m.bin)
#   --proxy-payload-16m-path PATH   Path for 16 MiB proxied payload benchmark (default: /proxy/payload-16m.bin)
#   --proxy-upload-path PATH        Path for proxied upload benchmark (default: /proxy/upload-large)
#   --proxy-slow-client-path PATH   Path for slow-client download benchmark (default: /proxy/payload-16m.bin)
#   --slow-client-limit-rate RATE   curl --limit-rate value for slow clients (default: 1M)
#   --slow-client-connections N     Concurrent slow clients (default: 4)
#   --h2-path PATH      Path for static-http2 (default: same as --static-path)
#   --h3-path PATH      Path for static-http3 (default: same as --static-path)
#   --scenarios LIST    Comma-separated scenario names to run (default: all)
#   --tool TOOL         Preferred tool: wrk|h2load|fortio|k6 (default: auto-detect)
#   --baseline FILE     Compare results against a baseline JSON file
#   --save FILE         Write results JSON to this file
#   --meta-file FILE    Merge extra JSON metadata into _meta
#   --sample-interval-ms N  CPU/RSS sample interval in milliseconds (default: 500)
#   --runs N            Repeat each scenario N times; output mean ± stddev (default: 1)
#   --idle-check        Abort if load average exceeds 0.7× CPU count before starting
#   --metrics-path PATH Prometheus metrics path scraped for QUIC transport state on H3 scenarios (default: /status/metrics)
#   --help              Show this message and exit
#
# Scenarios:
#   static-http1        Static file serving over HTTP/1.1
#   proxy-http1         Reverse proxy over HTTP/1.1
#   static-http2        Static file serving over HTTP/2 (requires h2load or k6+TLS)
#   proxy-http2         Reverse proxy over HTTP/2 (requires h2load)
#   static-http3        Static file serving over HTTP/3 (requires h2load with QUIC + --tls)
#   proxy-http3         Reverse proxy over HTTP/3 (requires h2load with QUIC + --tls)
#   keepalive           Keep-alive connection reuse
#   keepalive-starvation  Idle keepalive holders + active burst — measures worker starvation (#204)
#   proxy-payload-64k   Reverse proxy 64 KiB payload transfer
#   proxy-payload-256k  Reverse proxy 256 KiB payload transfer
#   proxy-payload-1m    Reverse proxy 1 MiB payload transfer
#   proxy-payload-16m   Reverse proxy 16 MiB payload transfer
#   proxy-upload-large  Reverse proxy 1 MiB fixed-length upload (requires k6)
#   proxy-slow-client-download
#                       Reverse proxy download through rate-limited clients
#   reload-under-load   Trigger SIGHUP during a load run and measure degradation
#
# Prerequisites:
#   At least one of: wrk, h2load (nghttp2), fortio, k6
#   curl, jq (for result formatting and comparison)
#   A running Tardigrade process at the target host/port
#
# Baseline comparison:
#   Run once with --save baselines/$(git describe --tags).json to capture a release.
#   Run again with --baseline baselines/<previous>.json to detect regressions.
#   Exit code 2 indicates a regression above the threshold (default: 10%).

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
TARGET_HOST="127.0.0.1"
TARGET_PORT="8069"
HOST_HEADER=""
DRIVER_LABEL="local"
WORKER_COUNT=""
CONFIG_LABEL=""
TARGET_PID=""
PID_FILE=""
PID_TREE=false
USE_TLS=false
INSECURE=false
DURATION=30
CONNECTIONS=50
THREADS=4
STATIC_PATH="/health"
PROXY_PATH="/proxy/health"
KEEPALIVE_PATH="/health"
PROXY_PAYLOAD_64K_PATH="/proxy/payload-64k.bin"
PROXY_PAYLOAD_256K_PATH="/proxy/payload-256k.bin"
PROXY_PAYLOAD_1M_PATH="/proxy/payload-1m.bin"
PROXY_PAYLOAD_16M_PATH="/proxy/payload-16m.bin"
PROXY_UPLOAD_PATH="/proxy/upload-large"
PROXY_SLOW_CLIENT_PATH="/proxy/payload-16m.bin"
SLOW_CLIENT_LIMIT_RATE="1M"
SLOW_CLIENT_CONNECTIONS=4
H2_PATH=""      # defaults to STATIC_PATH after arg parsing
H3_PATH=""      # defaults to STATIC_PATH after arg parsing
SCENARIOS="static-http1,proxy-http1,keepalive"
PREFERRED_TOOL=""
BASELINE_FILE=""
SAVE_FILE=""
META_FILE=""
REGRESSION_THRESHOLD=10  # percent
SAMPLE_INTERVAL_MS=500
RUNS=1            # repeat each scenario N times; mean/stddev reported when N>1
IDLE_CHECK=false  # gate on machine load average before starting
# #256-G: Prometheus path scraped right after an H3 scenario finishes to
# attach a `quic` transport-state block (packet/loss/PTO counts, effective
# PLPMTU, ECN state, requested-vs-effective UDP buffers) to that result.
# Best-effort only — never fabricated when the endpoint is unreachable.
QUIC_METRICS_PATH="/status/metrics"

# ── Arg parsing ───────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)       TARGET_HOST="$2";        shift 2 ;;
        --port)       TARGET_PORT="$2";        shift 2 ;;
        --host-header)HOST_HEADER="$2";        shift 2 ;;
        --driver)     DRIVER_LABEL="$2";       shift 2 ;;
        --worker-count)WORKER_COUNT="$2";      shift 2 ;;
        --config-label)CONFIG_LABEL="$2";      shift 2 ;;
        --pid)        TARGET_PID="$2";         shift 2 ;;
        --pid-file)   PID_FILE="$2";           shift 2 ;;
        --pid-tree)   PID_TREE=true;           shift ;;
        --tls)        USE_TLS=true;            shift ;;
        --insecure)   INSECURE=true;           shift ;;
        --duration)   DURATION="$2";           shift 2 ;;
        --connections)CONNECTIONS="$2";        shift 2 ;;
        --threads)    THREADS="$2";            shift 2 ;;
        --static-path)STATIC_PATH="$2";        shift 2 ;;
        --proxy-path) PROXY_PATH="$2";         shift 2 ;;
        --keepalive-path)KEEPALIVE_PATH="$2";  shift 2 ;;
        --proxy-payload-64k-path)PROXY_PAYLOAD_64K_PATH="$2"; shift 2 ;;
        --proxy-payload-256k-path)PROXY_PAYLOAD_256K_PATH="$2"; shift 2 ;;
        --proxy-payload-1m-path)PROXY_PAYLOAD_1M_PATH="$2"; shift 2 ;;
        --proxy-payload-16m-path)PROXY_PAYLOAD_16M_PATH="$2"; shift 2 ;;
        --proxy-upload-path)PROXY_UPLOAD_PATH="$2"; shift 2 ;;
        --proxy-slow-client-path)PROXY_SLOW_CLIENT_PATH="$2"; shift 2 ;;
        --slow-client-limit-rate)SLOW_CLIENT_LIMIT_RATE="$2"; shift 2 ;;
        --slow-client-connections)SLOW_CLIENT_CONNECTIONS="$2"; shift 2 ;;
        --h2-path)    H2_PATH="$2";            shift 2 ;;
        --h3-path)    H3_PATH="$2";            shift 2 ;;
        --scenarios)  SCENARIOS="$2";          shift 2 ;;
        --tool)       PREFERRED_TOOL="$2";     shift 2 ;;
        --baseline)   BASELINE_FILE="$2";      shift 2 ;;
        --save)       SAVE_FILE="$2";          shift 2 ;;
        --meta-file)  META_FILE="$2";          shift 2 ;;
        --threshold)  REGRESSION_THRESHOLD="$2"; shift 2 ;;
        --sample-interval-ms) SAMPLE_INTERVAL_MS="$2"; shift 2 ;;
        --runs)       RUNS="$2";               shift 2 ;;
        --idle-check) IDLE_CHECK=true;         shift ;;
        --metrics-path) QUIC_METRICS_PATH="$2"; shift 2 ;;
        --help)       sed -n '/^# Usage/,/^[^#]/p' "$0" | sed '$d'; exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

H2_PATH="${H2_PATH:-$STATIC_PATH}"
H3_PATH="${H3_PATH:-$STATIC_PATH}"
SCHEME=$( $USE_TLS && echo "https" || echo "http" )
BASE_URL="${SCHEME}://${TARGET_HOST}:${TARGET_PORT}"
REQUEST_HEADERS=()
if [[ -n "$HOST_HEADER" ]]; then
    REQUEST_HEADERS+=("Host: $HOST_HEADER")
fi

# ── Tool detection ─────────────────────────────────────────────────────────────
detect_tool() {
    local preferred="$1"
    if [[ -n "$preferred" ]]; then
        if command -v "$preferred" &>/dev/null; then echo "$preferred"; return; fi
        echo "Requested tool '$preferred' not found" >&2; exit 1
    fi
    for t in wrk h2load fortio k6; do
        if command -v "$t" &>/dev/null; then echo "$t"; return; fi
    done
    echo "No benchmark tool found. Install wrk, h2load (nghttp2), fortio, or k6." >&2
    exit 1
}

detect_zig_version() {
    if command -v zig &>/dev/null; then
        zig version
    else
        echo "unknown"
    fi
}

detect_os_name() {
    uname -s 2>/dev/null || echo "unknown"
}

detect_kernel_release() {
    uname -r 2>/dev/null || echo "unknown"
}

detect_arch() {
    uname -m 2>/dev/null || echo "unknown"
}

detect_cpu_model() {
    case "$(uname -s 2>/dev/null || true)" in
        Darwin)
            sysctl -n machdep.cpu.brand_string 2>/dev/null || sysctl -n hw.model 2>/dev/null || echo "unknown"
            ;;
        Linux)
            if command -v lscpu &>/dev/null; then
                lscpu | awk -F: '/Model name:/{gsub(/^[ \t]+/, "", $2); print $2; exit}'
            elif [[ -r /proc/cpuinfo ]]; then
                awk -F: '/model name/{gsub(/^[ \t]+/, "", $2); print $2; exit}' /proc/cpuinfo
            else
                echo "unknown"
            fi
            ;;
        *)
            echo "unknown"
            ;;
    esac
}

detect_cpu_threads() {
    getconf _NPROCESSORS_ONLN 2>/dev/null || echo "unknown"
}

detect_memory_mb() {
    case "$(uname -s 2>/dev/null || true)" in
        Darwin)
            local bytes
            bytes=$(sysctl -n hw.memsize 2>/dev/null || echo 0)
            awk -v b="$bytes" 'BEGIN { printf "%.0f", b / 1048576 }'
            ;;
        Linux)
            if [[ -r /proc/meminfo ]]; then
                awk '/MemTotal:/{printf "%.0f", $2 / 1024}' /proc/meminfo
            else
                echo "unknown"
            fi
            ;;
        *)
            echo "unknown"
            ;;
    esac
}

check_machine_idle() {
    local cpu_count threshold load1
    cpu_count=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)
    # Gate: load average must be below 0.7 × CPU count.
    threshold=$(awk -v n="$cpu_count" 'BEGIN { printf "%.2f", n * 0.7 }')
    case "$(uname -s 2>/dev/null || true)" in
        Darwin)
            load1=$(sysctl -n vm.loadavg 2>/dev/null | awk '{print $2}')
            ;;
        Linux)
            load1=$(awk '{print $1}' /proc/loadavg 2>/dev/null || echo "0")
            ;;
        *)
            echo "  --idle-check: unsupported platform; skipping load check" >&2
            return 0
            ;;
    esac
    local ok
    ok=$(awk -v l="${load1:-0}" -v t="$threshold" 'BEGIN { print (l < t) ? "yes" : "no" }')
    if [[ "$ok" != "yes" ]]; then
        echo "ERROR: --idle-check failed: load average ${load1} >= threshold ${threshold} (0.7 × ${cpu_count} CPUs)" >&2
        echo "       Wait for the machine to idle or omit --idle-check for a non-canonical run." >&2
        exit 1
    fi
    echo "Idle check passed: load=${load1} threshold=${threshold} (${cpu_count} CPUs)"
}

# ── Multi-run variance helpers ─────────────────────────────────────────────────
# awk-based mean/stddev so jq is not required for the math.
_stats_from_space_list() {
    local values="$1"
    awk -v vals="$values" 'BEGIN {
        n = split(vals, a, " ")
        if (n == 0) { print "null null null null"; exit }
        sum = 0; sum2 = 0
        min = a[1]; max = a[1]
        for (i = 1; i <= n; i++) {
            v = a[i] + 0
            sum += v
            sum2 += v * v
            if (v < min) min = v
            if (v > max) max = v
        }
        mean = sum / n
        if (n > 1) {
            variance = (sum2 - sum * sum / n) / (n - 1)
            stddev = (variance > 0) ? sqrt(variance) : 0
        } else {
            stddev = 0
        }
        printf "%.3f %.3f %.3f %.3f", mean, stddev, min, max
    }'
}

resolve_target_pid() {
    if [[ -n "$TARGET_PID" ]]; then
        printf '%s\n' "$TARGET_PID"
        return 0
    fi
    if [[ -n "$PID_FILE" ]]; then
        if [[ ! -f "$PID_FILE" ]]; then
            echo "PID file not found: $PID_FILE" >&2
            exit 1
        fi
        tr -d '[:space:]' < "$PID_FILE"
        return 0
    fi
    return 1
}

latency_value_to_ms() {
    local value="$1"
    if [[ -z "$value" || "$value" == "null" ]]; then
        echo "null"
        return 0
    fi
    awk -v v="$value" 'BEGIN {
        if (v ~ /us$/) { sub(/us$/, "", v); printf "%.3f", v / 1000; exit }
        if (v ~ /ms$/) { sub(/ms$/, "", v); printf "%.3f", v + 0; exit }
        if (v ~ /s$/)  { sub(/s$/, "", v);  printf "%.3f", v * 1000; exit }
        printf "%.3f", v + 0
    }'
}

percentile_from_file() {
    local file="$1" percentile="$2"
    if [[ ! -s "$file" ]]; then
        echo "null"
        return 0
    fi
    sort -n "$file" | awk -v pct="$percentile" '
        { values[++n] = $1 }
        END {
            if (n == 0) { print "null"; exit }
            rank = int((pct / 100.0) * n + 0.999999)
            if (rank < 1) rank = 1
            if (rank > n) rank = n
            printf "%.3f", values[rank]
        }'
}

wrk_percentile_ms() {
    local raw="$1" percentile="$2"
    local value
    value=$(printf '%s\n' "$raw" | awk -v pct="$percentile" '$1 == pct { print $2; exit }')
    latency_value_to_ms "$value"
}

# #256-G review: adjacency-based text parsing (grep for a percentile label,
# take the nearest number+unit) cannot work against h2load's *current*
# text-table output at all, for two independent reasons verified against a
# real nghttp2 1.69.0 build (the version --h3 requires): the label spelling
# changed ("50th"/"95th"/"99th" -> "median"/"p95"/"p99"), and — the part no
# amount of label-matching could fix — the labels and values now live in
# different table rows/columns (a header row naming the columns, then one
# data row per metric), not adjacent to each other on the same line.
# h2load's structured `--output-file=<path>` JSON export (see
# parse_h2load_json_result below) is the only interface that is stable to
# parse on a build that has it. But `--output-file` itself is a 1.69+
# addition — it does not exist on the older h2load still shipped by stock
# apt/brew packages, and unlike an unrecognized flag causing a clean exit,
# there is no reason to make plain HTTP/2 benchmarking (run_h2load, which
# never needs --h3 or QUIC) hard-require a feature only present in the same
# build that added QUIC support. `extract_h2load_percentile_ms` is that
# older build's text-table format — "50th"/"95th"/"99th" labels immediately
# adjacent to their number+unit on the same line — kept alive as a fallback
# for exactly that case, gated on H2LOAD_OUTPUT_FILE_SUPPORTED (see below).
# It is never used against a build that has --output-file, so it never has
# to cope with the new table layout above.
extract_h2load_percentile_ms() {
    local raw="$1" percentile="$2"
    local pattern
    case "$percentile" in
        50) pattern='50th' ;;
        95) pattern='95th' ;;
        99) pattern='99th' ;;
        99.9) pattern='99.9th' ;;
        *) echo "null"; return 0 ;;
    esac
    local value
    value=$(printf '%s\n' "$raw" | grep -E "$pattern" | grep -oE '[0-9.]+ (us|ms|s)' | head -1 | tr -d ' ')
    latency_value_to_ms "$value"
}

# Parses one h2load `--output-file=<path>` JSON document (schema verified
# against a real nghttp2 1.69.0 build) into this script's usual
# rps/p50/p95/p99/p999/errors/tput_mbps shape. Sets those variables directly
# in the caller's scope — they must already be `local` there — rather than
# returning a value, since every caller needs all seven at once anyway.
#
# `errors` is `requests.failed` alone (#256-G review: `.failed`/.errored`/
# `.timeout` are not disjoint counters — h2load already folds
# connection/transport errors and timeouts into `.failed`, so summing all
# three double- or triple-counts the same bad request).
#
# A missing, empty, or invalid JSON document — h2load crashed, was killed,
# or wrote nothing — is treated as a failed pass (rps=0, an explicit
# non-zero errors sentinel, every latency null), never as a fabricated
# clean zero-error result silently indistinguishable from an idle server.
parse_h2load_json_result() {
    local json_file="$1"
    if [[ ! -s "$json_file" ]] || ! jq -e '.measurements' "$json_file" >/dev/null 2>&1; then
        rps=0
        p50="null"; p95="null"; p99="null"; p999="null"
        errors=1
        tput_mbps="null"
        return 1
    fi
    rps=$(jq -r '(.measurements.request_per_second // 0) | floor' "$json_file")
    # #256-G review: requests.failed/.errored/.timeout are not disjoint —
    # h2load already folds connection/transport errors and timeouts into
    # requests.failed, so summing all three double- or triple-counts the
    # same bad request. requests.failed alone is the authoritative "not a
    # clean success" count for this script's single errors column.
    errors=$(jq -r '.measurements.requests.failed // 0' "$json_file")
    p50=$(jq -r '.measurements.performance.request.median as $v | if $v == null then null else (($v * 1000000 | round) / 1000) end' "$json_file")
    p95=$(jq -r '.measurements.performance.request.p95 as $v | if $v == null then null else (($v * 1000000 | round) / 1000) end' "$json_file")
    p99=$(jq -r '.measurements.performance.request.p99 as $v | if $v == null then null else (($v * 1000000 | round) / 1000) end' "$json_file")
    p999="null"
    tput_mbps=$(jq -r '.measurements.bytes_per_second as $v | if $v == null then null else (($v / 1048576 * 100 | round) / 100) end' "$json_file")
    return 0
}

average_column_or_null() {
    local file="$1" column="$2"
    awk -v col="$column" '
        NF >= col {
            sum += $col
            count += 1
        }
        END {
            if (count > 0) {
                printf "%.2f", sum / count
            } else {
                printf "null"
            }
        }
    ' "$file"
}

peak_rss_mb_or_null() {
    local file="$1"
    awk '
        NF >= 1 && $1 > max { max = $1 }
        END {
            if (max > 0) {
                printf "%.2f", max / 1024
            } else {
                printf "null"
            }
        }
    ' "$file"
}

wrk_error_count() {
    awk '
        /Non-2xx/ {
            for (i = 1; i <= NF; i++) {
                if ($i ~ /^[0-9]+$/) total += $i
            }
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

MONITOR_FILE=""
MONITOR_PID=""
CURRENT_CPU_PCT_AVG="null"
CURRENT_RSS_MB_PEAK="null"
CURRENT_OPEN_FDS_PEAK="null"
CPU_BEFORE_SECONDS="null"
MONITOR_START_NS="null"

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

process_tree_cpu_seconds() {
    local pid="$1"
    local pids clk total_ticks child
    if $PID_TREE; then
        pids="$(process_tree_pids "$pid" | paste -sd, -)"
    else
        pids="$pid"
    fi
    [[ -n "$pids" ]] || pids="$pid"
    if [[ "$(uname -s 2>/dev/null || true)" == "Linux" ]]; then
        clk="$(getconf CLK_TCK 2>/dev/null || true)"
        if [[ "$clk" =~ ^[0-9]+$ && "$clk" -gt 0 ]]; then
            total_ticks=0
            IFS=, read -ra _cpu_pids <<< "$pids"
            for child in "${_cpu_pids[@]}"; do
                [[ -r "/proc/${child}/stat" ]] || continue
                total_ticks=$((total_ticks + $(awk '{
                    paren_idx = match($0, /\) /)
                    rest = substr($0, paren_idx + 2)
                    split(rest, f, " ")
                    print (f[12] + f[13])
                }' "/proc/${child}/stat")))
            done
            awk -v ticks="$total_ticks" -v clk="$clk" 'BEGIN { printf "%.6f", ticks / clk }'
            return
        fi
    fi
    ps -p "$pids" -o time= 2>/dev/null | cpu_time_to_seconds
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

monitor_target_process() {
    local pid="$1" sample_interval_s="$2" outfile="$3"
    while kill -0 "$pid" 2>/dev/null; do
        local pids
        if $PID_TREE; then
            process_tree_pids "$pid" | paste -sd, - | {
                read -r pids
                [[ -n "$pids" ]] || pids="$pid"
                local fds
                fds="$(count_open_fds_for_pids "$pids")"
                ps -p "$pids" -o rss= 2>/dev/null |
                    awk -v fds="$fds" '{ rss += $1 } END { if (rss > 0) print rss, fds }' >> "$outfile"
            }
        else
            local fds
            fds="$(count_open_fds_for_pids "$pid")"
            ps -p "$pid" -o rss= 2>/dev/null | awk -v fds="$fds" 'NF >= 1 { print $1, fds; exit }' >> "$outfile"
        fi
        sleep "$sample_interval_s"
    done
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

start_process_monitor() {
    CURRENT_CPU_PCT_AVG="null"
    CURRENT_RSS_MB_PEAK="null"
    CURRENT_OPEN_FDS_PEAK="null"
    CPU_BEFORE_SECONDS="null"
    MONITOR_START_NS="null"
    MONITOR_FILE=""
    MONITOR_PID=""

    local pid
    if ! pid=$(resolve_target_pid 2>/dev/null); then
        return 0
    fi
    if ! kill -0 "$pid" 2>/dev/null; then
        echo "Target PID $pid is not running" >&2
        exit 1
    fi

    local sample_interval_s
    sample_interval_s=$(awk -v ms="$SAMPLE_INTERVAL_MS" 'BEGIN { printf "%.3f", ms / 1000 }')
    CPU_BEFORE_SECONDS="$(process_tree_cpu_seconds "$pid")"
    MONITOR_START_NS="$(monotonic_ns)"
    MONITOR_FILE=$(mktemp /tmp/tardigrade-bench-monitor-XXXXXX)
    monitor_target_process "$pid" "$sample_interval_s" "$MONITOR_FILE" &
    MONITOR_PID="$!"
}

stop_process_monitor() {
    if [[ -n "$MONITOR_PID" ]]; then
        kill "$MONITOR_PID" 2>/dev/null || true
        wait "$MONITOR_PID" 2>/dev/null || true
        MONITOR_PID=""
    fi
    if [[ -n "$MONITOR_FILE" && -f "$MONITOR_FILE" ]]; then
        local pid cpu_after end_ns
        if pid=$(resolve_target_pid 2>/dev/null); then
            cpu_after="$(process_tree_cpu_seconds "$pid")"
            end_ns="$(monotonic_ns)"
            CURRENT_CPU_PCT_AVG=$(awk -v before="$CPU_BEFORE_SECONDS" -v after="$cpu_after" -v start="$MONITOR_START_NS" -v end="$end_ns" '
                BEGIN {
                    elapsed = (end - start) / 1000000000
                    if (before != "null" && elapsed > 0) printf "%.2f", ((after - before) / elapsed) * 100
                    else printf "null"
                }')
        fi
        CURRENT_RSS_MB_PEAK=$(peak_rss_mb_or_null "$MONITOR_FILE")
        CURRENT_OPEN_FDS_PEAK=$(awk 'NF >= 2 && $2 ~ /^[0-9]+$/ && $2 > max { max = $2 } END { if (max > 0) printf "%d", max; else printf "null" }' "$MONITOR_FILE")
        rm -f "$MONITOR_FILE"
        MONITOR_FILE=""
    fi
}

if $IDLE_CHECK; then
    check_machine_idle
fi

TOOL=$(detect_tool "$PREFERRED_TOOL")
echo "Using tool: $TOOL"
if [[ "$RUNS" -gt 1 ]]; then
    echo "Runs per scenario: $RUNS (mean ± stddev will be reported)"
fi

# ── Result accumulator ────────────────────────────────────────────────────────
RESULTS_JSON="{}"
TOOL_HEADERS=()

# Per-scenario run accumulators (space-separated lists, populated by add_result
# when RUNS>1 and cleared by flush_multirun_result at the end of each scenario).
declare -A _run_rps_list=()
declare -A _run_p99_list=()
declare -A _run_errors_list=()
# #256-G review: per-run scenario-local QUIC transport deltas (JSON array,
# one element per completed run), so `--runs > 1` doesn't silently drop the
# transport evidence every H3 result is supposed to carry. Aggregated into
# `.[$s].quic` by flush_multirun_result.
declare -A _run_quic_list=()

add_result() {
    local scenario="$1" rps="$2" p50_ms="$3" p95_ms="$4" p99_ms="$5" p999_ms="$6" errors="$7" mbps="${8:-null}" cpu_pct_avg="${9:-null}" rss_mb_peak="${10:-null}" open_fds_peak="${11:-$CURRENT_OPEN_FDS_PEAK}"

    if [[ "$RUNS" -gt 1 ]]; then
        # Accumulate for this run; flush_multirun_result builds the final entry.
        _run_rps_list["$scenario"]+="${rps} "
        _run_p99_list["$scenario"]+="${p99_ms:-0} "
        _run_errors_list["$scenario"]+="${errors} "
        return
    fi

    RESULTS_JSON=$(jq --arg s "$scenario" \
        --argjson rps "$rps" \
        --argjson p50 "$p50_ms" --argjson p95 "$p95_ms" --argjson p99 "$p99_ms" --argjson p999 "$p999_ms" \
        --argjson err "$errors" --argjson mbps "$mbps" --argjson cpu "$cpu_pct_avg" --argjson rss "$rss_mb_peak" --argjson fds "$open_fds_peak" \
        '.[$s] = {
            rps: $rps,
            p50_ms: $p50,
            p95_ms: $p95,
            p99_ms: $p99,
            p999_ms: $p999,
            errors: $err,
            throughput_mbps: $mbps,
            cpu_pct_avg: $cpu,
            rss_mb_peak: $rss,
            open_fds_peak: $fds
        }' \
        <<<"$RESULTS_JSON")
}

# After all N runs of a scenario complete, compute mean/stddev/min/max and
# write a single result entry enriched with variance fields.
flush_multirun_result() {
    local scenario="$1"
    local rps_vals p99_vals err_vals
    rps_vals="${_run_rps_list[$scenario]:-}"
    p99_vals="${_run_p99_list[$scenario]:-}"
    err_vals="${_run_errors_list[$scenario]:-}"

    [[ -z "$rps_vals" ]] && return

    local rps_stats p99_stats
    rps_stats=$(_stats_from_space_list "${rps_vals% }")
    p99_stats=$(_stats_from_space_list "${p99_vals% }")

    local rps_mean rps_stddev rps_min rps_max
    read -r rps_mean rps_stddev rps_min rps_max <<<"$rps_stats"
    local p99_mean p99_stddev p99_min p99_max
    read -r p99_mean p99_stddev p99_min p99_max <<<"$p99_stats"

    local total_errors
    total_errors=$(echo "${err_vals% }" | awk '{s=0; for(i=1;i<=NF;i++) s+=$i; print s}')

    echo "  $scenario (${RUNS} runs) — rps mean=${rps_mean} stddev=${rps_stddev} min=${rps_min} max=${rps_max} | p99 mean=${p99_mean}ms stddev=${p99_stddev}ms"

    RESULTS_JSON=$(jq --arg s "$scenario" \
        --argjson rps "$rps_mean" \
        --argjson rps_stddev "$rps_stddev" --argjson rps_min "$rps_min" --argjson rps_max "$rps_max" \
        --argjson p99 "$p99_mean" \
        --argjson p99_stddev "$p99_stddev" --argjson p99_min "$p99_min" --argjson p99_max "$p99_max" \
        --argjson err "$total_errors" --argjson runs "$RUNS" \
        '.[$s] = {
            rps: $rps,
            rps_stddev: $rps_stddev,
            rps_min: $rps_min,
            rps_max: $rps_max,
            p99_ms: $p99,
            p99_ms_stddev: $p99_stddev,
            p99_ms_min: $p99_min,
            p99_ms_max: $p99_max,
            errors: $err,
            runs: $runs
        }' \
        <<<"$RESULTS_JSON")

    # #256-G review: aggregate the per-run scenario-local QUIC deltas
    # accumulated by attach_quic_transport_state, so a repeated H3 scenario
    # still carries transport evidence instead of silently omitting it.
    # Counters sum across runs; effective_plpmtu/udp_buffers/ecn.enabled use
    # the last run's post-pass state (they're gauges, not counters — summing
    # them would be meaningless).
    #
    # `runs_total` is the full accumulated array length — including runs
    # where the scrape came back null — since attach_quic_transport_state
    # now appends nulls too instead of skipping them (see its own comment):
    # a two-run scenario with one missing scrape must report
    # `runs_total: 2, runs_with_data: 1`, not silently collapse to
    # `runs_total: 1` as if only one run had ever happened. If every run's
    # scrape came back null, this still emits a `quic` block — with
    # `runs_with_data: 0` and every counter/gauge explicitly null — rather
    # than omitting the field entirely, which would be indistinguishable
    # from a scenario that never attempted QUIC evidence collection at all.
    local quic_runs="${_run_quic_list[$scenario]:-}"
    if [[ -n "$quic_runs" ]]; then
        local quic_agg
        quic_agg=$(jq -c '
            (map(select(. != null))) as $valid |
            {
                runs_total: (. | length),
                runs_with_data: ($valid | length)
            } + (if ($valid | length) == 0 then {
                packets_sent: null, packets_received: null, packets_lost: null, pto_total: null,
                bytes_sent: null, bytes_received: null, effective_plpmtu: null,
                pmtu_probes: null, pmtu_black_holes: null, ecn: null, udp_buffers: null
            } else {
                packets_sent: ($valid | map(.packets_sent) | add),
                packets_received: ($valid | map(.packets_received) | add),
                packets_lost: ($valid | map(.packets_lost) | add),
                pto_total: ($valid | map(.pto_total) | add),
                bytes_sent: ($valid | map(.bytes_sent) | add),
                bytes_received: ($valid | map(.bytes_received) | add),
                effective_plpmtu: ($valid[-1].effective_plpmtu),
                pmtu_probes: ($valid | map(.pmtu_probes) | add),
                pmtu_black_holes: ($valid | map(.pmtu_black_holes) | add),
                ecn: {
                    enabled: ($valid[-1].ecn.enabled),
                    marked_sent: ($valid | map(.ecn.marked_sent) | add),
                    paths_validated: ($valid | map(.ecn.paths_validated) | add),
                    paths_disabled: ($valid | map(.ecn.paths_disabled) | add),
                    ce_received: ($valid | map(.ecn.ce_received) | add)
                },
                udp_buffers: ($valid[-1].udp_buffers)
            } end)
        ' <<<"$quic_runs")
        RESULTS_JSON=$(jq --arg s "$scenario" --argjson quic "$quic_agg" '.[$s].quic = $quic' <<<"$RESULTS_JSON")
        unset "_run_quic_list[$scenario]"
    fi

    unset "_run_rps_list[$scenario]"
    unset "_run_p99_list[$scenario]"
    unset "_run_errors_list[$scenario]"
}

build_tool_headers() {
    local opt="$1"
    TOOL_HEADERS=()
    [[ ${#REQUEST_HEADERS[@]} -eq 0 ]] && return 0
    local header
    for header in "${REQUEST_HEADERS[@]}"; do
        TOOL_HEADERS+=("$opt" "$header")
    done
}

# ── wrk runner ────────────────────────────────────────────────────────────────
run_wrk() {
    local url="$1" label="$2"
    local extra=()
    $INSECURE && extra+=(--insecure)
    build_tool_headers -H
    [[ ${#TOOL_HEADERS[@]} -gt 0 ]] && extra+=("${TOOL_HEADERS[@]}")
    local raw summary_json
    start_process_monitor
    raw=$(wrk --latency -s "$(dirname "$0")/wrk-summary.lua" -t"$THREADS" -c"$CONNECTIONS" -d"${DURATION}s" \
        ${extra[@]+"${extra[@]}"} "$url" 2>&1) || true
    stop_process_monitor
    local rps p50 p95 p99 p999 errors
    summary_json=$(printf '%s\n' "$raw" | sed -n 's/^WRK_SUMMARY //p' | tail -1)
    if [[ -z "$summary_json" ]]; then
        echo "wrk summary hook did not emit percentile JSON" >&2
        echo "$raw" >&2
        exit 1
    fi
    rps=$(echo "$summary_json" | jq -r '.rps // 0')
    p50=$(echo "$summary_json" | jq -r '.p50_ms // null')
    p95=$(echo "$summary_json" | jq -r '.p95_ms // null')
    p99=$(echo "$summary_json" | jq -r '.p99_ms // null')
    p999=$(echo "$summary_json" | jq -r '.p999_ms // null')
    errors=$(printf '%s\n' "$raw" | wrk_error_count)
    rps=${rps:-0}; errors=${errors:-0}
    local tput_mbps
    tput_mbps=$(echo "$summary_json" | jq -r '.throughput_mbps // null')
    tput_mbps="${tput_mbps:-null}"
    local tput_display=""
    local cpu_display="" rss_display=""
    [[ "$tput_mbps" != "null" ]] && tput_display="  throughput=${tput_mbps}MB/s"
    [[ "$CURRENT_CPU_PCT_AVG" != "null" ]] && cpu_display="  cpu=${CURRENT_CPU_PCT_AVG}%"
    [[ "$CURRENT_RSS_MB_PEAK" != "null" ]] && rss_display="  rss_peak=${CURRENT_RSS_MB_PEAK}MiB"
    echo "  $label — ${rps} req/s  p50=${p50}ms  p95=${p95}ms  p99=${p99}ms  p999=${p999}ms  errors=${errors}${tput_display}${cpu_display}${rss_display}"
    add_result "$label" "$rps" "$p50" "$p95" "$p99" "$p999" "$errors" "$tput_mbps" "$CURRENT_CPU_PCT_AVG" "$CURRENT_RSS_MB_PEAK"
}

# #256-G review: `--output-file` (the structured JSON export parsed by
# parse_h2load_json_result) is a 1.69+ addition — the same build that added
# --h3/QUIC. run_h2load benchmarks plain HTTP/2 and never needs --h3, so it
# has no real reason to require that build; the older h2load still shipped
# by stock apt/brew packages fully supports HTTP/2 but doesn't recognize
# --output-file at all, and (like the --insecure case above) an unrecognized
# flag makes h2load exit immediately instead of running the benchmark. This
# checks for the flag directly rather than sniffing a version number, since
# that's the thing that actually matters and avoids parsing yet another
# version-string format.
h2load_output_file_supported() {
    h2load --help 2>&1 | grep -q -- '--output-file'
}

# ── h2load runner ─────────────────────────────────────────────────────────────
run_h2load() {
    local url="$1" label="$2"
    local extra=()
    # #256-G review: h2load has no --insecure/verify-skip flag at all
    # (verified against a real nghttp2 1.69.0 build) — it never validates
    # TLS certificates in the first place, so there's nothing to skip, and
    # passing an option it doesn't recognize makes it exit immediately.
    # $INSECURE is intentionally not forwarded here.
    build_tool_headers -H
    [[ ${#TOOL_HEADERS[@]} -gt 0 ]] && extra+=("${TOOL_HEADERS[@]}")
    local rps p50 p95 p99 p999 errors tput_mbps
    local raw
    if h2load_output_file_supported; then
        local out_json; out_json=$(mktemp /tmp/tardigrade-bench-h2load-XXXXXX.json)
        start_process_monitor
        # #256-G review: --duration is h2load's real timing-based mode (verified
        # wall-clock-accurate against a real build); the previous -n synthesis
        # only ever approximated the requested duration and could finish in a
        # fraction of it on a fast target while _meta.duration_s still claimed
        # the requested value.
        raw=$(h2load --duration "${DURATION}s" \
            -c "$CONNECTIONS" -t "$THREADS" --output-file="$out_json" \
            ${extra[@]+"${extra[@]}"} "$url" 2>&1) || true
        stop_process_monitor
        if ! parse_h2load_json_result "$out_json"; then
            echo "  $label — h2load produced no usable --output-file JSON; recording as a failed pass. Raw output:" >&2
            printf '%s\n' "$raw" | tail -20 >&2
        fi
        rm -f "$out_json"
    else
        echo "  $label — h2load has no --output-file support (pre-1.69 build); falling back to text-table parsing"
        start_process_monitor
        raw=$(h2load --duration "${DURATION}s" \
            -c "$CONNECTIONS" -t "$THREADS" \
            ${extra[@]+"${extra[@]}"} "$url" 2>&1) || true
        stop_process_monitor
        rps=$(echo "$raw" | grep -E "^finished" | grep -oE '[0-9.]+ req/s' | grep -oE '[0-9.]+' || echo 0)
        p50=$(extract_h2load_percentile_ms "$raw" "50")
        p95=$(extract_h2load_percentile_ms "$raw" "95")
        p99=$(extract_h2load_percentile_ms "$raw" "99")
        p999=$(extract_h2load_percentile_ms "$raw" "99.9")
        errors=$(echo "$raw" | grep -oE 'failed: [0-9]+' | grep -oE '[0-9]+' | head -1 || echo 0)
        rps=${rps:-0}; errors=${errors:-0}
        tput_mbps=$(echo "$raw" | grep -E "^finished" | grep -oE '[0-9.]+[KMG]B/s' | awk '{
            v=$1
            if (v ~ /GB\/s$/) { sub(/GB\/s$/, "", v); printf "%.2f", v*1024; exit }
            if (v ~ /MB\/s$/) { sub(/MB\/s$/, "", v); printf "%.2f", v; exit }
            if (v ~ /KB\/s$/) { sub(/KB\/s$/, "", v); printf "%.2f", v/1024; exit }
        }')
        tput_mbps="${tput_mbps:-null}"
    fi
    local tput_display="" cpu_display="" rss_display=""
    [[ "$tput_mbps" != "null" ]] && tput_display="  throughput=${tput_mbps}MB/s"
    [[ "$CURRENT_CPU_PCT_AVG" != "null" ]] && cpu_display="  cpu=${CURRENT_CPU_PCT_AVG}%"
    [[ "$CURRENT_RSS_MB_PEAK" != "null" ]] && rss_display="  rss_peak=${CURRENT_RSS_MB_PEAK}MiB"
    echo "  $label — ${rps} req/s  p50=${p50}ms  p95=${p95}ms  p99=${p99}ms  p999=${p999}ms  errors=${errors}${tput_display}${cpu_display}${rss_display}"
    add_result "$label" "$rps" "$p50" "$p95" "$p99" "$p999" "$errors" "$tput_mbps" "$CURRENT_CPU_PCT_AVG" "$CURRENT_RSS_MB_PEAK"
}

# ── QUIC transport-state capture (#256-G) ─────────────────────────────────────
# Best-effort scrape of the Prometheus metrics endpoint right after an H3
# scenario finishes, so its JSON result can explain *why* the numbers came
# out the way they did: packet/loss/PTO counts, the PLPMTU actually in
# effect, ECN state, and requested-vs-effective UDP socket buffer sizes.
# Requested and effective/granted are always read from separate metric
# series (never inferred from one another) — see docs/HTTP3_ROLLOUT.md.
# Returns the string "null" (not an error) when the endpoint is unreachable
# or HTTP/3 metrics are absent — a benchmark result should say "this could
# not be observed" rather than fabricate it.
quic_metric() {
    local body="$1" name="$2"
    printf '%s\n' "$body" | awk -v m="$name" '$1 == m { print $2; exit }'
}

quic_metric_labeled() {
    local body="$1" pattern="$2"
    printf '%s\n' "$body" | awk -v m="$pattern" '$0 ~ ("^" m) { print $2; exit }'
}

quic_buffer_status_label() {
    local body="$1" direction="$2"
    printf '%s\n' "$body" \
        | grep -oE "tardigrade_quic_udp_buffer_status\\{direction=\"${direction}\",status=\"[a-z]+\"\\}" \
        | grep -oE 'status="[a-z]+"' | sed -E 's/status="([a-z]+)"/\1/' | head -1
}

capture_quic_transport_state() {
    local url="${SCHEME}://${TARGET_HOST}:${TARGET_PORT}${QUIC_METRICS_PATH}"
    local extra=()
    $INSECURE && extra+=(--insecure)
    local body
    if ! body=$(curl -fsS "${extra[@]+"${extra[@]}"}" "$url" 2>/dev/null); then
        echo "null"
        return 0
    fi

    local packets_sent
    packets_sent=$(quic_metric "$body" tardigrade_quic_packets_sent_total)
    if [[ -z "$packets_sent" ]]; then
        # Endpoint answered but exposes no QUIC series at all (HTTP/3 metrics
        # disabled, or this isn't a Tardigrade /status/metrics endpoint).
        echo "null"
        return 0
    fi

    local packets_received packets_lost pto bytes_sent bytes_received
    packets_received=$(quic_metric "$body" tardigrade_quic_packets_received_total)
    packets_lost=$(quic_metric "$body" tardigrade_quic_packets_lost_total)
    pto=$(quic_metric "$body" tardigrade_quic_pto_total)
    bytes_sent=$(quic_metric "$body" tardigrade_quic_bytes_sent_total)
    bytes_received=$(quic_metric "$body" tardigrade_quic_bytes_received_total)

    # #256-G review: _lifetime_min/_lifetime_max never reset and are not
    # scoped to any single benchmark scenario or pass — see the matching
    # rename/doc comment on http3_runtime.Snapshot. Do not treat them as
    # evidence of path convergence within one run.
    local pmtu_probes pmtu_black_holes plpmtu_last plpmtu_lifetime_min plpmtu_lifetime_max
    pmtu_probes=$(quic_metric "$body" tardigrade_quic_pmtu_probes_total)
    pmtu_black_holes=$(quic_metric "$body" tardigrade_quic_pmtu_black_holes_total)
    plpmtu_last=$(quic_metric "$body" tardigrade_quic_effective_plpmtu_bytes_last)
    plpmtu_lifetime_min=$(quic_metric "$body" tardigrade_quic_effective_plpmtu_bytes_lifetime_min)
    plpmtu_lifetime_max=$(quic_metric "$body" tardigrade_quic_effective_plpmtu_bytes_lifetime_max)

    local ecn_enabled ecn_marked ecn_validated ecn_disabled ecn_ce
    ecn_enabled=$(quic_metric "$body" tardigrade_quic_ecn_enabled)
    ecn_marked=$(quic_metric "$body" tardigrade_quic_ecn_marked_sent_total)
    ecn_validated=$(quic_metric "$body" tardigrade_quic_ecn_paths_validated_total)
    ecn_disabled=$(quic_metric "$body" tardigrade_quic_ecn_paths_disabled_total)
    ecn_ce=$(quic_metric "$body" tardigrade_quic_ecn_ce_received_total)

    local recv_req recv_eff recv_grant recv_status send_req send_eff send_grant send_status
    recv_req=$(quic_metric_labeled "$body" 'tardigrade_quic_udp_buffer_requested_bytes\{direction="recv"\}')
    recv_eff=$(quic_metric_labeled "$body" 'tardigrade_quic_udp_buffer_effective_bytes\{direction="recv"\}')
    recv_grant=$(quic_metric_labeled "$body" 'tardigrade_quic_udp_buffer_granted_bytes\{direction="recv"\}')
    recv_status=$(quic_buffer_status_label "$body" recv)
    send_req=$(quic_metric_labeled "$body" 'tardigrade_quic_udp_buffer_requested_bytes\{direction="send"\}')
    send_eff=$(quic_metric_labeled "$body" 'tardigrade_quic_udp_buffer_effective_bytes\{direction="send"\}')
    send_grant=$(quic_metric_labeled "$body" 'tardigrade_quic_udp_buffer_granted_bytes\{direction="send"\}')
    send_status=$(quic_buffer_status_label "$body" send)

    # #256-G review: a missing series must stay missing, not become a
    # fabricated observed zero/default via `${var:-0}` — a result claiming
    # zero loss or default buffers is only meaningful if that was actually
    # scraped, not assumed because the field happened to be absent. Every
    # series checked here is normally emitted unconditionally by the same
    # runtime code path that emits packets_sent (see
    # appendQuicPmtuEcnBufferPrometheus in src/http/metrics.zig), so this
    # should only ever trip on a truncated scrape, a metrics-format
    # mismatch, or a version skew between this script and the binary being
    # benchmarked — cases where "unknown" is the honest answer, not a guess.
    local required
    for required in \
        "$packets_received" "$packets_lost" "$pto" "$bytes_sent" "$bytes_received" \
        "$pmtu_probes" "$pmtu_black_holes" "$plpmtu_last" "$plpmtu_lifetime_min" "$plpmtu_lifetime_max" \
        "$ecn_enabled" "$ecn_marked" "$ecn_validated" "$ecn_disabled" "$ecn_ce" \
        "$recv_req" "$recv_eff" "$recv_grant" "$recv_status" \
        "$send_req" "$send_eff" "$send_grant" "$send_status"
    do
        if [[ -z "$required" ]]; then
            echo "null"
            return 0
        fi
    done

    jq -n \
        --argjson packets_sent "$packets_sent" \
        --argjson packets_received "$packets_received" \
        --argjson packets_lost "$packets_lost" \
        --argjson pto_total "$pto" \
        --argjson bytes_sent "$bytes_sent" \
        --argjson bytes_received "$bytes_received" \
        --argjson pmtu_probes "$pmtu_probes" \
        --argjson pmtu_black_holes "$pmtu_black_holes" \
        --argjson plpmtu_last "$plpmtu_last" \
        --argjson plpmtu_lifetime_min "$plpmtu_lifetime_min" \
        --argjson plpmtu_lifetime_max "$plpmtu_lifetime_max" \
        --argjson ecn_enabled "$([[ "$ecn_enabled" == "1" ]] && echo true || echo false)" \
        --argjson ecn_marked_sent "$ecn_marked" \
        --argjson ecn_paths_validated "$ecn_validated" \
        --argjson ecn_paths_disabled "$ecn_disabled" \
        --argjson ecn_ce_received "$ecn_ce" \
        --argjson recv_requested "$recv_req" \
        --argjson recv_effective "$recv_eff" \
        --argjson recv_granted "$recv_grant" \
        --arg recv_status "$recv_status" \
        --argjson send_requested "$send_req" \
        --argjson send_effective "$send_eff" \
        --argjson send_granted "$send_grant" \
        --arg send_status "$send_status" \
        '{
            packets_sent: $packets_sent,
            packets_received: $packets_received,
            packets_lost: $packets_lost,
            pto_total: $pto_total,
            bytes_sent: $bytes_sent,
            bytes_received: $bytes_received,
            effective_plpmtu: {last_bytes: $plpmtu_last, lifetime_min_bytes: $plpmtu_lifetime_min, lifetime_max_bytes: $plpmtu_lifetime_max},
            pmtu_probes: $pmtu_probes,
            pmtu_black_holes: $pmtu_black_holes,
            ecn: {
                enabled: $ecn_enabled,
                marked_sent: $ecn_marked_sent,
                paths_validated: $ecn_paths_validated,
                paths_disabled: $ecn_paths_disabled,
                ce_received: $ecn_ce_received
            },
            udp_buffers: {
                recv: {requested_bytes: $recv_requested, effective_bytes: $recv_effective, granted_bytes: $recv_granted, status: $recv_status},
                send: {requested_bytes: $send_requested, effective_bytes: $send_effective, granted_bytes: $send_granted, status: $send_status}
            }
        }'
}

# #256-G review: the H3 listener started by the competitive harness stays up
# across the readiness check and every pass (small/large/proxy), so a single
# post-pass scrape of these listener-lifetime cumulative counters would
# attribute earlier passes' traffic to a later row. `capture_quic_transport_state`
# is a point-in-time snapshot; this turns two snapshots (taken immediately
# before and after one load run) into a scenario-local measurement by
# subtracting counter fields. Gauges/status (effective PLPMTU, ECN enabled,
# UDP buffer requested/effective/granted/status) are not counters and are not
# subtracted — they describe *current* state, so the post-run reading is used
# as-is. `null` in, `null` out: if either snapshot could not be observed, the
# delta is "unknown", never a fabricated zero.
quic_transport_delta() {
    local before="$1" after="$2"
    if [[ "$before" == "null" || "$after" == "null" ]]; then
        echo "null"
        return 0
    fi
    jq -cn --argjson b "$before" --argjson a "$after" '{
        packets_sent: ($a.packets_sent - $b.packets_sent),
        packets_received: ($a.packets_received - $b.packets_received),
        packets_lost: ($a.packets_lost - $b.packets_lost),
        pto_total: ($a.pto_total - $b.pto_total),
        bytes_sent: ($a.bytes_sent - $b.bytes_sent),
        bytes_received: ($a.bytes_received - $b.bytes_received),
        effective_plpmtu: $a.effective_plpmtu,
        pmtu_probes: ($a.pmtu_probes - $b.pmtu_probes),
        pmtu_black_holes: ($a.pmtu_black_holes - $b.pmtu_black_holes),
        ecn: {
            enabled: $a.ecn.enabled,
            marked_sent: ($a.ecn.marked_sent - $b.ecn.marked_sent),
            paths_validated: ($a.ecn.paths_validated - $b.ecn.paths_validated),
            paths_disabled: ($a.ecn.paths_disabled - $b.ecn.paths_disabled),
            ce_received: ($a.ecn.ce_received - $b.ecn.ce_received)
        },
        udp_buffers: $a.udp_buffers
    }'
}

# Attaches an already-computed scenario-local quic delta (see
# quic_transport_delta) to a scenario's result. Single-run scenarios get it
# directly; multi-run scenarios accumulate it into `_run_quic_list` for
# flush_multirun_result to aggregate once every run has completed (#256-G
# review: repeated H3 runs must not silently drop transport evidence).
attach_quic_transport_state() {
    local label="$1" quic_delta="$2"
    if [[ "$RUNS" -eq 1 ]]; then
        [[ "$quic_delta" == "null" ]] && return 0
        RESULTS_JSON=$(jq --arg s "$label" --argjson quic "$quic_delta" '.[$s].quic = $quic' <<<"$RESULTS_JSON")
        return 0
    fi
    # #256-G review: a null delta is appended too (not skipped) — otherwise
    # a scenario with one successful scrape and one missing one would end up
    # with a one-element array, and flush_multirun_result's `runs_total`
    # (the array length) would silently equal `runs_with_data`, hiding that
    # a run's transport evidence was never observed at all.
    local prev="${_run_quic_list[$label]:-[]}"
    _run_quic_list["$label"]=$(jq -cn --argjson acc "$prev" --argjson item "$quic_delta" '$acc + [$item]')
}

# #256-G review: `h2load --h3 --help` only proves the binary recognizes the
# flag syntactically. A build with no QUIC library linked at all — e.g. the
# stock Homebrew/apt nghttp2 package, which has no ngtcp2/nghttp3 build
# option — still passes that check, then silently negotiates a degraded TCP
# connection offering ALPN "h3" (only ever valid over QUIC/UDP), which a
# correct H3 server must reject. That reject looks identical to a real
# Tardigrade H3 regression unless this check can tell the two apart, so also
# confirm the binary is actually linked against a QUIC library — best
# effort: a statically-linked QUIC build won't show up here and is treated
# as unsupported, so this can produce false negatives but not the false
# positive that motivated it.
h2load_h3_supported() {
    command -v h2load >/dev/null 2>&1 || return 1
    h2load --h3 --help &>/dev/null 2>&1 || return 1
    local h2load_path
    h2load_path="$(command -v h2load)"
    if command -v otool >/dev/null 2>&1; then
        otool -L "$h2load_path" 2>/dev/null | grep -qiE 'libngtcp2|libnghttp3'
    elif command -v ldd >/dev/null 2>&1; then
        ldd "$h2load_path" 2>/dev/null | grep -qiE 'libngtcp2|libnghttp3'
    else
        return 0
    fi
}

# ── h2load HTTP/3 runner ──────────────────────────────────────────────────────
# Requires h2load built with QUIC/nghttp3+ngtcp2 support.
# If --h3 is unknown to this h2load build, the scenario is silently skipped.
run_h2load_h3() {
    local url="$1" label="$2"
    if ! h2load_h3_supported; then
        echo "  Skipping $label — h2load on this system does not support --h3 (HTTP/3)"
        return
    fi
    if ! $USE_TLS; then
        echo "  Skipping $label — HTTP/3 requires TLS; re-run with --tls"
        return
    fi
    local extra=()
    # #256-G review: h2load has no --insecure/verify-skip flag at all
    # (verified against a real nghttp2 1.69.0 build) — it never validates
    # TLS certificates in the first place. $INSECURE is intentionally not
    # forwarded here.
    build_tool_headers -H
    [[ ${#TOOL_HEADERS[@]} -gt 0 ]] && extra+=("${TOOL_HEADERS[@]}")
    # #256-G review: bracket the load run with metrics snapshots so the
    # attached `quic` block measures only this pass, not everything the
    # listener has done since it started.
    local quic_before
    quic_before=$(capture_quic_transport_state)
    local out_json; out_json=$(mktemp /tmp/tardigrade-bench-h2load-h3-XXXXXX.json)
    local raw
    start_process_monitor
    # #256-G review: --duration is h2load's real timing-based mode (verified
    # wall-clock-accurate against a real build); the previous -n synthesis
    # only ever approximated the requested duration. --output-file writes
    # structured JSON this parses instead of the plain-text table, whose
    # labels ("median"/"p95"/"p99") and values live in different table
    # rows/columns that adjacency-based text parsing cannot recover at all
    # on the h2load versions that actually support --h3.
    raw=$(h2load --h3 --duration "${DURATION}s" \
        -c "$CONNECTIONS" -t "$THREADS" --output-file="$out_json" \
        ${extra[@]+"${extra[@]}"} "$url" 2>&1) || true
    stop_process_monitor
    local quic_after
    quic_after=$(capture_quic_transport_state)
    local rps p50 p95 p99 p999 errors tput_mbps
    if ! parse_h2load_json_result "$out_json"; then
        echo "  $label — h2load produced no usable --output-file JSON; recording as a failed pass. Raw output:" >&2
        printf '%s\n' "$raw" | tail -20 >&2
    fi
    rm -f "$out_json"
    local tput_display="" cpu_display="" rss_display=""
    [[ "$tput_mbps" != "null" ]] && tput_display="  throughput=${tput_mbps}MB/s"
    [[ "$CURRENT_CPU_PCT_AVG" != "null" ]] && cpu_display="  cpu=${CURRENT_CPU_PCT_AVG}%"
    [[ "$CURRENT_RSS_MB_PEAK" != "null" ]] && rss_display="  rss_peak=${CURRENT_RSS_MB_PEAK}MiB"
    echo "  $label — ${rps} req/s  p50=${p50}ms  p95=${p95}ms  p99=${p99}ms  p999=${p999}ms  errors=${errors}${tput_display}${cpu_display}${rss_display}"
    add_result "$label" "$rps" "$p50" "$p95" "$p99" "$p999" "$errors" "$tput_mbps" "$CURRENT_CPU_PCT_AVG" "$CURRENT_RSS_MB_PEAK"
    attach_quic_transport_state "$label" "$(quic_transport_delta "$quic_before" "$quic_after")"
}

# ── fortio runner ─────────────────────────────────────────────────────────────
run_fortio() {
    local url="$1" label="$2"
    local extra=()
    $INSECURE && extra+=(-insecure)
    build_tool_headers -H
    [[ ${#TOOL_HEADERS[@]} -gt 0 ]] && extra+=("${TOOL_HEADERS[@]}")
    local raw
    start_process_monitor
    raw=$(fortio load -c "$CONNECTIONS" -t "${DURATION}s" \
        -json /dev/stdout ${extra[@]+"${extra[@]}"} "$url" 2>/dev/null) || true
    stop_process_monitor
    local rps p50 p95 p99 p999 errors
    rps=$(echo "$raw" | jq -r '.ActualQPS // 0')
    p50=$(echo "$raw" | jq -r '((.DurationHistogram.Percentiles[] | select(.Percentile==50) | .Value) // empty)' | awk 'NF {printf "%.3f", $1*1000}' || true)
    p95=$(echo "$raw" | jq -r '((.DurationHistogram.Percentiles[] | select(.Percentile==95) | .Value) // empty)' | awk 'NF {printf "%.3f", $1*1000}' || true)
    p99=$(echo "$raw" | jq -r '((.DurationHistogram.Percentiles[] | select(.Percentile==99) | .Value) // empty)' | awk 'NF {printf "%.3f", $1*1000}' || true)
    p999=$(echo "$raw" | jq -r '((.DurationHistogram.Percentiles[] | select(.Percentile==99.9) | .Value) // empty)' | awk 'NF {printf "%.3f", $1*1000}' || true)
    errors=$(echo "$raw" | jq -r '(.ErrorsDurationHistogram.Count // 0)')
    p50=${p50:-null}; p95=${p95:-null}; p99=${p99:-null}; p999=${p999:-null}
    rps=${rps:-0}; errors=${errors:-0}
    local cpu_display="" rss_display=""
    [[ "$CURRENT_CPU_PCT_AVG" != "null" ]] && cpu_display="  cpu=${CURRENT_CPU_PCT_AVG}%"
    [[ "$CURRENT_RSS_MB_PEAK" != "null" ]] && rss_display="  rss_peak=${CURRENT_RSS_MB_PEAK}MiB"
    echo "  $label — ${rps} req/s  p50=${p50}ms  p95=${p95}ms  p99=${p99}ms  p999=${p999}ms  errors=${errors}${cpu_display}${rss_display}"
    add_result "$label" "$rps" "$p50" "$p95" "$p99" "$p999" "$errors" "null" "$CURRENT_CPU_PCT_AVG" "$CURRENT_RSS_MB_PEAK"
}

# ── k6 summary parser ────────────────────────────────────────────────────────
# Parses a k6 --summary-export JSON file (v1.x flat format) and calls add_result.
_k6_parse_summary() {
    local tmpfile="$1" label="$2"
    local rps p50 p95 p99 p999 errors
    # k6 v1.x: metrics are flat objects — .rate/.count/.med/.["p(99)"] directly
    rps=$(jq -r '.metrics.http_reqs.rate // 0' "$tmpfile" | awk '{printf "%.0f", $1}')
    p50=$(jq -r '(.metrics.http_req_duration.med // null)' "$tmpfile")
    p95=$(jq -r '(.metrics.http_req_duration["p(95)"] // null)' "$tmpfile")
    p99=$(jq -r '(.metrics.http_req_duration["p(99)"] // null)' "$tmpfile")
    p999=$(jq -r '(.metrics.http_req_duration["p(99.9)"] // null)' "$tmpfile")
    # passes = count of http_req_failed=1 samples (i.e. actual failed requests)
    errors=$(jq -r '.metrics.http_req_failed.passes // 0' "$tmpfile")
    rps=${rps:-0}; p50=${p50:-null}; p95=${p95:-null}; p99=${p99:-null}; p999=${p999:-null}; errors=${errors:-0}
    local dr_rate tput_mbps
    dr_rate=$(jq -r '.metrics.data_received.rate // 0' "$tmpfile" 2>/dev/null || echo 0)
    tput_mbps=$(awk -v r="${dr_rate:-0}" 'BEGIN { if (r > 0) printf "%.2f", r/1048576; else print "null" }')
    local tput_display="" cpu_display="" rss_display=""
    [[ "$tput_mbps" != "null" ]] && tput_display="  throughput=${tput_mbps}MB/s"
    [[ "$CURRENT_CPU_PCT_AVG" != "null" ]] && cpu_display="  cpu=${CURRENT_CPU_PCT_AVG}%"
    [[ "$CURRENT_RSS_MB_PEAK" != "null" ]] && rss_display="  rss_peak=${CURRENT_RSS_MB_PEAK}MiB"
    echo "  $label — ${rps} req/s  p50=${p50}ms  p95=${p95}ms  p99=${p99}ms  p999=${p999}ms  errors=${errors}${tput_display}${cpu_display}${rss_display}"
    add_result "$label" "$rps" "$p50" "$p95" "$p99" "$p999" "$errors" "$tput_mbps" "$CURRENT_CPU_PCT_AVG" "$CURRENT_RSS_MB_PEAK"
}

# ── k6 throughput runner ──────────────────────────────────────────────────────
run_k6() {
    local url="$1" label="$2"
    local tmpfile; tmpfile=$(mktemp /tmp/k6-summary-XXXXXX)
    local extra_flags=()
    $INSECURE && extra_flags+=(--insecure-skip-tls-verify)

    local base_url="$BASE_URL"
    local target_path="${url#"$BASE_URL"}"

    start_process_monitor
    BASE_URL="$base_url" \
    K6_TARGET_PATH="$target_path" \
    K6_HOST_HEADER="$HOST_HEADER" \
    K6_VUS="$CONNECTIONS" \
    K6_DURATION="${DURATION}s" \
        k6 run --no-color --quiet \
            --summary-export "$tmpfile" \
            ${extra_flags[@]+"${extra_flags[@]}"} \
            "$(dirname "$0")/scenarios/throughput.js" 2>/dev/null || true
    stop_process_monitor

    _k6_parse_summary "$tmpfile" "$label"
    rm -f "$tmpfile"
}

# ── k6 behavioral scenario runner ─────────────────────────────────────────────
# Runs a named k6 JS script; passes BASE_URL and env overrides through.
# Results are added to the accumulator with rps/p50/p99/errors extracted from
# the k6 summary export.
run_k6_scenario() {
    local script="$1" label="$2"
    shift 2
    local tmpfile; tmpfile=$(mktemp /tmp/k6-summary-XXXXXX)
    local extra_flags=()
    $INSECURE && extra_flags+=(--insecure-skip-tls-verify)

    start_process_monitor
    BASE_URL="${SCHEME}://${TARGET_HOST}:${TARGET_PORT}" \
        K6_HOST_HEADER="$HOST_HEADER" \
        k6 run --no-color --quiet \
            --summary-export "$tmpfile" \
            ${extra_flags[@]+"${extra_flags[@]}"} \
            "$@" \
            "$(dirname "$0")/scenarios/${script}.js" 2>/dev/null || true
    stop_process_monitor

    _k6_parse_summary "$tmpfile" "$label"
    rm -f "$tmpfile"
}

# ── slow-client download runner ──────────────────────────────────────────────
# Uses curl --limit-rate so the gateway experiences real slow downstream reads.
run_slow_client_download() {
    local url="$1" label="$2"
    if ! command -v curl &>/dev/null; then
        echo "  Skipping — slow-client download scenario requires curl"
        return 0
    fi

    local clients="$SLOW_CLIENT_CONNECTIONS"
    if (( clients < 1 )); then
        clients=1
    fi
    local max_time=$((DURATION + 60))
    if (( max_time < 30 )); then
        max_time=30
    fi

    local tmpdir; tmpdir=$(mktemp -d /tmp/tardigrade-slow-client-XXXX)
    local times_file="$tmpdir/times_ms"
    local extra=()
    $INSECURE && extra+=(--insecure)
    build_tool_headers -H
    [[ ${#TOOL_HEADERS[@]} -gt 0 ]] && extra+=("${TOOL_HEADERS[@]}")

    start_process_monitor
    local start_epoch; start_epoch=$(date +%s)
    local pids=()
    local i
    for ((i = 0; i < clients; i++)); do
        (
            curl -sS -f --http1.1 \
                --limit-rate "$SLOW_CLIENT_LIMIT_RATE" \
                --max-time "$max_time" \
                -o /dev/null \
                -w "%{http_code} %{size_download} %{time_total}\n" \
                ${extra[@]+"${extra[@]}"} \
                "$url" > "$tmpdir/$i.out" 2> "$tmpdir/$i.err"
            printf '%s\n' "$?" > "$tmpdir/$i.code"
        ) &
        pids+=("$!")
    done

    local pid
    for pid in "${pids[@]}"; do
        wait "$pid" || true
    done
    local end_epoch; end_epoch=$(date +%s)
    stop_process_monitor

    local successes=0 errors=0 total_bytes=0
    for ((i = 0; i < clients; i++)); do
        local code="1"
        if [[ -f "$tmpdir/$i.code" ]]; then
            code=$(<"$tmpdir/$i.code")
        fi
        if [[ "$code" == "0" && -s "$tmpdir/$i.out" ]]; then
            local status bytes seconds
            read -r status bytes seconds < "$tmpdir/$i.out"
            if [[ "$status" =~ ^2[0-9][0-9]$ ]]; then
                successes=$((successes + 1))
                total_bytes=$((total_bytes + bytes))
                awk -v s="$seconds" 'BEGIN { printf "%.3f\n", s * 1000 }' >> "$times_file"
            else
                errors=$((errors + 1))
            fi
        else
            errors=$((errors + 1))
        fi
    done

    local elapsed=$((end_epoch - start_epoch))
    if (( elapsed < 1 )); then
        elapsed=1
    fi
    local rps tput_mbps p50 p95 p99 p999
    rps=$(awk -v ok="$successes" -v elapsed="$elapsed" 'BEGIN { printf "%.3f", ok / elapsed }')
    tput_mbps=$(awk -v bytes="$total_bytes" -v elapsed="$elapsed" 'BEGIN { if (bytes > 0) printf "%.2f", bytes / elapsed / 1048576; else print "null" }')
    p50=$(percentile_from_file "$times_file" 50)
    p95=$(percentile_from_file "$times_file" 95)
    p99=$(percentile_from_file "$times_file" 99)
    p999=$(percentile_from_file "$times_file" 99.9)

    local tput_display="" cpu_display="" rss_display=""
    [[ "$tput_mbps" != "null" ]] && tput_display="  throughput=${tput_mbps}MB/s"
    [[ "$CURRENT_CPU_PCT_AVG" != "null" ]] && cpu_display="  cpu=${CURRENT_CPU_PCT_AVG}%"
    [[ "$CURRENT_RSS_MB_PEAK" != "null" ]] && rss_display="  rss_peak=${CURRENT_RSS_MB_PEAK}MiB"
    echo "  $label — ${rps} req/s  p50=${p50}ms  p95=${p95}ms  p99=${p99}ms  p999=${p999}ms  errors=${errors}${tput_display}${cpu_display}${rss_display}"
    add_result "$label" "$rps" "$p50" "$p95" "$p99" "$p999" "$errors" "$tput_mbps" "$CURRENT_CPU_PCT_AVG" "$CURRENT_RSS_MB_PEAK"
    rm -rf "$tmpdir"
}

# ── Generic runner dispatcher ─────────────────────────────────────────────────
run_scenario() {
    local url="$1" label="$2"
    case "$TOOL" in
        wrk)    run_wrk    "$url" "$label" ;;
        h2load) run_h2load "$url" "$label" ;;
        fortio) run_fortio "$url" "$label" ;;
        k6)     run_k6     "$url" "$label" ;;
        *)      echo "Unsupported tool: $TOOL" >&2; exit 1 ;;
    esac
}

# ── Scenarios ─────────────────────────────────────────────────────────────────
scenario_static_http1() {
    echo "==> static-http1: static file serving over HTTP/1.1 (${STATIC_PATH})"
    run_scenario "${BASE_URL}${STATIC_PATH}" "static-http1"
}

scenario_proxy_http1() {
    echo "==> proxy-http1: reverse proxy route over HTTP/1.1 (${PROXY_PATH})"
    run_scenario "${BASE_URL}${PROXY_PATH}" "proxy-http1"
}

scenario_proxy_http2() {
    echo "==> proxy-http2: reverse proxy route over HTTP/2 (${PROXY_PATH})"
    if [[ "$TOOL" != "h2load" ]]; then
        echo "  Skipping — HTTP/2 scenario requires h2load"
        return
    fi
    run_h2load "${BASE_URL}${PROXY_PATH}" "proxy-http2"
}

scenario_static_http2() {
    echo "==> static-http2: static file serving over HTTP/2 (${H2_PATH})"
    if [[ "$TOOL" == "h2load" ]]; then
        run_h2load "${BASE_URL}${H2_PATH}" "static-http2"
    elif [[ "$TOOL" == "k6" ]] && $USE_TLS; then
        # k6 negotiates HTTP/2 automatically over HTTPS
        run_k6 "${BASE_URL}${H2_PATH}" "static-http2"
    else
        echo "  Skipping — static-http2 requires h2load or k6 with --tls"
    fi
}

scenario_static_http3() {
    echo "==> static-http3: static file serving over HTTP/3 (${H3_PATH})"
    if [[ "$TOOL" == "h2load" ]]; then
        run_h2load_h3 "${BASE_URL}${H3_PATH}" "static-http3"
    else
        echo "  Skipping — static-http3 requires h2load with HTTP/3 (QUIC) support"
    fi
}

scenario_proxy_http3() {
    echo "==> proxy-http3: reverse proxy route over HTTP/3 (${PROXY_PATH})"
    if [[ "$TOOL" == "h2load" ]]; then
        run_h2load_h3 "${BASE_URL}${PROXY_PATH}" "proxy-http3"
    else
        echo "  Skipping — proxy-http3 requires h2load with HTTP/3 (QUIC) support"
    fi
}

scenario_keepalive() {
    echo "==> keepalive: keep-alive connection reuse (${KEEPALIVE_PATH})"
    run_scenario "${BASE_URL}${KEEPALIVE_PATH}" "keepalive"
}

scenario_keepalive_starvation() {
    echo "==> keepalive-starvation: idle keepalive holders + active burst — worker starvation probe (#204)"
    if [[ "$TOOL" != "k6" ]]; then
        echo "  Skipping — keepalive-starvation scenario requires k6"
        return 0
    fi
    run_k6_scenario "keepalive-starvation" "keepalive-starvation" \
        -e "K6_TARGET_PATH=${KEEPALIVE_PATH}" \
        -e "IDLE_VUS=${KEEPALIVE_STARVATION_IDLE_VUS:-20}" \
        -e "ACTIVE_VUS=${KEEPALIVE_STARVATION_ACTIVE_VUS:-10}" \
        -e "IDLE_SLEEP_S=${KEEPALIVE_STARVATION_IDLE_SLEEP_S:-10}" \
        -e "K6_DURATION=${DURATION}s"
}

scenario_proxy_payload_64k() {
    echo "==> proxy-payload-64k: reverse proxy 64 KiB payload (${PROXY_PAYLOAD_64K_PATH})"
    run_scenario "${BASE_URL}${PROXY_PAYLOAD_64K_PATH}" "proxy-payload-64k"
}

scenario_proxy_payload_256k() {
    echo "==> proxy-payload-256k: reverse proxy 256 KiB payload (${PROXY_PAYLOAD_256K_PATH})"
    run_scenario "${BASE_URL}${PROXY_PAYLOAD_256K_PATH}" "proxy-payload-256k"
}

scenario_proxy_payload_1m() {
    echo "==> proxy-payload-1m: reverse proxy 1 MiB payload (${PROXY_PAYLOAD_1M_PATH})"
    run_scenario "${BASE_URL}${PROXY_PAYLOAD_1M_PATH}" "proxy-payload-1m"
}

scenario_proxy_payload_16m() {
    echo "==> proxy-payload-16m: reverse proxy 16 MiB payload (${PROXY_PAYLOAD_16M_PATH})"
    run_scenario "${BASE_URL}${PROXY_PAYLOAD_16M_PATH}" "proxy-payload-16m"
}

scenario_proxy_upload_large() {
    echo "==> proxy-upload-large: reverse proxy 1 MiB fixed-length upload (${PROXY_UPLOAD_PATH})"
    if [[ "$TOOL" != "k6" ]]; then
        echo "  Skipping — proxy-upload-large scenario requires k6"
        return 0
    fi
    run_k6_scenario "upload" "proxy-upload-large" \
        -e "UPLOAD_PATH=${PROXY_UPLOAD_PATH}" \
        -e "UPLOAD_BYTES=1048576" \
        -e "K6_VUS=${CONNECTIONS}" \
        -e "K6_DURATION=${DURATION}s"
}

scenario_proxy_slow_client_download() {
    echo "==> proxy-slow-client-download: rate-limited clients downloading ${PROXY_SLOW_CLIENT_PATH}"
    echo "  clients=${SLOW_CLIENT_CONNECTIONS} limit-rate=${SLOW_CLIENT_LIMIT_RATE}"
    run_slow_client_download "${BASE_URL}${PROXY_SLOW_CLIENT_PATH}" "proxy-slow-client-download"
}

scenario_auth_enforcement() {
    echo "==> auth-enforcement: verify 401 for unauthenticated and 2xx for authenticated requests"
    if [[ "$TOOL" != "k6" ]]; then
        echo "  Skipping — auth-enforcement scenario requires k6"
        return
    fi
    run_k6_scenario "auth-enforcement" "auth-enforcement" \
        -e K6_VUS="${CONNECTIONS}" \
        -e K6_DURATION="${DURATION}s" \
        ${AUTH_TOKEN:+-e AUTH_TOKEN="$AUTH_TOKEN"} \
        ${AUTH_PROTECTED_PATH:+-e AUTH_PROTECTED_PATH="$AUTH_PROTECTED_PATH"}
}

scenario_rate_limit() {
    echo "==> rate-limit: verify 429s appear when request rate exceeds the configured ceiling"
    if [[ "$TOOL" != "k6" ]]; then
        echo "  Skipping — rate-limit scenario requires k6"
        return
    fi
    run_k6_scenario "rate-limit" "rate-limit" \
        ${TARDIGRADE_RATE_LIMIT_RPS:+-e RATE_LIMIT_RPS="$TARDIGRADE_RATE_LIMIT_RPS"} \
        ${RATE_LIMIT_PATH:+-e RATE_LIMIT_PATH="$RATE_LIMIT_PATH"}
}

scenario_spike() {
    echo "==> spike: sudden surge to ${SPIKE_PEAK:-150} VUs — measure error rate and p99 under peak load"
    if [[ "$TOOL" != "k6" ]]; then
        echo "  Skipping — spike scenario requires k6"
        return
    fi
    run_k6_scenario "spike" "spike" \
        ${SPIKE_PEAK:+-e SPIKE_PEAK="$SPIKE_PEAK"}
}

scenario_reload_under_load() {
    echo "==> reload-under-load: SIGHUP during load (${STATIC_PATH})"
    if ! command -v wrk &>/dev/null; then
        echo "  Skipping — reload-under-load requires wrk"
        return
    fi
    local pid_file="${TARDIGRADE_PID_FILE:-/tmp/tardigrade.pid}"
    if [[ ! -f "$pid_file" ]]; then
        echo "  Skipping — no PID file at $pid_file (set TARDIGRADE_PID_FILE)"
        return
    fi
    local pid; pid=$(cat "$pid_file")
    (
        sleep "$((DURATION / 3))"
        echo "  Sending SIGHUP to PID $pid..."
        kill -HUP "$pid" 2>/dev/null || true
    ) &
    run_wrk "${BASE_URL}${STATIC_PATH}" "reload-under-load"
    wait 2>/dev/null || true
}

# ── Main loop ─────────────────────────────────────────────────────────────────
echo "Tardigrade benchmark — target: ${BASE_URL}  tool: ${TOOL}"
echo "Duration: ${DURATION}s  Connections: ${CONNECTIONS}  Threads: ${THREADS}"
echo "Paths: static=${STATIC_PATH} proxy=${PROXY_PATH} keepalive=${KEEPALIVE_PATH} proxy64k=${PROXY_PAYLOAD_64K_PATH} proxy256k=${PROXY_PAYLOAD_256K_PATH} proxy1m=${PROXY_PAYLOAD_1M_PATH} proxy16m=${PROXY_PAYLOAD_16M_PATH} h2=${H2_PATH} h3=${H3_PATH}"
if [[ -n "$HOST_HEADER" ]]; then
    echo "Host header override: ${HOST_HEADER}"
fi
if [[ -n "$TARGET_PID" || -n "$PID_FILE" ]]; then
    echo "Process sampling: CPU/RSS every ${SAMPLE_INTERVAL_MS}ms"
fi
echo ""

IFS=',' read -ra SCENARIO_LIST <<< "$SCENARIOS"
for scenario in "${SCENARIO_LIST[@]}"; do
    for (( _run=1; _run<=RUNS; _run++ )); do
        [[ "$RUNS" -gt 1 ]] && echo "==> $scenario (run ${_run}/${RUNS})"
        case "$scenario" in
            static-http1)       scenario_static_http1 ;;
            proxy-http1)        scenario_proxy_http1 ;;
            static-http2)       scenario_static_http2 ;;
            proxy-http2)        scenario_proxy_http2 ;;
            static-http3)       scenario_static_http3 ;;
            proxy-http3)        scenario_proxy_http3 ;;
            keepalive)          scenario_keepalive ;;
            keepalive-starvation) scenario_keepalive_starvation ;;
            proxy-payload-64k)  scenario_proxy_payload_64k ;;
            proxy-payload-256k) scenario_proxy_payload_256k ;;
            proxy-payload-1m)   scenario_proxy_payload_1m ;;
            proxy-payload-16m)  scenario_proxy_payload_16m ;;
            proxy-upload-large) scenario_proxy_upload_large ;;
            proxy-slow-client-download) scenario_proxy_slow_client_download ;;
            reload-under-load)  scenario_reload_under_load ;;
            auth-enforcement)   scenario_auth_enforcement ;;
            rate-limit)         scenario_rate_limit ;;
            spike)              scenario_spike ;;
            *)                  echo "Unknown scenario: $scenario" >&2 ;;
        esac
    done
    if [[ "$RUNS" -gt 1 ]]; then
        flush_multirun_result "$scenario"
    fi
done

# ── Attach metadata ──────────────────────────────────────────────────────────
GIT_TAG=$(git -C "$(dirname "$0")/.." describe --tags --always 2>/dev/null || echo "unknown")
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
ZIG_VERSION=$(detect_zig_version)
OS_NAME=$(detect_os_name)
KERNEL_RELEASE=$(detect_kernel_release)
ARCH_NAME=$(detect_arch)
CPU_MODEL=$(detect_cpu_model)
CPU_THREADS=$(detect_cpu_threads)
MEMORY_MB=$(detect_memory_mb)
# #256-G: high-bandwidth/dedicated-host evidence needs to say whether the
# installed h2load can even drive HTTP/3 — a run with h2load lacking --h3
# silently produces zero H3 rows, and that has to be distinguishable from
# "we tried and it was slow."
H2LOAD_VERSION="unknown"
H2LOAD_H3_SUPPORTED=false
H2LOAD_OUTPUT_FILE_SUPPORTED=false
if command -v h2load &>/dev/null; then
    H2LOAD_VERSION=$({ h2load --version 2>&1 || true; } | head -1)
    h2load_h3_supported && H2LOAD_H3_SUPPORTED=true
    # #256-G review: run_h2load falls back to text-table parsing on a build
    # without --output-file — record which path actually ran so a result
    # produced by the legacy fallback isn't silently indistinguishable from
    # one backed by the structured JSON export.
    h2load_output_file_supported && H2LOAD_OUTPUT_FILE_SUPPORTED=true
fi
RESULTS_JSON=$(jq \
    --arg tag "$GIT_TAG" --arg ts "$TIMESTAMP" \
    --arg host "$TARGET_HOST" --arg port "$TARGET_PORT" \
    --arg host_header "$HOST_HEADER" \
    --arg driver "$DRIVER_LABEL" \
    --arg worker_count "$WORKER_COUNT" \
    --arg config_label "$CONFIG_LABEL" \
    --arg pid_source "$(if [[ -n "$TARGET_PID" ]]; then echo pid; elif [[ -n "$PID_FILE" ]]; then echo pid-file; else echo none; fi)" \
    --arg static_path "$STATIC_PATH" --arg proxy_path "$PROXY_PATH" \
    --arg keepalive_path "$KEEPALIVE_PATH" \
    --arg h2_path "$H2_PATH" --arg h3_path "$H3_PATH" \
    --arg tool "$TOOL" \
    --argjson pid_tree "$($PID_TREE && echo true || echo false)" \
    --arg zig_version "$ZIG_VERSION" \
    --arg os_name "$OS_NAME" \
    --arg kernel_release "$KERNEL_RELEASE" \
    --arg arch_name "$ARCH_NAME" \
    --arg cpu_model "$CPU_MODEL" \
    --arg cpu_threads "$CPU_THREADS" \
    --arg memory_mb "$MEMORY_MB" \
    --arg h2load_version "$H2LOAD_VERSION" \
    --argjson h2load_h3_supported "$($H2LOAD_H3_SUPPORTED && echo true || echo false)" \
    --argjson h2load_output_file_supported "$($H2LOAD_OUTPUT_FILE_SUPPORTED && echo true || echo false)" \
    --argjson threads "$THREADS" \
    --argjson dur "$DURATION" --argjson conn "$CONNECTIONS" --argjson sample_interval_ms "$SAMPLE_INTERVAL_MS" \
    --argjson runs "$RUNS" \
    '. + {_meta: {tag: $tag, timestamp: $ts, host: $host, port: $port,
          tool: $tool, duration_s: $dur, connections: $conn, threads: $threads, runs: $runs,
          host_header: $host_header, driver: $driver,
          worker_count: (if $worker_count == "" then null else ($worker_count | tonumber) end),
          config_label: (if $config_label == "" then null else $config_label end),
          process_metrics: {
            enabled: ($pid_source != "none"),
            pid_source: $pid_source,
            pid_tree: $pid_tree,
            sample_interval_ms: $sample_interval_ms
          },
          zig_version: $zig_version,
          h2load_version: $h2load_version,
          h2load_h3_supported: $h2load_h3_supported,
          h2load_output_file_supported: $h2load_output_file_supported,
          environment: {
            os: $os_name,
            kernel: $kernel_release,
            arch: $arch_name,
            cpu_model: $cpu_model,
            cpu_threads: $cpu_threads,
            memory_mb: $memory_mb
          },
          static_path: $static_path,
          proxy_path: $proxy_path, keepalive_path: $keepalive_path,
          h2_path: $h2_path, h3_path: $h3_path}}' \
    <<<"$RESULTS_JSON")

if [[ -n "$META_FILE" ]]; then
    if [[ ! -f "$META_FILE" ]]; then
        echo "Metadata file not found: $META_FILE" >&2
        exit 1
    fi
    RESULTS_JSON=$(jq --slurpfile meta "$META_FILE" '._meta += ($meta[0] // {})' <<<"$RESULTS_JSON")
fi

# ── Save ─────────────────────────────────────────────────────────────────────
if [[ -n "$SAVE_FILE" ]]; then
    mkdir -p "$(dirname "$SAVE_FILE")"
    echo "$RESULTS_JSON" > "$SAVE_FILE"
    echo ""
    echo "Results saved to: $SAVE_FILE"
fi

# ── Baseline comparison ───────────────────────────────────────────────────────
REGRESSION=0
if [[ -n "$BASELINE_FILE" && -f "$BASELINE_FILE" ]]; then
    echo ""
    echo "Comparing against baseline: $BASELINE_FILE"
    compare_metric() {
        local scenario="$1" metric="$2" path="$3" direction="$4"
        local baseline_value current_value delta status
        baseline_value=$(jq -r --arg s "$scenario" "$path // null" "$BASELINE_FILE")
        current_value=$(echo "$RESULTS_JSON" | jq -r --arg s "$scenario" "$path // null")
        if [[ "$baseline_value" == "null" || "$current_value" == "null" || "$baseline_value" == "0" ]]; then
            return 0
        fi
        delta=$(awk -v b="$baseline_value" -v c="$current_value" 'BEGIN { printf "%.1f", (c - b) / b * 100 }')
        status="OK"
        case "$direction" in
            higher)
                if awk -v d="$delta" -v t="$REGRESSION_THRESHOLD" 'BEGIN { exit !(d < -t) }'; then
                    status="REGRESSION"
                    REGRESSION=1
                fi
                ;;
            lower)
                if awk -v d="$delta" -v t="$REGRESSION_THRESHOLD" 'BEGIN { exit !(d > t) }'; then
                    status="REGRESSION"
                    REGRESSION=1
                fi
                ;;
        esac
        echo "  ${scenario}.${metric}: baseline=${baseline_value} current=${current_value} delta=${delta}% [${status}]"
    }
    # shellcheck disable=SC2016 # single-quoted on purpose: $s is a jq --arg binding inside compare_metric's own jq program, not a shell variable
    while IFS= read -r scenario; do
        [[ "$scenario" == _meta ]] && continue
        compare_metric "$scenario" "rps" '.[$s].rps' higher
        compare_metric "$scenario" "p95_ms" '.[$s].p95_ms' lower
        compare_metric "$scenario" "p99_ms" '.[$s].p99_ms' lower
        compare_metric "$scenario" "p999_ms" '.[$s].p999_ms' lower
        compare_metric "$scenario" "cpu_pct_avg" '.[$s].cpu_pct_avg' lower
        compare_metric "$scenario" "rss_mb_peak" '.[$s].rss_mb_peak' lower
    done < <(echo "$RESULTS_JSON" | jq -r 'keys[]')
fi

echo ""
echo "$RESULTS_JSON" | jq .

[[ "$REGRESSION" -eq 0 ]] || exit 2

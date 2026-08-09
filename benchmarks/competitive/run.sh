#!/usr/bin/env bash
# Competitive benchmark orchestrator for Tardigrade, NGINX, HAProxy, and Caddy.
#
# It starts a shared origin fixture plus one selected edge server at a time,
# delegates HTTP measurements to benchmarks/run.sh, and emits combined JSON,
# CSV, and Markdown output with enough metadata to avoid ambiguous comparisons.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BENCH_DIR="${REPO_ROOT}/benchmarks"
COMP_DIR="${BENCH_DIR}/competitive"
CONFIG_DIR="${COMP_DIR}/configs"
BINARY="${REPO_ROOT}/zig-out/bin/tardi"
SERVERS="tardigrade,nginx,haproxy,caddy"
TOOL="wrk"
DURATION="15"
CONNECTIONS="32"
THREADS="4"
LISTEN_BASE="19080"
UPSTREAM_PORT="19079"
OUT_DIR="${COMP_DIR}/results/$(date -u +%Y%m%d-%H%M%S)"
META_FILE="${COMP_DIR}/target.json"
ALLOW_MISSING=false
PRINT_MANUAL=false
SMOKE=false
TMP_DIR=""
ORIGIN_PID=""
EDGE_PID=""
CURRENT_SERVER=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary) BINARY="$2"; shift 2 ;;
        --servers) SERVERS="$2"; shift 2 ;;
        --tool) TOOL="$2"; shift 2 ;;
        --duration) DURATION="$2"; shift 2 ;;
        --connections) CONNECTIONS="$2"; shift 2 ;;
        --threads) THREADS="$2"; shift 2 ;;
        --listen-base) LISTEN_BASE="$2"; shift 2 ;;
        --upstream-port) UPSTREAM_PORT="$2"; shift 2 ;;
        --out-dir) OUT_DIR="$2"; shift 2 ;;
        --meta-file) META_FILE="$2"; shift 2 ;;
        --allow-missing) ALLOW_MISSING=true; shift ;;
        --smoke)
            SMOKE=true
            DURATION="5"
            CONNECTIONS="8"
            THREADS="2"
            SERVERS="tardigrade"
            shift
            ;;
        --print-manual) PRINT_MANUAL=true; shift ;;
        --help)
            sed -n '2,80p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

print_manual_steps() {
    cat <<EOF
Competitive benchmark manual flow:

1. Install tools: jq, curl, python3, ${TOOL}, plus any selected competitors (${SERVERS}).
2. Build Tardigrade: zig build -Doptimize=ReleaseFast
3. Start the shared origin fixture:
   python3 benchmarks/fixtures/upstream_server.py --port ${UPSTREAM_PORT}
4. For each server in ${SERVERS}, render its template from benchmarks/competitive/configs
   with LISTEN_PORT, UPSTREAM_PORT, STATIC_ROOT, PID_FILE, ERROR_LOG, and THREADS.
5. Start one server at a time, wait for http://127.0.0.1:<port>/health, then run:
   benchmarks/run.sh --tool ${TOOL} --host 127.0.0.1 --port <port> \\
     --duration ${DURATION} --connections ${CONNECTIONS} --threads ${THREADS} \\
     --static-path /tiny.txt --keepalive-path /tiny.txt \\
     --proxy-path /proxy/health --save <server>-tiny-proxy.json
6. Repeat with --static-path /large.bin and --scenarios static-http1.
7. Repeat with --proxy-path /proxy/payload-1m.bin and --scenarios proxy-http1.
8. Repeat with --proxy-slow-client-path /proxy/payload-16m.bin and
   --scenarios proxy-slow-client-download.
9. With wrk, run the churn pass with -H "Connection: close" against /tiny.txt.
10. Compare only runs captured on the same idle host with the same tool, duration,
   connection count, kernel limits, and server versions.

The automated command is:
  benchmarks/competitive/run.sh --servers ${SERVERS} --tool ${TOOL} --duration ${DURATION} --connections ${CONNECTIONS} --threads ${THREADS}
EOF
}

if $PRINT_MANUAL; then
    print_manual_steps
    exit 0
fi

require_tool() {
    local tool="$1"
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Missing required tool: ${tool}" >&2
        exit 1
    fi
}

has_tool() {
    command -v "$1" >/dev/null 2>&1
}

cleanup_edge() {
    if [[ -n "$EDGE_PID" ]]; then
        kill "$EDGE_PID" 2>/dev/null || true
        wait "$EDGE_PID" 2>/dev/null || true
        EDGE_PID=""
    fi
    if [[ "$CURRENT_SERVER" == "nginx" && -n "$TMP_DIR" && -f "${TMP_DIR}/nginx/nginx.conf" ]] && has_tool nginx; then
        nginx -p "${TMP_DIR}/nginx" -c "${TMP_DIR}/nginx/nginx.conf" -s stop >/dev/null 2>&1 || true
    fi
    CURRENT_SERVER=""
}

cleanup() {
    local status=$?
    cleanup_edge
    if [[ -n "$ORIGIN_PID" ]]; then
        kill "$ORIGIN_PID" 2>/dev/null || true
        wait "$ORIGIN_PID" 2>/dev/null || true
        ORIGIN_PID=""
    fi
    if [[ $status -ne 0 && -n "$TMP_DIR" ]]; then
        find "$TMP_DIR" -maxdepth 3 -type f -name '*.log' -print -exec tail -80 {} \; || true
    fi
    [[ -n "$TMP_DIR" ]] && rm -rf "$TMP_DIR"
    exit "$status"
}
trap cleanup EXIT

wait_for_http() {
    local url="$1"
    local attempts="${2:-60}"
    local delay="${3:-0.2}"
    local i
    for ((i = 0; i < attempts; i += 1)); do
        if curl -fsS "$url" >/dev/null 2>&1; then
            return 0
        fi
        sleep "$delay"
    done
    echo "Timed out waiting for ${url}" >&2
    return 1
}

render_template() {
    local template="$1"
    local output="$2"
    local listen_port="$3"
    local pid_file="$4"
    local error_log="$5"
    sed \
        -e "s|__LISTEN_PORT__|${listen_port}|g" \
        -e "s|__UPSTREAM_PORT__|${UPSTREAM_PORT}|g" \
        -e "s|__STATIC_ROOT__|${TMP_DIR}/public|g" \
        -e "s|__PID_FILE__|${pid_file}|g" \
        -e "s|__ERROR_LOG__|${error_log}|g" \
        -e "s|__THREADS__|${THREADS}|g" \
        "$template" > "$output"
}

ensure_tardigrade_binary() {
    if [[ -x "$BINARY" ]]; then
        return
    fi
    echo "Building Tardigrade release binary..."
    (cd "$REPO_ROOT" && zig build -Doptimize=ReleaseFast)
}

start_tardigrade() {
    ensure_tardigrade_binary
    local port="$1"
    local dir="${TMP_DIR}/tardigrade"
    mkdir -p "$dir"
    render_template "${CONFIG_DIR}/tardigrade.conf.in" "${dir}/tardigrade.conf" "$port" "${dir}/tardigrade.pid" "${dir}/error.log"
    TARDIGRADE_RATE_LIMIT_RPS=0 TARDIGRADE_PROXY_STREAMING_MODE=response \
        "$BINARY" run -c "${dir}/tardigrade.conf" >"${dir}/server.log" 2>&1 &
    EDGE_PID="$!"
}

start_nginx() {
    local port="$1"
    local dir="${TMP_DIR}/nginx"
    mkdir -p "${dir}/logs" "${dir}/client_body_temp" "${dir}/proxy_temp"
    render_template "${CONFIG_DIR}/nginx.conf.in" "${dir}/nginx.conf" "$port" "${dir}/nginx.pid" "${dir}/logs/error.log"
    nginx -p "$dir" -c "${dir}/nginx.conf" -g "daemon off;" >"${dir}/server.log" 2>&1 &
    EDGE_PID="$!"
}

start_haproxy() {
    local port="$1"
    local dir="${TMP_DIR}/haproxy"
    mkdir -p "$dir"
    render_template "${CONFIG_DIR}/haproxy.cfg.in" "${dir}/haproxy.cfg" "$port" "${dir}/haproxy.pid" "${dir}/error.log"
    haproxy -f "${dir}/haproxy.cfg" -db >"${dir}/server.log" 2>&1 &
    EDGE_PID="$!"
}

start_caddy() {
    local port="$1"
    local dir="${TMP_DIR}/caddy"
    mkdir -p "$dir"
    render_template "${CONFIG_DIR}/Caddyfile.in" "${dir}/Caddyfile" "$port" "${dir}/caddy.pid" "${dir}/error.log"
    caddy run --config "${dir}/Caddyfile" --adapter caddyfile >"${dir}/server.log" 2>&1 &
    EDGE_PID="$!"
}

start_server() {
    local server="$1"
    local port="$2"
    CURRENT_SERVER="$server"
    case "$server" in
        tardigrade) start_tardigrade "$port" ;;
        nginx) start_nginx "$port" ;;
        haproxy) start_haproxy "$port" ;;
        caddy) start_caddy "$port" ;;
        *) echo "Unknown server: ${server}" >&2; exit 1 ;;
    esac
    wait_for_http "http://127.0.0.1:${port}/health"
}

server_tool() {
    case "$1" in
        tardigrade) echo "$BINARY" ;;
        nginx) echo nginx ;;
        haproxy) echo haproxy ;;
        caddy) echo caddy ;;
        *) echo "$1" ;;
    esac
}

server_version() {
    case "$1" in
        tardigrade) "$BINARY" --version 2>/dev/null | head -1 || echo "unknown" ;;
        nginx) nginx -v 2>&1 | sed 's/^nginx version: //' ;;
        haproxy) haproxy -v 2>/dev/null | head -1 ;;
        caddy) caddy version 2>/dev/null | head -1 ;;
        *) echo "unknown" ;;
    esac
}

rename_pass_json() {
    local input="$1"
    local output="$2"
    local server="$3"
    local pass="$4"
    jq --arg server "$server" --arg pass "$pass" '
        with_entries(
            if .key == "_meta" then
                .value += {competitive_server: $server, competitive_pass: $pass} |
                .
            elif $pass == "tiny-proxy" and .key == "static-http1" then .key = "static-tiny-http1" | .
            elif $pass == "tiny-proxy" and .key == "keepalive" then .key = "static-tiny-keepalive" | .
            elif $pass == "tiny-proxy" and .key == "proxy-http1" then .key = "proxy-small-http1" | .
            elif $pass == "tiny-static" and .key == "static-http1" then .key = "static-tiny-http1" | .
            elif $pass == "tiny-static" and .key == "keepalive" then .key = "static-tiny-keepalive" | .
            elif $pass == "large-static" and .key == "static-http1" then .key = "static-large-http1" | .
            elif $pass == "large-proxy" and .key == "proxy-http1" then .key = "proxy-large-http1" | .
            elif $pass == "slow-client" and .key == "proxy-slow-client-download" then .key = "proxy-slow-client-download" | .
            elif $pass == "idle-keepalive" and .key == "keepalive-starvation" then .key = "idle-keepalive-active-traffic" | .
            else .
            end
        )' "$input" > "$output"
}

run_benchmark_pass() {
    local server="$1"
    local port="$2"
    local pass="$3"
    local scenarios="$4"
    local static_path="$5"
    local proxy_path="$6"
    local raw="${OUT_DIR}/${server}-${pass}.raw.json"
    local renamed="${OUT_DIR}/${server}-${pass}.json"

    "${BENCH_DIR}/run.sh" \
        --tool "$TOOL" \
        --host 127.0.0.1 \
        --port "$port" \
        --driver "competitive-loopback" \
        --config-label "${server}" \
        --pid "$EDGE_PID" \
        --meta-file "$META_FILE" \
        --duration "$DURATION" \
        --connections "$CONNECTIONS" \
        --threads "$THREADS" \
        --static-path "$static_path" \
        --keepalive-path "$static_path" \
        --proxy-path "$proxy_path" \
        --proxy-payload-1m-path "$proxy_path" \
        --proxy-slow-client-path "$proxy_path" \
        --scenarios "$scenarios" \
        --save "$raw"
    rename_pass_json "$raw" "$renamed" "$server" "$pass"
}

run_connection_churn() {
    local server="$1"
    local port="$2"
    local output="${OUT_DIR}/${server}-connection-churn.json"
    if [[ "$TOOL" != "wrk" ]]; then
        echo "Skipping connection churn scenario; automated churn currently requires --tool wrk."
        return 0
    fi

    echo "==> connection-churn-http1: tiny static file with Connection: close"
    local raw summary_json rps p50 p95 p99 p999 errors tput_mbps
    raw=$(wrk --latency -s "${BENCH_DIR}/wrk-summary.lua" \
        -t"${THREADS}" -c"${CONNECTIONS}" -d"${DURATION}s" \
        -H "Connection: close" \
        "http://127.0.0.1:${port}/tiny.txt" 2>&1) || true
    summary_json=$(printf '%s\n' "$raw" | sed -n 's/^WRK_SUMMARY //p' | tail -1)
    if [[ -z "$summary_json" ]]; then
        echo "wrk summary hook did not emit percentile JSON for connection churn" >&2
        echo "$raw" >&2
        exit 1
    fi
    rps=$(echo "$summary_json" | jq -r '.rps // 0')
    p50=$(echo "$summary_json" | jq -r '.p50_ms // null')
    p95=$(echo "$summary_json" | jq -r '.p95_ms // null')
    p99=$(echo "$summary_json" | jq -r '.p99_ms // null')
    p999=$(echo "$summary_json" | jq -r '.p999_ms // null')
    tput_mbps=$(echo "$summary_json" | jq -r '.throughput_mbps // null')
    errors=$(echo "$raw" | grep -E "Non-2xx|Socket errors" | grep -oE '[0-9]+' | head -1 || echo 0)
    rps=${rps:-0}
    errors=${errors:-0}
    echo "  connection-churn-http1 — ${rps} req/s  p50=${p50}ms  p95=${p95}ms  p99=${p99}ms  p999=${p999}ms  errors=${errors}"
    jq -n \
        --arg server "$server" \
        --argjson rps "$rps" \
        --argjson p50 "$p50" \
        --argjson p95 "$p95" \
        --argjson p99 "$p99" \
        --argjson p999 "$p999" \
        --argjson mbps "$tput_mbps" \
        --argjson errors "$errors" \
        '{
            _meta: {
                competitive_server: $server,
                competitive_pass: "connection-churn",
                tool: "wrk"
            },
            "connection-churn-http1": {
                rps: $rps,
                p50_ms: $p50,
                p95_ms: $p95,
                p99_ms: $p99,
                p999_ms: $p999,
                throughput_mbps: $mbps,
                cpu_pct_avg: null,
                rss_mb_peak: null,
                errors: $errors
            }
        }' > "$output"
}

combine_server_results() {
    local server="$1"
    local combined="${OUT_DIR}/${server}.json"
    local inputs=()
    if [[ -f "${OUT_DIR}/${server}-large-static.json" ]]; then
        inputs+=("${OUT_DIR}/${server}-large-static.json")
    fi
    if [[ -f "${OUT_DIR}/${server}-tiny-proxy.json" ]]; then
        inputs+=("${OUT_DIR}/${server}-tiny-proxy.json")
    fi
    if [[ -f "${OUT_DIR}/${server}-tiny-static.json" ]]; then
        inputs+=("${OUT_DIR}/${server}-tiny-static.json")
    fi
    if [[ -f "${OUT_DIR}/${server}-large-proxy.json" ]]; then
        inputs+=("${OUT_DIR}/${server}-large-proxy.json")
    fi
    if [[ -f "${OUT_DIR}/${server}-slow-client.json" ]]; then
        inputs+=("${OUT_DIR}/${server}-slow-client.json")
    fi
    if [[ -f "${OUT_DIR}/${server}-idle-keepalive.json" ]]; then
        inputs+=("${OUT_DIR}/${server}-idle-keepalive.json")
    fi
    if [[ -f "${OUT_DIR}/${server}-connection-churn.json" ]]; then
        inputs+=("${OUT_DIR}/${server}-connection-churn.json")
    fi
    if [[ ${#inputs[@]} -eq 0 ]]; then
        echo "No normalized pass results found for ${server}" >&2
        exit 1
    fi
    local version
    version="$(server_version "$server")"
    jq -s --arg version "$version" '
        reduce .[] as $doc ({};
            ._meta = ((._meta // {}) + ($doc._meta // {})) |
            ._meta.server_version = $version |
            . + ($doc | del(._meta))
        )
    ' "${inputs[@]}" > "$combined"
}

write_combined_outputs() {
    local combined_json="${OUT_DIR}/competitive-results.json"
    local csv="${OUT_DIR}/competitive-results.csv"
    local md="${OUT_DIR}/competitive-summary.md"
    local server_files=()
    local known_server
    for known_server in tardigrade nginx haproxy caddy; do
        if [[ -f "${OUT_DIR}/${known_server}.json" ]]; then
            server_files+=("${OUT_DIR}/${known_server}.json")
        fi
    done
    if [[ ${#server_files[@]} -eq 0 ]]; then
        echo "No server result files were produced." >&2
        exit 1
    fi

    jq -s '
        {
            _meta: {
                generated_at: (now | todateiso8601),
                suite: "competitive",
                tool: $tool,
                duration_s: ($duration | tonumber),
                connections: ($connections | tonumber),
                threads: ($threads | tonumber),
                note: "Compare only same-host, same-tool, same-duration results. Laptop and shared-runner output is non-canonical."
            },
            servers: (reduce .[] as $doc ({};
                .[$doc._meta.competitive_server] = $doc
            ))
        }
    ' --arg tool "$TOOL" --arg duration "$DURATION" --arg connections "$CONNECTIONS" --arg threads "$THREADS" \
        "${server_files[@]}" > "$combined_json"

    jq -r '
        ["server","scenario","rps","p50_ms","p95_ms","p99_ms","p999_ms","throughput_mbps","cpu_pct_avg","rss_mb_peak","errors"],
        (.servers | to_entries[] as $server |
            $server.value | to_entries[] |
            select(.key != "_meta") |
            [$server.key, .key, (.value.rps // null), (.value.p50_ms // null), (.value.p95_ms // null),
             (.value.p99_ms // null), (.value.p999_ms // null), (.value.throughput_mbps // null),
             (.value.cpu_pct_avg // null), (.value.rss_mb_peak // null), (.value.errors // null)])
        | @csv
    ' "$combined_json" > "$csv"

    {
        echo "# Competitive Benchmark Summary"
        echo ""
        echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo ""
        echo "| Server | Scenario | req/s | p50 ms | p95 ms | p99 ms | p999 ms | MB/s | CPU % | RSS MiB | Errors |"
        echo "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"
        jq -r '
            .servers | to_entries[] as $server |
            $server.value | to_entries[] |
            select(.key != "_meta") |
            "| `\($server.key)` | `\(.key)` | \((.value.rps // 0) | floor) | \(.value.p50_ms // "-") | \(.value.p95_ms // "-") | \(.value.p99_ms // "-") | \(.value.p999_ms // "-") | \(.value.throughput_mbps // "-") | \(.value.cpu_pct_avg // "-") | \(.value.rss_mb_peak // "-") | \(.value.errors // 0) |"
        ' "$combined_json"
        echo ""
        echo "> Use these numbers only for same-host relative comparisons. Dedicated idle hosts are required for canonical claims."
    } > "$md"

    echo "Wrote:"
    echo "  ${combined_json}"
    echo "  ${csv}"
    echo "  ${md}"
}

require_tool jq
require_tool curl
require_tool python3
require_tool "$TOOL"

IFS=',' read -r -a SERVER_LIST <<< "$SERVERS"
for server in "${SERVER_LIST[@]}"; do
    tool_path="$(server_tool "$server")"
    if [[ "$server" == "tardigrade" ]]; then
        continue
    fi
    if ! has_tool "$tool_path"; then
        if $ALLOW_MISSING; then
            echo "Skipping ${server}: missing ${tool_path}"
            continue
        fi
        echo "Missing selected competitor '${server}' (${tool_path}). Re-run with --allow-missing to skip it." >&2
        exit 1
    fi
done

if $SMOKE; then
    echo "Running reduced competitive smoke benchmark for Tardigrade only."
fi

mkdir -p "$OUT_DIR"
TMP_DIR="$(mktemp -d /tmp/tardigrade-competitive-XXXX)"
mkdir -p "${TMP_DIR}/public"
printf 'ok\n' > "${TMP_DIR}/public/tiny.txt"
dd if=/dev/zero of="${TMP_DIR}/public/large.bin" bs=1024 count=1024 >/dev/null 2>&1

python3 "${BENCH_DIR}/fixtures/upstream_server.py" --port "$UPSTREAM_PORT" >"${TMP_DIR}/origin.log" 2>&1 &
ORIGIN_PID="$!"
wait_for_http "http://127.0.0.1:${UPSTREAM_PORT}/health"

for index in "${!SERVER_LIST[@]}"; do
    server="${SERVER_LIST[$index]}"
    tool_path="$(server_tool "$server")"
    if [[ "$server" != "tardigrade" ]] && ! has_tool "$tool_path"; then
        continue
    fi

    port=$((LISTEN_BASE + index))
    echo ""
    echo "== ${server} (${port}) =="
    echo "version: $(server_version "$server")"
    start_server "$server" "$port"

    if $SMOKE; then
        run_benchmark_pass "$server" "$port" "tiny-static" "static-http1" "/tiny.txt" "/proxy/health"
    else
        run_benchmark_pass "$server" "$port" "tiny-proxy" "static-http1,proxy-http1,keepalive" "/tiny.txt" "/proxy/health"
        run_benchmark_pass "$server" "$port" "large-static" "static-http1" "/large.bin" "/proxy/health"
        run_benchmark_pass "$server" "$port" "large-proxy" "proxy-http1" "/tiny.txt" "/proxy/payload-1m.bin"
        run_benchmark_pass "$server" "$port" "slow-client" "proxy-slow-client-download" "/tiny.txt" "/proxy/payload-16m.bin"
        run_connection_churn "$server" "$port"
    fi
    if $SMOKE; then
        :
    elif [[ "$TOOL" == "k6" ]]; then
        run_benchmark_pass "$server" "$port" "idle-keepalive" "keepalive-starvation" "/tiny.txt" "/proxy/health"
    else
        echo "Skipping idle keepalive plus active traffic scenario; it requires --tool k6."
    fi

    combine_server_results "$server"
    cleanup_edge
done

write_combined_outputs

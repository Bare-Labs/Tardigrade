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
BINARY_EXPLICIT=false
TARDIGRADE_BUILD_FLAGS="-Doptimize=ReleaseFast"
TARDIGRADE_BUILT=false
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
# #256-G: the H3 benchmark-only listener. A dedicated port outside the
# per-competitor block (LISTEN_BASE+0..3) and the upstream-pool-matrix range
# (LISTEN_BASE+200.. / +300..) so it never collides with either.
H3_LISTEN_OFFSET="250"
H3_TLS_SERVER_NAME="tardigrade.test"
TUNE_COMPARISON=false
H3_TUNED_UDP_BUFFER_BYTES="4194304"
# Set by run_tardigrade_http3_matrix right before launching the tuned pass, so
# udp_buffer_metadata_json (called once, globally, after all passes finish)
# can report what was actually requested. TARDIGRADE_HTTP3_UDP_*_BUFFER_BYTES
# themselves are only ever exported into the Tardigrade child process via
# `env NAME=VALUE ... "$BINARY" run`, never into this script's own
# environment, so reading them directly here always reads unset/0.
H3_TUNED_UDP_RECV_REQUESTED_BYTES=""
H3_TUNED_UDP_SEND_REQUESTED_BYTES=""
TMP_DIR=""
ORIGIN_PID=""
EDGE_PID=""
CURRENT_SERVER=""
CURRENT_CPU_PCT_AVG="null"
CURRENT_RSS_MB_PEAK="null"
CURRENT_OPEN_FDS_PEAK="null"
MONITOR_PID=""
MONITOR_FILE=""
CPU_BEFORE_SECONDS="null"
MONITOR_START_NS="null"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary) BINARY="$2"; BINARY_EXPLICIT=true; shift 2 ;;
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
            DURATION="2"
            CONNECTIONS="1"
            THREADS="1"
            SERVERS="tardigrade"
            shift
            ;;
        --tune-comparison) TUNE_COMPARISON=true; shift ;;
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
   with LISTEN_PORT, UPSTREAM_PORT, STATIC_ROOT, PID_FILE, and ERROR_LOG.
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
    if $BINARY_EXPLICIT; then
        if [[ ! -x "$BINARY" ]]; then
            echo "Explicit Tardigrade binary is not executable: ${BINARY}" >&2
            exit 1
        fi
        return
    fi
    if $TARDIGRADE_BUILT; then
        return
    fi
    echo "Building Tardigrade release binary (${TARDIGRADE_BUILD_FLAGS})..."
    (cd "$REPO_ROOT" && zig build ${TARDIGRADE_BUILD_FLAGS})
    TARDIGRADE_BUILT=true
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

# #256-G: benchmark-only local TLS identity for the H3 listener, generated
# fresh per run with the repository's existing interop cert tooling — never a
# checked-in or developer-machine path. `scripts/interop/gen-certs.sh` writes
# three identities; only the Ed25519 one is used here (the native stack's
# default profile).
generate_h3_certs() {
    local dir="$1"
    "${REPO_ROOT}/scripts/interop/gen-certs.sh" "${dir}/certs" >/dev/null
}

# #256-G: a second, TLS+HTTP/3-enabled Tardigrade listener alongside the
# plaintext HTTP/1.1 config the rest of this harness uses. Extra positional
# args after `port` are passed through as additional environment assignments
# (`env NAME=VALUE ...`) — used by the tuned-vs-baseline UDP buffer
# comparison to override `TARDIGRADE_HTTP3_UDP_RECV_BUFFER_BYTES` /
# `_SEND_BUFFER_BYTES` without a second config template.
start_tardigrade_http3() {
    ensure_tardigrade_binary
    local port="$1"
    shift
    local extra_env=("$@")
    local dir="${TMP_DIR}/tardigrade-http3"
    mkdir -p "$dir"
    generate_h3_certs "$dir"
    local cert="${dir}/certs/ed25519-cert.pem"
    local key="${dir}/certs/ed25519-key.pem"
    sed \
        -e "s|__LISTEN_PORT__|${port}|g" \
        -e "s|__UPSTREAM_PORT__|${UPSTREAM_PORT}|g" \
        -e "s|__STATIC_ROOT__|${TMP_DIR}/public|g" \
        -e "s|__PID_FILE__|${dir}/tardigrade.pid|g" \
        -e "s|__TLS_SERVER_NAME__|${H3_TLS_SERVER_NAME}|g" \
        -e "s|__TLS_CERT_PATH__|${cert}|g" \
        -e "s|__TLS_KEY_PATH__|${key}|g" \
        "${CONFIG_DIR}/tardigrade-http3.conf.in" > "${dir}/tardigrade.conf"
    env \
        TARDIGRADE_RATE_LIMIT_RPS=0 \
        TARDIGRADE_PROXY_STREAMING_MODE=response \
        TARDIGRADE_HTTP3_ENABLED=true \
        TARDIGRADE_QUIC_PORT="$port" \
        TARDIGRADE_TLS_SERVER_NAME="$H3_TLS_SERVER_NAME" \
        TARDIGRADE_HTTP3_ALT_SVC=auto \
        ${extra_env[@]+"${extra_env[@]}"} \
        "$BINARY" run -c "${dir}/tardigrade.conf" >"${dir}/server.log" 2>&1 &
    EDGE_PID="$!"
}

wait_for_https() {
    local url="$1"
    local attempts="${2:-60}"
    local delay="${3:-0.2}"
    local host_header="${4:-}"
    local extra=(--http1.1)
    [[ -n "$host_header" ]] && extra+=(-H "Host: ${host_header}")
    local i
    for ((i = 0; i < attempts; i += 1)); do
        if curl -k -fsS "${extra[@]+"${extra[@]}"}" "$url" >/dev/null 2>&1; then
            return 0
        fi
        sleep "$delay"
    done
    echo "Timed out waiting for ${url}" >&2
    return 1
}

# #256-G: "the process started" is not proof HTTP/3 is operational — the TLS
# port can come up while the QUIC/UDP side is misconfigured. Send one real
# HTTP/3 request over the actual load tool before any H3 result is recorded.
#
# Review note: this used to also check `h2load --h3 --help` itself and treat
# that failure the same as a failed request — conflating "this environment
# has no HTTP/3-capable load generator" (a legitimate `supported: false`)
# with "Tardigrade's QUIC listener didn't answer" (a product regression).
# Callers now check `h2load_h3_supported` *before* calling this, so a
# failure here always means the second case.
verify_h3_listener() {
    local port="$1"
    local url="https://127.0.0.1:${port}/health"
    local raw succeeded failed
    # #256-G review: h2load has no --insecure/verify-skip flag at all
    # (verified against a real nghttp2 1.69.0 build) — it never validates
    # TLS certificates in the first place, and passing an option it doesn't
    # recognize makes it exit immediately, which this loop would otherwise
    # misreport as "the listener didn't answer."
    # #256-G review: the benchmark config's `server_name` is
    # $H3_TLS_SERVER_NAME, not the 127.0.0.1 literal in $url — H3 dispatch
    # resolves routes off :authority, so without this header every request
    # here 404s before reaching /health regardless of whether QUIC itself
    # negotiated correctly.
    raw=$(h2load --h3 -n 1 -c 1 -H "Host: ${H3_TLS_SERVER_NAME}" "$url" 2>&1) || true
    succeeded=$(printf '%s\n' "$raw" | grep -oE '[0-9]+ succeeded' | grep -oE '^[0-9]+' | head -1)
    failed=$(printf '%s\n' "$raw" | grep -oE '[0-9]+ failed' | grep -oE '^[0-9]+' | head -1)
    if [[ "${succeeded:-0}" -lt 1 || "${failed:-1}" -gt 0 ]]; then
        echo "  H3/QUIC listener at ${url} did not answer a real HTTP/3 request; client capability was already verified, so the benchmark run will fail." >&2
        printf '%s\n' "$raw" | tail -20 >&2
        return 1
    fi
    return 0
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

tool_version() {
    case "$1" in
        wrk) { wrk --version 2>&1 || true; } | head -1 ;;
        h2load) { h2load --version 2>&1 || true; } | head -1 ;;
        fortio) { fortio version 2>&1 || true; } | head -1 ;;
        k6) { k6 version 2>&1 || true; } | head -1 ;;
        *) { "$1" --version 2>&1 || true; } | head -1 ;;
    esac
}

loopback_info() {
    if command -v ip >/dev/null 2>&1; then
        ip -o addr show lo 2>/dev/null | tr '\n' ';' || echo "unknown"
    elif command -v ifconfig >/dev/null 2>&1; then
        ifconfig lo0 2>/dev/null | awk '{$1=$1; printf "%s; ", $0}' || echo "unknown"
    else
        echo "unknown"
    fi
}

# Host-wide ceilings on per-socket UDP buffers (#256-D). A QUIC run whose
# receive buffer filled looks like packet loss in the results, so the ceiling
# that bounded it belongs in the metadata next to the numbers it explains.
# These are the *host* limits; the size the listener actually got is read back
# with getsockopt and logged by the runtime itself, since only the process can
# see it.
udp_sysctl() {
    local key="$1"
    if command -v sysctl >/dev/null 2>&1; then
        sysctl -n "$key" 2>/dev/null || echo "unknown"
    else
        echo "unknown"
    fi
}

udp_buffer_metadata_json() {
    if [[ "$(uname -s 2>/dev/null || true)" == "Linux" ]]; then
        jq -n \
            --arg rmem_max "$(udp_sysctl net.core.rmem_max)" \
            --arg wmem_max "$(udp_sysctl net.core.wmem_max)" \
            --arg rmem_default "$(udp_sysctl net.core.rmem_default)" \
            --arg wmem_default "$(udp_sysctl net.core.wmem_default)" \
            --arg requested_recv "${H3_TUNED_UDP_RECV_REQUESTED_BYTES:-0}" \
            --arg requested_send "${H3_TUNED_UDP_SEND_REQUESTED_BYTES:-0}" \
            '{
                host_ceiling: {
                    "net.core.rmem_max": $rmem_max,
                    "net.core.wmem_max": $wmem_max,
                    "net.core.rmem_default": $rmem_default,
                    "net.core.wmem_default": $wmem_default
                },
                tardigrade_requested: {
                    recv_bytes: $requested_recv,
                    send_bytes: $requested_send
                }
            }'
    else
        jq -n \
            --arg maxsockbuf "$(udp_sysctl kern.ipc.maxsockbuf)" \
            --arg recvspace "$(udp_sysctl net.inet.udp.recvspace)" \
            --arg requested_recv "${H3_TUNED_UDP_RECV_REQUESTED_BYTES:-0}" \
            --arg requested_send "${H3_TUNED_UDP_SEND_REQUESTED_BYTES:-0}" \
            '{
                host_ceiling: {
                    "kern.ipc.maxsockbuf": $maxsockbuf,
                    "net.inet.udp.recvspace": $recvspace
                },
                tardigrade_requested: {
                    recv_bytes: $requested_recv,
                    send_bytes: $requested_send
                }
            }'
    fi
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
    h2load --h3 --help >/dev/null 2>&1 || return 1
    local h2load_path
    h2load_path="$(command -v h2load)"
    if command -v otool >/dev/null 2>&1; then
        otool -L "$h2load_path" 2>/dev/null | grep -qiE 'libngtcp2|libnghttp3'
    elif command -v ldd >/dev/null 2>&1; then
        ldd "$h2load_path" 2>/dev/null | grep -qiE 'libngtcp2|libnghttp3'
    else
        # Neither linkage-inspection tool is available, so QUIC-library
        # linkage can't be verified — this must fail closed (unsupported),
        # matching the "prefer false negatives, never false positives"
        # design this function documents above. Returning success here would
        # readmit exactly the false-positive `--h3 --help`-only check this
        # function was written to replace.
        echo "  Neither otool nor ldd is available to verify h2load's QUIC linkage; treating HTTP/3 as unsupported on this host." >&2
        return 1
    fi
}

host_metadata_json() {
    jq -n \
        --arg load_tool "$TOOL" \
        --arg load_tool_version "$(tool_version "$TOOL")" \
        --arg ulimit_n "$(ulimit -n 2>/dev/null || echo unknown)" \
        --arg ulimit_u "$(ulimit -u 2>/dev/null || echo unknown)" \
        --arg loopback "$(loopback_info)" \
        --argjson udp_buffers "$(udp_buffer_metadata_json)" \
        --arg tardigrade_build_flags "$TARDIGRADE_BUILD_FLAGS" \
        --argjson tardigrade_binary_explicit "$($BINARY_EXPLICIT && echo true || echo false)" \
        --arg h2load_version "$(tool_version h2load)" \
        --argjson h2load_h3_supported "$(h2load_h3_supported && echo true || echo false)" \
        '{
            load_tool: $load_tool,
            load_tool_version: $load_tool_version,
            ulimit: {
                open_files: $ulimit_n,
                max_user_processes: $ulimit_u
            },
            network: {
                loopback: $loopback,
                udp_buffers: $udp_buffers
            },
            tardigrade: {
                build_flags: $tardigrade_build_flags,
                binary_explicit: $tardigrade_binary_explicit
            },
            h2load: {
                version: $h2load_version,
                h3_supported: $h2load_h3_supported
            }
        }'
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
    local pid="$1" pids clk total_ticks child
    pids="$(process_tree_pids "$pid" | paste -sd, -)"
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

monitor_process_tree() {
    local pid="$1" sample_interval_s="$2" outfile="$3"
    while kill -0 "$pid" 2>/dev/null; do
        process_tree_pids "$pid" | paste -sd, - | {
            read -r pids
            [[ -n "$pids" ]] || pids="$pid"
            local fds
            fds="$(count_open_fds_for_pids "$pids")"
            ps -p "$pids" -o rss= 2>/dev/null |
                awk -v fds="$fds" '{ rss += $1 } END { if (rss > 0) print rss, fds }' >> "$outfile"
        }
        sleep "$sample_interval_s"
    done
}

average_column_or_null() {
    local file="$1" column="$2"
    awk -v col="$column" 'NF >= col { sum += $col; count += 1 } END { if (count > 0) printf "%.2f", sum / count; else printf "null" }' "$file"
}

peak_rss_mb_or_null() {
    local file="$1"
    awk 'NF >= 1 && $1 > max { max = $1 } END { if (max > 0) printf "%.2f", max / 1024; else printf "null" }' "$file"
}

start_process_monitor() {
    CURRENT_CPU_PCT_AVG="null"
    CURRENT_RSS_MB_PEAK="null"
    CURRENT_OPEN_FDS_PEAK="null"
    CPU_BEFORE_SECONDS="$(process_tree_cpu_seconds "$EDGE_PID")"
    MONITOR_START_NS="$(monotonic_ns)"
    MONITOR_FILE="$(mktemp /tmp/tardigrade-competitive-monitor-XXXXXX)"
    local sample_interval_s
    sample_interval_s="0.500"
    monitor_process_tree "$EDGE_PID" "$sample_interval_s" "$MONITOR_FILE" &
    MONITOR_PID="$!"
}

stop_process_monitor() {
    if [[ -n "$MONITOR_PID" ]]; then
        kill "$MONITOR_PID" 2>/dev/null || true
        wait "$MONITOR_PID" 2>/dev/null || true
        MONITOR_PID=""
    fi
    if [[ -n "$MONITOR_FILE" && -f "$MONITOR_FILE" ]]; then
        local cpu_after end_ns
        cpu_after="$(process_tree_cpu_seconds "$EDGE_PID")"
        end_ns="$(monotonic_ns)"
        CURRENT_CPU_PCT_AVG="$(awk -v before="$CPU_BEFORE_SECONDS" -v after="$cpu_after" -v start="$MONITOR_START_NS" -v end="$end_ns" '
            BEGIN {
                elapsed = (end - start) / 1000000000
                if (before != "null" && elapsed > 0) printf "%.2f", ((after - before) / elapsed) * 100
                else printf "null"
            }')"
        CURRENT_RSS_MB_PEAK="$(peak_rss_mb_or_null "$MONITOR_FILE")"
        CURRENT_OPEN_FDS_PEAK="$(awk 'NF >= 2 && $2 ~ /^[0-9]+$/ && $2 > max { max = $2 } END { if (max > 0) printf "%d", max; else printf "null" }' "$MONITOR_FILE")"
        rm -f "$MONITOR_FILE"
        MONITOR_FILE=""
    fi
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

assert_payload_size() {
    local url="$1"
    local expected_bytes="$2"
    local host_header="${3:-}"
    local tmp actual_bytes
    tmp="$(mktemp /tmp/tardigrade-competitive-payload-XXXX)"
    local extra=()
    [[ -n "$host_header" ]] && extra+=(-H "Host: ${host_header}")
    [[ "$url" == https://* ]] && extra+=(--http1.1)
    # -k is a no-op for plain http:// URLs; needed for the benchmark-only
    # self-signed H3 listener's https:// URLs (#256-G).
    curl -k -fsS "${extra[@]+"${extra[@]}"}" "$url" -o "$tmp"
    actual_bytes="$(wc -c < "$tmp" | tr -d '[:space:]')"
    rm -f "$tmp"
    if [[ "$actual_bytes" != "$expected_bytes" ]]; then
        echo "Preflight failed for ${url}: expected ${expected_bytes} bytes, got ${actual_bytes}" >&2
        exit 1
    fi
}

preflight_server() {
    local server="$1"
    local port="$2"
    local base="http://127.0.0.1:${port}"
    assert_payload_size "${base}/tiny.txt" 3
    if [[ "$server" != "haproxy" ]]; then
        assert_payload_size "${base}/large.bin" 1048576
    fi
    assert_payload_size "${base}/proxy/health" 2
    assert_payload_size "${base}/proxy/payload-1m.bin" 1048576
    assert_payload_size "${base}/proxy/payload-16m.bin" 16777216
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
            elif $pass == "static-small-h3" and .key == "static-http3" then .key = "static-small-http3" | .
            elif $pass == "static-large-h3" and .key == "static-http3" then .key = "static-large-http3" | .
            elif $pass == "proxy-large-h3" and .key == "proxy-http3" then .key = "proxy-large-http3" | .
            elif $pass == "static-small-h3-tuned" and .key == "static-http3" then .key = "static-small-http3-tuned" | .
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
    local pass_tool="${7:-$TOOL}"
    local raw="${OUT_DIR}/${server}-${pass}.raw.json"
    local renamed="${OUT_DIR}/${server}-${pass}.json"

    "${BENCH_DIR}/run.sh" \
        --tool "$pass_tool" \
        --host 127.0.0.1 \
        --port "$port" \
        --driver "competitive-loopback" \
        --config-label "${server}" \
        --pid "$EDGE_PID" \
        --pid-tree \
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

# #256-G: H3-specific pass runner — forces --tool h2load (the only driver
# benchmarks/run.sh can speak HTTP/3 with) and --tls --insecure (the
# benchmark-only cert is self-signed for this host). Otherwise mirrors
# run_benchmark_pass, including the raw/renamed/rename_pass_json flow.
run_benchmark_pass_h3() {
    local server="$1"
    local port="$2"
    local pass="$3"
    local scenarios="$4"
    local h3_path="$5"
    local proxy_path="$6"
    local raw="${OUT_DIR}/${server}-${pass}.raw.json"
    local renamed="${OUT_DIR}/${server}-${pass}.json"

    "${BENCH_DIR}/run.sh" \
        --tool h2load \
        --host 127.0.0.1 \
        --port "$port" \
        --host-header "$H3_TLS_SERVER_NAME" \
        --tls \
        --insecure \
        --driver "competitive-loopback" \
        --config-label "${server}" \
        --pid "$EDGE_PID" \
        --pid-tree \
        --meta-file "$META_FILE" \
        --duration "$DURATION" \
        --connections "$CONNECTIONS" \
        --threads "$THREADS" \
        --h3-path "$h3_path" \
        --proxy-path "$proxy_path" \
        --scenarios "$scenarios" \
        --save "$raw"
    rename_pass_json "$raw" "$renamed" "$server" "$pass"
}

# #256-G review: dumps the H3 listener's logs to stderr for diagnosis. Split
# out because both the readiness and the (post-capability) hard-failure
# paths in run_tardigrade_http3_matrix need it.
dump_h3_logs() {
    find "${TMP_DIR}/tardigrade-http3" -maxdepth 1 -name '*.log' -print -exec tail -60 {} \; >&2 || true
}

# #256-G: canonical H3 rows for the `tardigrade` server — small/large static
# object, large streaming reverse proxy, and (opt-in) a before/after UDP
# socket buffer tuning comparison. Runs its own dedicated TLS+H3 listener
# rather than reusing the plaintext HTTP/1.1 instance the rest of this
# harness drives, since HTTP/3 needs TLS credentials and a QUIC port the
# plaintext config does not have. Writes `${OUT_DIR}/tardigrade-<pass>.json`
# files and re-runs `combine_server_results tardigrade` so they land in the
# same combined `tardigrade.json` the HTTP/1.1 passes already wrote.
#
# Review note: this used to treat "h2load can't speak HTTP/3" and "Tardigrade's
# QUIC listener didn't come up/answer" identically — both wrote unsupported
# rows and returned 0, so a real Tardigrade H3 regression could go unnoticed
# behind a green run. Client capability is now checked *first* and is the
# only case that is a soft `supported: false`; every failure after that is a
# product-side failure and aborts the run (`return 1` under this script's
# `set -e`, which the trap on EXIT still cleans up after).
run_tardigrade_http3_matrix() {
    local port=$((LISTEN_BASE + H3_LISTEN_OFFSET))
    echo ""
    echo "== tardigrade-http3 (${port}) =="

    if ! h2load_h3_supported; then
        echo "  h2load on this host does not support --h3 (HTTP/3/QUIC) — H3 rows will be marked unsupported." >&2
        write_unsupported_result "tardigrade" "static-small-http3" "h2load on this host does not support HTTP/3 (no QUIC-enabled build)." "${OUT_DIR}/tardigrade-static-small-h3.json"
        write_unsupported_result "tardigrade" "static-large-http3" "h2load on this host does not support HTTP/3 (no QUIC-enabled build)." "${OUT_DIR}/tardigrade-static-large-h3.json"
        write_unsupported_result "tardigrade" "proxy-large-http3" "h2load on this host does not support HTTP/3 (no QUIC-enabled build)." "${OUT_DIR}/tardigrade-proxy-large-h3.json"
        combine_server_results "tardigrade"
        return 0
    fi
    echo "h2load supports HTTP/3 on this host — any Tardigrade H3 failure from here is a product regression, not an environment limitation, and fails this run."

    start_tardigrade_http3 "$port"
    if ! wait_for_https "https://127.0.0.1:${port}/health" 60 0.2 "$H3_TLS_SERVER_NAME"; then
        echo "  tardigrade did not come up with HTTP/3 enabled." >&2
        dump_h3_logs
        cleanup_edge
        return 1
    fi
    assert_payload_size "https://127.0.0.1:${port}/tiny.txt" 3 "$H3_TLS_SERVER_NAME"
    if ! $SMOKE; then
        assert_payload_size "https://127.0.0.1:${port}/large.bin" 1048576 "$H3_TLS_SERVER_NAME"
        assert_payload_size "https://127.0.0.1:${port}/proxy/payload-1m.bin" 1048576 "$H3_TLS_SERVER_NAME"
    fi

    if ! verify_h3_listener "$port"; then
        echo "  H3/QUIC listener did not answer a real HTTP/3 request." >&2
        dump_h3_logs
        cleanup_edge
        return 1
    fi

    echo "H3/QUIC listener verified — recording H3 results."
    run_benchmark_pass_h3 "tardigrade" "$port" "static-small-h3" "static-http3" "/tiny.txt" "/proxy/health"
    if ! $SMOKE; then
        run_benchmark_pass_h3 "tardigrade" "$port" "static-large-h3" "static-http3" "/large.bin" "/proxy/health"
        run_benchmark_pass_h3 "tardigrade" "$port" "proxy-large-h3" "proxy-http3" "/tiny.txt" "/proxy/payload-1m.bin"
    fi
    cleanup_edge

    if $TUNE_COMPARISON && ! $SMOKE; then
        echo ""
        echo "== tardigrade-http3 tuned UDP buffers (${port}) =="
        H3_TUNED_UDP_RECV_REQUESTED_BYTES="$H3_TUNED_UDP_BUFFER_BYTES"
        H3_TUNED_UDP_SEND_REQUESTED_BYTES="$H3_TUNED_UDP_BUFFER_BYTES"
        start_tardigrade_http3 "$port" \
            "TARDIGRADE_HTTP3_UDP_RECV_BUFFER_BYTES=${H3_TUNED_UDP_BUFFER_BYTES}" \
            "TARDIGRADE_HTTP3_UDP_SEND_BUFFER_BYTES=${H3_TUNED_UDP_BUFFER_BYTES}"
        if ! wait_for_https "https://127.0.0.1:${port}/health" 60 0.2 "$H3_TLS_SERVER_NAME" || ! verify_h3_listener "$port"; then
            # Baseline H3 already proved the client is capable and the
            # untuned listener works — a tuned-listener failure here is the
            # same kind of product regression as the baseline checks above,
            # not a reason to quietly drop the comparison row.
            echo "  Tuned-buffer listener did not come up cleanly (baseline H3 already verified — this is a real failure)." >&2
            dump_h3_logs
            cleanup_edge
            return 1
        fi
        run_benchmark_pass_h3 "tardigrade" "$port" "static-small-h3-tuned" "static-http3" "/tiny.txt" "/proxy/health"
        cleanup_edge
    fi

    combine_server_results "tardigrade"
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
    start_process_monitor
    raw=$(wrk --latency -s "${BENCH_DIR}/wrk-summary.lua" \
        -t"${THREADS}" -c"${CONNECTIONS}" -d"${DURATION}s" \
        -H "Connection: close" \
        "http://127.0.0.1:${port}/tiny.txt" 2>&1) || true
    stop_process_monitor
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
    errors=$(printf '%s\n' "$raw" | wrk_error_count)
    rps=${rps:-0}
    errors=${errors:-0}
    if [[ "$errors" != "0" ]]; then
        echo "wrk reported ${errors} errors for connection-churn-http1 (${server})" >&2
        echo "$raw" >&2
        exit 1
    fi
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
        --argjson cpu "$CURRENT_CPU_PCT_AVG" \
        --argjson rss "$CURRENT_RSS_MB_PEAK" \
        --argjson fds "$CURRENT_OPEN_FDS_PEAK" \
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
                cpu_pct_avg: $cpu,
                rss_mb_peak: $rss,
                open_fds_peak: $fds,
                errors: $errors
            }
        }' > "$output"
}

write_unsupported_result() {
    local server="$1"
    local scenario="$2"
    local reason="$3"
    local output="$4"
    jq -n --arg server "$server" --arg scenario "$scenario" --arg reason "$reason" '{
        _meta: {
            competitive_server: $server,
            competitive_pass: $scenario
        },
        ($scenario): {
            supported: false,
            reason: $reason,
            rps: null,
            p50_ms: null,
            p95_ms: null,
            p99_ms: null,
            p999_ms: null,
            throughput_mbps: null,
            cpu_pct_avg: null,
            rss_mb_peak: null,
            errors: null
        }
    }' > "$output"
}

run_idle_keepalive_aux() {
    local server="$1"
    local port="$2"
    if ! command -v k6 >/dev/null 2>&1; then
        echo "Skipping idle keepalive plus active traffic scenario; k6 is not installed."
        return 0
    fi
    run_benchmark_pass "$server" "$port" "idle-keepalive" "keepalive-starvation" "/tiny.txt" "/proxy/health" "k6"
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
    # #256-G: H3 rows, present only for `tardigrade` and only when the H3
    # matrix actually ran (verified listener) or explicitly recorded as
    # unsupported — never silently absent.
    local h3_pass
    for h3_pass in static-small-h3 static-large-h3 proxy-large-h3 static-small-h3-tuned; do
        if [[ -f "${OUT_DIR}/${server}-${h3_pass}.json" ]]; then
            inputs+=("${OUT_DIR}/${server}-${h3_pass}.json")
        fi
    done
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
        | with_entries(
            if .key == "_meta" or (.value.supported? == false) then
                .
            else
                .value.cpu_ms_per_request =
                    (if ((.value.cpu_pct_avg // null) != null and (.value.rps // 0) > 0)
                     then ((.value.cpu_pct_avg / 100.0) / .value.rps * 1000.0)
                     else null end) |
                .value.p99_ttfb_ms = null |
                .
            end
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

    local upstream_matrix="${OUT_DIR}/upstream-pool-matrix.json"
    local upstream_arg=()
    if [[ -f "$upstream_matrix" ]]; then
        upstream_arg=(--slurpfile upstream "$upstream_matrix")
    else
        upstream_arg=(--argjson upstream '[]')
    fi

    jq -s "${upstream_arg[@]}" '
        {
            _meta: {
                generated_at: (now | todateiso8601),
                suite: "competitive",
                tool: $tool,
                duration_s: ($duration | tonumber),
                connections: ($connections | tonumber),
                threads: ($threads | tonumber),
                host: $host_metadata,
                note: "Compare only same-host, same-tool, same-duration results. Laptop and shared-runner output is non-canonical."
            },
            servers: (reduce .[] as $doc ({};
                .[$doc._meta.competitive_server] = $doc
            )),
            upstream_pool_matrix: (if ($upstream | length) > 0 then $upstream[0] else null end)
        }
    ' --arg tool "$TOOL" --arg duration "$DURATION" --arg connections "$CONNECTIONS" --arg threads "$THREADS" \
        --argjson host_metadata "$(host_metadata_json)" \
        "${server_files[@]}" > "$combined_json"

    jq -r '
        ["server","scenario","supported","reason","rps","p50_ms","p95_ms","p99_ms","p999_ms","p99_ttfb_ms","throughput_mbps","cpu_pct_avg","cpu_ms_per_request","rss_mb_peak","open_fds_peak","errors","pool_lock_wait_ns_per_request","pool_lock_wait_ns_per_acquire","quic_packets_sent","quic_packets_lost","quic_pto_total","quic_effective_plpmtu_last_bytes","quic_ecn_enabled","quic_udp_recv_buffer_status","quic_udp_send_buffer_status"],
        (.servers | to_entries[] as $server |
            $server.value | to_entries[] |
            select(.key != "_meta") |
            [$server.key, .key, (if .value.supported == null then true else .value.supported end), (.value.reason // null), (.value.rps // null), (.value.p50_ms // null), (.value.p95_ms // null),
             (.value.p99_ms // null), (.value.p999_ms // null), (.value.p99_ttfb_ms // null), (.value.throughput_mbps // null),
             (.value.cpu_pct_avg // null), (.value.cpu_ms_per_request // null), (.value.rss_mb_peak // null), (.value.open_fds_peak // null), (.value.errors // null), null, null,
             (.value.quic.packets_sent // null), (.value.quic.packets_lost // null), (.value.quic.pto_total // null),
             (.value.quic.effective_plpmtu.last_bytes // null), (.value.quic.ecn.enabled // null),
             (.value.quic.udp_buffers.recv.status // null), (.value.quic.udp_buffers.send.status // null)]),
        (if .upstream_pool_matrix != null then
            (.upstream_pool_matrix.scenarios | to_entries[] |
                (.value.combined // .value) as $v |
                ["tardigrade", ("upstream-pool/" + .key), (if .value.covered != null then .value.covered elif .value.supported != null then .value.supported else true end), (.value.reason // .value.sharding_note // null),
                 ($v.rps // null), null, null, ($v.p99_ms // null), null, ($v.p99_ttfb_ms // null), null,
                 ($v.cpu_pct_avg // null), ($v.cpu_ms_per_request // null), ($v.rss_mb_peak // null), ($v.open_fds_peak // null), (.value.errors // $v.errors // null),
                 ($v.pool_lock_wait_ns_per_request // null), ($v.pool_lock_wait_ns_per_acquire // null),
                 null, null, null, null, null, null, null]),
            (.upstream_pool_matrix.scenarios["uneven-route-distribution"].routes // {} | to_entries[] |
                ["tardigrade", ("upstream-pool/uneven/" + .key), (if .value.covered == null then true else .value.covered end), (.value.reason // null),
                 (.value.rps // null), null, null, (.value.p99_ms // null), null, (.value.p99_ttfb_ms // null), null,
                 (.value.cpu_pct_avg // null), (.value.cpu_ms_per_request // null), (.value.rss_mb_peak // null), (.value.open_fds_peak // null), (.value.errors // null),
                 (.value.pool_lock_wait_ns_per_request // null), (.value.pool_lock_wait_ns_per_acquire // null),
                 null, null, null, null, null, null, null]),
            (.upstream_pool_matrix.scenarios["many-origins-low-volume"].measurements // [] | .[] |
                ["tardigrade", ("upstream-pool/origin/" + (.origin // "unknown")), (if .covered == null then true else .covered end), (.reason // null),
                 (.rps // null), null, null, (.p99_ms // null), null, (.p99_ttfb_ms // null), null,
                 (.cpu_pct_avg // null), (.cpu_ms_per_request // null), (.rss_mb_peak // null), (.open_fds_peak // null), (.errors // null),
                 (.pool_lock_wait_ns_per_request // null), (.pool_lock_wait_ns_per_acquire // null),
                 null, null, null, null, null, null, null]),
            (.upstream_pool_matrix.scenarios["pool-contention"].measurements // [] | .[] |
                ["tardigrade", ("upstream-pool/contention/" + ((.worker_threads // 0) | tostring) + "w"), (if .covered == null then true else .covered end), (.reason // null),
                 (.rps // null), null, null, (.p99_ms // null), null, (.p99_ttfb_ms // null), null,
                 (.cpu_pct_avg // null), (.cpu_ms_per_request // null), (.rss_mb_peak // null), (.open_fds_peak // null), (.errors // null),
                 (.pool_lock_wait_ns_per_request // null), (.pool_lock_wait_ns_per_acquire // null),
                 null, null, null, null, null, null, null])
         else empty end)
        | @csv
    ' "$combined_json" > "$csv"

    {
        echo "# Competitive Benchmark Summary"
        echo ""
        echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo ""
        echo "| Server | Scenario | Supported | req/s | p50 ms | p95 ms | p99 ms | p999 ms | p99 TTFB ms | MB/s | CPU % | RSS MiB | Open FDs | Errors |"
        echo "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"
        jq -r '
            .servers | to_entries[] as $server |
            $server.value | to_entries[] |
            select(.key != "_meta") |
            if (.value.supported? == false) then
                "| `\($server.key)` | `\(.key)` | unsupported: \(.value.reason // "not supported") | - | - | - | - | - | - | - | - | - | - | - |"
            else
                "| `\($server.key)` | `\(.key)` | yes | \((.value.rps // 0) | floor) | \(.value.p50_ms // "-") | \(.value.p95_ms // "-") | \(.value.p99_ms // "-") | \(.value.p999_ms // "-") | \(.value.p99_ttfb_ms // "-") | \(.value.throughput_mbps // "-") | \(.value.cpu_pct_avg // "-") | \(.value.rss_mb_peak // "-") | \(.value.open_fds_peak // "-") | \(.value.errors // 0) |"
            end
        ' "$combined_json"
        if jq -e '[.servers[] | to_entries[] | select(.value.quic != null)] | length > 0' "$combined_json" >/dev/null; then
            echo ""
            echo "## H3/QUIC Transport State (#256-G)"
            echo ""
            echo "Requested vs effective/granted UDP buffer sizes are never the same number — see [docs/HTTP3_ROLLOUT.md](../../../docs/HTTP3_ROLLOUT.md#socket-buffers)."
            echo ""
            echo "| Scenario | Packets sent | Packets received | Packets lost | PTO | Effective PLPMTU (last / listener-lifetime min-max) | PMTU probes | Black holes | ECN enabled | ECN CE received | RCVBUF req/eff/granted (status) | SNDBUF req/eff/granted (status) |"
            echo "| --- | ---: | ---: | ---: | ---: | --- | ---: | ---: | --- | ---: | --- | --- |"
            jq -r '
                .servers | to_entries[] as $server |
                $server.value | to_entries[] |
                select(.value.quic != null) |
                .value.quic as $q |
                "| `\(.key)` | \($q.packets_sent) | \($q.packets_received) | \($q.packets_lost) | \($q.pto_total) | \($q.effective_plpmtu.last_bytes) / \($q.effective_plpmtu.lifetime_min_bytes)-\($q.effective_plpmtu.lifetime_max_bytes) | \($q.pmtu_probes) | \($q.pmtu_black_holes) | \($q.ecn.enabled) | \($q.ecn.ce_received) | \($q.udp_buffers.recv.requested_bytes)/\($q.udp_buffers.recv.effective_bytes)/\($q.udp_buffers.recv.granted_bytes) (\($q.udp_buffers.recv.status)) | \($q.udp_buffers.send.requested_bytes)/\($q.udp_buffers.send.effective_bytes)/\($q.udp_buffers.send.granted_bytes) (\($q.udp_buffers.send.status)) |"
            ' "$combined_json"
        fi
        if jq -e '.upstream_pool_matrix != null' "$combined_json" >/dev/null; then
            echo ""
            echo "## Upstream Pool Matrix"
            echo ""
            echo "| Scenario | Covered | req/s | p99 ms | p99 TTFB ms | CPU % | CPU ms/req | RSS MiB | New conn/s | Reuse ratio | Lock wait ns/req | Sharding | Errors | Reason |"
            echo "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: | --- |"
            jq -r '
                .upstream_pool_matrix.scenarios | to_entries[] |
                (.value.combined // .value) as $v |
                "| `\(.key)` | \((if .value.covered != null then .value.covered elif .value.supported != null then .value.supported else true end)) | \($v.rps // "-") | \($v.p99_ms // "-") | \($v.p99_ttfb_ms // "-") | \($v.cpu_pct_avg // "-") | \($v.cpu_ms_per_request // "-") | \($v.rss_mb_peak // "-") | \($v.new_connections_per_sec // "-") | \($v.reuse_ratio // "-") | \($v.pool_lock_wait_ns_per_request // "-") | \(.value.sharding_justified // "-") | \(.value.errors // $v.errors // "-") | \(.value.reason // "-") |"
            ' "$combined_json"
            echo ""
            echo "### Upstream Pool Detail Rows"
            echo ""
            echo "| Detail | req/s | p99 ms | p99 TTFB ms | CPU % | CPU ms/req | RSS MiB | Open FDs | New conn/s | Reuse ratio | Lock wait ns/req | Lock wait ns/acq | Errors |"
            echo "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"
            jq -r '
                def row($name; $v):
                    "| `" + $name + "` | " +
                    (($v.rps // "-") | tostring) + " | " +
                    (($v.p99_ms // "-") | tostring) + " | " +
                    (($v.p99_ttfb_ms // "-") | tostring) + " | " +
                    (($v.cpu_pct_avg // "-") | tostring) + " | " +
                    (($v.cpu_ms_per_request // "-") | tostring) + " | " +
                    (($v.rss_mb_peak // "-") | tostring) + " | " +
                    (($v.open_fds_peak // "-") | tostring) + " | " +
                    (($v.new_connections_per_sec // "-") | tostring) + " | " +
                    (($v.reuse_ratio // "-") | tostring) + " | " +
                    (($v.pool_lock_wait_ns_per_request // "-") | tostring) + " | " +
                    (($v.pool_lock_wait_ns_per_acquire // "-") | tostring) + " | " +
                    (($v.errors // "-") | tostring) + " |";
                (.upstream_pool_matrix.scenarios["uneven-route-distribution"].routes // {} | to_entries[] | row("uneven/" + .key; .value)),
                (.upstream_pool_matrix.scenarios["many-origins-low-volume"].measurements // [] | .[] | row("origin/" + (.origin // "unknown"); .)),
                (.upstream_pool_matrix.scenarios["pool-contention"].measurements // [] | .[] | row("contention/" + ((.worker_threads // 0) | tostring) + "w"; .))
            ' "$combined_json"
        fi
        echo ""
        echo "> Use these numbers only for same-host relative comparisons. Dedicated idle hosts are required for canonical claims."
    } > "$md"

    echo "Wrote:"
    echo "  ${combined_json}"
    echo "  ${csv}"
    echo "  ${md}"
}

selected_tardigrade() {
    local server
    for server in "${SERVER_LIST[@]}"; do
        [[ "$server" == "tardigrade" ]] && return 0
    done
    return 1
}

require_tool jq
require_tool curl
require_tool python3
require_tool "$TOOL"
if [[ ",$SERVERS," == *",tardigrade,"* ]]; then
    # #256-G: the H3 matrix (run_tardigrade_http3_matrix) needs openssl to
    # generate a benchmark-only local TLS identity, and runs even under
    # --smoke (bounded there), so this is no longer smoke-conditional.
    require_tool openssl
fi
if ! $SMOKE; then
    require_tool k6
fi

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
    if [[ "$server" == "tardigrade" ]]; then
        ensure_tardigrade_binary
    fi
    echo "version: $(server_version "$server")"
    start_server "$server" "$port"
    preflight_server "$server" "$port"

    if $SMOKE; then
        run_benchmark_pass "$server" "$port" "tiny-static" "static-http1" "/tiny.txt" "/proxy/health"
    else
        run_benchmark_pass "$server" "$port" "tiny-proxy" "static-http1,proxy-http1,keepalive" "/tiny.txt" "/proxy/health"
        if [[ "$server" == "haproxy" ]]; then
            write_unsupported_result "$server" "static-large-http1" \
                "HAProxy http-request return file responses must fit a response buffer; the 1 MiB static-file scenario is intentionally unsupported for this representative config." \
                "${OUT_DIR}/${server}-large-static.json"
        else
            run_benchmark_pass "$server" "$port" "large-static" "static-http1" "/large.bin" "/proxy/health"
        fi
        run_benchmark_pass "$server" "$port" "large-proxy" "proxy-http1" "/tiny.txt" "/proxy/payload-1m.bin"
        run_benchmark_pass "$server" "$port" "slow-client" "proxy-slow-client-download" "/tiny.txt" "/proxy/payload-16m.bin"
        run_connection_churn "$server" "$port"
    fi
    if $SMOKE; then
        :
    else
        run_idle_keepalive_aux "$server" "$port"
    fi

    combine_server_results "$server"
    cleanup_edge
done

if selected_tardigrade; then
    # #256-G: runs even under --smoke — bounded there because $DURATION/
    # $CONNECTIONS/$THREADS are already reduced to 2s/1/1 and the
    # large/proxy/tuned rows are skipped, leaving only "config renders,
    # Tardigrade launches with TLS+H3, one real H3 request succeeds."
    run_tardigrade_http3_matrix
fi

if ! $SMOKE && selected_tardigrade; then
    "${COMP_DIR}/upstream-pool-matrix.sh" \
        --binary "$BINARY" \
        --listen-port "$((LISTEN_BASE + 200))" \
        --origin-base-port "$((LISTEN_BASE + 300))" \
        --duration "$DURATION" \
        --connections "$CONNECTIONS" \
        --threads "$THREADS" \
        --output "${OUT_DIR}/upstream-pool-matrix.json"
fi

write_combined_outputs

#!/usr/bin/env bash
# Cross-machine competitive benchmark orchestrator for #593.
#
# benchmarks/competitive/run.sh runs the client (wrk/k6/h2load) and every
# server on the SAME machine, hitting 127.0.0.1. That measures the server in
# isolation from the OS scheduler's perspective, but the load generator and
# the server under test compete for the same CPUs the whole time.
#
# This script instead starts exactly one edge server (plus its origin
# fixture) on a remote guest that is otherwise idle, and drives load from
# THIS machine across a real network link via benchmarks/run.sh. Only one
# server runs on the guest at a time.
#
# Prerequisites:
#   - wrk/k6/h2load installed locally (this machine is the load generator)
#   - A guest reachable at --guest-ip from this machine (a route/NAT hop is
#     fine; see scripts/run-proxmox-performance-campaign.sh for how the
#     Proxmox guest used in development got a path off the 5GbE direct link)
#   - The guest reachable via SSH at --guest-ssh-host, with the Tardigrade
#     repo checked out at --guest-workdir (zig-out/bin/tardi already built)
#     and nginx/haproxy/caddy/python3/wrk/k6 installed
#
# Usage:
#   scripts/run-cross-machine-competitive.sh \
#       --guest-ip 192.168.86.58 \
#       --guest-ssh-host 'fe80::be24:11ff:fe28:59f3%vmbr0' \
#       --guest-ssh-key /tmp/.../vm_ssh_key \
#       --proxmox-host root@10.250.250.2 --proxmox-bind 10.250.250.1
#
# All guest SSH calls are double-hopped through --proxmox-host, matching the
# rest of this repo's Proxmox campaign tooling. If your guest is directly
# reachable, set --proxmox-host "" to skip the outer hop.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BENCH_DIR="${REPO_ROOT}/benchmarks"

PROXMOX_HOST="root@10.250.250.2"
PROXMOX_BIND="10.250.250.1"
GUEST_SSH_HOST=""
GUEST_SSH_KEY=""
GUEST_IP=""
GUEST_WORKDIR="/work/Tardigrade"
SERVERS="tardigrade,nginx,haproxy,caddy"
LISTEN_BASE=19080
UPSTREAM_PORT=19079
DURATION=15
CONNECTIONS=32
THREADS=4
SMOKE=false
WITH_H3=false
H3_TLS_SERVER_NAME="tardigrade.test"
OUT_DIR="${BENCH_DIR}/results/$(date -u +%Y%m%d-%H%M%S)-crossmachine"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --proxmox-host)   PROXMOX_HOST="$2"; shift 2 ;;
        --proxmox-bind)   PROXMOX_BIND="$2"; shift 2 ;;
        --guest-ssh-host) GUEST_SSH_HOST="$2"; shift 2 ;;
        --guest-ssh-key)  GUEST_SSH_KEY="$2"; shift 2 ;;
        --guest-ip)       GUEST_IP="$2"; shift 2 ;;
        --guest-workdir)  GUEST_WORKDIR="$2"; shift 2 ;;
        --servers)        SERVERS="$2"; shift 2 ;;
        --duration)       DURATION="$2"; shift 2 ;;
        --connections)    CONNECTIONS="$2"; shift 2 ;;
        --threads)        THREADS="$2"; shift 2 ;;
        --out-dir)        OUT_DIR="$2"; shift 2 ;;
        --smoke)          SMOKE=true; shift ;;
        --with-h3)        WITH_H3=true; shift ;;
        -h|--help) sed -n '2,32p' "$0"; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

[[ -n "$GUEST_SSH_HOST" ]] || { echo "--guest-ssh-host is required" >&2; exit 1; }
[[ -n "$GUEST_SSH_KEY" ]]  || { echo "--guest-ssh-key is required" >&2; exit 1; }
[[ -n "$GUEST_IP" ]]       || { echo "--guest-ip is required" >&2; exit 1; }

mkdir -p "$OUT_DIR"

# ── guest control plane ─────────────────────────────────────────────────────
# Pipes a script into the guest over a (possibly double-hopped) SSH
# connection and runs it with `bash -s`, forwarding "$@" as script args.
guest_exec() {
    local script="$1"; shift
    if [[ -n "$PROXMOX_HOST" ]]; then
        printf '%s' "$script" | ssh -o BatchMode=yes -o ConnectTimeout=10 -b "$PROXMOX_BIND" "$PROXMOX_HOST" \
            "ssh -i $GUEST_SSH_KEY -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 'root@${GUEST_SSH_HOST}' bash -s -- $*"
    else
        printf '%s' "$script" | ssh -i "$GUEST_SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 "root@${GUEST_SSH_HOST}" bash -s -- "$@"
    fi
}

echo "==> verifying guest reachability"
guest_exec 'echo "guest ok: $(hostname)"'

echo "==> preparing guest fixtures"
guest_exec '
set -euo pipefail
cd "$1"
mkdir -p benchmarks/results/crossmachine/public
printf "ok\n" > benchmarks/results/crossmachine/public/tiny.txt
dd if=/dev/zero of=benchmarks/results/crossmachine/public/large.bin bs=1024 count=1024 >/dev/null 2>&1
pkill -9 -f "results/crossmachine/" >/dev/null 2>&1 || true
pkill -9 -f "fixtures/upstream_server.py" >/dev/null 2>&1 || true
pkill -9 -f "^nginx: master" >/dev/null 2>&1 || true
pkill -9 -f "^/usr/sbin/haproxy" >/dev/null 2>&1 || true
pkill -9 -f "^caddy run" >/dev/null 2>&1 || true
sleep 1
echo "fixtures ready"
' "$GUEST_WORKDIR"

echo "==> starting origin fixture on guest"
guest_exec '
set -euo pipefail
cd "$1"
nohup python3 benchmarks/fixtures/upstream_server.py --port "$2" \
    >benchmarks/results/crossmachine/origin.log 2>&1 &
disown
echo $! > benchmarks/results/crossmachine/origin.pid
for _ in $(seq 1 20); do
    curl -sf -o /dev/null "http://127.0.0.1:$2/health" && { echo "origin ok"; exit 0; }
    sleep 0.5
done
echo "origin failed to become healthy" >&2
exit 1
' "$GUEST_WORKDIR" "$UPSTREAM_PORT"

render_and_start_server() {
    local server="$1" port="$2"
    guest_exec '
set -euo pipefail
cd "$1"; server="$2"; port="$3"; upstream="$4"; threads="$5"
dir="benchmarks/results/crossmachine"
static_root="${dir}/public"
pidfile="${dir}/${server}.pid"
errlog="${dir}/${server}.error.log"
svclog="${dir}/${server}.server.log"
cfgfile="${dir}/${server}.conf"

render() {
    sed \
        -e "s|__LISTEN_PORT__|${port}|g" \
        -e "s|__UPSTREAM_PORT__|${upstream}|g" \
        -e "s|__STATIC_ROOT__|${static_root}|g" \
        -e "s|__PID_FILE__|${pidfile}|g" \
        -e "s|__ERROR_LOG__|${errlog}|g" \
        -e "s|__THREADS__|${threads}|g" \
        "$1" > "$2"
}

case "$server" in
    tardigrade)
        render benchmarks/competitive/configs/tardigrade.conf.in "$cfgfile"
        TARDIGRADE_RATE_LIMIT_RPS=0 TARDIGRADE_PROXY_STREAMING_MODE=response \
            nohup ./zig-out/bin/tardi run -c "$cfgfile" >"$svclog" 2>&1 &
        disown
        echo $! > "${pidfile}.wrapper"
        ;;
    nginx)
        render benchmarks/competitive/configs/nginx.conf.in "$cfgfile"
        sed -i "s|127.0.0.1:${port}|0.0.0.0:${port}|" "$cfgfile"
        mkdir -p "${dir}/client_body_temp" "${dir}/proxy_temp"
        chmod -R a+rwX "$dir"
        nohup nginx -p "$(pwd)" -c "$(pwd)/$cfgfile" -g "daemon off;" >"$svclog" 2>&1 &
        disown
        echo $! > "${pidfile}.wrapper"
        ;;
    haproxy)
        render benchmarks/competitive/configs/haproxy.cfg.in "$cfgfile"
        sed -i "s|127.0.0.1:${port}|0.0.0.0:${port}|" "$cfgfile"
        nohup haproxy -f "$cfgfile" -db >"$svclog" 2>&1 &
        disown
        echo $! > "${pidfile}.wrapper"
        ;;
    caddy)
        render benchmarks/competitive/configs/Caddyfile.in "$cfgfile"
        nohup caddy run --config "$cfgfile" --adapter caddyfile >"$svclog" 2>&1 &
        disown
        echo $! > "${pidfile}.wrapper"
        ;;
    *)
        echo "unknown server: $server" >&2; exit 1 ;;
esac

for _ in $(seq 1 30); do
    curl -sf -o /dev/null "http://127.0.0.1:${port}/health" && { echo "${server} ok"; exit 0; }
    sleep 0.5
done
echo "${server} failed to become healthy" >&2
cat "$svclog" >&2 2>/dev/null || true
exit 1
' "$GUEST_WORKDIR" "$server" "$port" "$UPSTREAM_PORT" "$THREADS"
}

stop_server() {
    local server="$1"
    guest_exec '
set -uo pipefail
cd "$1"; server="$2"
dir="benchmarks/results/crossmachine"
wrapper_pid=""
[[ -f "${dir}/${server}.pid.wrapper" ]] && wrapper_pid="$(cat "${dir}/${server}.pid.wrapper")"
if [[ -n "$wrapper_pid" ]]; then
    children="$(pgrep -P "$wrapper_pid" 2>/dev/null | tr "\n" " ")"
    kill "$wrapper_pid" $children >/dev/null 2>&1
    for _ in $(seq 1 10); do
        kill -0 "$wrapper_pid" >/dev/null 2>&1 || break
        sleep 1
    done
    kill -9 "$wrapper_pid" $children >/dev/null 2>&1
fi
rm -f "${dir}/${server}.pid" "${dir}/${server}.pid.wrapper"
sleep 1
echo "${server} stopped"
' "$GUEST_WORKDIR" "$server"
}

verify_idle() {
    guest_exec '
ps -ef | grep -E "tardi run|nginx: master|/usr/sbin/haproxy|caddy run" | grep -v grep || echo "(none)"
' "$GUEST_WORKDIR"
}

SCENARIOS="static-http1,proxy-http1,keepalive,proxy-payload-16m"
if $SMOKE; then
    DURATION=5
    CONNECTIONS=8
fi

IFS=',' read -r -a SERVER_LIST <<< "$SERVERS"
declare -a RESULT_FILES=()

for idx in "${!SERVER_LIST[@]}"; do
    server="${SERVER_LIST[$idx]}"
    port=$((LISTEN_BASE + idx))
    echo ""
    echo "== ${server} (guest port ${port}) =="
    echo "-- guest state before start --"
    verify_idle

    render_and_start_server "$server" "$port"

    echo "-- verifying reachable from this machine over the network --"
    if ! curl -sf -o /dev/null -m 5 "http://${GUEST_IP}:${port}/health"; then
        echo "FATAL: ${server} not reachable at ${GUEST_IP}:${port} from this machine" >&2
        stop_server "$server"
        exit 1
    fi
    tiny_ok=true
    curl -sf -o /dev/null -m 5 "http://${GUEST_IP}:${port}/tiny.txt" || tiny_ok=false

    save_file="${OUT_DIR}/${server}.json"
    echo "-- running benchmarks/run.sh from this machine against ${GUEST_IP}:${port} --"
    bash "${BENCH_DIR}/run.sh" \
        --host "$GUEST_IP" --port "$port" \
        --scenarios "$SCENARIOS" \
        --duration "$DURATION" --connections "$CONNECTIONS" --threads "$THREADS" \
        --static-path "/tiny.txt" --proxy-path "/proxy/health" --keepalive-path "/tiny.txt" \
        --driver "macbook-5gbe-crossmachine" --config-label "$server" \
        --save "$save_file" || echo "warning: benchmarks/run.sh reported a non-zero exit for ${server}" >&2
    RESULT_FILES+=("$save_file")
    if ! $tiny_ok; then
        echo "note: ${server} /tiny.txt was not reachable before this pass (see ${save_file} for what actually ran)" >&2
    fi

    stop_server "$server"
    echo "-- guest state after stop --"
    verify_idle
done

has_tardigrade() {
    local s
    for s in "${SERVER_LIST[@]}"; do
        [[ "$s" == "tardigrade" ]] && return 0
    done
    return 1
}

if $WITH_H3 && has_tardigrade; then
    h3_port=$((LISTEN_BASE + 250))
    echo ""
    echo "== tardigrade-http3 (guest port ${h3_port}, TLS+QUIC) =="
    echo "-- guest state before start --"
    verify_idle

    guest_exec '
set -euo pipefail
cd "$1"; port="$2"; upstream="$3"; sni="$4"
dir="benchmarks/results/crossmachine"
static_root="${dir}/public"
certdir="${dir}/h3-certs"
scripts/interop/gen-certs.sh "$certdir" >/dev/null
cfgfile="${dir}/tardigrade-http3.conf"
sed \
    -e "s|__LISTEN_PORT__|${port}|g" \
    -e "s|__UPSTREAM_PORT__|${upstream}|g" \
    -e "s|__STATIC_ROOT__|${static_root}|g" \
    -e "s|__PID_FILE__|${dir}/tardigrade-http3.pid|g" \
    -e "s|__TLS_SERVER_NAME__|${sni}|g" \
    -e "s|__TLS_CERT_PATH__|${certdir}/ed25519-cert.pem|g" \
    -e "s|__TLS_KEY_PATH__|${certdir}/ed25519-key.pem|g" \
    benchmarks/competitive/configs/tardigrade-http3.conf.in > "$cfgfile"
env TARDIGRADE_RATE_LIMIT_RPS=0 TARDIGRADE_PROXY_STREAMING_MODE=response \
    TARDIGRADE_HTTP3_ENABLED=true TARDIGRADE_QUIC_PORT="$port" \
    TARDIGRADE_TLS_SERVER_NAME="$sni" TARDIGRADE_HTTP3_ALT_SVC=auto \
    nohup ./zig-out/bin/tardi run -c "$cfgfile" >"${dir}/tardigrade-http3.server.log" 2>&1 &
disown
echo $! > "${dir}/tardigrade-http3.pid.wrapper"
for _ in $(seq 1 30); do
    curl -sk -o /dev/null -m 3 --http1.1 -H "Host: ${sni}" "https://127.0.0.1:${port}/health" && { echo "tardigrade-http3 ok"; exit 0; }
    sleep 0.5
done
echo "tardigrade-http3 failed to become healthy" >&2
cat "${dir}/tardigrade-http3.server.log" >&2 2>/dev/null || true
exit 1
' "$GUEST_WORKDIR" "$h3_port" "$UPSTREAM_PORT" "$H3_TLS_SERVER_NAME"

    echo "-- verifying reachable from this machine over the network (real QUIC, via h2load) --"
    # macOS's system curl (LibreSSL) fails the TLS handshake against this
    # Ed25519 cert even though it's valid -- h2load (built with a real
    # OpenSSL-backed QUIC stack) is both the actual load tool and a working
    # preflight, so use it for verification instead of curl here.
    if ! h2load --h3 -n1 -c1 -t1 -H "Host: ${H3_TLS_SERVER_NAME}" "https://${GUEST_IP}:${h3_port}/health" 2>&1 | grep -q "1 succeeded"; then
        echo "FATAL: tardigrade-http3 not reachable at ${GUEST_IP}:${h3_port} from this machine" >&2
        stop_server "tardigrade-http3"
        exit 1
    fi

    h3_save_file="${OUT_DIR}/tardigrade-http3.json"
    echo "-- running benchmarks/run.sh (h2load --h3) from this machine against ${GUEST_IP}:${h3_port} --"
    bash "${BENCH_DIR}/run.sh" \
        --host "$GUEST_IP" --port "$h3_port" --tls --tool h2load \
        --host-header "$H3_TLS_SERVER_NAME" \
        --scenarios "static-http3,proxy-http3" \
        --duration "$DURATION" --connections "$CONNECTIONS" --threads "$THREADS" \
        --static-path "/tiny.txt" --proxy-path "/proxy/health" \
        --driver "macbook-5gbe-crossmachine" --config-label "tardigrade-http3" \
        --save "$h3_save_file" || echo "warning: benchmarks/run.sh reported a non-zero exit for tardigrade-http3" >&2
    RESULT_FILES+=("$h3_save_file")

    stop_server "tardigrade-http3"
    echo "-- guest state after stop --"
    verify_idle
fi

guest_exec '
set -uo pipefail
cd "$1"
pid="$(cat benchmarks/results/crossmachine/origin.pid 2>/dev/null || true)"
[[ -n "$pid" ]] && kill "$pid" 2>/dev/null
echo "origin stopped"
' "$GUEST_WORKDIR"

echo ""
echo "==> results:"
for f in "${RESULT_FILES[@]}"; do
    echo "  $f"
done

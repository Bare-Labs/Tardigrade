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
#   benchmarks/run-cross-machine-competitive.sh \
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
TARDIGRADE_GIT_SHA=""
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
        --tardigrade-git-sha) TARDIGRADE_GIT_SHA="$2"; shift 2 ;;
        -h|--help) sed -n '2,32p' "$0"; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

[[ -n "$GUEST_SSH_HOST" ]] || { echo "--guest-ssh-host is required" >&2; exit 1; }
[[ -n "$GUEST_SSH_KEY" ]]  || { echo "--guest-ssh-key is required" >&2; exit 1; }
[[ -n "$GUEST_IP" ]]       || { echo "--guest-ip is required" >&2; exit 1; }
if [[ -z "$TARDIGRADE_GIT_SHA" ]]; then
    echo "warning: --tardigrade-git-sha not given; results will record a" >&2
    echo "  binary sha256 and 'tardi version' output as SUT identity, but" >&2
    echo "  no human-readable source ref -- pass it if you know what ref" >&2
    echo "  --guest-workdir was built from." >&2
fi

mkdir -p "$OUT_DIR"

# ── guest control plane ─────────────────────────────────────────────────────
# Pipes a script into the guest over a (possibly double-hopped) SSH
# connection and runs it with `bash -s`, forwarding "$@" as script args.
#
# "$@" is never interpolated into a shell command string: it's %q-quoted
# into a `set --` line prepended to the piped script, so the values only
# ever get parsed once, by `bash -s` reading them as literal source text --
# not re-parsed by an intermediate remote shell. For the double-hop case,
# the remote command sent to the Proxmox host (which DOES get parsed by a
# shell there, since ssh always joins a remote command into one string) is
# itself built with printf %q, so GUEST_SSH_KEY/GUEST_SSH_HOST survive
# safely even if they ever contain shell metacharacters.
guest_exec() {
    local script="$1"; shift
    local wrapped="set --"
    local arg
    for arg in "$@"; do
        wrapped+=" $(printf '%q' "$arg")"
    done
    wrapped+=$'\n'"${script}"

    if [[ -n "$PROXMOX_HOST" ]]; then
        local inner_cmd
        printf -v inner_cmd 'ssh -i %q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 %q bash -s' \
            "$GUEST_SSH_KEY" "root@${GUEST_SSH_HOST}"
        printf '%s' "$wrapped" | ssh -o BatchMode=yes -o ConnectTimeout=10 -b "$PROXMOX_BIND" "$PROXMOX_HOST" "$inner_cmd"
    else
        printf '%s' "$wrapped" | ssh -i "$GUEST_SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 "root@${GUEST_SSH_HOST}" bash -s
    fi
}

echo "==> verifying guest reachability"
# shellcheck disable=SC2016 # intentional: this runs on the guest, not here
guest_exec 'echo "guest ok: $(hostname)"'

echo "==> preparing guest fixtures"
# shellcheck disable=SC2016 # intentional: this runs on the guest, not here
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
# shellcheck disable=SC2016 # intentional: this runs on the guest, not here
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
    # shellcheck disable=SC2016 # intentional: this runs on the guest, not here
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
    # shellcheck disable=SC2016 # intentional: this runs on the guest, not here
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

# Fails closed (rather than just printing) if any benchmark server is
# running on the guest when it shouldn't be. #705 was exactly this class of
# bug (stale servers racing on a reused port and corrupting metrics) inside
# the loopback harness; this guards the same failure mode here.
verify_idle() {
    local context="$1"
    local found
    # shellcheck disable=SC2016 # intentional: this runs on the guest, not here
    found="$(guest_exec '
ps -ef | grep -E "tardi run|nginx: master|/usr/sbin/haproxy|caddy run" | grep -v grep || true
' "$GUEST_WORKDIR")"
    if [[ -n "$found" ]]; then
        echo "FATAL: guest is not idle ($context):" >&2
        echo "$found" >&2
        exit 1
    fi
    echo "(none)"
}

# Requires --tardigrade-git-sha to match a marker file the deployer is
# expected to have written into --guest-workdir at archive/extraction time
# (".tardigrade-source-sha", containing `git rev-parse HEAD` from the
# machine that built the archive). Without this, a caller-supplied SHA is
# just an unverified label -- this makes it an assertion against the actual
# guest artifact instead. Only runs once, for the tardigrade family, since
# that's the only server this harness's git SHA claim describes.
require_verified_source() {
    [[ -n "$TARDIGRADE_GIT_SHA" ]] || return 0
    local marker
    # shellcheck disable=SC2016 # intentional: this runs on the guest, not here
    marker="$(guest_exec '
cd "$1" && cat .tardigrade-source-sha 2>/dev/null || true
' "$GUEST_WORKDIR")"
    marker="$(printf '%s' "$marker" | tr -d '[:space:]')"
    if [[ -z "$marker" ]]; then
        echo "FATAL: --tardigrade-git-sha was given but ${GUEST_WORKDIR}/.tardigrade-source-sha" >&2
        echo "  does not exist on the guest -- the claimed SHA is unverifiable. Write that file" >&2
        echo "  (containing the exact 'git rev-parse HEAD' the archive was built from) when" >&2
        echo "  preparing --guest-workdir, or omit --tardigrade-git-sha." >&2
        exit 1
    fi
    if [[ "$marker" != "$TARDIGRADE_GIT_SHA" ]]; then
        echo "FATAL: --tardigrade-git-sha=${TARDIGRADE_GIT_SHA} does not match" >&2
        echo "  ${GUEST_WORKDIR}/.tardigrade-source-sha=${marker}" >&2
        exit 1
    fi
    echo "==> verified: guest source matches --tardigrade-git-sha (${TARDIGRADE_GIT_SHA})"
}

# Independently verifiable identity of whatever is actually running on the
# guest right now, queried from the guest itself rather than assumed from
# this machine's own git state (which describes the load generator, not the
# system under test, and can silently drift from what --guest-workdir was
# actually built from). Called after render_and_start_server, so the
# rendered config for this pass already exists and can be queried/hashed.
capture_sut_meta() {
    local server="$1" port="$2"
    local scheme="http" host_header=""
    if [[ "$server" == "tardigrade-http3" ]]; then
        scheme="https"
        host_header="$H3_TLS_SERVER_NAME"
    fi
    local out
    # shellcheck disable=SC2016 # intentional: this runs on the guest, not here
    out="$(guest_exec '
set -uo pipefail
cd "$1"; server="$2"; port="$3"; scheme="$4"; host_header="$5"
kernel="$(uname -a)"
cpu_model="$(lscpu 2>/dev/null | awk -F: "/Model name:/{gsub(/^[ \t]+/, \"\", \$2); print \$2; exit}")"
[[ -z "$cpu_model" && -r /proc/cpuinfo ]] && cpu_model="$(awk -F: "/model name/{gsub(/^[ \t]+/, \"\", \$2); print \$2; exit}" /proc/cpuinfo)"
cpu_threads="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo unknown)"
memory_mb="unknown"
[[ -r /proc/meminfo ]] && memory_mb="$(awk "/MemTotal:/{printf \"%.0f\", \$2 / 1024}" /proc/meminfo)"
config_sha256="$(sha256sum "benchmarks/results/crossmachine/${server}.conf" 2>/dev/null | cut -d" " -f1)"
open_file_limit="$(ulimit -n 2>/dev/null || echo unknown)"
default_route="$(ip route show default 2>/dev/null | head -1)"
worker_threads=""
case "$server" in
    tardigrade|tardigrade-http3)
        version_output="$(./zig-out/bin/tardi version 2>&1)"
        binary_sha256="$(sha256sum zig-out/bin/tardi 2>/dev/null | cut -d" " -f1)"
        # metrics_path is served on the same vhost as everything else --
        # without a matching Host header Tardigrade 404s this exactly like
        # any other unmatched vhost request, silently yielding no metric.
        metrics_extra=()
        [[ -n "$host_header" ]] && metrics_extra=(-H "Host: ${host_header}")
        metrics="$(curl -sk -m 3 --http1.1 "${metrics_extra[@]}" "${scheme}://127.0.0.1:${port}/status/metrics" 2>/dev/null || true)"
        worker_threads="$(printf "%s" "$metrics" | awk "/^tardigrade_worker_threads /{print \$2; exit}")"
        ;;
    nginx)   version_output="$(nginx -v 2>&1)"; binary_sha256="" ;;
    haproxy) version_output="$(haproxy -v 2>&1 | head -1)"; binary_sha256="" ;;
    caddy)   version_output="$(caddy version 2>&1)"; binary_sha256="" ;;
    *)       version_output=""; binary_sha256="" ;;
esac
jq -n \
    --arg kernel "$kernel" --arg cpu_model "$cpu_model" --arg cpu_threads "$cpu_threads" \
    --arg memory_mb "$memory_mb" --arg config_sha256 "$config_sha256" \
    --arg open_file_limit "$open_file_limit" --arg default_route "$default_route" \
    --arg worker_threads "$worker_threads" \
    --arg version_output "$version_output" --arg binary_sha256 "$binary_sha256" \
    "{sut_kernel: \$kernel, sut_cpu_model: \$cpu_model, sut_cpu_threads: \$cpu_threads, sut_memory_mb: \$memory_mb, sut_config_sha256: \$config_sha256, sut_open_file_limit: \$open_file_limit, sut_default_route: \$default_route, sut_worker_threads: (\$worker_threads | select(. != \"\") // null), sut_server_version: \$version_output, sut_binary_sha256: \$binary_sha256}"
' "$GUEST_WORKDIR" "$server" "$port" "$scheme" "$host_header" 2>/dev/null)"
    if ! jq -e . >/dev/null 2>&1 <<<"$out"; then
        out='{"sut_kernel": null, "sut_cpu_model": null, "sut_cpu_threads": null, "sut_memory_mb": null, "sut_config_sha256": null, "sut_open_file_limit": null, "sut_default_route": null, "sut_worker_threads": null, "sut_server_version": null, "sut_binary_sha256": null}'
    fi
    # The Tardigrade source-identity claim only describes the tardigrade
    # binary -- attaching it to nginx/HAProxy/Caddy results would falsely
    # imply their SUT identity was verified the same way.
    if [[ -n "$TARDIGRADE_GIT_SHA" && ( "$server" == "tardigrade" || "$server" == "tardigrade-http3" ) ]]; then
        out="$(jq --arg sha "$TARDIGRADE_GIT_SHA" '. + {sut_tardigrade_git_sha: $sha, sut_tardigrade_git_sha_verified: true}' <<<"$out")"
    fi
    printf '%s' "$out"
}

# Patches a benchmarks/run.sh result file in place: merges SUT provenance
# into _meta, and marks the run non-canonical if any scenario reported
# errors OR this is a --smoke run (a 5s/8-connection smoke pass is
# intrinsically not canonical #593 evidence regardless of whether it
# happened to come back error-free), so a clean baseline and an
# exploratory/reduced run are never ambiguous from the JSON alone.
finalize_result_file() {
    local save_file="$1" sut_meta_json="$2" server="$3"
    if [[ ! -f "$save_file" ]]; then
        echo "FATAL: benchmarks/run.sh did not write ${save_file} -- it likely aborted" >&2
        echo "  partway through (this machine's own outbound connection churn from" >&2
        echo "  rapid back-to-back short scenario runs, especially under --smoke, can" >&2
        echo "  transiently exhaust local ephemeral ports as 'Can't assign requested" >&2
        echo "  address'). Not a stale/misleading result -- there is no result." >&2
        exit 1
    fi
    local total_errors
    total_errors="$(jq '[to_entries[] | select(.key != "_meta") | (.value.errors // 0)] | add // 0' "$save_file")"
    local canonical=true
    [[ "$total_errors" != "0" ]] && canonical=false
    $SMOKE && canonical=false
    local unverified_tardigrade=false missing_sut_metadata=false
    if [[ "$server" == "tardigrade" || "$server" == "tardigrade-http3" ]]; then
        [[ "$(jq -r '.sut_tardigrade_git_sha_verified // false' <<<"$sut_meta_json")" == "true" ]] || unverified_tardigrade=true
        [[ "$(jq -r '.sut_worker_threads // "null"' <<<"$sut_meta_json")" == "null" ]] && missing_sut_metadata=true
    fi
    $unverified_tardigrade && canonical=false
    $missing_sut_metadata && canonical=false
    jq --argjson sut "$sut_meta_json" --argjson total_errors "$total_errors" --argjson canonical "$canonical" --argjson smoke "$SMOKE" \
        '._meta += $sut | ._meta.total_errors = $total_errors | ._meta.canonical = $canonical | ._meta.smoke = $smoke' \
        "$save_file" > "${save_file}.tmp" && mv "${save_file}.tmp" "$save_file"
    if ! $canonical; then
        local why="${total_errors} total error(s) across scenarios"
        $SMOKE && why="--smoke run"
        $unverified_tardigrade && why="Tardigrade source identity not verified (pass --tardigrade-git-sha)"
        $missing_sut_metadata && why="required SUT metadata (sut_worker_threads) is missing"
        echo "note: ${save_file} marked _meta.canonical=false (${why})" >&2
    fi
}

require_verified_source

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
    verify_idle "before starting ${server}"

    render_and_start_server "$server" "$port"

    echo "-- verifying reachable from this machine over the network --"
    if ! curl -sf -o /dev/null -m 5 "http://${GUEST_IP}:${port}/health"; then
        echo "FATAL: ${server} not reachable at ${GUEST_IP}:${port} from this machine" >&2
        stop_server "$server"
        exit 1
    fi
    tiny_ok=true
    curl -sf -o /dev/null -m 5 "http://${GUEST_IP}:${port}/tiny.txt" || tiny_ok=false

    sut_meta="$(capture_sut_meta "$server" "$port")"

    save_file="${OUT_DIR}/${server}.json"
    echo "-- running benchmarks/run.sh from this machine against ${GUEST_IP}:${port} --"
    bash "${BENCH_DIR}/run.sh" \
        --host "$GUEST_IP" --port "$port" \
        --scenarios "$SCENARIOS" \
        --duration "$DURATION" --connections "$CONNECTIONS" --threads "$THREADS" \
        --static-path "/tiny.txt" --proxy-path "/proxy/health" --keepalive-path "/tiny.txt" \
        --driver "macbook-5gbe-crossmachine" --config-label "$server" \
        --save "$save_file" || echo "warning: benchmarks/run.sh reported a non-zero exit for ${server}" >&2
    finalize_result_file "$save_file" "$sut_meta" "$server"
    RESULT_FILES+=("$save_file")
    if ! $tiny_ok; then
        echo "note: ${server} /tiny.txt was not reachable before this pass (see ${save_file} for what actually ran)" >&2
    fi

    stop_server "$server"
    echo "-- guest state after stop --"
    verify_idle "after stopping ${server}"
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
    verify_idle "before starting tardigrade-http3"

    # shellcheck disable=SC2016 # intentional: this runs on the guest, not here
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

    h3_sut_meta="$(capture_sut_meta "tardigrade-http3" "$h3_port")"

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
    finalize_result_file "$h3_save_file" "$h3_sut_meta" "tardigrade-http3"
    RESULT_FILES+=("$h3_save_file")

    stop_server "tardigrade-http3"
    echo "-- guest state after stop --"
    verify_idle "after stopping tardigrade-http3"
fi

# shellcheck disable=SC2016 # intentional: this runs on the guest, not here
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

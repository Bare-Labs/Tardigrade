#!/usr/bin/env bash
# Permanent regression coverage for #708/#714: the client-RTT-sensitive small
# HTTP/1 streaming reverse-proxy case.
#
# #708 found that Tardigrade's streaming proxy path (`proxy_streaming_mode
# response`) collapsed ~8x under real client-facing network RTT because it
# forced downstream `Connection: close` and wrote response output in many
# small fragmented syscalls. #710/#711 fixed the downstream keep-alive and
# write-coalescing defects. This script reproduces the original failure
# shape on demand so a future regression in either fix is caught.
#
# METHODOLOGY (corrected 2026-08-30, see #714 evidence-correction thread):
# the original version of this script applied `tc netem` directly to the
# loopback interface (`lo`) while both Tardigrade AND the origin fixture ran
# on loopback. That does NOT isolate client-facing RTT: `lo` carries both
# client<->Tardigrade traffic and Tardigrade<->origin traffic, so the
# injected delay impaired both legs simultaneously and the sweep's claim to
# measure only client-facing sensitivity was never actually true.
#
# This version instead builds an isolated client network namespace + veth
# topology:
#
#   [rtt_client netns]                    [root/server namespace]
#     wrk  --veth-cli--veth-srv-->  Tardigrade  --127.0.0.1/lo-->  origin
#          (10.250.201.2)  (10.250.201.1)
#
# `tc netem` is applied ONLY to `veth-srv` (the server-side leg of the veth
# pair carrying client<->Tardigrade traffic). Tardigrade<->origin traffic
# uses the loopback interface and never touches the impaired veth link. The
# script measures and records actual RTT via `ping` on both legs at every
# delay level to prove this directly rather than assume it from the tc
# command alone (see the "RTT verification" section of REPORT.md).
#
# The one-way netem delay is applied only on the server->client egress leg
# of the veth pair, so a configured `delay Nms` produces a measured
# client-facing round-trip of approximately N ms (not 2N) -- this is
# documented explicitly in REPORT.md rather than assumed.
#
# Linux-only (tc netem, network namespaces) and manual/scheduled by design
# (see the repo's non-goal: this must not gate every PR on privileged
# tc/dedicated hardware/CAP_NET_ADMIN). Run it by hand or from a
# workflow_dispatch/scheduled job, as root or with CAP_NET_ADMIN.
#
# Usage:
#   sudo benchmarks/competitive/rtt-streaming-regression.sh \
#       --delays 0,1,2,5 --duration 10 --connections 32 --threads 4 --reps 3
#
# Options:
#   --delays LIST       Comma-separated added client-RTT values in ms (default: 0,1,2,5)
#   --duration SECONDS  wrk duration per row (default: 10)
#   --connections N     wrk -c (default: 32)
#   --threads N         wrk -t (default: 4)
#   --reps N            Repetitions per (delay, scenario) cell (default: 3)
#   --upstream-workers N  Prefork workers for the origin fixture (default: 4)
#   --tardigrade-bin PATH  Pre-built binary (default: build ReleaseFast via zig)
#   --out-dir DIR        Output directory (default: benchmarks/competitive/results/<ts>-rtt-streaming-regression)
#   --smoke              Minimal one-delay, one-rep run for CI sanity checking
#   --help
#
# Scenarios run at every delay point:
#   normal      - streaming response, ordinary client, keep-alive eligible (the
#                 exact #708 failing case: proxy_streaming_mode=response)
#   close       - same route, explicit `Connection: close` (churn control,
#                 proves the normal row is actually reusing connections when
#                 compared against it)
#   buffered    - same origin route, proxy_streaming_mode=off (buffered
#                 control, must be flat regardless of RTT)
#   static      - tiny in-process static response (host/network sanity control)
#   large       - streaming response, 1 MiB upstream body (regression check
#                 for #711's write coalescing under RTT)
#   slow        - streaming response, upstream `/slow?ms=200` (regression
#                 check for correctness when the upstream is slow; #712/#713
#                 were closed not planned, so this does not assert an
#                 event-driven claim, only that nothing regresses)
#
# Each row captures: req/s, p50/p95/p99/p999, client/socket errors,
# tardigrade_accepts_total/tardigrade_requests_total churn (downstream
# connection reuse proof), upstream new/reused connection counts,
# tardigrade_proxy_streaming_requests_total/fallback_total deltas (proof the
# intended streaming path executed), tardigrade_worker_active_jobs/
# worker_queued_jobs samples taken *during* the load (not just before/after),
# worker_queue_wait_us histogram delta, and Tardigrade process CPU/RSS/fd
# deltas.
#
# Output: one JSON file per (delay, scenario, rep) compatible with the
# WRK_SUMMARY schema emitted by benchmarks/wrk-summary.lua, plus a
# REPORT.md summary with topology/RTT-verification evidence and per-cell
# mean/median/stdev aggregates across repetitions.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BENCH_DIR="${REPO_ROOT}/benchmarks"

DELAYS="0,1,2,5"
DURATION=10
CONNECTIONS=32
THREADS=4
REPS=3
UPSTREAM_WORKERS=4
TARDIGRADE_BIN=""
OUT_DIR=""
SMOKE=false

usage() { sed -n '2,79p' "$0" | sed 's/^# \{0,1\}//'; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --delays) DELAYS="$2"; shift 2 ;;
        --duration) DURATION="$2"; shift 2 ;;
        --connections) CONNECTIONS="$2"; shift 2 ;;
        --threads) THREADS="$2"; shift 2 ;;
        --reps) REPS="$2"; shift 2 ;;
        --upstream-workers) UPSTREAM_WORKERS="$2"; shift 2 ;;
        --tardigrade-bin) TARDIGRADE_BIN="$2"; shift 2 ;;
        --out-dir) OUT_DIR="$2"; shift 2 ;;
        --smoke) SMOKE=true; shift ;;
        --help) usage; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; usage >&2; exit 1 ;;
    esac
done

if $SMOKE; then
    DELAYS="0,1"
    DURATION=2
    REPS=1
fi

if [[ "$(uname -s 2>/dev/null || true)" != "Linux" ]]; then
    echo "rtt-streaming-regression.sh is Linux-only (tc netem, network namespaces); this host is $(uname -s 2>/dev/null || echo unknown)." >&2
    echo "SCENARIO NOT EXECUTED." >&2
    exit 1
fi

for tool in wrk curl jq python3 tc ip ping; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Required tool '${tool}' not found. SCENARIO NOT EXECUTED." >&2
        exit 1
    fi
done

if [[ $EUID -ne 0 ]]; then
    echo "Root (or an equivalent CAP_NET_ADMIN/netns-capable environment) is required to create network namespaces and apply tc netem. SCENARIO NOT EXECUTED." >&2
    exit 1
fi

OUT_DIR="${OUT_DIR:-${BENCH_DIR}/competitive/results/$(date -u +%Y%m%d-%H%M%S)-rtt-streaming-regression}"
mkdir -p "$OUT_DIR"

UPSTREAM_PORT=28079
LISTEN_PORT=28180
CONF_FILE="${OUT_DIR}/tardi.conf"
PID_FILE="${OUT_DIR}/tardi.pid"
TARDI_LOG="${OUT_DIR}/tardi.log"
UPSTREAM_LOG="${OUT_DIR}/upstream.log"

TARDI_PID=""
UPSTREAM_PID=""

# ── Isolated client-namespace/veth topology ──────────────────────────────
CLIENT_NETNS="tardirtt_client"
SRV_VETH="tardirtt-srv"
CLI_VETH="tardirtt-cli"
SRV_VETH_ADDR="10.250.201.1"
CLI_VETH_ADDR="10.250.201.2"
VETH_PREFIX_LEN="30"
TOPOLOGY_UP=false
NETEM_APPLIED=false

teardown_topology() {
    if $NETEM_APPLIED; then
        tc qdisc del dev "$SRV_VETH" root netem >/dev/null 2>&1 || true
        NETEM_APPLIED=false
    fi
    if $TOPOLOGY_UP; then
        ip link del "$SRV_VETH" >/dev/null 2>&1 || true
        ip netns del "$CLIENT_NETNS" >/dev/null 2>&1 || true
        TOPOLOGY_UP=false
    fi
}

cleanup() {
    local status=$?
    [[ -n "$TARDI_PID" ]] && kill "$TARDI_PID" 2>/dev/null || true
    [[ -n "$UPSTREAM_PID" ]] && kill "$UPSTREAM_PID" 2>/dev/null || true
    wait "$TARDI_PID" 2>/dev/null || true
    wait "$UPSTREAM_PID" 2>/dev/null || true
    teardown_topology
    exit "$status"
}
trap cleanup EXIT INT TERM

# Idempotent: clear any leftovers from a previous crashed run before we start.
ip netns del "$CLIENT_NETNS" >/dev/null 2>&1 || true
ip link del "$SRV_VETH" >/dev/null 2>&1 || true

echo "==> Building isolated client-namespace/veth topology"
ip netns add "$CLIENT_NETNS"
ip link add "$SRV_VETH" type veth peer name "$CLI_VETH" netns "$CLIENT_NETNS"
ip addr add "${SRV_VETH_ADDR}/${VETH_PREFIX_LEN}" dev "$SRV_VETH"
ip link set "$SRV_VETH" up
ip netns exec "$CLIENT_NETNS" ip addr add "${CLI_VETH_ADDR}/${VETH_PREFIX_LEN}" dev "$CLI_VETH"
ip netns exec "$CLIENT_NETNS" ip link set "$CLI_VETH" up
ip netns exec "$CLIENT_NETNS" ip link set lo up
ip netns exec "$CLIENT_NETNS" ip route replace default via "$SRV_VETH_ADDR"
TOPOLOGY_UP=true

TOPOLOGY_DUMP="${OUT_DIR}/topology.txt"
{
    echo "# Isolated client-RTT topology (recorded $(date -u +%Y-%m-%dT%H:%M:%SZ))"
    echo
    echo "## Namespaces"
    ip netns list
    echo
    echo "## Server-side veth (${SRV_VETH}, root/server namespace)"
    ip addr show "$SRV_VETH"
    echo
    echo "## Client-side veth (${CLI_VETH}, ${CLIENT_NETNS} namespace)"
    ip netns exec "$CLIENT_NETNS" ip addr show "$CLI_VETH"
    echo
    echo "## Client namespace routes"
    ip netns exec "$CLIENT_NETNS" ip route show
    echo
    echo "## Root namespace addresses (Tardigrade + origin live here)"
    ip -4 addr show
    echo
    echo "Tardigrade listen address: 0.0.0.0:${LISTEN_PORT} (reachable via ${SRV_VETH_ADDR} from the client namespace, and via 127.0.0.1 from the root namespace)"
    echo "Origin fixture address: 127.0.0.1:${UPSTREAM_PORT} (loopback only -- never traverses ${SRV_VETH}/${CLI_VETH})"
} >"$TOPOLOGY_DUMP"
echo "==> Topology recorded to ${TOPOLOGY_DUMP}"

measure_rtt_ms() {
    # Parses `ping -q -c N <target>` rtt avg from the summary line.
    local target="$1" count="${2:-20}" out
    out=$(ping -c "$count" -q "$target" 2>/dev/null | grep -Eo 'rtt [a-z/]+ = [0-9./]+' | awk -F'= ' '{print $2}' | awk -F/ '{print $2}')
    echo "${out:-NaN}"
}
measure_rtt_ms_netns() {
    local ns="$1" target="$2" count="${3:-20}" out
    out=$(ip netns exec "$ns" ping -c "$count" -q "$target" 2>/dev/null | grep -Eo 'rtt [a-z/]+ = [0-9./]+' | awk -F'= ' '{print $2}' | awk -F/ '{print $2}')
    echo "${out:-NaN}"
}

if [[ -z "$TARDIGRADE_BIN" ]]; then
    echo "==> Building tardi (ReleaseFast) from $(cd "$REPO_ROOT" && git rev-parse HEAD)"
    (cd "$REPO_ROOT" && zig build -Doptimize=ReleaseFast) >>"${OUT_DIR}/build.log" 2>&1
    TARDIGRADE_BIN="${REPO_ROOT}/zig-out/bin/tardi"
fi
[[ -x "$TARDIGRADE_BIN" ]] || { echo "Tardigrade binary not found/executable: ${TARDIGRADE_BIN}" >&2; exit 1; }

GIT_SHA="$(cd "$REPO_ROOT" && git rev-parse HEAD)"
BIN_SHA256="$(shasum -a 256 "$TARDIGRADE_BIN" 2>/dev/null | awk '{print $1}' || sha256sum "$TARDIGRADE_BIN" | awk '{print $1}')"

echo "==> Starting origin fixture (prefork, ${UPSTREAM_WORKERS} workers) on 127.0.0.1:${UPSTREAM_PORT} (loopback-only, never crosses the client veth)"
python3 "${BENCH_DIR}/fixtures/upstream_server.py" --port "$UPSTREAM_PORT" --workers "$UPSTREAM_WORKERS" >"$UPSTREAM_LOG" 2>&1 &
UPSTREAM_PID=$!

cat >"$CONF_FILE" <<EOF
pid ${PID_FILE};
listen 0.0.0.0:${LISTEN_PORT};
metrics_path /status/metrics;
proxy_streaming_mode response;

location = /health {
    return 200 ok;
}

location = /proxy/health {
    proxy_pass http://127.0.0.1:${UPSTREAM_PORT}/health;
}

location = /proxy/buffered/health {
    proxy_pass http://127.0.0.1:${UPSTREAM_PORT}/health;
    proxy_streaming off;
}

location = /proxy/payload-1m.bin {
    proxy_pass http://127.0.0.1:${UPSTREAM_PORT}/payload-1m.bin;
}

location = /proxy/slow {
    proxy_pass http://127.0.0.1:${UPSTREAM_PORT}/slow;
}
EOF

wait_for_http() {
    local url="$1" attempts=60 i
    for ((i = 0; i < attempts; i += 1)); do
        curl -fsS "$url" >/dev/null 2>&1 && return 0
        sleep 0.2
    done
    echo "Timed out waiting for ${url}" >&2
    return 1
}

wait_for_http "http://127.0.0.1:${UPSTREAM_PORT}/health"

# Explicit env var, not an inherited/undocumented default: the config file's
# top-level `proxy_streaming_mode response;` directive is ALSO parsed (via
# src/http/config_file.zig's generic directive->TARDIGRADE_* override
# mechanism) into the same effective setting, but this script sets the
# environment variable directly so the intended mode does not depend on that
# indirection being understood/trusted by a future reader.
export TARDIGRADE_PROXY_STREAMING_MODE=response
export TARDIGRADE_RATE_LIMIT_RPS=0
echo "==> Starting tardi (${GIT_SHA}, sha256 ${BIN_SHA256}) on 0.0.0.0:${LISTEN_PORT}"
echo "    TARDIGRADE_PROXY_STREAMING_MODE=${TARDIGRADE_PROXY_STREAMING_MODE} (explicit env var)"
echo "    TARDIGRADE_RATE_LIMIT_RPS=${TARDIGRADE_RATE_LIMIT_RPS}"
"$TARDIGRADE_BIN" -c "$CONF_FILE" >"$TARDI_LOG" 2>&1 &
TARDI_PID=$!
wait_for_http "http://127.0.0.1:${LISTEN_PORT}/health"
wait_for_http "http://${SRV_VETH_ADDR}:${LISTEN_PORT}/health"
if ! ip netns exec "$CLIENT_NETNS" curl -fsS "http://${SRV_VETH_ADDR}:${LISTEN_PORT}/health" >/dev/null 2>&1; then
    echo "Client namespace cannot reach Tardigrade over the veth topology. SCENARIO NOT EXECUTED." >&2
    exit 1
fi
echo "==> Verified: Tardigrade reachable from ${CLIENT_NETNS} via ${SRV_VETH_ADDR}:${LISTEN_PORT}"

ENV_DUMP="${OUT_DIR}/environment.txt"
{
    echo "commit: ${GIT_SHA}"
    echo "binary_sha256: ${BIN_SHA256}"
    echo "build_command: zig build -Doptimize=ReleaseFast (or --tardigrade-bin override)"
    echo "launch_command: TARDIGRADE_PROXY_STREAMING_MODE=response TARDIGRADE_RATE_LIMIT_RPS=0 ${TARDIGRADE_BIN} -c ${CONF_FILE}"
    echo "rendered_config:"
    sed 's/^/  /' "$CONF_FILE"
    echo "kernel: $(uname -a)"
    echo "cpu: $(grep -m1 'model name' /proc/cpuinfo 2>/dev/null || echo unknown), $(nproc) cores"
} >"$ENV_DUMP"

metrics_snapshot() {
    curl -fsS "http://127.0.0.1:${LISTEN_PORT}/status/metrics" 2>/dev/null || true
}

metric_sum() {
    local name="$1" text="$2"
    awk -v name="$name" '
        $0 ~ "^" name "(\\{|[ ]|$)" {
            v = $NF
            if (v ~ /^[0-9.eE+-]+$/) sum += v
        }
        END { printf "%.0f", sum + 0 }
    ' <<<"$text"
}

metric_gauge() {
    # single-series gauge (no labels), returns 0 if absent
    local name="$1" text="$2"
    awk -v name="$name" '$1 == name { print $2; found=1 } END { if (!found) print 0 }' <<<"$text"
}

proc_cpu_ticks() {
    local pid="$1"
    awk '{print $14+$15}' "/proc/${pid}/stat" 2>/dev/null || echo 0
}
proc_rss_kb() {
    local pid="$1"
    awk '/VmRSS/{print $2}' "/proc/${pid}/status" 2>/dev/null || echo 0
}
proc_fd_count() {
    local pid="$1"
    ls "/proc/${pid}/fd" 2>/dev/null | wc -l | tr -d ' '
}

# Samples tardigrade_worker_active_jobs / worker_queued_jobs at ~10Hz for the
# duration of the wrk run this wraps. Writes newline-delimited "active queued"
# pairs to $1 until killed.
worker_sampler() {
    local out_file="$1"
    : >"$out_file"
    while true; do
        local snap active queued
        snap="$(metrics_snapshot)"
        active="$(metric_gauge tardigrade_worker_active_jobs "$snap")"
        queued="$(metric_gauge tardigrade_worker_queued_jobs "$snap")"
        echo "${active} ${queued}" >>"$out_file"
        sleep 0.1
    done
}

run_row() {
    local scenario="$1" delay="$2" rep="$3" path="$4"
    local out_json="${OUT_DIR}/delay${delay}ms-${scenario}-rep${rep}.json"
    local before after raw summary_json
    before="$(metrics_snapshot)"
    local extra_hdr=()
    [[ "$scenario" == "close" ]] && extra_hdr=(-H "Connection: close")

    local cpu_before rss_before fd_before
    cpu_before="$(proc_cpu_ticks "$TARDI_PID")"
    rss_before="$(proc_rss_kb "$TARDI_PID")"
    fd_before="$(proc_fd_count "$TARDI_PID")"

    local sampler_file="${OUT_DIR}/.worker-samples-${scenario}-${delay}-${rep}.txt"
    worker_sampler "$sampler_file" &
    local sampler_pid=$!

    raw=$(ip netns exec "$CLIENT_NETNS" wrk --latency -s "${BENCH_DIR}/wrk-summary.lua" \
        -t"${THREADS}" -c"${CONNECTIONS}" -d"${DURATION}s" \
        "${extra_hdr[@]}" \
        "http://${SRV_VETH_ADDR}:${LISTEN_PORT}${path}" 2>&1) || true

    kill "$sampler_pid" 2>/dev/null || true
    wait "$sampler_pid" 2>/dev/null || true

    after="$(metrics_snapshot)"
    local cpu_after rss_after fd_after
    cpu_after="$(proc_cpu_ticks "$TARDI_PID")"
    rss_after="$(proc_rss_kb "$TARDI_PID")"
    fd_after="$(proc_fd_count "$TARDI_PID")"

    summary_json=$(printf '%s\n' "$raw" | sed -n 's/^WRK_SUMMARY //p' | tail -1)
    if [[ -z "$summary_json" ]]; then
        echo "wrk did not emit a summary for ${scenario} @ ${delay}ms rep ${rep}:" >&2
        echo "$raw" >&2
        return 1
    fi

    local accepts_before accepts_after requests_before requests_after
    local up_new_before up_new_after up_reused_before up_reused_after
    local stream_req_before stream_req_after stream_fallback_before stream_fallback_after
    local qwait_count_before qwait_count_after qwait_sum_before qwait_sum_after
    accepts_before="$(metric_sum tardigrade_accepts_total "$before")"
    accepts_after="$(metric_sum tardigrade_accepts_total "$after")"
    requests_before="$(metric_sum tardigrade_requests_total "$before")"
    requests_after="$(metric_sum tardigrade_requests_total "$after")"
    up_new_before="$(metric_sum tardigrade_upstream_pool_connections_new_total "$before")"
    up_new_after="$(metric_sum tardigrade_upstream_pool_connections_new_total "$after")"
    up_reused_before="$(metric_sum tardigrade_upstream_pool_connections_reused_total "$before")"
    up_reused_after="$(metric_sum tardigrade_upstream_pool_connections_reused_total "$after")"
    stream_req_before="$(metric_sum tardigrade_proxy_streaming_requests_total "$before")"
    stream_req_after="$(metric_sum tardigrade_proxy_streaming_requests_total "$after")"
    stream_fallback_before="$(metric_sum tardigrade_proxy_streaming_fallback_total "$before")"
    stream_fallback_after="$(metric_sum tardigrade_proxy_streaming_fallback_total "$after")"
    qwait_count_before="$(metric_sum tardigrade_worker_queue_wait_us_count "$before")"
    qwait_count_after="$(metric_sum tardigrade_worker_queue_wait_us_count "$after")"
    qwait_sum_before="$(metric_sum tardigrade_worker_queue_wait_us_sum "$before")"
    qwait_sum_after="$(metric_sum tardigrade_worker_queue_wait_us_sum "$after")"

    local worker_active_max=0 worker_active_mean=0 worker_queued_max=0 worker_queued_mean=0 worker_samples=0
    if [[ -s "$sampler_file" ]]; then
        read -r worker_active_max worker_active_mean worker_queued_max worker_queued_mean worker_samples < <(
            awk '{
                if ($1+0>amax) amax=$1+0; asum+=$1+0;
                if ($2+0>qmax) qmax=$2+0; qsum+=$2+0;
                n++
            } END {
                if (n==0) { print 0,0,0,0,0; exit }
                printf "%d %.3f %d %.3f %d\n", amax, asum/n, qmax, qsum/n, n
            }' "$sampler_file"
        )
    fi
    rm -f "$sampler_file"

    local qwait_count_delta=$((qwait_count_after - qwait_count_before))
    local qwait_sum_delta=$((qwait_sum_after - qwait_sum_before))
    local qwait_avg_us="null"
    if [[ "$qwait_count_delta" -gt 0 ]]; then
        qwait_avg_us=$(awk -v s="$qwait_sum_delta" -v c="$qwait_count_delta" 'BEGIN{printf "%.1f", s/c}')
    fi

    jq -n \
        --arg scenario "$scenario" \
        --argjson delay_ms "$delay" \
        --argjson rep "$rep" \
        --argjson summary "$summary_json" \
        --argjson accepts_delta "$((accepts_after - accepts_before))" \
        --argjson requests_delta "$((requests_after - requests_before))" \
        --argjson upstream_new_delta "$((up_new_after - up_new_before))" \
        --argjson upstream_reused_delta "$((up_reused_after - up_reused_before))" \
        --argjson streaming_requests_delta "$((stream_req_after - stream_req_before))" \
        --argjson streaming_fallback_delta "$((stream_fallback_after - stream_fallback_before))" \
        --argjson worker_active_max "$worker_active_max" \
        --argjson worker_active_mean "$worker_active_mean" \
        --argjson worker_queued_max "$worker_queued_max" \
        --argjson worker_queued_mean "$worker_queued_mean" \
        --argjson worker_samples "$worker_samples" \
        --argjson worker_queue_wait_avg_us "$qwait_avg_us" \
        --argjson cpu_ticks_delta "$((cpu_after - cpu_before))" \
        --argjson rss_kb_before "$rss_before" \
        --argjson rss_kb_after "$rss_after" \
        --argjson fd_before "$fd_before" \
        --argjson fd_after "$fd_after" \
        '{
            scenario: $scenario,
            delay_ms: $delay_ms,
            rep: $rep,
            rps: $summary.rps,
            p50_ms: $summary.p50_ms,
            p95_ms: $summary.p95_ms,
            p99_ms: $summary.p99_ms,
            p999_ms: $summary.p999_ms,
            errors: $summary.errors,
            throughput_mbps: $summary.throughput_mbps,
            downstream_accepts_delta: $accepts_delta,
            downstream_requests_delta: $requests_delta,
            downstream_churn_pct: (if $requests_delta > 0 then ($accepts_delta / $requests_delta * 100) else null end),
            upstream_connections_new_delta: $upstream_new_delta,
            upstream_connections_reused_delta: $upstream_reused_delta,
            upstream_reuse_pct: (if ($upstream_new_delta + $upstream_reused_delta) > 0 then ($upstream_reused_delta / ($upstream_new_delta + $upstream_reused_delta) * 100) else null end),
            streaming_requests_delta: $streaming_requests_delta,
            streaming_fallback_delta: $streaming_fallback_delta,
            worker_active_jobs_max: $worker_active_max,
            worker_active_jobs_mean: $worker_active_mean,
            worker_queued_jobs_max: $worker_queued_max,
            worker_queued_jobs_mean: $worker_queued_mean,
            worker_metric_samples: $worker_samples,
            worker_queue_wait_avg_us: $worker_queue_wait_avg_us,
            tardi_cpu_ticks_delta: $cpu_ticks_delta,
            tardi_rss_kb_before: $rss_kb_before,
            tardi_rss_kb_after: $rss_kb_after,
            tardi_fd_before: $fd_before,
            tardi_fd_after: $fd_after
        }' >"$out_json"
    echo "    ${scenario} @ ${delay}ms rep ${rep}: $(jq -r '"\(.rps) req/s, p99=\(.p99_ms)ms, errors=\(.errors), churn=\(.downstream_churn_pct)%, streaming_reqs=\(.streaming_requests_delta), worker_active_max=\(.worker_active_jobs_max), worker_queued_max=\(.worker_queued_jobs_max)"' "$out_json")"
}

IFS=',' read -r -a DELAY_LIST <<<"$DELAYS"

RTT_VERIFICATION="${OUT_DIR}/rtt-verification.json"
echo "[]" >"$RTT_VERIFICATION"

for delay in "${DELAY_LIST[@]}"; do
    echo "==> Delay: ${delay}ms (configured one-way netem delay on ${SRV_VETH} egress, server->client leg only)"
    if [[ "$delay" != "0" ]]; then
        if ! tc qdisc add dev "$SRV_VETH" root netem delay "${delay}ms" 2>"${OUT_DIR}/tc-err-${delay}.log"; then
            echo "Failed to apply tc netem delay=${delay}ms (need root/CAP_NET_ADMIN):" >&2
            cat "${OUT_DIR}/tc-err-${delay}.log" >&2
            echo "SCENARIO NOT EXECUTED for delay=${delay}ms." >&2
            continue
        fi
        NETEM_APPLIED=true
    fi

    echo "    tc qdisc show dev ${SRV_VETH}: $(tc qdisc show dev "$SRV_VETH" | tr '\n' ' ')"

    client_rtt_ms="$(measure_rtt_ms_netns "$CLIENT_NETNS" "$SRV_VETH_ADDR" 20)"
    origin_rtt_ms="$(measure_rtt_ms 127.0.0.1 10)"
    origin_curl_s=$(curl -o /dev/null -s -w '%{time_total}' "http://127.0.0.1:${UPSTREAM_PORT}/health" 2>/dev/null || echo "NaN")
    proxy_curl_s=$(ip netns exec "$CLIENT_NETNS" curl -o /dev/null -s -w '%{time_total}' "http://${SRV_VETH_ADDR}:${LISTEN_PORT}/proxy/health" 2>/dev/null || echo "NaN")
    echo "    measured client-facing RTT (ping, n=20): ${client_rtt_ms}ms | measured origin/loopback RTT (ping, n=10): ${origin_rtt_ms}ms | origin direct curl: ${origin_curl_s}s | proxy curl: ${proxy_curl_s}s"

    jq --argjson delay_ms "$delay" \
       --arg client_rtt_ms "$client_rtt_ms" \
       --arg origin_rtt_ms "$origin_rtt_ms" \
       --arg origin_curl_s "$origin_curl_s" \
       --arg proxy_curl_s "$proxy_curl_s" \
       '. + [{
           configured_netem_delay_ms: $delay_ms,
           measured_client_facing_rtt_ms: ($client_rtt_ms | tonumber? // null),
           measured_origin_loopback_rtt_ms: ($origin_rtt_ms | tonumber? // null),
           origin_direct_curl_time_s: ($origin_curl_s | tonumber? // null),
           proxy_curl_time_s: ($proxy_curl_s | tonumber? // null)
       }]' "$RTT_VERIFICATION" >"${RTT_VERIFICATION}.tmp" && mv "${RTT_VERIFICATION}.tmp" "$RTT_VERIFICATION"

    for rep in $(seq 1 "$REPS"); do
        run_row normal   "$delay" "$rep" "/proxy/health"
        run_row close    "$delay" "$rep" "/proxy/health"
        run_row buffered "$delay" "$rep" "/proxy/buffered/health"
        run_row static   "$delay" "$rep" "/health"
        run_row large    "$delay" "$rep" "/proxy/payload-1m.bin"
        run_row slow     "$delay" "$rep" "/proxy/slow?ms=200"
    done

    if $NETEM_APPLIED; then
        tc qdisc del dev "$SRV_VETH" root netem >/dev/null 2>&1 || echo "WARNING: failed to remove netem qdisc from ${SRV_VETH} after delay=${delay}ms" >&2
        NETEM_APPLIED=false
    fi
done

# ── Aggregate REPORT.md ──────────────────────────────────────────────────
REPORT="${OUT_DIR}/REPORT.md"
{
    echo "# RTT-sensitive streaming proxy regression report"
    echo
    echo "Generated $(date -u +%Y-%m-%dT%H:%M:%SZ) by \`benchmarks/competitive/rtt-streaming-regression.sh\` (corrected client-namespace/veth methodology)."
    echo
    echo "- Tardigrade commit under test: \`${GIT_SHA}\`"
    echo "- binary sha256: \`${BIN_SHA256}\`"
    echo "- \`TARDIGRADE_PROXY_STREAMING_MODE=response\` set explicitly as a launch environment variable (see environment.txt)"
    echo "- wrk: \`-t${THREADS} -c${CONNECTIONS} -d${DURATION}s\`, ${REPS} rep(s) per cell, run from inside the isolated \`${CLIENT_NETNS}\` network namespace"
    echo
    echo "## Topology"
    echo
    echo '```'
    cat "$TOPOLOGY_DUMP"
    echo '```'
    echo
    echo "## RTT verification (configured vs. measured)"
    echo
    echo "One-way \`tc netem delay\` is applied only to ${SRV_VETH} (server->client egress leg)."
    echo "Origin traffic (Tardigrade -> 127.0.0.1:${UPSTREAM_PORT}) never traverses ${SRV_VETH}/${CLI_VETH}."
    echo
    echo "| configured delay (ms) | measured client-facing RTT (ms, ping avg n=20) | measured origin/loopback RTT (ms, ping avg n=10) | origin direct curl (s) | proxy curl (s) |"
    echo "|---:|---:|---:|---:|---:|"
    jq -r '.[] | "| \(.configured_netem_delay_ms) | \(.measured_client_facing_rtt_ms) | \(.measured_origin_loopback_rtt_ms) | \(.origin_direct_curl_time_s) | \(.proxy_curl_time_s) |"' "$RTT_VERIFICATION"
    echo
    echo "If origin RTT is held constant across all configured delays while client-facing RTT scales with the configured delay, client-facing RTT is isolated from the origin path as intended."
    echo
    echo "## Aggregate results (mean / median / stdev across ${REPS} rep(s))"
    echo
    echo "| delay (ms) | scenario | req/s mean | req/s median | req/s stdev | p99 mean (ms) | errors (sum) | downstream churn % (mean) | upstream reuse % (mean) | streaming reqs (sum) | worker active max | worker queued max |"
    echo "|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"
    for delay in "${DELAY_LIST[@]}"; do
        for scenario in normal close buffered static large slow; do
            files=("${OUT_DIR}/delay${delay}ms-${scenario}-rep"*.json)
            [[ -e "${files[0]}" ]] || continue
            jq -s '{
                rps_mean: (map(.rps) | add / length),
                rps_median: (map(.rps) | sort | .[length/2 | floor]),
                rps_stdev: (map(.rps) as $xs | ($xs | add / length) as $m | (($xs | map((. - $m) * (. - $m)) | add) / ($xs | length)) | sqrt),
                p99_mean: (map(.p99_ms) | add / length),
                errors_sum: (map(.errors) | add),
                churn_mean: (map(.downstream_churn_pct // 0) | add / length),
                reuse_mean: (map(.upstream_reuse_pct // 0) | add / length),
                streaming_reqs_sum: (map(.streaming_requests_delta) | add),
                worker_active_max: (map(.worker_active_jobs_max) | max),
                worker_queued_max: (map(.worker_queued_jobs_max) | max)
            }' "${files[@]}" | jq -r --arg d "$delay" --arg s "$scenario" \
                '"| \($d) | \($s) | \(.rps_mean|round) | \(.rps_median|round) | \((.rps_stdev*10|round)/10) | \((.p99_mean*10|round)/10) | \(.errors_sum) | \((.churn_mean*10|round)/10) | \((.reuse_mean*10|round)/10) | \(.streaming_reqs_sum) | \(.worker_active_max) | \(.worker_queued_max) |"'
        done
    done
    echo
    echo "## Notes"
    echo
    echo "- \`streaming reqs (sum)\` uses \`tardigrade_proxy_streaming_requests_total\`, proving the streaming code path (not just buffered) executed for the \`normal\`/\`close\`/\`large\`/\`slow\` rows. \`buffered\` and \`static\` rows are expected to show 0 here."
    echo "- \`worker active/queued max\` uses \`tardigrade_worker_active_jobs\`/\`tardigrade_worker_queued_jobs\`, sampled at ~10Hz throughout each row's wrk run (not a single before/after snapshot)."
    echo "- Per-repetition raw JSON files (all ${REPS} reps, not just the best) are preserved alongside this report."
} >"$REPORT"

echo "==> Report written to ${REPORT}"

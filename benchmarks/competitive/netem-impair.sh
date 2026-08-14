#!/usr/bin/env bash
# Controlled network impairment for HTTP/3/QUIC loss/reordering evidence (#256-G).
#
# Wraps a benchmark command with a `tc netem` qdisc on a chosen interface
# (loopback by default, since the competitive harness runs client and server
# on 127.0.0.1), records the exact impairment applied, and always removes it
# on exit — including on failure, Ctrl-C, or if the wrapped command itself
# fails.
#
# Linux-only (tc netem is a Linux traffic-control feature) and manual: this
# is never invoked from benchmarks/run.sh, benchmarks/competitive/run.sh, or
# any GitHub Actions workflow. Run it by hand, or from a dedicated scheduled
# job, when you specifically want loss/reordering evidence.
#
# Requires root or CAP_NET_ADMIN to modify the qdisc. If that privilege is
# missing, this script reports the scenario as NOT EXECUTED and exits
# non-zero — it never falls back to running the wrapped command unimpaired
# and calling that an impairment result.
#
# Usage:
#   benchmarks/competitive/netem-impair.sh \
#     --loss 1 --reorder 25 --delay 20 --interface lo \
#     --evidence-file /tmp/netem-evidence.json \
#     -- benchmarks/competitive/run.sh --servers tardigrade --smoke
#
# Options:
#   --interface IFACE   Interface to impair (default: lo)
#   --loss PERCENT       Packet loss percentage, e.g. 1 for 1% (optional)
#   --reorder PERCENT     Packet reorder percentage (optional; requires --delay,
#                         since netem reordering is defined relative to a delay)
#   --delay MS            Base delay in milliseconds (required if --reorder is set;
#                         optional standalone)
#   --evidence-file FILE  Where to write the impairment-config JSON (default:
#                         benchmarks/competitive/results/netem-evidence-<ts>.json)
#   --help                Show this message and exit
#
# At least one of --loss/--reorder/--delay must be given.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
INTERFACE="lo"
LOSS_PERCENT=""
REORDER_PERCENT=""
DELAY_MS=""
EVIDENCE_FILE=""
APPLIED=false
TC_COMMAND=""

usage() {
    sed -n '2,33p' "$0" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --interface) INTERFACE="$2"; shift 2 ;;
        --loss) LOSS_PERCENT="$2"; shift 2 ;;
        --reorder) REORDER_PERCENT="$2"; shift 2 ;;
        --delay) DELAY_MS="$2"; shift 2 ;;
        --evidence-file) EVIDENCE_FILE="$2"; shift 2 ;;
        --help) usage; exit 0 ;;
        --) shift; break ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
    esac
done

if [[ "$(uname -s 2>/dev/null || true)" != "Linux" ]]; then
    echo "netem-impair.sh is Linux-only (tc netem); this host is $(uname -s 2>/dev/null || echo unknown)." >&2
    echo "SCENARIO NOT EXECUTED." >&2
    exit 1
fi

if [[ -z "$LOSS_PERCENT" && -z "$REORDER_PERCENT" && -z "$DELAY_MS" ]]; then
    echo "At least one of --loss, --reorder, or --delay must be given." >&2
    usage >&2
    exit 1
fi

if [[ -n "$REORDER_PERCENT" && -z "$DELAY_MS" ]]; then
    echo "--reorder requires --delay (netem defines reordering relative to a delayed stream)." >&2
    exit 1
fi

if [[ $# -eq 0 ]]; then
    echo "No command given to run under impairment (expected: ... -- <command>)." >&2
    usage >&2
    exit 1
fi

if ! command -v tc >/dev/null 2>&1; then
    echo "tc (iproute2) is not installed. SCENARIO NOT EXECUTED." >&2
    exit 1
fi

EVIDENCE_FILE="${EVIDENCE_FILE:-${REPO_ROOT}/benchmarks/competitive/results/netem-evidence-$(date -u +%Y%m%d-%H%M%S).json}"
mkdir -p "$(dirname "$EVIDENCE_FILE")"

# Build the exact `tc qdisc` netem args so the recorded command is precisely
# what ran, not a reconstruction from flags. `netem` args must appear in a
# single `qdisc add` invocation.
netem_args=()
[[ -n "$DELAY_MS" ]] && netem_args+=(delay "${DELAY_MS}ms")
[[ -n "$LOSS_PERCENT" ]] && netem_args+=(loss "${LOSS_PERCENT}%")
[[ -n "$REORDER_PERCENT" ]] && netem_args+=(reorder "${REORDER_PERCENT}%")

TC_ADD_CMD=(tc qdisc add dev "$INTERFACE" root netem "${netem_args[@]}")
TC_COMMAND="${TC_ADD_CMD[*]}"

cleanup() {
    local status=$?
    if $APPLIED; then
        echo "Removing netem qdisc from ${INTERFACE}..." >&2
        tc qdisc del dev "$INTERFACE" root netem >/dev/null 2>&1 || \
            echo "WARNING: 'tc qdisc del dev ${INTERFACE} root netem' failed — verify host networking state manually with 'tc qdisc show dev ${INTERFACE}'." >&2
        APPLIED=false
    fi
    exit "$status"
}
trap cleanup EXIT INT TERM

echo "Applying: ${TC_COMMAND}"
if ! "${TC_ADD_CMD[@]}" 2>/tmp/netem-impair-tc-err.$$; then
    echo "Failed to apply netem qdisc — this usually means missing root/CAP_NET_ADMIN," >&2
    echo "an existing qdisc already on ${INTERFACE}, or an unsupported interface." >&2
    cat /tmp/netem-impair-tc-err.$$ >&2
    rm -f /tmp/netem-impair-tc-err.$$
    echo "SCENARIO NOT EXECUTED." >&2
    exit 1
fi
rm -f /tmp/netem-impair-tc-err.$$
APPLIED=true

START_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Running under impairment: $*"
set +e
"$@"
CMD_STATUS=$?
set -e
END_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

jq -n \
    --arg interface "$INTERFACE" \
    --argjson loss_percent "${LOSS_PERCENT:-null}" \
    --argjson reorder_percent "${REORDER_PERCENT:-null}" \
    --argjson delay_ms "${DELAY_MS:-null}" \
    --arg tc_command "$TC_COMMAND" \
    --arg started_at "$START_TS" \
    --arg finished_at "$END_TS" \
    --argjson command_exit_status "$CMD_STATUS" \
    --arg command "$*" \
    '{
        impairment: {
            interface: $interface,
            loss_percent: $loss_percent,
            reorder_percent: $reorder_percent,
            delay_ms: $delay_ms,
            tc_command: $tc_command
        },
        started_at: $started_at,
        finished_at: $finished_at,
        wrapped_command: $command,
        wrapped_command_exit_status: $command_exit_status
    }' > "$EVIDENCE_FILE"

echo "Impairment evidence written to: ${EVIDENCE_FILE}"
exit "$CMD_STATUS"

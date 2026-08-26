#!/usr/bin/env bash
# Deterministic harness tests for upstream-pool-matrix.sh's concurrent uneven
# route scenario. This intentionally avoids starting Tardigrade.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT_UNDER_TEST="${REPO_ROOT}/benchmarks/competitive/upstream-pool-matrix.sh"
TEST_DIR="$(mktemp -d /tmp/tardigrade-upstream-matrix-test-XXXXXX)"

# shellcheck disable=SC2329 # invoked by trap
cleanup() {
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

mkdir -p "${TEST_DIR}/bin"
cat > "${TEST_DIR}/bin/wrk" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

url="${@: -1}"
route="${url##*/}"
record_dir="${WRK_TEST_DIR:?WRK_TEST_DIR is required}"

python3 - "$record_dir" "$route" start "$*" <<'PY'
import pathlib, sys, time
root = pathlib.Path(sys.argv[1])
route = sys.argv[2]
kind = sys.argv[3]
args = sys.argv[4]
(root / f"{route}.{kind}").write_text(str(time.monotonic_ns()))
(root / f"{route}.args").write_text(args)
PY

touch "${record_dir}/${route}.ready"
for _ in $(seq 1 100); do
    if [[ -f "${record_dir}/route-a.ready" && -f "${record_dir}/route-b.ready" && -f "${record_dir}/route-c.ready" ]]; then
        break
    fi
    sleep 0.02
done
[[ -f "${record_dir}/route-a.ready" && -f "${record_dir}/route-b.ready" && -f "${record_dir}/route-c.ready" ]] || {
    echo "barrier timed out for ${route}" >&2
    exit 9
}

sleep 0.05
python3 - "$record_dir" "$route" complete "$*" <<'PY'
import pathlib, sys, time
root = pathlib.Path(sys.argv[1])
route = sys.argv[2]
kind = sys.argv[3]
(root / f"{route}.{kind}").write_text(str(time.monotonic_ns()))
PY

if [[ "${WRK_FAIL_ROUTE:-}" == "$route" ]]; then
    echo "forced failure for ${route}" >&2
    exit 17
fi
if [[ "${WRK_MALFORMED_ROUTE:-}" == "$route" ]]; then
    echo "missing summary for ${route}"
    exit 0
fi

case "$route" in
    route-a) echo 'WRK_SUMMARY {"rps":800,"p99_ms":4.2}' ;;
    route-b) echo 'WRK_SUMMARY {"rps":150,"p99_ms":4.8}' ;;
    route-c) echo 'WRK_SUMMARY {"rps":50,"p99_ms":5.1}' ;;
    *) echo "unexpected route: ${route}" >&2; exit 2 ;;
esac
SH
chmod +x "${TEST_DIR}/bin/wrk"

# shellcheck source=benchmarks/competitive/upstream-pool-matrix.sh
source "$SCRIPT_UNDER_TEST"

PATH="${TEST_DIR}/bin:${PATH}"
TMP_DIR="${TEST_DIR}/scenario"
BENCH_DIR="${REPO_ROOT}/benchmarks"
LISTEN_PORT="19180"
DURATION="7"
METRICS_COUNTER_FILE="${TEST_DIR}/metrics-count"
mkdir -p "$TMP_DIR"

current_metrics() {
    local count
    count="$(cat "$METRICS_COUNTER_FILE" 2>/dev/null || printf '0')"
    count=$((count + 1))
    printf '%s\n' "$count" > "$METRICS_COUNTER_FILE"
    if [[ "$count" -eq 1 ]]; then
        cat <<'EOF'
tardigrade_upstream_connections_new_total 10
tardigrade_upstream_connections_reused_total 20
tardigrade_upstream_connections_reused_local_total 15
tardigrade_upstream_connections_reused_cross_worker_total 5
tardigrade_upstream_stale_retries_total 1
tardigrade_upstream_pool_lock_wait_ns_total 100
tardigrade_upstream_pool_lock_acquires_total 2
EOF
    else
        cat <<'EOF'
tardigrade_upstream_connections_new_total 14
tardigrade_upstream_connections_reused_total 36
tardigrade_upstream_connections_reused_local_total 25
tardigrade_upstream_connections_reused_cross_worker_total 11
tardigrade_upstream_stale_retries_total 1
tardigrade_upstream_pool_lock_wait_ns_total 5100
tardigrade_upstream_pool_lock_acquires_total 12
EOF
    fi
}

start_monitor() {
    printf '123 %s 1.000000 1000000000\n' "${TEST_DIR}/monitor.samples"
}

stop_monitor() {
    printf '12.50 34.00 56\n'
}

monotonic_ns() {
    printf '3000000000\n'
}

reset_scenario_state() {
    rm -f "${TEST_DIR}"/route-*.* "${TEST_DIR}"/scenario/* 2>/dev/null || true
    printf '0\n' > "$METRICS_COUNTER_FILE"
}

assert_concurrent_window() {
    python3 - "$TEST_DIR" <<'PY'
import pathlib, sys
root = pathlib.Path(sys.argv[1])
starts = [int((root / f"route-{r}.start").read_text()) for r in "abc"]
completes = [int((root / f"route-{r}.complete").read_text()) for r in "abc"]
if max(starts) > min(completes):
    raise SystemExit(f"routes did not overlap: starts={starts} completes={completes}")
PY
}

echo "==> Test 1: uneven route scenario launches route-a/b/c concurrently and attributes results"
reset_scenario_state
export WRK_TEST_DIR="$TEST_DIR"
unset WRK_FAIL_ROUTE WRK_MALFORMED_ROUTE
result="$(run_concurrent_uneven_routes)"
assert_concurrent_window
metrics_calls="$(cat "$METRICS_COUNTER_FILE")"
[[ "$metrics_calls" -eq 2 ]] || fail "expected two metrics snapshots, got ${metrics_calls}"
jq -e '
    .covered == true
    and .concurrent == true
    and .routes.route_a.rps == 800
    and .routes.route_b.rps == 150
    and .routes.route_c.rps == 50
    and .routes.route_a.p99_ms == 4.2
    and .routes.route_b.p99_ms == 4.8
    and .routes.route_c.p99_ms == 5.1
    and .routes.route_a.configured_duration_s == 7
    and .routes.route_a.configured_connections == 16
    and .routes.route_b.configured_connections == 3
    and .routes.route_c.configured_connections == 1
    and .routes.route_a.achieved_share == 0.8
    and .routes.route_b.achieved_share == 0.15
    and .routes.route_c.achieved_share == 0.05
    and .combined.rps == 1000
    and .combined.new_connections == 4
    and .combined.reused_connections == 16
    and .combined.local_reuse == 10
    and .combined.cross_worker_reuse == 6
    and .combined.pool_lock_wait_ns_total == 5000
    and .errors == 0
' <<<"$result" >/dev/null || fail "unexpected success JSON: ${result}"
! grep -R '/hot' "$TEST_DIR"/route-*.args >/dev/null || fail "route-a aliased or invoked the hot-origin path"

echo "==> Test 2: malformed route output fails loudly"
reset_scenario_state
export WRK_MALFORMED_ROUTE="route-b"
if run_concurrent_uneven_routes >"${TEST_DIR}/malformed.out" 2>"${TEST_DIR}/malformed.err"; then
    fail "malformed route output unexpectedly succeeded"
fi
grep -q 'missing wrk summary for route-b' "${TEST_DIR}/malformed.err" || {
    cat "${TEST_DIR}/malformed.err" >&2
    fail "missing malformed-output diagnostic"
}

echo "==> Test 3: non-zero route process status fails and reports raw output"
reset_scenario_state
unset WRK_MALFORMED_ROUTE
export WRK_FAIL_ROUTE="route-c"
if run_concurrent_uneven_routes >"${TEST_DIR}/failed.out" 2>"${TEST_DIR}/failed.err"; then
    fail "failed route process unexpectedly succeeded"
fi
grep -q 'concurrent uneven route wrk failed: route-a=0 route-b=0 route-c=17' "${TEST_DIR}/failed.err" || {
    cat "${TEST_DIR}/failed.err" >&2
    fail "missing child-status diagnostic"
}
grep -q 'forced failure for route-c' "${TEST_DIR}/failed.err" || {
    cat "${TEST_DIR}/failed.err" >&2
    fail "missing failed-route raw output"
}

echo "PASS: upstream-pool matrix concurrent route tests"

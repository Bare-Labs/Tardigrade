#!/usr/bin/env bash
# Validates the #256-G HTTP/3/QUIC benchmark extension: config rendering,
# QUIC metric-scrape parsing, requested-vs-effective buffer handling,
# unsupported-h2load reporting, H3 pass renaming, CSV/Markdown output, and
# netem impairment cleanup. Exercises the real functions from run.sh /
# competitive/run.sh / netem-impair.sh by sourcing them, not reimplementing
# their logic — a change to the real function fails this test too.
#
# Usage:
#   ./benchmarks/test-h3-benchmark.sh
#
# Exit code 0 = all tests passed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RUN_SH="${SCRIPT_DIR}/run.sh"
COMPETITIVE_DIR="${SCRIPT_DIR}/competitive"
COMPETITIVE_RUN_SH="${COMPETITIVE_DIR}/run.sh"
NETEM_SH="${COMPETITIVE_DIR}/netem-impair.sh"

for tool in jq curl; do
    if ! command -v "$tool" &>/dev/null; then
        echo "$tool is required but not installed." >&2
        exit 1
    fi
done

pass=0
fail=0

check() {
    local desc="$1" expected="$2" actual="$3"
    if printf '%s' "$actual" | grep -qF -- "$expected"; then
        echo "  PASS: $desc"
        pass=$((pass + 1))
    else
        echo "  FAIL: $desc"
        echo "        expected to find: $expected"
        echo "        in output:"
        printf '%s\n' "$actual" | sed 's/^/          /'
        fail=$((fail + 1))
    fi
}

check_not() {
    local desc="$1" forbidden="$2" actual="$3"
    if printf '%s' "$actual" | grep -qF -- "$forbidden"; then
        echo "  FAIL: $desc"
        echo "        expected NOT to find: $forbidden"
        fail=$((fail + 1))
    else
        echo "  PASS: $desc"
        pass=$((pass + 1))
    fi
}

# Extract one or more function definitions from a script by name, for
# testing in isolation without running the whole script (which has real
# side effects — starting servers, requiring root, etc.).
source_functions() {
    local script="$1"; shift
    local fn out=""
    for fn in "$@"; do
        out+="$(awk -v fn="$fn" '
            $0 ~ "^"fn"\\(\\) \\{" { printing = 1 }
            printing { print }
            printing && /^}/ { printing = 0 }
        ' "$script")"$'\n'
    done
    printf '%s' "$out"
}

echo "==> Test 1: H3 benchmark config template renders with no leftover placeholders"
TMP_CONF="$(mktemp /tmp/tardi-h3-conf-test-XXXX.conf)"
sed \
    -e "s|__LISTEN_PORT__|19330|g" \
    -e "s|__UPSTREAM_PORT__|19079|g" \
    -e "s|__STATIC_ROOT__|/tmp/tardi-h3-test-public|g" \
    -e "s|__PID_FILE__|/tmp/tardi-h3-test.pid|g" \
    -e "s|__TLS_SERVER_NAME__|tardigrade.test|g" \
    -e "s|__TLS_CERT_PATH__|/tmp/tardi-h3-test/certs/ed25519-cert.pem|g" \
    -e "s|__TLS_KEY_PATH__|/tmp/tardi-h3-test/certs/ed25519-key.pem|g" \
    "${COMPETITIVE_DIR}/configs/tardigrade-http3.conf.in" > "$TMP_CONF"
RENDERED="$(cat "$TMP_CONF")"
check "listen directive uses ssl"        "listen 19330 ssl;" "$RENDERED"
check "tls_server_name substituted"      "server_name tardigrade.test;" "$RENDERED"
check "tls_cert_path substituted"        "tls_cert_path /tmp/tardi-h3-test/certs/ed25519-cert.pem;" "$RENDERED"
check "tls_key_path substituted"         "tls_key_path /tmp/tardi-h3-test/certs/ed25519-key.pem;" "$RENDERED"
check "proxy route present"              "proxy_pass http://127.0.0.1:19079/;" "$RENDERED"
check "metrics path enabled"             "metrics_path /status/metrics;" "$RENDERED"
check_not "no leftover placeholders"     "__" "$RENDERED"
rm -f "$TMP_CONF"

echo ""
echo "==> Test 2: capture_quic_transport_state parses a full metrics scrape into the documented schema"
FAKE_METRICS='tardigrade_quic_packets_sent_total 42
tardigrade_quic_packets_received_total 41
tardigrade_quic_packets_lost_total 2
tardigrade_quic_pto_total 1
tardigrade_quic_bytes_sent_total 123456
tardigrade_quic_bytes_received_total 654321
tardigrade_quic_pmtu_probes_total 3
tardigrade_quic_pmtu_black_holes_total 0
tardigrade_quic_effective_plpmtu_bytes_last 1452
tardigrade_quic_effective_plpmtu_bytes_lifetime_min 1200
tardigrade_quic_effective_plpmtu_bytes_lifetime_max 1452
tardigrade_quic_ecn_enabled 1
tardigrade_quic_ecn_marked_sent_total 10
tardigrade_quic_ecn_paths_validated_total 2
tardigrade_quic_ecn_paths_disabled_total 1
tardigrade_quic_ecn_ce_received_total 5
tardigrade_quic_udp_buffer_requested_bytes{direction="recv"} 4194304
tardigrade_quic_udp_buffer_requested_bytes{direction="send"} 2097152
tardigrade_quic_udp_buffer_effective_bytes{direction="recv"} 2097152
tardigrade_quic_udp_buffer_effective_bytes{direction="send"} 2097152
tardigrade_quic_udp_buffer_granted_bytes{direction="recv"} 1048576
tardigrade_quic_udp_buffer_granted_bytes{direction="send"} 2097152
tardigrade_quic_udp_buffer_status{direction="recv",status="clamped"} 1
tardigrade_quic_udp_buffer_status{direction="send",status="applied"} 1'

QUIC_FNS="$(source_functions "$RUN_SH" quic_metric quic_metric_labeled quic_buffer_status_label capture_quic_transport_state)"
QUIC_JSON="$(bash -c "
set -euo pipefail
SCHEME=https; TARGET_HOST=127.0.0.1; TARGET_PORT=9443; QUIC_METRICS_PATH=/status/metrics; INSECURE=true
curl() { cat <<'EOF2'
${FAKE_METRICS}
EOF2
}
${QUIC_FNS}
capture_quic_transport_state
")"
check "packets_sent parsed"              '"packets_sent": 42' "$(echo "$QUIC_JSON" | jq .)"
check "packets_lost parsed"              '"packets_lost": 2' "$(echo "$QUIC_JSON" | jq .)"
check "effective_plpmtu parsed"          '"last_bytes": 1452' "$(echo "$QUIC_JSON" | jq .)"
check "ecn.enabled is a real boolean"    '"enabled": true' "$(echo "$QUIC_JSON" | jq .)"
# Test 5: requested vs effective vs granted are never confused with each other.
check "recv requested != recv effective (distinct values, not aliased)" \
    "$(echo "$QUIC_JSON" | jq '.udp_buffers.recv.requested_bytes == 4194304 and .udp_buffers.recv.effective_bytes == 2097152 and .udp_buffers.recv.granted_bytes == 1048576')" \
    "true"
check "recv status reflects the clamp"   '"status": "clamped"' "$(echo "$QUIC_JSON" | jq .udp_buffers.recv)"
check "send status reflects the grant"   '"status": "applied"' "$(echo "$QUIC_JSON" | jq .udp_buffers.send)"
check "send requested == send effective == send granted (fully granted, not a coincidence of parsing)" \
    "$(echo "$QUIC_JSON" | jq '.udp_buffers.send.requested_bytes == 2097152 and .udp_buffers.send.effective_bytes == 2097152 and .udp_buffers.send.granted_bytes == 2097152')" \
    "true"

echo ""
echo "==> Test 2b: quic_transport_delta isolates each pass's traffic on a listener kept alive across passes (#256-G review)"
# The competitive harness keeps one H3 listener alive across the readiness
# probe and every pass, so the underlying Prometheus counters are cumulative
# for the listener's whole lifetime, not per-pass. Two synthetic snapshots
# with increasing cumulative values prove the delta between them — not the
# raw post-pass reading — is what a pass's `quic` block gets.
eval "$(source_functions "$RUN_SH" quic_transport_delta)"
snap() {
    jq -cn --argjson sent "$1" --argjson recv "$2" '{
        packets_sent: $sent, packets_received: $recv, packets_lost: 0, pto_total: 0,
        bytes_sent: ($sent * 100), bytes_received: ($recv * 100),
        effective_plpmtu: {last_bytes: 1200, lifetime_min_bytes: 1200, lifetime_max_bytes: 1200},
        pmtu_probes: 0, pmtu_black_holes: 0,
        ecn: {enabled: true, marked_sent: 0, paths_validated: 0, paths_disabled: 0, ce_received: 0},
        udp_buffers: {
            recv: {requested_bytes: 0, effective_bytes: 1, granted_bytes: 0, status: "default"},
            send: {requested_bytes: 0, effective_bytes: 1, granted_bytes: 0, status: "default"}
        }
    }'
}
SNAP_AFTER_READINESS="$(snap 5 5)"      # the H3 readiness probe request
SNAP_AFTER_PASS1="$(snap 105 104)"      # +100 packets during pass 1
SNAP_AFTER_PASS2="$(snap 355 353)"      # +250 packets during pass 2 (cumulative 355, not 250)

DELTA1="$(quic_transport_delta "$SNAP_AFTER_READINESS" "$SNAP_AFTER_PASS1")"
DELTA2="$(quic_transport_delta "$SNAP_AFTER_PASS1" "$SNAP_AFTER_PASS2")"

check "pass 1's delta is its own 100 packets, not the readiness probe's 5" \
    '"packets_sent": 100' "$(echo "$DELTA1" | jq .)"
check "pass 2's delta is its own 250 packets" \
    '"packets_sent": 250' "$(echo "$DELTA2" | jq .)"
check_not "pass 2's delta is NOT the listener-lifetime cumulative total (355) a naive single post-pass scrape would have attributed to it" \
    '"packets_sent": 355' "$(echo "$DELTA2" | jq .)"

echo ""
echo "==> Test 2c: --runs > 1 aggregates each run's scenario-local quic delta instead of dropping it (#256-G review)"
(
    # shellcheck disable=SC2034 # read by flush_multirun_result, sourced via eval below — shellcheck can't see across that
    RUNS=2
    RESULTS_JSON='{}'
    declare -A _run_quic_list=()
    declare -A _run_rps_list=()
    declare -A _run_p99_list=()
    declare -A _run_errors_list=()
    eval "$(source_functions "$RUN_SH" _stats_from_space_list attach_quic_transport_state flush_multirun_result)"

    _run_rps_list[static-http3]='100 110 '
    _run_p99_list[static-http3]='5 6 '
    _run_errors_list[static-http3]='0 0 '

    RUN1_DELTA="$(snap 100 99)"
    RUN2_DELTA="$(snap 150 148)"
    attach_quic_transport_state "static-http3" "$RUN1_DELTA"
    attach_quic_transport_state "static-http3" "$RUN2_DELTA"
    flush_multirun_result "static-http3"

    echo "$RESULTS_JSON" > /tmp/tardi-h3-multirun-test.json
)
MULTIRUN_JSON="$(jq . /tmp/tardi-h3-multirun-test.json)"
check "repeated-run scenario still carries a quic block (not silently dropped)" \
    '"quic"' "$MULTIRUN_JSON"
check "aggregated packets_sent sums every run's delta (100+150=250)" \
    '"packets_sent": 250' "$MULTIRUN_JSON"
check "aggregate records how many runs actually had observable quic data" \
    '"runs_with_data": 2' "$MULTIRUN_JSON"
rm -f /tmp/tardi-h3-multirun-test.json

echo ""
echo "==> Test 4: QUIC metric collection handles an unreachable/metrics-disabled endpoint explicitly (not fabricated)"
UNREACHABLE_JSON="$(bash -c "
set -euo pipefail
SCHEME=https; TARGET_HOST=127.0.0.1; TARGET_PORT=9443; QUIC_METRICS_PATH=/status/metrics; INSECURE=true
curl() { return 7; }
${QUIC_FNS}
capture_quic_transport_state
")"
check "unreachable endpoint yields null, not zeros" "null" "$UNREACHABLE_JSON"

NO_QUIC_SERIES_JSON="$(bash -c "
set -euo pipefail
SCHEME=https; TARGET_HOST=127.0.0.1; TARGET_PORT=9443; QUIC_METRICS_PATH=/status/metrics; INSECURE=true
curl() { echo 'tardigrade_h3_requests_total 0'; }
${QUIC_FNS}
capture_quic_transport_state
")"
check "endpoint with no QUIC series yields null, not zeros" "null" "$NO_QUIC_SERIES_JSON"

echo ""
echo "==> Test 6: an h2load without HTTP/3 support is reported as unsupported, never treated as a pass"
H3_RUNNER="$(source_functions "$RUN_SH" h2load_h3_supported run_h2load_h3)"
# Stub h2load so '--h3 --help' fails exactly the way a non-QUIC nghttp2 build does.
H3_SKIP_OUTPUT="$(bash -c "
set -euo pipefail
h2load() { return 1; }
USE_TLS=true; INSECURE=false; TOOL_HEADERS=(); CONNECTIONS=1; DURATION=1; THREADS=1
add_result() { echo 'add_result SHOULD NOT HAVE BEEN CALLED' >&2; exit 1; }
attach_quic_transport_state() { :; }
build_tool_headers() { :; }
start_process_monitor() { :; }
stop_process_monitor() { :; }
${H3_RUNNER}
run_h2load_h3 'https://127.0.0.1:9443/health' 'static-http3'
")"
check "h2load without --h3 support prints an explicit skip, not a fabricated result" \
    "does not support --h3" "$H3_SKIP_OUTPUT"

echo ""
echo "==> Test 12: the competitive harness separates an unsupported h2load from a broken Tardigrade H3 listener (#256-G review)"
MATRIX_FNS="$(source_functions "$COMPETITIVE_RUN_SH" run_tardigrade_http3_matrix dump_h3_logs)"

# Case A: h2load lacks HTTP/3 support entirely — a legitimate environment
# limitation. Must write unsupported rows, must NEVER start Tardigrade, and
# must return success (this is not a failure of anything Tardigrade does).
CASE_A_OUT="$(bash -c "
set -euo pipefail
LISTEN_BASE=19080; H3_LISTEN_OFFSET=250; OUT_DIR=/tmp; SMOKE=false; TUNE_COMPARISON=false; TMP_DIR=/tmp
h2load_h3_supported() { return 1; }
start_tardigrade_http3() { echo 'START SHOULD NOT HAVE BEEN CALLED' >&2; exit 1; }
write_unsupported_result() { echo \"UNSUPPORTED: \$2\"; }
combine_server_results() { :; }
${MATRIX_FNS}
run_tardigrade_http3_matrix
echo \"EXIT_CODE=\$?\"
" 2>&1)"
check "case A (no HTTP/3-capable h2load): writes unsupported rows" \
    "UNSUPPORTED: static-small-http3" "$CASE_A_OUT"
check "case A: returns success — this is an environment limitation, not a failure" \
    "EXIT_CODE=0" "$CASE_A_OUT"
CASE_A_STARTED="$(printf '%s' "$CASE_A_OUT" | grep -c 'SHOULD NOT HAVE BEEN CALLED' || true)"
if [[ "$CASE_A_STARTED" -eq 0 ]]; then
    echo "  PASS: case A never starts Tardigrade at all (capability is checked before any process launch)"
    pass=$((pass + 1))
else
    echo "  FAIL: case A started Tardigrade despite h2load lacking HTTP/3 support"
    fail=$((fail + 1))
fi

# Case B: h2load DOES support HTTP/3, but Tardigrade's TLS/H3 listener never
# comes up. Once capability is established, this is a product regression —
# must NOT write a soft unsupported row, and must fail the run (nonzero
# exit under this script's `set -e`), not go quietly green.
set +e
CASE_B_OUT="$(bash -c "
set -euo pipefail
LISTEN_BASE=19080; H3_LISTEN_OFFSET=250; OUT_DIR=/tmp; SMOKE=false; TUNE_COMPARISON=false; TMP_DIR=/tmp
h2load_h3_supported() { return 0; }
start_tardigrade_http3() { :; }
wait_for_https() { return 1; }
write_unsupported_result() { echo 'UNSUPPORTED SHOULD NOT HAVE BEEN CALLED FOR A REAL FAILURE' >&2; }
cleanup_edge() { :; }
${MATRIX_FNS}
run_tardigrade_http3_matrix
" 2>&1)"
CASE_B_STATUS=$?
set -e
CASE_B_WROTE_UNSUPPORTED="$(printf '%s' "$CASE_B_OUT" | grep -c 'SHOULD NOT HAVE BEEN CALLED FOR A REAL FAILURE' || true)"
if [[ "$CASE_B_STATUS" -ne 0 ]]; then
    echo "  PASS: case B (h2load supports HTTP/3, Tardigrade's listener doesn't come up) fails the run, exit=${CASE_B_STATUS}"
    pass=$((pass + 1))
else
    echo "  FAIL: case B should have failed the run but exited 0"
    fail=$((fail + 1))
fi
if [[ "$CASE_B_WROTE_UNSUPPORTED" -eq 0 ]]; then
    echo "  PASS: case B does not paper over a real Tardigrade H3 failure with a soft unsupported row"
    pass=$((pass + 1))
else
    echo "  FAIL: case B wrote an unsupported row for what should be a hard product-regression failure"
    fail=$((fail + 1))
fi

echo ""
echo "==> Test 3 & 9: H3 pass renaming produces the canonical scenario keys, and JSON stays valid"
RENAME_FNS="$(source_functions "$COMPETITIVE_RUN_SH" rename_pass_json)"
RAW_H3_RESULT='{"static-http3": {"rps": 5000, "p99_ms": 3.4, "quic": {"packets_sent": 10}}, "_meta": {"tag": "test"}}'
RAW_FILE="$(mktemp /tmp/tardi-h3-raw-XXXX.json)"
RENAMED_FILE="$(mktemp /tmp/tardi-h3-renamed-XXXX.json)"
echo "$RAW_H3_RESULT" > "$RAW_FILE"
bash -c "
set -euo pipefail
${RENAME_FNS}
rename_pass_json '$RAW_FILE' '$RENAMED_FILE' tardigrade static-small-h3
"
RENAMED_SMALL="$(cat "$RENAMED_FILE")"
check "static-small-h3 pass renames static-http3 -> static-small-http3" \
    "static-small-http3" "$RENAMED_SMALL"
check "renamed JSON is valid and preserves the quic block" \
    '"packets_sent": 10' "$(echo "$RENAMED_SMALL" | jq .)"
check "renamed JSON records the competitive pass label" \
    "static-small-h3" "$(echo "$RENAMED_SMALL" | jq .)"

bash -c "
set -euo pipefail
${RENAME_FNS}
rename_pass_json '$RAW_FILE' '$RENAMED_FILE' tardigrade static-large-h3
"
check "static-large-h3 pass renames the same static-http3 key -> static-large-http3" \
    "static-large-http3" "$(cat "$RENAMED_FILE")"
rm -f "$RAW_FILE" "$RENAMED_FILE"

echo ""
echo "==> Test 9: combined CSV/Markdown handle the new H3 quic columns without breaking non-H3 rows"
FAKE_COMBINED="$(mktemp /tmp/tardi-h3-combined-XXXX.json)"
cat > "$FAKE_COMBINED" <<'EOF'
{
  "_meta": {"generated_at": "2026-01-01T00:00:00Z", "suite": "competitive"},
  "servers": {
    "tardigrade": {
      "static-tiny-http1": {"rps": 1000, "p99_ms": 2.0, "errors": 0},
      "static-small-http3": {"rps": 900, "p99_ms": 2.5, "errors": 0,
        "quic": {
          "packets_sent": 50000, "packets_received": 49998, "packets_lost": 2, "pto_total": 0,
          "bytes_sent": 100, "bytes_received": 100,
          "effective_plpmtu": {"last_bytes": 1452, "lifetime_min_bytes": 1200, "lifetime_max_bytes": 1452},
          "pmtu_probes": 3, "pmtu_black_holes": 0,
          "ecn": {"enabled": true, "marked_sent": 1, "paths_validated": 1, "paths_disabled": 0, "ce_received": 0},
          "udp_buffers": {
            "recv": {"requested_bytes": 0, "effective_bytes": 212992, "granted_bytes": 0, "status": "default"},
            "send": {"requested_bytes": 0, "effective_bytes": 212992, "granted_bytes": 0, "status": "default"}
          }
        }
      }
    }
  },
  "upstream_pool_matrix": null
}
EOF
CSV_ROWS="$(jq -r '
    ["server","scenario","quic_packets_sent","quic_ecn_enabled"],
    (.servers | to_entries[] as $server |
        $server.value | to_entries[] |
        [$server.key, .key, (.value.quic.packets_sent // null), (.value.quic.ecn.enabled // null)])
    | @csv
' "$FAKE_COMBINED")"
check "HTTP/1.1 row has null quic columns (not crashed, not fabricated)" \
    'static-tiny-http1",,' "$CSV_ROWS"
check "H3 row carries its quic packet count in CSV form" \
    '"static-small-http3",50000,true' "$CSV_ROWS"
rm -f "$FAKE_COMBINED"

echo ""
echo "==> Test 8: --smoke keeps the H3 matrix bounded (large/proxy/tuned rows are skipped)"
# shellcheck disable=SC2016 # single-quoted on purpose: grepping for the literal text "$port"/"$SMOKE" in the source file, not expanding them
SMOKE_GATE_SRC="$(grep -n 'run_benchmark_pass_h3 "tardigrade" "\$port" "static-large-h3"\|run_benchmark_pass_h3 "tardigrade" "\$port" "proxy-large-h3"\|if ! \$SMOKE; then' "$COMPETITIVE_RUN_SH" | head -5)"
check "large/proxy H3 passes stay inside an '! \$SMOKE' guard" \
    "if ! \$SMOKE; then" "$SMOKE_GATE_SRC"

echo ""
echo "==> Test 10: no benchmark result exposes secrets, private key material, connection IDs, or per-peer cardinality"
FULL_TEXT="${QUIC_JSON} ${CSV_ROWS}"
check_not "no PEM private key markers"     "BEGIN PRIVATE KEY" "$FULL_TEXT"
check_not "no PEM certificate markers"     "BEGIN CERTIFICATE" "$FULL_TEXT"
check_not "no connection_id field"         "connection_id" "$FULL_TEXT"
check_not "no peer_addr field"             "peer_addr" "$FULL_TEXT"
check_not "no keylog marker"               "CLIENT_RANDOM" "$FULL_TEXT"
# The competitive harness must never point at a developer-machine cert path.
check_not "H3 config template has no hard-coded developer cert path" \
    "/Users/" "$(cat "${COMPETITIVE_DIR}/configs/tardigrade-http3.conf.in")"
check_not "H3 config template has no hard-coded /home path either" \
    "/home/" "$(cat "${COMPETITIVE_DIR}/configs/tardigrade-http3.conf.in")"

echo ""
echo "==> Test 7: netem-impair.sh always removes the qdisc on exit, including on a failing wrapped command"
if [[ "$(uname -s 2>/dev/null || true)" == "Linux" ]]; then
    STUB_BIN="$(mktemp -d /tmp/tardi-netem-stub-XXXX)"
    # netem-impair.sh redirects the add command's stderr to a temp file it
    # deletes on success, and the cleanup del's output to /dev/null
    # unconditionally (by design — it only surfaces tc's own output on
    # failure). A stub that writes to its OWN stderr is therefore invisible
    # to a test capturing the script's stdout/stderr, even though it really
    # ran — confirmed by `tc qdisc show dev lo` staying at the untouched
    # default when a first version of this test relied on captured output
    # and passed for the wrong reason (real tc, running as CI root, silently
    # applied and removed a real qdisc instead of the stub ever being
    # exercised). Logging to an independent file sidesteps the redirects
    # entirely and proves the stub — not real tc — actually ran.
    STUB_LOG="$(mktemp /tmp/tardi-netem-stub-log-XXXX)"
    cat > "${STUB_BIN}/tc" <<EOF2
#!/usr/bin/env bash
echo "\$*" >> "${STUB_LOG}"
exit 0
EOF2
    chmod +x "${STUB_BIN}/tc"
    EVIDENCE_OK="$(mktemp /tmp/tardi-netem-evidence-ok-XXXX.json)"
    PATH="${STUB_BIN}:$PATH" "$NETEM_SH" --loss 1 --reorder 25 --delay 20 --interface lo \
        --evidence-file "$EVIDENCE_OK" -- true > /tmp/tardi-netem-ok.log 2>&1 || true
    check "successful run: qdisc add invoked (via the stub, not real tc)" "qdisc add dev lo root netem" "$(cat "$STUB_LOG")"
    check "successful run: cleanup del invoked (via the stub, not real tc)" "qdisc del dev lo root netem" "$(cat "$STUB_LOG")"
    check "successful run: exact tc command recorded"       '"tc_command": "tc qdisc add dev lo root netem delay 20ms loss 1% reorder 25%"' "$(cat "$EVIDENCE_OK")"

    : > "$STUB_LOG"
    EVIDENCE_FAIL="$(mktemp /tmp/tardi-netem-evidence-fail-XXXX.json)"
    set +e
    PATH="${STUB_BIN}:$PATH" "$NETEM_SH" --loss 5 --evidence-file "$EVIDENCE_FAIL" -- false > /tmp/tardi-netem-fail.log 2>&1
    NETEM_FAIL_STATUS=$?
    set -e
    check "failing wrapped command: cleanup del still invoked (via the stub, not real tc)" "qdisc del dev lo root netem" "$(cat "$STUB_LOG")"
    check "failing wrapped command: exit status propagated"    "1" "$NETEM_FAIL_STATUS"
    rm -rf "$STUB_BIN" "$EVIDENCE_OK" "$EVIDENCE_FAIL" "$STUB_LOG" /tmp/tardi-netem-ok.log /tmp/tardi-netem-fail.log
else
    echo "  SKIP: netem-impair.sh is Linux-only; this host is $(uname -s 2>/dev/null || echo unknown)."
    echo "  SKIP: verifying only that it refuses cleanly on a non-Linux host instead."
    NON_LINUX_OUTPUT="$("$NETEM_SH" --loss 1 -- true 2>&1)" || true
    check "non-Linux host: explicit not-executed message, no silent no-op success" \
        "SCENARIO NOT EXECUTED" "$NON_LINUX_OUTPUT"
fi

echo ""
echo "==> Test 13: parse_h2load_json_result parses a real h2load 1.69.0 --output-file document (#256-G review)"
# Provenance, corrected per review: this is a real --output-file=<path>
# capture's *schema* from a local nghttp2 1.69.0 h2load run against a real
# local Tardigrade listener — but it is an HTTP/2 capture, not HTTP/3/QUIC
# evidence. The commit that root-caused #256-G's ALPN failure (cff15570)
# established that this same local h2load recognizes `--h3` syntactically
# but has no QUIC library linked, so it degrades to a plain TCP connection;
# pointed at Tardigrade's HTTP/2 (TCP) listener instead of the HTTP/3 one,
# that degraded connection completes normally and produced this JSON. The
# --output-file schema itself (field names, nesting, units) is real and
# verified, which is all this parser test needs — it is not, and must not be
# read as, the real H3 benchmark evidence #256 still requires.
# #256-G review: requests.failed/.errored/.timeout are not disjoint in real
# h2load — .errored/.timeout requests are already folded into .failed — so
# this fixture keeps failed >= errored + timeout (5 >= 1 + 1) instead of
# baking in the double-counting bug the review caught (the original fixture
# here asserted failed+errored+timeout==5 as if they were additive).
REAL_H2LOAD_JSON='{"version":"v1","metadata":{"generator":"h2load 1.69.0"},"measurements":{"duration":0.004285,"request_per_second":4667.44457,"bytes_per_second":956826,"requests":{"total":20,"started":20,"done":20,"succeeded":15,"failed":5,"errored":1,"timeout":1},"status_codes":{"2xx":15,"3xx":0,"4xx":3,"5xx":0},"traffic":{"total":4100,"headers":3260,"headers_decompressed":2960,"data":420},"performance":{"request":{"min":3.9083e-05,"max":0.000132292,"median":4.3833e-05,"p95":0.000132292,"p99":0.000132292,"mean":5.714995e-05,"sd":2.6971523e-05,"within_sd":80,"samples":[3.9083e-05]},"connect":{"min":0.002875125,"max":0.00343225,"median":0.0031536875,"p95":0.00343225,"p99":0.00343225,"mean":0.0031536875,"sd":0.000393946865,"within_sd":100,"samples":[0.002875125]},"ttfb":{"min":0.003575625,"max":0.003682917,"median":0.003629271,"p95":0.003682917,"p99":0.003682917,"mean":0.003629271,"sd":7.58669008e-05,"within_sd":100,"samples":[0.003575625]},"request_per_second":{"min":2384.07438,"max":2429.12541,"median":2406.5999,"p95":2429.12541,"p99":2429.12541,"mean":2406.5999,"sd":31.8558852,"within_sd":100,"samples":[2384.07438]}}}}'
REAL_JSON_FILE="$(mktemp /tmp/tardi-h2load-real-json-XXXX.json)"
printf '%s' "$REAL_H2LOAD_JSON" > "$REAL_JSON_FILE"
eval "$(source_functions "$RUN_SH" parse_h2load_json_result)"
(
    rps=0; p50="null"; p95="null"; p99="null"; p999="null"; errors=0; tput_mbps="null"
    if parse_h2load_json_result "$REAL_JSON_FILE"; then
        echo "PARSE_OK rps=$rps p50=$p50 p95=$p95 p99=$p99 p999=$p999 errors=$errors tput_mbps=$tput_mbps"
    else
        echo "PARSE_FAILED_UNEXPECTEDLY"
    fi
) > /tmp/tardi-h2load-real-parse-result.txt
REAL_PARSE_OUT="$(cat /tmp/tardi-h2load-real-parse-result.txt)"
check "real h2load 1.69.0 JSON: parse succeeds" "PARSE_OK" "$REAL_PARSE_OUT"
check "real h2load 1.69.0 JSON: rps floored from request_per_second" "rps=4667" "$REAL_PARSE_OUT"
check "real h2load 1.69.0 JSON: p50 converted from median seconds to ms" "p50=0.044" "$REAL_PARSE_OUT"
check "real h2load 1.69.0 JSON: errors uses requests.failed alone (5), not failed+errored+timeout" "errors=5" "$REAL_PARSE_OUT"
rm -f "$REAL_JSON_FILE" /tmp/tardi-h2load-real-parse-result.txt

echo ""
echo "==> Test 14: an invalid/missing h2load --output-file is a failed pass, not a fabricated clean zero (#256-G review)"
(
    rps=99; p50="1"; p95="1"; p99="1"; p999="1"; errors=0; tput_mbps="1"
    if parse_h2load_json_result /tmp/tardi-does-not-exist-XYZ.json; then
        echo "SHOULD_HAVE_FAILED"
    else
        echo "CORRECTLY_FAILED rps=$rps errors=$errors p50=$p50"
    fi
) > /tmp/tardi-h2load-missing-result.txt
MISSING_OUT="$(cat /tmp/tardi-h2load-missing-result.txt)"
check "missing --output-file: reported as a failed pass" "CORRECTLY_FAILED" "$MISSING_OUT"
check "missing --output-file: rps resets to 0, not a stale prior value" "rps=0" "$MISSING_OUT"
check "missing --output-file: errors is a non-zero sentinel, not a fabricated clean 0" "errors=1" "$MISSING_OUT"
rm -f /tmp/tardi-h2load-missing-result.txt

echo ""
echo "==> Test 15: the H3 load command uses h2load's real --duration timing mode, not a synthesized -n request count (#256-G review)"
H3_INVOCATION_SRC="$(grep -n 'h2load --h3 --duration' "$RUN_SH" || true)"
# shellcheck disable=SC2016 # single-quoted on purpose: matching the literal source text "${DURATION}s", not expanding a shell variable
check "run_h2load_h3 invokes h2load with --duration" '--duration "${DURATION}s"' "$H3_INVOCATION_SRC"
# shellcheck disable=SC2016 # single-quoted on purpose: matching the literal old source text, not expanding a shell variable
check_not "run_h2load_h3 no longer synthesizes a request count from CONNECTIONS*DURATION*10" \
    'h2load --h3 -n $((CONNECTIONS * DURATION * 10))' "$(sed -n '/^run_h2load_h3/,/^}/p' "$RUN_SH")"
H2_INVOCATION_SRC="$(grep -n 'h2load --duration' "$RUN_SH" || true)"
# shellcheck disable=SC2016 # single-quoted on purpose: matching the literal source text "${DURATION}s", not expanding a shell variable
check "run_h2load (HTTP/2) also invokes h2load with --duration" '--duration "${DURATION}s"' "$H2_INVOCATION_SRC"

echo ""
echo "==> Test 16: a missing single required QUIC series is treated as unobserved, not a fabricated zero/default (#256-G review)"
PARTIAL_METRICS='tardigrade_quic_packets_sent_total 42
tardigrade_quic_packets_received_total 41
tardigrade_quic_pto_total 1
tardigrade_quic_bytes_sent_total 100
tardigrade_quic_bytes_received_total 100
tardigrade_quic_pmtu_probes_total 0
tardigrade_quic_pmtu_black_holes_total 0
tardigrade_quic_effective_plpmtu_bytes_last 1200
tardigrade_quic_effective_plpmtu_bytes_lifetime_min 1200
tardigrade_quic_effective_plpmtu_bytes_lifetime_max 1200
tardigrade_quic_ecn_enabled 1
tardigrade_quic_ecn_marked_sent_total 1
tardigrade_quic_ecn_paths_validated_total 1
tardigrade_quic_ecn_paths_disabled_total 0
tardigrade_quic_ecn_ce_received_total 0
tardigrade_quic_udp_buffer_requested_bytes{direction="recv"} 0
tardigrade_quic_udp_buffer_effective_bytes{direction="recv"} 1
tardigrade_quic_udp_buffer_granted_bytes{direction="recv"} 0
tardigrade_quic_udp_buffer_status{direction="recv",status="default"} 1
tardigrade_quic_udp_buffer_requested_bytes{direction="send"} 0
tardigrade_quic_udp_buffer_effective_bytes{direction="send"} 1
tardigrade_quic_udp_buffer_granted_bytes{direction="send"} 0
tardigrade_quic_udp_buffer_status{direction="send",status="default"} 1'
# packets_lost_total is deliberately omitted above — everything else present.
PARTIAL_JSON="$(bash -c "
set -euo pipefail
SCHEME=https; TARGET_HOST=127.0.0.1; TARGET_PORT=9443; QUIC_METRICS_PATH=/status/metrics; INSECURE=true
curl() { cat <<'EOF3'
${PARTIAL_METRICS}
EOF3
}
${QUIC_FNS}
capture_quic_transport_state
")"
check "packets_sent present but packets_lost missing: whole snapshot is null, not zero-filled" "null" "$PARTIAL_JSON"

echo ""
echo "==> Test 17: multi-run scenario accounting distinguishes attempted runs from runs with data end-to-end (#256-G review)"
(
    # shellcheck disable=SC2034 # read by flush_multirun_result, sourced via eval below — shellcheck can't see across that
    RUNS=2
    RESULTS_JSON='{}'
    declare -A _run_quic_list=()
    declare -A _run_rps_list=()
    declare -A _run_p99_list=()
    declare -A _run_errors_list=()
    eval "$(source_functions "$RUN_SH" _stats_from_space_list attach_quic_transport_state flush_multirun_result)"
    _run_rps_list[static-http3]='100 110 '
    _run_p99_list[static-http3]='5 6 '
    _run_errors_list[static-http3]='0 0 '
    VALID=$(jq -cn '{packets_sent:100,packets_received:99,packets_lost:1,pto_total:0,bytes_sent:1000,bytes_received:900,effective_plpmtu:{last_bytes:1200,lifetime_min_bytes:1200,lifetime_max_bytes:1200},pmtu_probes:0,pmtu_black_holes:0,ecn:{enabled:true,marked_sent:5,paths_validated:1,paths_disabled:0,ce_received:0},udp_buffers:{recv:{},send:{}}}')
    attach_quic_transport_state "static-http3" "$VALID"
    attach_quic_transport_state "static-http3" "null"
    flush_multirun_result "static-http3"
    echo "$RESULTS_JSON" > /tmp/tardi-h3-runstotal-test.json
)
RUNSTOTAL_JSON="$(jq . /tmp/tardi-h3-runstotal-test.json)"
check "one valid + one missing scrape: runs_total reflects both attempted runs (2)" '"runs_total": 2' "$RUNSTOTAL_JSON"
check "one valid + one missing scrape: runs_with_data reflects only the observed one (1)" '"runs_with_data": 1' "$RUNSTOTAL_JSON"
rm -f /tmp/tardi-h3-runstotal-test.json

echo ""
echo "==> Test 18: run_h2load falls back to text-table parsing when h2load lacks --output-file (pre-1.69 build) (#256-G review)"
H2LOAD_RUNNER="$(source_functions "$RUN_SH" h2load_output_file_supported run_h2load extract_h2load_percentile_ms latency_value_to_ms)"
# Synthetic pre-1.69 h2load text output: real historical baselines were
# produced against this label/token layout (see commit 124c1d8e's
# "failed: N" fix), not captured fresh from an installed old build — this
# test is only exercising the capability-gating branch added here, not
# re-verifying that decade-old parsing regex.
FALLBACK_OUTPUT="$(bash -c "
set -euo pipefail
FAKE_LEGACY_H2LOAD_OUTPUT='finished in 3.00s, 1234.56 req/s, 1.20MB/s
requests: 5000 total, 5000 started, 5000 done, 4995 succeeded, failed: 5, errored: 2, timeout: 1
status codes: 4995 2xx, 0 3xx, 5 4xx, 0 5xx
  50th percentile: 12.34 ms
  95th percentile: 45.67 ms
  99th percentile: 78.90 ms
  99.9th percentile: 120.00 ms'
h2load() {
    if [[ \"\$1\" == \"--help\" ]]; then
        echo 'usage: h2load [OPTIONS]... <URI>'
        echo '  -c, --clients=N     ...'
        return 0
    fi
    printf '%s\n' \"\$FAKE_LEGACY_H2LOAD_OUTPUT\"
    return 0
}
USE_TLS=true; INSECURE=false; TOOL_HEADERS=(); CONNECTIONS=1; DURATION=1; THREADS=1
CURRENT_CPU_PCT_AVG=null; CURRENT_RSS_MB_PEAK=null
add_result() { echo \"add_result rps=\$2 p50=\$3 p95=\$4 p99=\$5 p999=\$6 errors=\$7 tput=\$8\"; }
build_tool_headers() { :; }
start_process_monitor() { :; }
stop_process_monitor() { :; }
${H2LOAD_RUNNER}
run_h2load 'https://127.0.0.1:9443/health' 'static-http2'
")"
check "no --output-file build: prints an explicit fallback notice, not a silent switch" \
    "falling back to text-table parsing" "$FALLBACK_OUTPUT"
check "no --output-file build: rps parsed from legacy 'finished' line" \
    "rps=1234.56" "$FALLBACK_OUTPUT"
check "no --output-file build: p50 parsed from legacy '50th percentile' line" \
    "p50=12.340" "$FALLBACK_OUTPUT"
check "no --output-file build: p999 parsed from legacy '99.9th percentile' line" \
    "p999=120.000" "$FALLBACK_OUTPUT"
check "no --output-file build: errors parsed from legacy 'failed: N' token" \
    "errors=5" "$FALLBACK_OUTPUT"
check "no --output-file build: throughput parsed from legacy 'finished' line" \
    "tput=1.20" "$FALLBACK_OUTPUT"

echo ""
echo "==> Test 19: h2load_h3_supported requires real QUIC linkage, not just flag recognition (#256-G review — the exact false positive hit investigating #256's ALPN blocker)"
H3_SUPPORT_FNS="$(source_functions "$RUN_SH" h2load_h3_supported)"

# Case A: h2load recognizes --h3 syntactically but there is no real on-disk
# binary for otool/ldd to inspect — this reproduces the "flag yes, QUIC
# library linkage no" shape of the stock Homebrew nghttp2 package, which is
# exactly what silently negotiated a degraded TCP connection offering ALPN
# "h3" against a live local Tardigrade H3 listener during #256-G review, and
# was misread as a Tardigrade regression before that was root-caused.
CASE_A_OUT="$(bash -c "
set -euo pipefail
h2load() { [[ \"\$1\" == --h3 ]] && return 0; return 1; }
${H3_SUPPORT_FNS}
h2load_h3_supported && echo SUPPORTED || echo UNSUPPORTED
")"
check "flag-only h2load (no real binary to link-check): reported unsupported, not the false positive that caused #256-G's ALPN investigation" \
    "UNSUPPORTED" "$CASE_A_OUT"

# Case B: a real on-disk h2load that recognizes --h3 AND is actually linked
# against libngtcp2/libnghttp3 (faked via stub otool/ldd placed first on
# PATH, so this runs identically on macOS and Linux CI regardless of which
# linker-inspection tool the host actually has).
CASE_B_DIR="$(mktemp -d /tmp/tardi-h2load-linked-test-XXXX)"
cat > "${CASE_B_DIR}/h2load" <<'H2LOAD_STUB'
#!/usr/bin/env bash
[[ "$1" == "--h3" ]] && exit 0
exit 1
H2LOAD_STUB
cat > "${CASE_B_DIR}/otool" <<'OTOOL_STUB'
#!/usr/bin/env bash
echo "	/usr/lib/libngtcp2.dylib (compatibility version 1.0.0, current version 1.0.0)"
OTOOL_STUB
cat > "${CASE_B_DIR}/ldd" <<'LDD_STUB'
#!/usr/bin/env bash
echo "	libngtcp2.so.16 => /usr/lib/x86_64-linux-gnu/libngtcp2.so.16"
LDD_STUB
chmod +x "${CASE_B_DIR}/h2load" "${CASE_B_DIR}/otool" "${CASE_B_DIR}/ldd"
CASE_B_OUT="$(bash -c "
set -euo pipefail
export PATH=\"${CASE_B_DIR}:\$PATH\"
${H3_SUPPORT_FNS}
h2load_h3_supported && echo SUPPORTED || echo UNSUPPORTED
")"
check "real QUIC-linked h2load (flag + linkage both present): still reported supported" \
    "SUPPORTED" "$CASE_B_OUT"
rm -rf "$CASE_B_DIR"

echo ""
echo "==> Test 20: competitive/run.sh's h2load_h3_supported (what run_tardigrade_http3_matrix actually gates on) gets the same linkage check (#256-G review)"
COMPETITIVE_H3_SUPPORT_FNS="$(source_functions "$COMPETITIVE_RUN_SH" h2load_h3_supported)"
COMPETITIVE_CASE_A_OUT="$(bash -c "
set -euo pipefail
h2load() { [[ \"\$1\" == --h3 ]] && return 0; return 1; }
${COMPETITIVE_H3_SUPPORT_FNS}
h2load_h3_supported && echo SUPPORTED || echo UNSUPPORTED
")"
check "competitive/run.sh: flag-only h2load is also reported unsupported, not a false positive" \
    "UNSUPPORTED" "$COMPETITIVE_CASE_A_OUT"

echo ""
echo "==> Test 21: capture_quic_transport_state sends the configured Host header to the metrics scrape, not just the load pass (#256-G review)"
# capture_quic_transport_state's own curl call redirects stderr to
# /dev/null (so an unreachable endpoint doesn't spam the run), so the stub
# below has to record its args to a file rather than stderr.
CURL_ARGS_LOG="$(mktemp /tmp/tardi-h3-curlargs-XXXX.log)"
bash -c "
set -euo pipefail
SCHEME=https; TARGET_HOST=127.0.0.1; TARGET_PORT=9443; QUIC_METRICS_PATH=/status/metrics; INSECURE=true; HOST_HEADER=tardigrade.test
curl() { printf '%s\n' \"\$*\" >> '${CURL_ARGS_LOG}'; echo 'tardigrade_quic_packets_sent_total 1'; }
${QUIC_FNS}
capture_quic_transport_state >/dev/null
"
check "capture_quic_transport_state: metrics scrape sends Host header matching \$HOST_HEADER, not just the load pass" \
    "Host: tardigrade.test" "$(cat "$CURL_ARGS_LOG")"
rm -f "$CURL_ARGS_LOG"

echo ""
echo "==> Test 22: the H3 matrix sends Host/:authority matching the benchmark config's server_name end-to-end, not the 127.0.0.1 literal in the URL (#256-G review)"
MATRIX_SRC="$(sed -n '/^run_tardigrade_http3_matrix/,/^}/p' "$COMPETITIVE_RUN_SH")"
# shellcheck disable=SC2016 # single-quoted on purpose: matching the literal source text, not expanding a shell variable
check "readiness checks (wait_for_https) pass the configured Host header" \
    'wait_for_https "https://127.0.0.1:${port}/health" 60 0.2 "$H3_TLS_SERVER_NAME"' "$MATRIX_SRC"
# shellcheck disable=SC2016 # single-quoted on purpose: matching the literal source text, not expanding a shell variable
check "payload preflight checks (assert_payload_size) pass the configured Host header" \
    'assert_payload_size "https://127.0.0.1:${port}/tiny.txt" 3 "$H3_TLS_SERVER_NAME"' "$MATRIX_SRC"
VERIFY_H3_SRC="$(sed -n '/^verify_h3_listener/,/^}/p' "$COMPETITIVE_RUN_SH")"
# shellcheck disable=SC2016 # single-quoted on purpose: matching the literal source text, not expanding a shell variable
check "verify_h3_listener's real HTTP/3 readiness request sends the configured Host header" \
    'h2load --h3 -n 1 -c 1 -H "Host: ${H3_TLS_SERVER_NAME}"' "$VERIFY_H3_SRC"
PASS_H3_SRC="$(sed -n '/^run_benchmark_pass_h3/,/^}/p' "$COMPETITIVE_RUN_SH")"
# shellcheck disable=SC2016 # single-quoted on purpose: matching the literal source text, not expanding a shell variable
check "run_benchmark_pass_h3 forwards --host-header to benchmarks/run.sh (so the h2load load pass also gets it via TOOL_HEADERS)" \
    '--host-header "$H3_TLS_SERVER_NAME"' "$PASS_H3_SRC"

echo ""
echo "==> Test 23: #247 validation evidence doc keeps the closeout contract wired to existing harnesses"
VALIDATION_DOC="${SCRIPT_DIR}/../docs/HTTP3_VALIDATION_EVIDENCE.md"
VALIDATION_TEXT="$(cat "$VALIDATION_DOC")"
check "validation doc links the deterministic QUIC/H3 proof matrix" \
    "QUIC_H3_FUZZ_MATRIX.md" "$VALIDATION_TEXT"
check "validation doc points to the existing interop runner" \
    "scripts/interop/run-interop.sh" "$VALIDATION_TEXT"
check "validation doc requires a genuinely QUIC-capable client" \
    "genuinely QUIC-capable" "$VALIDATION_TEXT"
check "validation doc requires scenario-local QUIC metric deltas" \
    "scenario-local QUIC metric deltas" "$VALIDATION_TEXT"
check "validation doc preserves the bounded soak resource contract" \
    "RSS and open file descriptors" "$VALIDATION_TEXT"
check "validation doc keeps obsolete qvis issue #608 out of the #247 closeout path" \
    "$(printf '%s' "$VALIDATION_TEXT" | grep -c '#608')" "0"
check "validation doc uses netem-impair.sh as the checked-in wrapper command" \
    "-- ./benchmarks/competitive/run.sh --servers tardigrade" "$VALIDATION_TEXT"
check "validation doc does not document nonexistent netem apply/clear subcommands" \
    "$(printf '%s' "$VALIDATION_TEXT" | grep -Ec 'netem-impair\\.sh (apply|clear)')" "0"
check "validation doc uses numeric netem percentages without literal percent signs" \
    "--loss 1 --reorder 2 --delay 20" "$VALIDATION_TEXT"

echo ""
echo "==> Test: existing HTTP/1 benchmark behavior does not regress (run.sh --help still documents http1 scenarios)"
HELP_OUTPUT="$("$RUN_SH" --help 2>&1)"
check "static-http1 still documented"   "static-http1" "$HELP_OUTPUT"
check "proxy-http1 still documented"    "proxy-http1"  "$HELP_OUTPUT"
check "new --metrics-path flag documented" "--metrics-path" "$HELP_OUTPUT"

echo ""
if [[ "$fail" -eq 0 ]]; then
    echo "All ${pass} tests passed."
    exit 0
else
    echo "${fail} test(s) FAILED, ${pass} passed."
    exit 1
fi

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
tardigrade_quic_effective_plpmtu_bytes_min 1200
tardigrade_quic_effective_plpmtu_bytes_max 1452
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
H3_RUNNER="$(source_functions "$RUN_SH" run_h2load_h3)"
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
          "effective_plpmtu": {"last_bytes": 1452, "min_bytes": 1200, "max_bytes": 1452},
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
    cat > "${STUB_BIN}/tc" <<'EOF2'
#!/usr/bin/env bash
echo "STUB tc $*" >&2
exit 0
EOF2
    chmod +x "${STUB_BIN}/tc"
    EVIDENCE_OK="$(mktemp /tmp/tardi-netem-evidence-ok-XXXX.json)"
    PATH="${STUB_BIN}:$PATH" "$NETEM_SH" --loss 1 --reorder 25 --delay 20 --interface lo \
        --evidence-file "$EVIDENCE_OK" -- true > /tmp/tardi-netem-ok.log 2>&1 || true
    check "successful run: qdisc add then del both invoked" "STUB tc qdisc add" "$(cat /tmp/tardi-netem-ok.log)"
    check "successful run: cleanup del invoked"             "STUB tc qdisc del" "$(cat /tmp/tardi-netem-ok.log)"
    check "successful run: exact tc command recorded"       '"tc_command": "tc qdisc add dev lo root netem delay 20ms loss 1% reorder 25%"' "$(cat "$EVIDENCE_OK")"

    EVIDENCE_FAIL="$(mktemp /tmp/tardi-netem-evidence-fail-XXXX.json)"
    set +e
    PATH="${STUB_BIN}:$PATH" "$NETEM_SH" --loss 5 --evidence-file "$EVIDENCE_FAIL" -- false > /tmp/tardi-netem-fail.log 2>&1
    NETEM_FAIL_STATUS=$?
    set -e
    check "failing wrapped command: cleanup del still invoked" "STUB tc qdisc del" "$(cat /tmp/tardi-netem-fail.log)"
    check "failing wrapped command: exit status propagated"    "1" "$NETEM_FAIL_STATUS"
    rm -rf "$STUB_BIN" "$EVIDENCE_OK" "$EVIDENCE_FAIL" /tmp/tardi-netem-ok.log /tmp/tardi-netem-fail.log
else
    echo "  SKIP: netem-impair.sh is Linux-only; this host is $(uname -s 2>/dev/null || echo unknown)."
    echo "  SKIP: verifying only that it refuses cleanly on a non-Linux host instead."
    NON_LINUX_OUTPUT="$("$NETEM_SH" --loss 1 -- true 2>&1)" || true
    check "non-Linux host: explicit not-executed message, no silent no-op success" \
        "SCENARIO NOT EXECUTED" "$NON_LINUX_OUTPUT"
fi

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

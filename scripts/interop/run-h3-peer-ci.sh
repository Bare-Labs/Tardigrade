#!/usr/bin/env bash
# Runs the pinned external H3 peer matrix entries that CI builds in
# build-h3-peer-ci.sh. This wrapper keeps peer-specific environment names
# inside scripts/interop/, the dependency-audit external-peer boundary.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
examples_dir="${H3_PEER_EXAMPLES_DIR:?set H3_PEER_EXAMPLES_DIR to the built examples directory}"
workdir="${INTEROP_WORKDIR:-${RUNNER_TEMP:-/tmp}/tardigrade-h3-peer-interop}"
output="${INTEROP_OUTPUT_LOG:-$workdir/matrix.log}"

mkdir -p "$workdir" "$(dirname "$output")"

dump_hrr_logs() {
  for log in \
    "$workdir/logs/333-1-native-client-hrr.log" \
    "$workdir/logs/333-1-gtlsserver-hrr.log" \
    "$workdir/logs/333-2-native-server-hrr.log" \
    "$workdir/logs/333-2-gtlsclient-hrr.log"
  do
    if [ -f "$log" ]; then
      printf '\n--- %s ---\n' "$log"
      sed -n '1,420p' "$log"
    fi
  done
}

set +e
INTEROP_WORKDIR="$workdir" NGTCP2_EXAMPLES_DIR="$examples_dir" "$here/run-interop.sh" | tee "$output"
matrix_rc=${PIPESTATUS[0]}
set -e

if [ "$matrix_rc" -ne 0 ]; then
  dump_hrr_logs
  exit "$matrix_rc"
fi

grep -q "#333 native HRR client -> ngtcp2 gtlsserver[[:space:]]*PASS" "$output"
grep -q "#333 ngtcp2 HRR gtlsclient -> native server[[:space:]]*PASS" "$output"

grep "tls retry_state=hrr_received" "$workdir/logs/333-1-native-client-hrr.log"
grep "tls hello_retry_request=true" "$workdir/logs/333-2-native-server-hrr.log"

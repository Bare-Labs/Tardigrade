#!/bin/bash
# Shared-TLS-engine interoperability and conformance matrix (#338).
#
# Drives the *same* TLS 1.3 engine that the production listener uses, in both
# client and server roles, over both transports, against out-of-process
# external implementations:
#
#   record transport  tls_interop_tool  <-> openssl s_client / s_server
#                                       <-> gnutls-cli / gnutls-serv
#   QUIC transport    h3_interop_tool   <-> ngtcp2 gtlsclient / gtlsserver
#                                       (native loopback when no peer is set)
#
# Nothing foreign links into Tardigrade: every peer is a separate process.
#
# Positive rows walk the engine's full cipher-suite x group x signature matrix
# and assert on what was actually negotiated, not merely that a handshake
# completed. Negative rows assert the failure class both sides agree on, using
# the RFC 8446 §6 alert where the standard defines one.
#
# usage:
#   scripts/interop/run-tls-interop.sh [--profile ci|full] [--list]
#
# environment:
#   TLS_INTEROP_PROFILE   ci | full   (default: full; --profile wins)
#   TLS_INTEROP_WORKDIR   where certs, logs and transcripts land
#                         (default: a fresh mktemp -d, printed on exit)
#   OPENSSL_BIN           openssl binary            (default: openssl)
#   GNUTLS_CLI/GNUTLS_SERV gnutls binaries          (default: gnutls-cli/-serv)
#   NGTCP2_EXAMPLES_DIR   dir with gtlsclient/gtlsserver, for external QUIC
#
# Both profiles run every supported (suite, group, signature) tuple in both
# record roles against OpenSSL, every tuple on QUIC, and every negative and
# certificate-selection row. `ci` reduces only the *second* implementation's
# sweep: GnuTLS cross-checks one representative tuple per suite instead of all
# of them. See docs/TLS_INTEROP_MATRIX.md.
set -u

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"

profile="${TLS_INTEROP_PROFILE:-full}"
list_only=0
while [ $# -gt 0 ]; do
  case "$1" in
    --profile) profile="${2:?--profile needs ci|full}"; shift 2 ;;
    --list) list_only=1; shift ;;
    -h|--help) sed -n '2,35p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
case "$profile" in
  ci|full) ;;
  *) echo "unknown profile: $profile (want ci or full)" >&2; exit 2 ;;
esac

openssl_bin="${OPENSSL_BIN:-openssl}"
gnutls_cli="${GNUTLS_CLI:-gnutls-cli}"
gnutls_serv="${GNUTLS_SERV:-gnutls-serv}"

# #359: when non-empty, the GnuTLS peer advertises this RFC 8449
# `record_size_limit` (its `--recordsize` is the payload size; GnuTLS adds the
# content-type byte itself, so `--recordsize 1024` puts 1025 on the wire).
# Scoped by the record-size rows and cleared straight after, so every other row
# keeps the peer's default.
gnutls_recordsize=""

workdir="${TLS_INTEROP_WORKDIR:-$(mktemp -d)}"
certs="$workdir/certs"
logs="$workdir/logs"
transcripts="$workdir/transcripts"
mkdir -p "$certs" "$logs" "$transcripts"

tls_tool="$repo/zig-out/bin/tls_interop_tool"
h3_tool="$repo/zig-out/bin/h3_interop_tool"

pass=0
fail=0
skip=0
failed_rows=()

say() { printf '%s\n' "$*"; }

result() { # name status [detail]
  case "$2" in
    PASS) pass=$((pass + 1)) ;;
    FAIL) fail=$((fail + 1)); failed_rows+=("$1") ;;
    SKIP) skip=$((skip + 1)) ;;
  esac
  printf '%-64s %-4s %s\n' "$1" "$2" "${3:-}"
}

port=25100
# Assigns the global rather than echoing: `p=$(next_port)` would run in a
# subshell and leave `port` unchanged, so every row would reuse one port and
# collide with the previous row's lingering listener.
next_port() { port=$((port + 1)); }

# Wait for the native tool's own readiness line rather than sleeping: loading
# an RSA identity takes over a second, and a fixed sleep would race it.
wait_for_native_listener() { # logfile
  for _ in $(seq 1 150); do
    grep -q 'tls-interop: listening' "$1" 2>/dev/null && return 0
    sleep 0.1
  done
  return 1
}

# Wait on the external server's own readiness output. Deliberately *not* a
# `nc -z` connect probe: `openssl s_server -naccept 1` serves exactly one
# connection, and the probe would consume it, leaving the row's real client
# with nothing to talk to.
wait_for_peer_listener() { # logfile pattern
  for _ in $(seq 1 150); do
    grep -qi "$2" "$1" 2>/dev/null && return 0
    sleep 0.1
  done
  return 1
}

# ── matrix vocabulary ───────────────────────────────────────────────────────
# The dimension lists are *not* written here. They come from the engine via
# `tls_interop_tool list-capabilities`, so this script cannot drift from
# `native_capabilities`: a newly supported suite/group/signature becomes a new
# row automatically, and one this script has no peer spelling for fails
# preflight loudly instead of being silently skipped.
#
# Only the peer *spellings* below are script-local -- they describe OpenSSL and
# GnuTLS, not Tardigrade, so there is nothing on the Zig side for them to drift
# from.

suites=()
groups=()
signatures=()

load_capabilities() {
  local kind name
  while IFS=$'\t' read -r kind name; do
    [ -z "$kind" ] && continue
    case "$kind" in
      cipher-suite) suites+=("$name") ;;
      group) groups+=("$name") ;;
      signature) signatures+=("$name") ;;
      *) say "unknown capability kind from the engine: $kind"; exit 1 ;;
    esac
  done < <("$tls_tool" list-capabilities)

  if [ ${#suites[@]} -eq 0 ] || [ ${#groups[@]} -eq 0 ] || [ ${#signatures[@]} -eq 0 ]; then
    say "the engine reported an empty capability dimension; refusing to run a hollow matrix"
    exit 1
  fi
}

# Every engine capability must have a spelling for each peer, or the row would
# silently degrade into "whatever that peer defaults to" -- which is exactly
# the drift consuming `list-capabilities` is meant to prevent. Missing
# spellings are a preflight failure, not a skip.
check_peer_spellings() {
  local value missing=0
  for value in "${suites[@]}"; do
    [ -z "$(openssl_suite "$value")" ] && { say "no OpenSSL spelling for cipher suite: $value"; missing=1; }
    [ "$have_gnutls" -eq 1 ] && [ -z "$(gnutls_suite "$value")" ] && { say "no GnuTLS spelling for cipher suite: $value"; missing=1; }
  done
  for value in "${groups[@]}"; do
    [ -z "$(openssl_group "$value")" ] && { say "no OpenSSL spelling for group: $value"; missing=1; }
    [ "$have_gnutls" -eq 1 ] && [ -z "$(gnutls_group "$value")" ] && { say "no GnuTLS spelling for group: $value"; missing=1; }
  done
  for value in "${signatures[@]}"; do
    [ -z "$(openssl_sigalg "$value")" ] && { say "no OpenSSL spelling for signature scheme: $value"; missing=1; }
    [ "$have_gnutls" -eq 1 ] && [ -z "$(gnutls_sign "$value")" ] && { say "no GnuTLS spelling for signature scheme: $value"; missing=1; }
    [ -z "$(cert_for_signature "$value")" ] && { say "no credential for signature scheme: $value"; missing=1; }
  done
  if [ "$missing" -ne 0 ]; then
    say ""
    say "The engine gained a capability this runner cannot drive yet. Add the"
    say "peer spellings above (and a credential if the signature dimension grew)"
    say "so the new tuple is actually covered."
    exit 1
  fi
}

list_matrix_rows() {
  say "profile: $profile"
  say "engine capabilities: ${#suites[@]} suites x ${#groups[@]} groups x ${#signatures[@]} signatures"
  for suite in "${suites[@]}"; do
    for group in "${groups[@]}"; do
      for sig in "${signatures[@]}"; do
        tuple="$suite/$group/$sig"
        say "positive  record/server/openssl/$tuple"
        say "positive  record/client/openssl/$tuple"
        if [ "$have_gnutls" -eq 0 ]; then
          say "skip      record/server/gnutls/$tuple"
          say "skip      record/client/gnutls/$tuple"
        elif gnutls_row_in_profile "$suite" "$group" "$sig"; then
          say "positive  record/server/gnutls/$tuple"
          say "positive  record/client/gnutls/$tuple"
        fi
        say "positive  quic/loopback/$tuple"
      done
    done
  done
  say "positive  record/server/openssl/http2_entrypoint"
  say "positive  record/server/openssl/hrr"
  say "positive  record/client/openssl/hrr"
  if [ "$have_gnutls" -eq 0 ]; then
    say "skip      record/server/gnutls/record-size-limit"
    say "skip      record/client/gnutls/record-size-limit"
  else
    say "positive  record/server/gnutls/record-size-limit"
    say "positive  record/client/gnutls/record-size-limit"
  fi
  say "positive  record/server/openssl/key-update/reciprocal"
  say "positive  record/client/openssl/key-update/reciprocal"
  say "positive  record/client/openssl/key-update/one-way"
  say "positive  record/server/openssl/close_notify"
  say "negative  record/server/openssl/truncation"
  say "negative  record/negative/alpn_no_overlap"
  say "negative  record/negative/tls12_downgrade"
  say "negative  record/negative/cipher_no_overlap"
  say "negative  record/negative/group_no_overlap"
  say "negative  record/negative/signature_no_overlap"
  say "negative  record/negative/sni_absent"
  say "negative  record/negative/malformed_ordering"
  say "negative  record/negative/ccs_before_clienthello"
  say "negative  record/negative/wrong_pinned_certificate"
  say "selection record/selection/sni_ed25519"
  say "selection record/selection/sni_ecdsa_p256"
  say "selection record/selection/sni_rsa"
  say "selection record/selection/unknown_sni_uses_default"
  say "selection record/selection/sigalgs_ed25519"
  say "selection record/selection/sigalgs_rsa_pss"
  say "selection record/selection/no_applicable_credential"
}

openssl_suite() {
  case "$1" in
    aes128-gcm-sha256) echo TLS_AES_128_GCM_SHA256 ;;
    aes256-gcm-sha384) echo TLS_AES_256_GCM_SHA384 ;;
    chacha20-poly1305-sha256) echo TLS_CHACHA20_POLY1305_SHA256 ;;
  esac
}
openssl_group() {
  case "$1" in
    x25519) echo X25519 ;;
    secp256r1) echo P-256 ;;
  esac
}
openssl_sigalg() {
  case "$1" in
    ed25519) echo ed25519 ;;
    ecdsa-p256-sha256) echo ecdsa_secp256r1_sha256 ;;
    rsa-pss-rsae-sha256) echo rsa_pss_rsae_sha256 ;;
  esac
}
# GnuTLS selects a TLS 1.3 ciphersuite from its cipher plus its hash, so a
# suite contributes two priority tokens.
gnutls_suite() {
  case "$1" in
    aes128-gcm-sha256) echo "+AES-128-GCM:+SHA256" ;;
    aes256-gcm-sha384) echo "+AES-256-GCM:+SHA384" ;;
    chacha20-poly1305-sha256) echo "+CHACHA20-POLY1305:+SHA256" ;;
  esac
}
gnutls_group() {
  case "$1" in
    x25519) echo "+GROUP-X25519" ;;
    secp256r1) echo "+GROUP-SECP256R1" ;;
  esac
}
gnutls_sign() {
  case "$1" in
    ed25519) echo "+SIGN-EDDSA-ED25519" ;;
    ecdsa-p256-sha256) echo "+SIGN-ECDSA-SECP256R1-SHA256" ;;
    rsa-pss-rsae-sha256) echo "+SIGN-RSA-PSS-RSAE-SHA256" ;;
  esac
}
gnutls_priority() { # suite group signature
  echo "NONE:+VERS-TLS1.3:$(gnutls_suite "$1"):+AEAD:$(gnutls_group "$2"):$(gnutls_sign "$3"):+CTYPE-X509"
}

# The signature dimension picks the credential, exactly as
# `identityKeyForSignature` in tests/tls_interop_matrix.zig says it must.
cert_for_signature() {
  case "$1" in
    ed25519) echo "$certs/ed25519" ;;
    ecdsa-p256-sha256) echo "$certs/p256" ;;
    rsa-pss-rsae-sha256) echo "$certs/rsa2048" ;;
  esac
}

# The reduced CI profile reduces *peer multiplicity*, never tuple coverage.
#
# #338 requires CI to prove positive interop for every supported tuple in both
# roles, so every `(suite, group, signature)` combination runs in both record
# roles against OpenSSL, and every combination runs on QUIC, in both profiles.
# What `ci` drops is the second implementation's sweep: GnuTLS cross-checks one
# representative tuple per suite rather than all of them. A regression in any
# tuple is still caught; only a regression that is simultaneously
# tuple-specific *and* GnuTLS-specific could slip to the nightly full profile.
gnutls_row_in_profile() { # suite group signature
  [ "$profile" = "full" ] && return 0
  [ "$2" = "x25519" ] && [ "$3" = "ed25519" ] && return 0
  return 1
}

# ── row runners ─────────────────────────────────────────────────────────────

# What an external client feeds the native server on stdin.
#
# `once` is the ordinary case: one request, then EOF.
#
# `keep_writing` exists for the KeyUpdate rows (#357). RFC 8446 §4.6.3 obliges
# a peer that receives `update_requested` to answer "prior to sending its next
# Application Data record" -- so a peer that has already stopped writing owes
# us nothing, and the row would time out waiting for a reply the standard never
# required. The delayed second request *is* that next record, and it also
# lands after the transition, so the peer has to have followed the update to
# send it at all.
peer_request_stdin() { # once|keep_writing
  case "$1" in
    keep_writing)
      printf 'GET / HTTP/1.0\r\n\r\n'
      sleep 2
      printf 'GET / HTTP/1.0\r\nX-Key-Update-Probe: 1\r\n\r\n'
      sleep 2
      ;;
    h2_preface)
      printf 'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
      printf '\x00\x00\x00\x04\x00\x00\x00\x00\x00'
      ;;
    *) printf 'GET / HTTP/1.0\r\n\r\n' ;;
  esac
}

# native TLS server <- external client
run_server_alpn_row() { # name peer suite group signature alpn peer_stdin [extra native args...]
  local name="$1" peer="$2" suite="$3" group="$4" sig="$5" alpn="$6" peer_stdin="$7"
  shift 7
  local p log cert peer_groups
  next_port; p="$port"
  log="$logs/${name//\//_}"
  cert="$(cert_for_signature "$sig")"
  # An HRR row wants the peer to offer its first key share for a group the
  # native server does not accept; ordinary rows offer the row's own group.
  peer_groups="$(openssl_group "$group")"
  case " $* " in *" --expect-hrr "*) peer_groups="P-384:$(openssl_group "$group")" ;; esac
  case " $* " in *" --key-update "*) peer_stdin=keep_writing ;; esac

  "$tls_tool" server --port "$p" --cert "$cert-cert.pem" --key "$cert-key.pem" \
    --cipher-suite "$suite" --group "$group" --signature "$sig" \
    --alpn "$alpn" --transcript "$transcripts/${name//\//_}.txt" \
    --timeout-ms 20000 "$@" > "$log.native" 2>&1 &
  local native_pid=$!
  if ! wait_for_native_listener "$log.native"; then
    kill "$native_pid" 2>/dev/null
    result "$name" FAIL "native listener never came up"
    return
  fi

  case "$peer" in
    openssl)
      peer_request_stdin "$peer_stdin" | "$openssl_bin" s_client -connect "127.0.0.1:$p" \
        -servername tardigrade.test -tls1_3 \
        -ciphersuites "$(openssl_suite "$suite")" -groups "$peer_groups" \
        -sigalgs "$(openssl_sigalg "$sig")" -alpn "$alpn" \
        -CAfile "$cert-cert.pem" > "$log.peer" 2>&1
      ;;
    gnutls)
      local cli_args=(--port "$p" --x509cafile "$cert-cert.pem" --alpn="$alpn"
        --sni-hostname=tardigrade.test --priority "$(gnutls_priority "$suite" "$group" "$sig")")
      [ -n "$gnutls_recordsize" ] && cli_args+=(--recordsize "$gnutls_recordsize")
      peer_request_stdin "$peer_stdin" | "$gnutls_cli" "${cli_args[@]}" 127.0.0.1 > "$log.peer" 2>&1
      ;;
  esac

  if wait "$native_pid"; then
    result "$name" PASS "$(grep -o 'suite=.*' "$log.native" | head -1)"
  else
    result "$name" FAIL "see $log.native"
  fi
}

run_server_row() { # name peer suite group signature [extra native args...]
  local name="$1" peer="$2" suite="$3" group="$4" sig="$5"
  shift 5
  run_server_alpn_row "$name" "$peer" "$suite" "$group" "$sig" http/1.1 once "$@"
}

run_server_truncation_row() {
  local name="record/server/openssl/truncation"
  local suite="aes128-gcm-sha256" group="x25519" sig="ed25519"
  local p log cert fifo peer_pid native_pid
  next_port; p="$port"
  log="$logs/${name//\//_}"
  cert="$(cert_for_signature "$sig")"
  fifo="$workdir/${name//\//_}.fifo"
  mkfifo "$fifo"

  "$tls_tool" server --port "$p" --cert "$cert-cert.pem" --key "$cert-key.pem" \
    --cipher-suite "$suite" --group "$group" --signature "$sig" \
    --alpn http/1.1 --expect fail --expect-error TruncatedStream \
    --expect-peer-close truncated --expect-min-bytes 42 \
    --transcript "$transcripts/${name//\//_}.txt" \
    --timeout-ms 20000 > "$log.native" 2>&1 &
  native_pid=$!
  if ! wait_for_native_listener "$log.native"; then
    kill "$native_pid" 2>/dev/null
    result "$name" FAIL "native listener never came up"
    return
  fi

  "$openssl_bin" s_client -connect "127.0.0.1:$p" \
    -servername tardigrade.test -tls1_3 \
    -ciphersuites "$(openssl_suite "$suite")" -groups "$(openssl_group "$group")" \
    -sigalgs "$(openssl_sigalg "$sig")" -alpn http/1.1 \
    -CAfile "$cert-cert.pem" < "$fifo" > "$log.peer" 2>&1 &
  peer_pid=$!

  exec 3>"$fifo"
  printf 'GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n' >&3
  sleep 1
  kill -KILL "$peer_pid" 2>/dev/null
  exec 3>&-
  wait "$peer_pid" 2>/dev/null
  rm -f "$fifo"

  if wait "$native_pid"; then
    result "$name" PASS "$(grep -o 'error=.*' "$log.native" | head -1)"
  else
    result "$name" FAIL "see $log.native"
  fi
}

# native TLS client -> external server
run_client_row() { # name peer suite group signature [extra native args...]
  local name="$1" peer="$2" suite="$3" group="$4" sig="$5"
  shift 5
  local p log cert peer_pid
  next_port; p="$port"
  log="$logs/${name//\//_}"
  cert="$(cert_for_signature "$sig")"

  case "$peer" in
    openssl)
      "$openssl_bin" s_server -accept "$p" -cert "$cert-cert.pem" -key "$cert-key.pem" \
        -tls1_3 -ciphersuites "$(openssl_suite "$suite")" -groups "$(openssl_group "$group")" \
        -sigalgs "$(openssl_sigalg "$sig")" -alpn http/1.1 -www -naccept 1 > "$log.peer" 2>&1 &
      peer_pid=$!
      wait_for_peer_listener "$log.peer" '^ACCEPT'
      ;;
    gnutls)
      local serv_args=(--port "$p" --http --x509certfile "$cert-cert.pem"
        --x509keyfile "$cert-key.pem" --alpn=http/1.1
        --priority "$(gnutls_priority "$suite" "$group" "$sig")")
      [ -n "$gnutls_recordsize" ] && serv_args+=(--recordsize "$gnutls_recordsize")
      "$gnutls_serv" "${serv_args[@]}" > "$log.peer" 2>&1 &
      peer_pid=$!
      wait_for_peer_listener "$log.peer" 'listening on ipv4'
      ;;
  esac

  "$tls_tool" client --host 127.0.0.1 --port "$p" --pin "$cert-cert.pem" \
    --server-name tardigrade.test \
    --cipher-suite "$suite" --group "$group" --signature "$sig" \
    --alpn http/1.1 --expect-alpn http/1.1 --expect-contains "HTTP/1.0 200" \
    --transcript "$transcripts/${name//\//_}.txt" \
    --timeout-ms 20000 "$@" > "$log.native" 2>&1
  local status=$?

  kill "$peer_pid" 2>/dev/null
  wait "$peer_pid" 2>/dev/null

  if [ $status -eq 0 ]; then
    result "$name" PASS "$(grep -o 'suite=.*' "$log.native" | head -1)"
  else
    result "$name" FAIL "see $log.native"
  fi
}

# Start the native server for a negative row and wait until it is listening.
# Reports the port and PID through globals rather than stdout: a
# `p="$(start_negative_server ...)"` would run the whole function in a
# subshell, so the backgrounded server's PID (and `next_port`'s increment)
# would be lost with that subshell and `finish_negative_row` would have
# nothing to wait on.
negative_native_pid=""
negative_port=""
start_negative_server() { # name expect_alert native_args...
  local name="$1"; shift
  local expect_alert="$1"; shift
  local log
  next_port; negative_port="$port"
  log="$logs/${name//\//_}"

  local native_args=("$@")
  # An unset-vs-empty array expands to nothing under `set -u` on bash 3.2
  # (still the system bash on macOS), so a row with no expected alert is
  # folded into `native_args` rather than expanded as its own empty array.
  if [ -n "$expect_alert" ]; then
    native_args=(--expect-alert "$expect_alert" "${native_args[@]}")
  fi

  "$tls_tool" server --port "$negative_port" --cert "$certs/ed25519-cert.pem" --key "$certs/ed25519-key.pem" \
    --expect fail "${native_args[@]}" \
    --transcript "$transcripts/${name//\//_}.txt" --timeout-ms 20000 > "$log.native" 2>&1 &
  negative_native_pid=$!
  if ! wait_for_native_listener "$log.native"; then
    kill "$negative_native_pid" 2>/dev/null
    negative_native_pid=""
    return 1
  fi
  return 0
}

finish_negative_row() { # name
  local name="$1"
  local log="$logs/${name//\//_}"
  if wait "$negative_native_pid"; then
    result "$name" PASS "$(grep -o 'error=.*' "$log.native" | head -1)"
  else
    result "$name" FAIL "see $log.native"
  fi
  negative_native_pid=""
}

# A negative row driven by an external TLS client. The peer's argv is passed as
# real arguments with the literal token `@PORT@` standing in for this row's
# port -- the port is only known once `start_negative_server` has run, and
# substituting a placeholder keeps the command an argv rather than a string
# handed to a child shell -- no `eval`, no quoting hazard, and no unexpanded
# `$VAR` sitting inside a single-quoted string for a linter to trip over.
run_negative_server_row() { # name expect_alert native_args... -- peer_argv...
  local name="$1"; shift
  local expect_alert="$1"; shift
  local native_args=()
  while [ "$1" != "--" ]; do native_args+=("$1"); shift; done
  shift

  if ! start_negative_server "$name" "$expect_alert" "${native_args[@]}"; then
    result "$name" FAIL "native listener never came up"
    return
  fi

  local peer_argv=()
  local arg
  for arg in "$@"; do peer_argv+=("${arg//@PORT@/$negative_port}"); done
  printf 'x' | "${peer_argv[@]}" > "$logs/${name//\//_}.peer" 2>&1

  finish_negative_row "$name"
}

# A negative row driven by raw bytes on the socket rather than by a TLS client.
# Written from this shell (where the port is an ordinary variable) so there is
# no child-shell indirection at all.
run_raw_record_row() { # name expect_alert byte_string native_args...
  local name="$1"; shift
  local expect_alert="$1"; shift
  local bytes="$1"; shift

  if ! start_negative_server "$name" "$expect_alert" "$@"; then
    result "$name" FAIL "native listener never came up"
    return
  fi

  # shellcheck disable=SC2059 # `bytes` is a printf format supplying \x escapes
  printf "$bytes" > "/dev/tcp/127.0.0.1/$negative_port"

  finish_negative_row "$name"
}

# ── preflight ───────────────────────────────────────────────────────────────

for tool in "$tls_tool" "$h3_tool"; do
  if [ ! -x "$tool" ]; then
    say "building $(basename "$tool")..."
    (cd "$repo" && zig build build-tls-interop build-h3-interop) || {
      say "cannot build the interop tools"; exit 1;
    }
  fi
done

if ! command -v "$openssl_bin" >/dev/null 2>&1; then
  say "openssl is required for the #338 conformance matrix (set OPENSSL_BIN)"
  exit 1
fi
have_gnutls=0
if command -v "$gnutls_cli" >/dev/null 2>&1 && command -v "$gnutls_serv" >/dev/null 2>&1; then
  have_gnutls=1
fi

# The dimension lists come from the engine itself; peer spellings are checked
# against them before a single row runs.
load_capabilities
check_peer_spellings

if [ "$list_only" -eq 1 ]; then
  list_matrix_rows
  exit 0
fi

say "generating interop certificates in $certs"
"$here/gen-certs.sh" "$certs" >/dev/null || { say "certificate generation failed"; exit 1; }

say ""
say "shared-TLS-engine conformance matrix (#338), profile=$profile"
say "workdir: $workdir"
say "openssl: $("$openssl_bin" version)"
if [ "$have_gnutls" -eq 1 ]; then
  say "gnutls:  $("$gnutls_cli" --version | head -1)"
else
  say "gnutls:  not found -- the independent-implementation rows will be skipped"
fi
say ""

# ── 1. positive record-transport matrix, both roles, both peers ─────────────

# Every supported tuple, both roles, in every profile -- #338 requires CI to
# prove positive interop for all of them. Only the second implementation's
# sweep is reduced under `ci`; see `gnutls_row_in_profile`.
say "== record transport: positive tuples =="
for suite in "${suites[@]}"; do
  for group in "${groups[@]}"; do
    for sig in "${signatures[@]}"; do
      tuple="$suite/$group/$sig"
      run_server_row "record/server/openssl/$tuple" openssl "$suite" "$group" "$sig"
      run_client_row "record/client/openssl/$tuple" openssl "$suite" "$group" "$sig"
      if [ "$have_gnutls" -eq 0 ]; then
        result "record/server/gnutls/$tuple" SKIP "gnutls not installed"
        result "record/client/gnutls/$tuple" SKIP "gnutls not installed"
      elif gnutls_row_in_profile "$suite" "$group" "$sig"; then
        run_server_row "record/server/gnutls/$tuple" gnutls "$suite" "$group" "$sig"
        run_client_row "record/client/gnutls/$tuple" gnutls "$suite" "$group" "$sig"
      fi
    done
  done
done

say ""
say "== record transport: HTTP protocol entrypoints =="
# #358: the positive tuple sweep proves HTTP/1.1 application bytes in both
# roles. This row pins the HTTP/2 ALPN entrypoint against OpenSSL too: the
# peer sends the RFC 9113 client connection preface and an empty SETTINGS
# frame after negotiation, and the native server verifies those bytes crossed
# under the negotiated TLS 1.3 application keys.
run_server_alpn_row "record/server/openssl/http2_entrypoint" openssl aes128-gcm-sha256 x25519 ed25519 \
  h2 h2_preface --expect-contains $'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n' \
  --expect-min-bytes 33 --send "tardigrade-h2-interop"

# ── 2. HelloRetryRequest, both roles ────────────────────────────────────────

say ""
say "== record transport: HelloRetryRequest =="
# The peer's first key share is for P-384, a group the native server does not
# accept, so the server must retry with one it does rather than fail
# (`run_server_row` widens the peer's `-groups` for any `--expect-hrr` row).
# This row is what caught the middlebox-compatibility change_cipher_spec
# rejection after HelloRetryRequest (#338).
run_server_row "record/server/openssl/hrr" openssl aes128-gcm-sha256 x25519 ed25519 --expect-hrr
# The native client omits its initial key share, forcing the peer to retry.
run_client_row "record/client/openssl/hrr" openssl aes128-gcm-sha256 x25519 ed25519 \
  --empty-initial-key-share --expect-hrr

# ── 2b. post-handshake KeyUpdate, both roles ────────────────────────────────

say ""
say "== record transport: post-handshake KeyUpdate =="
# #357. Each row makes the native side send one KeyUpdate once the connection
# is open and *before* its application payload, so every application byte in
# the row crosses under the new generation -- a peer that failed to follow the
# transition could not read the exchange at all, and the row fails.
#
# `--key-update requested` also obliges the peer to roll its own sending keys
# and answer with `update_not_requested`. `--expect-key-updates 1` requires
# that answer to have arrived and been applied, which is what exercises the
# *receiving* half against a real implementation rather than against ourselves.
#
# One tuple per role is enough: KeyUpdate advances a traffic secret through the
# negotiated suite's own HKDF, which the positive matrix above already sweeps
# for every suite. What is peer-specific here is the message exchange, not the
# arithmetic.
run_server_row "record/server/openssl/key-update/reciprocal" openssl aes128-gcm-sha256 x25519 ed25519 \
  --key-update requested --expect-key-updates 1
run_client_row "record/client/openssl/key-update/reciprocal" openssl aes128-gcm-sha256 x25519 ed25519 \
  --key-update requested --expect-key-updates 1
# The one-way form: we refresh our sending keys and ask nothing back, so the
# peer must follow the transition without being prompted to make one itself.
run_client_row "record/client/openssl/key-update/one-way" openssl aes128-gcm-sha256 x25519 ed25519 \
  --key-update not-requested

# ── 2c. RFC 8449 record_size_limit, both roles ──────────────────────────────

say ""
say "== record transport: record_size_limit (RFC 8449) =="
# #359. OpenSSL does not implement RFC 8449, but GnuTLS does -- and its
# `--recordsize` makes the peer advertise a non-default limit, so these rows
# assert *negotiated* record sizing against an independent implementation
# rather than against ourselves.
#
# The two rows deliberately cover opposite halves of the RFC, because one
# direction cannot stand in for the other:
#
#   * the server row proves **we honor the peer's** limit -- a 3000-byte
#     response must leave as several records, none larger than the 1025 the
#     peer asked for; and
#   * the client row proves **the peer honors ours** -- we advertise 512, and
#     GnuTLS must fragment its ~780-byte response to fit while still
#     delivering every byte of it.
#
# Both assert on real record sizes, not merely on a completed handshake: a
# row where the extension was silently ignored fails on the size assertions.
if [ "$have_gnutls" -eq 0 ]; then
  result "record/server/gnutls/record-size-limit" SKIP "gnutls not installed"
  result "record/client/gnutls/record-size-limit" SKIP "gnutls not installed"
else
  # Larger than the peer's 1025-byte limit, so it cannot be sent as one record.
  record_size_payload="$(printf 'x%.0s' $(seq 1 3000))"

  # `keep_writing` keeps GnuTLS attached while the response drains: a peer that
  # sends its request and immediately EOFs would close mid-flush and the row
  # would fail on the truncation rather than on record sizing.
  gnutls_recordsize=1024
  run_server_alpn_row "record/server/gnutls/record-size-limit" gnutls \
    aes128-gcm-sha256 x25519 ed25519 http/1.1 keep_writing \
    --record-size-limit 2048 --send "$record_size_payload" \
    --expect-peer-record-size-limit 1025 \
    --expect-max-record-bytes 1025 --expect-min-records-sent 5

  # We advertise 512 while the peer advertises 1025, so both directions are
  # pinned in one row: the peer's value must round-trip to us, and every
  # record it sends must fit the bound we asked for.
  run_client_row "record/client/gnutls/record-size-limit" gnutls \
    aes128-gcm-sha256 x25519 ed25519 \
    --record-size-limit 512 --expect-peer-record-size-limit 1025 \
    --expect-max-received-record-bytes 512 --expect-min-bytes 700
  gnutls_recordsize=""
fi

# #358: shutdown semantics are asserted explicitly because ordinary positive
# rows may complete before observing the peer's terminal close behavior.
run_server_row "record/server/openssl/close_notify" openssl aes128-gcm-sha256 x25519 ed25519 \
  --expect-peer-close clean
run_server_truncation_row

# ── 3. negative conformance rows ────────────────────────────────────────────

say ""
say "== record transport: negative conformance =="

# Each row hands the peer a real argv; `@PORT@` is substituted with that row's
# port by `run_negative_server_row`.
ca="$certs/ed25519-cert.pem"

# RFC 7301 §3.2: no mutually supported protocol is fatal no_application_protocol.
run_negative_server_row "record/negative/alpn_no_overlap" no_application_protocol \
  --alpn h2 -- \
  "$openssl_bin" s_client -connect "127.0.0.1:@PORT@" -servername tardigrade.test \
  -tls1_3 -alpn http/1.1 -CAfile "$ca"

# RFC 8446 Appendix D.2: a ClientHello with no `supported_versions` is a legal
# *legacy* hello, not a malformed one -- the server negotiates
# `min(legacy_version, TLS 1.2)`, has nothing in that range, and per §4.2.1
# aborts with `protocol_version`. Reporting `missing_extension` here would tell
# a perfectly conformant TLS 1.2 client that its hello was malformed.
run_negative_server_row "record/negative/tls12_downgrade" protocol_version \
  --alpn http/1.1 --expect-error UnsupportedProtocolVersion -- \
  "$openssl_bin" s_client -connect "127.0.0.1:@PORT@" -tls1_2 -CAfile "$ca"

# No mutually supported cipher suite: the server has nothing to select.
run_negative_server_row "record/negative/cipher_no_overlap" handshake_failure \
  --cipher-suite chacha20-poly1305-sha256 --alpn http/1.1 --expect-error NoMutualParameters -- \
  "$openssl_bin" s_client -connect "127.0.0.1:@PORT@" -servername tardigrade.test \
  -tls1_3 -ciphersuites TLS_AES_256_GCM_SHA384 -alpn http/1.1 -CAfile "$ca"

# No mutually supported group: neither the offered share nor a retry can help.
run_negative_server_row "record/negative/group_no_overlap" handshake_failure \
  --group x25519 --alpn http/1.1 --expect-error NoMutualParameters -- \
  "$openssl_bin" s_client -connect "127.0.0.1:@PORT@" -servername tardigrade.test \
  -tls1_3 -groups P-384 -alpn http/1.1 -CAfile "$ca"

# No signature scheme the server's Ed25519 credential can satisfy
# (RFC 8446 §4.4.2.2 -> handshake_failure).
run_negative_server_row "record/negative/signature_no_overlap" handshake_failure \
  --signature ed25519 --alpn http/1.1 --expect-error NoApplicableCredential -- \
  "$openssl_bin" s_client -connect "127.0.0.1:@PORT@" -servername tardigrade.test \
  -tls1_3 -sigalgs rsa_pss_rsae_sha256 -alpn http/1.1 -CAfile "$ca"

# A ClientHello with no SNI against a server that requires one. Both the wire
# class and the typed local error are pinned: asserting only "something failed"
# would let a timeout or an unrelated handshake bug keep this row green while
# the SNI policy was never exercised at all.
run_negative_server_row "record/negative/sni_absent" missing_extension \
  --require-sni --alpn http/1.1 --expect-error MissingExtension -- \
  "$openssl_bin" s_client -connect "127.0.0.1:@PORT@" -noservername \
  -tls1_3 -alpn http/1.1 -CAfile "$ca"

# Malformed record ordering: an application_data record arriving before any
# ClientHello must be rejected, not buffered until keys exist. Written straight
# to the socket rather than through a TLS client -- piping these bytes to
# `openssl s_client` would send them as post-handshake application data, which
# is a different (and legal) thing entirely.
run_raw_record_row "record/negative/malformed_ordering" "" '\x17\x03\x03\x00\x05hello' \
  --alpn http/1.1 --allow-absent-alpn --expect-error UnexpectedRecordContent

# A middlebox-compat change_cipher_spec with no ClientHello before it. RFC 8446
# §5.1 only tolerates that record *after* a ClientHello has been accepted, so
# the compatibility window must stay shut here -- the companion to the
# post-HelloRetryRequest widening this change makes.
run_raw_record_row "record/negative/ccs_before_clienthello" "" '\x14\x03\x03\x00\x01\x01' \
  --alpn http/1.1 --allow-absent-alpn --expect-error UnexpectedRecordContent

# The native client must reject a server certificate it did not pin.
negative_client_pin() {
  local p log
  next_port; p="$port"
  log="$logs/record_negative_wrong_pin"
  "$openssl_bin" s_server -accept "$p" -cert "$certs/p256-cert.pem" -key "$certs/p256-key.pem" \
    -tls1_3 -alpn http/1.1 -www -naccept 1 > "$log.peer" 2>&1 &
  local peer_pid=$!
  wait_for_peer_listener "$log.peer" '^ACCEPT'
  # Pins the Ed25519 leaf while the peer presents the P-256 one.
  "$tls_tool" client --host 127.0.0.1 --port "$p" --pin "$certs/ed25519-cert.pem" \
    --server-name tardigrade.test --alpn http/1.1 \
    --expect fail --expect-error CertificateInvalid --expect-alert bad_certificate \
    --transcript "$transcripts/record_negative_wrong_pin.txt" --timeout-ms 20000 > "$log.native" 2>&1
  local status=$?
  kill "$peer_pid" 2>/dev/null; wait "$peer_pid" 2>/dev/null
  if [ $status -eq 0 ]; then
    result "record/negative/wrong_pinned_certificate" PASS "$(grep -o 'error=.*' "$log.native" | head -1)"
  else
    result "record/negative/wrong_pinned_certificate" FAIL "see $log.native"
  fi
}
negative_client_pin

# ── 4. QUIC transport: the same tuples through the same engine ──────────────

# ── 3b. server certificate selection ────────────────────────────────────────

say ""
say "== record transport: server certificate selection =="
# The positive rows above hand the server exactly one identity, so they prove
# the *preselected* certificate works -- they cannot prove the engine would
# have chosen it. These rows give the server all three credentials at once
# through the production SNI/signature-algorithm credential provider and let
# the peer's ClientHello drive the choice, then assert which one the engine
# actually signed with (`--expect-signature`, read back from the engine's own
# `negotiated_signature_scheme`, not from what the harness passed in).

all_identities=(
  --identity "tardigrade.test:$certs/ed25519-cert.pem:$certs/ed25519-key.pem"
  --identity "p256.tardigrade.test:$certs/p256-cert.pem:$certs/p256-key.pem"
  --identity "rsa.tardigrade.test:$certs/rsa2048-cert.pem:$certs/rsa2048-key.pem"
)
# Two credentials under one host name: SNI cannot disambiguate these, so only
# the peer's signature_algorithms offer can.
ambiguous_identities=(
  --identity "tardigrade.test:$certs/ed25519-cert.pem:$certs/ed25519-key.pem"
  --identity "tardigrade.test:$certs/rsa2048-cert.pem:$certs/rsa2048-key.pem"
)

run_selection_row() { # name expect_signature server_args... -- peer_args...
  local name="$1" expect_sig="$2"
  shift 2
  local server_args=()
  while [ "$1" != "--" ]; do server_args+=("$1"); shift; done
  shift
  local p log
  next_port; p="$port"
  log="$logs/${name//\//_}"

  local expect_args=()
  if [ -n "$expect_sig" ]; then
    expect_args=(--expect-signature "$expect_sig")
  else
    # No credential can satisfy the peer: RFC 8446 §4.4.2.2 handshake_failure.
    expect_args=(--expect fail --expect-alert handshake_failure --expect-error NoApplicableCredential)
  fi

  "$tls_tool" server --port "$p" "${server_args[@]}" --alpn http/1.1 \
    "${expect_args[@]}" --transcript "$transcripts/${name//\//_}.txt" \
    --timeout-ms 20000 > "$log.native" 2>&1 &
  local native_pid=$!
  if ! wait_for_native_listener "$log.native"; then
    kill "$native_pid" 2>/dev/null
    result "$name" FAIL "native listener never came up"
    return
  fi

  printf 'GET / HTTP/1.0\r\n\r\n' | "$openssl_bin" s_client -connect "127.0.0.1:$p" \
    -tls1_3 -alpn http/1.1 -CAfile "$certs/ed25519-cert.pem" "$@" > "$log.peer" 2>&1

  if wait "$native_pid"; then
    result "$name" PASS "$(grep -o 'signature=[^ ]*\|error=.*' "$log.native" | head -1)"
  else
    result "$name" FAIL "see $log.native"
  fi
}

# SNI picks the credential: three names, three key types, one server.
run_selection_row "record/selection/sni_ed25519" ed25519 \
  "${all_identities[@]}" -- -servername tardigrade.test
run_selection_row "record/selection/sni_ecdsa_p256" ecdsa-p256-sha256 \
  "${all_identities[@]}" -- -servername p256.tardigrade.test
run_selection_row "record/selection/sni_rsa" rsa-pss-rsae-sha256 \
  "${all_identities[@]}" -- -servername rsa.tardigrade.test

# An SNI matching no bundle falls back to the default (first) credential
# rather than failing, which is the configured `unknown_sni_policy`.
run_selection_row "record/selection/unknown_sni_uses_default" ed25519 \
  "${all_identities[@]}" -- -servername nobody.tardigrade.test

# signature_algorithms picks the credential when SNI cannot: same host name,
# two key types, and only the peer's offer distinguishes them.
run_selection_row "record/selection/sigalgs_ed25519" ed25519 \
  "${ambiguous_identities[@]}" -- -servername tardigrade.test -sigalgs ed25519
run_selection_row "record/selection/sigalgs_rsa_pss" rsa-pss-rsae-sha256 \
  "${ambiguous_identities[@]}" -- -servername tardigrade.test -sigalgs rsa_pss_rsae_sha256

# No credential the peer can verify: neither identity signs with ECDSA-P256.
run_selection_row "record/selection/no_applicable_credential" "" \
  "${ambiguous_identities[@]}" -- -servername tardigrade.test -sigalgs ecdsa_secp256r1_sha256

say ""
say "== QUIC transport: the same tuples =="
# The record rows above and these QUIC rows share one policy builder
# (tests/tls_interop_matrix.zig), so a tuple name means the same engine
# configuration on either transport. External QUIC peers (ngtcp2, quiche,
# aioquic) have their own richer H3 matrix in run-interop.sh; here we prove the
# negotiation tuple itself traverses the QUIC transport.
run_quic_row() { # suite group signature
  local suite="$1" group="$2" sig="$3"
  local name="quic/loopback/$suite/$group/$sig"
  local p log cert
  next_port; p="$port"
  log="$logs/${name//\//_}"
  cert="$(cert_for_signature "$sig")"

  "$h3_tool" server --port "$p" --cert "$cert-cert.pem" --key "$cert-key.pem" \
    --cipher-suite "$suite" --group "$group" --signature "$sig" \
    --timeout-ms 20000 > "$log.server" 2>&1 &
  local server_pid=$!
  sleep 1
  "$h3_tool" client --host 127.0.0.1 --port "$p" --pin "$cert-cert.der" \
    --cipher-suite "$suite" --group "$group" --signature "$sig" \
    --timeout-ms 20000 > "$log.client" 2>&1
  local status=$?
  wait "$server_pid"
  local server_status=$?
  if [ $status -eq 0 ] && [ $server_status -eq 0 ]; then
    result "$name" PASS "$(grep -o 'suite=.*' "$log.client" | head -1)"
  else
    result "$name" FAIL "see $log.client / $log.server"
  fi
}

# Every tuple on QUIC too, in both profiles: the transport is the dimension
# this section exists to cover, so thinning it would leave the "both transports
# exercise the same engine" claim resting on a subset.
for suite in "${suites[@]}"; do
  for group in "${groups[@]}"; do
    for sig in "${signatures[@]}"; do
      # Ed25519 is not offered by every QUIC peer's default verifier, but the
      # loopback rows pin the leaf directly, so every signature is reachable.
      run_quic_row "$suite" "$group" "$sig"
    done
  done
done

if [ -n "${NGTCP2_EXAMPLES_DIR:-}" ]; then
  say ""
  say "external QUIC peers are configured; run scripts/interop/run-interop.sh"
  say "for the full H3 peer matrix (ngtcp2/quiche/aioquic, both directions)."
fi

# ── summary ─────────────────────────────────────────────────────────────────

say ""
say "----------------------------------------------------------------"
printf 'pass=%d fail=%d skip=%d\n' "$pass" "$fail" "$skip"
say "logs:        $logs"
say "transcripts: $transcripts"
if [ "$fail" -gt 0 ]; then
  say ""
  say "failed rows:"
  for row in "${failed_rows[@]}"; do say "  $row"; done
  exit 1
fi
exit 0

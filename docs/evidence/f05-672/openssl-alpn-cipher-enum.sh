#!/usr/bin/env sh
set -eu

OPENSSL_BIN="${OPENSSL_BIN:-openssl}"
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-18443}"
SNI="${SNI:-tardigrade.test}"
ALPN="${ALPN:-http/1.1}"

run_probe() {
    name="$1"
    shift
    printf '\n## %s\n' "$name"
    printf '$'
    for arg in "$@"; do
        printf ' %s' "$arg"
    done
    printf '\n'
    if "$@" </dev/null 2>&1; then
        printf 'RESULT: success\n'
    else
        code="$?"
        printf 'RESULT: failure exit=%s\n' "$code"
    fi
}

printf '# OpenSSL ALPN cipher/protocol enumeration\n'
printf 'openssl=%s\n' "$("$OPENSSL_BIN" version)"
printf 'target=%s:%s\n' "$HOST" "$PORT"
printf 'sni=%s\n' "$SNI"
printf 'alpn=%s\n' "$ALPN"

printf '\n# Local TLS 1.3 ciphersuites enumerated by OpenSSL\n'
"$OPENSSL_BIN" ciphers -tls1_3 -stdname -s -V

run_probe tls13_tls_aes_256_gcm_sha384 \
    "$OPENSSL_BIN" s_client -connect "$HOST:$PORT" -tls1_3 \
    -servername "$SNI" -alpn "$ALPN" \
    -ciphersuites TLS_AES_256_GCM_SHA384 -brief

run_probe tls13_tls_chacha20_poly1305_sha256 \
    "$OPENSSL_BIN" s_client -connect "$HOST:$PORT" -tls1_3 \
    -servername "$SNI" -alpn "$ALPN" \
    -ciphersuites TLS_CHACHA20_POLY1305_SHA256 -brief

run_probe tls13_tls_aes_128_gcm_sha256 \
    "$OPENSSL_BIN" s_client -connect "$HOST:$PORT" -tls1_3 \
    -servername "$SNI" -alpn "$ALPN" \
    -ciphersuites TLS_AES_128_GCM_SHA256 -brief

run_probe tls12 \
    "$OPENSSL_BIN" s_client -connect "$HOST:$PORT" -tls1_2 \
    -servername "$SNI" -alpn "$ALPN" -brief

run_probe tls11 \
    "$OPENSSL_BIN" s_client -connect "$HOST:$PORT" -tls1_1 \
    -servername "$SNI" -brief

run_probe tls10 \
    "$OPENSSL_BIN" s_client -connect "$HOST:$PORT" -tls1 \
    -servername "$SNI" -brief

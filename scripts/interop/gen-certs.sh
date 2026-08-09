#!/bin/sh
# Generate the interop test certificates (#247, #338): one Ed25519 identity
# (the native stack's default profile; accepted by GnuTLS/OpenSSL peers), one
# ECDSA P-256 identity (required by BoringSSL-based peers such as quiche,
# whose default verifier does not offer Ed25519), and one RSA-2048 identity
# (the credential the `rsa-pss-rsae-sha256` rows of the #338 conformance
# matrix need; 2048 bits keeps the DER leaf inside the engine's
# `max_certificate_len`).
#
# The signature dimension of the matrix picks which of these a row uses --
# see `identityKeyForSignature` in tests/tls_interop_matrix.zig.
#
# usage: gen-certs.sh OUT_DIR
set -eu

out="${1:?usage: gen-certs.sh OUT_DIR}"
mkdir -p "$out"

# Each identity also carries a per-key-type SAN (`ed25519.tardigrade.test`,
# ...). #338's certificate-selection rows drive the engine's SNI selector by
# connecting with those names, and a certificate that did not actually assert
# the name it was selected for would make the row prove less than it looks.
gen() { # name extra-san algo-args...
  name="$1"
  extra_san="$2"
  shift 2
  openssl genpkey "$@" -out "$out/$name-key.pem" 2>/dev/null
  openssl req -new -x509 -key "$out/$name-key.pem" -out "$out/$name-cert.pem" -days 30 \
    -subj "/CN=tardigrade.test" \
    -addext "subjectAltName=DNS:tardigrade.test,DNS:$extra_san,IP:127.0.0.1" 2>/dev/null
  openssl x509 -in "$out/$name-cert.pem" -outform DER -out "$out/$name-cert.der"
  openssl pkcs8 -topk8 -nocrypt -in "$out/$name-key.pem" -outform DER -out "$out/$name-key.pkcs8.der"
}

gen ed25519 ed25519.tardigrade.test -algorithm ed25519
gen p256 p256.tardigrade.test -algorithm EC -pkeyopt ec_paramgen_curve:P-256
gen rsa2048 rsa.tardigrade.test -algorithm RSA -pkeyopt rsa_keygen_bits:2048

echo "certificates written to $out"

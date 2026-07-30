#!/usr/bin/env sh
set -eu

ROOT="${1:-.}"

cd "$ROOT"

if ! command -v rg >/dev/null 2>&1; then
    printf '%s\n' "audit-crypto-boundary: ripgrep (rg) is required but not found in PATH" >&2
    exit 1
fi

status=0

check_file() {
    file="$1"
    pattern="$2"
    rationale="$3"
    if rg -n "$pattern" "$file" >/tmp/tardigrade-crypto-boundary.$$ 2>/dev/null; then
        printf '%s\n' "disallowed direct keyed crypto in $file"
        cat /tmp/tardigrade-crypto-boundary.$$
        printf '%s\n' "rationale: $rationale"
        status=1
    fi
    rm -f /tmp/tardigrade-crypto-boundary.$$
}

# Protocol modules must not add new concrete keyed crypto dependencies. Keep
# public transcript hashing, parsing, nonce arithmetic, and shared secret
# containers out of this grep; those are reviewed separately by code owners.
# AES block-cipher construction, matched everywhere below: the exact form
# QUIC header protection uses (`crypto.core.aes.Aes128` / `Aes128.initEnc`),
# not just the AEAD encrypt/decrypt entry points.
aes_block_pattern="Aes[0-9]+\\.initEnc|crypto\\.core\\.aes\\."

check_file "src/quic/connection.zig" \
    "std\\.crypto\\.(aead|auth|dh|sign|kdf)|crypto\\.(aead|auth|dh|sign|kdf)|Aes[0-9]+Gcm\\.(encrypt|decrypt)|ChaCha20Poly1305\\.(encrypt|decrypt)|X25519\\.|Ed25519\\.|Ecdsa|Rsa|hkdfExpandLabel\\(|$aes_block_pattern" \
    "QUIC connection logic owns framing, packet numbers, and nonce arithmetic only; keyed crypto belongs to src/quic/tls_adapter.zig through CryptoProvider."

check_file "src/quic/packet.zig" \
    "std\\.crypto\\.(auth|dh|sign|kdf)|crypto\\.(auth|dh|sign|kdf)|ChaCha20Poly1305\\.(encrypt|decrypt)|X25519\\.|Ed25519\\.|Ecdsa|Rsa|hkdfExpandLabel\\(|$aes_block_pattern" \
    "QUIC packet parsing/encoding is public protocol logic. The existing AES-GCM Retry integrity test vector is allowed because RFC 9001 fixes the public key/nonce and it is not packet-protection key material."

check_file "src/quic/path.zig" \
    "std\\.crypto\\.(dh|sign|kdf)|crypto\\.(dh|sign|kdf)|X25519\\.|Ed25519\\.|Ecdsa|Rsa|hkdfExpandLabel\\(|$aes_block_pattern" \
    "QUIC path validation may use public constants and existing token/retry exceptions, but must not add key exchange, signatures, or KDF shortcuts."

if rg -n "std\\.crypto\\.(aead|dh|sign|kdf)|crypto\\.(aead|dh|sign|kdf)|Aes[0-9]+Gcm\\.(encrypt|decrypt)|ChaCha20Poly1305\\.(encrypt|decrypt)|X25519\\.|Ed25519\\.|Ecdsa|Rsa|hkdfExpandLabel\\(|$aes_block_pattern" src/quic \
    --glob '*.zig' --glob '!tls_adapter.zig' --glob '!tls_handshake.zig' --glob '!path.zig' --glob '!connection.zig' --glob '!packet.zig' >/tmp/tardigrade-crypto-boundary.$$ 2>/dev/null; then
    printf '%s\n' "disallowed direct keyed crypto in QUIC protocol modules outside the allowlist"
    cat /tmp/tardigrade-crypto-boundary.$$
    status=1
fi
rm -f /tmp/tardigrade-crypto-boundary.$$

exit "$status"

# Native crypto ownership audit (#490)

This audit records the current disposition for direct cryptographic operations
in native TLS, QUIC, PKI, resumption, and composition roots. The rule is:
provider-owned keyed operations cross `crypto.provider.CryptoProvider`; direct
protocol code is limited to public parsing/framing, unkeyed transcript hashing,
fixed public constants, and documented temporary exceptions.

| Area | Direct operation class | Disposition |
| --- | --- | --- |
| `src/crypto/` | crypto implementation internals | Allowed. Concrete `std.crypto` use lives behind `CryptoProvider`, `SigningKey`, or shared secret helpers. |
| `src/quic/tls_adapter.zig` | provider-owned keyed crypto | Live for QUIC packet protection. `QuicTlsAdapter` owns a `CryptoProvider` (defaulted to the pure-Zig backend) and every send/receive path — key derivation, AEAD seal/open, key updates, and AES-128 header protection apply/remove — calls the `*WithProvider` entry points. The non-provider free functions and `PacketProtectionKeys` methods remain only for differential test vectors (`tests/crypto_vectors.zig`, `tests/crypto_openssl_diff.zig`), not the live path. |
| `src/quic/connection.zig` / `packet.zig` | public protocol logic | Allowed only for framing, packet-number reconstruction, nonce XOR arithmetic, and public Retry formatting. New keyed AEAD/KDF/ECDH/signature shortcuts are blocked by `scripts/audit-crypto-boundary.sh`. |
| `src/quic/path.zig` | temporary exception | Existing address-validation tokens and Retry integrity use AES-GCM with process keys or RFC-fixed public constants. They are allowlisted pending a provider-backed token-protection follow-up; no key exchange, signing, or KDF shortcuts may be added there. |
| `src/quic/tls_handshake.zig` | test backend fixture | Allowed. The in-memory handshake test backend uses deterministic transcript/HKDF fixtures and is excluded from the QUIC protocol guard. |
| `src/tls/key_schedule.zig` | provider-owned keyed crypto plus provider-independent transcript hashing | Open follow-up. Secret-bearing TLS HKDF/Finished paths are explicitly classified for migration to the provider/security seam; transcript hashing may remain provider-independent if kept unkeyed. |
| `src/tls/record_protection.zig`, `ticket_protection.zig`, resumption runtime | provider-owned keyed crypto | Provider-owned. Record AEAD and stateless ticket protection consume provider/security abstractions; unsupported-provider test doubles carry complete provider vtables. |
| `src/pki/` | signature verification and public DER parsing | Provider-owned for signature verification; public DER/name/policy parsing remains protocol-local. |
| Native TLS/HTTP/QUIC composition roots | provider selection and OpenSSL policy | Allowed to construct concrete providers and backends. Native appliance paths stay OpenSSL/libcrypto-free; general-purpose OpenSSL TLS and out-of-process OpenSSL oracles remain separate roles. |

The automated guard is intentionally narrow and deterministic. It is not a
semantic proof; it prevents accidental reintroduction of obvious concrete AEAD,
KDF, ECDH, and signature shortcuts in QUIC protocol modules and forces any new
exception to be reviewed in this document and the script allowlist.

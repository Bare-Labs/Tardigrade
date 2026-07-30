# Native crypto ownership audit (#490)

This audit records the current disposition for direct cryptographic operations
in native TLS, QUIC, PKI, resumption, and composition roots. The rule is:
provider-owned keyed operations cross `crypto.provider.CryptoProvider`; direct
protocol code is limited to public parsing/framing, unkeyed transcript hashing,
fixed public constants, and documented temporary exceptions.

| Area | Direct operation class | Disposition |
| --- | --- | --- |
| `src/crypto/` | crypto implementation internals | Allowed. Concrete `std.crypto` use lives behind `CryptoProvider`, `SigningKey`, or shared secret helpers. |
| `src/quic/tls_adapter.zig` | provider-owned keyed crypto | Live for QUIC packet protection, and provider-neutral: `QuicTlsAdapter` never names a concrete backend (no `crypto.pure_zig` import). `provider: CryptoProvider` is a required field with no default, set only through `init`/`setProvider`, both of which reject a provider missing the fixed profile's required capabilities (SHA-256, AES-128-GCM, AES-128 header protection). Every send/receive path — key derivation, AEAD seal/open, key updates, header protection apply/remove — calls the `*WithProvider` entry points. The non-provider free functions and `PacketProtectionKeys` methods remain only for differential test vectors (`tests/crypto_vectors.zig`, `tests/crypto_openssl_diff.zig`) and the `testOnlyDefaultProvider` used by unit-test fixtures across `src/quic/` that exercise the seam without a composition root; neither is reachable from the live path. |
| `src/quic/connection.zig` / `packet.zig` | public protocol logic | Allowed only for framing, packet-number reconstruction, nonce XOR arithmetic, and public Retry formatting. New keyed AEAD/KDF/ECDH/signature shortcuts, the AES block-cipher form (`crypto.core.aes.`/`Aes128.initEnc`), and the legacy `tls_adapter` wrapper call names are all blocked by `scripts/audit_crypto_boundary.zig`. |
| `src/quic/path.zig` | temporary exception | Existing address-validation tokens and Retry integrity use AES-GCM with process keys or RFC-fixed public constants. They are allowlisted pending a provider-backed token-protection follow-up; no key exchange, signing, KDF, or AES block-cipher shortcuts may be added there. |
| `src/quic/cid.zig` | temporary exception | Stateless-reset-token derivation (RFC 9000 §10.3.1) is HMAC-SHA256 under a static process-lifetime key (`statelessResetToken`) — the same shape as `path.zig`'s exception: a keyed local derivation outside the TLS/QUIC-negotiated packet-protection suite, not a `CryptoProvider` capability. Allowlisted for `std.crypto.auth.`/HMAC only; no AEAD, ECDH, signature, KDF, or AES block-cipher shortcuts may be added there. |
| `src/quic/tls_handshake.zig` | test backend fixture | Allowed. The in-memory handshake test backend uses deterministic transcript/HKDF fixtures and is excluded from the QUIC protocol guard. |
| `src/tls/key_schedule.zig` | provider-owned keyed crypto plus provider-independent transcript hashing | Open follow-up. Secret-bearing TLS HKDF/Finished paths are explicitly classified for migration to the provider/security seam; transcript hashing may remain provider-independent if kept unkeyed. |
| `src/tls/tls13_backend.zig` | provider-owned keyed crypto | Open follow-up. The TLS 1.3 handshake engine still generates its X25519 key share (`X25519.KeyPair.generateDeterministic`) and verifies/signs CertificateVerify directly rather than through `CryptoProvider.generateKeyShare`/`.verify`; PKI chain-signature verification (`src/pki/verify.zig`) already goes through the provider. |
| `src/tls/record_protection.zig`, `ticket_protection.zig`, resumption runtime | provider-owned keyed crypto | Provider-owned. Record AEAD and stateless ticket protection consume provider/security abstractions; unsupported-provider test doubles carry complete provider vtables. |
| `src/pki/` | signature verification and public DER parsing | Provider-owned for signature verification; public DER/name/policy parsing remains protocol-local. |
| Native TLS/HTTP/QUIC composition roots | provider selection and OpenSSL policy | Allowed to construct concrete providers and backends — this is the only place permitted to choose one. `src/http/http3_runtime.zig`'s `Runtime` is the native QUIC/H3 composition root: it owns the pure-Zig `CryptoProvider` (fed by OS entropy) and injects it into every `Connection.Options.crypto_provider`. Native appliance paths stay OpenSSL/libcrypto-free; general-purpose OpenSSL TLS and out-of-process OpenSSL oracles remain separate roles. |

The automated guard (`scripts/audit_crypto_boundary.zig`, run via
`zig build audit-crypto-boundary`) is a small checked-in Zig program, not a
shell script shelling out to an ambient tool like `rg` — every CI runner
enforces it identically with nothing extra to install. It is intentionally
narrow and deterministic, not a semantic proof: it prevents accidental
reintroduction of obvious concrete AEAD/KDF/ECDH/signature shortcuts and the
AES block-cipher form in QUIC protocol modules, and separately blocks the
concrete legacy `tls_adapter` wrapper call names (`sealPayload`,
`openPayload`, `applyHeaderProtection`, `removeHeaderProtection`,
`headerProtectionMask`, `deriveAes128GcmKeys`, `deriveInitialSecretsV1`,
`deriveNextGenerationSecret`) from the live runtime modules that migrated onto
the `*WithProvider` entry points, so reverting that migration fails the audit
even though the names themselves remain approved inside `tls_adapter.zig` as
differential-test fixtures. It forces any new exception to be reviewed in
this document and the tool's allowlist, and its own fixture tests
(`zig build audit-crypto-boundary` runs them) prove each bypass class it
exists to catch actually fails the audit.

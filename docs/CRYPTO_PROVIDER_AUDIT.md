# Native crypto ownership audit (#490)

This audit records the current disposition for direct cryptographic operations
in native TLS, QUIC, PKI, resumption, and composition roots. The rule is:
provider-owned keyed operations cross `crypto.provider.CryptoProvider`; direct
protocol code is limited to public parsing/framing, unkeyed transcript hashing,
fixed public constants, and documented temporary exceptions.

| Area | Direct operation class | Disposition |
| --- | --- | --- |
| `src/crypto/` | crypto implementation internals | Allowed. Concrete `std.crypto` use lives behind `CryptoProvider`, `SigningKey`, or shared secret helpers. |
| `src/quic/tls_adapter.zig` | provider-owned keyed crypto | Live for QUIC packet protection, and provider-neutral: `QuicTlsAdapter` never names a concrete backend (no `crypto.pure_zig` import). `provider: CryptoProvider` is a required field with no default, set only through `init`/`setProvider`, both of which reject a provider missing the fixed profile's required capabilities (SHA-256, AES-128-GCM, AES-128 header protection). Every send/receive path — key derivation, AEAD seal/open, key updates, header protection apply/remove — calls the `*WithProvider` entry points. The non-provider free functions and `PacketProtectionKeys` methods remain only for differential test vectors (`tests/crypto_vectors.zig`, `tests/crypto_openssl_diff.zig`). Concrete backend selection for tests/tools lives in `tests/support/quic_crypto.zig`, not here — this file has no comptime-constant pure-Zig provider of its own. This file is fully scanned by `scripts/audit_crypto_boundary.zig` like any other: only the three type aliases the legacy fixtures are built on (`HkdfSha256`, `Aes128Gcm`, `Aes128`), the eight named legacy functions/methods themselves (`sealPayload`, `openPayload`, `headerProtectionMask`, `applyHeaderProtection`, `removeHeaderProtection`, `deriveInitialSecretsV1`, `deriveAes128GcmKeys`, `deriveNextGenerationSecret`), and the differential-vector test region after `const testing = std.testing;` are exempted. Every canonical `QuicTlsAdapter` method and every `*WithProvider` entry point is scanned like ordinary production code, so both a canonical method reverting to a legacy call *and* a `*WithProvider` implementation silently delegating to its own legacy sibling fail the audit. |
| `src/quic/connection.zig` | public protocol logic | Fully scanned, no exceptions. Allowed only for framing, packet-number reconstruction, nonce XOR arithmetic, and public Retry formatting. New keyed AEAD/KDF/ECDH/signature shortcuts, the AES block-cipher form (`crypto.core.aes.`/`Aes128.initEnc`), and the legacy `tls_adapter` wrapper call names are all blocked by `scripts/audit_crypto_boundary.zig`. |
| `src/quic/packet.zig` | public protocol logic plus one named exception | Fully scanned except `computeRetryIntegrityTag`'s own body (public RFC 9001 Retry-integrity key/nonce, not packet-protection key material). No other function in the file may add keyed crypto. |
| `src/quic/path.zig` | public protocol logic plus named exceptions | Fully scanned except the top-level `Aes128Gcm` type alias and the bodies of `issueRetry`, `validateRetry`, `retryIntegrityTag`, and the test helper `sealTokenPlaintextForTest` — existing address-validation tokens and Retry integrity use AES-GCM with process keys or RFC-fixed public constants. Allowlisted pending a provider-backed token-protection follow-up; no key exchange, signing, KDF, or AES block-cipher shortcuts, and no *new* AEAD use, may be added anywhere else in the file. |
| `src/quic/cid.zig` | temporary exception | Fully scanned except the top-level `HmacSha256` type alias. Stateless-reset-token derivation (RFC 9000 §10.3.1) is HMAC-SHA256 under a static process-lifetime key (`statelessResetToken`) — the same shape as `path.zig`'s exception: a keyed local derivation outside the TLS/QUIC-negotiated packet-protection suite, not a `CryptoProvider` capability. No AEAD, ECDH, signature, KDF, or AES block-cipher shortcuts, and no *new* HMAC use, may be added anywhere else in the file. |
| `src/quic/tls_handshake.zig` | backend-agnostic driver plus test backend fixture | Fully scanned except the top-level `HkdfSha256` type alias: the in-memory `TestTlsBackend` test fixture builds a deterministic transcript hash with `std.crypto.kdf.hkdf.HkdfSha256` directly (it stands in for a TLS engine rather than driving one). The production `Handshake`/`CoreDriver` code sharing this file has no keyed-crypto dependency of its own; every other forbidden category, including the legacy `tls_adapter` wrapper call names and any *other* KDF use, is still blocked here. |
| `src/tls/key_schedule.zig` | provider-owned keyed crypto plus provider-independent transcript hashing | Open follow-up. Secret-bearing TLS HKDF/Finished paths are explicitly classified for migration to the provider/security seam; transcript hashing may remain provider-independent if kept unkeyed. |
| `src/tls/tls13_backend.zig` | provider-owned keyed crypto | Open follow-up. The TLS 1.3 handshake engine still generates its X25519 key share (`X25519.KeyPair.generateDeterministic`) and verifies/signs CertificateVerify directly rather than through `CryptoProvider.generateKeyShare`/`.verify`; PKI chain-signature verification (`src/pki/verify.zig`) already goes through the provider. |
| `src/tls/record_protection.zig`, `ticket_protection.zig`, resumption runtime | provider-owned keyed crypto | Provider-owned. Record AEAD and stateless ticket protection consume provider/security abstractions; unsupported-provider test doubles carry complete provider vtables. |
| `src/pki/` | signature verification and public DER parsing | Provider-owned for signature verification; public DER/name/policy parsing remains protocol-local. |
| Native TLS/HTTP/QUIC composition roots | provider selection and OpenSSL policy | Allowed to construct concrete providers and backends — this is the only place permitted to choose one. `src/http/http3_runtime.zig`'s `Runtime` is the native QUIC/H3 composition root: it owns the pure-Zig `CryptoProvider` (fed by OS entropy) and injects it into every `Connection.Options.crypto_provider`. It is otherwise fully scanned like `connection.zig` — the composition root may select/construct a provider, but must not perform packet crypto itself. Native appliance paths stay OpenSSL/libcrypto-free; general-purpose OpenSSL TLS and out-of-process OpenSSL oracles remain separate roles. |
| `tests/support/quic_crypto.zig` | test-only concrete provider | Owns the pure-Zig provider singleton used by QUIC/H3 tests and tools that exercise the seam without the native `Runtime` composition root. `build.zig` wires it into `src/quic/`, `src/http/http3_runtime.zig`, and the QUIC/H3 test tools so their `test` blocks and test-only fixtures can reach it, but no production (non-test) code path may reference it — `scripts/audit_crypto_boundary.zig` checks that every `test_quic_crypto.` usage in those files falls after the file's test boundary (`const testing = std.testing;`, or the first `test "..."` block where that marker doesn't exist). |

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
differential-test fixtures.

Every approved exception is narrow and named (#490 fourth-pass review): a
specific function/method body or an exact top-level declaration, blanked out
of a scratch copy of the file before the rest of that file is scanned in
full against the complete forbidden-pattern set — never a whole pattern
category omitted from a file's forbidden list, which would silently allow a
*second*, unrelated use of that category anywhere else new in the file. This
is what lets `tls_adapter.zig` itself be scanned like any other file:
naming its eight legacy functions/methods and three type aliases as
exceptions (plus exempting the differential-vector test region after
`const testing = std.testing;`) means every canonical `QuicTlsAdapter` method
*and* every `*WithProvider` implementation is scanned for both the legacy
wrapper names and the raw concrete primitives, catching a regression in
either direction without naming either set of functions explicitly.

Directory-wide scans (`src/quic`) walk recursively, so a new nested
subdirectory gets no free pass, and exclusions are matched by exact
root-relative path rather than basename, so a nested file that happens to
reuse an excluded name (e.g. `src/quic/nested/connection.zig`) is not
exempt. Every explicitly named protected file/function fails closed if it
goes missing (a rename or deletion is itself a violation, not a silent
pass). It forces any new exception to be reviewed in this document and the
tool's allowlist, and its own fixture tests (`zig build audit-crypto-boundary`
runs them) prove each bypass class it exists to catch actually fails the
audit, including the narrow-exception-doesn't-cover-a-second-call-site,
missing-file, and nested-directory cases above. This is a source-audit
build tool, not part of the shipped product, so it (and its `zig_compat`
dependency) are always built for the build host — not whatever `-Dtarget`
the rest of the build graph is cross-compiling for.

# Native crypto ownership audit (#490)

This audit records the current disposition for direct cryptographic operations
in native TLS, QUIC, PKI, resumption, and composition roots. The rule is:
provider-owned keyed operations cross `crypto.provider.CryptoProvider`; direct
protocol code is limited to public parsing/framing, unkeyed transcript hashing,
fixed public constants, and documented temporary exceptions.

| Area | Direct operation class | Disposition |
| --- | --- | --- |
| `src/crypto/` | crypto implementation internals | Allowed. Concrete `std.crypto` use lives behind `CryptoProvider`, `SigningKey`, or shared secret helpers. |
| `src/quic/tls_adapter.zig` | provider-owned keyed crypto | Live for QUIC packet protection, and provider-neutral: `QuicTlsAdapter` never names a concrete backend (no `crypto.pure_zig` import). `provider: CryptoProvider` is a required field with no default, set only through `init`/`setProvider`, both of which reject a provider missing the RFC-fixed Initial profile plus every negotiated QUIC packet-protection profile (SHA-256/SHA-384 HKDF, AES-128-GCM/AES-256-GCM/ChaCha20-Poly1305 AEAD, and AES-128/AES-256/ChaCha20 header protection). Every send/receive path — key derivation, AEAD seal/open, key updates, header protection apply/remove — calls the `*WithProvider` entry points and selects non-Initial algorithms from explicit TLS negotiated-parameter metadata, not from secret length guesses. The non-provider free functions and `PacketProtectionKeys` methods remain only for differential test vectors (`tests/crypto_vectors.zig`, `tests/crypto_openssl_diff.zig`). Concrete backend selection for tests/tools lives in `tests/support/quic_crypto.zig`, not here — this file has no comptime-constant pure-Zig provider of its own. This file is fully scanned by `scripts/audit_crypto_boundary.zig` like any other: only the three type aliases the legacy fixtures are built on (`HkdfSha256`, `Aes128Gcm`, `Aes128`), the eight named legacy functions/methods themselves (`sealPayload`, `openPayload`, `headerProtectionMask`, `applyHeaderProtection`, `removeHeaderProtection`, `deriveInitialSecretsV1`, `deriveAes128GcmKeys`, `deriveNextGenerationSecret`), and the differential-vector test region after `const testing = std.testing;` are exempted. Every canonical `QuicTlsAdapter` method and every `*WithProvider` entry point is scanned like ordinary production code, so both a canonical method reverting to a legacy call *and* a `*WithProvider` implementation silently delegating to its own legacy sibling fail the audit. |
| `src/quic/connection.zig` | public protocol logic | Fully scanned, no exceptions. Allowed only for framing, packet-number reconstruction, nonce XOR arithmetic, and public Retry formatting. New keyed AEAD/KDF/ECDH/signature shortcuts, the AES block-cipher form (`crypto.core.aes.`/`Aes128.initEnc`), and the legacy `tls_adapter` wrapper call names are all blocked by `scripts/audit_crypto_boundary.zig`. |
| `src/quic/packet.zig` | public protocol logic plus one named exception | Fully scanned except `computeRetryIntegrityTag`'s own body, the single RFC 9001 Retry-integrity implementation (public fixed key/nonce, not packet-protection key material). No other function in the file may add keyed crypto. |
| `src/quic/path.zig` | public protocol logic plus named exceptions | Fully scanned except the top-level `Aes128Gcm` type alias and the bodies of `issueRetry`, `validateRetry`, and the test helper `sealTokenPlaintextForTest` — existing address-validation tokens use AES-GCM with process keys. Retry integrity tag construction and verification live only in `src/quic/packet.zig`. Allowlisted pending a provider-backed token-protection follow-up; no key exchange, signing, KDF, or AES block-cipher shortcuts, and no *new* AEAD use, may be added anywhere else in the file. |
| `src/quic/cid.zig` | temporary exception | Fully scanned except the top-level `HmacSha256` type alias and `statelessResetToken`'s own body. Stateless-reset-token derivation (RFC 9000 §10.3.1) is HMAC-SHA256 under a static process-lifetime key — the same shape as `path.zig`'s exception: a keyed local derivation outside the TLS/QUIC-negotiated packet-protection suite, not a `CryptoProvider` capability. The forbidden set also includes the bare alias name `HmacSha256.` (not only the fully-qualified `std.crypto.auth.` spelling blanking the alias declaration would otherwise leave unconstrained), so no AEAD, ECDH, signature, KDF, AES block-cipher, or *other* `HmacSha256` use may be added anywhere else in the file. |
| `src/quic/tls_handshake.zig` | backend-agnostic driver plus test backend fixture | Fully scanned except the top-level `HkdfSha256` type alias and `TestTlsBackend.deriveSecret`'s own body: the in-memory test fixture builds a deterministic transcript hash with `std.crypto.kdf.hkdf.HkdfSha256` directly (it stands in for a TLS engine rather than driving one). The production `Handshake`/`CoreDriver` code sharing this file has no keyed-crypto dependency of its own. The forbidden set also includes the bare alias name `HkdfSha256.`, so every other forbidden category, including the legacy `tls_adapter` wrapper call names and any *other* KDF use, is still blocked throughout the file. |
| `src/tls/key_schedule.zig` | provider-owned keyed crypto plus provider-independent transcript hashing | Provider-owned. Every secret-bearing HKDF operation — HKDF-Extract, HKDF-Expand-Label, the early/handshake/master/resumption/PSK/client-early-traffic derivations, and Finished `verify_data` (expressed as `HKDF-Extract(salt = finished_key, ikm = transcript_hash)` per RFC 5869, rather than adding a generic HMAC entry point) — crosses `crypto.provider.CryptoProvider`, held on `KeySchedule` (or passed explicitly to the free functions resumption/ticket code calls before a `KeySchedule` exists). Unkeyed transcript hashing (`Sha256.hash` for the comptime empty-transcript constant) stays provider-independent by design. `derived_early_secret` — the zero-PSK schedule's fixed "derived" early secret, a public constant with no connection-specific secret input — is the one documented comptime exception, scanned by `scripts/audit_crypto_boundary.zig` with two exact-line exemptions (the block-scoped HKDF type alias and its one expand-label call), not a whole-block or whole-category omission; a live (non-comptime) HKDF-Expand-Label call anywhere else in the file is caught by a forbidden-pattern variant that permits `crypto_provider.hkdfExpandLabel(`/`self.provider.hkdfExpandLabel(` but blocks the legacy `crypto.tls.hkdfExpandLabel(` spelling, the same shape as `tls_adapter.zig`'s equivalent variant below. `KeySchedule.init`/`.initWithPsk`/`.applicationSecrets` and the free HKDF-driven functions are now fallible (`provider.HkdfError!...`), propagating the provider's typed `InvalidInput`/`UnsupportedCapability` errors rather than collapsing them. Every output buffer's `errdefer`/`defer` cleanup is armed *before* the fallible provider call that fills it, not after (#490 review): the provider interface does not promise `out` stays untouched on error, so a conforming provider that writes a partial output and then fails must still have it wiped — proven by a fault-provider fixture in `key_schedule_tests.zig` that writes a recognizable prefix into every output buffer and then errors. Cleanup calls the canonical `provider.secureZero`, never `std.crypto.secureZero` directly. This file has no test block of its own; its tests, including the direct-HMAC cross-check and raw-vtable fixtures, live in the separate, unscanned `key_schedule_tests.zig` (see the guard description above) — every RFC 8448 vector and resumption/PSK known-answer literal there is unchanged byte-for-byte, since none of them depend on key-exchange output, only on `shared`/`hello_transcript_hash` values supplied directly. |
| `src/tls/tls13_backend.zig` | provider-owned keyed crypto | Provider-owned; no exceptions, fully scanned. X25519 ephemeral key-share generation and shared-secret derivation route through `CryptoProvider.generateKeyShare`/`.deriveSharedSecret` (the provider draws its own randomness from its injected `Entropy`, not from a caller-supplied seed — `Tls13Backend.Entropy` no longer carries `key_share_seed`/`retry_key_share_seed`, only `hello_random`, which is unrelated key-exchange-independent ClientHello/ServerHello random and stays a backend-local injected value per this doc's "Entropy is injected" section). CertificateVerify peer-signature authentication routes through `CryptoProvider.verify`, preflighted against `capabilities().supportsSignature`. Error mapping (#490 review correction): a missing signature capability, or `error.UnsupportedCapability` from `.verify` itself, is a local provider/configuration fault (`ProofResult.provider_failure`, surfaced as `error.SecretExportFailed`) — not attributed to the peer, since `scheme` here was already screened against this side's own negotiated policy and the peer's actual offer, so a provider that cannot perform it is this side's misconfiguration, never the peer's. `pure_zig.verifyImpl` distinguishes malformed *public-key* encoding (`error.InvalidInput`, mapped to `.invalid_certificate`/`bad_certificate`) from malformed *signature* encoding, which it now reports as `error.AuthenticationFailed` alongside a well-formed-but-wrong signature (both mapped to `.invalid_signature`/`decrypt_error`, RFC 8446 §4.4.3) — preserving the exact pre-migration split (a malformed key was `bad_certificate`; a malformed *or* incorrect signature was `decrypt_error`) that an earlier revision of this migration had collapsed by mapping every `InvalidInput` to `bad_certificate` regardless of which of the two cases it came from. Local CertificateVerify signing keeps the existing `credentials.CredentialProvider`/`SelectedCredential` opaque async contract unchanged; `credentials.zig`'s `Identity.sign` (the concrete fixed/native credential) now delegates through the opaque `provider.SigningKey` handle (`pure_zig.SoftwareSigningKey` for Ed25519, `pure_zig.SoftwareEcdsaP256SigningKey` for ECDSA-P256) instead of calling `Ed25519.KeyPair.sign`/`EcdsaP256.KeyPair.sign` directly, so private-key bytes never cross into the TLS state machine and the provider boundary owns every keyed signing operation, not only verification. `src/pki/verify.zig` already routed chain-signature verification through the provider before this migration and is unchanged; its own upstream signature-encoding pre-validation means it never sends a malformed-encoding signature into `.verify` in the first place, so this error-taxonomy change does not affect it. |
| `src/tls/record_protection.zig`, `ticket_protection.zig`, resumption runtime | provider-owned keyed crypto | Provider-owned. Record AEAD and stateless ticket protection consume provider/security abstractions; unsupported-provider test doubles carry complete provider vtables. |
| `src/pki/` | signature verification and public DER parsing | Provider-owned for signature verification; public DER/name/policy parsing remains protocol-local. |
| Native TLS/HTTP/QUIC composition roots | provider selection and OpenSSL policy | Allowed to construct concrete providers and backends — this is the only place permitted to choose one. `src/http/http3_runtime.zig`'s `Runtime` is the native QUIC/H3 composition root: it owns the pure-Zig `CryptoProvider` (fed by OS entropy) and injects it into every `Connection.Options.crypto_provider`. It is otherwise fully scanned like `connection.zig` — the composition root may select/construct a provider, but must not perform packet crypto itself. Native appliance paths stay OpenSSL/libcrypto-free; general-purpose OpenSSL TLS and out-of-process OpenSSL oracles remain separate roles. |
| `tests/support/quic_crypto.zig` | test-only concrete provider | Owns per-instance deterministic provider storage (`HandshakeProviderStorage`) that QUIC/H3 tests exercising the seam without the native `Runtime` composition root construct their own, domain-seeded providers from — each caller owns its storage rather than sharing one process-wide mutable stream (#490 review). Isolation from production code is structural, not scanned: `build.zig` wires this module only into explicit test roots — `quic_test_mod` and `exe_test_mod` (used solely by `zig build test-quic`/`zig build test`'s `quic_tests`/`exe_unit_tests`) and the QUIC/H3 smoke/e2e/UDP test modules — never into `quic_mod`, `exe_mod`, the H3 interop tool, or any other module that feeds the shipped `tardi` build or a network-facing process. The H3 interop tool (`tests/h3_interop_tool.zig`) does not import this module at all: it drives real handshakes against real peers, so it owns an OS-backed `production_crypto.Provider` for its own process lifetime instead, the same way the production `Runtime`/`Connection` composition roots do (#490 review — a deterministic provider in a network-facing process makes ephemeral X25519 keys predictable). Any reachable reference to `tests/support/quic_crypto.zig` from code compiled as part of the production module graph — under any local binding name, any indirection such as an inline `@import`, at any position in the file — is therefore a Zig compiler error, not something `scripts/audit_crypto_boundary.zig` has to detect after the fact (#490 sixth-pass review: an earlier revision tried a source-text scan for this — a fixed importer list, then a "before/after a textual test-boundary marker" heuristic — which a renamed binding or an inline `@import` defeated, and which couldn't see that Zig declarations are order-independent, so a public declaration before the marker could call a private helper physically written after it). See the comment beside `test_quic_crypto_mod` in `build.zig`. |

The automated guard (`scripts/audit_crypto_boundary.zig`, run via
`zig build audit-crypto-boundary`) is a small checked-in Zig program, not a
shell script shelling out to an ambient tool like `rg` — every CI runner
enforces it identically with nothing extra to install. It is intentionally
narrow and deterministic, not a semantic proof: it prevents accidental
reintroduction of obvious concrete AEAD/KDF/ECDH/signature shortcuts and the
AES block-cipher form in QUIC protocol modules and the native TLS 1.3 engine,
and separately blocks the concrete legacy `tls_adapter` wrapper call names
(`sealPayload`, `openPayload`, `applyHeaderProtection`,
`removeHeaderProtection`, `headerProtectionMask`, `deriveAes128GcmKeys`,
`deriveInitialSecretsV1`, `deriveNextGenerationSecret`) from the live runtime
modules that migrated onto the `*WithProvider` entry points, so reverting
that migration fails the audit even though the names themselves remain
approved inside `tls_adapter.zig` as differential-test fixtures. Each legacy
name is matched unqualified, not only dot-called (`sealPayload(` rather than
only `.sealPayload(`): a `*WithProvider` method and its legacy sibling share
one Zig container, so the sibling can be called either way, and #490's
fifth-pass review found the dot-only form missed a same-container unqualified
call.

`src/tls/key_schedule.zig` and `src/tls/tls13_backend.zig` are scanned the
same way: `tls13_backend.zig` carries no exceptions at all (a plain
whole-file check, like `connection.zig`/`http3_runtime.zig`), and
`key_schedule.zig` carries exactly two narrow exact-line exemptions for its
one documented comptime "derived early secret" public constant, scanned
against a forbidden-pattern variant that permits the provider-routed
`crypto_provider.hkdfExpandLabel(`/`self.provider.hkdfExpandLabel(` calls
while still blocking the legacy `crypto.tls.hkdfExpandLabel(` spelling — the
same qualified/bare-call distinction `tls_adapter_zig_forbidden` already
makes for the QUIC seam. `key_schedule.zig` carries no `production_only_marker`
and no test-block exemption at all (#490 second review pass): a textual
"scan only content before this position" boundary is not a sound production/
test reachability proof, since Zig declarations are order-independent and a
production declaration positioned before such a marker could still call a
private helper positioned after it without the scan ever seeing the call —
the same structural class of bug `test_quic_crypto`'s isolation (described
below) exists to avoid. `key_schedule.zig`'s direct-crypto test fixtures —
the cross-check of the provider-routed Finished `verify_data` derivation
against a direct `std.crypto.auth.hmac.sha2.HmacSha256` computation, and the
raw `CryptoProvider` test vtables proving typed-error propagation — instead
live in `src/tls/key_schedule_tests.zig`, a file this tool never scans at
all, and which is *not* reachable from the production `tls_core` module
(`src/tls/root.zig`) even transitively: `key_schedule_tests.zig` is compiled
only as part of a dedicated `key_schedule_test_root_mod` in `build.zig`,
wired solely into the `test-tls`/`test-crypto`/`test` test artifacts, never
into `quic_mod`/`exe_mod`/the shipped `tardi` executable. That isolation is
therefore a Zig compiler property (a production file that tried to `@import`
`key_schedule_tests.zig` would be a compile error, the same class of
guarantee `test_quic_crypto`'s module-graph isolation below provides), not a
scanned convention — the same reason this tool does not scan
`tests/support/quic_crypto.zig` or `tests/crypto_vectors.zig` either.

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

Directory-wide scans (`src/quic`) walk recursively against the full
forbidden set — concrete primitives *and* the legacy wrapper names, so
packet-protection code refactored out of `connection.zig` into a new file is
still caught — so a new nested subdirectory gets no free pass, and
exclusions are matched by exact root-relative path rather than basename, so
a nested file that happens to reuse an excluded name (e.g.
`src/quic/nested/connection.zig`) is not exempt. Every explicitly named
protected file/function fails closed if it goes missing (a rename or
deletion is itself a violation, not a silent pass). It forces any new
exception to be reviewed in this document and the tool's allowlist, and its
own fixture tests (`zig build audit-crypto-boundary` runs them) prove each
bypass class it exists to catch actually fails the audit, including the
narrow-exception-doesn't-cover-a-second-call-site, unqualified-call,
missing-file, and nested-directory cases above. This is a source-audit
build tool, not part of the shipped product, so it (and its `zig_compat`
dependency) are always built for the build host — not whatever `-Dtarget`
the rest of the build graph is cross-compiling for.

Not every boundary in this document is enforced by source-text scanning.
`test_quic_crypto`'s production/test isolation (see the table row above) is
instead a property of `build.zig`'s module graph, checked by the Zig
compiler itself on every build — the more direct tool for a property that
depends on true reachability rather than a pattern in the source text, which
is exactly what pattern-matching text cannot soundly decide (#490
sixth-pass review).

# Cryptographic-provider boundary (#370, epic #327)

This note records the stable cryptographic-provider boundary Tardigrade's TLS,
QUIC, and PKI code is written against, and the rules every implementation of it
must obey. It is the deliverable of research story **327-A** and the foundation
the rest of epic #327 builds on.

## Context

A working TLS state machine is not enough to replace or complement OpenSSL
safely. The project needs one deliberate place where cryptography enters the
protocol code, so that:

- protocol modules (TLS 1.3, QUIC packet protection, X.509 verification, record
  protection, tickets) never name a concrete primitive or a foreign TLS type;
- more than one backend — a pure-Zig one built on `std.crypto`, and the approved
  production OpenSSL one — can satisfy the same interface where their
  capabilities overlap;
- algorithm selection is explicit and cannot pick something a backend cannot do;
- secret ownership and lifetime are stated, not assumed.

Per epic #327, OpenSSL remains the approved production backend; the pure-Zig
provider grows alongside it as an experimental and eventual alternative. This
boundary is what keeps the two from coupling to each other.

## Where it lives

- `src/crypto/provider.zig` — the boundary: algorithm identifiers, capability
  discovery, the error taxonomy, the injected `Entropy` source, the opaque
  `SigningKey` handle, and the `CryptoProvider` interface (a `context` pointer
  plus a `*const VTable`, the same seam shape as the QUIC `TlsBackend`).
- `src/crypto/profile.zig` — the checked-in capability matrix: every
  TLS/QUIC/PKI algorithm name, implementation family, primitive-provider
  status, protocol-integration consumers, product-profile notes, tests, and
  Zig version floor.
- `src/tls/crypto_profile.zig` — the TLS-side adapter that maps provider
  capabilities to TLS policy capabilities without making crypto import TLS.
- `src/crypto/secrets.zig` — fixed-size and bounded dynamic secret containers,
  shared secure-zero and constant-time comparison helpers, and the non-formatting
  convention for secret-bearing values.
- `src/crypto/pure_zig.zig` — the first concrete backend, built entirely on
  `std.crypto`. Implements the narrow first profile and advertises exactly that.
- `src/crypto/root.zig` — the package aggregator.
- `docs/CRYPTO_PROVIDER_AUDIT.md` — the current native TLS/QUIC/PKI/resumption
  direct-crypto ownership audit and exception list.
- Tests run under `zig build test-crypto` and as part of `zig build test`.

The OpenSSL adapter is future work: a second file implementing the same
`CryptoProvider.VTable`, selected at the composition root. No protocol code
changes when it lands.

## What the boundary covers

- **HKDF** extract and expand-label over SHA-256 and SHA-384.
- **AEAD** seal/open for AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305.
- **QUIC header protection** for the AES-128 profile, exposed as a narrow
  packet-protection mask operation rather than as a reusable AES block API.
- **Key exchange** — ephemeral key-share generation and shared-secret derivation
  for X25519 and (declared, not yet implemented in pure Zig) secp256r1.
- **Signatures** — verification for Ed25519, ECDSA-P256, and RSA-PSS, plus
  signing through the opaque `SigningKey` handle for Ed25519.
- **Random bytes**, **constant-time comparison**, and **secure zeroing**.
- **Secret containers** for fixed-size stack material and bounded heap material,
  with explicit replacement and deinitialization rules.
- **Opaque private-key handles** and **capability discovery**.

The pure-Zig backend implements the overlap the TLS/QUIC engines need today:
HKDF (SHA-256/384), all three AEAD primitives, AES-128 QUIC header protection,
X25519, Ed25519, ECDSA-P256 verification, and RSA-PSS verification. The
remaining algorithms are named by the interface so protocol and negotiation
code is written once; capability discovery reports them absent and every entry
point returns `error.UnsupportedCapability` until a backend provides them.

Primitive support, protocol integration, and product enablement are three
separate dimensions, and `src/crypto/profile.zig` records all three as typed
data, not prose:

- **Primitive support** — `pure_zig_status` / `openssl_status`: can a backend
  do this at all.
- **Protocol integration** — `Row.integrations`, a `(Consumer,
  IntegrationStatus)` list: whether each consumer's *live* runtime actually
  calls the provider for it today. This is per consumer because it commonly
  differs within one row — e.g. HKDF-SHA256 is `.live` for QUIC packet
  protection but `.not_integrated` for the TLS 1.3 handshake engine, which
  still calls a parallel `std.crypto` path for the same primitive.
  `IntegrationStatus.live` means the live runtime calls `CryptoProvider`
  today, not that it could if wired up — see `profile.zig`'s "QUIC packet
  protection is live-integrated through CryptoProvider" test, which pins the
  two rows this holds for.
- **Product enablement** — `Row.enabled_product_profiles`, a named
  `EnumSet(ProductProfile)` (`.native_appliance`, `.general_purpose_openssl`):
  which product actually selects this capability. This is authored per row,
  not derived from `pure_zig_status`/`openssl_status` — primitive support
  does not imply product selectability. AES-256-GCM and ChaCha20-Poly1305
  both report `pure_zig_status = .supported` but neither is negotiated by the
  native appliance, so neither claims `.native_appliance`; secp256r1 has
  `openssl_status = .provider_deferred` (no in-process OpenSSL
  `CryptoProvider` yet) but the real general-purpose OpenSSL product supports
  P-256 ECDH outside this seam, so it still claims `.general_purpose_openssl`.
  See `profile.zig`'s "enabled product profiles are not a mechanical copy of
  primitive support" test.

## Supported profile matrix

The source of truth is `src/crypto/profile.zig`, not prose in this document.
The table below summarizes the checked-in profile for review; "Integration"
lists only the consumers whose live runtime calls `CryptoProvider` today
(`.live`), not every consumer the row names:

| Capability | Pure-Zig status | Pure-Zig implementation | OpenSSL status | Consumers | Live integration | Product profiles |
| --- | --- | --- | --- | --- | --- | --- |
| SHA-256 | supported | `std.crypto` | provider deferred | TLS transcript, HKDF, QUIC TLS bridge | none — unkeyed hashing has no `CryptoProvider` entry point by design | native appliance, general-purpose OpenSSL |
| SHA-384 | supported | `std.crypto` | provider deferred | TLS transcript, HKDF | none — unkeyed hashing has no `CryptoProvider` entry point by design | general-purpose OpenSSL only (the native appliance's engine negotiates TLS_AES_128_GCM_SHA256 only, so SHA-384 is never selected there) |
| HKDF-SHA256 | supported | `std.crypto` HMAC/TLS label code | provider deferred | TLS 1.3 key schedule, QUIC packet protection | QUIC packet protection and the QUIC/TLS secret bridge; the TLS 1.3 key schedule (`src/tls/key_schedule.zig`) still calls `std.crypto` directly | native appliance, general-purpose OpenSSL |
| HKDF-SHA384 | supported | `std.crypto` HMAC/TLS label code | provider deferred | TLS 1.3 key schedule | none — `src/tls/key_schedule.zig` still calls `std.crypto` directly | general-purpose OpenSSL only (the native appliance's engine negotiates TLS_AES_128_GCM_SHA256 only, so HKDF-SHA384 is never selected there) |
| AES-128-GCM | supported | `std.crypto` | provider deferred | TLS records, QUIC packet protection | both — TLS record protection and QUIC packet protection seal/open through `CryptoProvider` | native appliance, general-purpose OpenSSL |
| AES-256-GCM | supported | `std.crypto` | provider deferred | TLS records; QUIC integration deferred | none — TLS_AES_256_GCM_SHA384 is not negotiated by the native appliance's engine | general-purpose OpenSSL only (negotiated there outside this seam) |
| ChaCha20-Poly1305 | supported | `std.crypto` | provider deferred | protocol integration deferred | none | general-purpose OpenSSL only |
| QUIC AES-128 header protection | supported | `std.crypto` behind provider mask API | provider deferred | QUIC packet protection | live — every send/receive path in `src/quic/tls_adapter.zig` applies/removes header protection through `CryptoProvider` | native appliance only (QUIC-specific; the general-purpose backend is TLS-over-TCP) |
| X25519 | supported | `std.crypto` | provider deferred | TLS key share, QUIC TLS bridge | none — `src/tls/tls13_backend.zig` generates the TLS key share via `X25519.KeyPair.generateDeterministic` directly | native appliance, general-purpose OpenSSL |
| secp256r1 / P-256 | provider deferred | unavailable | provider deferred | TLS key share, PKI | none | general-purpose OpenSSL only (P-256 ECDH outside this seam; not implemented in pure Zig at all) |
| Ed25519 | supported | `std.crypto` | provider deferred | CertificateVerify, PKI | PKI chain-signature verification only; the handshake's own CertificateVerify message calls a local verifier directly | native appliance, general-purpose OpenSSL |
| ECDSA-P256-SHA256 | supported | `std.crypto` verification | provider deferred | CertificateVerify, PKI | PKI chain-signature verification only, same split as Ed25519 | native appliance, general-purpose OpenSSL |
| RSA-PSS-RSAE-SHA256 | supported | project verifier | provider deferred | CertificateVerify, PKI | PKI chain-signature verification only, same split as Ed25519 | general-purpose OpenSSL only (the native appliance negotiates Ed25519/ECDSA only) |
| DER parser | provider deferred | project code | provider deferred | PKI | none — parsing has no `CryptoProvider` entry point | native appliance, general-purpose OpenSSL (shared protocol-local code) |
| chain builder, WebPKI validation | provider deferred | unavailable | provider deferred | PKI | none | neither — not implemented yet |
| injected random bytes, secure zero, constant-time compare | supported | project code | provider deferred / project code | all secret-bearing paths | none through `CryptoProvider.entropy` — TLS/QUIC/resumption inject randomness through their own longer-standing `Entropy` parameters instead; secure-zero/constant-time-compare are shared helpers, not vtable dispatch targets | native appliance, general-purpose OpenSSL |

The Zig compatibility floor for this matrix is `0.16.0`; when the project moves
to a newer compiler or starts carrying compatibility shims for crypto APIs, the
floor and each affected row must be updated together.

Protocol configuration must not hand-write provider-derived TLS capabilities.
Use `tls.crypto_profile.fromProfile(product, provider.capabilities())`, naming
the caller's `crypto.profile.ProductProfile` explicitly (`.native_appliance`
for the pure-Zig in-process path, `.general_purpose_openssl` for the OpenSSL
backend), then pass the returned `asPolicyCapabilities()` slice set to
`tls.Policy`. There is no product-agnostic shortcut: which cipher suites,
named groups, and signature schemes a product actually negotiates is a
product decision, not something a provider's raw capability set can answer on
its own — a pure-Zig provider reports AES-256-GCM/ChaCha20-Poly1305/RSA-PSS
support, but `fromProfile` still withholds them for `.native_appliance`
because that product's engine doesn't negotiate them, while
`.general_purpose_openssl` advertises the full set. Each cipher suite is
gated on every profile dimension it binds together (AEAD, transcript hash,
HKDF hash), not only its AEAD row. When a call site must accept hand-written
TLS capability lists, it should preflight them with
`tls.crypto_profile.validateAgainstProvider` before handshake execution.

The native appliance profile remains the deliberately narrow in-process
pure-Zig path: no OpenSSL or libcrypto linkage, and general-purpose OpenSSL
TLS available only through the existing non-native backend. QUIC packet
protection — AEAD seal/open and header protection on every send/receive path
in `src/quic/tls_adapter.zig` — runs through `CryptoProvider`; the TLS 1.3
handshake engine underneath it (key schedule, key share generation,
CertificateVerify) does not yet and is tracked as open follow-up for #490.
OpenSSL remains valid as the general-purpose TLS backend and as an
out-of-process deterministic/differential oracle; it is not required as an
in-process native `CryptoProvider` for this profile.

## Design rules

### Capability discovery is explicit

A provider advertises exactly what it can do through `Capabilities` (sets of
supported hashes, AEADs, groups, and signature schemes). Negotiation selects
only from that set with the `select*` helpers, and every operation re-checks
membership. An unsupported algorithm is therefore always a typed
`error.UnsupportedCapability` — never a call into a primitive that cannot handle
it, and never undefined behaviour.

Every algorithm addition or status change must update `src/crypto/profile.zig`
in the same PR as the implementation. Reviewers should check that the row names
the implementation family, provider status, test coverage, consumers, and
security assumptions before accepting a new negotiated algorithm.

`zig build audit-crypto-boundary` and `zig build test-crypto` run the checked-in
source guard, `scripts/audit_crypto_boundary.zig` — a small Zig program, not a
shell script depending on an ambient tool like `rg`, so it runs identically on
every CI runner. The guard blocks new direct keyed crypto shortcuts and the
AES block-cipher form in QUIC protocol modules outside the approved
provider-owned adapter and documented exceptions, and separately blocks the
concrete legacy `tls_adapter` wrapper call names from the live runtime
modules that migrated onto the `*WithProvider` entry points.

### Errors are classified

The taxonomy lets the protocol layer map each failure to the correct alert
without guessing:

| Class | Meaning | Typical protocol response |
| --- | --- | --- |
| `InputError.InvalidInput` | Malformed or wrong-sized caller/peer input (bad point encoding, wrong-length key, undersized output buffer). | `decode_error` / `illegal_parameter`, QUIC `CRYPTO_ERROR`. |
| `CapabilityError.UnsupportedCapability` | Well-formed but this backend cannot do it. A negotiation/config bug, not peer misbehaviour. | internal error; should be unreachable after negotiation. |
| `ProviderError.{EntropyFailure, ProviderFailure}` | The provider itself failed, independent of input. | internal error; not fixable by renegotiating. |
| `AuthError.AuthenticationFailed` | An AEAD tag or a signature did not verify. | `bad_record_mac` / handshake failure; never treated as a benign decode error. |

### Secrets are borrowed, never retained

Every slice handed to the provider — keys, IKM, plaintext, private scalars,
peer public values — is valid only for the duration of the call. A backend must
not retain a pointer to borrowed secret material after it returns. The only
provider-owned secret is a `SigningKey`'s private key, which lives behind the
opaque handle; its owner scrubs it explicitly when retiring the key (for the
pure-Zig backend, `SoftwareSigningKey.deinit` — a Zig value is not zeroed just
by going out of scope). Internally, backends copy secrets into fixed buffers
only as long as a primitive needs them and `secureZero` those buffers on the
way out — including HKDF's per-block temporaries, the X25519 seed, ephemeral
private scalar, and shared-secret copies. AEAD-open zeroes its output buffer on
authentication failure so no unauthenticated plaintext is ever left for the
caller to read.

Secret-bearing protocol state should use `crypto.secrets.FixedSecret(N)` for
fixed-capacity storage and `crypto.secrets.BoundedSecret` for heap-backed
storage with an explicit upper bound. These types copy input into owned memory,
return borrowed slices through `slice`, wipe replaced contents before reuse, and
must be `deinit`ed before the owning connection/key object is discarded. Secret
containers deliberately provide a `format` method that fails compilation so
accidental `{}` logging does not expose key material. `BoundedSecret` is
initialized in place so callers do not receive an owning heap allocation by
value; any ownership transfer must be explicit at the call site.

### Entropy is injected

There is no ambient RNG, matching the rest of `src/quic/`. A provider draws all
randomness — ephemeral scalars, nonces, per-signature noise — from the
`Entropy` source handed in at construction. The composition root wires this to
the OS CSPRNG in production; tests and reproducible fixtures use
`pure_zig.DeterministicEntropy` (a seedable splitmix64 source that is explicitly
*not* a CSPRNG). Entropy failure surfaces as `ProviderError.EntropyFailure`.

### Private keys can move off-host later

`SigningKey` is an opaque `context` + `VTable` pair, so a software key today and
an HSM or remote signer tomorrow present the identical interface. The TLS engine
holds a `SigningKey` and calls `sign`; it never learns where the private key
lives. This is why signing goes through the handle rather than through the main
provider vtable.

## Acceptance criteria mapping (#370)

- *Protocol modules compile against provider-owned types only* — the interface
  exposes only its own enums, error sets, and handles; no `std.crypto` or
  OpenSSL type crosses the seam. Migrating the existing QUIC/TLS modules onto it
  is follow-up implementation work (#323–#326), which this boundary enables.
- *Pure-Zig and OpenSSL providers satisfy the same interface where capabilities
  overlap* — both implement `CryptoProvider.VTable`; overlap is exactly what
  `Capabilities` makes queryable.
- *Capability negotiation is explicit and cannot select unsupported algorithms*
  — see "Capability discovery is explicit" above; covered by tests.
- *Errors distinguish invalid peer input, unsupported capability, and provider
  failure* — see the error taxonomy table; covered by tests.
- *No provider retains borrowed secrets beyond documented call lifetimes* — see
  "Secrets are borrowed, never retained".

## Not in scope here

TLS handshake behaviour (#323), X.509/Web PKI (#324), the TCP record layer
(#325), and resumption/0-RTT (#326) live in their own stories. So do the
differential-testing, Wycheproof-style corpora, fuzzing, performance budgets,
and the pure-Zig production-readiness checklist enumerated in epic #327. This
story defines the boundary they all attach to.

# Cryptographic-provider boundary (#370, epic #327)

This note records the stable cryptographic-provider boundary Tardigrade's TLS,
QUIC, and PKI code is written against, and the rules every implementation of it
must obey. This document originated with #370 / 327-A and now records the
cryptographic-provider architecture and ownership rules established by the
completed #327 assurance work.

## Context

A working TLS state machine is not enough to replace or complement OpenSSL
safely. The project needs one deliberate place where cryptography enters the
protocol code, so that:

- protocol modules (TLS 1.3, QUIC packet protection, X.509 verification, record
  protection, tickets) never name a concrete primitive or a foreign TLS type;
- native TLS/QUIC uses the in-process pure-Zig `CryptoProvider`
  implementation for provider-owned keyed operations, in every shipping
  profile (`general` and `appliance` — #649 retired the OpenSSL production
  backend `general` used to link);
- algorithm selection is explicit and cannot pick something a backend cannot do;
- secret ownership and lifetime are stated, not assumed;
- no OpenSSL type or hidden `libcrypto` operation leaks into the native
  TLS/QUIC provider path.

The architecture is now a single production path: native TLS/QUIC uses the
in-process pure-Zig `CryptoProvider` seam for keyed cryptographic work in both
build profiles. #649 retired the general-purpose TLS backend that
`-Dtls-profile=general` previously linked (`src/http/tls_backend.zig` and the
OpenSSL implementations of `tls_termination.zig`/`acme_client.zig` were
deleted); out-of-process OpenSSL remains valid only as an interoperability and
differential-testing oracle (`evp_oracle`, `tests/crypto_openssl_diff.zig`,
`tests/pki_openssl_diff.zig`). The native provider path never imports or
exposes OpenSSL-backed types.

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
- `src/crypto/pure_zig.zig` — the concrete in-process `CryptoProvider` used by
  the native TLS/QUIC path; it is built on `std.crypto` and advertises exactly
  those provider capabilities.
- `src/http/tls_termination.zig` — the native upstream HTTPS/TLS client
  (`UpstreamTlsConn`, #634) used for upstream proxying in every profile; no
  `@cImport`, OpenSSL type, or C linkage. Downstream TLS termination is served
  by `src/http/native_tls_connection.zig`, not this file. #649 retired this
  file's former OpenSSL downstream-terminator implementation and deleted
  `src/http/tls_backend.zig`, the selector layer that used to choose between
  it and the native stub; the downstream `TlsTerminator`/`TlsConnection`
  types that remain in this file are now permanently inert (fail closed with
  `error.ContextInitFailed`), kept only so shared option-struct field shapes
  compile identically across profiles.
- `src/crypto/root.zig` — the package aggregator.
- `docs/CRYPTO_PROVIDER_AUDIT.md` — the current native TLS/QUIC/PKI/resumption
  direct-crypto ownership audit and exception list.
- Tests run under `zig build test-crypto` and as part of `zig build test`.

There is no in-process OpenSSL `CryptoProvider`, and after #649 there is no
production OpenSSL TLS backend of any kind — every shipping profile is
pure-Zig native. Out-of-process OpenSSL remains valid as an interoperability
and differential oracle.

## What the boundary covers

- **HKDF** extract and expand-label over SHA-256 and SHA-384.
- **AEAD** seal/open for AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305.
- **QUIC header protection** for AES-128, AES-256, and ChaCha20, exposed as a
  narrow packet-protection mask operation rather than as reusable block/stream
  cipher APIs.
- **Key exchange** — ephemeral key-share generation and shared-secret derivation
  for X25519 and secp256r1.
- **Signatures** — verification for Ed25519, ECDSA-P256, and RSA-PSS, plus
  signing through the opaque `SigningKey` handle for Ed25519, ECDSA-P256, and
  RSA-PSS.
- **Random bytes**, **constant-time comparison**, and **secure zeroing**.
- **Secret containers** for fixed-size stack material and bounded heap material,
  with explicit replacement and deinitialization rules.
- **Opaque private-key handles** and **capability discovery**.

The pure-Zig provider implements the overlap the native TLS/QUIC engines need
now: HKDF (SHA-256/384), all three AEAD primitives, AES-128/AES-256/ChaCha20
QUIC header protection, X25519, secp256r1 ECDH, Ed25519, ECDSA-P256
signing/verification, and RSA-PSS signing/verification. The remaining algorithms
are named by the interface so protocol and negotiation code is written once;
capability discovery reports them absent and every entry point returns
`error.UnsupportedCapability` until a backend provides them.

Primitive support, protocol integration, and product enablement are three
separate dimensions, and `src/crypto/profile.zig` records all three as typed
data, not prose:

- **Primitive/provider support** — `pure_zig_status` and `openssl_status`: can a
  backend do this at all inside the `CryptoProvider` model. `openssl_status`
  never described an in-process OpenSSL `CryptoProvider` (none has ever
  existed); it tracks primitive/algorithm support an out-of-process OpenSSL
  peer has, for differential-testing purposes, independent of what any
  shipping product profile enables.
- **Protocol integration** — `Row.integrations`, a `(Consumer,
  IntegrationStatus)` list: whether each named native consumer's *live* runtime
  actually calls the provider for it today. This is per consumer because it
  commonly differs within one row. `IntegrationStatus.live` means the live
  runtime calls `CryptoProvider` today, not that it could if wired up — see
  `profile.zig`'s integration-status tests, which pin the rows this holds for.
- **Product enablement** — `Row.enabled_product_profiles`, a named
  `EnumSet(ProductProfile)` (`.appliance`, `.general`): which
  product actually selects this capability. This is authored per row, not
  derived from `pure_zig_status`/`openssl_status` — primitive support does not
  imply product selectability. Both profiles are pure-Zig native and share the
  same in-process `CryptoProvider` seam (#649 retired the OpenSSL production
  TLS backend `.general` used to name); they differ only in product
  policy — `.appliance` is the strict Bare Systems single-identity
  policy, `.general` the multi-identity general-purpose policy.

## Supported profile matrix

The source of truth is `src/crypto/profile.zig`, not prose in this document. The
matrix below summarizes the checked-in profile for review. The column labeled
"OpenSSL `CryptoProvider` status" is about the in-process provider model only,
which has never existed and is unrelated to whether either product profile
enables a capability.

The Zig compatibility floor for this matrix is `0.16.0`; when the project moves
to a newer compiler or starts carrying compatibility shims for crypto APIs, the
floor and each affected row must be updated together.

| Capability | Pure-Zig status | Pure-Zig implementation | OpenSSL `CryptoProvider` status | Consumers | Product profiles |
| --- | --- | --- | --- | --- | --- |
| SHA-256 | supported | `std.crypto` | provider deferred | TLS handshake: `.not_provider_routed`; QUIC TLS bridge: `.not_provider_routed` | native appliance, general-purpose |
| SHA-384 | supported | `std.crypto` | provider deferred | TLS handshake: `.not_provider_routed` | native appliance, general-purpose |
| HKDF-SHA256 | supported | `std.crypto` HMAC/TLS label code | provider deferred | TLS handshake: `.live`; QUIC TLS bridge: `.live`; QUIC packet protection: `.live` | native appliance, general-purpose |
| HKDF-SHA384 | supported | `std.crypto` HMAC/TLS label code | provider deferred | TLS handshake: `.live`; QUIC packet protection: `.live` | native appliance, general-purpose |
| AES-128-GCM | supported | `std.crypto` | provider deferred | TLS record: `.live`; QUIC packet protection: `.live` | native appliance, general-purpose |
| AES-256-GCM | supported | `std.crypto` | provider deferred | TLS record: `.live`; QUIC packet protection: `.live` | native appliance, general-purpose |
| ChaCha20-Poly1305 | supported | `std.crypto` | provider deferred | TLS record: `.live`; QUIC packet protection: `.live` | native appliance, general-purpose |
| QUIC AES-128 header protection | supported | `std.crypto` behind provider mask API | provider deferred | QUIC packet protection: `.live` | native appliance only |
| QUIC AES-256 header protection | supported | `std.crypto` behind provider mask API | provider deferred | QUIC packet protection: `.live` | native appliance only |
| QUIC ChaCha20 header protection | supported | `std.crypto` behind provider mask API | provider deferred | QUIC packet protection: `.live` | native appliance only |
| X25519 | supported | `std.crypto` | provider deferred | TLS handshake: `.live`; QUIC TLS bridge: `.not_integrated` | native appliance, general-purpose |
| secp256r1 / P-256 | supported | `std.crypto` | provider deferred | TLS handshake: `.live`; QUIC TLS bridge: `.not_integrated`; PKI: `.not_integrated` | general-purpose only |
| Ed25519 | supported | `std.crypto` | provider deferred | TLS handshake: `.live`; PKI: `.live` | native appliance, general-purpose |
| ECDSA-P256-SHA256 | supported | `std.crypto` signing/verification | provider deferred | TLS handshake: `.live`; PKI: `.live` | native appliance, general-purpose |
| RSA-PSS-RSAE-SHA256 | supported | project code | provider deferred | TLS handshake: `.live`; PKI: `.live` | general-purpose only |
| DER/X.509 parser helpers | provider deferred | project code | provider deferred | PKI: `.not_provider_routed` | native appliance, general-purpose |
| Certificate chain builder | provider deferred | unavailable | provider deferred | PKI: `.not_integrated` | neither |
| WebPKI validation | provider deferred | unavailable | provider deferred | PKI: `.not_integrated` | neither |
| Injected random bytes | supported | project code | provider deferred | TLS handshake: `.live`; QUIC packet protection: `.not_integrated`; resumption: `.not_integrated` | native appliance, general-purpose |
| Secure zero | supported | project code | supported | TLS handshake: `.not_provider_routed`; TLS record: `.not_provider_routed`; QUIC packet protection: `.not_provider_routed`; PKI: `.not_provider_routed`; resumption: `.not_provider_routed` | native appliance, general-purpose |
| Constant-time compare | supported | project code | supported | TLS handshake: `.not_provider_routed`; TLS record: `.not_provider_routed`; PKI: `.not_provider_routed` | native appliance, general-purpose |

Protocol configuration must not hand-write provider-derived TLS capabilities.
Use `tls.crypto_profile.fromProfile(product, provider.capabilities())`, naming
the caller's `crypto.profile.ProductProfile` explicitly (`.appliance`
for the appliance policy, `.general` for the general-purpose policy —
both pure-Zig in-process), then pass the returned `asPolicyCapabilities()`
slice set to `tls.Policy`. This is the TLS-policy adapter for the
provider-backed native TLS path: it intersects an actual `CryptoProvider`
capability set with the selected product-profile policy. When a call site
must accept hand-written TLS capability lists, it should preflight them with
`tls.crypto_profile.validateAgainstProvider` before handshake execution.

The native appliance profile remains the deliberately narrow in-process
pure-Zig path: no OpenSSL or `libcrypto` linkage. Since #649, the same is true
of the `general` profile — there is no production build with OpenSSL TLS
available any more. QUIC packet
protection — AEAD seal/open and header protection on every send/receive path
in `src/quic/tls_adapter.zig` — runs through `CryptoProvider`, and so does the
TLS 1.3 handshake engine underneath it: the key schedule (HKDF-Extract,
HKDF-Expand-Label, and Finished `verify_data`), X25519/secp256r1 key-share
generation and shared-secret derivation, and CertificateVerify authentication all cross
`CryptoProvider` (#490). Local CertificateVerify signing keeps using the
existing opaque `CredentialProvider`/`SelectedCredential` contract
(`src/tls/credentials.zig`), whose concrete fixed/native implementation signs
through `provider.SigningKey` rather than a named `std.crypto.sign` type.

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
way out — including HKDF's per-block temporaries, X25519 and secp256r1
key-share seeds/scalars, and shared-secret copies. P-256 ECDH accepts only
canonical uncompressed SEC1 peer points and rejects malformed, off-curve,
infinity, non-canonical, zero-scalar, and out-of-range scalar inputs as
`InvalidInput`. AEAD-open zeroes its output buffer on authentication failure so
no unauthenticated plaintext is ever left for the caller to read.

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

There is no ambient RNG, matching the rest of `src/quic/`. Provider-owned
random operations draw from `CryptoProvider.entropy`; this includes native
X25519/P-256 ephemeral scalar generation and provider-side randomized signing
such as ECDSA. Some protocol-owned randomness still uses separate, explicitly
injected entropy parameters. TLS ClientHello/ServerHello random values and
QUIC/resumption nonces are examples of protocol-level injected entropy that do
not travel through `CryptoProvider.entropy`. The composition root wires the
provider entropy to the OS CSPRNG in production; tests and reproducible fixtures
use `pure_zig.DeterministicEntropy` (a seedable splitmix64 source that is
explicitly *not* a CSPRNG). Entropy failure surfaces as
`ProviderError.EntropyFailure`. The native TLS 1.3 engine's ephemeral
X25519/P-256 scalar is one concrete instance of this (#490): `Tls13Backend` no
longer carries its own key-share seed — `CryptoProvider.generateKeyShare` draws
that randomness from the same injected `Entropy` every other provider operation
uses, and a production composition root's `EntropyFailure` there surfaces through
the engine's existing error taxonomy rather than a silent fallback.

### Private keys can move off-host later

`SigningKey` is an opaque `context` + `VTable` pair, so a software key today and
an HSM or remote signer tomorrow present the identical interface. The TLS engine
holds a `SigningKey` and calls `sign`; it never learns where the private key
lives. This is why signing goes through the handle rather than through the main
provider vtable. `src/tls/credentials.zig`'s fixed/native `Identity` — the
concrete credential the native TLS engine actually signs CertificateVerify
with — is this abstraction's first real user rather than only its documented
intent (#490): it holds a `pure_zig.SoftwareSigningKey` (Ed25519) or
`pure_zig.SoftwareEcdsaP256SigningKey` (ECDSA-P256) and signs through
`provider.SigningKey.sign`, never a named `std.crypto.sign.Ed25519.KeyPair`/
`EcdsaP256Sha256.KeyPair` type. The ECDSA implementation rejects undersized
output buffers before drawing entropy and publishes bytes only after a complete
canonical DER signature exists. Canonical DER does not imply low-S
normalization in this provider: ECDSA signing emits the primitive's `s` value
directly, and verification accepts any valid non-zero in-range `r`/`s` pair
without silently normalizing or rewriting it. The engine-facing `CredentialProvider`/
`SelectedCredential` async contract in the same file is unchanged by this —
it already only ever handed the engine an opaque signing capability, never
key bytes; what changed is what the *concrete* credential behind that
contract calls internally.

## Acceptance criteria mapping (#370)

- *Protocol modules compile against provider-owned types only* — the interface
  exposes only its own enums, error sets, and handles; no `std.crypto` or
  OpenSSL type crosses the seam. The native TLS/QUIC path consumes this seam
  where required; protocol-specific breadth remains owned by the relevant
  protocol epics.
- *The native pure-Zig path implements and consumes `CryptoProvider`; the
  general-purpose backend remains behind its separate TLS adapter/backend*
  — the original #370 criterion, satisfied for as long as that second backend
  existed: the two paths shared no requirement to implement the same provider
  vtable. #649 has since retired the general-purpose backend entirely,
  so the native pure-Zig path is now the only one; no OpenSSL type crosses
  into the native/provider architecture.
- *Capability negotiation is explicit and cannot select unsupported algorithms*
  — see "Capability discovery is explicit" above; covered by tests.
- *Errors distinguish invalid peer input, unsupported capability, and provider
  failure* — see the error taxonomy table; covered by tests.
- *No provider retains borrowed secrets beyond documented call lifetimes* — see
  "Secrets are borrowed, never retained".

## Not in scope here

The completed cross-cutting #327 architecture and assurance work is documented
here. Ongoing protocol-specific breadth remains owned by the relevant protocol
stories (#323–#326), and controlled appliance release evidence remains owned by
#391. This ticket only needs the documentation to describe those ownership
boundaries accurately.

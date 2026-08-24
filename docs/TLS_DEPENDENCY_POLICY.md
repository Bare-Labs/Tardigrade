# TLS/crypto dependency policy and pure-Zig cutover (#379, epic #327, #634)

This note records Tardigrade's external-library policy for TLS, crypto, QUIC,
HTTP/3, and certificate handling, how that policy is enforced in source, build
configuration, CI, and release artifacts, and the checklist that governs the
cutover to the pure-Zig implementation. It began as the deliverable of
research story **327-J** and a required v0.5 release gate for the Bare Systems
appliance (#391); the canonical architecture owner is now **#634**.

## Why

The project architecture (#634) is that **the native Zig TLS/crypto/PKI/QUIC/
HTTP implementation is the only implementation that ships to users**:

- Every distributed `tardi` artifact — release archives, packages, containers,
  Homebrew, installer paths — must be built on the native implementation, with
  no OpenSSL or other foreign TLS/crypto/QUIC/H3 library linked, configured,
  or reachable through a hidden runtime fallback.
- External implementations (OpenSSL, GnuTLS, independent QUIC stacks, …)
  remain encouraged as **test, interoperability, differential-validation, and
  benchmark infrastructure**, always outside the shipping link/runtime graph.
- Appliance vs. general-purpose differences are **product policy** expressed
  on the same native implementation (cipher/identity/lifecycle policy), not a
  choice of implementation backend.

During the remaining transition the default `general` build profile still
links the single, narrowly isolated OpenSSL adapter as a compatibility
backend. That composition is transitional: it is not a permitted final
shipping backend, and no new architecture should make it more permanent.

A policy that is only written down drifts. This one is enforced by the build
graph and by CI, and every release artifact makes its selected profile and
linked dependencies inspectable.

## Approved build profiles

The profile is selected at build time with `-Dtls-profile` and is baked into
the binary. There is no runtime switch and no fallback between profiles.

### Bare Systems appliance profile (`-Dtls-profile=appliance`)

- Uses the native Zig TLS/crypto path only, with the strict Bare Systems
  product policy on top: a single Ed25519 identity, a required
  `TARDIGRADE_TLS_SERVER_NAME`, TLS 1.3 only, restart-owned credential
  rotation. The supported TLS/certificate/client matrix is defined by #391.
- Must not link `libssl`, `libcrypto`, or any other foreign TLS, crypto, QUIC,
  HTTP/3, or certificate library.
- The OpenSSL adapter module (`src/http/tls_termination.zig`) is **replaced in
  the module graph** by a no-OpenSSL stub (`src/http/tls_termination_stub.zig`)
  via `src/http/tls_backend.zig`. Because the adapter source is never imported,
  its `@cImport("openssl/...")` is never analyzed and OpenSSL is never linked.
  Live termination runs on `src/http/native_tls_connection.zig`; the stub only
  fills the module graph and fails closed (`error.ContextInitFailed`) if
  anything ever reaches it.

### General-purpose native profile (`-Dtls-profile=native`, #634)

- The general-purpose expression of the same native implementation: generic
  multi-identity credential loading (default cert/key plus
  `TARDIGRADE_TLS_SNI_CERTS`), native TCP TLS termination, native QUIC/H3,
  SIGHUP-driven credential reload, opt-in native resumption
  (`TARDIGRADE_TLS_NATIVE_RESUMPTION_MODE`), and a **native upstream HTTPS/TLS
  client** (`src/http/tls_termination_stub.zig`'s `UpstreamTlsConn`, #634) —
  `proxy_pass https://…` upstreams are served entirely by the native TLS
  engine, record layer, and PKI stack, never by OpenSSL.
- Downstream SNI selection: an explicit `TARDIGRADE_TLS_SNI_CERTS` mapping
  always wins first; failing that, the default identity is served if its own
  certificate's SAN actually covers the requested hostname (RFC 9525 matching
  via `src/pki/identity.zig`, not string heuristics — see
  `sni_provider.UnknownSniPolicy.use_default_when_identity_matches`); failing
  that, the handshake fails closed. Absent SNI still serves the default
  identity unconditionally, unchanged from before.
- Upstream TLS: certificate verification (`TARDIGRADE_UPSTREAM_TLS_VERIFY`,
  `TARDIGRADE_UPSTREAM_TLS_CA_BUNDLE`) uses the same native PKI path-building/
  validation as downstream mTLS would (`src/tls/webpki_verifier.zig`), falling
  back to a small set of well-known system CA bundle file locations when no
  bundle is configured; SNI/hostname derivation
  (`TARDIGRADE_UPSTREAM_TLS_SERVER_NAME`), upstream ALPN/protocol selection
  (`TARDIGRADE_UPSTREAM_PROTOCOL`), upstream client certificates (mTLS to the
  origin), and existing connect/response timeouts all continue to work
  unchanged; disabling verification still encrypts the connection, it just
  skips identity checking. See `docs/CONFIGURATION.md` for the full knob
  list and `docs/TROUBLESHOOTING.md` for native-profile-specific upstream TLS
  failure modes.
  **Signature algorithm caveat:** chain validation authenticates each
  certificate's signature through the native matrix (`src/pki/verify.zig`),
  originally #343 (Ed25519, ECDSA P-256/SHA-256, RSA-PSS/SHA-256) and
  extended by #645 to also cover classic `sha256WithRSAEncryption`/
  `sha384WithRSAEncryption` (RSA PKCS#1 v1.5/SHA-256 and SHA-384) —
  still-common signature algorithms among public CAs and intermediates. RSA
  PKCS#1 v1.5 support is certificate-chain-signature verification only: RFC
  8446 §4.2.3 forbids `rsa_pkcs1` schemes in TLS 1.3 `CertificateVerify`, so
  the native handshake engine's own proof-of-possession step continues to use
  only Ed25519, ECDSA P-256/SHA-256, or RSA-PSS/SHA-256 regardless of what
  algorithm signed the certificate chain (`src/tls/crypto_profile.zig`'s
  `supportsSignatureScheme` unconditionally refuses to advertise or select
  it). Other public-WebPKI variants — ECDSA/SHA-384 and RSA PKCS#1 v1.5/
  SHA-512 among them — remain unsupported; a chain signed with one of them
  still fails closed with a verification error, mapped through the same
  bounded upstream-TLS failure path as any other handshake/certificate
  failure (see `docs/TROUBLESHOOTING.md`). Extending the native signature
  matrix further (e.g. ECDSA/SHA-384) remains tracked separately; until then,
  native-profile upstream HTTPS is production-ready only against origins
  whose certificate chain uses one of the five now-supported signature
  algorithms.
  **Certificate/handshake size caveat (#646, resolved):** the shared
  handshake engine (`src/tls/tls13_backend.zig`) used to hard-cap every peer
  `CertificateEntry` at `max_certificate_len` (2048 bytes) and the whole
  handshake message at `max_message_len` (8 KiB), rejected before the
  signature/verifier code ever ran — a certificate did not need an
  unsupported algorithm to cross this: an Ed25519 leaf, already supported,
  could exceed 2 KiB DER with a moderately large SAN set, and a
  multi-certificate public chain could exceed the aggregate 8 KiB bound even
  with small individual certificates. Both bounds are now `max_certificate_len`
  (8 KiB) and `max_message_len` (16 KiB) — comfortably above ordinary public
  WebPKI norms while still fail-closed against a genuinely oversized/DoS-shaped
  handshake — so this is no longer an independent blocker alongside #645.
- Must not link `libssl`, `libcrypto`, or any other foreign TLS, crypto, QUIC,
  HTTP/3, or certificate library — audited identically to the appliance
  profile.
- OpenSSL-adapter-only settings (TLS 1.2, cipher-string overrides, downstream
  mTLS client verification, the OpenSSL session cache/tickets, OCSP stapling,
  CRL checks, ACME, the filesystem credential watcher, PROXY protocol with
  TLS) fail config validation deterministically
  (`UnsupportedNativeTlsConfiguration`) instead of being silently ignored;
  each is either natively implemented later or explicitly dispositioned under
  #634. Upstream TLS is not on this list: every upstream TLS knob is
  supported natively (see above), not rejected.
- This is the profile #634 promotes to the shipping default once feature
  disposition and release/packaging cutover complete.

### General-purpose OpenSSL profile (`-Dtls-profile=general`, default, transitional)

- Links the single approved OpenSSL adapter as a transitional
  compatibility/reference backend; superseded as a shipping backend by #634.
- OpenSSL types and state stay behind the adapter boundary
  (`src/http/tls_termination.zig`, `src/http/acme_client.zig`) and must not
  shape TLS, HTTP, QUIC, PKI, or application interfaces.
- No external TLS/crypto implementation other than the approved OpenSSL adapter
  may be linked.

### Shared policy

- ngtcp2/nghttp3 remain fully removed (#328); HTTP/3 and QUIC run on the
  pure-Zig transport.
- External TLS/QUIC/H3 implementations may run only as out-of-process or
  containerized interoperability peers (`scripts/interop/`), never in the
  Tardigrade link graph.
- Build and release artifacts must make their selected profile and linked
  dependencies inspectable.

## How the binary reports its profile

`tardi version` prints the profile and backend, so operators and release
audits can verify an artifact without inspecting its link graph:

```
$ tardi version
0.5.0 (tls-profile=appliance, tls-backend=native)
$ tardi version
0.5.0 (tls-profile=native, tls-backend=native)
$ tardi version
0.5.0 (tls-profile=general, tls-backend=openssl-adapter)
```

## Enforcement

### Source and configuration audit — `scripts/audit-dependencies.sh`

Runs before anything is compiled and fails if:

1. A forbidden TLS/crypto/QUIC/H3 dependency name (ngtcp2, nghttp3, quiche,
   BoringSSL, mbedTLS, wolfSSL, GnuTLS, LibreSSL, rustls, s2n-tls, botan, …) is
   **configured** in `build.zig`, `build.zig.zon`, workflows, scripts,
   Dockerfiles, or packaging metadata. Comments are stripped before matching so
   the policy can be documented in prose; only real configuration fails.
2. An OpenSSL `@cInclude` appears outside the approved adapter boundary.
3. Any `@cImport` appears in a native implementation path (`src/tls`,
   `src/pki`, `src/quic`, `src/crypto`, `src/http3`).

### Binary linkage audit — `scripts/audit-release-binary.sh`

Inspects a produced binary's dynamic dependencies (`ldd` on Linux, `otool -L`
on macOS) and emits a machine-readable JSON inventory. It fails if:

- an appliance or native artifact links OpenSSL or any forbidden foreign
  library, or does not self-report the native TLS path; or
- a general artifact's actual linkage disagrees with its self-reported backend
  (so the inventory cannot lie).

The inventory records the binary, profile, host OS, inspection tool,
self-reported backend, full dependency list, and any violations.

### CI

The `TLS dependency audit` job in `.github/workflows/ci.yml` runs the source
audit, builds **all three** profiles, and runs the binary audit against each,
uploading the inventories as artifacts. It is a required check: CI fails if any
forbidden implementation is configured, imported, or linked in any profile.

### Release

`.github/workflows/release.yml` re-runs the source audit, audits each released
(general-profile) binary's linkage, and publishes the dependency inventory
alongside the release assets and SBOM.

## Cutover checklist

### Bare Systems appliance (blocks #391)

- [x] `appliance` build profile selects the native TLS/crypto path.
- [x] Appliance builds link no OpenSSL/libcrypto/foreign TLS library (enforced
      by binary audit).
- [x] No hidden runtime fallback to OpenSSL (stub fails closed; profile is a
      build-graph decision).
- [x] Appliance artifact self-reports the native TLS path.
- [x] CI builds and audits the appliance artifact on every change.
- [x] Native TLS termination serves live appliance connections
      (`src/http/native_tls_connection.zig`); CI runs the appliance unit and
      integration suites on every change.
- [ ] #391 appliance certification (exact-artifact/device/product-policy
      gate) complete.

### General-purpose native cutover (#634; governs OpenSSL adapter removal)

- [x] OpenSSL confined to the adapter boundary; no OpenSSL types in TLS/HTTP/
      QUIC/PKI/application interfaces (enforced by source audit).
- [x] General artifacts expose a complete dependency inventory and identify the
      selected backend.
- [x] A general-purpose native profile exists (`-Dtls-profile=native`): no
      foreign linkage, generic multi-identity credentials, deterministic
      rejection of OpenSSL-adapter-only settings, built and binary-audited in
      CI.
- [x] Native upstream HTTPS/TLS client exists and is wired into the data
      plane: `proxy_pass https://…` upstreams work under `-Dtls-profile=native`
      through the native TLS engine, record layer, and PKI stack — hostname/
      SAN checking, SNI, ALPN/protocol selection, connection pooling/reuse,
      and bounded failure mapping all function — no OpenSSL, no runtime
      fallback.
- [ ] Native upstream HTTPS/TLS client is **production-ready against ordinary
      public HTTPS origins** (#634's actual upstream criterion) — **not yet
      true, and this is a partial implementation until this box is checked.**
      The two gaps this box previously tracked are both now resolved:
      #645 extended the certificate-signature matrix past the original #343
      three algorithms, and #646 raised the handshake engine's
      `max_certificate_len`/`max_message_len` bounds past ordinary public
      WebPKI norms (see both caveats above). This box stays unchecked because
      other public-WebPKI signature algorithms (e.g. ECDSA/SHA-384, RSA
      PKCS#1 v1.5/SHA-512) remain unsupported and still fail closed with a
      native-profile 502 even with a correct CA bundle and hostname — closing
      those, or otherwise establishing that the remaining gap is
      acceptable, is what remains before this box can be checked.
- [x] Native certificate-signature matrix (`src/pki/verify.zig`) extended to
      cover classic RSA PKCS#1 v1.5/SHA-256 and SHA-384 (`sha256WithRSAEncryption`/
      `sha384WithRSAEncryption`) so native-profile upstream verification is not
      restricted to the original #343 three-algorithm matrix (#645). This is
      certificate-chain-signature verification only, not a TLS 1.3
      `CertificateVerify` option — see the signature algorithm caveat above.
      Other public-WebPKI variants (e.g. ECDSA/SHA-384) remain unsupported;
      #645 did not claim to close every possible signature algorithm, only
      the classic RSA PKCS#1 v1.5 gap.
- [x] Native handshake engine's client-role certificate/message size bounds
      made practical for ordinary public WebPKI chains without weakening the
      fail-closed posture for genuinely oversized ones (#646).
- [x] Default downstream identity SAN/SNI eligibility: a default certificate
      may satisfy a requested SNI its own SAN actually covers, without
      requiring an explicit `TARDIGRADE_TLS_SNI_CERTS` entry; explicit
      mappings still take precedence and mismatched/unmatched SNI still fails
      closed.
- [ ] Every remaining operator-visible OpenSSL-path capability (downstream
      mTLS, OCSP, CRL, ACME, TLS 1.2, cipher policy, watcher-based reload) is
      migrated to native code or explicitly dispositioned per #634. Upstream
      TLS is no longer on this list — see above.
- [ ] Native TLS reaches the v1.0 general-purpose support contract
      (`docs/SUPPORT_MATRIX.md`).
- [ ] Native path passes the TLS/interop conformance suite at parity with the
      OpenSSL adapter.
- [ ] Default profile flips from `general` to `native` once parity holds.
- [ ] Release/package/container/Homebrew artifacts ship the native profile and
      pass the no-foreign-linkage audit (#634 distribution criteria).
- [ ] OpenSSL adapter removed from all builds; `configureSsl`, the adapter
      modules, and the general profile retired.

When the final boxes are checked, the OpenSSL adapter and the `-Dtls-profile`
switch can be removed and Tardigrade ships a single pure-Zig TLS stack.

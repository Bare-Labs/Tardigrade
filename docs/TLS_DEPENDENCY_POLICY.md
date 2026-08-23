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
  (`TARDIGRADE_TLS_NATIVE_RESUMPTION_MODE`). The credential store is
  fail-closed on SNI, matching the existing native HTTP/3 behavior: the
  default identity serves clients that send no SNI, and every host name
  clients will request must be registered via `TARDIGRADE_TLS_SNI_CERTS`
  (default-identity SAN matching is part of the remaining #634 parity
  work).
- Must not link `libssl`, `libcrypto`, or any other foreign TLS, crypto, QUIC,
  HTTP/3, or certificate library — audited identically to the appliance
  profile.
- OpenSSL-adapter-only settings (TLS 1.2, cipher-string overrides, mTLS client
  verification, the OpenSSL session cache/tickets, OCSP stapling, CRL checks,
  ACME, the filesystem credential watcher, PROXY protocol with TLS) fail
  config validation deterministically (`UnsupportedNativeTlsConfiguration`)
  instead of being silently ignored; each is either natively implemented later
  or explicitly dispositioned under #634.
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
- [ ] Every operator-visible OpenSSL-path capability (mTLS, OCSP, CRL, ACME,
      TLS 1.2, cipher policy, watcher-based reload, upstream TLS) is migrated
      to native code or explicitly dispositioned per #634.
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

# v0.6.x TLS Interop/Conformance Hardening Run (#674)

Date: 2026-08-26

This note records a dedicated release-hardening execution of the existing
shared-TLS-engine interoperability suite
([`docs/TLS_INTEROP_MATRIX.md`](TLS_INTEROP_MATRIX.md), #338), run with the
`full` profile and both OpenSSL and GnuTLS peer tooling installed, per #674.
It reuses the existing interop system (`tests/tls_interop_matrix.zig`,
`tests/tls_interop_tool.zig`, `scripts/interop/run-tls-interop.sh`) rather than
adding a parallel harness. No new external TLS implementation was added.

## Environment

Recorded before running, per #674's "Required setup":

```
$ zig version
0.16.0
$ openssl version
OpenSSL 3.6.3 9 Jun 2026 (Library: OpenSSL 3.6.3 9 Jun 2026)
$ gnutls-cli --version
gnutls-cli 3.8.13
$ uname -a
Darwin mac.lan 25.3.0 Darwin Kernel Version 25.3.0: Wed Jan 28 20:49:24 PST 2026; root:xnu-12377.81.4~5/RELEASE_ARM64_T8132 arm64
```

- Source SHA: `9e871817e82b9aec28060b0e7a26a5f2f388f470` (v0.6.3, "Cut 0.6.3"
  #691 — the `main` HEAD this run was executed against)
- OS/architecture: Darwin 25.3.0, arm64
- Both OpenSSL and GnuTLS peer tooling were already present on this host, so
  no CI-only installer (`scripts/interop/install-tls-peer-deps-ci.sh`, which
  targets Debian/Ubuntu `apt-get`) was needed.

## Canonical commands

```bash
zig build build-tls-interop build-h3-interop \
  --summary all --error-style verbose

scripts/interop/run-tls-interop.sh --list

mkdir -p artifacts/tls-interop
TLS_INTEROP_WORKDIR="$PWD/artifacts/tls-interop" \
  scripts/interop/run-tls-interop.sh --profile full

zig build test-tls-interop-matrix --summary all --error-style verbose
```

All four commands completed successfully. The build step produced
`tls_interop_tool` and `h3_interop_tool`; `--list` enumerated 137 rows before
any peer connected; `test-tls-interop-matrix` (the #338 vocabulary-vs-engine
unit check) passed 16/16.

## Full-profile result

```
pass=116 fail=0 skip=0
```

**Zero unexplained FAIL rows. Zero unexplained applicable SKIP rows** — every
row that is applicable to this product/profile ran against a real peer and
passed. The complete sanitized row-by-row output (no private keys, keylogs,
traffic secrets, ticket keys, or session material — the tool's transcripts
never capture that layer; see "Redaction contract" in
[`TLS_INTEROP_MATRIX.md`](TLS_INTEROP_MATRIX.md)) is retained at
[`evidence/674-tls-interop-hardening/full-profile-run.log`](evidence/674-tls-interop-hardening/full-profile-run.log).

| Category | Rows | Result |
| --- | --- | --- |
| Positive tuples (3 suites × 2 groups × 3 signatures, OpenSSL server/client + GnuTLS server/client + QUIC loopback) | 90 | 90 PASS |
| HTTP/2 ALPN entrypoint (`record/server/openssl/http2_entrypoint`) | 1 | PASS |
| HelloRetryRequest, both roles | 2 | 2 PASS |
| Post-handshake KeyUpdate (server reciprocal, client reciprocal, client one-way) | 3 | 3 PASS |
| Record Size Limit (RFC 8449), both directions, GnuTLS | 2 | 2 PASS |
| Shutdown: clean `close_notify` | 1 | PASS |
| Shutdown: abrupt truncation → `TruncatedStream` | 1 | PASS |
| Negative conformance (ALPN/cipher/group/signature no-overlap, TLS 1.2 downgrade, SNI absent, malformed ordering, CCS-before-ClientHello, wrong pinned certificate) | 9 | 9 PASS |
| Certificate-selection rows (SNI × 3, unknown-SNI default, sigalgs × 2, no-applicable-credential) | 7 | 7 PASS |
| **Total** | **116** | **116 PASS / 0 FAIL / 0 SKIP** |

## Positive negotiation matrix (#674 checklist)

- [x] `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`,
      `TLS_CHACHA20_POLY1305_SHA256` — each combined with every group and
      signature scheme below, in both roles, against both peers.
- [x] X25519, P-256/secp256r1
- [x] Ed25519, ECDSA P-256/SHA-256, RSA-PSS-RSAE/SHA-256
- [x] Tardigrade as TLS server / as TLS client
- [x] OpenSSL external peer / GnuTLS external peer
- [x] HTTP/1.1 ALPN/application path — every positive record-transport row
      exchanges application data over ALPN `http/1.1`
- [x] HTTP/2 ALPN/application entrypoint —
      `record/server/openssl/http2_entrypoint`
- [x] QUIC/H3 tuple path via the native loopback rows (`quic/loopback/...`,
      18/18 tuples PASS) — proves the pinned negotiation tuple traverses the
      QUIC transport of the same engine. See "H3 external peer" below for the
      separate out-of-process ngtcp2/quiche matrix.

### Required non-basic rows

- [x] HRR: server forces/handles, client handles peer HRR — both PASS
- [x] KeyUpdate: server reciprocal, client reciprocal, client one-way, and
      application data succeeds across updated generations (asserted via
      `key_updates_sent`/`key_updates_received` plus post-update
      `app_bytes` in the retained log) — all PASS
- [x] Record Size Limit against GnuTLS, both directions — PASS
- [x] Shutdown: clean `close_notify` and abrupt truncation → the expected
      `TruncatedStream` failure — both PASS

### Required negative matrix

- [x] ALPN no overlap → `no_application_protocol`
- [x] Cipher no overlap → `handshake_failure`
- [x] Group no overlap → `handshake_failure`
- [x] Signature no overlap → `handshake_failure`
- [x] TLS 1.2 downgrade/version mismatch → `protocol_version`
- [x] Required SNI absent → `missing_extension`
- [x] Wrong pinned certificate → `bad_certificate`
- [x] Application data/malformed record ordering before ClientHello →
      `UnexpectedRecordContent`
- [x] CCS before ClientHello → `UnexpectedRecordContent`
- [x] No applicable configured credential → `handshake_failure`

Every negative row's expected alert/error class is asserted by the harness
itself (see `run_negative_server_row` / `--expect-error` /
`--expect-alert` in `tests/tls_interop_tool.zig`), not inferred from a
generic disconnect.

## H3 external peer (ngtcp2/quiche) — environment limitation

`scripts/interop/install-h3-peer-deps-ci.sh` and
`scripts/interop/build-h3-peer-ci.sh` build the pinned ngtcp2/nghttp3 GnuTLS
example peer from source, and are written specifically for a Debian/Ubuntu CI
runner: they call `apt-get`, install `clang-19` from `apt.llvm.org`, and
depend on `libstdc++-14-dev`, none of which exist on this hardening host
(Darwin 25.3.0 / arm64). This is a genuine environment limitation under #674's
skip policy ("the independent peer lacks the required capability and the
limitation is documented") — the peer itself is not missing by oversight, its
build pipeline targets a different OS.

This does not leave the H3/QUIC/UDP exchange unproven:

- The native QUIC loopback rows above (18/18 tuples PASS) prove the same
  engine's QUIC transport negotiates every supported tuple correctly.
- The exact external-peer pipeline this run could not execute
  (`install-h3-peer-deps-ci.sh` → `build-h3-peer-ci.sh` →
  `scripts/interop/run-h3-peer-ci.sh` and
  `zig build test-integration-resumption-interop`) already runs on **every
  PR** via the `h3-resumption-interop` job in
  [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) on
  `ubuntu-latest`, building the same pinned ngtcp2 `v1.25.0`/nghttp3 `v1.18.0`
  GnuTLS peer and exercising real QUIC/UDP/H3 exchange, including the two
  focused HRR peer-matrix rows described in
  [`scripts/interop/README.md`](../scripts/interop/README.md). That job was
  green at the source SHA recorded above.

**Follow-up**: to co-locate literal external-peer transcripts with a future
hardening pass, run `scripts/interop/run-interop.sh` (after
`install-h3-peer-deps-ci.sh` and `build-h3-peer-ci.sh`) on a Linux host or CI
runner rather than this Darwin host. Tracked as follow-up rather than blocking
#674, since the peer/build combination is continuously proven in CI and #674
scopes H3 peer proof to "where run".

## Failure handling

No FAIL rows occurred, so #674's failure-handling contract (row name,
SHA/version/profile, peer version, exact command, sanitized transcript,
expected-vs-observed alert, and a deterministic regression) did not apply to
this run. No product defect was found, so no lower-layer regression test was
added.

## Outcome

- Full profile completed with OpenSSL installed. ✅
- Full profile completed with GnuTLS installed for applicable rows. ✅
- Zero unexplained FAIL rows. ✅
- Zero unexplained applicable SKIP rows. ✅
- HRR, KeyUpdate, record-size-limit, shutdown/truncation, and negative
  negotiation rows are explicitly covered. ✅
- H3 external-peer rows prove real QUIC/UDP exchange **where run**: not run on
  this Darwin hardening host (documented environment limitation above); run
  and green on every PR in the `h3-resumption-interop` CI job on
  `ubuntu-latest` at the recorded source SHA. ⚠️ documented, not blocking
- Every discovered defect has a focused regression and rerun evidence: N/A,
  zero defects discovered in this pass.
- This result is linked from [`docs/RELEASE_CHECKLIST.md`](RELEASE_CHECKLIST.md)
  and [`docs/TLS_INTEROP_MATRIX.md`](TLS_INTEROP_MATRIX.md). ✅

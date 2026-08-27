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

scripts/interop/run-tls-interop.sh --list --profile full

mkdir -p artifacts/tls-interop
TLS_INTEROP_WORKDIR="$PWD/artifacts/tls-interop" \
  scripts/interop/run-tls-interop.sh --profile full

zig build test-tls-interop-matrix --summary all --error-style verbose
```

All four commands completed successfully. The build step produced
`tls_interop_tool` and `h3_interop_tool`. `--list --profile full` enumerated
**116 matrix rows** (118 output lines, including the `profile:` and `engine
capabilities:` header lines) before any peer connected — the same 116 rows
that executed and passed below. The retained, source-SHA-matched row list is
[`evidence/674-tls-interop-hardening/rows.txt`](evidence/674-tls-interop-hardening/rows.txt).
`test-tls-interop-matrix` (the #338 vocabulary-vs-engine unit check) passed
16/16, confirming the row list is derived from the engine's own
`native_capabilities` rather than a second, driftable copy.

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

### Explicit row-name verification

A superficially green `pass=N fail=0 skip=0` summary line could in principle
hide a runner bug that stopped enumerating one of the special-case sections
while the aggregate count still looked healthy. Each of the following exact
row names was independently grep-verified against the retained log to end in
` PASS`:

```
record/server/openssl/http2_entrypoint
record/server/openssl/hrr
record/client/openssl/hrr
record/server/gnutls/record-size-limit
record/client/gnutls/record-size-limit
record/server/openssl/key-update/reciprocal
record/client/openssl/key-update/reciprocal
record/client/openssl/key-update/one-way
record/server/openssl/close_notify
record/server/openssl/truncation
record/negative/alpn_no_overlap
record/negative/tls12_downgrade
record/negative/cipher_no_overlap
record/negative/group_no_overlap
record/negative/signature_no_overlap
record/negative/sni_absent
record/negative/malformed_ordering
record/negative/ccs_before_clienthello
record/negative/wrong_pinned_certificate
record/selection/sni_ed25519
record/selection/sni_ecdsa_p256
record/selection/sni_rsa
record/selection/unknown_sni_uses_default
record/selection/sigalgs_ed25519
record/selection/sigalgs_rsa_pss
record/selection/no_applicable_credential
```

All 26 rows: present, and PASS.

## Repeatable full-profile hardening gate

The `full`-profile record/TLS run above was executed by hand on this Darwin
host. `run-tls-interop.sh` intentionally exits success on `SKIP` (so a
contributor without GnuTLS installed can still run it locally), which is too
permissive to be the canonical hardening gate on its own. #674 requires an
intentional manual/scheduled entrypoint that also enforces `fail=0 skip=0` and
runs the pinned external H3/QUIC peer matrix. That entrypoint is
[`.github/workflows/tls-conformance-full.yml`](../.github/workflows/tls-conformance-full.yml):
`workflow_dispatch` plus a weekly schedule, running on `ubuntu-latest` (so
both installers — `install-tls-peer-deps-ci.sh` and the H3 peer's
`install-h3-peer-deps-ci.sh`/`build-h3-peer-ci.sh` — apply), installing both
peers, running `--list --profile full` and `--profile full`, parsing the
final `pass=/fail=/skip=` line and failing the job if `fail` or `skip` is
non-zero, then running `scripts/interop/run-h3-peer-ci.sh` against the pinned
external H3 peer, and uploading the row list, matrix logs, and H3 peer log as
a 90-day retained Actions artifact (never the generated `certs/`
directories).

## H3 external peer — pinned peer, real QUIC/UDP/H3 exchange

`scripts/interop/install-h3-peer-deps-ci.sh` and
`scripts/interop/build-h3-peer-ci.sh` build the pinned external H3/QUIC
example peer from source, and are written specifically for a Debian/Ubuntu CI
runner (`apt-get`, a pinned `clang` toolchain, and Debian-only C++ standard
library packages), none of which exist on this Darwin/arm64 hardening host.
The `tls-conformance-full.yml` workflow above runs this exact pipeline on
`ubuntu-latest` instead, giving #674 a real, repeatable external-peer run
rather than a permanently-deferred one.

- Native QUIC loopback rows (18/18 tuples PASS, in the full-profile run
  above) prove the same engine's QUIC transport negotiates every supported
  tuple correctly.
- The external-peer run (`install-h3-peer-deps-ci.sh` →
  `build-h3-peer-ci.sh` → `scripts/interop/run-h3-peer-ci.sh`, which drives
  `scripts/interop/run-interop.sh` against the pinned peer and additionally
  asserts the two `#333` HRR peer-matrix rows by name) is captured in
  [`evidence/674-tls-interop-hardening/h3-external-peer-run.md`](evidence/674-tls-interop-hardening/h3-external-peer-run.md),
  with the peer version/build identity, the workflow run link, and the
  sanitized matrix log.

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
- H3 external-peer rows prove real QUIC/UDP exchange: run via
  `tls-conformance-full.yml` on `ubuntu-latest` against the pinned external
  peer; see
  [`evidence/674-tls-interop-hardening/h3-external-peer-run.md`](evidence/674-tls-interop-hardening/h3-external-peer-run.md)
  for the run link, peer version, and result. ✅
- Every discovered defect has a focused regression and rerun evidence: N/A,
  zero defects discovered in this pass.
- This result is linked from [`docs/RELEASE_CHECKLIST.md`](RELEASE_CHECKLIST.md)
  and [`docs/TLS_INTEROP_MATRIX.md`](TLS_INTEROP_MATRIX.md). ✅

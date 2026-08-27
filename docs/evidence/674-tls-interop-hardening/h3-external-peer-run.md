# H3 external-peer run (#674)

Date: 2026-08-27

This is the real, out-of-process H3/QUIC/UDP external-peer evidence for
#674's closeout, produced by the exact `tls-conformance-full.yml` pipeline
(`install-h3-peer-deps-ci.sh` → `build-h3-peer-ci.sh` →
`scripts/interop/run-h3-peer-ci.sh`), executed on a Linux (`ubuntu:24.04`,
arm64) host rather than the Darwin host used for the record/TLS matrix,
since that pipeline's dependencies are Debian/Ubuntu-specific. Peer package
names live only in `scripts/interop/`, per the existing audited external-peer
boundary, and are not repeated here beyond what `scripts/interop/README.md`
already documents publicly (the pinned example client/server built from
nghttp3 + its QUIC client/server examples).

## Environment

```
zig version: 0.16.0
openssl version: OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024)
gnutls-cli --version: gnutls-cli 3.8.3
uname -a: Linux 6.10.14-linuxkit aarch64 GNU/Linux (ubuntu:24.04 container)
```

- Tardigrade source SHA: `b598417b` (this PR branch,
  `claude/issue-674-implementation-46131b`, built against #674's addressed
  review feedback)
- External peer build refs (pinned defaults in `build-h3-peer-ci.sh`):
  `H3_PEER_LIB_REF=v1.18.0`, `H3_PEER_CLIENT_REF=v1.25.0`
- Peer build identity (resolved commit SHAs at those tags, this run):
  - peer library repo: `dbfc24286138cb0b6490160e7ca87fe1ce6722a0`
  - peer client/server example repo: `f9e9ff01ad2c8116bc09de4f644b0028a61486a6`

## Commands

```bash
./scripts/interop/install-h3-peer-deps-ci.sh
H3_PEER_WORKDIR=/tmp/tardigrade-h3-peer ./scripts/interop/build-h3-peer-ci.sh
zig build build-h3-interop --summary all --error-style verbose

H3_PEER_EXAMPLES_DIR=/tmp/tardigrade-h3-peer/client/build/examples \
  ./scripts/interop/run-h3-peer-ci.sh
```

## Result

```
generating interop certificates in /tmp/h3-peer-interop/certs
native client -> ngtcp2 gtlsserver             PASS
ngtcp2 gtlsclient -> native server             PASS
#333 native HRR client -> ngtcp2 gtlsserver    PASS
#333 ngtcp2 HRR gtlsclient -> native server    PASS
native client -> quiche http3-server           SKIP
quiche http3-client -> native server           SKIP
native client -> aioquic server (optional)     SKIP
aioquic client -> native server (optional)     SKIP

interop summary: 4 passed, 0 failed, 4 skipped
h3-interop: tls retry_state=hrr_received
h3-interop: tls hello_retry_request=true
```

`run-h3-peer-ci.sh` exited `0`: both directions against the pinned external
peer passed (native client ↔ external server, external client ↔ native
server), both #333 HelloRetryRequest directions passed by name, and both
retry-state log assertions the script greps for were present. The full
sanitized matrix log is retained at
[`h3-external-peer/matrix.log`](h3-external-peer/matrix.log); the two HRR
QUIC-level diagnostic logs (handshake/recovery/stream-state trace, no key
material — matches the redaction contract in
[`../../TLS_INTEROP_MATRIX.md`](../../TLS_INTEROP_MATRIX.md)) are retained at
[`h3-external-peer/333-1-native-client-hrr.log`](h3-external-peer/333-1-native-client-hrr.log)
and
[`h3-external-peer/333-2-native-server-hrr.log`](h3-external-peer/333-2-native-server-hrr.log).

The four `SKIP` rows are the quiche and aioquic peers, which this pipeline
does not build (`QUICHE_EXAMPLES_DIR`/`AIOQUIC_PYTHON` unset). Per #674's own
scoping, the pinned ngtcp2-family peer is the required external QUIC peer for
this ticket; additional quiche/aioquic application coverage belongs to
#677/#389.

## How this was produced

`tls-conformance-full.yml`'s `workflow_dispatch` trigger only becomes
callable once the workflow file exists on the repository's default branch —
a GitHub Actions platform restriction, not something this PR can route
around before merge. To close out #674 in this PR rather than deferring the
external-peer proof past merge, the exact same pipeline the workflow runs was
executed locally in a disposable `ubuntu:24.04` container (matching the
workflow's `runs-on: ubuntu-latest` and using the repository's own
`scripts/interop/install-h3-peer-deps-ci.sh` / `build-h3-peer-ci.sh` /
`run-h3-peer-ci.sh`, unmodified) against this PR's exact source tree. The
record/TLS full-profile run was repeated in the same container for
consistency; it reproduced the same `pass=116 fail=0 skip=0` result recorded
in [`../../TLS_INTEROP_HARDENING_674.md`](../../TLS_INTEROP_HARDENING_674.md).
Once this PR merges, `tls-conformance-full.yml` becomes dispatchable and
takes over as the ongoing repeatable gate (manual dispatch or the weekly
schedule).

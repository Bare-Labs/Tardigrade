# HTTP/2 and HTTP/3 Release Sweep Slice (#677)

This is a local PR-safe evidence slice for #677, not the final release sweep.
It records what was run on an ordinary macOS development host before the
dedicated release-artifact, browser, malformed-input, and external-peer matrix
can be completed.

## Environment

- Date: 2026-08-25
- Source SHA: `5e88d4ae97934ca052637f1d06cd8a465f1c8ec7`
- Branch: `codex/issue-677-local-sweep`
- OS: macOS 26.3, Darwin 25.3.0, arm64
- CPU: Apple M4
- Zig: `0.16.0`
- curl: `8.7.1`, SecureTransport/LibreSSL, HTTP/2-capable, no HTTP/3 protocol
  support reported
- nghttp: `nghttp2/1.69.0`
- h2load: `nghttp2/1.69.0`
- OpenSSL: `3.6.3`

## Local Artifact Identity

This slice used the source-tree build output, not an installed release
candidate. To get closer to #677's artifact rule, a ReleaseFast local binary
was built and identified:

```sh
zig build -Doptimize=ReleaseFast -Dversion=issue-677-local-5e88d4a \
  --summary all --error-style verbose
```

Result: passed. Build summary reported `4/4 steps succeeded`.

```sh
./zig-out/bin/tardi version
shasum -a 256 ./zig-out/bin/tardi
file ./zig-out/bin/tardi
ls -lh ./zig-out/bin/tardi
```

Observed identity:

- `tardi version`: `issue-677-local-5e88d4a (tls-profile=general, tls-backend=native)`
- binary SHA-256:
  `4ef83313bebf415bfcdd5af1684fb58788ccc70d5cec07dd51c61e061609d71a`
- file type: `Mach-O 64-bit executable arm64`
- size: `4.6M`

## Repeatable Release-Artifact Sweep Path

This PR adds a reusable sweep entrypoint that can target an installed or
release-candidate binary directly:

```sh
TARDI_BIN="$(command -v tardi)" \
  scripts/run-http-release-sweep.sh
```

For local ReleaseFast fallback validation when no installed package is
available:

```sh
zig build -Doptimize=ReleaseFast -Dversion=issue-677-release-sweep
TARDI_BIN="$PWD/zig-out/bin/tardi" \
  scripts/run-http-release-sweep.sh
```

The script records `tardi version`, the source SHA, executable path, SHA-256,
OS/architecture, Zig, curl, nghttp, h2load, OpenSSL, GnuTLS, and configured H3
peer path metadata into `.zig-cache/http-release-sweep-677/metadata.txt`, then
runs the focused H2 and native TLS integration rows with
`-Dtardigrade-bin-path` so those rows exercise the selected artifact instead
of silently using the freshly built debug binary. Its QUIC/H3 unit and
interop-tool steps remain source-tree regression evidence until a black-box H3
artifact row launches the selected `tardi` binary over UDP. The external H3
peer matrix remains owned by the dedicated interop runner and should be
executed separately when peer paths are available.

## Passed Local Gates

```sh
zig build test-quic --summary all --error-style verbose
```

Result: passed. Build summary reported `18/18 steps succeeded; 984/984 tests
passed`.

This includes the PR-safe HTTP/3 resource-settle soaks:

| Soak | Before | Peak/end sample | After settle |
| --- | --- | --- | --- |
| `soak.h3.bounded_repeated_connections` | `rss_kb=3648 open_fds=13 tracked_connections=0 active_cid_routes=0 native_connections=0` | up to `rss_kb=26880 open_fds=17 tracked_connections=14 active_cid_routes=27 native_connections=14` | `rss_kb=12448 open_fds=13 tracked_connections=0 active_cid_routes=0 native_connections=0` |
| `soak.h3.bounded_resumed_reconnects` | `rss_kb=10544 open_fds=13 tracked_connections=0 active_cid_routes=0 native_connections=0` | up to `rss_kb=20304 open_fds=15 tracked_connections=7 active_cid_routes=13 native_connections=7` | `rss_kb=13632 open_fds=13 tracked_connections=0 active_cid_routes=0 native_connections=0`; resumption cache `client=8 server=8`, both at configured limit `8` |
| `soak.h3.bounded_cancelled_requests` | `rss_kb=11568 open_fds=13 tracked_connections=0 active_cid_routes=0 native_connections=0` | up to `rss_kb=16752 open_fds=15 tracked_connections=2 active_cid_routes=4 native_connections=2` | `rss_kb=13904 open_fds=13 tracked_connections=0 active_cid_routes=0 native_connections=0` |

```sh
zig build test-quic -Doptimize=ReleaseFast --summary all --error-style verbose
```

Result: passed. Build summary reported `18/18 steps succeeded; 984/984 tests
passed`.

ReleaseFast H3 soak observations:

| Soak | Before | Peak/end sample | After settle |
| --- | --- | --- | --- |
| `soak.h3.bounded_repeated_connections` | `rss_kb=2096 open_fds=13 tracked_connections=0 active_cid_routes=0 native_connections=0` | up to `rss_kb=25344 open_fds=17 tracked_connections=15 active_cid_routes=29 native_connections=15` | `rss_kb=14272 open_fds=13 tracked_connections=0 active_cid_routes=0 native_connections=0` |
| `soak.h3.bounded_resumed_reconnects` | `rss_kb=13328 open_fds=13 tracked_connections=0 active_cid_routes=0 native_connections=0` | up to `rss_kb=21392 open_fds=15 tracked_connections=6 active_cid_routes=11 native_connections=6` | `rss_kb=9728 open_fds=13 tracked_connections=0 active_cid_routes=0 native_connections=0`; resumption cache `client=8 server=8`, both at configured limit `8` |
| `soak.h3.bounded_cancelled_requests` | `rss_kb=8944 open_fds=13 tracked_connections=0 active_cid_routes=0 native_connections=0` | up to `rss_kb=13632 open_fds=15 tracked_connections=2 active_cid_routes=4 native_connections=2` | `rss_kb=11568 open_fds=13 tracked_connections=0 active_cid_routes=0 native_connections=0` |

```sh
TARDIGRADE_SOAK_HEAVY=1 \
  zig build test-quic -Dquic-test-filter='soak.h3.' \
  --summary all --error-style verbose
```

Result: passed. Build summary reported `18/18 steps succeeded; 296/296 tests
passed`.

Heavy H3 soak observations:

| Soak | Before | Peak/end sample | After settle |
| --- | --- | --- | --- |
| `soak.h3.bounded_repeated_connections` | `rss_kb=3632 open_fds=13 tracked_connections=0 active_cid_routes=0 native_connections=0` | up to `rss_kb=40384 open_fds=17 tracked_connections=21 active_cid_routes=42 native_connections=21` | `rss_kb=24304 open_fds=13 tracked_connections=0 active_cid_routes=0 native_connections=0` |
| `soak.h3.bounded_resumed_reconnects` | `rss_kb=22208 open_fds=13 tracked_connections=0 active_cid_routes=0 native_connections=0` | up to `rss_kb=36912 open_fds=15 tracked_connections=12 active_cid_routes=23 native_connections=12` | `rss_kb=26384 open_fds=13 tracked_connections=0 active_cid_routes=0 native_connections=0`; resumption cache `client=8 server=8`, both at configured limit `8` |
| `soak.h3.bounded_cancelled_requests` | `rss_kb=24128 open_fds=13 tracked_connections=0 active_cid_routes=0 native_connections=0` | up to `rss_kb=33008 open_fds=15 tracked_connections=2 active_cid_routes=4 native_connections=2` | `rss_kb=30432 open_fds=13 tracked_connections=0 active_cid_routes=0 native_connections=0` |

```sh
zig build test --summary all --error-style verbose
```

Result: passed. Build summary reported `62/62 steps succeeded; 3841/3851 tests
passed (10 skipped)`.

The broader unit gate repeated the same HTTP/3 soak family and again settled
tracked connections, active CID routes, native connections, and open file
descriptors back to baseline.

```sh
zig build build-h3-interop --summary all --error-style verbose
```

Result: passed. Build summary reported `3/3 steps succeeded`; the native
`h3_interop_tool` executable was built.

```sh
zig build test-tls-interop-matrix --summary all --error-style verbose
```

Result: passed. Build summary reported `3/3 steps succeeded; 16/16 tests
passed`.

```sh
zig build build-tls-interop --summary all --error-style verbose
```

Result: passed. Build summary reported `3/3 steps succeeded`; the shared TLS
interop tool was built.

```sh
scripts/interop/run-tls-interop.sh --profile ci
```

Result: passed. Summary reported `pass=86 fail=0 skip=0`.

Relevant #677-adjacent rows included:

- record transport positive TLS 1.3 tuples against OpenSSL and GnuTLS
- `record/server/openssl/http2_entrypoint` with ALPN `h2`
- record transport HRR and KeyUpdate rows
- record transport negative ALPN/cipher/group/signature/SNI/certificate rows
- server certificate selection rows
- QUIC loopback tuples with ALPN `h3`

```sh
zig build test-integration-native-tls --summary all --error-style verbose
```

Result: passed. Build summary reported `8/8 steps succeeded; 19/24 tests
passed (5 skipped)`.

This includes the native TLS listener HTTP/2 ALPN dispatch row:
`native TLS listener dispatches ALPN h2 through HTTP/2 frames`.

```sh
zig build test-integration -Dintegration-test-filter='interop.openssl.h2' \
  --summary all --error-style verbose
```

Result: passed. Build summary reported `8/8 steps succeeded; 3/3 tests
passed`.

Covered rows:

- `interop.openssl.h2.tls_resume`
- `interop.openssl.h2.proxy_request_translation_is_secret_safe`
- `interop.openssl.h2.auth_required_proxy_fails_closed`

These rows use OpenSSL `s_client` with explicit `-alpn h2` and
`-servername tardigrade.test`, then send real HTTP/2 frame bytes through the
TLS connection.

```sh
zig build test-integration -Dintegration-test-filter='interop.h2.' \
  --summary all --error-style verbose
```

Result: passed. Build summary reported `8/8 steps succeeded; 21/21 tests
passed`.

Covered rows:

- malformed authority rejected before upstream side effects
- oversized body across DATA frames rejected boundedly
- connection memory cap rejection before per-stream cap
- mismatched content length rejected before upstream side effects
- forbidden transfer-encoding header rejected before upstream side effects
- SETTINGS/WINDOW_UPDATE overflow failure scope
- stream overflow and memory-accounting release
- response flow control waiting for WINDOW_UPDATE
- multiplexed streams completing after WINDOW_UPDATE
- peer initial-window-size behavior
- ACL/rate-limit/retry/passive-health/circuit-breaker/middleware failure
  behavior over HTTP/2
- return-directive parity over HTTP/2
- location streaming override failure behavior

```sh
zig build test-integration -Doptimize=ReleaseFast \
  -Dintegration-test-filter='interop.h2.' \
  --summary all --error-style verbose
```

Result: passed. Build summary reported `8/8 steps succeeded; 21/21 tests
passed`.

```sh
zig build test-integration -Dintegration-test-filter='native upstream h2' \
  --summary all --error-style verbose
```

Result: passed. Build summary reported `8/8 steps succeeded; 1/1 tests
passed`.

This is the best-effort native upstream H2 row:
`native upstream h2 (best-effort, not CI-gated): negotiates h2 and completes a
real proxied request over H2`.

```sh
zig build test-integration-resumption-interop --summary all --error-style verbose
```

Result: passed. Build summary reported `8/8 steps succeeded; 43/49 tests
passed (6 skipped)`.

Additional visible soak output:

- `soak.reconnect_resumption: iterations=40 accepted=40 executions=80 heavy=false`
- `soak.persistent.multi_process_nonce_safety: heavy=false rounds=2 samples_per_process=8 lease_width=1000000 final_generation=3 tuples=52`

```sh
zig build test-integration -Dintegration-test-filter='h3interop.quic.' \
  --summary all --error-style verbose
```

Result: completed with skips. Build summary reported `8/8 steps succeeded;
0/4 tests passed (4 skipped)`.

These production H3 resumption/0-RTT external-peer rows require a built
ngtcp2/GnuTLS `gtlsclient` configured through `H3_INTEROP_CLIENT_PATH`; that
peer was not available on this host.

After the local ngtcp2/GnuTLS peer build was completed with the include-order
workaround below, the H3 production rows were rerun:

```sh
H3_INTEROP_CLIENT_PATH=/tmp/tardigrade-h3-peer-macos2/client/build/examples/gtlsclient \
  zig build test-integration -Dintegration-test-filter='h3interop.quic.' \
  --summary all --error-style verbose
```

Result: passed. Build summary reported `8/8 steps succeeded; 4/4 tests
passed`.

The broader resumption/interop target was also rerun with the same peer path
and peer dynamic-library path:

```sh
DYLD_LIBRARY_PATH=/tmp/tardigrade-h3-peer-macos2/client/build/lib:\
/tmp/tardigrade-h3-peer-macos2/client/build/crypto/gnutls:\
/tmp/tardigrade-h3-peer-macos2/prefix/lib \
H3_INTEROP_CLIENT_PATH=/tmp/tardigrade-h3-peer-macos2/client/build/examples/gtlsclient \
  zig build test-integration-resumption-interop --summary all --error-style verbose
```

Result: passed after the test-harness SNI/OpenSSL fix in this PR. Build
summary reported `8/8 steps succeeded; 49/49 tests passed`.

```sh
zig build test-failure --summary all --error-style verbose
```

Result: passed. Build summary reported `8/8 steps succeeded; 9/9 tests
passed`.

The run logged one expected broken-origin/client diagnostic,
`upstream handler failed: error.ConnectionResetByPeer`, while the failure-mode
harness itself passed.

```sh
zig build test-security-corpus --summary all --error-style verbose
```

Result: passed. Build summary reported `3/3 steps succeeded; 3/3 tests
passed`.

This is request-parser malformed-input/security corpus coverage, including
checked-in hostile parser vectors.

```sh
zig build test-quic-h3-driver --summary all --error-style verbose
```

Result: passed. Build summary reported `3/3 steps succeeded; 23/23 tests
passed`.

This is deterministic native QUIC/H3 driver coverage for protocol-level
scenarios that do not require external peers.

```sh
zig build test-integration -Dintegration-test-filter='#170' \
  --summary all --error-style verbose
```

Result: passed. Build summary reported `8/8 steps succeeded; 9/9 tests
passed`.

Covered lifecycle rows:

- location-block reload takes effect for new requests after SIGHUP
- in-flight request completes safely across reload and new requests use the
  new config
- reload while serving short static requests
- reload while proxying a long upstream response
- reload while a client is uploading a request body
- reload during active upstream health checks
- parked keepalive connection survives reload
- graceful shutdown drains an active in-flight request
- graceful shutdown with a slow client connected
- invalid reload leaves the previous config active

```sh
zig build test-quic -Dquic-test-filter='udp smoke: HTTP/3 runtime drain' \
  --summary all --error-style verbose
```

Result: passed. Build summary reported `18/18 steps succeeded; 294/294 tests
passed`.

This filter includes the H3 UDP runtime drain smoke:
`udp smoke: HTTP/3 runtime drain lets admitted work finish and rejects new
work`.

## External HTTP/3 Interop Harness

```sh
scripts/interop/run-interop.sh
```

Result: script completed with `0 passed, 0 failed, 8 skipped`.

All rows skipped because this host did not have external peer variables
configured:

- `NGTCP2_EXAMPLES_DIR`
- `QUICHE_EXAMPLES_DIR`
- `AIOQUIC_PYTHON`

Skipped rows:

- native client -> ngtcp2 `gtlsserver`
- ngtcp2 `gtlsclient` -> native server
- native HRR client -> ngtcp2 `gtlsserver`
- ngtcp2 HRR `gtlsclient` -> native server
- native client -> quiche `http3-server`
- quiche `http3-client` -> native server
- native client -> aioquic server
- aioquic client -> native server

This proves only that the native interop tool builds and that the harness
reports missing peers explicitly. It does not satisfy #677's real-QUIC proof
rule.

After building the ngtcp2/GnuTLS peer locally, the matrix was rerun with GNU
bash 5.3 (macOS `/bin/bash` 3.2 exits early on an empty-array expansion under
`set -u`):

```sh
DYLD_LIBRARY_PATH=/tmp/tardigrade-h3-peer-macos2/client/build/lib:\
/tmp/tardigrade-h3-peer-macos2/client/build/crypto/gnutls:\
/tmp/tardigrade-h3-peer-macos2/prefix/lib \
NGTCP2_EXAMPLES_DIR=/tmp/tardigrade-h3-peer-macos2/client/build/examples \
  /opt/homebrew/bin/bash scripts/interop/run-interop.sh
```

Result: passed for the ngtcp2 rows. Summary reported `4 passed, 0 failed,
4 skipped`.

Passed rows:

- native client -> ngtcp2 `gtlsserver`
- ngtcp2 `gtlsclient` -> native server
- native HRR client -> ngtcp2 `gtlsserver`
- ngtcp2 HRR `gtlsclient` -> native server

Still skipped:

- native client -> quiche `http3-server`
- quiche `http3-client` -> native server
- native client -> aioquic server
- aioquic client -> native server

## External HTTP/3 Peer Build Attempt

The canonical peer dependency installer,
`scripts/interop/install-h3-peer-deps-ci.sh`, is Debian/Ubuntu-specific and
uses `apt-get`, so it is not directly runnable on this macOS host.

The peer build script was attempted with a temporary `PATH` containing
`clang-19`/`clang++-19` wrapper scripts that exec this host's system
`clang`/`clang++`. The host compiler passed a direct C++23 `<print>` smoke
test, and GnuTLS was available:

- `gnutls-cli 3.8.13`
- `pkg-config --modversion gnutls` reported `3.8.13`

First attempt:

```sh
PATH=<symlink-wrapper-dir>:$PATH \
  H3_PEER_WORKDIR=/tmp/tardigrade-h3-peer-macos \
  scripts/interop/build-h3-peer-ci.sh
```

Result: failed during ngtcp2 client CMake compiler probing because Apple tool
lookup treated the symlink name `clang-19` as an Xcode tool name:
`xcode-select: Failed to locate 'clang-19'`.

Second attempt:

```sh
PATH=<exec-wrapper-dir>:$PATH \
  H3_PEER_WORKDIR=/tmp/tardigrade-h3-peer-macos2 \
  scripts/interop/build-h3-peer-ci.sh
```

Result: partially built the pinned nghttp3 peer library and configured the
pinned ngtcp2 client, then failed while compiling `gtlsclient`.

Observed versions:

- nghttp3 checkout: `v1.18.0`
- ngtcp2 checkout: `v1.25.0`
- generated prefix header: `NGHTTP3_VERSION "1.18.0"`
- Homebrew global header: `NGHTTP3_VERSION "1.15.0"`

Failure shape:

- `gtlsclient` compile failed on `NGHTTP3_STREAM_CLOSE_FLAG_NONE`,
  `NGHTTP3_STREAM_CLOSE_FLAG_RX_APP_ERROR_CODE_SET`,
  `NGHTTP3_STREAM_CLOSE_FLAG_TX_APP_ERROR_CODE_SET`, and
  `nghttp3_conn_close_stream2`
- those symbols exist in the freshly built `/tmp/.../prefix/include` header
- CMake placed `/opt/homebrew/include` before `/tmp/.../prefix/include`, so
  the compile picked up Homebrew's older nghttp3 `1.15.0` headers

The local build was continued by reordering the generated `/tmp` CMake
`flags.make` files so `/tmp/tardigrade-h3-peer-macos2/prefix/include` precedes
`/opt/homebrew/include` for both `gtlsclient` and `gtlsserver`, then rebuilding
the example targets. That produced:

- `/tmp/tardigrade-h3-peer-macos2/client/build/examples/gtlsclient`
- `/tmp/tardigrade-h3-peer-macos2/client/build/examples/gtlsserver`

This workaround was local to `/tmp` and is not a Tardigrade product change.

## Historical Full Integration Gate Attempt

```sh
zig build test-integration --summary all --error-style verbose
```

Historical result from the early #680 evidence pass: failed. Build summary
reported `6/8 steps succeeded`; the integration test binary reported
`160 pass, 19 skip, 3 fail (182 total)`.

Failing tests:

- `bearclaw fixture serves chat over https with bearer auth and transcript persistence`
- `bearclaw transcript append path errors do not fail the request`
- `bearclaw edge prefix routes health without auth and enforces auth on v1 paths`

Failure shape:

- each failure returned `error.CurlFailed` from `sendCurlRequest` in
  `tests/integration.zig`
- the failing curl invocations were HTTPS requests against the Bearclaw fixture
  with `ready_https_insecure = true`
- the integration output also logged upstream handler failures including
  `error.InvalidHttpResponse`, `error.ConnectionResetByPeer`, and
  `error.SocketUnconnected`

A focused rerun was attempted with:

```sh
zig build test-integration -- --test-filter bearclaw
```

That invocation produced no output for several minutes and was interrupted in
the early pass.

Current status after merged PR #680: these Bearclaw HTTPS failures were fixed
by replacing the fragile curl/OpenSSL probe path with SNI-aware pure-Zig TLS
requests and by correcting the Bearclaw fixture/mocking setup. The final #680
validation reported:

```sh
zig build test-integration --summary all --error-style verbose
```

Result: passed. The stale failure above is retained only as historical
diagnostic context; it is not an outstanding #677 product defect.

## Additional Malformed H2 Coverage From This PR

This PR extends the downstream H2 frame loop and integration tests with direct
failure-scope assertions for malformed rows that were still only partially
covered:

- SETTINGS ACK carrying a payload now returns connection-scope `GOAWAY` with
  `FRAME_SIZE_ERROR`.
- invalid SETTINGS payload length now returns connection-scope `GOAWAY` with
  `FRAME_SIZE_ERROR`.
- WINDOW_UPDATE with an invalid payload length now returns connection-scope
  `GOAWAY` with `FRAME_SIZE_ERROR`.
- connection-level WINDOW_UPDATE increment zero now returns connection-scope
  `GOAWAY` with `PROTOCOL_ERROR`.
- stream-level WINDOW_UPDATE increment zero now returns stream-scope
  `RST_STREAM` with `PROTOCOL_ERROR`, and a later unrelated stream on the
  same connection remains usable.
- HEADERS on stream 0 now returns connection-scope `GOAWAY` with
  `PROTOCOL_ERROR`.
- stray CONTINUATION and DATA interleaved while CONTINUATION is required now
  return connection-scope `GOAWAY` with `PROTOCOL_ERROR`.
- valid fragmented HEADERS/CONTINUATION blocks are buffered, decoded once
  `END_HEADERS` arrives, and dispatched only after the complete field section
  is available.
- over-limit encoded HEADERS/CONTINUATION accumulation resets only the
  offending stream and leaves a later unrelated stream on the same connection
  usable.
- malformed/truncated HPACK integer encoding now returns connection-scope
  `GOAWAY` with `COMPRESSION_ERROR`.

Validation:

```sh
zig build test-integration -Dintegration-test-filter='interop.h2.' \
  --summary all --error-style verbose
```

Result on 2026-08-25: passed. Build summary reported `8/8 steps succeeded;
30/30 tests passed`.

## Independent H2 Client Attempts

`nghttp` was available, but this build does not expose a connect-to/resolve
override. The local test certificate identity is `tardigrade.test`, while the
temporary server listens on loopback. Without changing host resolution, `nghttp`
could not be used to connect to `127.0.0.1` while sending the required
authority/SNI.

curl was also available with HTTP/2 support and was attempted with
`--http2 --resolve tardigrade.test:<port>:127.0.0.1 --noproxy '*'`. In this
environment the server logged `error.NoApplicableCredential` during readiness
probes, so the manual curl slice was not counted as proof. The OpenSSL H2 rows
above remain the successful independent external H2 proof for this local slice
because they set both ALPN and SNI explicitly and complete application-level
HTTP/2 exchanges.

## Coverage and Remaining Gaps

Covered by this slice:

- local Zig version and host identity recorded
- required `zig build test` gate passed
- required `zig build test-quic` gate passed
- ReleaseFast `zig build test-quic` gate passed
- HTTP/3 repeated connection, resumption, cancellation, and resource-settle
  soaks passed in the PR-safe profile
- heavy HTTP/3 soak profile passed for the filtered `soak.h3.` rows
- native TLS/H2 listener integration passed
- TLS interop CI profile passed with OpenSSL/GnuTLS record rows, an explicit
  OpenSSL `h2` ALPN entrypoint, and QUIC loopback `h3` tuples
- OpenSSL H2 external-client rows passed
- HTTP/2 malformed/proxy/flow-control filtered integration rows passed,
  including this PR's failure-scope rows listed above
- ReleaseFast HTTP/2 malformed/proxy/flow-control filtered integration rows
  passed
- native upstream H2 best-effort proxied request row passed
- resumption/restart/rotation/soak filtered integration rows passed with
  documented skips
- failure-mode chaos harness passed
- request parser security corpus passed
- deterministic QUIC/H3 driver scenarios passed
- reload/shutdown lifecycle subset passed
- H3 UDP runtime drain smoke passed
- native H3 interop tool built
- external H3 peer matrix reported explicit local skips
- ngtcp2/GnuTLS external H3 peer was built locally with a `/tmp` include-order
  workaround
- external H3 matrix passed the native/ngtcp2 directions and HRR directions
- production `h3interop.quic.*` rows passed with the ngtcp2/GnuTLS client
- resumption/restart/rotation/soak filtered integration rows passed 49/49 with
  the ngtcp2/GnuTLS client wired in
- required `zig build test-integration` gate passed in final #680 validation;
  the earlier Bearclaw failures are historical and fixed

Not covered by this slice:

- execution against an actual installed/Homebrew release-candidate `tardi`
  artifact; the repeatable `TARDI_BIN=... scripts/run-http-release-sweep.sh`
  path exists for H2/native TLS integration rows, and local ReleaseFast
  fallback validation is acceptable only when no installed candidate is
  available
- independent HTTP/2 TLS/ALPN/application exchange using `nghttp` specifically
- malformed/truncated H2 frame-header and declared-payload-shorter-than-frame
  rows where the peer cannot send a complete frame; these are currently
  connection-close/read-boundary cases rather than GOAWAY-proven protocol rows
- browser protocol attempts
- real external HTTP/3 peer proof with quiche or aioquic
- black-box H3 proof that launches the selected `TARDI_BIN`; current H3 rows
  in the wrapper are source-tree regression evidence
- H3 Alt-Svc proof against a usable advertised endpoint
- controlled-host resource sweep beyond the existing PR-safe soaks
- final #389 stable-promotion evidence

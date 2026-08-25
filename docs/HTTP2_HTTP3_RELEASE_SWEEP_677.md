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
zig build test-integration-resumption-interop --summary all --error-style verbose
```

Result: passed. Build summary reported `8/8 steps succeeded; 43/49 tests
passed (6 skipped)`.

Additional visible soak output:

- `soak.reconnect_resumption: iterations=40 accepted=40 executions=80 heavy=false`
- `soak.persistent.multi_process_nonce_safety: heavy=false rounds=2 samples_per_process=8 lease_width=1000000 final_generation=3 tuples=52`

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

## Failed Local Gate

```sh
zig build test-integration --summary all --error-style verbose
```

Result: failed. Build summary reported `6/8 steps succeeded`; the integration
test binary reported `160 pass, 19 skip, 3 fail (182 total)`.

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

That invocation produced no output for several minutes and was interrupted.
The full integration failure above is the actionable evidence for this slice;
a follow-up should isolate the curl stderr/stdout for the three Bearclaw HTTPS
cases and decide whether the failure is environment-specific, test flakiness,
or a product regression.

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
- HTTP/3 repeated connection, resumption, cancellation, and resource-settle
  soaks passed in the PR-safe profile
- native TLS/H2 listener integration passed
- OpenSSL H2 external-client rows passed
- HTTP/2 malformed/proxy/flow-control filtered integration rows passed
- resumption/restart/rotation/soak filtered integration rows passed with
  documented skips
- native H3 interop tool built
- external H3 peer matrix reported explicit local skips
- required `zig build test-integration` gate was run and produced concrete
  failures for triage

Not covered by this slice:

- release artifact identity from an installed/release candidate `tardi`
- independent HTTP/2 TLS/ALPN/application exchange using `nghttp` specifically
- HTTP/2 malformed frame and HPACK failure-scope matrix
- browser protocol attempts
- real external HTTP/3 peer proof with ngtcp2, quiche, or aioquic
- H3 Alt-Svc proof against a usable advertised endpoint
- controlled-host resource sweep beyond the existing PR-safe soaks
- final #389 stable-promotion evidence

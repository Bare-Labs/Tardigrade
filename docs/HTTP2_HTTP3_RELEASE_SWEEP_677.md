# HTTP/2 and HTTP/3 Release Sweep Slice (#677)

## Final Closeout: 2026-08-27 (commit `a30ff0f3e2af`)

This section supersedes the "Closeout Slice: 2026-08-27" section below, which
recorded a `#694` review pass that used a local ReleaseFast fallback, skipped
the black-box H3 external-peer rows, and (per the review) had a
self-contradictory static/404 predicate. This section is the final,
post-review-remediation evidence run against the exact commit that closes
`#694`'s remaining findings, plus two more product/harness defects discovered
while re-running the black-box row (see "Defects found and fixed" below).

- Commit: `a30ff0f3e2af09843599f55ae99356ca728f4e5c` (branch
  `codex/issue-677-release-sweep-closeout`)
- OS: macOS 26.3, Darwin 25.3.0, arm64 (Apple M4)
- Zig: `0.16.0`
- nghttp/h2load: `nghttp2/1.69.0`
- OpenSSL: `3.6.3` (Homebrew; the system `curl`/`openssl` alias resolves to an
  ancient bundled LibreSSL 3.3.6 that fails the handshake against this
  server's cipher/group selection -- use the Homebrew `openssl` binary, not
  system `curl`, for any manual TLS 1.3 probe on this class of host)
- GnuTLS: `gnutls-cli 3.8.13`
- ngtcp2/GnuTLS H3 peer: built from source, pinned `nghttp3 v1.18.0` +
  `ngtcp2 v1.25.0` (the same pins `scripts/interop/build-h3-peer-ci.sh` uses)
- aioquic: `1.3.0`, installed into an isolated `venv` (`pip install aioquic`)
- Second independent H3 implementation: aioquic (quiche was not attempted --
  its example client/server need a Rust/Cargo build not set up in this pass;
  ngtcp2 + aioquic already give two independent H3 implementations in both
  directions, so this is recorded as a disposition, not a gap)

### Release-artifact identity

Two artifacts were exercised, deliberately: the actual last-published release
(to prove the pre-fix defects this PR closes actually shipped), and a fresh
ReleaseFast build of the exact final commit (the closeout candidate).

**Published `v0.6.3` release** (downloaded via `gh release download`,
SHA-256-verified against the release's own `tardigrade-checksums.txt`):

- `tardi version`: `0.6.3 (tls-profile=general, tls-backend=native)`
- artifact SHA-256: `3264be223a7d32483844b193389412e9c237a97fd6f9797ac5006c0ed991763e`
- source SHA: `9e871817e82b9aec28060b0e7a26a5f2f388f470` (predates this PR)

**Final-head ReleaseFast build** (`zig build -Doptimize=ReleaseFast
-Dversion=issue-677-closeout-final`):

- `tardi version`: `issue-677-closeout-final (tls-profile=general, tls-backend=native)`
- artifact SHA-256: `9c6edb4a89655b3bf0f33f9118e9c6951893b2dba4851930ed669086eebe0478`
- source SHA: `a30ff0f3e2af09843599f55ae99356ca728f4e5c`

### Black-box release-artifact sweep, before/after

```sh
TARDI_BIN=<artifact> \
NGTCP2_EXAMPLES_DIR=/tmp/tardigrade-h3-peer/client/build/examples \
AIOQUIC_PYTHON=<venv>/bin/python \
HTTP_SWEEP_RESOURCE_CYCLES=30 \
scripts/http-release-blackbox-677.sh
```

| Row | `v0.6.3` (pre-fix) | final head `a30ff0f3e2af` |
| --- | --- | --- |
| independent `nghttp` H2 (static/404/proxy/proxy-error/HEAD/POST small+large) | **FAIL** | **PASS** |
| Alt-Svc advertised when H3 usable | PASS | PASS |
| black-box ngtcp2/GnuTLS H3 (static/proxy over real QUIC) | **FAIL** | **PASS** |
| second H3 implementation (aioquic) | PASS | PASS |
| Alt-Svc withheld when H3 disabled | PASS | PASS |
| resource settle (30 cycles) | `before rss_kb=4192` -> `cycle_30 rss_kb=9344` -> `after_settle rss_kb=7088`, `fds=10 sockets=2` throughout | `before rss_kb=4144` -> `cycle_30 rss_kb=8880` -> `after_settle rss_kb=6624`, `fds=10 sockets=2` throughout |

`v0.6.3`'s two failures are exactly the two defects this PR fixes, confirmed
by inspecting its own black-box logs:

- `nghttp-head.log`: `[INVALID; error=Protocol error] recv DATA frame` -- the
  pre-fix direct-return HEAD sends a body-bearing DATA frame after HEADERS
  instead of ending on HEADERS.
- `gtlsclient-h3-multi.log`: `stream 0x0 [:status: 404]` for `/index.html` --
  the pre-fix H3 path has no top-level static-root fallback (see below).

Neither FD count nor socket count grew across 30 cycles on either artifact;
RSS returns to a low, bounded plateau after the cycle burst rather than
growing linearly with cycle count.

### External H3 peer matrix (`scripts/interop/run-interop.sh`)

```sh
NGTCP2_EXAMPLES_DIR=/tmp/tardigrade-h3-peer/client/build/examples \
AIOQUIC_PYTHON=<venv>/bin/python \
scripts/interop/run-interop.sh
```

Result: `6 passed, 0 failed, 2 skipped` (final head).

| Direction | Result |
| --- | --- |
| native client -> ngtcp2 `gtlsserver` | PASS |
| ngtcp2 `gtlsclient` -> native server | PASS |
| #333 native HRR client -> ngtcp2 `gtlsserver` | PASS |
| #333 ngtcp2 HRR `gtlsclient` -> native server | PASS |
| native client -> aioquic server | PASS |
| aioquic client -> native server | PASS |
| native client -> quiche `http3-server` | SKIP (no Rust/Cargo build in this pass) |
| quiche `http3-client` -> native server | SKIP (same) |

### Production resumption/0-RTT/HRR rows with the real peer wired in

```sh
DYLD_LIBRARY_PATH=<peer libs> \
H3_INTEROP_CLIENT_PATH=/tmp/tardigrade-h3-peer/client/build/examples/gtlsclient \
zig build test-integration -Dintegration-test-filter='h3interop.quic.' --summary all --error-style verbose
```

Result: passed, `8/8 steps succeeded; 4/4 tests passed` -- ordinary
resumption, safe early request, unsafe-method 425, and replay/fallback rows
all green against a real external GnuTLS/ngtcp2 client.

```sh
DYLD_LIBRARY_PATH=<peer libs> \
H3_INTEROP_CLIENT_PATH=<gtlsclient> \
zig build test-integration-resumption-interop --summary all --error-style verbose
```

Result: passed, `8/8 steps succeeded; 65/65 tests passed`.

### Required test gate, exact final head

```sh
zig build test --summary all --error-style verbose
zig build test-integration --summary all --error-style verbose
zig build test-quic --summary all --error-style verbose
```

All three passed with no failures on commit `a30ff0f3e2af`: `test`:
`3885/3895` (10 skipped), `test-integration`: `180/199` (19 skipped, no
`H3_INTEROP_CLIENT_PATH` configured for this particular invocation --
see the peer-wired reruns above for that coverage), `test-quic`:
`984/984`.

### Defects found and fixed in this closeout

1. **Use-after-free** (`src/edge_gateway.zig`,
   `appendHttp2UpstreamResponseHeaders`): the proxied-HEAD
   `Content-Length` fix from the prior slice appended
   `response.representation_content_length` -- owned by the response's
   `metadata_arena` -- directly into the H2 header list, but the caller
   deinitializes that arena before the list is HPACK-encoded. Fixed by
   duplicating the value into `owned_values` like every other upstream
   header.
2. **Missing H2-origin propagation** (`src/gateway_proxy.zig`,
   `h2ResponseToBuffered`): the representation-length field was populated
   only by the HTTP/1 parser, so a downstream H2 HEAD proxied to a native H2
   (h2c) upstream still lost `Content-Length`. Fixed by scanning
   `h2resp.headers` for `content-length` in the H2-origin conversion path
   too.
3. **Connection-token trust-boundary bypass** (`src/gateway_proxy.zig`,
   `parseBufferedUpstreamResponse`): the representation-length capture ran
   before the existing `Connection`-nomination filter, so a hostile or
   misbehaving upstream sending `Connection: content-length` alongside a
   real `Content-Length` could smuggle that value past the trust boundary
   through this new hidden field. Fixed by gating the capture (and the
   ordinary forwarding skip) on the same `anyRawConnectionHeaderReferencesHeader`
   check.
4. **H3 top-level static-root fallback gap** (`src/gateway_handlers.zig`,
   new discovery): H1 (`resolveRequestConfig`) and H2
   (`buildHttp2StaticResponse`) both serve a request from the top-level
   `root`/`try_files` when no `location {}` block matches -- the
   nginx-style implicit `location /`. `routeHttp3Location` had no such
   fallback: any path outside an explicit `location { root ...; }` block
   404'd over H3 even with a top-level `root` configured, which the
   identical request served correctly over H1/H2. Found by re-running the
   black-box row's `/index.html` request over real QUIC once the
   authority/vhost mismatch below was fixed. Fixed by adding
   `handleHttp3TopLevelStaticFallback`, invoked from
   `handleHttp3Connection`'s final fallthrough before the 404, with two new
   unit regressions in `gateway_handlers.zig`.
5. **Harness: static/404 black-box predicate contradiction**
   (`scripts/http-release-blackbox-677.sh`): `try_files $uri /index.html;`
   made `/missing` resolve to the index fallback (200), while the same
   script's own predicate still asserted a 404 for it. Fixed by dropping the
   SPA-style fallback (`try_files $uri;`), keeping the static (`/index.html`)
   and 404 (`/missing`) rows independently provable.
6. **Harness: H3 external-client authority mismatch**
   (`scripts/http-release-blackbox-677.sh`,
   `scripts/interop/aioquic_client.py`): the gtlsclient/aioquic H3 rows sent
   `:authority: localhost` or a bare IP. Both have a valid TLS-SNI credential
   in this harness's cert map, so the handshake succeeds, but neither
   matches the config's `server_name tardigrade.test`, so the gateway's
   virtual-host resolution 404s -- exactly as HTTP/1.1 would for a
   mismatched `Host` header hitting a name-based vhost. This looked like a
   protocol-level H3 defect until isolated with `h3_interop_tool` and
   `curl`/`openssl s_client` against the same config over H1/H3 with
   authority held constant. Fixed by using `tardigrade.test` as the
   authority (matching the existing H1 probe's `--resolve`/`-servername`
   pattern) and adding an optional 4th `AUTHORITY` argument to
   `aioquic_client.py`.
7. **Harness: gtlsclient hexdump-line-wrap grep fragility**
   (`scripts/http-release-blackbox-677.sh`): gtlsclient logs received
   bodies as a hexdump wrapped at 16 bytes per line. The 19-byte
   `blackbox-static-ok\n` needle straddled a wrap boundary, so a
   single-line `grep -q` silently failed even though the byte-for-byte
   response content was correct. Fixed by extracting just the `|...|`
   ASCII column from each dump line and concatenating before searching
   (plain newline-stripping is not sufficient -- the next line's own
   offset/hex columns would still be spliced into the needle).
8. **Harness: `run-interop.sh` fails on macOS's stock bash**
   (`scripts/interop/run-interop.sh`): the script's `set -u` plus
   `"${native_artifact_args[@]}"` on an empty array is a known bash
   incompatibility -- pre-4.4 bash (macOS ships 3.2 at `/bin/bash` for
   licensing reasons) treats this as an unbound-variable error; 4.4+ does
   not. This blocked running the external H3 peer matrix on this host at
   all, independent of any peer being configured. Fixed with the portable
   `"${arr[@]+"${arr[@]}"}"` idiom at all 8 call sites.

Items 1-3 and 5 are the four blockers from the prior `#694` review pass.
Items 4, 6, 7, 8 were found while re-verifying the fix for item 5 against
real external peers; each has a focused regression and was re-verified
against the exact final commit above.

### Browser-client disposition

Chrome/Firefox/Safari versions were recorded in the prior slice
(`Chrome 152.0.7977.64`, `Firefox 150.0.3`, `Safari 26.3`) but no automated
in-browser protocol proof was completed then or in this pass. This pass
attempted to drive a Chromium-based browser (this environment's sandboxed
browser tool) against a locally running `tardi` instance; the browser
sandbox could not reach either `tardigrade.test` or `127.0.0.1` on this
host's loopback (network-isolated from the shell environment that runs the
server), so no page ever loaded far enough to observe protocol behavior.
Driving a real, unsandboxed Safari/Chrome/Firefox would need an
interactive, permissioned desktop-automation session, which this autonomous
closeout pass does not have. Per the issue's own guidance ("record
limitations honestly when browser internals make protocol forcing/proof
unreliable... command-line external peers remain the canonical
deterministic proof"), this is recorded as an honest gap rather than a
fabricated pass: the command-line `nghttp` (H2) and ngtcp2/aioquic (H3) rows
above are the canonical, reproducible proof for this closeout.

### Linked evidence

This evidence is linked back to #389 as reusable pre-performance
correctness evidence (see the #389 comment posted alongside this PR).

## Closeout Slice: 2026-08-27

- Source SHA before this PR commit: `9e871817e82b9aec28060b0e7a26a5f2f388f470`
- Branch: `codex/issue-677-release-sweep-closeout`
- OS: macOS 26.3, Darwin 25.3.0, arm64
- Zig: `0.16.0`
- curl: `8.7.1`
- nghttp: `nghttp2/1.69.0`
- OpenSSL: `3.6.3`
- Installed `tardi` on PATH: unavailable in this environment; the repeatable
  harness now accepts `TARDI_BIN` and was exercised against the local
  ReleaseFast fallback artifact.
- Browser version discovery: Chrome `152.0.7977.64`, Firefox `150.0.3`, Safari
  `26.3`; no automated in-browser HTTP/3 protocol proof was run from this
  terminal-only environment.

ReleaseFast fallback artifact:

```sh
zig build -Doptimize=ReleaseFast -Dversion=issue-677-blackbox \
  --summary all --error-style verbose
TARDI_BIN="$PWD/zig-out/bin/tardi" HTTP_SWEEP_RESOURCE_CYCLES=4 \
  scripts/run-http-release-sweep.sh
```

Results:

- build: passed, `4/4 steps succeeded`; composed sweep wrapper also completed
- binary: `.zig-cache/http-release-sweep-677/selected-tardi`
- `tardi version`: `issue-677-blackbox (tls-profile=general, tls-backend=native)`
- binary SHA-256:
  `d92471d3607b6ec2038cec50a7b090211d219c3c99c746d07689b97d77af2d30`
- independent `nghttp` H2 proof: passed over ALPN `h2`, including SETTINGS,
  200 static return, 404 miss, 500 proxied upstream error, HEAD without DATA,
  and small/large POST proxy bodies
- Alt-Svc enabled proof: passed, emitted `h3=":53967"` for the selected UDP port
- Alt-Svc disabled proof: passed, HTTP/1.1 200 response with no `h3` Alt-Svc
- resource settle sample: `before rss_kb=4064 fds=10 sockets=2`,
  `cycle_2 rss_kb=4912 fds=10 sockets=2`,
  `cycle_4 rss_kb=4912 fds=10 sockets=2`,
  `after_settle rss_kb=4864 fds=10 sockets=2`
- black-box H3 with ngtcp2/GnuTLS: skipped because
  `NGTCP2_EXAMPLES_DIR/gtlsclient` was unavailable
- second H3 implementation: skipped because neither `AIOQUIC_PYTHON` nor
  `QUICHE_EXAMPLES_DIR/http3-client` was configured

Additional H2 malformed-input closeout:

```sh
zig build test-integration -Dintegration-test-filter='interop.h2.' \
  --summary all --error-style verbose
```

Result: passed, `8/8 steps succeeded; 33/33 tests passed`. This includes the
previously incomplete truncated-frame-header EOF and truncated-frame-payload EOF
boundary rows. Both prove the malformed connection closes cleanly and a fresh
request can still complete on the listener afterward.

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
- over-limit encoded HEADERS/CONTINUATION accumulation returns connection-scope
  `GOAWAY` with `COMPRESSION_ERROR`, including when existing buffered request
  bodies leave insufficient remaining connection-memory budget.
- malformed/truncated HPACK integer encoding now returns connection-scope
  `GOAWAY` with `COMPRESSION_ERROR`.

Validation:

```sh
zig build test-integration -Dintegration-test-filter='interop.h2.' \
  --summary all --error-style verbose
```

Result on 2026-08-25: passed. Build summary reported `8/8 steps succeeded;
31/31 tests passed`.

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

## Coverage and Remaining Gaps (superseded by "Final Closeout" above)

The bullets below described the state of an earlier, partial slice and are
retained only as historical record of the incremental sequence
(#680 -> initial #694 slice -> this final closeout). They are **not** the
current state; see "Final Closeout" at the top of this document for what is
actually true as of commit `a30ff0f3e2af09843599f55ae99356ca728f4e5c`. In
particular, the following items previously listed as "Not covered" are now
covered:

- independent `nghttp` H2 exchange: now passes against both the published
  `v0.6.3` release artifact's own general rows and the final-head build
  (static/404/proxy/proxy-error/HEAD/POST-small/POST-large)
- black-box H3 proof against the selected `TARDI_BIN` over real QUIC: now
  passes with a from-source ngtcp2/GnuTLS peer and aioquic
- real external HTTP/3 peer proof: now covered by aioquic (quiche remains an
  explicit skip -- see the "Second independent H3 implementation"
  disposition at the top)
- H3 Alt-Svc proof against a usable advertised endpoint: now covered (the
  black-box ngtcp2/aioquic rows complete a real request against the
  advertised port)
- browser protocol attempts: attempted and given an honest disposition (see
  "Browser-client disposition" above), not silently dropped
- required `zig build test-integration` gate: passed clean on the final
  commit, no Bearclaw-style flakiness observed

Still genuinely not covered by this closeout (unchanged from before, and
consistent with #677's own non-goals / #389's separate ownership):

- execution against an actual installed/Homebrew *package* of `tardi`
  specifically (as opposed to a checksum-verified downloaded release
  archive, which was used here and is the closest available proxy on a host
  with no Tardigrade Homebrew tap)
- a second external H3 implementation beyond aioquic (quiche), for lack of a
  Rust/Cargo build in this pass
- real, unsandboxed browser (Safari/Chrome/Firefox) protocol-forcing proof
- controlled-host resource/performance sweep beyond the existing PR-safe
  soaks and this closeout's 30-cycle black-box resource-settle sample
  (explicitly #389/#593/#669's ownership, not #677's)
- final #389 stable-promotion evidence and support-matrix flip (explicitly
  #389's ownership; this closeout's evidence is meant to be reusable input
  to that process, not a replacement for it)

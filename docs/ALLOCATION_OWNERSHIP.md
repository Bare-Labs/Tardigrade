# Hot-Path Allocation Ownership

Issue #143 reconciles allocation ownership for the general HTTP and reverse-proxy
runtime. The allocation counter harness from issue #155 remains the source of
deterministic hot-path allocation budgets; this note records what owns each
meaningful allocation class, when it may be released, and why the current
measurements do not justify a broad request arena.

## Measured Scenarios

`zig build bench-allocations` on `main` before this audit reported:

| Scenario | Allocations/request | Bytes/request | Peak live bytes |
| --- | ---: | ---: | ---: |
| `static-tiny-file-warm` | 13.00 | 779.00 | 311 |
| `static-304-conditional` | 13.00 | 779.00 | 311 |
| `proxy-keepalive-warm` | 6.00 | 410.00 | 239 |
| `rejected-overload` | 12.00 | 716.00 | 407 |

The audit adds deterministic harness rows for header-heavy proxy parsing and
route matching:

- `proxy-header-heavy-response` routes allocation-capable production parsing
  through the counting allocator, then serializes the filtered response through
  caller-owned output. This makes the arena-owned response metadata observable
  instead of relying on an allocator-free serializer alone.
- The four `mixed-route-*` rows cover one route lookup per reported request
  class: exact match, priority prefix, regex match, and plain-prefix return
  after a case-sensitive anchored literal regex miss. They return borrowed route slices, but
  regex evaluation requires request-owned Zig scratch. This audit makes that
  scratch allocator-aware and budgeted; case-sensitive anchored literal misses skip full regex
  preparation before `regcomp`, and POSIX `regcomp` may still allocate through
  libc outside the Zig allocator interface.
- `h1-regex-route-arena-reset` models the production HTTP/1 request arena by
  putting the counter under an arena, performing two regex route resolutions in
  one request lifecycle, and asserting the backing allocator returns to zero
  live bytes only after request-arena deinit.

The after run reported:

| Scenario | Allocations/request | Bytes/request | Peak live bytes |
| --- | ---: | ---: | ---: |
| `static-tiny-file-warm` | 13.00 | 779.00 | 311 |
| `static-304-conditional` | 13.00 | 779.00 | 311 |
| `proxy-keepalive-warm` | 6.00 | 410.00 | 239 |
| `proxy-header-heavy-response` | 4.00 | 1742.00 | 1742 |
| `mixed-route-exact` | 0.00 | 0.00 | 0 |
| `mixed-route-priority` | 0.00 | 0.00 | 0 |
| `mixed-route-regex` | 4.00 | 181.00 | 146 |
| `mixed-route-prefix-after-regex` | 0.00 | 0.00 | 0 |
| `h1-regex-route-arena-reset` | 1.00 | 256.00 | 256 |
| `rejected-overload` | 12.00 | 716.00 | 407 |

The measurement-only header-heavy helper was also applied to a temporary
`main` worktree, because it exercises existing buffered proxy parsing and does
not depend on this branch's matcher changes:

| Scenario | Build | Allocations/request | Bytes/request | Peak live bytes |
| --- | --- | ---: | ---: | ---: |
| `proxy-header-heavy-response` | base | 4.00 | 1742.00 | 1742 |
| `proxy-header-heavy-response` | head | 4.00 | 1742.00 | 1742 |

For mixed routing, base has an instrumentation boundary: before this fix, regex
matching used `std.heap.page_allocator`, so the harness could not observe Zig
regex scratch through the request allocator. The head route rows above are the
first allocator-visible budgets for those request classes. Exact and
priority-prefix requests still avoid regex scratch entirely; anchored literal
regex misses now skip full regex preparation before `regcomp`, so the
prefix-after-regex row also stays at zero allocator churn. Regex matches record
the now request-allocator-owned Zig scratch while still documenting the external
libc `regcomp` boundary.

No reusable workspace or pool was introduced, so there is no workspace
high-water mark, fallback count, or retained capacity contract to report.

## Live Evidence

Base and head release binaries were built from `main` and this branch and run on
the same local macOS loopback host with PID sampling. These are local fallback
rows, not canonical release-baseline numbers; they are included to record the
latency/CPU/RSS shape for the ownership audit.

CI-smoke command shape:

```bash
benchmarks/ci-smoke.sh --duration 5 --connections 4 --threads 1 --save <file>
```

| Scenario | Build | req/s | p99 ms | p999 ms | CPU % | Peak RSS MiB | Errors |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `static-http1` | base | 38147.35 | 0.284 | 3.228 | 285.11 | 4.94 | 0 |
| `static-http1` | head | 42345.02 | 0.242 | 3.068 | 303.79 | 4.91 | 0 |
| `proxy-http1` | base | 15011.66 | 0.934 | 2.823 | 116.20 | 5.27 | 0 |
| `proxy-http1` | head | 15423.09 | 0.782 | 2.535 | 120.00 | 5.20 | 0 |
| `keepalive` | base | 42553.87 | 0.230 | 3.143 | 302.97 | 5.28 | 0 |
| `keepalive` | head | 39439.34 | 0.233 | 1.872 | 293.77 | 5.20 | 0 |

Regex route benchmark config:

```nginx
pid /tmp/issue143-regex-live-<build>/tardi.pid;
listen <port>;
metrics_path /status/metrics;

location = /health {
    return 200 ok;
}

location /regex/ {
    proxy_pass http://127.0.0.1:<upstream-port>;
}

location ~ ^/regex/health$ {
    proxy_pass http://127.0.0.1:<upstream-port>;
}

location ~ ^/assets/.+\.css$ {
    proxy_pass http://127.0.0.1:<upstream-port>;
}

location /prefix/ {
    proxy_pass http://127.0.0.1:<upstream-port>;
}
```

Regex route benchmark command shape:

```bash
TARDIGRADE_RATE_LIMIT_RPS=0 \
TARDIGRADE_MAX_REQUESTS_PER_CONNECTION=0 \
TARDIGRADE_UPSTREAM_RETRY_ATTEMPTS=1 \
./zig-out/bin/tardi run -c /tmp/issue143-regex-live-<build>/tardigrade.conf &
pid=$!

benchmarks/run.sh --duration 5 --connections 4 --threads 1 --tool wrk \
  --scenarios proxy-http1 \
  --proxy-path <path> \
  --pid "$pid"
```

| Scenario | Build | Path | req/s | p99 ms | p999 ms | CPU % | Peak RSS MiB | Errors |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `regex-match` | base | `/regex/health` | 18912.18 | 5.261 | 14.807 | 133.20 | 5.52 | 0 |
| `regex-match` | head | `/regex/health` | 22493.27 | 2.849 | 10.331 | 127.82 | 5.55 | 0 |

The `regex-match` path returns from the regex location and exercises the
request-owned regex scratch path. The initial 5s `prefix-after-regex` sample
showed noisy tail latency after moving scratch into the request allocator, so
the matcher now performs a conservative case-sensitive anchored-literal prefix check before
full regex preparation. A repeated run then measured the affected
plain-prefix-after-nonmatching-regex shape with 5 independent 15s samples per
build:

```bash
benchmarks/run.sh --duration 15 --connections 4 --threads 1 --tool wrk \
  --scenarios proxy-http1 \
  --proxy-path /prefix/health \
  --pid "$pid" \
  --save prefix-<build>-<run>.json
```

| Build | req/s median (min-max) | p99 ms median (min-max) | p999 ms median (min-max) | CPU % median (min-max) | Peak RSS MiB median (min-max) | Errors |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| base | 24553.11 (22252.61-25018.83) | 0.386 (0.348-0.619) | 3.177 (1.201-12.082) | 169.19 (160.03-170.09) | 5.09 (5.00-5.69) | 0 |
| head | 24937.52 (23197.48-25110.12) | 0.456 (0.387-0.497) | 2.908 (1.636-65.429) | 146.02 (141.59-147.13) | 4.69 (4.59-5.39) | 0 |

After the case-sensitive anchored-literal miss fast path, the deterministic allocation row for
this shape is `0.00` allocations and `0.00` bytes per request. The repeated live
run no longer reproduces the original p999 regression by median; p99 remains in
the same local-run band with overlapping ranges, while throughput, sampled CPU,
and RSS are neutral-to-better on head. CPU and p999 are still short local macOS
PID/wrk samples and are recorded as fallback evidence rather than canonical
release-baseline numbers.

Large streaming proxy server config:

```nginx
pid /tmp/issue143-<build>/tardi.pid;
listen <port>;
metrics_path /status/metrics;

location = /health {
    return 200 ok;
}

location /proxy/ {
    proxy_pass http://127.0.0.1:<upstream-port>;
    proxy_streaming response;
}
```

Large streaming proxy launch and benchmark shape:

```bash
TARDIGRADE_RATE_LIMIT_RPS=0 \
TARDIGRADE_MAX_REQUESTS_PER_CONNECTION=0 \
TARDIGRADE_UPSTREAM_RETRY_ATTEMPTS=1 \
./zig-out/bin/tardi run -c /tmp/issue143-<build>/tardigrade.conf &
pid=$!

benchmarks/run.sh --duration 5 --connections 2 --threads 1 \
  --proxy-payload-1m-path /proxy/payload-1m.bin \
  --proxy-slow-client-path /proxy/payload-16m.bin \
  --slow-client-connections 2 \
  --slow-client-limit-rate 2M \
  --scenarios proxy-payload-1m,proxy-slow-client-download \
  --pid "$pid"
```

| Scenario | Build | req/s | p99 ms | p999 ms | CPU % | Peak RSS MiB | Errors |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `proxy-payload-1m` | base | 3263.47 | 0.865 | 3.292 | 472341.51 | 5.89 | 2 |
| `proxy-payload-1m` | head | 3265.22 | 0.853 | 2.997 | 395236.62 | 6.14 | 2 |

The 1 MiB row exercises the response-streaming proxy path with PID/RSS
sampling. A single-request metric check against the same config produced
`tardigrade_proxy_streaming_requests_total 1`,
`tardigrade_proxy_buffered_requests_total 0`, and all
`tardigrade_proxy_streaming_fallback_total{reason=...}` counters at `0` for
both base and head, confirming the configured route selected the streaming path.
On this local fallback run, the benchmark driver reported two errors in both
base and head, and the very short 5s macOS CPU sample produced unusable CPU
percentages. The comparable p99/p999, throughput, and RSS rows are still
recorded because they show no branch-specific ownership regression. The
`proxy-slow-client-download` row was attempted with the same config, but the
driver reported only `errors=2` with null latency/CPU/RSS for both builds, so it
is not used as quantitative evidence.

## Ownership Inventory

| Allocation class | Owner | Release/reset boundary | Reuse decision |
| --- | --- | --- | --- |
| Static normalized path, resolved path, cache validators | Request-owned | `StaticServed.deinit` after file response selection/serialization has completed | Direct allocation is retained. Slices are exposed through `StaticServed`, and the current 13 allocations/779 bytes per request stay under the checked budget without a safe common arena boundary for file-backed response metadata. |
| Static file bytes | Request-owned only for buffered static responses; file-backed warm path is OS/file owned | Buffered bodies are freed by `StaticServed.deinit`; file-backed responses close the file after write completion | No broad pooling. The warm tiny-file benchmark keeps file bytes out of heap by requiring `prefer_file_backed`. |
| Proxy target URL and optional query string | Request-owned | Freed before proxy dispatch helper completion, or by the request path before retry/keepalive state is released | Direct allocation is retained. These strings may be needed across retry/error handling for a single request but must not be retained by upstream connection pools. |
| Forwarded request header vector | Worker/request scratch | `stackFallback` storage is released when header assembly returns; heap fallback is freed by `ArrayList.deinit` | Existing bounded stack fallback is the right reuse mechanism. The warm proxy scenario confirms forwarded headers remain stack-backed. |
| Proxy trusted-identity derived header values | Request-owned | Freed with the request's owned header value list after upstream dispatch completes | Direct allocation is retained because values include per-request timestamp/signature material and cannot be shared with connection-owned pools. |
| Exact and priority-prefix server/location matching | Process/config-owned metadata plus borrowed request URI path | Matching returns before dispatch; matched route slices remain tied to the config snapshot | No request workspace is needed. The `mixed-route-exact` and `mixed-route-priority` rows enforce zero request-allocator churn for the request classes that return before regex evaluation. |
| H1 regex server/location matching | Process/config-owned metadata plus request-arena regex scratch | Logical regex scratch frees occur before match return, but the H1 request arena retains backing capacity until `handleConnection` request-arena deinit | Direct request-arena scratch is retained for actual regex evaluation. The `mixed-route-regex` row records logical scratch churn for one matcher invocation/request class, while `mixed-route-prefix-after-regex` proves a case-sensitive anchored literal miss can return the borrowed prefix match without request-allocator churn. `h1-regex-route-arena-reset` models two route resolutions in one H1 request and proves backing storage returns to zero live bytes only after request completion. POSIX `regcomp` remains an external libc allocation boundary; precompiled config-owned regexes are a future targeted optimization if regex-heavy routing becomes material. |
| H2/H3 regex server/location matching | Allocator supplied by the H2/H3 dispatch path plus process/config-owned metadata | Reset follows the supplied allocator's owner, not the route matcher call itself | The matcher is allocator-aware, so H2/H3 callers account scratch against their dispatch allocator. They must not assume a universal match-scoped physical release boundary. |
| Buffered proxy response body | Request-owned, with aggregate proxy-buffer accounting | Released after downstream write completion, abort cleanup, or local capacity failure handling | Existing accounting and streaming fallback rules are the safety mechanism. Reusing this memory in a request arena would risk hiding retained bytes from proxy buffer limits. |
| HTTP/1 streaming relay buffer and response-head arena | Request/proxy-attempt-owned | Released when `streamProxyOverTransport` returns after body relay, abort cleanup, or local capacity failure handling | A request workspace must not reset at response-head generation because the relay buffer and parsed head arena live through the full streaming attempt. They may reset after the attempt completes. |
| HTTP/2 stream receive queues and connection backpressure state | Stream/connection-owned | Queue drain, stream close/reset, connection close, or pool teardown | Never point these structures into request-reset memory. They can outlive a request-local header-generation phase and are independently accounted. |
| Upstream connection pool entries | Connection-owned | Pool eviction, stale retry cleanup, or gateway shutdown | Not a request workspace candidate. Idle keepalive connections intentionally outlive individual requests. |
| Overload/error JSON and response headers | Request-owned | Freed after the rejection response is written and the request is closed | Direct allocation is acceptable because this is not a success hot path and produces structured operator/client errors. |
| Security header config, route config, add-header config, Alt-Svc | Process/config-owned | Config snapshot replacement or shutdown | Not reset by requests. Runtime response formatting borrows these immutable slices. |
| HTTP/2 stream queues, HTTP/3/QPACK state, TLS encrypted-stream buffers | Connection/stream-owned | Stream close, connection close, or protocol-specific teardown | Excluded from request arenas. These owners have independent async/backpressure lifetimes. |
| Access log, metrics, and tracing label values | Borrowed/caller-owned or process-owned | Logging/metrics calls complete after response construction but before request storage could be reused | Request memory must remain valid through logging and metrics emission. Long-lived metrics labels must come from process/config-owned constants. |

## Reset Boundary

For request-owned memory, the safe reset point is after all of the following are
complete:

- response bytes that reference the memory have been written or abandoned;
- HTTP/1 streaming proxy attempts have completed body relay/abort cleanup and
  released request-owned relay/head memory;
- H2/H3 streaming state has either taken ownership of its own buffers or has
  been torn down;
- upstream retry/error cleanup has completed;
- access logging, metrics, and tracing callbacks have consumed any borrowed
  request fields;
- the downstream keepalive connection has been parked without retaining request
  slices.

"Application response selected" is not a sufficient reset boundary. The
observable boundary is request lifecycle completion after write, cleanup, and
post-response accounting.

## Strategy

No broad request arena is introduced. The measured direct allocations are small,
already budgeted, and several classes have lifetimes that either cross the write
boundary or are owned by connection/stream state. The existing targeted
mechanisms match the actual owners:

- `stackFallback` for proxy request header scratch;
- fixed, bounded buffer pools for uniform reusable byte buffers;
- proxy buffer accounting for retained body/relay allocations;
- process/config-owned immutable slices for route/security/header policy;
- direct allocations for rare rejection/error payloads and small request-local
  strings.

The benchmark additions in `src/allocation_regression.zig` make header-heavy
proxy response metadata ownership, per-request route matcher classes, and the
H1 request-arena reset boundary explicit. Any future workspace or pool should
be added only when a measured scenario shows material allocator churn and the
owner has a single reset boundary.

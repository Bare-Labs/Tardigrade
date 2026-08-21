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

The audit adds `proxy-header-heavy-response` to cover upstream response header
filtering and downstream response-head assembly. That path has a zero-allocation
budget because it borrows parsed upstream header slices and writes to a
caller-owned output buffer. The after run reported:

| Scenario | Allocations/request | Bytes/request | Peak live bytes |
| --- | ---: | ---: | ---: |
| `static-tiny-file-warm` | 13.00 | 779.00 | 311 |
| `static-304-conditional` | 13.00 | 779.00 | 311 |
| `proxy-keepalive-warm` | 6.00 | 410.00 | 239 |
| `proxy-header-heavy-response` | 0.00 | 0.00 | 0 |
| `rejected-overload` | 12.00 | 716.00 | 407 |

No reusable workspace or pool was introduced, so there is no workspace
high-water mark, fallback count, or retained capacity contract to report.
Because runtime behavior did not change beyond a deterministic benchmark guard,
latency, CPU/request, RSS, and p99/p999 risk is unchanged from the current
benchmark suite; future runtime reuse changes must record those rows when they
alter allocation ownership.

## Ownership Inventory

| Allocation class | Owner | Release/reset boundary | Reuse decision |
| --- | --- | --- | --- |
| Static normalized path, resolved path, cache validators | Request-owned | `StaticServed.deinit` after file response selection/serialization has completed | Direct allocation is retained. Slices are exposed through `StaticServed`, and the current 13 allocations/779 bytes per request stay under the checked budget without a safe common arena boundary for file-backed response metadata. |
| Static file bytes | Request-owned only for buffered static responses; file-backed warm path is OS/file owned | Buffered bodies are freed by `StaticServed.deinit`; file-backed responses close the file after write completion | No broad pooling. The warm tiny-file benchmark keeps file bytes out of heap by requiring `prefer_file_backed`. |
| Proxy target URL and optional query string | Request-owned | Freed before proxy dispatch helper completion, or by the request path before retry/keepalive state is released | Direct allocation is retained. These strings may be needed across retry/error handling for a single request but must not be retained by upstream connection pools. |
| Forwarded request header vector | Worker/request scratch | `stackFallback` storage is released when header assembly returns; heap fallback is freed by `ArrayList.deinit` | Existing bounded stack fallback is the right reuse mechanism. The warm proxy scenario confirms forwarded headers remain stack-backed. |
| Proxy trusted-identity derived header values | Request-owned | Freed with the request's owned header value list after upstream dispatch completes | Direct allocation is retained because values include per-request timestamp/signature material and cannot be shared with connection-owned pools. |
| Buffered proxy response body | Request-owned, with aggregate proxy-buffer accounting | Released after downstream write completion, abort cleanup, or local capacity failure handling | Existing accounting and streaming fallback rules are the safety mechanism. Reusing this memory in a request arena would risk hiding retained bytes from proxy buffer limits. |
| Streaming proxy relay buffers | Connection/stream-owned | Released when the streaming transfer completes, aborts, or the owning H2/H3 stream/connection closes | Must not move into request-reset memory. Backpressure queues and stream state can retain buffers after response headers are generated. |
| Upstream connection pool entries | Connection-owned | Pool eviction, stale retry cleanup, or gateway shutdown | Not a request workspace candidate. Idle keepalive connections intentionally outlive individual requests. |
| Overload/error JSON and response headers | Request-owned | Freed after the rejection response is written and the request is closed | Direct allocation is acceptable because this is not a success hot path and produces structured operator/client errors. |
| Security header config, route config, add-header config, Alt-Svc | Process/config-owned | Config snapshot replacement or shutdown | Not reset by requests. Runtime response formatting borrows these immutable slices. |
| HTTP/2 stream queues, HTTP/3/QPACK state, TLS encrypted-stream buffers | Connection/stream-owned | Stream close, connection close, or protocol-specific teardown | Excluded from request arenas. These owners have independent async/backpressure lifetimes. |
| Access log, metrics, and tracing label values | Borrowed/caller-owned or process-owned | Logging/metrics calls complete after response construction but before request storage could be reused | Request memory must remain valid through logging and metrics emission. Long-lived metrics labels must come from process/config-owned constants. |

## Reset Boundary

For request-owned memory, the safe reset point is after all of the following are
complete:

- response bytes that reference the memory have been written or abandoned;
- streaming proxy state has either taken ownership of its own buffers or has
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

The benchmark addition in `src/allocation_regression.zig` makes the
header-heavy proxy response path explicit and enforces that response header
filtering stays allocation-free. Any future workspace or pool should be added
only when a measured scenario shows material allocator churn and the owner has a
single reset boundary.

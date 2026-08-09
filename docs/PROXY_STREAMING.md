# Reverse-proxy streaming

Tardigrade can relay reverse-proxy traffic incrementally instead of
materializing whole bodies in memory. This document is the contract for that
behavior: which combinations stream, which fall back to the bounded buffered
path, how a fallback is observed, and what streaming costs in retry and
middleware semantics.

Related: [OBSERVABILITY.md](OBSERVABILITY.md) for the exported metric names,
[TIMEOUTS.md](TIMEOUTS.md) for the per-phase deadlines that bound a stalled
stream, and [UPSTREAM_POOLING.md](UPSTREAM_POOLING.md) for connection reuse.

## Policy

Streaming is off by default. It is selected globally and can be overridden per
route.

**Global** — `TARDIGRADE_PROXY_STREAMING_MODE`, or the `proxy_streaming_mode`
directive in a config file:

| Value | Aliases | Effect |
| --- | --- | --- |
| `off` | `buffered` | Bounded buffered path for every request. |
| `response` | `responses` | Upstream responses stream; request bodies are buffered. |
| `full` | `request_response`, `request-response` | Eligible request bodies stream as well. |

**Per route** — the `proxy_streaming` (or `proxy_streaming_mode`) directive
inside a `location` block, or the `stream:<value>` location option:

| Value | Effect |
| --- | --- |
| `inherit` | Default. Use the global mode. |
| `off` / `buffered` | Force the buffered path for this route. |
| `response` / `responses` | Stream responses for this route even when the global mode is `off`. |
| `full` / `request_response` / `request-response` | Stream responses and eligible uploads for this route. |

A route override replaces the global mode for that route in both directions; it
never partially merges with it.

```nginx
proxy_streaming_mode off;          # global default: buffered

location /bulk/ {
    proxy_pass http://origin;
    proxy_streaming full;          # stream uploads and downloads on this route
}
```

## Supported matrix

Response streaming and request-upload streaming are decided independently, so a
route may stream a large response while buffering a small upload.

### Upstream responses

| Upstream framing | Behavior |
| --- | --- |
| `Content-Length` | Streamed; re-chunked downstream. |
| `Transfer-Encoding: chunked` | Decoded incrementally and re-chunked downstream; chunk extensions and trailers are not forwarded. |
| Close-delimited (HTTP/1.0-style) | Streamed; the upstream connection is not reusable afterwards. |
| Bodiless (HEAD, 1xx, 204, 304) | Head relayed, no body read. |
| HTTP/2 upstream | Streamed over the shared per-origin connection; the stream receive window is replenished only as the downstream relay drains, so a slow client backpressures the origin. |

An HTTP/1.1 upstream connection is returned to the keep-alive pool only when the
framing ended exactly on a message boundary. Extra bytes, a truncated body, or a
close-delimited response mark the connection unusable rather than risking a
desynchronized pipeline.

### Client uploads (`full` mode only)

| Client framing | HTTP/1.1 upstream | HTTP/2 upstream |
| --- | --- | --- |
| `Content-Length` | Streamed with the same `Content-Length`. | Streamed as flow-controlled DATA frames. |
| `Transfer-Encoding: chunked` | Decoded incrementally and re-framed as `Transfer-Encoding: chunked`. | Decoded incrementally and sent as DATA frames terminated by `END_STREAM`; no `Content-Length` is synthesized. |

Chunked uploads are re-framed rather than forwarded byte-for-byte, so chunk
extensions and trailers sent by the client are consumed and dropped, not passed
to the origin. The decoded payload is counted against the configured
request-body maximum while it is relayed: an upload that outgrows the maximum is
rejected with `413` mid-relay, and malformed chunk framing is rejected with
`400`. Neither is attributed to the origin's health.

Because either failure is only detectable once the offending bytes arrive, the
origin has by then received a partial request. How that is cleaned up depends on
the upstream protocol: an HTTP/1.1 connection carries only this request, so it is
closed rather than returned to the pool; an HTTP/2 connection is shared, so only
the affected stream is reset with `CANCEL` and the connection stays reusable for
unrelated multiplexed requests unless it is independently unhealthy.

A streamed upload disables downstream keep-alive for that connection.

### Transports

Unix-socket and mTLS upstreams stream. The streaming relay owns AF_UNIX
connect and pooling directly, and it uses the same `UpstreamTlsOptions` —
including the client certificate and key — as the buffered path. A Unix-socket
upstream always uses HTTP/1.1: there is no origin for the HTTP/2 pool to key or
ALPN-negotiate.

## Fallback reasons

When a request cannot stream, it takes the bounded buffered path and the reason
is recorded on `tardigrade_proxy_streaming_fallback_total{reason=...}` and
logged at debug level with the request's correlation ID.

| Reason | Applies to | Meaning |
| --- | --- | --- |
| `policy_disabled` | response, upload | The effective policy for the route does not enable this direction. |
| `retries_configured` | response, upload | The retry budget resolves to more than one attempt, and a streamed exchange cannot be replayed. |
| `early_data_retry_semantics` | response | The request arrived as replay-exposed TLS early data and needs 425 orchestration, which requires a retryable exchange. |
| `missing_content_length` | upload | A body-bearing method sent neither `Content-Length` nor `Transfer-Encoding`. |
| `body_too_large` | upload | The declared `Content-Length` exceeds the request-body maximum. |
| `body_dependent_middleware` | upload | Rewrite, return, conditional, internal-redirect, mirror, or `auth_request` rules are configured, and they may read or duplicate the body. |
| `unsupported_route_type` | upload | The request did not match a route, or matched a route whose action is not a direct `proxy_pass`. |

Upload and response eligibility are evaluated separately, so a single request can
contribute more than one fallback event.

Streaming eligibility for an upload is decided from the request head, before any
body byte is read. If routing later resolves to something the streaming path
cannot serve, the request fails with `502` rather than silently buffering — the
client bytes have already been committed and cannot be replayed.

## Retry and middleware contract

Streaming trades replayability for bounded memory. The boundaries are:

- **A streamed response cannot be retried once downstream bytes are committed.**
  The response head reaches the client before the body is known to be complete,
  so a mid-body upstream failure surfaces as a truncated body and an
  `tardigrade_proxy_upstream_aborts_total` event, not as a retry. Requests are
  only eligible for streaming when the retry budget is exactly one attempt.
- **A streamed upload is not replayable once client bytes are consumed.** The
  stale-pooled-connection retry that the buffered path performs is disabled for
  streamed uploads even before any response byte exists, because the request
  body has already been forwarded and cannot be re-sent.
- **Body-dependent middleware requires buffering.** Rewrite, return,
  conditional, internal-redirect, mirror, and `auth_request` all need the whole
  body, or need to duplicate it. Routes configured with any of them fall back
  with `body_dependent_middleware`. Making them work with streaming needs an
  explicit tee, not an incidental buffer.
- **Streaming mode is a route behavior decision, not a guarantee.** Enabling
  `full` asks for streaming where it is supported; it does not promise that
  every target and middleware combination can stream. The fallback reasons above
  are the supported way to find out what actually happened.

## Memory

The HTTP/1 relay copies through one fixed buffer per direction and writes to the
far side before reading more, so user-space relay memory does not grow with body
size. The response buffer is `proxy_stream_buffer_size` (floored at 16 KiB); the
upload buffer is a fixed 16 KiB. The HTTP/2 relay is bounded by the per-stream
receive window, replenished only as the downstream relay drains.

### HTTP/2 response bounds

The streaming receive window an HTTP/2 upstream connection advertises is
`TARDIGRADE_PROXY_BUFFER_PER_STREAM_HIGH_WATERMARK_BYTES` — the same value the
accounting model treats as "this stream's queue is full" — so a well-behaved
origin stops sending exactly there. An origin that overruns the window is
committing a flow-control violation and fails only its own stream.

Credit is then returned with hysteresis rather than chunk by chunk. While a
stream's queue sits at or above the high watermark, downstream-consumed bytes
are accumulated but **not** credited back to the origin; the accumulated total
is sent as a single `WINDOW_UPDATE` once the queue drains below
`TARDIGRADE_PROXY_BUFFER_PER_STREAM_LOW_WATERMARK_BYTES`. Crediting each chunk
as it drained would let the origin refill the queue immediately and the
watermark band would never actually pause anything. Each transition is visible
as `tardigrade_buffer_read_pauses_total{side="upstream"}` and
`tardigrade_buffer_read_resumes_total{side="upstream"}`.

Per-stream bounds alone do not bound the process: N concurrent slow streams
retain up to N windows. Two aggregate hard limits close that gap:

| Limit | Scope |
| --- | --- |
| `TARDIGRADE_PROXY_BUFFER_PER_ORIGIN_HARD_LIMIT_BYTES` | every stream on every connection to one upstream origin |
| `TARDIGRADE_PROXY_BUFFER_GLOBAL_HARD_LIMIT_BYTES` | the whole process, across all origins |

Both default to `0`, which means unlimited. Reservations are taken *before* any
memory is committed, and they track each queue's **retained allocation** rather
than its logical length — a drained queue that still owned its peak buffer
would otherwise be invisible to these limits. A queue's storage (and its
reservation) is released as soon as it drains empty.

#### What a refusal does

The behavior depends on whether the downstream response has been committed:

- **Before the response head is written** — including the case where the reader
  rejects DATA between decoding the origin's headers and the worker relaying
  them — the request fails with `503` and the code `proxy_buffer_saturated`.
  This is *local* saturation, so it is never recorded against upstream health
  or the circuit breaker, and it is not retried: a retry would meet the same
  wall.
- **After commitment** the status can no longer change. The stream is reset
  upstream immediately (`RST_STREAM(CANCEL)`), the downstream response is
  truncated, every scope's reservation is released, and the truncation is
  logged. It is counted in `tardigrade_buffer_limit_exceeded_total` at the
  refusing scope but, again, is **not** counted as an upstream failure — local
  memory pressure must not trip a healthy origin's failure policy.

In both cases the stream becomes discard-only: DATA still in flight for it is
dropped without reserving again, so a single refusal cannot be re-counted or
re-queue bytes behind an error the consumer has not seen yet. Unrelated
streams — including others on the same connection — are untouched, and a
refusal rolls back cleanly across scopes, so a stream the origin scope rejects
never leaves bytes reserved at the global scope.

#### Reload semantics

Aggregate hard limits apply immediately, including to origins that already hold
reservations. The per-stream policy — and the receive window derived from it —
applies to connections opened after the reload: `SETTINGS_INITIAL_WINDOW_SIZE`
is negotiated once per connection, and a peer already holding credit is still
judged by what it was granted. Each connection therefore pins the complete
low/high/hard policy it advertised, and every stream on it is measured against
that, never against a newer snapshot.

The HTTP/1 relay's fixed buffers are accounted per stream but are not reserved
against the aggregate scopes; their size does not grow with concurrency the way
an HTTP/2 stream queue does.

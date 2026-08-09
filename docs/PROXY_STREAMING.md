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
`400`. Neither is attributed to the origin's health. Because the failure is only
detectable once the offending bytes arrive, the origin has by then received a
partial request; that upstream connection is torn down rather than pooled.

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

Configurable buffer accounting, aggregate caps, and pause/resume metrics are
tracked separately in #140; the bounds described here are structural, not a
substitute for that enforcement.

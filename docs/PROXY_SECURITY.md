# HTTP Proxy Security Hardening

This document describes Tardigrade's intended security behavior at each HTTP
proxy trust boundary. It is the authoritative reference for what the codebase
guarantees and what operators must configure for safe deployments.

## Threat Model Summary

Tardigrade sits between untrusted external clients and trusted internal
upstreams. The attack surface at this boundary includes:

- Request smuggling via ambiguous body framing (TE/CL conflicts, duplicate
  headers, malformed chunked encoding).
- Header injection and log poisoning via unvalidated header names/values.
- Trust boundary bypass by forwarding client-controlled proxy identity headers.
- Information disclosure via upstream technology headers.
- Directory traversal via path-encoded sequences in static file serving.
- Cross-site tracing (XST) via TRACE method reflection.
- Correlation-ID spoofing to poison audit logs.

## 1. Hop-by-Hop Header Stripping

**RFC 7230 §6.1.** Hop-by-hop headers must not be forwarded beyond the next
hop. Tardigrade strips the following headers in both directions.

### Request direction (client → upstream)

Removed unconditionally before the upstream request is sent:

| Header | Reason |
|---|---|
| `Connection` | Hop-by-hop, not end-to-end |
| `Keep-Alive` | Connection management, not forwarded |
| `Proxy-Authenticate` | Proxy auth, not upstream auth |
| `Proxy-Authorization` | Proxy auth, not upstream auth |
| `Proxy-Connection` | Non-standard keep-alive signal |
| `TE` | Transfer-encoding negotiation |
| `Trailer` | Chunked trailer announcement |
| `Transfer-Encoding` | Body framing, re-framed by Tardigrade |
| `Upgrade` | Protocol upgrade negotiation |
| `Accept-Encoding` | Tardigrade controls upstream compression |
| `Content-Length` | Re-calculated by Tardigrade |
| `Host` | Replaced with the upstream host |

Additionally, any header named by the inbound `Connection` header value is
treated as hop-by-hop and removed. Example: if the client sends
`Connection: X-My-Custom-Header`, Tardigrade strips `X-My-Custom-Header`
before forwarding (RFC 7230 §6.1). See `connectionHeaderReferencesHeader()`
in `src/gateway_proxy_headers.zig`.

### Response direction (upstream → client)

Removed before the client response is written:

| Header | Reason |
|---|---|
| `Connection` | Hop-by-hop |
| `Keep-Alive` | Connection management |
| `Proxy-Connection` | Non-standard |
| `TE` | Transfer-encoding negotiation |
| `Trailer` | Chunked trailer announcement |
| `Transfer-Encoding` | Body framing; re-framed by Tardigrade |
| `Upgrade` | Protocol upgrade |
| `Content-Encoding` | Tardigrade decodes before re-encoding |
| `Content-Length` | Recalculated from materialized body |
| `Server` | Replaced by Tardigrade's own Server header |
| `X-Powered-By` | Technology disclosure (WSTG-INFO-02, ASVS-14.3.3) |
| `X-Request-ID` | Prevents upstream from spoofing correlation IDs |
| `X-Correlation-ID` | Same; Tardigrade emits authoritative IDs |

Additionally, any header named by the upstream response's own `Connection`
header value is treated as hop-by-hop and removed before the response
reaches the client (#673), mirroring the request-direction handling in §2.

Implementation: `shouldSkipUpstreamRequestHeader()` and
`shouldSkipUpstreamResponseHeader()` in `src/gateway_proxy_headers.zig`.

## 2. Connection Header Token Handling

When a `Connection` header lists additional header names (RFC 7230 §6.1),
Tardigrade splits the value on commas, trims whitespace around each token,
and strips the named headers before forwarding. Token comparison is
case-insensitive. This applies in **both directions**: an inbound client
`Connection` header nominates headers to drop before the upstream request is
sent, and an upstream response's own `Connection` header nominates headers to
drop before the response reaches the client (#673) -- a malicious or
misbehaving upstream cannot use this mechanism to smuggle an arbitrary header
past the static hop-by-hop list.

Example (request direction):

```
Connection: X-Foo, X-Bar
X-Foo: client-value
X-Bar: client-value
```

Both `X-Foo` and `X-Bar` are removed before the upstream request is sent,
in addition to `Connection` itself. The same holds symmetrically for an
upstream response that sends `Connection: X-Foo` alongside `X-Foo: ...`.

If `Connection` is itself repeated as multiple header fields, every field's
tokens are honored (#673): a nomination hiding in a second or later
`Connection` field is treated exactly like one in the first, in both
directions. RFC 7230 §3.2.2 treats duplicate fields with the same name as
semantically equivalent to one comma-joined field, and the filtering logic
must not silently fall back to only the first occurrence. Each occurrence's
own value is scanned directly rather than pre-joined into a fixed-size
buffer -- an earlier version of this fix joined every occurrence into a
`[4096]u8` buffer and silently truncated on overflow, which was itself
bypassable by padding earlier fields past the buffer boundary.

Implementation: `anyConnectionHeaderReferencesHeader()` /
`anyRawConnectionHeaderReferencesHeader()` in `src/gateway_proxy_headers.zig`.

## 3. Transfer-Encoding vs Content-Length Conflict

**RFC 7230 §3.3.3** states that a message with both `Transfer-Encoding` and
`Content-Length` is a potential HTTP request smuggling vector and MUST be
rejected. Tardigrade returns `400 Bad Request` for any such request.

Similarly, duplicate `Content-Length` headers (with or without matching
values) are rejected: the parser returns `error.ConflictingHeaders` which the
gateway maps to `400 Bad Request`.

Upstream responses with conflicting framing headers are also treated as
`error.UpstreamProtocolError`, causing a synthetic `502 Bad Gateway`.

Implementation: `src/http/request.zig`, function `Request.parse()`, lines
that set `error.ConflictingHeaders`.

## 4. Duplicate Content-Length

Duplicate `Content-Length` headers are rejected with `error.ConflictingHeaders`
regardless of whether the values match. A single unambiguous value is required.

See the regression corpus case `tests/corpus/http/request/duplicate_content_length.http`.

## 4a. Duplicate Authorization (#673)

HTTP defines no combination semantics for `Authorization`, so a request
carrying more than one `Authorization` field is ambiguous in the same way a
request with duplicate `Content-Length` fields is. Duplicate `Authorization`
headers are rejected with `error.DuplicateAuthorizationHeader` (mapped to
`400 Bad Request`) before routing or auth resolution ever runs -- regardless
of field order, and even when one of the two duplicated values would
otherwise have been a valid credential. A client cannot smuggle a second,
attacker-controlled `Authorization` value past whichever single value a
given code path happens to read.

Implementation: `src/http/request.zig`, `Request.parse()` and
`Request.parseHead()`.

## 5. Header Casing and Normalization

All header names stored by Tardigrade's `Headers` collection are lowercased on
ingress. Lookups are always case-insensitive. Header values are trimmed of
leading and trailing whitespace (HTAB and SP).

Header names must consist only of RFC 7230 token characters: visible ASCII
excluding control characters, DEL (0x7F), and the separator characters
`` ()<>@,;:\"/[]?={} `` and SP/HTAB. The colon separator is also rejected
within a name. Any inbound header that violates this rule is rejected with
`400 Bad Request`.

Header values must not contain CR (0x0D), LF (0x0A), NUL (0x00), or any other
control character (0x00–0x1F, 0x7F). HTAB (0x09) and SP (0x20) are allowed
within a value. This prevents CRLF injection and log poisoning.

Obs-fold (line continuation with LF + SP/HTAB) is rejected; folded headers
produce `400 Bad Request`.

The same name/value validation is applied to **upstream response** headers
before they are forwarded to the client (#673): a header line is only split
on an exact `\r\n` boundary, so without this check a bare CR or embedded NUL
inside what should be a single value would survive parsing and be forwarded
verbatim, letting a hostile or compromised upstream inject control
characters into a response header the client receives. A response with an
invalid header name or value is rejected as `error.UpstreamProtocolError`
(`502 Bad Gateway`) rather than partially forwarded.

Implementation: `isValidHeaderName()`, `isValidHeaderValue()`,
`parseHeaders()` in `src/http/headers.zig`; the same two functions applied
to upstream response headers in `parseBufferedUpstreamResponse()` and
`readUpstreamHead()` in `src/gateway_proxy.zig`.

## 6. Absolute-Form vs Origin-Form Request Targets

Clients may send requests in either origin-form (`GET /path HTTP/1.1`) or
absolute-form (`GET http://example.com/path HTTP/1.1`). Tardigrade's request
parser normalizes absolute-form targets by extracting the path component and
discarding the scheme and authority. The `Host` header value is not overridden
by the absolute-form authority; host-based routing still uses the `Host` header.

Absolute-form URIs with no explicit path component (e.g., `http://example.com`
with no trailing slash) are rejected with `400 Bad Request` (`error.InvalidUri`).

Implementation: `parseUri()` in `src/http/request.zig`.

## 7. Forwarded / X-Forwarded-* Trust Boundary

Tardigrade unconditionally strips all client-supplied `X-Forwarded-For`,
`X-Forwarded-Host`, `X-Forwarded-Proto`, and `X-Real-IP` headers before
forwarding the request upstream. Tardigrade then sets authoritative values
derived from the actual connection:

| Header | Value |
|---|---|
| `X-Forwarded-For` | Client IP appended to any existing chain from a trusted proxy tier in front of Tardigrade (see below) |
| `X-Real-IP` | Direct connection IP |
| `X-Forwarded-Proto` | `https` or `http` based on TLS state |
| `X-Forwarded-Host` | The inbound `Host` header value |

### Trusted upstream identity

When `trust_require_upstream_identity: true` is set in the config, Tardigrade
only treats a forwarding chain as authoritative if the connection originates
from a host in `trusted_upstream_identities`. If an untrusted host sends
`X-Forwarded-For`, that header is stripped and replaced by just the connection
IP.

**Default**: trust is open (any connecting host). Operators running Tardigrade
behind a load balancer MUST set `trusted_upstream_identities` to the load
balancer's address(es) and enable `trust_require_upstream_identity: true` to
prevent clients from spoofing their source IP via `X-Forwarded-For`.

The same trust decision also governs the `client_ip` Tardigrade uses
internally: the identity rate limiting keys unauthenticated traffic on
(`ip:{client_ip}` buckets) and the `client_ip` field written to access logs.
Before #673, this internal resolution (`extractClientIp()`) had no trust
gate at all -- any client could rewrite both just by sending
`X-Forwarded-For`/`X-Real-IP`, live even behind a correctly configured
`trusted_upstream_identities`, because that code path never consulted it.

Implementation: `isTrustedUpstream()`, `buildForwardedFor()`,
`appendProxyRequestHeaders()` in `src/gateway_proxy_headers.zig`;
`extractClientIp()` in `src/http/request_context.zig`; the untrusted-path
header strip in `edge_gateway.zig` (`handleConnection`, right before
`extractClientIp()` is called).

## 8. Host Header Handling

**RFC 7230 §5.4** requires HTTP/1.1 clients to include a `Host` header.
Tardigrade rejects any HTTP/1.1 request that lacks a `Host` header with
`400 Bad Request` before routing or proxying. HTTP/1.0 clients are exempt.

The `Host` header value (stripped of port) is used for virtual-host routing
when multiple server blocks share a port. A non-matching Host produces a
`404 Not Found`.

## 9. Request Body Size Enforcement

The maximum accepted request body is configured via `max_body_size` (default:
1 MB). Bodies exceeding this limit are rejected with `413 Payload Too Large`
after parsing, before any upstream connection is opened. For chunked bodies,
each decoded chunk is accumulated and the running total is checked against the
limit; the first chunk that would push the total over the limit causes
`error.BodyTooLarge`.

## 10. Header Size and Header Count Limits

Three independent limits are enforced during request parsing:

| Limit | Default | Error |
|---|---|---|
| Single header line size | 8 KB | `error.HeaderTooLarge` → 431 |
| Aggregate headers size | 32 KB | `error.HeadersTooLarge` → 431 |
| Maximum header count | 100 | `error.TooManyHeaders` → 431 |

All three limits are applied by the parser before any gateway logic runs,
preventing hash-flood and slow-header attacks.

Implementation: constants `MAX_HEADER_SIZE`, `MAX_HEADERS_TOTAL_SIZE`,
`MAX_HEADERS` in `src/http/headers.zig`.

## 11. Proxying Malformed Upstream Responses

If an upstream closes the connection before sending a complete HTTP response
head (`\r\n\r\n`), or sends a partial status line, Tardigrade returns
`502 Bad Gateway` (`error.UpstreamProtocolError`). The parser does not attempt
to recover or guess at partial responses.

Upstream hop-by-hop and technology-disclosure headers are stripped from all
responses regardless of status code, including 5xx error responses.

An upstream `1xx`, `204`, or `304` response is bodiless by definition (RFC
7230 §3.3, RFC 7231 §6.3.5/§6.5.5), regardless of any `Content-Length` the
upstream sends. Tardigrade discards any trailing bytes on those responses
rather than forwarding them as a body: a downstream client honors the
bodiless rule and would otherwise treat the illegal bytes as the start of
the next response on the connection, making a naive pass-through a
response-splitting vector (#673).

Implementation: `parseBufferedUpstreamResponse()` in `src/gateway_proxy.zig`.

## 12. Directory Traversal — Static File Serving

Tardigrade resolves the canonical (`realpath`) absolute path of both the
configured document root and the requested file. The resolved file path must
have the document root as a prefix; any path that escapes the root is served
as `403 Forbidden`.

The following traversal sequences are all blocked:

| Sequence | Example |
|---|---|
| `..` segments | `/../secret.txt` |
| Percent-encoded `..` | `/%2e%2e/secret.txt` |
| Double percent-encoded | `/%252e%252e/secret.txt` |
| Backslash traversal | `/..\\secret.txt` |
| Symlink outside root | Symlink pointing to a file above the document root |

The protection is implemented by comparing real paths (resolved by the OS via
`realpath()`), which handles all encoding variants by operating on the
normalized filesystem namespace.

Implementation: `resolvePath()` in `src/http/static_file.zig`.
Tests: see the `serve rejects traversal …` test cases in the same file.

## 12a. `root` / `index` / `try_files` Interaction (#437)

A `location` block that sets `root` (or `alias`) is served through
`resolvePath()` in the following order for a directory-style request (the
request path is empty after stripping the location prefix, or ends in `/`):

1. **`try_files`**, if configured — each candidate is tried in order; `$uri`
   resolves to the request path. A candidate that resolves to a directory
   falls through to step 2 (the directory-relative index) before step 3.
2. **`index`**, resolved *relative to the requested directory* — not just the
   location root. `GET /docs/` checks `docs/index.html`, not the root's
   `index.html`; a nonexistent directory still 404s. If `index` is not
   explicitly configured, it **defaults to `index.html`** (nginx-compatible),
   so `location / { root ...; }` alone serves `index.html` instead of
   404ing. This applies identically after stripping an `alias` prefix.
3. **`autoindex`**, if `on` — a directory listing is generated only after
   steps 1–2 fail to resolve a file, so an existing `index.html` always takes
   priority over a directory listing.

To opt out of the default index fallback entirely (e.g. to rely solely on
`autoindex` or a custom `error_page`), set an explicit empty index:
`index "";`.

Implementation: `buildLocationBlockEntry()` in `src/http/config_file.zig`
(default applied at config-parse time) and `resolveDirectoryIndex()` /
`resolvePath()` in `src/http/static_file.zig` (directory-relative resolution
and fallback order).
Tests: `location block with root and no index or try_files defaults index to
index.html` in `src/http/config_file.zig`; `static file integration serves
default index.html when root is set without index or try_files (#437)`,
`static file integration resolves nested directory index relative to the
requested directory (#437)`, `static file integration does not fall back to
the root index for a nonexistent directory (#437)`, and `static file
integration prefers an existing index over autoindex when both are enabled
(#437)` in `tests/integration.zig`.

## 13. TRACE Method Rejection

**RFC 7231 §4.3.8 / ASVS-14.5.1.** The `TRACE` method is rejected globally
with `405 Method Not Allowed` before any location block is consulted. This
prevents Cross-Site Tracing (XST) attacks, which can expose `HttpOnly` cookies
and `Authorization` headers via JavaScript even when those headers are
otherwise inaccessible.

Implementation: `edge_gateway.zig`, immediately after Host header validation.

## 14. Correlation ID Validation (Log Poisoning Defense)

Client-supplied `X-Request-ID` and `X-Correlation-ID` headers are accepted only
if they match the Tardigrade ID format: `tg-<decimal-ms>-<lowercase-hex>`. Any
other value is discarded and a fresh ID is generated. This prevents log
poisoning (WSTG-INPV-11, ASVS-7.1.1) and trace-ID spoofing.

The ID is reflected in the response `X-Request-ID` / `X-Correlation-ID`
headers and in the access log.

Implementation: `isValid()` and `fromHeadersOrGenerate()` in
`src/http/correlation_id.zig`.

## 15. Asserted Identity Headers (X-Tardigrade-*)

The `X-Tardigrade-Auth-Identity`, `X-Tardigrade-User-ID`,
`X-Tardigrade-Device-ID`, and `X-Tardigrade-Scopes` headers are set by
Tardigrade after authentication resolves. Any client-supplied header with the
`X-Tardigrade-` prefix is stripped before the upstream request is forwarded,
preventing clients from impersonating authenticated identities.

Implementation: `shouldSkipUpstreamRequestHeader()` in `src/gateway_proxy_headers.zig`.

## Safe Deployment Checklist

1. **Load balancer in front of Tardigrade**: Set `trusted_upstream_identities`
   to the load balancer's IP(s) and enable `trust_require_upstream_identity:
   true`.  Without this, clients can forge `X-Forwarded-For` to spoof their
   apparent source IP.

2. **TLS termination**: Enable `tls_cert_path` / `tls_key_path` to terminate
   TLS at Tardigrade. Use `hsts_enabled: true` on public HTTPS services.

3. **Auth on sensitive routes**: Set `auth: required` on any `location` block
   that should not be publicly accessible.

4. **Body size limit**: Tune `max_body_size` to match the largest expected
   upload for each upstream. The default 1 MB is conservative.

5. **Upstream TLS verification**: Enable `upstream_tls_verify: true` (the
   default) unless the upstream uses a self-signed certificate in a controlled
   environment. Never disable verification in production.

6. **Metrics and logs**: Configure an access log destination. Rejected
   malformed requests are logged at `warn` level with the rejection category
   (e.g., "Too many headers: 105", "URI too long: 9123 bytes") without echoing
   the raw header values that caused the rejection.

## See Also

- `docs/SECURITY_TEST_PLAN.md` — test coverage map and release gate
- `docs/PENTEST_PLAYBOOK.md` — internal pentest procedures
- `docs/CODE_REVIEW_CHECKLIST.md` — per-PR security checklist
- `src/gateway_proxy_headers.zig` — hop-by-hop filtering implementation
- `src/http/request.zig` — request parser with smuggling defenses
- `src/http/headers.zig` — header validation and limits
- `src/http/correlation_id.zig` — correlation ID validation
- `src/http/static_file.zig` — directory traversal protections

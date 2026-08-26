# Security Test Plan

Tardigrade is a public-edge service that terminates TLS, parses untrusted HTTP
input, enforces auth, and proxies to internal upstreams. Security validation is
a release gate, not a best-effort activity.

## Threat Model To Coverage Map

### Path and filesystem safety

- Unit coverage lives in `src/http/static_file.zig`.
- Focus areas: traversal, percent-encoded traversal, double-encoded traversal,
  backslash traversal, symlink escape, alias/root interaction, autoindex safety.
- Integration coverage lives in `tests/integration.zig` for live static serving
  and top-level `try_files`.

### Request parser abuse

- Unit coverage lives in `src/http/request.zig` and `src/http/headers.zig`.
- Focus areas: duplicate `Content-Length`, `Transfer-Encoding` conflicts,
  malformed chunked bodies, premature EOF, oversized request lines, header line
  limits, aggregate header limits, header-count limits, obs-fold rejection.
- Live edge coverage lives in `tests/integration.zig` to verify malformed input
  is rejected before routing or proxying.

### Header injection and response splitting

- Unit coverage lives in `src/http/headers.zig`.
- Focus areas: control characters in names/values, CRLF injection, obs-fold,
  log-poisoning-safe header validation.
- Integration coverage verifies hop-by-hop stripping and upstream header
  sanitization.

### Auth, sessions, rate limiting, and approval policy

- Unit coverage lives in `src/http/auth.zig`, `src/http/session.zig`, and
  `src/edge_gateway.zig`.
- Integration coverage lives in `tests/integration.zig`.
- Focus areas: protected-route bypass, malformed bearer input, invalid JWT
  signature, malformed session token input, asserted-identity rate limiting,
  approval-management route bypass from recursive approval checks.

### Corpus and fuzz-style replay

- Corpus files live under `tests/corpus/http/request/`.
- The replay and deterministic mutation harness lives in
  `tests/security/request_parser_corpus.zig`.
- This harness is the v1 seed corpus for future true fuzzing. It replays known
  malicious inputs and applies small deterministic byte mutations to verify that
  the parser fails safely.

## Commands

Use Zig `0.16.0` (see `CONTRIBUTING.md`). If it is not already on `PATH`,
bootstrap it first:

```bash
sh ./scripts/install-zig.sh 0.16.0
```

```bash
# Unit + parser/path/auth hardening coverage
zig build test

# Seed corpus replay + deterministic mutation pass
zig build test-security-corpus

# Live-process integration coverage
zig build test-integration
```

## Release Gate

Do not ship a wider public distribution unless all of the following are true:

- `zig build test` passes with the pinned Zig `0.16.0` toolchain.
- `zig build test-security-corpus` passes with the pinned Zig `0.16.0`
  toolchain.
- `zig build test-integration` passes, or any environment-specific skip is
  explicitly documented in the release notes.
- The first internal pentest playbook has been executed against a local or
  isolated non-public target and the sanitized result has been recorded in
  `docs/PENTEST_PLAYBOOK.md`.
- Public-edge behavior changes update tests and operator-facing docs.

## Current Gaps And Follow-Up

- HTTP/2, HTTP/3, WebSocket, SSE, FastCGI, SCGI, and uWSGI malicious-input
  coverage is still narrower than HTTP/1.1 parser coverage.
- The corpus harness is a deterministic mutation entrypoint, not a full
  coverage-guided fuzz target.
- Security replay and fuzz-style runs are manual today; moving them into
  scheduled CI or nightly automation remains follow-up work.

### Resolved Gaps (issue #174)

**F-01 — HTTP method enforcement (WSTG-CONF-06, ASVS-13.2.1)** ✅ RESOLVED
`TRACE` is rejected globally with 405 in `edge_gateway.zig` before any
location block is consulted. The `return_response` action additionally rejects
non-GET/HEAD methods on non-redirect static-return directives with 405
(ASVS-14.5.1). Corpus case `trace_method.http` documents the expected
behavior.

**F-02 — Upstream Server header passthrough (WSTG-INFO-02, ASVS-14.3.3)** ✅ RESOLVED
`shouldSkipUpstreamResponseHeader()` in `gateway_proxy_headers.zig` strips
upstream `Server` and `X-Powered-By` headers. Tardigrade emits its own
`Server: tardigrade` header. Covered by unit tests in `gateway_proxy_headers.zig`.

**F-03 — Missing Host header not rejected (WSTG-CONF-07, ASVS-14.5.1)** ✅ RESOLVED
HTTP/1.1 requests missing `Host` are rejected with `400 Bad Request` in
`edge_gateway.zig` before routing or proxying. HTTP/1.0 is exempt per RFC
1945. Corpus case `no_host_http11.http` documents parser acceptance; gateway
enforcement is tested via unit conditions in `edge_gateway.zig`.

**F-04 — Client-controlled X-Request-ID / X-Correlation-ID (WSTG-INPV-11, ASVS-7.1.1)** ✅ RESOLVED
`fromHeadersOrGenerate()` in `src/http/correlation_id.zig` validates incoming
IDs against the `tg-<decimal>-<lowercase-hex>` format. Arbitrary client values
are discarded and a fresh ID is generated. Covered by unit tests in
`correlation_id.zig`.

**F-05 — Live native TLS surface pass** ✅ RESOLVED
Issue #672 completed a live black-box pass against an isolated native
`tardi` listener using synthetic credentials, OpenSSL probes, `nghttp`, and
scanner tooling. The committed sanitized evidence, command matrix, public
certificate metadata, and scanner-tool limitations are recorded in
[`docs/F05_LIVE_TLS_SURFACE_672.md`](F05_LIVE_TLS_SURFACE_672.md).

**F-07 — Static file serving via catch-all `location /` non-functional** ✅ RESOLVED
A `location` block with `root` but no `index` or `try_files` directive used
to 404 on directory requests because static serving had no default index
value. Maintainer decision (#437): default `index` to `index.html` when not
explicitly configured (nginx-compatible). See `docs/PROXY_SECURITY.md` §12a
for the full `root`/`index`/`try_files` resolution order. Covered by a unit
test in `src/http/config_file.zig` and an integration test in
`tests/integration.zig`.

**F-06 — Auth enforcement and hostile HTTP/1.1 framing pass (WSTG-ATHZ-01/02, WSTG-INPV-15, ASVS-4.1/4.3, RFC 7230 §6.1) (#673)** ✅ RESOLVED
A live black-box campaign runs raw, byte-exact HTTP/1.1 requests against a
real local `tardi` process fronting a disposable marker-recording upstream,
with one bearer/JWT-protected route, one deliberately hostile upstream
route, and (per the Safe Deployment Checklist) `trust_require_upstream_identity`
enabled with the test client itself left untrusted. Assertions are made from
the upstream's own hit log, not just the client-visible status code, so
"denied" means the protected upstream was never invoked, not merely that the
client got a 4xx -- and every smuggling-shaped framing probe additionally
appends a unique pipelined marker request to prove it is never dispatched,
not just that the malformed probe itself was rejected.

Coverage (126 live cases):
- missing/malformed credentials (no header, bare `Bearer`, wrong scheme,
  oversized token, malformed/invalid-signature JWT, comma-joined
  `Authorization`, NUL/CR injection attempts), including a strict deny for
  duplicate `Authorization` fields in **both** orderings regardless of
  whether one of the two duplicated values is itself valid;
- `X-Tardigrade-*` / `X-Forwarded-*` / `Connection`-nominated identity
  spoofing cannot become trusted identity, and rotating forged
  `X-Forwarded-For`/`X-Real-IP` values from an untrusted connection cannot
  rewrite the client identity used for rate limiting and access logging;
- method-change bypass across GET/HEAD/POST/PUT/PATCH/DELETE/OPTIONS/TRACE/CONNECT;
- path/Host canonicalization variants (trailing slash, duplicate/encoded
  slashes, dot segments, single/double percent-encoding, absolute-form
  target, a genuine duplicate `Host` field) cannot move a request off the
  protected boundary;
- positive control plus sequential and concurrent bearer/JWT reuse;
- the issue's own TE+CL and duplicate-conflicting-`Content-Length` smuggling
  probes, plus the wider CL/TE/duplicate-TE/chunked matrix -- every
  non-truncated case proven with a unique pipelined marker request that
  never reaches the upstream; truncated-body cases (where no coherent
  trailing request could exist) proven by zero upstream hits instead;
- request header syntax limits (obs-fold, NUL/CTL, bare LF, bare CR without
  LF, oversized line/header, header-count and aggregate-size limits,
  malformed version/method);
- the static traversal boundary, including a real symlink escaping the doc
  root and a separate `alias`-rooted location retested for the same
  boundary;
- a hostile upstream response matrix (equal and conflicting duplicate CL,
  TE+CL, malformed status line, control-character/bare-CR injection in a
  header value, `Connection`-nominated header, `Proxy-Connection`/`TE`/
  `Trailer`/`Upgrade`/`Server`/`X-Powered-By`, truncated body, extra bytes
  after the framed response, unusual 1xx chain, invalid 204/304 framing),
  each checked both on a fresh connection and on the *same* downstream
  connection used for the hostile probe (with the first response's own
  framing validated, not just what follows it), plus a dedicated check that
  a "ghost" second response smuggled by the hostile upstream never leaks
  into a later, unrelated proxied response over a reused upstream
  connection -- including when the hostile upstream deliberately delays
  sending the ghost bytes until after Tardigrade would have returned the
  connection to the idle pool;
- the client-visible result of an upstream `103 → 103 → 200` interim-response
  chain is exactly the real final response, not a bare 103 with the 200
  silently dropped, and a Connection-nominated header hidden behind a bare
  LF in the status line is still stripped;
- every scenario in the hostile upstream response matrix that specifically
  targets the buffered proxy path's bodiless-response/1xx/Content-Length
  handling is replayed against a forced-streaming twin route
  (`/hostile-streaming`, `proxy_streaming response;`), since the streaming
  proxy path (`streamProxyOverTransport()`/`readUpstreamHead()`) has its
  own, separately-fixed copies of that logic and is off by default.

The campaign found and fixed twelve real defects, all now covered by
deterministic regression tests:

1. `shouldSkipUpstreamResponseHeader()` did not honor the upstream
   response's own `Connection` header nomination (RFC 7230 §6.1) the way
   the request-direction `shouldSkipUpstreamRequestHeader()` already did. A
   malicious or misconfigured upstream sending `Connection: X-Hostile-Secret`
   alongside `X-Hostile-Secret: ...` could ride an arbitrary header past the
   static response hop-by-hop list straight through to the client. Fixed at
   all five call sites (buffered and streamed proxy response paths, HTTP/2
   upstream header forwarding in `edge_gateway.zig`).
2. That same nomination check only consulted the *first* `Connection` field
   when a header was duplicated, in both directions (`Headers.get()`
   returns only the first match). A first attempt at fixing this by joining
   every occurrence into a fixed `[4096]u8` buffer was itself bypassable:
   padding earlier `Connection` field(s) with enough benign tokens pushes a
   real nomination past byte 4096, where it silently drops out of the
   truncated joined value. Fixed by scanning each occurrence's own
   (unbounded) value directly instead -- `anyConnectionHeaderReferencesHeader()`
   / `anyRawConnectionHeaderReferencesHeader()` in `gateway_proxy_headers.zig` --
   which has no size limit to bypass.
3. Duplicate `Authorization` header fields were accepted whenever the
   *first* field (whichever the reading code path happened to consult) was
   a valid credential, silently ignoring a second, malformed field. Fixed
   by rejecting any request with more than one `Authorization` field
   outright (`error.DuplicateAuthorizationHeader` in `src/http/request.zig`,
   mapped to `400 Bad Request` before routing or auth ever runs) --
   analogous to the existing duplicate-`Content-Length` rejection.
4. `extractClientIp()` (`src/http/request_context.zig`) honored client-supplied
   `X-Forwarded-For`/`X-Real-IP` unconditionally, with no trust gate at all,
   even though `docs/PROXY_SECURITY.md` §7 documents `trust_require_upstream_identity`
   / `trusted_upstream_identities` as the boundary that should govern this.
   Any client could rewrite the identity used to key rate-limit buckets and
   the `client_ip` recorded in access logs, live even behind a correctly
   configured trust boundary. Fixed by gating on the same trust check used
   elsewhere (`gph.isTrustedUpstream()`) and stripping the headers from the
   request outright when untrusted, before any other code (including the
   outbound `X-Forwarded-For` chain sent to Tardigrade's own upstream) can
   read them.
5. Upstream response headers were copied into the client-facing response
   with no validation at all -- unlike client *request* headers, which
   `Headers.append()` validates against `isValidHeaderName()` /
   `isValidHeaderValue()`. Because a header line is only split on an exact
   `\r\n` boundary, a bare CR or embedded NUL inside what should be a
   single header value survived parsing and was forwarded to the client
   verbatim, letting a hostile or compromised upstream inject control
   characters into a response header. Fixed by validating every upstream
   response header name/value the same way request headers already are,
   rejecting the response as `error.UpstreamProtocolError` (502) if either
   fails, at both the buffered (`parseBufferedUpstreamResponse()`) and
   streamed (`readUpstreamHead()`) parse sites in `gateway_proxy.zig`.
6. The buffered proxy path forwarded a body for upstream `204`/`304`/`1xx`
   responses whenever the upstream included one, even though those statuses
   are bodiless by definition regardless of `Content-Length` -- a real
   response-splitting vector, since a downstream client would treat the
   illegal bytes as the start of the next response on the connection.
7. Both the buffered and streamed proxy paths could still return a bodiless
   (`204`/`304`/`1xx`/`HEAD`) upstream connection to the idle pool for reuse
   whenever nothing had trailed the header block *at the instant it was
   parsed*. That cannot prove a malicious/misbehaving upstream won't send
   an illegal body or a full ghost response moments later, after the
   connection is already pooled -- those delayed bytes would then become
   part of whatever unrelated request next checks the connection out,
   poisoning it. Fixed by never marking a bodiless response's upstream
   connection reusable, in `exchangeBoundedBufferedHttpRequest()` and
   `relayUpstreamBody()` in `gateway_proxy.zig`.
8. `detectResponseFraming()` maps every `1xx` status to bodiless framing,
   which the buffered exchange loop treated as "the response is complete" --
   so the *first* interim `1xx` response (e.g. `103 Early Hints`) was
   wrongly returned to the caller as if it were the final response, and
   whatever actually followed (including the real final response) was
   silently discarded. Fixed by having the buffered exchange loop discard
   1xx interim responses (other than `101`, which completes a protocol
   switch rather than signaling more to come) and keep reading until the
   real final response arrives, in `exchangeBoundedBufferedHttpRequest()`
   in `gateway_proxy.zig`.
9. Defects 7 and 8's fixes only ran on the **buffered** HTTP/1 proxy path.
   The **streaming** path (`streamProxyOverTransport()`) calls
   `relayUpstreamBody()` -- where defect 7's fix lives -- only inside
   `if (body_allowed)`, and `responseBodyAllowed()` is false for exactly
   `HEAD`/`1xx`/`204`/`304`, so that branch (and the fix in it) never ran
   for precisely the response family it was meant to protect; a delayed
   illegal body/ghost could still poison a streamed HTTP/1 upstream socket.
   Fixed by making bodiless streamed final responses fail closed for reuse
   in `streamProxyOverTransport()` itself, not only in the relay helper.
10. `streamProxyOverTransport()` still called `readUpstreamHead()` once and
    immediately serialized that head downstream, so a streaming route
    receiving a `103 → 103 → 200` chain still treated the first `103` as
    the completed exchange and abandoned the final response -- the
    streaming analog of defect 8, in a separate code path. Fixed by
    looping `readUpstreamHead()` past 1xx interim responses (101 excepted)
    before committing anything downstream, mirroring the buffered fix.
11. `detectResponseFraming()` overwrote `content_length` on every
    `Content-Length` occurrence instead of rejecting duplicates, so a
    conflicting pair resolved to whichever field came last regardless of
    order -- reversing the order from "small value first" to "large value
    first" flips which boundary wins, and picking the smaller one leaves
    "extra" bytes (e.g. a smuggled follow-up request or a ghost response)
    past what the parser thinks is the end of the response. Fixed by
    rejecting any duplicate `Content-Length` outright (`error.UpstreamProtocolError`),
    matching the request-direction policy, regardless of field order or
    whether the values happen to match.
12. Upstream response status-line parsing was not strict, and a bare LF (not
    part of a `\r\n` pair) right after the status line could bypass the
    `Connection`-nomination filter from defect 2's fix: in the buffered
    path, the nomination scanner walked the raw header block from byte 0
    using exact `\r\n` splitting, so the still-unterminated status line text
    merged with the first real header line into one bogus segment that no
    longer matched `connection` by name; in the streaming path, the whole
    run up to the first genuine `\r\n` -- including an injected header --
    was swallowed into the reason phrase and later written verbatim into
    the status line sent to the downstream client, which may treat the
    embedded LF as a line terminator of its own and interpret the smuggled
    text as a genuine extra header. This composes two explicit #673
    malicious-upstream cases: malformed status line and
    Connection-nominated hop-by-hop header. Fixed by validating the parsed
    status line for embedded control characters (rejecting the response
    outright if present, in both paths) and, in the buffered path, scanning
    the same header-lines view the main per-header loop already uses
    (starting after the status line) rather than the whole raw block from
    byte 0. Also rejects a status line whose status code doesn't parse,
    rather than silently defaulting to `200`/`0`.

Tooling: `scripts/run-f06-auth-framing-campaign.sh` builds `tardi`, starts
the fixtures in `tests/security/fixtures/` (`f06_upstream.py`,
`f06_tardigrade.conf` -- with both a buffered `/hostile` route and a
forced-streaming `/hostile-streaming` twin -- plus a symlink and an
`alias`-rooted directory), and runs the probe engine in
`tests/security/f06_live_campaign.py`, writing evidence (metadata, raw
results, process logs) to `.zig-cache/f06-campaign-673/`. All credentials
are synthetic and local-only; no production secrets or traffic were used.
126/126 probes pass after the fixes (Zig 0.16.0, macOS arm64; rerun the
script for current evidence -- results are not committed).

## Proxy Security Behavior Reference

See `docs/PROXY_SECURITY.md` for the authoritative description of Tardigrade's
intended behavior at each HTTP proxy trust boundary, including:

- Hop-by-hop header stripping (request and response directions)
- Connection header token handling (RFC 7230 §6.1)
- TE/CL conflict and duplicate Content-Length rejection
- Header casing normalization and validation rules
- Absolute-form vs origin-form URI handling
- X-Forwarded-* trust boundary and safe deployment requirements
- Host header enforcement (HTTP/1.1)
- Body size and header size/count limits
- Malformed upstream response handling
- Directory traversal protection for static serving
- TRACE method rejection (XST defense)
- Correlation ID validation (log poisoning defense)
- X-Tardigrade-* asserted identity header stripping

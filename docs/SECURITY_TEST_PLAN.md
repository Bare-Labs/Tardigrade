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
with one bearer/JWT-protected route and one deliberately hostile upstream
route. Assertions are made from the upstream's own hit log, not just the
client-visible status code, so "denied" means the protected upstream was
never invoked, not merely that the client got a 4xx.

Coverage (92 live cases):
- missing/malformed credentials (no header, bare `Bearer`, wrong scheme,
  oversized token, malformed/invalid-signature JWT, duplicate/comma-joined
  `Authorization`, NUL/CR injection attempts);
- `X-Tardigrade-*` / `X-Forwarded-*` / `Connection`-nominated identity
  spoofing cannot become trusted identity;
- method-change bypass across GET/HEAD/POST/PUT/PATCH/DELETE/OPTIONS/TRACE/CONNECT;
- path/Host canonicalization variants (trailing slash, duplicate/encoded
  slashes, dot segments, single/double percent-encoding, absolute-form
  target, conflicting Host) cannot move a request off the protected boundary;
- positive control plus sequential and concurrent bearer/JWT reuse;
- the issue's own TE+CL and duplicate-conflicting-`Content-Length` smuggling
  probes, plus the wider CL/TE/chunked matrix, proven with upstream marker
  evidence that no smuggled follow-up request is ever dispatched;
- request header syntax limits (obs-fold, NUL/CTL, oversized line/header,
  header-count and aggregate-size limits, malformed version/method);
- the static traversal boundary;
- a hostile upstream response matrix (duplicate/conflicting CL, TE+CL,
  malformed status line, CRLF injection, `Connection`-nominated header,
  truncated body, extra bytes after the framed response, unusual 1xx chain,
  invalid 204/304 framing), including a dedicated check that a "ghost" second
  response smuggled by the hostile upstream never leaks into a later,
  unrelated proxied response over a reused upstream connection.

The campaign found and fixed one real defect: `shouldSkipUpstreamResponseHeader()`
in `src/gateway_proxy_headers.zig` did not honor the upstream response's own
`Connection` header nomination (RFC 7230 §6.1) the way the request-direction
`shouldSkipUpstreamRequestHeader()` already did. A malicious or misconfigured
upstream sending `Connection: X-Hostile-Secret` alongside
`X-Hostile-Secret: ...` could ride an arbitrary header past the static
response hop-by-hop list straight through to the client. Fixed at all five
call sites (buffered and streamed proxy response paths, HTTP/2 upstream
header forwarding in `edge_gateway.zig`). Regression: `shouldSkipUpstreamResponseHeader
strips headers nominated by the upstream's own Connection value (#673)` in
`src/gateway_proxy_headers.zig`.

Tooling: `scripts/run-f06-auth-framing-campaign.sh` builds `tardi`, starts
the fixtures in `tests/security/fixtures/` (`f06_upstream.py`,
`f06_tardigrade.conf`), and runs the probe engine in
`tests/security/f06_live_campaign.py`, writing evidence (metadata, raw
results, process logs) to `.zig-cache/f06-campaign-673/`. All credentials are
synthetic and local-only; no production secrets or traffic were used. 92/92
probes pass after the fix (Zig 0.16.0, macOS arm64; rerun the script for
current evidence -- results are not committed).

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

//! Shared proxy primitives and bounded buffered HTTP/1 upstream transports.
//!
//! Functions whose names include `BoundedBuffered` materialize an upstream
//! response in memory only after enforcing an explicit size cap. They are kept
//! separate from the reverse-proxy data-plane orchestration in
//! `gateway_proxy_runtime.zig` so streaming/backpressure work can replace the
//! data-plane executor without depending on control-plane helper behavior.

const compat = @import("zig_compat");
const std = @import("std");
const http = @import("http.zig");
const edge_config = @import("edge_config.zig");
const gs = @import("gateway_state.zig");
const gph = @import("gateway_proxy_headers.zig");
const gpres = @import("gateway_proxy_response.zig");
const gpt = @import("gateway_proxy_target.zig");
const gconn = @import("gateway_connection.zig");
const proxy_buffer_account = http.proxy_buffer_account;

fn upstreamAlpnPolicy(protocol: edge_config.UpstreamProtocol) http.tls_termination.UpstreamAlpnPolicy {
    return switch (protocol) {
        .http1 => .require_http1,
        .h2, .h2c => .require_h2,
        .auto => .prefer_h2_allow_http1,
    };
}

// Compatibility re-exports of the split-out proxy helper APIs (headers /
// response / target modules) so existing callers that import this module keep
// compiling. New code should import from the owning module directly
// (`gph` / `gpres` / `gpt`); this shim shrinks as callers migrate (#156, #152).
// Grouped by owning module so code search points at the true owner.
//
// -- gateway_proxy_headers.zig (gph)
pub const buildForwardedFor = gph.buildForwardedFor;
pub const isTrustedUpstream = gph.isTrustedUpstream;
pub const appendTrustedUpstreamHeaders = gph.appendTrustedUpstreamHeaders;
pub const appendRequestIdHeaders = gph.appendRequestIdHeaders;
pub const writeRequestIdHeaders = gph.writeRequestIdHeaders;
pub const setRequestIdHeaders = gph.setRequestIdHeaders;
// -- gateway_proxy_response.zig (gpres)
pub const applyResponseHeaders = gpres.applyResponseHeaders;
pub const writeStreamedUpstreamResponse = gpres.writeStreamedUpstreamResponse;
pub const writeStreamedUpstreamResponseHeadFromHeaders = gpres.writeStreamedUpstreamResponseHeadFromHeaders;
pub const writeBufferedUpstreamResponse = gpres.writeBufferedUpstreamResponse;
pub const writeBufferedUpstreamResponseWithMetrics = gpres.writeBufferedUpstreamResponseWithMetrics;
pub const computeHstsValue = gpres.computeHstsValue;
pub const writeSecurityHeaders = gpres.writeSecurityHeaders;
pub const writeChunk = gpres.writeChunk;
pub const buildApiErrorJson = gpres.buildApiErrorJson;
pub const sendApiError = gpres.sendApiError;
pub const upstreamReasonPhrase = gpres.upstreamReasonPhrase;
// -- gateway_proxy_target.zig (gpt)
pub const ResolvedProxyTarget = gpt.ResolvedProxyTarget;
pub const resolveProxyTarget = gpt.resolveProxyTarget;
pub const appendProxyQueryString = gpt.appendProxyQueryString;
pub const unixSocketPathFromEndpoint = gpt.unixSocketPathFromEndpoint;
const maxBufferedUpstreamResponseBytes = gs.maxBufferedUpstreamResponseBytes;
const CancellationToken = http.cancellation.CancellationToken;

fn setSocketRecvTimeoutMs(fd: std.posix.fd_t, timeout_ms: u32) !void {
    const tv = std.posix.timeval{
        .sec = @intCast(timeout_ms / 1000),
        .usec = @intCast((timeout_ms % 1000) * 1000),
    };
    try std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&tv));
}

fn setSocketTimeoutMs(fd: std.posix.fd_t, recv_timeout_ms: u32, send_timeout_ms: u32) !void {
    const recv_tv = std.posix.timeval{
        .sec = @intCast(recv_timeout_ms / 1000),
        .usec = @intCast((recv_timeout_ms % 1000) * 1000),
    };
    const send_tv = std.posix.timeval{
        .sec = @intCast(send_timeout_ms / 1000),
        .usec = @intCast((send_timeout_ms % 1000) * 1000),
    };
    try std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&recv_tv));
    try std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, std.mem.asBytes(&send_tv));
}

fn isHttpMethodIdempotent(method: []const u8) bool {
    return std.ascii.eqlIgnoreCase(method, "GET") or
        std.ascii.eqlIgnoreCase(method, "HEAD") or
        std.ascii.eqlIgnoreCase(method, "PUT") or
        std.ascii.eqlIgnoreCase(method, "DELETE") or
        std.ascii.eqlIgnoreCase(method, "OPTIONS") or
        std.ascii.eqlIgnoreCase(method, "TRACE");
}

pub const UpstreamHeader = struct {
    name: []const u8,
    value: []const u8,
};

/// Fully materialized upstream response returned by bounded buffered helpers.
pub const BufferedUpstreamResponse = struct {
    metadata_arena: std.heap.ArenaAllocator,
    status_code: u16,
    reason: []const u8,
    headers: []UpstreamHeader,
    body: []u8,

    pub fn deinit(self: *BufferedUpstreamResponse, allocator: std.mem.Allocator) void {
        self.metadata_arena.deinit();
        allocator.free(self.body);
        self.* = undefined;
    }

    pub fn headerValue(self: *const BufferedUpstreamResponse, name: []const u8) ?[]const u8 {
        for (self.headers) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
        }
        return null;
    }
};

/// A client upload that is relayed to the upstream incrementally instead of
/// being materialized first (#139).
pub const StreamingRequestBody = struct {
    /// Downstream body framing.
    framing: Framing,
    /// Body bytes that arrived in the same read as the request head. They are
    /// relayed before the downstream connection is read again.
    initial_bytes: []const u8 = &.{},
    /// Decoded-payload budget enforced while relaying `.chunked` uploads. A
    /// `.length` upload is bounded by its own Content-Length, which routing
    /// already checked against the same maximum.
    max_body_bytes: usize = 0,

    pub const Framing = union(enum) {
        /// Client sent a `Content-Length`; the exact byte count is known up front.
        length: usize,
        /// Client sent `Transfer-Encoding: chunked`; the total size is unknown
        /// until the terminal chunk arrives.
        chunked,
    };
};

const ProxyBufferReservation = struct {
    account: proxy_buffer_account.Account,
    observer: proxy_buffer_account.Observer,
    /// Aggregate scopes this relay's bytes must clear on top of the per-stream
    /// bound. An empty capacity (a path with no origin identity and no process
    /// account, or a test harness) leaves those scopes unlimited.
    capacity: proxy_buffer_account.AggregateCapacity,
    active: bool = false,

    fn init(
        direction: proxy_buffer_account.Direction,
        limits: proxy_buffer_account.Limits,
        observer: proxy_buffer_account.Observer,
        capacity: proxy_buffer_account.AggregateCapacity,
    ) ProxyBufferReservation {
        return .{
            .account = proxy_buffer_account.Account.init(direction, .stream, limits),
            .observer = observer,
            .capacity = capacity,
        };
    }

    fn reserve(self: *ProxyBufferReservation, bytes: usize) !void {
        const before = self.account.snapshot();
        self.account.reserve(bytes) catch |err| {
            const after = self.account.snapshot();
            if (after.limit_exceeded_events > before.limit_exceeded_events) {
                self.observer.recordReservation(self.account.direction, 0, false, true);
            }
            return err;
        };
        // Charge the aggregate scopes only once the per-stream bound has
        // admitted the bytes, and roll the per-stream reservation back if they
        // refuse: no scope may be left holding bytes this relay never took.
        self.capacity.reserve(self.account.direction, bytes) catch |err| {
            self.account.release(bytes) catch unreachable;
            self.observer.recordAggregateLimitExceeded(
                self.account.direction,
                proxy_buffer_account.aggregateFailureScope(err),
            );
            return error.ProxyBufferCapacityUnavailable;
        };
        const after = self.account.snapshot();
        self.observer.recordReservation(
            self.account.direction,
            bytes,
            after.high_watermark_events > before.high_watermark_events,
            after.limit_exceeded_events > before.limit_exceeded_events,
        );
        // The HTTP/1 relay's buffer is allocated for as long as it is reserved,
        // so its logical and retained byte counts move together — unlike an
        // HTTP/2 stream queue, which drains ahead of its backing storage.
        self.observer.recordRetainedBytes(self.account.direction, bytes);
        self.active = true;
    }

    fn release(self: *ProxyBufferReservation, bytes: usize) void {
        if (!self.active) return;
        self.account.release(bytes) catch unreachable;
        self.capacity.release(self.account.direction, bytes);
        self.observer.releaseReservation(self.account.direction, bytes);
        self.observer.releaseRetainedBytes(self.account.direction, bytes);
        self.active = self.account.snapshot().current != 0;
    }

    fn releaseAll(self: *ProxyBufferReservation) void {
        const current = self.account.snapshot().current;
        if (current == 0) return;
        self.release(current);
    }
};

/// Reserve request-direction relay bytes with the failure semantics #140 defines
/// for the pre-commitment side of the boundary. The two refusals mean different
/// things and must not collapse into one status: a per-stream refusal is this
/// client's in-flight upload outgrowing the bound it is allowed (`413`), while
/// an aggregate refusal is the proxy being out of room for anybody (`503`,
/// already the error's own meaning). Both are raised before any response byte
/// is committed, and neither is charged to the origin.
fn reserveUploadBytes(reservation: *ProxyBufferReservation, bytes: usize) !void {
    reservation.reserve(bytes) catch |err| return switch (err) {
        error.BufferLimitExceeded => error.RequestBufferLimitExceeded,
        else => err,
    };
}

/// The HTTP/1 upload relay's fixed copy buffer. Named because the reservation
/// covering it is taken before the request head is written, in a different
/// function from the array it describes.
const http1_upload_relay_bytes: usize = 16 * 1024;

/// Bytes a relay retains from the request head, on top of its fixed relay
/// buffer. The two framings retain different amounts of the same slice: a
/// `.length` upload forwards only the body bytes it is owed, while a `.chunked`
/// upload hands the whole raw remainder to the decoder, which reads framing
/// octets out of it too — so the retained slice there is its raw length.
fn uploadInitialBytesFootprint(sb: StreamingRequestBody) usize {
    return switch (sb.framing) {
        .length => |content_length| @min(sb.initial_bytes.len, content_length),
        .chunked => sb.initial_bytes.len,
    };
}

/// Claim an upload's whole known buffer footprint *before* anything is sent
/// upstream.
///
/// #140 requires capacity decisions to be deterministic before request
/// forwarding, and that is not just bookkeeping: reserving inside the relay
/// means the request head (HTTP/1) or HEADERS (HTTP/2) has already reached the
/// origin, so a local 413/503 would leave a real, possibly side-effecting
/// request half-delivered. Reserving first makes a refusal something the origin
/// never sees.
///
/// The returned reservation is live and owned by the caller, which must
/// `releaseAll` it on every exit; the relay releases the initial-bytes portion
/// as those bytes drain.
fn preflightUploadReservation(
    limits: proxy_buffer_account.Limits,
    observer: proxy_buffer_account.Observer,
    capacity: proxy_buffer_account.AggregateCapacity,
    relay_bytes: usize,
    initial_bytes: usize,
) !ProxyBufferReservation {
    var reservation = ProxyBufferReservation.init(.downstream_to_upstream, limits, observer, capacity);
    errdefer reservation.releaseAll();

    try reserveUploadBytes(&reservation, relay_bytes);
    if (initial_bytes != 0) try reserveUploadBytes(&reservation, initial_bytes);
    return reservation;
}

/// Note a write that cannot make progress right now as a downstream read pause.
/// The check never waits (zero timeout), so a relay whose origin keeps draining
/// costs one non-blocking `poll` per chunk and never touches the counters.
/// Only a genuinely full send buffer counts: a socket that is erroring or hung
/// up records nothing, so a broken upstream never looks like a slow one.
///
/// This reports a stall that is *already* in effect, so a single write that
/// happens to block briefly after the check passes is not counted. That is the
/// intended reading: an origin that has genuinely stopped consuming leaves the
/// send buffer full across relay iterations and is caught, while a momentary
/// block is not a backpressure event worth a counter.
fn noteUpstreamWriteStall(fd: std.posix.fd_t, stall: *proxy_buffer_account.ReadStall) void {
    if (pollUpstreamWritability(fd) == .blocked) stall.pause();
}

pub const StreamingProxyResult = struct {
    status_code: u16,
    reason: []const u8,
    response_body_bytes: usize,
    upstream_ttfb_ms: u64,
    upstream_aborted: bool = false,
    /// The relay was truncated because *local* proxy buffer capacity ran out,
    /// not because the origin failed. The response head was already committed
    /// so the status cannot change, but the origin must not be blamed for it —
    /// counting this against upstream health would let local memory pressure
    /// trip a healthy origin's circuit breaker.
    local_capacity_aborted: bool = false,
};

pub fn uriComponentBytes(component: std.Uri.Component) []const u8 {
    return switch (component) {
        .raw => |value| value,
        .percent_encoded => |value| value,
    };
}

/// Parse an HTTP/1 response that has already been read under a caller-owned
/// bound. Do not call this on unbounded network input.
pub fn parseBufferedUpstreamResponse(allocator: std.mem.Allocator, raw: []const u8) !BufferedUpstreamResponse {
    var metadata_arena = std.heap.ArenaAllocator.init(allocator);
    errdefer metadata_arena.deinit();
    const metadata_allocator = metadata_arena.allocator();

    // If the upstream closed before sending a complete response head, treat it
    // as a protocol error (not an unsupported method — the name would be
    // misleading here).  Callers synthesise a 502 Bad Gateway for this case.
    const header_end = std.mem.find(u8, raw, "\r\n\r\n") orelse return error.UpstreamProtocolError;
    const headers_raw = raw[0..header_end];
    const resp_body = raw[header_end + 4 ..];

    const first_line_end = std.mem.findScalar(u8, headers_raw, '\n') orelse return error.UpstreamProtocolError;
    const first_line = compat.trimRight(u8, headers_raw[0..first_line_end], "\r");
    var line_parts = std.mem.splitScalar(u8, first_line, ' ');
    _ = line_parts.next();
    const status_str = line_parts.next() orelse "200";
    const status_code = std.fmt.parseInt(u16, status_str, 10) catch 200;
    const reason = line_parts.rest();

    var resp_headers = std.array_list.Managed(UpstreamHeader).init(metadata_allocator);
    var hdr_lines = std.mem.splitSequence(u8, headers_raw[first_line_end + 1 ..], "\r\n");
    while (hdr_lines.next()) |line| {
        const colon = std.mem.findScalar(u8, line, ':') orelse continue;
        const hname = std.mem.trim(u8, line[0..colon], " \t");
        const hval = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (gph.shouldSkipUpstreamResponseHeader(hname)) continue;
        try resp_headers.append(.{
            .name = try metadata_allocator.dupe(u8, hname),
            .value = try metadata_allocator.dupe(u8, hval),
        });
    }

    // Allocate everything into the arena BEFORE copying `metadata_arena` into
    // the returned struct. A struct literal evaluates fields in order, so
    // copying the arena first would snapshot its buffer list before these
    // allocations — and when no headers were kept (response carried only
    // hop-by-hop headers), the arena had no buffer node yet, so the `reason`
    // node would be created only in the local arena and leak.
    const reason_owned = try metadata_allocator.dupe(u8, reason);
    const headers_owned = try resp_headers.toOwnedSlice();
    const body_owned = try allocator.dupe(u8, resp_body);

    return .{
        .metadata_arena = metadata_arena,
        .status_code = status_code,
        .reason = reason_owned,
        .headers = headers_owned,
        .body = body_owned,
    };
}

/// Execute a bounded buffered HTTP/1 request over a Unix socket. This is
/// appropriate for small control-plane/internal calls and compatibility paths
/// where the caller provides a strict response cap.
///
/// When `pool` is non-null and enabled, connections are kept alive and reused
/// under `unix:<path>` keys (#239 — unix connects are cheap, but keep-alive
/// still spares the origin per-request accept/fd churn, matters for
/// php-fpm-style backends, and brings unix upstreams under the same
/// idle/lifetime/active-cap policy and metrics as TCP). A reused connection
/// the origin closed while idle is retried once on a fresh one.
pub fn executeBoundedBufferedUnixSocketHttpRequest(
    allocator: std.mem.Allocator,
    socket_path: []const u8,
    uri: std.Uri,
    method: []const u8,
    extra_headers: []const std.http.Header,
    body: []const u8,
    content_type_override: ?[]const u8,
    max_buffered_response_bytes: usize,
    timeout_ms: u32,
    /// If > 0, overrides `SO_RCVTIMEO` after sending the request to enforce a
    /// separate deadline for waiting on the first response byte (distinct from
    /// the write-phase timeout above).
    response_timeout_ms: u32,
    /// Optional keep-alive pool (#239). Null (or disabled) keeps the previous
    /// fresh `Connection: close` connection per request.
    pool: ?*http.upstream_pool.UpstreamPool,
) !BufferedUpstreamResponse {
    const active_pool: ?*http.upstream_pool.UpstreamPool = if (pool) |p| (if (p.config.enabled) p else null) else null;

    if (active_pool == null) {
        const fd = try compat.connectBlockingUnix(socket_path);
        defer _ = std.c.close(fd);
        return exchangeBoundedBufferedHttpRequest(
            allocator,
            compat.netStreamFromFd(fd),
            fd,
            uri,
            method,
            extra_headers,
            body,
            content_type_override,
            max_buffered_response_bytes,
            timeout_ms,
            response_timeout_ms,
            false,
            null,
        );
    }

    const p = active_pool.?;
    var key_buf: [512]u8 = undefined;
    const key = std.fmt.bufPrint(&key_buf, "unix:{s}", .{socket_path}) catch socket_path;

    var attempt: usize = 0;
    while (attempt < 2) : (attempt += 1) {
        const now_ms = http.event_loop.monotonicMs();
        var reused = false;
        var conn: http.upstream_pool.PooledConn = undefined;
        if (attempt == 0) {
            if (try p.checkout(key, now_ms)) |pooled| {
                conn = pooled;
                reused = true;
            }
        } else {
            try p.reserveSlot(key); // stale retry: deliberately fresh, still capped
        }
        if (!reused) {
            const connect_start_ms = http.event_loop.monotonicMs();
            const new_fd = compat.connectBlockingUnix(socket_path) catch |err| {
                p.releaseSlot(key);
                return err;
            };
            p.recordConnectLatency(http.event_loop.monotonicMs() - connect_start_ms);
            p.noteNewConnection(key);
            conn = .{ .stream = compat.netStreamFromFd(new_fd), .tls = null, .created_ms = now_ms, .last_used_ms = now_ms };
        }
        const fd = conn.stream.handle;

        var reusable = false;
        const result = exchangeBoundedBufferedHttpRequest(allocator, compat.netStreamFromFd(fd), fd, uri, method, extra_headers, body, content_type_override, max_buffered_response_bytes, timeout_ms, response_timeout_ms, true, &reusable);

        if (result) |resp| {
            p.release(key, conn, reusable, http.event_loop.monotonicMs());
            return resp;
        } else |err| {
            p.release(key, conn, false, http.event_loop.monotonicMs());
            if (reused and err == error.UpstreamConnectionClosed and attempt == 0 and isHttpMethodIdempotent(method)) {
                p.recordStaleRetry(key);
                continue; // request never delivered — retry once on a fresh conn
            }
            return err;
        }
    }
    unreachable;
}

/// Execute a bounded buffered HTTP/1 request over a TCP socket, with optional
/// TLS. This is the manual-transport replacement for the `std.http.Client`
/// data-plane and control-plane proxy paths: unlike `std.http.Client` it
/// exposes the underlying socket fd, so per-phase connect and response timeouts
/// (`SO_SNDTIMEO`/`SO_RCVTIMEO`/`poll`) are enforced (issue #196).
///
/// When `pool` is non-null and enabled the connection is kept alive and reused
/// across requests (issue #141), for both plain HTTP and TLS (#141 Phase 1c).
/// The pool key is scheme-prefixed so plain and TLS connections to the same
/// origin are never confused. When pooling is off, a fresh `Connection: close`
/// connection is used per request.
pub fn executeBoundedBufferedTcpHttpRequest(
    allocator: std.mem.Allocator,
    host: []const u8,
    port: u16,
    /// When non-null, wrap the TCP stream in TLS before exchanging the request.
    tls_options: ?http.tls_termination.UpstreamTlsOptions,
    uri: std.Uri,
    method: []const u8,
    extra_headers: []const std.http.Header,
    body: []const u8,
    content_type_override: ?[]const u8,
    max_buffered_response_bytes: usize,
    /// Bounds the connect/handshake and request-write phase. The blocking TCP
    /// connect itself is not interruptible by SO_*TIMEO; this bounds the
    /// handshake stall and the write phase that follow.
    connect_timeout_ms: u32,
    /// If > 0, overrides `SO_RCVTIMEO` after the request is sent to bound the
    /// wait for the first response byte separately from the write phase.
    response_timeout_ms: u32,
    /// Optional keep-alive pool for upstream connection reuse.
    pool: ?*http.upstream_pool.UpstreamPool,
    /// Optional per-origin HTTP/2 multiplexing pool (#145). When present and the
    /// caller offered h2, requests multiplex over a shared origin connection.
    h2_pool: ?*http.upstream_h2.H2ConnPool,
    /// Speak prior-knowledge cleartext h2c to this plain-HTTP upstream (#237).
    /// Only set when the operator explicitly configured
    /// `TARDIGRADE_UPSTREAM_PROTOCOL=h2c` — there is no negotiation on
    /// cleartext, so an h1-only origin would break under it. Ignored for TLS.
    h2c_prior_knowledge: bool,
) !BufferedUpstreamResponse {
    // HTTP/2 upstream (#145): when the caller asked to offer h2 (TLS only),
    // multiplex over a shared per-origin connection when an h2 pool is provided,
    // else fall back to a fresh single-stream connection. h1 origins are
    // detected via ALPN and handled on the HTTP/1.1 path.
    if (tls_options) |opts| {
        if (opts.alpn_policy.offersH2()) {
            if (h2_pool) |hp| {
                return executeBufferedViaH2Pool(allocator, hp, host, port, opts, uri, method, extra_headers, body, content_type_override, max_buffered_response_bytes, connect_timeout_ms, response_timeout_ms, pool);
            }
            return executeBufferedH2OrH1Fresh(allocator, host, port, opts, uri, method, extra_headers, body, content_type_override, max_buffered_response_bytes, connect_timeout_ms, response_timeout_ms, pool);
        }
    } else if (h2c_prior_knowledge) {
        // Cleartext h2c (#237): multiplex over the shared per-origin plain h2
        // connection. Requires the pool (always present on the data plane);
        // without one, fall through to HTTP/1.1.
        if (h2_pool) |hp| {
            return executeBufferedViaH2Pool(allocator, hp, host, port, null, uri, method, extra_headers, body, content_type_override, max_buffered_response_bytes, connect_timeout_ms, response_timeout_ms, pool);
        }
    }
    // Every request that reaches the buffered HTTP/1.1 path counts as h1 (an h2
    // request would have returned above). The streaming path counts its own
    // requests in executeStreamingHttpProxyRequest.
    if (pool) |p| p.recordProtocol(false);

    const active_pool: ?*http.upstream_pool.UpstreamPool = if (pool) |p| (if (p.config.enabled) p else null) else null;

    // No pool: a single fresh `Connection: close` connection (plain or TLS),
    // cleaned up on return.
    if (active_pool == null) {
        const start_ms = http.event_loop.monotonicMs();
        const fd = try compat.connectBoundedTcp(host, port, connect_timeout_ms);
        defer _ = std.c.close(fd);
        if (connect_timeout_ms > 0) {
            try setSocketTimeoutMs(fd, connect_timeout_ms, connect_timeout_ms);
        }
        if (tls_options) |opts| {
            var tls_conn = try http.tls_termination.UpstreamTlsConn.connect(fd, host, opts);
            defer tls_conn.deinit();
            const resp = try exchangeBoundedBufferedHttpRequest(allocator, &tls_conn, fd, uri, method, extra_headers, body, content_type_override, max_buffered_response_bytes, connect_timeout_ms, response_timeout_ms, false, null);
            if (pool) |p| p.recordRequestLatency(false, http.event_loop.monotonicMs() - start_ms);
            return resp;
        }
        const resp = try exchangeBoundedBufferedHttpRequest(allocator, compat.netStreamFromFd(fd), fd, uri, method, extra_headers, body, content_type_override, max_buffered_response_bytes, connect_timeout_ms, response_timeout_ms, false, null);
        if (pool) |p| p.recordRequestLatency(false, http.event_loop.monotonicMs() - start_ms);
        return resp;
    }

    const p = active_pool.?;
    const is_tls = tls_options != null;
    var key_buf: [268]u8 = undefined;
    const key = std.fmt.bufPrint(&key_buf, "{s}:{s}:{d}", .{ if (is_tls) "https" else "http", host, port }) catch host;

    // Attempt 0 uses a pooled connection when available; a reused connection the
    // origin already closed (error.UpstreamConnectionClosed with zero bytes) is
    // retried once on a fresh connection since the request was never delivered.
    // Checkout reserves an active slot before connecting, so the per-origin
    // active cap (#239) cannot be raced past; a failed connect must release the
    // reservation.
    var attempt: usize = 0;
    while (attempt < 2) : (attempt += 1) {
        const now_ms = http.event_loop.monotonicMs();
        var reused = false;
        var conn: http.upstream_pool.PooledConn = undefined;
        if (attempt == 0) {
            if (try p.checkout(key, now_ms)) |pooled| {
                conn = pooled;
                reused = true;
            }
        } else {
            // Stale retry: deliberately fresh, but still capped.
            try p.reserveSlot(key);
        }
        if (!reused) {
            const connect_start_ms = http.event_loop.monotonicMs();
            const new_fd = compat.connectBoundedTcp(host, port, connect_timeout_ms) catch |err| {
                p.releaseSlot(key);
                return err;
            };
            p.recordConnectLatency(http.event_loop.monotonicMs() - connect_start_ms);
            if (is_tls) {
                if (connect_timeout_ms > 0) setSocketTimeoutMs(new_fd, connect_timeout_ms, connect_timeout_ms) catch {};
                const tls_ptr = p.allocator.create(http.tls_termination.UpstreamTlsConn) catch {
                    _ = std.c.close(new_fd);
                    p.releaseSlot(key);
                    return error.OutOfMemory;
                };
                tls_ptr.* = http.tls_termination.UpstreamTlsConn.connect(new_fd, host, tls_options.?) catch |err| {
                    p.allocator.destroy(tls_ptr);
                    _ = std.c.close(new_fd);
                    p.releaseSlot(key);
                    return err;
                };
                p.noteNewConnection(key);
                conn = .{ .stream = compat.netStreamFromFd(new_fd), .tls = tls_ptr, .created_ms = now_ms, .last_used_ms = now_ms };
            } else {
                p.noteNewConnection(key);
                conn = .{ .stream = compat.netStreamFromFd(new_fd), .tls = null, .created_ms = now_ms, .last_used_ms = now_ms };
            }
        }
        const fd = conn.stream.handle;

        if (connect_timeout_ms > 0) {
            setSocketTimeoutMs(fd, connect_timeout_ms, connect_timeout_ms) catch {};
        }

        var reusable = false;
        const exchange_start_ms = http.event_loop.monotonicMs();
        const result = if (conn.tls) |tls|
            exchangeBoundedBufferedHttpRequest(allocator, tls, fd, uri, method, extra_headers, body, content_type_override, max_buffered_response_bytes, connect_timeout_ms, response_timeout_ms, true, &reusable)
        else
            exchangeBoundedBufferedHttpRequest(allocator, compat.netStreamFromFd(fd), fd, uri, method, extra_headers, body, content_type_override, max_buffered_response_bytes, connect_timeout_ms, response_timeout_ms, true, &reusable);

        if (result) |resp| {
            p.release(key, conn, reusable, http.event_loop.monotonicMs());
            p.recordRequestLatency(false, http.event_loop.monotonicMs() - exchange_start_ms);
            return resp;
        } else |err| {
            p.release(key, conn, false, http.event_loop.monotonicMs()); // active--, close (deinits TLS)
            if (reused and err == error.UpstreamConnectionClosed and attempt == 0 and isHttpMethodIdempotent(method)) {
                p.recordStaleRetry(key);
                continue; // retry once on a fresh connection
            }
            return err;
        }
    }
    unreachable;
}

/// HTTP/2 upstream attempt over a fresh TLS connection (#145, PR 1). Connects,
/// handshakes with ALPN offering h2, and — if the origin negotiated h2 — runs a
/// single-stream h2 exchange; otherwise falls back to the HTTP/1.1 buffered
/// exchange on the same connection. Not pooled in PR 1 (the connection is closed
/// on return); h2 pooling/multiplexing is a later PR.
fn executeBufferedH2OrH1Fresh(
    allocator: std.mem.Allocator,
    host: []const u8,
    port: u16,
    opts: http.tls_termination.UpstreamTlsOptions,
    uri: std.Uri,
    method: []const u8,
    extra_headers: []const std.http.Header,
    body: []const u8,
    content_type_override: ?[]const u8,
    max_buffered_response_bytes: usize,
    connect_timeout_ms: u32,
    response_timeout_ms: u32,
    pool: ?*http.upstream_pool.UpstreamPool,
) !BufferedUpstreamResponse {
    const fd = try compat.connectBoundedTcp(host, port, connect_timeout_ms);
    defer _ = std.c.close(fd);
    if (connect_timeout_ms > 0) setSocketTimeoutMs(fd, connect_timeout_ms, connect_timeout_ms) catch {};

    var tls_conn = try http.tls_termination.UpstreamTlsConn.connect(fd, host, opts);
    defer tls_conn.deinit();

    if (tls_conn.negotiatedProtocol() == .http2) {
        if (pool) |p| p.recordProtocol(true);
        const deadline_ms: u32 = if (response_timeout_ms > 0)
            response_timeout_ms
        else if (connect_timeout_ms > 0) connect_timeout_ms else 30_000;

        var authority_buf: [300]u8 = undefined;
        const authority = if (port == 443)
            host
        else
            std.fmt.bufPrint(&authority_buf, "{s}:{d}", .{ host, port }) catch host;

        var path_buf: std.Io.Writer.Allocating = .init(allocator);
        defer path_buf.deinit();
        const path_component = uriComponentBytes(uri.path);
        try path_buf.writer.writeAll(if (path_component.len > 0) path_component else "/");
        if (uri.query) |q| {
            try path_buf.writer.writeByte('?');
            try path_buf.writer.writeAll(uriComponentBytes(q));
        }

        const start_ms = http.event_loop.monotonicMs();
        var h2resp = try http.upstream_h2.exchange(allocator, &tls_conn, fd, .{
            .method = method,
            .scheme = "https",
            .authority = authority,
            .path = path_buf.written(),
            .headers = extra_headers,
            .body = body,
        }, deadline_ms);
        defer h2resp.deinit();
        if (pool) |p| p.recordRequestLatency(true, http.event_loop.monotonicMs() - start_ms);
        return h2ResponseToBuffered(allocator, &h2resp);
    }

    // Origin chose HTTP/1.1: run the buffered h1 exchange on this connection.
    if (pool) |p| p.recordProtocol(false);
    var reusable = false;
    const start_ms = http.event_loop.monotonicMs();
    const resp = try exchangeBoundedBufferedHttpRequest(allocator, &tls_conn, fd, uri, method, extra_headers, body, content_type_override, max_buffered_response_bytes, connect_timeout_ms, response_timeout_ms, false, &reusable);
    if (pool) |p| p.recordRequestLatency(false, http.event_loop.monotonicMs() - start_ms);
    return resp;
}

/// HTTP/2 buffered request multiplexed over a shared per-origin connection
/// (#145, PR 2). Acquires (or creates) the origin's h2 connection from the pool
/// and issues one stream on it. A connection-level failure evicts the dead
/// connection and retries once on a fresh one. If the origin negotiated HTTP/1.1
/// over ALPN, the request runs on the HTTP/1.1 path over that connection.
///
/// `opts == null` selects prior-knowledge cleartext h2c (#237): plain socket,
/// `http` scheme, `h2c:`-prefixed pool key, and no `.h1` fallback (there is no
/// negotiation to fall back from).
fn executeBufferedViaH2Pool(
    allocator: std.mem.Allocator,
    h2_pool: *http.upstream_h2.H2ConnPool,
    host: []const u8,
    port: u16,
    opts: ?http.tls_termination.UpstreamTlsOptions,
    uri: std.Uri,
    method: []const u8,
    extra_headers: []const std.http.Header,
    body: []const u8,
    content_type_override: ?[]const u8,
    max_buffered_response_bytes: usize,
    connect_timeout_ms: u32,
    response_timeout_ms: u32,
    h1_pool: ?*http.upstream_pool.UpstreamPool,
) !BufferedUpstreamResponse {
    const deadline_ms: u32 = if (response_timeout_ms > 0)
        response_timeout_ms
    else if (connect_timeout_ms > 0) connect_timeout_ms else 30_000;

    const is_tls = opts != null;
    const scheme: []const u8 = if (is_tls) "https" else "http";
    const default_port: u16 = if (is_tls) 443 else 80;
    var key_buf: [300]u8 = undefined;
    const key = std.fmt.bufPrint(&key_buf, "{s}:{s}:{d}", .{ if (is_tls) "h2" else "h2c", host, port }) catch host;

    var attempt: usize = 0;
    while (attempt < 2) : (attempt += 1) {
        const acq = try h2_pool.acquire(key, host, port, opts, connect_timeout_ms, deadline_ms);
        switch (acq) {
            .h1 => |tls_ptr| {
                // ALPN negotiated HTTP/1.1: run the h1 exchange on this fresh
                // (unpooled) connection, then tear it down. (TLS only — the
                // h2c path has no negotiation and never lands here.)
                defer {
                    tls_ptr.close();
                    h2_pool.allocator.destroy(tls_ptr);
                }
                if (h1_pool) |p| p.recordProtocol(false);
                var reusable = false;
                const start_ms = http.event_loop.monotonicMs();
                const resp = try exchangeBoundedBufferedHttpRequest(allocator, tls_ptr, tls_ptr.fd, uri, method, extra_headers, body, content_type_override, max_buffered_response_bytes, connect_timeout_ms, response_timeout_ms, false, &reusable);
                if (h1_pool) |p| p.recordRequestLatency(false, http.event_loop.monotonicMs() - start_ms);
                return resp;
            },
            .h2 => |conn| {
                if (h1_pool) |p| p.recordProtocol(true);

                var authority_buf: [300]u8 = undefined;
                const authority = if (port == default_port)
                    host
                else
                    std.fmt.bufPrint(&authority_buf, "{s}:{d}", .{ host, port }) catch host;

                var path_buf: std.Io.Writer.Allocating = .init(allocator);
                defer path_buf.deinit();
                const path_component = uriComponentBytes(uri.path);
                try path_buf.writer.writeAll(if (path_component.len > 0) path_component else "/");
                if (uri.query) |q| {
                    try path_buf.writer.writeByte('?');
                    try path_buf.writer.writeAll(uriComponentBytes(q));
                }

                const start_ms = http.event_loop.monotonicMs();
                var h2resp = conn.request(.{
                    .method = method,
                    .scheme = scheme,
                    .authority = authority,
                    .path = path_buf.written(),
                    .headers = extra_headers,
                    .body = body,
                }) catch |err| {
                    // Connection-level failure: evict the dead connection so new
                    // requests do not pick it, drop our ref, and retry once.
                    h2_pool.evict(key, conn);
                    h2_pool.release(conn);
                    if (attempt == 0 and (err == error.Http2GoAway or err == error.Http2ConnectionClosed or err == error.Http2StreamReset)) {
                        continue;
                    }
                    return err;
                };
                defer h2resp.deinit();
                h2_pool.release(conn);
                if (h1_pool) |p| p.recordRequestLatency(true, http.event_loop.monotonicMs() - start_ms);
                return h2ResponseToBuffered(allocator, &h2resp);
            },
        }
    }
    unreachable;
}

/// Streaming reverse-proxy exchange over the per-origin HTTP/2 pool (#145,
/// Phase 4b PR 4). Issues the request as one stream on the shared origin
/// connection and relays DATA frames downstream as they arrive, with bounded
/// per-stream buffering: the actor replenishes the stream-level flow-control
/// window only as this relay drains, so a slow downstream client
/// backpressures its own stream without stalling other streams on the shared
/// connection (whose connection-level window the reader replenishes promptly).
///
/// A failure before any downstream byte evicts the connection and retries once
/// on connection-level errors (matching the buffered h2 path). Once the
/// response head has been written downstream, an upstream failure is reported
/// as an aborted relay (truncated chunked body) rather than an error. When the
/// Relay a streamed client upload to an HTTP/2 upstream as incremental DATA.
/// The caller owns connection teardown on error. `read_buf` is the single relay
/// buffer, so upload memory stays bounded; per-stream flow control supplies the
/// backpressure.
///
/// `reservation` is preflighted by the caller — before HEADERS are sent, so a
/// capacity refusal is something the origin never sees — and already covers
/// `read_buf` plus `uploadInitialBytesFootprint(sb)`. The caller releases the
/// rest; this function gives back only the initial-bytes portion as it drains.
fn relayStreamingUploadToHttp2(
    conn: anytype,
    stream: anytype,
    sb: StreamingRequestBody,
    read_buf: []u8,
    downstream_conn: anytype,
    cancel_token: ?*const CancellationToken,
    reservation: *ProxyBufferReservation,
) !void {
    switch (sb.framing) {
        .length => |content_length| {
            var sent: usize = @min(sb.initial_bytes.len, content_length);
            if (sent > 0) {
                conn.writeStreamingRequestBody(stream, sb.initial_bytes[0..sent], sent == content_length) catch |err| {
                    reservation.release(sent);
                    return err;
                };
                // Forwarded: the request head's body bytes are no longer held.
                reservation.release(sent);
            }
            while (sent < content_length) {
                if (cancelStopped(cancel_token)) return error.RequestCancelled;
                const want = @min(read_buf.len, content_length - sent);
                const n = downstream_conn.read(read_buf[0..want]) catch return error.ClientAborted;
                if (n == 0) return error.ClientAborted;
                try conn.writeStreamingRequestBody(stream, read_buf[0..n], sent + n == content_length);
                sent += n;
            }
            // A zero-length streamed body still needs an END_STREAM DATA frame.
            if (content_length == 0) try conn.writeStreamingRequestBody(stream, "", true);
        },
        .chunked => {
            // HTTP/2 has no chunked transfer coding: the decoded payload goes
            // out as DATA frames and END_STREAM replaces the terminal chunk, so
            // the upstream never sees a Content-Length it cannot know.
            var reader = http.chunked_upload.Reader(@TypeOf(downstream_conn))
                .init(downstream_conn, sb.initial_bytes, sb.max_body_bytes);
            // The decoder borrows the whole raw request-head remainder, framing
            // octets included — see `uploadInitialBytesFootprint`.
            var head_bytes_held = sb.initial_bytes.len;
            while (true) {
                if (cancelStopped(cancel_token)) return error.RequestCancelled;
                const n = try reader.next(read_buf);
                // Before acting on `n`: the terminal call consumes borrowed
                // trailer bytes too.
                releaseDrainedHeadBytes(reservation, &head_bytes_held, reader.pendingBytes());
                if (n == 0) break;
                try conn.writeStreamingRequestBody(stream, read_buf[0..n], false);
            }
            try conn.writeStreamingRequestBody(stream, "", true);
        },
    }
}

/// Streaming reverse-proxy exchange over the per-origin HTTP/2 pool (#145,
/// Phase 4b PR 4). Issues the request as one stream on the shared origin
/// connection and relays DATA frames downstream as they arrive, with bounded
/// per-stream buffering: the actor replenishes the stream-level flow-control
/// window only as this relay drains, so a slow downstream client
/// backpressures its own stream without stalling other streams on the shared
/// connection (whose connection-level window the reader replenishes promptly).
///
/// A failure before any downstream byte evicts the connection and retries once
/// on connection-level errors (matching the buffered h2 path). Once the
/// response head has been written downstream, an upstream failure is reported
/// as an aborted relay (truncated chunked body) rather than an error. When the
/// origin negotiates HTTP/1.1 via ALPN, the request runs on the h1 streaming
/// relay over that fresh (unpooled) connection instead.
///
/// `opts == null` selects prior-knowledge cleartext h2c (#237): plain socket,
/// `http` scheme, `h2c:`-prefixed pool key, no `.h1` fallback.
fn streamViaH2Pool(
    allocator: std.mem.Allocator,
    h2_pool: *http.upstream_h2.H2ConnPool,
    h1_pool: ?*http.upstream_pool.UpstreamPool,
    host: []const u8,
    port: u16,
    opts: ?http.tls_termination.UpstreamTlsOptions,
    uri: std.Uri,
    method: []const u8,
    extra_headers: []const std.http.Header,
    buffered_body: []const u8,
    streaming_body: ?StreamingRequestBody,
    read_buf: []u8,
    downstream_conn: anytype,
    downstream_writer: anytype,
    security: *const http.security_headers.SecurityHeaders,
    alt_svc: ?[]const u8,
    sticky_set_cookie: ?[]const u8,
    correlation_id: []const u8,
    connect_timeout_ms: u32,
    read_deadline_ms: u32,
    cancel_token: ?*const CancellationToken,
    proxy_buffer_limits: proxy_buffer_account.Limits,
    proxy_buffer_observer: proxy_buffer_account.Observer,
    proxy_buffer_global: ?*proxy_buffer_account.Aggregate,
) !StreamingProxyResult {
    const deadline_ms: u32 = if (read_deadline_ms > 0)
        read_deadline_ms
    else if (connect_timeout_ms > 0) connect_timeout_ms else 30_000;

    const is_tls = opts != null;
    const scheme: []const u8 = if (is_tls) "https" else "http";
    const default_port: u16 = if (is_tls) 443 else 80;
    var key_buf: [300]u8 = undefined;
    const key = std.fmt.bufPrint(&key_buf, "{s}:{s}:{d}", .{ if (is_tls) "h2" else "h2c", host, port }) catch host;

    var attempt: usize = 0;
    while (attempt < 2) : (attempt += 1) {
        const acq = try h2_pool.acquire(key, host, port, opts, connect_timeout_ms, deadline_ms);
        switch (acq) {
            .h1 => |tls_ptr| {
                // ALPN negotiated HTTP/1.1: run the h1 streaming relay on this
                // fresh (unpooled) connection, then tear it down.
                defer {
                    tls_ptr.close();
                    h2_pool.allocator.destroy(tls_ptr);
                }
                if (h1_pool) |p| p.recordProtocol(false);
                const start_ms = http.event_loop.monotonicMs();
                var wrote_downstream = false;
                // An ALPN-h1 origin never creates an h2 origin entry, so its
                // per-origin account comes from the h1 pool — under the h1 key
                // (`https:host:port`), which is the same origin identity the
                // h1 relay would use had h2 never been offered. Keying it under
                // `h2:…` would split one origin's memory across two limits.
                const h1_origin_account: ?*proxy_buffer_account.Aggregate = if (h1_pool) |p| blk: {
                    var h1_key_buf: [300]u8 = undefined;
                    const h1_key = std.fmt.bufPrint(&h1_key_buf, "{s}:{s}:{d}", .{ scheme, host, port }) catch host;
                    break :blk p.originBufferAccount(h1_key) catch return error.ProxyBufferCapacityUnavailable;
                } else null;
                const res = try streamProxyOverTransport(allocator, tls_ptr, tls_ptr.fd, read_buf, uri, method, extra_headers, buffered_body, streaming_body, downstream_conn, downstream_writer, security, alt_svc, sticky_set_cookie, correlation_id, connect_timeout_ms, read_deadline_ms, cancel_token, &wrote_downstream, proxy_buffer_limits, proxy_buffer_observer, .{ .origin = h1_origin_account, .global = proxy_buffer_global });
                if (h1_pool) |p| p.recordRequestLatency(false, http.event_loop.monotonicMs() - start_ms);
                return res.result;
            },
            .h2 => |conn| {
                if (h1_pool) |p| p.recordProtocol(true);

                // Aggregate capacity for this origin's queued response bytes
                // (#140). Looked up only on the h2 path, so an ALPN-h1 origin
                // never creates an h2 origin entry. The pointer is stable for
                // the pool's life, surviving retries and reconnects.
                //
                // A failure here means the accounting itself is unavailable
                // (allocation failure) — precisely when these limits matter
                // most. Dropping the scope would let the request retain
                // response bytes outside the configured per-origin bound, so
                // this is a deterministic pre-commit rejection instead.
                const origin_buffer_account = h2_pool.originBufferAccount(key) catch {
                    h2_pool.release(conn);
                    return error.ProxyBufferCapacityUnavailable;
                };
                // One budget for everything this stream owns at once, per
                // direction (#140). On the response side the queue's retained
                // storage and the relay buffer the consumer copies into are
                // both live at the same time — the queue's reservation is not
                // released until after the downstream write — so giving each
                // its own per-stream limit let a single stream own two hard
                // limits' worth while neither reported an exceedance. The
                // queue's per-stream `Account` still tracks its logical length
                // on its own, because that is what drives the watermarks and
                // the `WINDOW_UPDATE` hysteresis.
                //
                // Block-scoped, and safe as such: every path out of this block
                // calls `finishStreaming` first, which removes the stream from
                // the connection's map under its state lock and destroys it, so
                // no reader can reach this budget afterwards. A retry starts a
                // fresh one, as it should — it is a fresh stream.
                //
                // The per-stream policy is connection-pinned, so this needs no
                // reload mutation: the stream is judged by the policy its
                // connection advertised.
                var stream_hard_budget = proxy_buffer_account.Aggregate.init(
                    .stream,
                    proxy_buffer_limits.per_stream_hard_limit,
                );
                const proxy_buffer_capacity = proxy_buffer_account.AggregateCapacity{
                    .stream = &stream_hard_budget,
                    .origin = origin_buffer_account,
                    .global = proxy_buffer_global,
                };

                var authority_buf: [300]u8 = undefined;
                const authority = if (port == default_port)
                    host
                else
                    std.fmt.bufPrint(&authority_buf, "{s}:{d}", .{ host, port }) catch host;

                var path_buf: std.Io.Writer.Allocating = .init(allocator);
                defer path_buf.deinit();
                const path_component = uriComponentBytes(uri.path);
                try path_buf.writer.writeAll(if (path_component.len > 0) path_component else "/");
                if (uri.query) |q| {
                    try path_buf.writer.writeByte('?');
                    try path_buf.writer.writeAll(uriComponentBytes(q));
                }

                // Claim the upload's buffer footprint before `openStreaming`,
                // which sends HEADERS (#140). Reserving after it would let a
                // local 413/503 be raised only once the origin had already
                // received a request it will never see the body of.
                var upload_reservation: ?ProxyBufferReservation = null;
                defer if (upload_reservation) |*reservation| reservation.releaseAll();
                if (streaming_body) |sb| {
                    upload_reservation = preflightUploadReservation(
                        proxy_buffer_limits,
                        proxy_buffer_observer,
                        proxy_buffer_capacity,
                        read_buf.len,
                        uploadInitialBytesFootprint(sb),
                    ) catch |err| {
                        h2_pool.release(conn);
                        return err;
                    };
                }

                const start_ms = http.event_loop.monotonicMs();
                const stream = conn.openStreaming(.{
                    .method = method,
                    .scheme = scheme,
                    .authority = authority,
                    .path = path_buf.written(),
                    .headers = extra_headers,
                    .body = buffered_body,
                    .body_mode = if (streaming_body == null) .complete else .streaming,
                    .proxy_buffer_accounting = true,
                    .proxy_buffer_observer = proxy_buffer_observer,
                    .proxy_buffer_capacity = proxy_buffer_capacity,
                }) catch |err| {
                    // Nothing has reached the client yet: evict the dead
                    // connection so new requests do not pick it, and retry
                    // once on connection-level failures.
                    h2_pool.evict(key, conn);
                    h2_pool.release(conn);
                    if (streaming_body == null and attempt == 0 and (err == error.Http2GoAway or err == error.Http2ConnectionClosed or err == error.Http2StreamReset)) {
                        continue;
                    }
                    return err;
                };

                if (streaming_body) |sb| {
                    relayStreamingUploadToHttp2(
                        conn,
                        stream,
                        sb,
                        read_buf,
                        downstream_conn,
                        cancel_token,
                        &upload_reservation.?,
                    ) catch |err| {
                        const capacity_abort = err == error.BufferLimitExceeded or
                            conn.abortCause(stream) == .local_capacity;
                        conn.finishStreaming(stream);
                        if (!conn.healthy()) h2_pool.evict(key, conn);
                        h2_pool.release(conn);
                        // An early response can exhaust local buffer capacity
                        // while the upload is still being written, and the
                        // reader reports that through the *next* body write.
                        // Nothing is committed downstream yet, so it is a 503 —
                        // returning the raw error here made it a 502 charged to
                        // a healthy origin.
                        if (capacity_abort) return error.ProxyBufferCapacityUnavailable;
                        return err;
                    };
                    // The upload is done: `read_buf` holds no client bytes any
                    // more, so the request-direction claim ends here rather
                    // than at the end of the exchange. Carrying it through
                    // `waitStreamingResponseHead` and the response relay would
                    // occupy upload capacity for as long as the response takes
                    // — long enough for one slow response to make unrelated
                    // uploads fail with a 503 they should never have seen, and
                    // long enough for the direction gauges to keep reporting an
                    // upload that finished. (The HTTP/1 path has no equivalent
                    // window: `sendStreamingProxyRequest` returns, releasing
                    // its reservation, before the response is read.)
                    if (upload_reservation) |*reservation| {
                        reservation.releaseAll();
                        upload_reservation = null;
                    }
                }

                conn.waitStreamingResponseHead(stream) catch |err| {
                    conn.finishStreaming(stream);
                    if (!conn.healthy()) h2_pool.evict(key, conn);
                    h2_pool.release(conn);
                    // Local capacity, not the origin: nothing has reached the
                    // client, so this becomes a clean 503 and never counts
                    // against the origin. Retrying would hit the same wall.
                    if (err == error.BufferLimitExceeded) return error.ProxyBufferCapacityUnavailable;
                    if (streaming_body == null and attempt == 0 and (err == error.Http2GoAway or err == error.Http2ConnectionClosed or err == error.Http2StreamReset)) {
                        continue;
                    }
                    return err;
                };
                const ttfb_ms = http.event_loop.monotonicMs() - start_ms;
                const status = stream.status.?; // requestStreaming guarantees a status

                const reason = gpres.upstreamReasonPhrase(@enumFromInt(status));
                const body_allowed = gpres.responseBodyAllowed(method, status);

                // The response relay copies queued DATA out of the stream into
                // `read_buf`, and the queue's own reservation is not released
                // until `acknowledgeStreamingBody` — which runs *after* the
                // downstream write. While a slow client blocks in that write
                // the same bytes therefore exist twice in application-owned
                // memory, and charging only the queue let N concurrent slow
                // responses exceed every configured ceiling by roughly
                // N * read_buf.len with nothing in the accounting to show it
                // (#140).
                //
                // Taken before the commitment boundary below, so a refusal is
                // still a clean pre-commit 503 rather than a committed status
                // that has to be truncated, and released on every exit from
                // this block — including the retry `continue` paths. A
                // bodiless response never touches the buffer and is not
                // charged for it, which is the line HTTP/1 draws too.
                var response_reservation: ?ProxyBufferReservation = null;
                defer if (response_reservation) |*reservation| reservation.releaseAll();
                if (body_allowed) {
                    var reservation = ProxyBufferReservation.init(
                        .upstream_to_downstream,
                        proxy_buffer_limits,
                        proxy_buffer_observer,
                        proxy_buffer_capacity,
                    );
                    // `reserve` rolls itself back completely at either scope,
                    // so a refusal leaves nothing to clean up here.
                    reservation.reserve(read_buf.len) catch {
                        conn.finishStreaming(stream);
                        if (!conn.healthy()) h2_pool.evict(key, conn);
                        h2_pool.release(conn);
                        return error.ProxyBufferCapacityUnavailable;
                    };
                    response_reservation = reservation;
                }

                // Linearize the commitment boundary: the reader can reject DATA
                // in the gap between the head arriving and this write starting.
                // Claiming the transition under the connection's state lock
                // makes that a decided question — a refusal that lands first is
                // still a pre-commit 503 rather than a committed origin status
                // that we then have to truncate.
                conn.beginDownstreamCommit(stream) catch {
                    conn.finishStreaming(stream);
                    if (!conn.healthy()) h2_pool.evict(key, conn);
                    h2_pool.release(conn);
                    return error.ProxyBufferCapacityUnavailable;
                };
                gpres.writeStreamedUpstreamResponseHeadFromHeaders(
                    downstream_writer,
                    status,
                    reason,
                    stream.headers.items,
                    body_allowed,
                    correlation_id,
                    security,
                    alt_svc,
                    sticky_set_cookie,
                ) catch {
                    conn.finishStreaming(stream); // resets the unfinished stream
                    h2_pool.release(conn);
                    return error.ClientAborted;
                };

                var body_bytes: usize = 0;
                var aborted = false;
                var local_capacity_aborted = false;
                if (body_allowed) {
                    while (true) {
                        if (cancelStopped(cancel_token)) {
                            conn.finishStreaming(stream);
                            h2_pool.release(conn);
                            return error.RequestCancelled;
                        }
                        const n = conn.readStreamingBody(stream, read_buf) catch |err| {
                            // Failed mid-body after the head went downstream:
                            // report an aborted relay (the client sees the
                            // truncated chunked body); other streams on the
                            // connection are unaffected unless the whole
                            // connection died (handled below).
                            //
                            // The status can no longer change, but the *cause*
                            // still matters: a local buffer-capacity abort is
                            // this proxy running out of room, and blaming the
                            // origin for it would let local memory pressure
                            // trip a healthy origin's failure policy.
                            local_capacity_aborted = err == error.BufferLimitExceeded;
                            aborted = true;
                            break;
                        };
                        if (n == 0) break;
                        gpres.writeChunk(downstream_writer, read_buf[0..n]) catch {
                            conn.finishStreaming(stream);
                            h2_pool.release(conn);
                            return error.ClientAborted;
                        };
                        conn.acknowledgeStreamingBody(stream, n);
                        body_bytes += n;
                    }
                    if (!aborted) {
                        gpres.writeChunk(downstream_writer, "") catch {
                            conn.finishStreaming(stream);
                            h2_pool.release(conn);
                            return error.ClientAborted;
                        };
                    }
                }
                conn.finishStreaming(stream);
                // A connection-level failure mid-relay leaves the connection
                // unhealthy — evict it so new requests reconnect.
                if (aborted and !conn.healthy()) h2_pool.evict(key, conn);
                h2_pool.release(conn);
                if (!aborted) {
                    if (h1_pool) |p| p.recordRequestLatency(true, http.event_loop.monotonicMs() - start_ms);
                }

                return .{
                    .status_code = status,
                    .reason = reason,
                    .response_body_bytes = body_bytes,
                    .upstream_ttfb_ms = ttfb_ms,
                    .upstream_aborted = aborted,
                    .local_capacity_aborted = local_capacity_aborted,
                };
            },
        }
    }
    unreachable;
}

/// Convert an HTTP/2 response into the buffered-response shape the proxy path
/// expects. Headers + reason are owned by the response's metadata arena; the
/// body is duped with `allocator` (freed in `BufferedUpstreamResponse.deinit`).
fn h2ResponseToBuffered(allocator: std.mem.Allocator, h2resp: *http.upstream_h2.Response) !BufferedUpstreamResponse {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const aa = arena.allocator();

    const reason = try aa.dupe(u8, gpres.upstreamReasonPhrase(@enumFromInt(h2resp.status)));
    var headers = try aa.alloc(UpstreamHeader, h2resp.headers.len);
    for (h2resp.headers, 0..) |h, i| {
        headers[i] = .{ .name = try aa.dupe(u8, h.name), .value = try aa.dupe(u8, h.value) };
    }
    const body = try allocator.dupe(u8, h2resp.body);
    return .{
        .metadata_arena = arena,
        .status_code = h2resp.status,
        .reason = reason,
        .headers = headers,
        .body = body,
    };
}

/// Send a bounded buffered HTTP/1 request over an already-connected transport
/// and parse the response. `transport` must provide `writeAll([]const u8)` and
/// `read([]u8) !usize` (satisfied by both `compat.NetStream` and
/// `*UpstreamTlsConn`). `fd` is the underlying socket used for per-phase
/// timeout control. The caller owns connecting and closing the transport.
fn headerValue(headers: []const std.http.Header, name: []const u8) ?[]const u8 {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
    }
    return null;
}

fn exchangeBoundedBufferedHttpRequest(
    allocator: std.mem.Allocator,
    transport: anytype,
    fd: std.posix.fd_t,
    uri: std.Uri,
    method: []const u8,
    extra_headers: []const std.http.Header,
    body: []const u8,
    content_type_override: ?[]const u8,
    max_buffered_response_bytes: usize,
    send_timeout_ms: u32,
    response_timeout_ms: u32,
    /// When true the request omits `Connection: close`, allowing the upstream
    /// socket to be returned to the pool for reuse.
    keep_alive: bool,
    /// Set (when non-null) to whether the connection may be safely reused after
    /// this exchange: HTTP/1.1, no `Connection: close` in the response,
    /// definitively framed body, and the socket left in sync.
    reusable: ?*bool,
) !BufferedUpstreamResponse {
    if (reusable) |r| r.* = false;
    if (send_timeout_ms > 0) {
        try setSocketTimeoutMs(fd, send_timeout_ms, send_timeout_ms);
    }

    var req_aw: std.Io.Writer.Allocating = .init(allocator);
    defer req_aw.deinit();
    const req_writer = &req_aw.writer;
    var host_buf: [256]u8 = undefined;
    const upstream_host = if (uri.host) |value| try value.toRaw(&host_buf) else "localhost";
    const host_override = headerValue(extra_headers, "host");
    const host = host_override orelse upstream_host;

    try req_writer.print("{s} {s}", .{ method, uriComponentBytes(uri.path) });
    if (uri.query) |query| {
        try req_writer.print("?{s}", .{uriComponentBytes(query)});
    }
    try req_writer.writeAll(" HTTP/1.1\r\n");
    // Preserve a non-default upstream port in the Host header.
    const default_port: u16 = if (std.ascii.eqlIgnoreCase(uri.scheme, "https")) 443 else 80;
    if (host_override != null) {
        try req_writer.print("Host: {s}\r\n", .{host});
    } else if (uri.port) |p| {
        if (p != default_port) {
            try req_writer.print("Host: {s}:{d}\r\n", .{ host, p });
        } else {
            try req_writer.print("Host: {s}\r\n", .{host});
        }
    } else {
        try req_writer.print("Host: {s}\r\n", .{host});
    }
    if (!keep_alive) {
        try req_writer.writeAll("Connection: close\r\n");
    }
    if (content_type_override) |content_type| {
        try req_writer.print("Content-Type: {s}\r\n", .{content_type});
    }
    for (extra_headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "host")) continue;
        try req_writer.print("{s}: {s}\r\n", .{ header.name, header.value });
    }
    if (body.len > 0) {
        try req_writer.print("Content-Length: {d}\r\n", .{body.len});
    }
    try req_writer.writeAll("\r\n");
    if (body.len > 0) {
        try req_writer.writeAll(body);
    }

    try transport.writeAll(req_aw.written());

    // Bound the wait for the response with poll() rather than SO_RCVTIMEO:
    // SO_RCVTIMEO is reliably honored on AF_UNIX sockets but is silently ignored
    // on the AF_INET upstream sockets used here, so a hung TCP origin would block
    // the worker forever. SO_RCVTIMEO is still set (best effort) so OpenSSL-driven
    // TLS reads remain bounded; poll() is the authoritative deadline. (issue #196)
    if (response_timeout_ms > 0) {
        setSocketRecvTimeoutMs(fd, response_timeout_ms) catch {};
    }
    const read_deadline_ms = if (response_timeout_ms > 0) response_timeout_ms else send_timeout_ms;

    // Read until the response is complete per HTTP/1.1 framing. Reading until
    // EOF would stall against keep-alive upstreams that frame with
    // Content-Length / chunked and hold the socket open, so determine the body
    // boundary from the headers and stop there (issue #196).
    var resp_raw = std.array_list.Managed(u8).init(allocator);
    defer resp_raw.deinit();
    var read_buf: [8192]u8 = undefined;
    var header_end: ?usize = null;
    var framing: ResponseFraming = .close;
    while (true) {
        if (header_end == null) {
            if (std.mem.find(u8, resp_raw.items, "\r\n\r\n")) |he| {
                header_end = he;
                framing = detectResponseFraming(resp_raw.items[0..he], method);
            }
        }
        if (header_end) |he| {
            const headers_block = resp_raw.items[0..he];
            const body_start = he + 4;
            const resp_body = resp_raw.items[body_start..];
            switch (framing) {
                .none => {
                    // Bodiless: reusable only if nothing trailed the headers.
                    setReusable(reusable, keep_alive, headers_block, resp_body.len == 0);
                    break;
                },
                .length => |content_length| {
                    if (content_length > max_buffered_response_bytes) return error.StreamTooLong;
                    if (resp_body.len >= content_length) {
                        // Extra bytes past Content-Length leave the socket out of
                        // sync, so it can only be reused when the body landed
                        // exactly on the boundary.
                        setReusable(reusable, keep_alive, headers_block, resp_body.len == content_length);
                        resp_raw.shrinkRetainingCapacity(body_start + content_length);
                        break;
                    }
                },
                .chunked => {
                    if (try decodeChunkedBody(allocator, resp_body, max_buffered_response_bytes)) |decoded| {
                        defer allocator.free(decoded);
                        setReusable(reusable, keep_alive, headers_block, true);
                        var rebuilt = std.array_list.Managed(u8).init(allocator);
                        defer rebuilt.deinit();
                        try rebuilt.appendSlice(resp_raw.items[0..body_start]);
                        try rebuilt.appendSlice(decoded);
                        return parseBufferedUpstreamResponse(allocator, rebuilt.items);
                    }
                },
                .close => {}, // no length advertised — server will close; not reusable
            }
        }

        if (read_deadline_ms > 0 and !try pollFdReadable(fd, read_deadline_ms)) {
            return error.Timeout;
        }
        const n = try transport.read(&read_buf);
        if (n == 0) {
            // EOF. A close-delimited body ends here, and an empty/partial header
            // block is handled by the checks below. But a Content-Length or
            // chunked body that has not yet reached its declared end means the
            // origin closed mid-response: surface it as a protocol error so the
            // caller returns 502 instead of forwarding a body shorter than the
            // advertised length (#269).
            if (header_end != null) {
                switch (framing) {
                    .length, .chunked => return error.UpstreamProtocolError,
                    .none, .close => {},
                }
            }
            break;
        }
        try resp_raw.appendSlice(read_buf[0..n]);
        if (resp_raw.items.len > max_buffered_response_bytes) return error.StreamTooLong;
    }

    // A reused keep-alive connection the origin closed while idle yields zero
    // bytes here; surface it distinctly so the caller can retry on a fresh
    // connection (the request was never delivered).
    if (resp_raw.items.len == 0) return error.UpstreamConnectionClosed;

    return parseBufferedUpstreamResponse(allocator, resp_raw.items);
}

/// Set the caller's reusability flag: a connection may be reused only when we
/// asked to keep it alive, the response is HTTP/1.1 without `Connection: close`,
/// and the socket was left in sync (no bytes past the framed body).
fn setReusable(out: ?*bool, keep_alive: bool, headers_block: []const u8, in_sync: bool) void {
    const r = out orelse return;
    if (!keep_alive or !in_sync) {
        r.* = false;
        return;
    }
    const first_line_end = std.mem.find(u8, headers_block, "\r\n") orelse headers_block.len;
    if (!std.mem.startsWith(u8, headers_block[0..first_line_end], "HTTP/1.1")) {
        r.* = false;
        return;
    }
    var lines = std.mem.splitSequence(u8, headers_block[@min(first_line_end + 2, headers_block.len)..], "\r\n");
    while (lines.next()) |line| {
        const colon = std.mem.findScalar(u8, line, ':') orelse continue;
        if (!std.ascii.eqlIgnoreCase(std.mem.trim(u8, line[0..colon], " \t"), "connection")) continue;
        var tokens = std.mem.splitScalar(u8, std.mem.trim(u8, line[colon + 1 ..], " \t"), ',');
        while (tokens.next()) |token| {
            if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, token, " \t"), "close")) {
                r.* = false;
                return;
            }
        }
    }
    r.* = true;
}

/// How the upstream delimits the response body (RFC 7230 §3.3.3).
const ResponseFraming = union(enum) {
    none, // bodiless: HEAD request, or 1xx/204/304 status
    length: usize, // Content-Length bytes follow the header block
    chunked, // Transfer-Encoding: chunked
    close, // no length advertised — body ends when the connection closes
};

fn responseStatusIsBodiless(status: u16) bool {
    return (status >= 100 and status < 200) or status == 204 or status == 304;
}

/// Determine response framing from the header block (excluding the trailing
/// CRLFCRLF), the request method, and the status line.
fn detectResponseFraming(header_block: []const u8, method: []const u8) ResponseFraming {
    const first_line_end = std.mem.find(u8, header_block, "\r\n") orelse header_block.len;
    var status_parts = std.mem.splitScalar(u8, header_block[0..first_line_end], ' ');
    _ = status_parts.next();
    const status = std.fmt.parseInt(u16, status_parts.next() orelse "0", 10) catch 0;

    if (std.ascii.eqlIgnoreCase(method, "HEAD")) return .none;
    if (responseStatusIsBodiless(status)) return .none;

    var content_length: ?usize = null;
    var chunked = false;
    var lines = std.mem.splitSequence(u8, header_block[@min(first_line_end + 2, header_block.len)..], "\r\n");
    while (lines.next()) |line| {
        const colon = std.mem.findScalar(u8, line, ':') orelse continue;
        const name = std.mem.trim(u8, line[0..colon], " \t");
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (std.ascii.eqlIgnoreCase(name, "transfer-encoding")) {
            var tokens = std.mem.splitScalar(u8, value, ',');
            while (tokens.next()) |token| {
                if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, token, " \t"), "chunked")) chunked = true;
            }
        } else if (std.ascii.eqlIgnoreCase(name, "content-length")) {
            content_length = std.fmt.parseInt(usize, value, 10) catch null;
        }
    }

    // Transfer-Encoding takes precedence over Content-Length (RFC 7230 §3.3.3).
    if (chunked) return .chunked;
    if (content_length) |cl| return .{ .length = cl };
    return .close;
}

/// Decode a chunked message body. Returns the decoded payload when the
/// terminating zero-length chunk (and trailer section) has fully arrived, or
/// null when more bytes are needed. The caller owns the returned slice.
fn decodeChunkedBody(allocator: std.mem.Allocator, encoded: []const u8, max_bytes: usize) !?[]u8 {
    var out = std.array_list.Managed(u8).init(allocator);
    errdefer out.deinit();
    var pos: usize = 0;
    while (true) {
        const line_len = std.mem.find(u8, encoded[pos..], "\r\n") orelse return null;
        const size_line = encoded[pos .. pos + line_len];
        // Strip optional chunk extensions (";name=value").
        const size_str = if (std.mem.findScalar(u8, size_line, ';')) |s| size_line[0..s] else size_line;
        const size = std.fmt.parseInt(usize, std.mem.trim(u8, size_str, " \t"), 16) catch return error.UpstreamProtocolError;
        const data_start = pos + line_len + 2;
        if (size == 0) {
            // Last chunk: consume the (possibly empty) trailer section, which
            // ends at the first blank line.
            var tpos = data_start;
            while (true) {
                const tlen = std.mem.find(u8, encoded[tpos..], "\r\n") orelse return null;
                if (tlen == 0) return try out.toOwnedSlice(); // blank line → done
                tpos += tlen + 2;
            }
        }
        const data_end = data_start + size;
        if (data_end + 2 > encoded.len) return null; // chunk data + trailing CRLF not yet here
        try out.appendSlice(encoded[data_start..data_end]);
        if (out.items.len > max_bytes) return error.StreamTooLong;
        pos = data_end + 2; // skip the CRLF after the chunk data
    }
}

/// Wait up to `timeout_ms` for `fd` to become readable. Returns false on
/// timeout. EINTR is retried within the original deadline.
fn pollFdReadable(fd: std.posix.fd_t, timeout_ms: u32) !bool {
    var pfds = [_]std.posix.pollfd{.{
        .fd = fd,
        .events = std.posix.POLL.IN | std.posix.POLL.HUP | std.posix.POLL.ERR,
        .revents = 0,
    }};
    const ready = std.posix.poll(&pfds, @intCast(@min(timeout_ms, std.math.maxInt(i32)))) catch |err| switch (err) {
        error.Unexpected => return error.Timeout,
        else => return err,
    };
    return ready != 0;
}

/// What a zero-timeout writability check found on the upstream socket.
const UpstreamWritability = enum {
    /// The socket can take bytes right now.
    writable,
    /// The send buffer is full because the peer has stopped draining, so the
    /// next write blocks until it resumes. This — and only this — is
    /// backpressure, and for the synchronous HTTP/1 relay it is the whole of
    /// it, since that relay has no queue whose depth could cross a watermark.
    blocked,
    /// The socket is in error or hung up, or the check itself failed. A broken
    /// connection is not a slow one: the write is about to fail, and calling
    /// that a pause would report an upstream *failure* as a stalled origin.
    failed,
};

/// Ask whether `fd` can take bytes right now. Never waits.
///
/// `poll` reports a descriptor as ready for `POLLERR`, `POLLHUP`, or
/// `POLLNVAL` even when `POLLOUT` is absent, so readiness alone does not mean
/// writable and its absence does not mean full — the three outcomes have to be
/// separated or a dead upstream shows up in the backpressure counters.
fn pollUpstreamWritability(fd: std.posix.fd_t) UpstreamWritability {
    var pfds = [_]std.posix.pollfd{.{
        .fd = fd,
        .events = std.posix.POLL.OUT,
        .revents = 0,
    }};
    const ready = std.posix.poll(&pfds, 0) catch return .failed;
    if (ready == 0) return .blocked;
    const revents = pfds[0].revents;
    // Error bits win even when POLLOUT is also set: the write is not going to
    // succeed, so this is not a stall to wait out.
    if ((revents & (std.posix.POLL.ERR | std.posix.POLL.HUP | std.posix.POLL.NVAL)) != 0) return .failed;
    if ((revents & std.posix.POLL.OUT) != 0) return .writable;
    return .failed;
}

test "parseBufferedUpstreamResponse keeps metadata in an arena and preserves forwarded headers" {
    var parsed = try parseBufferedUpstreamResponse(
        std.testing.allocator,
        "HTTP/1.1 200 OK\r\n" ++
            "Content-Type: text/plain\r\n" ++
            "Cache-Control: no-store\r\n" ++
            "Connection: close\r\n" ++
            "\r\n" ++
            "ok",
    );
    defer parsed.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 200), parsed.status_code);
    try std.testing.expectEqualStrings("OK", parsed.reason);
    try std.testing.expectEqualStrings("text/plain", parsed.headerValue("content-type").?);
    try std.testing.expect(bufferedUpstreamResponseHasNoStore(&parsed));
    try std.testing.expectEqualStrings("ok", parsed.body);
}

test "parseBufferedUpstreamResponse returns UpstreamProtocolError on partial upstream response" {
    // Simulates an upstream that closes the TCP connection before sending a
    // complete HTTP response head (the scenario reported in issue #94).
    // Before the fix this returned error.UnsupportedHttpMethod, a misleading
    // name that also prevented callers from distinguishing a real method
    // rejection from a dropped-connection scenario.
    const testing = std.testing;

    // Upstream closed immediately — empty body
    try testing.expectError(error.UpstreamProtocolError, parseBufferedUpstreamResponse(testing.allocator, ""));

    // Upstream sent a partial status line and closed
    try testing.expectError(error.UpstreamProtocolError, parseBufferedUpstreamResponse(testing.allocator, "HTTP/1.1"));

    // Upstream sent headers but no blank line (no \r\n\r\n terminator)
    try testing.expectError(error.UpstreamProtocolError, parseBufferedUpstreamResponse(testing.allocator, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"));
}

pub fn bufferedUpstreamResponseHasNoStore(response: *const BufferedUpstreamResponse) bool {
    for (response.headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "cache-control")) continue;
        var tokens = std.mem.splitScalar(u8, header.value, ',');
        while (tokens.next()) |token_raw| {
            const token = std.mem.trim(u8, token_raw, " \t\r\n");
            if (std.ascii.eqlIgnoreCase(token, "no-store")) return true;
        }
    }
    return false;
}

/// Execute the current bounded buffered HTTP/1 reverse-proxy transport.
/// `gateway_proxy_runtime.zig` owns data-plane retry/routing semantics and
/// should be the place future streaming/backpressure work swaps this out.
pub fn executeBoundedBufferedHttpProxyRequest(
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    url: []const u8,
    unix_socket_path: ?[]const u8,
    method: []const u8,
    request_headers: *const http.Headers,
    body: []const u8,
    correlation_id: []const u8,
    client_ip: []const u8,
    forwarded_proto: []const u8,
    incoming_host: ?[]const u8,
    upstream_host_override: ?[]const u8,
    auth_identity: ?[]const u8,
    auth_user_id: ?[]const u8,
    auth_device_id: ?[]const u8,
    auth_scopes: ?[]const u8,
    forward_early_data: bool,
    attempt_timeout_ms: u32,
    connect_timeout_ms: u32,
    /// If > 0, caps the time from finished request-send to first response byte.
    /// Enforced on all transports (Unix socket, TCP, TLS) via per-phase socket
    /// timeouts now that the path no longer routes through std.http.Client.
    response_timeout_ms: u32,
    cancel_token: ?*const CancellationToken,
    /// Optional keep-alive pool for plain-HTTP upstream connection reuse (#141).
    pool: ?*http.upstream_pool.UpstreamPool,
    /// Optional per-origin HTTP/2 multiplexing pool (#145).
    h2_pool: ?*http.upstream_h2.H2ConnPool,
) !BufferedUpstreamResponse {
    // Bail out before touching the network if the request is already stopped.
    if (cancel_token) |tok| {
        if (tok.isStopped()) return error.RequestCancelled;
    }
    const proxy_extra_header_slack = 11;
    const max_buffered_response_bytes = maxBufferedUpstreamResponseBytes(cfg);
    const uri = try std.Uri.parse(url);

    var extra_headers_stack = std.heap.stackFallback(2048, allocator);
    const extra_headers_allocator = extra_headers_stack.get();
    var forwarded_for = try gph.buildForwardedFor(allocator, request_headers.get("x-forwarded-for"), client_ip);
    defer forwarded_for.deinit(allocator);

    var extra_headers = std.array_list.Managed(std.http.Header).init(extra_headers_allocator);
    defer extra_headers.deinit();
    try extra_headers.ensureUnusedCapacity(request_headers.count() + proxy_extra_header_slack);
    try gph.appendProxyRequestHeaders(&extra_headers, request_headers);
    if (upstream_host_override) |value| {
        const trimmed = std.mem.trim(u8, value, " \t\r\n");
        if (trimmed.len > 0) try extra_headers.append(.{ .name = "Host", .value = trimmed });
    }
    try gph.appendCanonicalEarlyDataHeader(&extra_headers, forward_early_data);
    try gph.appendRequestIdHeaders(&extra_headers, correlation_id);
    try extra_headers.append(.{ .name = "X-Forwarded-For", .value = forwarded_for.value });
    try extra_headers.append(.{ .name = "X-Real-IP", .value = client_ip });
    try extra_headers.append(.{ .name = "X-Forwarded-Proto", .value = forwarded_proto });
    if (incoming_host) |value| {
        const trimmed = std.mem.trim(u8, value, " \t\r\n");
        if (trimmed.len > 0) try extra_headers.append(.{ .name = "X-Forwarded-Host", .value = trimmed });
    }
    try gph.appendAssertedIdentityHeaders(&extra_headers, auth_identity, auth_user_id, auth_device_id, auth_scopes);
    // W3C Trace Context: propagate inbound traceparent or originate a new one.
    // A child span is created from an inbound context so the trace ID is preserved
    // but each hop gets its own span ID.
    var traceparent_buf: [55]u8 = undefined;
    if (request_headers.get("traceparent") == null) {
        const tc = http.trace_context.generate();
        const tp = tc.format(&traceparent_buf);
        if (tp.len > 0) try extra_headers.append(.{ .name = "traceparent", .value = tp });
    }

    if (unix_socket_path) |socket_path| {
        const base_timeout_ms = if (attempt_timeout_ms > 0) attempt_timeout_ms else connect_timeout_ms;
        const effective_timeout_ms = if (cancel_token) |tok|
            tok.effectiveTimeoutMs(base_timeout_ms)
        else
            base_timeout_ms;
        const effective_response_timeout_ms = if (cancel_token) |tok|
            tok.effectiveTimeoutMs(response_timeout_ms)
        else
            response_timeout_ms;
        return executeBoundedBufferedUnixSocketHttpRequest(
            allocator,
            socket_path,
            uri,
            method,
            extra_headers.items,
            body,
            null,
            max_buffered_response_bytes,
            effective_timeout_ms,
            effective_response_timeout_ms,
            pool,
        );
    }

    // Plain HTTP/1 or TLS TCP upstream — manual bounded transport with per-phase
    // timeout enforcement (issue #196) and keep-alive pooling (#141). HTTPS uses
    // the global upstream TLS config and is pooled separately from plain HTTP.
    const is_https = std.ascii.eqlIgnoreCase(uri.scheme, "https");
    const host = if (uri.host) |h| uriComponentBytes(h) else return error.UpstreamProtocolError;
    const port: u16 = uri.port orelse (if (is_https) @as(u16, 443) else 80);
    const tls_options: ?http.tls_termination.UpstreamTlsOptions = if (is_https) .{
        .skip_verify = !cfg.upstream_tls_verify,
        .ca_bundle_path = cfg.upstream_tls_ca_bundle,
        .sni_override = cfg.upstream_tls_server_name,
        .client_cert_path = cfg.upstream_tls_client_cert,
        .client_key_path = cfg.upstream_tls_client_key,
        .alpn_policy = upstreamAlpnPolicy(cfg.upstream_protocol),
    } else null;
    const base_timeout_ms = if (attempt_timeout_ms > 0) attempt_timeout_ms else connect_timeout_ms;
    const effective_send_timeout_ms = if (cancel_token) |tok|
        tok.effectiveTimeoutMs(base_timeout_ms)
    else
        base_timeout_ms;
    const effective_response_timeout_ms = if (cancel_token) |tok|
        tok.effectiveTimeoutMs(response_timeout_ms)
    else
        response_timeout_ms;
    return executeBoundedBufferedTcpHttpRequest(
        allocator,
        host,
        port,
        tls_options,
        uri,
        method,
        extra_headers.items,
        body,
        null,
        max_buffered_response_bytes,
        effective_send_timeout_ms,
        effective_response_timeout_ms,
        pool,
        h2_pool,
        cfg.upstream_protocol.h2cPriorKnowledge(),
    );
}

// ---------------------------------------------------------------------------
// Manual streaming upstream reader (#141 Phase 3)
//
// Replaces std.http.Client's framing-aware reader on the streaming proxy path
// with a poll-bounded manual reader so streaming inherits the #196 timeout
// enforcement and pooling instead of the opaque client.
// ---------------------------------------------------------------------------

/// A sliding-window read buffer over a manual transport. Holds bytes read from
/// the socket so the response head can be parsed and the body streamed without
/// re-reading. `buf` is caller-owned.
const StreamReadBuf = struct {
    buf: []u8,
    start: usize = 0,
    end: usize = 0,

    fn available(self: *const StreamReadBuf) []u8 {
        return self.buf[self.start..self.end];
    }

    fn consume(self: *StreamReadBuf, n: usize) void {
        self.start += n;
        if (self.start == self.end) {
            self.start = 0;
            self.end = 0;
        }
    }

    /// Read more bytes from the transport (poll-bounded). Returns false on EOF.
    fn fill(self: *StreamReadBuf, transport: anytype, fd: std.posix.fd_t, deadline_ms: u32) !bool {
        if (self.start == self.end) {
            self.start = 0;
            self.end = 0;
        } else if (self.end == self.buf.len) {
            std.mem.copyForwards(u8, self.buf[0 .. self.end - self.start], self.buf[self.start..self.end]);
            self.end -= self.start;
            self.start = 0;
        }
        if (self.end == self.buf.len) return error.StreamTooLong; // window full without a delimiter
        if (deadline_ms > 0 and !try pollFdReadable(fd, deadline_ms)) return error.Timeout;
        const n = try transport.read(self.buf[self.end..]);
        if (n == 0) return false;
        self.end += n;
        return true;
    }
};

fn cancelStopped(tok: ?*const CancellationToken) bool {
    if (tok) |t| return t.isStopped();
    return false;
}

const ParsedUpstreamHead = struct {
    status_code: u16,
    reason: []const u8, // arena-owned
    headers: []UpstreamHeader, // arena-owned
    framing: ResponseFraming,
    connection_close: bool,
    http_1_1: bool,
};

/// Read and parse the upstream response head from `rb` (poll-bounded), leaving
/// any already-read body bytes in `rb`. reason/headers are allocated in `arena`.
fn readUpstreamHead(
    arena: std.mem.Allocator,
    rb: *StreamReadBuf,
    transport: anytype,
    fd: std.posix.fd_t,
    deadline_ms: u32,
    method: []const u8,
) !ParsedUpstreamHead {
    while (std.mem.find(u8, rb.available(), "\r\n\r\n") == null) {
        if (!try rb.fill(transport, fd, deadline_ms)) {
            return if (rb.available().len == 0) error.UpstreamConnectionClosed else error.UpstreamProtocolError;
        }
    }
    const win = rb.available();
    const head_end = std.mem.find(u8, win, "\r\n\r\n").?;
    const header_block = win[0..head_end];

    const first_line_end = std.mem.find(u8, header_block, "\r\n") orelse head_end;
    const status_line = header_block[0..first_line_end];
    const http_1_1 = std.mem.startsWith(u8, status_line, "HTTP/1.1");
    var sp = std.mem.splitScalar(u8, status_line, ' ');
    _ = sp.next();
    const status_code = std.fmt.parseInt(u16, sp.next() orelse "0", 10) catch 0;
    const reason = try arena.dupe(u8, sp.rest());

    var headers = std.array_list.Managed(UpstreamHeader).init(arena);
    var connection_close = false;
    var lines = std.mem.splitSequence(u8, header_block[@min(first_line_end + 2, header_block.len)..], "\r\n");
    while (lines.next()) |line| {
        const colon = std.mem.findScalar(u8, line, ':') orelse continue;
        const name = std.mem.trim(u8, line[0..colon], " \t");
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (std.ascii.eqlIgnoreCase(name, "connection")) {
            var toks = std.mem.splitScalar(u8, value, ',');
            while (toks.next()) |t| {
                if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, t, " \t"), "close")) connection_close = true;
            }
        }
        if (gph.shouldSkipUpstreamResponseHeader(name)) continue;
        try headers.append(.{ .name = try arena.dupe(u8, name), .value = try arena.dupe(u8, value) });
    }
    const framing = detectResponseFraming(header_block, method);
    rb.consume(head_end + 4);
    return .{
        .status_code = status_code,
        .reason = reason,
        .headers = try headers.toOwnedSlice(),
        .framing = framing,
        .connection_close = connection_close,
        .http_1_1 = http_1_1,
    };
}

const RelayOutcome = struct {
    body_bytes: usize,
    aborted: bool, // upstream closed/failed before the framed body completed
    reusable: bool, // connection may be returned to the pool
};

fn readChunkSize(rb: *StreamReadBuf, transport: anytype, fd: std.posix.fd_t, deadline_ms: u32) !?usize {
    while (std.mem.find(u8, rb.available(), "\r\n") == null) {
        if (!try rb.fill(transport, fd, deadline_ms)) return null;
    }
    const avail = rb.available();
    const eol = std.mem.find(u8, avail, "\r\n").?;
    const size_line = avail[0..eol];
    const size_str = if (std.mem.findScalar(u8, size_line, ';')) |s| size_line[0..s] else size_line;
    const size = std.fmt.parseInt(usize, std.mem.trim(u8, size_str, " \t"), 16) catch return error.UpstreamProtocolError;
    rb.consume(eol + 2);
    return size;
}

fn consumeExactCrlf(rb: *StreamReadBuf, transport: anytype, fd: std.posix.fd_t, deadline_ms: u32) !bool {
    while (rb.available().len < 2) {
        if (!try rb.fill(transport, fd, deadline_ms)) return false;
    }
    if (!std.mem.eql(u8, rb.available()[0..2], "\r\n")) return error.UpstreamProtocolError;
    rb.consume(2);
    return true;
}

fn consumeChunkTrailers(rb: *StreamReadBuf, transport: anytype, fd: std.posix.fd_t, deadline_ms: u32) !bool {
    while (true) {
        while (std.mem.find(u8, rb.available(), "\r\n") == null) {
            if (!try rb.fill(transport, fd, deadline_ms)) return false;
        }
        const avail = rb.available();
        const eol = std.mem.find(u8, avail, "\r\n").?;
        rb.consume(eol + 2);
        if (eol == 0) return true; // blank line terminates the trailer section
    }
}

/// Relay the upstream response body to `downstream_writer` (re-chunked via
/// `writeChunk`), decoding the upstream framing as it streams. Returns the
/// number of body bytes relayed and whether the connection is reusable.
/// Downstream write failures surface as error.ClientAborted.
fn relayUpstreamBody(
    rb: *StreamReadBuf,
    transport: anytype,
    fd: std.posix.fd_t,
    deadline_ms: u32,
    framing: ResponseFraming,
    downstream_writer: anytype,
    cancel_token: ?*const CancellationToken,
) !RelayOutcome {
    var total: usize = 0;
    switch (framing) {
        // Bodiless (HEAD/204/304/1xx): reusable only if nothing trailed the head.
        .none => return .{ .body_bytes = 0, .aborted = false, .reusable = rb.available().len == 0 },
        .length => |content_length| {
            var remaining = content_length;
            while (remaining > 0) {
                if (cancelStopped(cancel_token)) return error.RequestCancelled;
                if (rb.available().len == 0 and !try rb.fill(transport, fd, deadline_ms)) {
                    return .{ .body_bytes = total, .aborted = true, .reusable = false };
                }
                const take = @min(rb.available().len, remaining);
                gpres.writeChunk(downstream_writer, rb.available()[0..take]) catch return error.ClientAborted;
                rb.consume(take);
                total += take;
                remaining -= take;
            }
            // Reusable only if the socket is back in sync (no bytes past the body).
            return .{ .body_bytes = total, .aborted = false, .reusable = rb.available().len == 0 };
        },
        .chunked => {
            while (true) {
                if (cancelStopped(cancel_token)) return error.RequestCancelled;
                const size = (try readChunkSize(rb, transport, fd, deadline_ms)) orelse
                    return .{ .body_bytes = total, .aborted = true, .reusable = false };
                if (size == 0) {
                    if (!try consumeChunkTrailers(rb, transport, fd, deadline_ms)) {
                        return .{ .body_bytes = total, .aborted = true, .reusable = false };
                    }
                    // Reusable only if nothing trailed the terminating chunk.
                    return .{ .body_bytes = total, .aborted = false, .reusable = rb.available().len == 0 };
                }
                var chunk_remaining = size;
                while (chunk_remaining > 0) {
                    if (rb.available().len == 0 and !try rb.fill(transport, fd, deadline_ms)) {
                        return .{ .body_bytes = total, .aborted = true, .reusable = false };
                    }
                    const take = @min(rb.available().len, chunk_remaining);
                    gpres.writeChunk(downstream_writer, rb.available()[0..take]) catch return error.ClientAborted;
                    rb.consume(take);
                    total += take;
                    chunk_remaining -= take;
                }
                if (!try consumeExactCrlf(rb, transport, fd, deadline_ms)) {
                    return .{ .body_bytes = total, .aborted = true, .reusable = false };
                }
            }
        },
        .close => {
            while (true) {
                if (cancelStopped(cancel_token)) return error.RequestCancelled;
                if (rb.available().len == 0 and !try rb.fill(transport, fd, deadline_ms)) break;
                gpres.writeChunk(downstream_writer, rb.available()) catch return error.ClientAborted;
                total += rb.available().len;
                rb.consume(rb.available().len);
            }
            // Close-delimited responses cannot be reused (the socket is spent).
            return .{ .body_bytes = total, .aborted = false, .reusable = false };
        },
    }
}

/// Send the proxied request head and body to the upstream over `transport`.
/// `streaming_body` relays the client upload incrementally; `buffered_body` is
/// sent in one shot. Keep-alive (no `Connection: close`) so the connection can
/// be pooled.
fn sendStreamingProxyRequest(
    allocator: std.mem.Allocator,
    transport: anytype,
    fd: std.posix.fd_t,
    uri: std.Uri,
    method: []const u8,
    extra_headers: []const std.http.Header,
    buffered_body: []const u8,
    streaming_body: ?StreamingRequestBody,
    downstream_conn: anytype,
    cancel_token: ?*const CancellationToken,
    proxy_buffer_limits: proxy_buffer_account.Limits,
    proxy_buffer_observer: proxy_buffer_account.Observer,
    proxy_buffer_capacity: proxy_buffer_account.AggregateCapacity,
) !void {
    // Claim the upload's buffer footprint before a single byte of the request
    // reaches the origin (#140). Reserving inside the relay meant a local
    // 413/503 could only be raised after the origin had already received a
    // half-delivered, possibly side-effecting request.
    var upload_reservation: ?ProxyBufferReservation = null;
    defer if (upload_reservation) |*reservation| reservation.releaseAll();
    if (streaming_body) |sb| {
        upload_reservation = try preflightUploadReservation(
            proxy_buffer_limits,
            proxy_buffer_observer,
            proxy_buffer_capacity,
            http1_upload_relay_bytes,
            uploadInitialBytesFootprint(sb),
        );
    }

    var req_aw: std.Io.Writer.Allocating = .init(allocator);
    defer req_aw.deinit();
    const w = &req_aw.writer;
    var host_buf: [256]u8 = undefined;
    const host = if (uri.host) |value| try value.toRaw(&host_buf) else "localhost";

    try w.print("{s} {s}", .{ method, uriComponentBytes(uri.path) });
    if (uri.query) |query| try w.print("?{s}", .{uriComponentBytes(query)});
    try w.writeAll(" HTTP/1.1\r\n");
    // Preserve a non-default upstream port in the Host header.
    const default_port: u16 = if (std.ascii.eqlIgnoreCase(uri.scheme, "https")) 443 else 80;
    if (uri.port) |p| {
        if (p != default_port) {
            try w.print("Host: {s}:{d}\r\n", .{ host, p });
        } else {
            try w.print("Host: {s}\r\n", .{host});
        }
    } else {
        try w.print("Host: {s}\r\n", .{host});
    }
    for (extra_headers) |header| try w.print("{s}: {s}\r\n", .{ header.name, header.value });
    if (streaming_body) |sb| {
        switch (sb.framing) {
            // A chunked client upload is re-framed rather than buffered, so the
            // upstream request stays chunked and no length is declared.
            .length => |content_length| try w.print("Content-Length: {d}\r\n", .{content_length}),
            .chunked => try w.writeAll("Transfer-Encoding: chunked\r\n"),
        }
    } else if (buffered_body.len > 0) {
        try w.print("Content-Length: {d}\r\n", .{buffered_body.len});
    }
    try w.writeAll("\r\n");
    try transport.writeAll(req_aw.written());

    if (streaming_body) |sb| {
        try relayStreamingUploadToHttp1(
            transport,
            fd,
            sb,
            downstream_conn,
            cancel_token,
            &upload_reservation.?,
            proxy_buffer_observer,
        );
    } else if (buffered_body.len > 0) {
        try transport.writeAll(buffered_body);
    }
}

/// Relay a streamed client upload to an HTTP/1.1 upstream. Both framings copy
/// through one fixed relay buffer, so peak user-space upload memory is bounded
/// regardless of the body size.
///
/// `fd` is the upstream socket (the TLS carrier when the transport is TLS). It
/// is used only to notice a write that would block: this relay reads the client
/// again only after the upstream write completes, so a full upstream send buffer
/// *is* a pause of downstream reads, and that transition is the only place a
/// slow origin becomes visible on a path that deliberately has no queue (#140).
///
/// `reservation` is preflighted by the caller and already covers this relay
/// buffer plus `uploadInitialBytesFootprint(sb)`; the caller releases the rest.
/// This function only gives back the initial-bytes portion as those bytes
/// actually drain, so a long upload does not hold the request head's peak for
/// its whole life.
fn relayStreamingUploadToHttp1(
    transport: anytype,
    fd: std.posix.fd_t,
    sb: StreamingRequestBody,
    downstream_conn: anytype,
    cancel_token: ?*const CancellationToken,
    reservation: *ProxyBufferReservation,
    observer: proxy_buffer_account.Observer,
) !void {
    var relay: [http1_upload_relay_bytes]u8 = undefined;

    // Balanced on every exit — success, client abort, cancellation, upstream
    // failure — so the pause/resume difference reads as "relays stalled right
    // now" instead of drifting by one per aborted upload.
    var stall = proxy_buffer_account.ReadStall.init(.downstream, observer);
    defer stall.unpause();

    switch (sb.framing) {
        .length => |content_length| {
            var sent: usize = @min(sb.initial_bytes.len, content_length);
            if (sent > 0) {
                noteUpstreamWriteStall(fd, &stall);
                transport.writeAll(sb.initial_bytes[0..sent]) catch |err| {
                    reservation.release(sent);
                    return err;
                };
                stall.unpause();
                // Forwarded: the request head's body bytes are no longer held.
                reservation.release(sent);
            }
            while (sent < content_length) {
                if (cancelStopped(cancel_token)) return error.RequestCancelled;
                const want = @min(relay.len, content_length - sent);
                const n = downstream_conn.read(relay[0..want]) catch return error.ClientAborted;
                if (n == 0) return error.ClientAborted;
                noteUpstreamWriteStall(fd, &stall);
                try transport.writeAll(relay[0..n]);
                stall.unpause();
                sent += n;
            }
        },
        .chunked => {
            // Decode the client's framing and re-chunk downstream-to-upstream.
            // Re-framing (rather than forwarding the raw octets) keeps the
            // upstream request well formed even when the client uses chunk
            // extensions or trailers, which this hop does not forward.
            var reader = http.chunked_upload.Reader(@TypeOf(downstream_conn))
                .init(downstream_conn, sb.initial_bytes, sb.max_body_bytes);
            // The decoder borrows the whole raw request-head remainder —
            // framing octets included, which is why the reservation covers the
            // raw length rather than the decoded payload.
            var head_bytes_held = sb.initial_bytes.len;
            while (true) {
                if (cancelStopped(cancel_token)) return error.RequestCancelled;
                const n = try reader.next(&relay);
                // Give back what the decoder has finished with, before acting on
                // `n`: the terminal call consumes borrowed trailer bytes too.
                releaseDrainedHeadBytes(reservation, &head_bytes_held, reader.pendingBytes());
                if (n == 0) break;
                var size_buf: [24]u8 = undefined;
                const size_line = std.fmt.bufPrint(&size_buf, "{x}\r\n", .{n}) catch unreachable;
                // One stall check per chunk, not per write: the three writes
                // below are one logical chunk and stall or drain together.
                noteUpstreamWriteStall(fd, &stall);
                try transport.writeAll(size_line);
                try transport.writeAll(relay[0..n]);
                try transport.writeAll("\r\n");
                stall.unpause();
            }
            try transport.writeAll("0\r\n\r\n");
        },
    }
}

/// Release the request-head bytes a chunked decoder has consumed since the last
/// check. `still_held` is what it still borrows; anything below the previous
/// mark has been copied out and is no longer retained.
fn releaseDrainedHeadBytes(
    reservation: *ProxyBufferReservation,
    head_bytes_held: *usize,
    still_held: usize,
) void {
    if (still_held >= head_bytes_held.*) return;
    reservation.release(head_bytes_held.* - still_held);
    head_bytes_held.* = still_held;
}

/// Run one streaming proxy attempt over an already-connected `transport`: send
/// the request, read the response head, relay the head+body downstream, and
/// report whether the connection is reusable. `wrote_downstream` is set true the
/// moment any response bytes are written to the client (after which the caller
/// must not retry on a fresh connection).
fn streamProxyOverTransport(
    allocator: std.mem.Allocator,
    transport: anytype,
    fd: std.posix.fd_t,
    read_buf: []u8,
    uri: std.Uri,
    method: []const u8,
    extra_headers: []const std.http.Header,
    buffered_body: []const u8,
    streaming_body: ?StreamingRequestBody,
    downstream_conn: anytype,
    downstream_writer: anytype,
    security: *const http.security_headers.SecurityHeaders,
    alt_svc: ?[]const u8,
    sticky_set_cookie: ?[]const u8,
    correlation_id: []const u8,
    connect_timeout_ms: u32,
    read_deadline_ms: u32,
    cancel_token: ?*const CancellationToken,
    wrote_downstream: *bool,
    proxy_buffer_limits: proxy_buffer_account.Limits,
    proxy_buffer_observer: proxy_buffer_account.Observer,
    proxy_buffer_capacity: proxy_buffer_account.AggregateCapacity,
) !struct { result: StreamingProxyResult, reusable: bool } {
    if (connect_timeout_ms > 0) setSocketTimeoutMs(fd, connect_timeout_ms, connect_timeout_ms) catch {};
    try sendStreamingProxyRequest(
        allocator,
        transport,
        fd,
        uri,
        method,
        extra_headers,
        buffered_body,
        streaming_body,
        downstream_conn,
        cancel_token,
        proxy_buffer_limits,
        proxy_buffer_observer,
        proxy_buffer_capacity,
    );
    if (read_deadline_ms > 0) setSocketRecvTimeoutMs(fd, read_deadline_ms) catch {};

    const ttfb_start_ms = http.event_loop.monotonicMs();
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    var rb = StreamReadBuf{ .buf = read_buf };
    const head = try readUpstreamHead(arena.allocator(), &rb, transport, fd, read_deadline_ms, method);
    const ttfb_ms = http.event_loop.monotonicMs() - ttfb_start_ms;

    const reason = gpres.upstreamReasonPhrase(@enumFromInt(head.status_code));
    const body_allowed = gpres.responseBodyAllowed(method, head.status_code);
    var response_reservation: ?ProxyBufferReservation = null;
    if (body_allowed) {
        response_reservation = ProxyBufferReservation.init(.upstream_to_downstream, proxy_buffer_limits, proxy_buffer_observer, proxy_buffer_capacity);
        try response_reservation.?.reserve(read_buf.len);
    }
    defer if (response_reservation) |*reservation| reservation.releaseAll();

    gpres.writeStreamedUpstreamResponseHeadFromHeaders(
        downstream_writer,
        head.status_code,
        reason,
        head.headers,
        body_allowed,
        correlation_id,
        security,
        alt_svc,
        sticky_set_cookie,
    ) catch return error.ClientAborted;
    wrote_downstream.* = true;

    var body_bytes: usize = 0;
    var aborted = false;
    var reusable = head.http_1_1 and !head.connection_close;
    if (body_allowed) {
        const outcome = try relayUpstreamBody(&rb, transport, fd, read_deadline_ms, head.framing, downstream_writer, cancel_token);
        body_bytes = outcome.body_bytes;
        aborted = outcome.aborted;
        reusable = reusable and outcome.reusable;
        if (!aborted) gpres.writeChunk(downstream_writer, "") catch return error.ClientAborted;
    }
    if (aborted) reusable = false;

    return .{
        .result = .{
            .status_code = head.status_code,
            .reason = reason,
            .response_body_bytes = body_bytes,
            .upstream_ttfb_ms = ttfb_ms,
            .upstream_aborted = aborted,
        },
        .reusable = reusable,
    };
}

/// Stream a reverse-proxy request/response over the manual bounded transport
/// (issue #141 Phase 3), replacing `std.http.Client`. The upstream connection
/// is pooled (plain or TLS) and per-phase reads are `poll`-bounded, so the
/// streaming path inherits the #196 timeout enforcement and #141 reuse.
///
/// When `TARDIGRADE_UPSTREAM_PROTOCOL` offers h2 and the target is HTTPS, or
/// when h2c prior knowledge is explicitly configured for plain HTTP, the
/// exchange is multiplexed over the shared per-origin HTTP/2 connection. Full
/// streaming uploads relay request DATA incrementally over the h2 stream; h1 is
/// used only when h2 is not requested or TLS ALPN negotiates HTTP/1.1.
pub fn executeStreamingHttpProxyRequest(
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    url: []const u8,
    /// When set, the exchange runs over this AF_UNIX socket instead of a TCP
    /// connection to `url`'s authority; `url` still supplies the request target.
    unix_socket_path: ?[]const u8,
    method: []const u8,
    request_headers: *const http.Headers,
    buffered_body: []const u8,
    streaming_body: ?StreamingRequestBody,
    downstream_conn: anytype,
    downstream_writer: anytype,
    correlation_id: []const u8,
    client_ip: []const u8,
    forwarded_proto: []const u8,
    incoming_host: ?[]const u8,
    auth_identity: ?[]const u8,
    auth_user_id: ?[]const u8,
    auth_device_id: ?[]const u8,
    auth_scopes: ?[]const u8,
    security: *const http.security_headers.SecurityHeaders,
    alt_svc: ?[]const u8,
    sticky_set_cookie: ?[]const u8,
    cancel_token: ?*const CancellationToken,
    proxy_buffer_observer: proxy_buffer_account.Observer,
    /// Process-wide proxy buffer aggregate (#140). Streams reserve against it
    /// before retaining queued body bytes, so aggregate memory stays bounded no
    /// matter how many origins or concurrent streams are slow.
    proxy_buffer_global: ?*proxy_buffer_account.Aggregate,
    pool: ?*http.upstream_pool.UpstreamPool,
    /// Optional per-origin HTTP/2 multiplexing pool (#145).
    h2_pool: ?*http.upstream_h2.H2ConnPool,
) !StreamingProxyResult {
    if (cancelStopped(cancel_token)) return error.RequestCancelled;

    const proxy_extra_header_slack = 10;
    const uri = try std.Uri.parse(url);
    // A Unix-socket upstream is always plain HTTP/1.1 over the socket: the
    // resolved URL is a synthetic http://localhost target that only carries the
    // request line and Host header.
    const is_https = unix_socket_path == null and std.ascii.eqlIgnoreCase(uri.scheme, "https");
    const host = if (uri.host) |h| uriComponentBytes(h) else return error.UpstreamProtocolError;
    const port: u16 = uri.port orelse (if (is_https) @as(u16, 443) else 80);
    const tls_options: ?http.tls_termination.UpstreamTlsOptions = if (is_https) .{
        .skip_verify = !cfg.upstream_tls_verify,
        .ca_bundle_path = cfg.upstream_tls_ca_bundle,
        .sni_override = cfg.upstream_tls_server_name,
        .client_cert_path = cfg.upstream_tls_client_cert,
        .client_key_path = cfg.upstream_tls_client_key,
        // Must match the buffered path: without this the policy defaults to
        // `require_http1`, so a TLS origin is only ever offered `http/1.1` and
        // `streamViaH2Pool` can never negotiate h2 no matter how
        // `TARDIGRADE_UPSTREAM_PROTOCOL` is set.
        .alpn_policy = upstreamAlpnPolicy(cfg.upstream_protocol),
    } else null;

    // Per-phase deadlines (closes the #196 streaming gap): bound the connect/
    // write phase and each response read; the read deadline bounds a hung
    // upstream stalling mid-stream.
    const connect_timeout_ms: u32 = if (cfg.upstream_connect_timeout_ms > 0) cfg.upstream_connect_timeout_ms else cfg.upstream_timeout_ms;
    const base_read_ms: u32 = if (cfg.upstream_response_timeout_ms > 0) cfg.upstream_response_timeout_ms else cfg.upstream_timeout_ms;
    const read_deadline_ms: u32 = if (cancel_token) |tok| tok.effectiveTimeoutMs(base_read_ms) else base_read_ms;

    var forwarded_for = try buildForwardedFor(allocator, request_headers.get("x-forwarded-for"), client_ip);
    defer forwarded_for.deinit(allocator);
    var extra_headers_stack = std.heap.stackFallback(2048, allocator);
    const extra_headers_allocator = extra_headers_stack.get();
    var extra_headers = std.array_list.Managed(std.http.Header).init(extra_headers_allocator);
    defer extra_headers.deinit();
    try extra_headers.ensureUnusedCapacity(request_headers.count() + proxy_extra_header_slack);
    try gph.appendProxyRequestHeaders(&extra_headers, request_headers);
    try gph.appendRequestIdHeaders(&extra_headers, correlation_id);
    try extra_headers.append(.{ .name = "X-Forwarded-For", .value = forwarded_for.value });
    try extra_headers.append(.{ .name = "X-Real-IP", .value = client_ip });
    try extra_headers.append(.{ .name = "X-Forwarded-Proto", .value = forwarded_proto });
    if (incoming_host) |value| {
        const trimmed = std.mem.trim(u8, value, " \t\r\n");
        if (trimmed.len > 0) try extra_headers.append(.{ .name = "X-Forwarded-Host", .value = trimmed });
    }
    try gph.appendAssertedIdentityHeaders(&extra_headers, auth_identity, auth_user_id, auth_device_id, auth_scopes);
    var traceparent_buf: [55]u8 = undefined;
    if (request_headers.get("traceparent") == null) {
        const tc = http.trace_context.generate();
        const tp = tc.format(&traceparent_buf);
        if (tp.len > 0) try extra_headers.append(.{ .name = "traceparent", .value = tp });
    }

    const read_buf = try allocator.alloc(u8, @max(cfg.proxy_stream_buffer_size, 16 * 1024));
    defer allocator.free(read_buf);

    // HTTP/2 upstream (#145/#301): multiplex the streaming exchange over the
    // shared per-origin h2 connection when configured — via ALPN for HTTPS (h1
    // origins fall back inside) or prior-knowledge h2c for plain HTTP when
    // explicitly opted in (#237).
    // A Unix-socket upstream has no origin the h2 pool can key or ALPN-negotiate,
    // so it always uses the HTTP/1.1 relay below.
    const h2_requested_for_streaming = if (is_https) cfg.upstream_protocol.offersH2() else cfg.upstream_protocol.h2cPriorKnowledge();
    const stream_h2 = unix_socket_path == null and h2_requested_for_streaming;
    if (stream_h2) {
        if (h2_pool) |hp| {
            const h2_opts: ?http.tls_termination.UpstreamTlsOptions = if (is_https) tls_options.? else null;
            return streamViaH2Pool(allocator, hp, pool, host, port, h2_opts, uri, method, extra_headers.items, buffered_body, streaming_body, read_buf, downstream_conn, downstream_writer, security, alt_svc, sticky_set_cookie, correlation_id, connect_timeout_ms, read_deadline_ms, cancel_token, cfg.proxy_buffer_limits, proxy_buffer_observer, proxy_buffer_global);
        }
        if (streaming_body != null) {
            if (pool) |p| p.recordH2StreamingUploadFallback();
        }
    }
    // Everything below runs HTTP/1.1 (counted per request, not per attempt).
    if (pool) |p| p.recordProtocol(false);

    const active_pool: ?*http.upstream_pool.UpstreamPool = if (pool) |p| (if (p.config.enabled) p else null) else null;
    var key_buf: [512]u8 = undefined;
    const key = if (unix_socket_path) |socket_path|
        std.fmt.bufPrint(&key_buf, "unix:{s}", .{socket_path}) catch socket_path
    else
        std.fmt.bufPrint(&key_buf, "{s}:{s}:{d}", .{ if (is_https) "https" else "http", host, port }) catch host;

    // Aggregate capacity for this connection's relay buffers, in both
    // directions (#140). A fixed relay buffer bounds one request, but nothing
    // bounds how many requests an origin has in flight, so the per-origin scope
    // is what stops one slow origin from multiplying its own relay memory.
    //
    // Looked up on `pool` rather than `active_pool`: the account exists to
    // bound memory, which is just as true when connection pooling is disabled.
    // A lookup failure means the accounting itself is unavailable (allocation
    // failure) — precisely when these limits matter most — so it is a
    // deterministic pre-commit refusal rather than a silently unaccounted
    // request.
    const h1_origin_buffer_account: ?*proxy_buffer_account.Aggregate = if (pool) |p|
        p.originBufferAccount(key) catch return error.ProxyBufferCapacityUnavailable
    else
        null;
    const h1_buffer_capacity = proxy_buffer_account.AggregateCapacity{
        .origin = h1_origin_buffer_account,
        .global = proxy_buffer_global,
    };

    // A dead reused connection can only be retried before any response byte
    // reaches the client, and only when the request body is re-sendable (a
    // streamed upload has already consumed the client).
    const retry_allowed = streaming_body == null;
    var attempt: usize = 0;
    while (true) : (attempt += 1) {
        const now_ms = http.event_loop.monotonicMs();

        // Acquire a connection: pooled (attempt 0) or freshly connected. The
        // checkout/reserveSlot reserves an active slot before connecting so the
        // per-origin cap (#239) is a real hard cap; failed connects release it.
        var reused = false;
        var conn: http.upstream_pool.PooledConn = undefined;
        if (active_pool) |p| {
            if (attempt == 0) {
                if (try p.checkout(key, now_ms)) |c| {
                    conn = c;
                    reused = true;
                }
            } else {
                try p.reserveSlot(key); // stale retry: deliberately fresh, still capped
            }
        }
        if (!reused) {
            const connect_start = http.event_loop.monotonicMs();
            const new_fd = (if (unix_socket_path) |socket_path|
                compat.connectBoundedUnix(socket_path, connect_timeout_ms)
            else
                compat.connectBoundedTcp(host, port, connect_timeout_ms)) catch |err| {
                if (active_pool) |p| p.releaseSlot(key);
                return err;
            };
            if (active_pool) |p| p.recordConnectLatency(http.event_loop.monotonicMs() - connect_start);
            if (tls_options) |opts| {
                if (connect_timeout_ms > 0) setSocketTimeoutMs(new_fd, connect_timeout_ms, connect_timeout_ms) catch {};
                const owner = if (active_pool) |p| p.allocator else allocator;
                const tls_ptr = owner.create(http.tls_termination.UpstreamTlsConn) catch {
                    _ = std.c.close(new_fd);
                    if (active_pool) |p| p.releaseSlot(key);
                    return error.OutOfMemory;
                };
                tls_ptr.* = http.tls_termination.UpstreamTlsConn.connect(new_fd, host, opts) catch |err| {
                    owner.destroy(tls_ptr);
                    _ = std.c.close(new_fd);
                    if (active_pool) |p| p.releaseSlot(key);
                    return err;
                };
                if (active_pool) |p| p.noteNewConnection(key);
                conn = .{ .stream = compat.netStreamFromFd(new_fd), .tls = tls_ptr, .created_ms = now_ms, .last_used_ms = now_ms };
            } else {
                if (active_pool) |p| p.noteNewConnection(key);
                conn = .{ .stream = compat.netStreamFromFd(new_fd), .tls = null, .created_ms = now_ms, .last_used_ms = now_ms };
            }
        }

        var wrote_downstream = false;
        const exchange_start_ms = http.event_loop.monotonicMs();
        const fd = conn.stream.handle;
        const res = (if (conn.tls) |tls|
            streamProxyOverTransport(allocator, tls, fd, read_buf, uri, method, extra_headers.items, buffered_body, streaming_body, downstream_conn, downstream_writer, security, alt_svc, sticky_set_cookie, correlation_id, connect_timeout_ms, read_deadline_ms, cancel_token, &wrote_downstream, cfg.proxy_buffer_limits, proxy_buffer_observer, h1_buffer_capacity)
        else
            streamProxyOverTransport(allocator, compat.netStreamFromFd(fd), fd, read_buf, uri, method, extra_headers.items, buffered_body, streaming_body, downstream_conn, downstream_writer, security, alt_svc, sticky_set_cookie, correlation_id, connect_timeout_ms, read_deadline_ms, cancel_token, &wrote_downstream, cfg.proxy_buffer_limits, proxy_buffer_observer, h1_buffer_capacity)) catch |err| {
            // Tear down the connection (release handles active-- and close).
            if (active_pool) |p| {
                p.release(key, conn, false, http.event_loop.monotonicMs());
            } else {
                if (conn.tls) |t| {
                    t.deinit();
                    allocator.destroy(t);
                }
                var s = conn.stream;
                s.close();
            }
            if (!wrote_downstream and reused and retry_allowed and attempt == 0 and
                (err == error.UpstreamConnectionClosed or err == error.WriteFailed))
            {
                if (active_pool) |p| p.recordStaleRetry(key);
                continue;
            }
            return err;
        };

        // Success: pool the connection when reusable, else close it.
        if (active_pool) |p| {
            p.release(key, conn, res.reusable, http.event_loop.monotonicMs());
        } else {
            if (conn.tls) |t| {
                t.deinit();
                allocator.destroy(t);
            }
            var s = conn.stream;
            s.close();
        }
        if (pool) |p| p.recordRequestLatency(false, http.event_loop.monotonicMs() - exchange_start_ms);
        return res.result;
    }
}

pub fn upstreamResponseHasNoStore(response: std.http.Client.Response.Head) bool {
    var it = response.iterateHeaders();
    while (it.next()) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "cache-control")) continue;
        var tokens = std.mem.splitScalar(u8, header.value, ',');
        while (tokens.next()) |token_raw| {
            const token = std.mem.trim(u8, token_raw, " \t\r\n");
            if (std.ascii.eqlIgnoreCase(token, "no-store")) return true;
        }
    }
    return false;
}

pub const UpstreamMappedError = struct {
    status: u16,
    code: []const u8,
    message: []const u8,
};

pub const ProxyExecMappedError = struct {
    status: http.Status,
    code: []const u8,
    message: []const u8,
};

pub fn mapUpstreamError(status: u16) UpstreamMappedError {
    return switch (status) {
        401 => .{ .status = 401, .code = "unauthorized", .message = "Unauthorized" },
        429 => .{ .status = 429, .code = "rate_limited", .message = "Rate limited" },
        502, 503 => .{ .status = 503, .code = "tool_unavailable", .message = "Upstream unavailable" },
        504 => .{ .status = 504, .code = "upstream_timeout", .message = "Upstream timeout" },
        else => .{ .status = 500, .code = "internal_error", .message = "Internal error" },
    };
}

/// Intentionally takes `anyerror`: proxy execution surfaces a heterogeneous set
/// (the specific upstream errors below, plus allocator and compat socket I/O
/// errors that are themselves `anyerror` until the I/O boundary is narrowed in
/// #211). The `else` arm maps everything unrecognized to a safe gateway-timeout.
pub fn mapControlPlaneProxyExecutionError(err: anyerror) ProxyExecMappedError {
    return switch (err) {
        error.UpstreamUntrusted => .{
            .status = .service_unavailable,
            .code = "upstream_untrusted",
            .message = "Untrusted upstream response",
        },
        error.Timeout => .{
            .status = .gateway_timeout,
            .code = "upstream_timeout",
            .message = "Upstream timeout",
        },
        error.UpstreamAtCapacity => .{
            .status = .service_unavailable,
            .code = "upstream_saturated",
            .message = "Upstream connection limit reached",
        },
        else => .{
            .status = .gateway_timeout,
            .code = "upstream_timeout",
            .message = "Upstream timeout",
        },
    };
}

test "mapUpstreamError returns stable codes" {
    const mapped = mapUpstreamError(502);
    try std.testing.expectEqual(@as(u16, 503), mapped.status);
    try std.testing.expectEqualStrings("tool_unavailable", mapped.code);
}

// --- Malformed upstream response handling tests ---

test "parseBufferedUpstreamResponse handles response with no body" {
    // The parser requires at least one header line so that headers_raw contains
    // a newline (from which the status-line boundary is found).
    var parsed = try parseBufferedUpstreamResponse(
        std.testing.allocator,
        "HTTP/1.1 204 No Content\r\nX-Accel-Buffering: no\r\n\r\n",
    );
    defer parsed.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u16, 204), parsed.status_code);
    try std.testing.expectEqualStrings("No Content", parsed.reason);
    try std.testing.expectEqualStrings("", parsed.body);
    try std.testing.expectEqualStrings("no", parsed.headerValue("X-Accel-Buffering").?);
}

test "parseBufferedUpstreamResponse strips hop-by-hop headers from upstream 5xx responses" {
    var parsed = try parseBufferedUpstreamResponse(
        std.testing.allocator,
        "HTTP/1.1 502 Bad Gateway\r\n" ++
            "Connection: close\r\n" ++
            "Transfer-Encoding: chunked\r\n" ++
            "Server: nginx/1.24.0\r\n" ++
            "X-Powered-By: PHP/8.1\r\n" ++
            "Content-Type: text/plain\r\n" ++
            "\r\n" ++
            "error",
    );
    defer parsed.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u16, 502), parsed.status_code);
    try std.testing.expect(parsed.headerValue("connection") == null);
    try std.testing.expect(parsed.headerValue("transfer-encoding") == null);
    try std.testing.expect(parsed.headerValue("server") == null);
    try std.testing.expect(parsed.headerValue("x-powered-by") == null);
    try std.testing.expectEqualStrings("text/plain", parsed.headerValue("content-type").?);
}

test "parseBufferedUpstreamResponse strips Content-Length from upstream (Tardigrade recalculates)" {
    var parsed = try parseBufferedUpstreamResponse(
        std.testing.allocator,
        "HTTP/1.1 200 OK\r\n" ++
            "Content-Length: 5\r\n" ++
            "Content-Type: text/plain\r\n" ++
            "\r\n" ++
            "hello",
    );
    defer parsed.deinit(std.testing.allocator);
    try std.testing.expect(parsed.headerValue("content-length") == null);
    try std.testing.expectEqualStrings("text/plain", parsed.headerValue("content-type").?);
    try std.testing.expectEqualStrings("hello", parsed.body);
}

test "parseBufferedUpstreamResponse handles upstream with missing reason phrase" {
    var parsed = try parseBufferedUpstreamResponse(
        std.testing.allocator,
        "HTTP/1.1 200 \r\nContent-Type: text/plain\r\n\r\nbody",
    );
    defer parsed.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u16, 200), parsed.status_code);
    try std.testing.expectEqualStrings("body", parsed.body);
}

test "parseBufferedUpstreamResponse errors on empty response" {
    try std.testing.expectError(
        error.UpstreamProtocolError,
        parseBufferedUpstreamResponse(std.testing.allocator, ""),
    );
}

test "parseBufferedUpstreamResponse errors on truncated status line" {
    try std.testing.expectError(
        error.UpstreamProtocolError,
        parseBufferedUpstreamResponse(std.testing.allocator, "HTTP/1.1 200"),
    );
}

test "parseBufferedUpstreamResponse errors when header block is never terminated" {
    try std.testing.expectError(
        error.UpstreamProtocolError,
        parseBufferedUpstreamResponse(
            std.testing.allocator,
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n",
        ),
    );
}

// ---------------------------------------------------------------------------
// Bounded transport exchange + timeout enforcement (issue #196)
// ---------------------------------------------------------------------------
//
// These tests drive exchangeBoundedBufferedHttpRequest over a blocking
// socketpair: deterministic, no event loop, no threads. They cover the two
// behaviors the std.http.Client path could not provide: a correct buffered
// request/response exchange, and a bounded response read that returns an error
// (rather than blocking forever) when the peer never replies.

fn makeBlockingSocketpair() ![2]std.posix.fd_t {
    var fds: [2]std.posix.fd_t = undefined;
    if (std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds) != 0) {
        return error.SocketPairFailed;
    }
    return fds;
}

test "exchangeBoundedBufferedHttpRequest parses a buffered response from a peer" {
    const allocator = std.testing.allocator;
    const fds = try makeBlockingSocketpair();
    const client_fd = fds[0];
    const peer_fd = fds[1];
    defer _ = std.c.close(client_fd);
    defer _ = std.c.close(peer_fd);

    // Pre-load the peer's response, then shut its write side so the client read
    // loop sees EOF once the response is drained.
    const response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nhello";
    _ = std.c.write(peer_fd, response.ptr, response.len);
    _ = std.c.shutdown(peer_fd, std.posix.SHUT.WR);

    const uri = try std.Uri.parse("http://localhost/");
    var resp = try exchangeBoundedBufferedHttpRequest(
        allocator,
        compat.netStreamFromFd(client_fd),
        client_fd,
        uri,
        "GET",
        &.{},
        "",
        null,
        1 << 20,
        1_000,
        1_000,
        false,
        null,
    );
    defer resp.deinit(allocator);

    try std.testing.expectEqual(@as(u16, 200), resp.status_code);
    try std.testing.expectEqualStrings("hello", resp.body);
    try std.testing.expectEqualStrings("text/plain", resp.headerValue("content-type").?);

    // The serialized request is readable from the peer end, Connection: close
    // and a derived Host header included.
    var req_buf: [512]u8 = undefined;
    const n = std.c.read(peer_fd, &req_buf, req_buf.len);
    try std.testing.expect(n > 0);
    const req = req_buf[0..@intCast(n)];
    try std.testing.expect(std.mem.startsWith(u8, req, "GET / HTTP/1.1\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, req, "Connection: close\r\n") != null);
}

/// Run one buffered exchange against a socketpair peer and return the request
/// bytes the client serialized (caller owns the returned slice).
fn captureBufferedRequestBytes(allocator: std.mem.Allocator, url: []const u8) ![]u8 {
    const fds = try makeBlockingSocketpair();
    const client_fd = fds[0];
    const peer_fd = fds[1];
    defer _ = std.c.close(client_fd);
    defer _ = std.c.close(peer_fd);

    const response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    _ = std.c.write(peer_fd, response.ptr, response.len);
    _ = std.c.shutdown(peer_fd, std.posix.SHUT.WR);

    const uri = try std.Uri.parse(url);
    var resp = try exchangeBoundedBufferedHttpRequest(
        allocator,
        compat.netStreamFromFd(client_fd),
        client_fd,
        uri,
        "GET",
        &.{},
        "",
        null,
        1 << 20,
        1_000,
        1_000,
        false,
        null,
    );
    resp.deinit(allocator);

    var req_buf: [512]u8 = undefined;
    const n = std.c.read(peer_fd, &req_buf, req_buf.len);
    try std.testing.expect(n > 0);
    return allocator.dupe(u8, req_buf[0..@intCast(n)]);
}

test "buffered request Host header includes a non-default upstream port" {
    const allocator = std.testing.allocator;
    const req = try captureBufferedRequestBytes(allocator, "http://127.0.0.1:8123/");
    defer allocator.free(req);
    try std.testing.expect(std.mem.indexOf(u8, req, "Host: 127.0.0.1:8123\r\n") != null);
}

test "buffered request Host header omits a default upstream port" {
    const allocator = std.testing.allocator;
    // Explicit default port (80) must not be echoed into the Host header.
    const req = try captureBufferedRequestBytes(allocator, "http://127.0.0.1:80/");
    defer allocator.free(req);
    try std.testing.expect(std.mem.indexOf(u8, req, "Host: 127.0.0.1\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, req, "127.0.0.1:80") == null);
}

test "exchangeBoundedBufferedHttpRequest enforces the response read timeout when the peer never replies" {
    const allocator = std.testing.allocator;
    const fds = try makeBlockingSocketpair();
    const client_fd = fds[0];
    const peer_fd = fds[1];
    defer _ = std.c.close(client_fd);
    defer _ = std.c.close(peer_fd);

    // The peer accepts the request bytes but never writes a response and never
    // closes. Without per-phase timeouts the client read would block forever;
    // the 200ms response timeout must surface an error instead.
    const uri = try std.Uri.parse("http://localhost/");
    const start_ms = http.event_loop.monotonicMs();
    const result = exchangeBoundedBufferedHttpRequest(
        allocator,
        compat.netStreamFromFd(client_fd),
        client_fd,
        uri,
        "GET",
        &.{},
        "",
        null,
        1 << 20,
        1_000, // send timeout: generous
        200, // response timeout: short — this must fire on the silent peer
        false,
        null,
    );
    const elapsed_ms = http.event_loop.monotonicMs() - start_ms;

    if (result) |resp_val| {
        var resp = resp_val;
        resp.deinit(allocator);
        return error.TestUnexpectedResult; // a silent peer must not yield a response
    } else |_| {}

    // Returned via the 200ms poll deadline, with generous slack for scheduler
    // noise on busy CI hosts.
    try std.testing.expect(elapsed_ms >= 150);
    try std.testing.expect(elapsed_ms < 5_000);
}

/// Run an exchange against a peer that has pre-written `response` and then keeps
/// the socket open (never closes) — simulating a keep-alive HTTP/1.1 upstream
/// that frames its body with Content-Length/chunked. With a generous response
/// timeout, a framing-unaware reader would block until the deadline; a correct
/// one returns as soon as the framed body is complete.
fn exchangeAgainstKeepAlivePeer(allocator: std.mem.Allocator, method: []const u8, response: []const u8) !BufferedUpstreamResponse {
    const fds = try makeBlockingSocketpair();
    const client_fd = fds[0];
    const peer_fd = fds[1];
    defer _ = std.c.close(client_fd);
    defer _ = std.c.close(peer_fd);

    _ = std.c.write(peer_fd, response.ptr, response.len);
    // Deliberately do NOT close peer_fd — the body boundary must come from
    // framing, not EOF.
    const uri = try std.Uri.parse("http://localhost/");
    return exchangeBoundedBufferedHttpRequest(
        allocator,
        compat.netStreamFromFd(client_fd),
        client_fd,
        uri,
        method,
        &.{},
        "",
        null,
        1 << 20,
        1_000,
        1_000,
        false,
        null,
    );
}

test "exchange stops at Content-Length on a keep-alive upstream (issue #196 regression)" {
    const allocator = std.testing.allocator;
    var resp = try exchangeAgainstKeepAlivePeer(
        allocator,
        "GET",
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\nhello",
    );
    defer resp.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), resp.status_code);
    try std.testing.expectEqualStrings("hello", resp.body);
}

test "exchange decodes a chunked body on a keep-alive upstream" {
    const allocator = std.testing.allocator;
    var resp = try exchangeAgainstKeepAlivePeer(
        allocator,
        "GET",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
    );
    defer resp.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), resp.status_code);
    try std.testing.expectEqualStrings("hello world", resp.body);
}

test "exchange treats 204 as bodiless on a keep-alive upstream" {
    const allocator = std.testing.allocator;
    var resp = try exchangeAgainstKeepAlivePeer(
        allocator,
        "GET",
        "HTTP/1.1 204 No Content\r\nConnection: keep-alive\r\n\r\n",
    );
    defer resp.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), resp.status_code);
    try std.testing.expectEqual(@as(usize, 0), resp.body.len);
}

test "exchange treats a HEAD response as bodiless despite Content-Length" {
    const allocator = std.testing.allocator;
    var resp = try exchangeAgainstKeepAlivePeer(
        allocator,
        "HEAD",
        "HTTP/1.1 200 OK\r\nContent-Length: 99\r\nConnection: keep-alive\r\n\r\n",
    );
    defer resp.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), resp.status_code);
    try std.testing.expectEqual(@as(usize, 0), resp.body.len);
}

/// A capturing downstream writer for the streaming-relay tests: satisfies the
/// `print`/`writeAll` interface `writeChunk` needs and records all bytes.
const CaptureWriter = struct {
    list: *std.array_list.Managed(u8),
    pub fn writeAll(self: CaptureWriter, bytes: []const u8) !void {
        try self.list.appendSlice(bytes);
    }
    pub fn print(self: CaptureWriter, comptime fmt: []const u8, args: anytype) !void {
        var buf: [64]u8 = undefined;
        try self.list.appendSlice(try std.fmt.bufPrint(&buf, fmt, args));
    }
};

/// Drive readUpstreamHead + relayUpstreamBody over a socketpair preloaded with
/// `response`. Returns the parsed head and the de-chunked relayed body. The peer
/// stays open (length/chunked) unless `close_after` shuts it for close-framing.
fn runStreamingRelay(
    allocator: std.mem.Allocator,
    method: []const u8,
    response: []const u8,
    close_after: bool,
    out_body: *std.array_list.Managed(u8),
) !struct { status: u16, framing_tag: []const u8, reusable: bool, aborted: bool, body_len: usize } {
    const fds = try makeBlockingSocketpair();
    const client_fd = fds[0];
    const peer_fd = fds[1];
    defer _ = std.c.close(client_fd);
    defer _ = std.c.close(peer_fd);
    _ = std.c.write(peer_fd, response.ptr, response.len);
    if (close_after) _ = std.c.shutdown(peer_fd, std.posix.SHUT.WR);

    var read_storage: [4096]u8 = undefined;
    var rb = StreamReadBuf{ .buf = &read_storage };
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const transport = compat.netStreamFromFd(client_fd);

    const head = try readUpstreamHead(arena.allocator(), &rb, transport, client_fd, 1_000, method);

    var captured = std.array_list.Managed(u8).init(allocator);
    defer captured.deinit();
    const writer = CaptureWriter{ .list = &captured };
    const outcome = try relayUpstreamBody(&rb, transport, client_fd, 1_000, head.framing, writer, null);

    // De-chunk the captured downstream stream (relay does not emit the
    // terminating zero chunk; append it so decodeChunkedBody can parse).
    try captured.appendSlice("0\r\n\r\n");
    if (try decodeChunkedBody(allocator, captured.items, 1 << 20)) |decoded| {
        defer allocator.free(decoded);
        try out_body.appendSlice(decoded);
    }
    const tag = switch (head.framing) {
        .none => "none",
        .length => "length",
        .chunked => "chunked",
        .close => "close",
    };
    return .{ .status = head.status_code, .framing_tag = tag, .reusable = outcome.reusable, .aborted = outcome.aborted, .body_len = outcome.body_bytes };
}

test "streaming relay streams a Content-Length body and keeps the connection reusable" {
    const allocator = std.testing.allocator;
    var body = std.array_list.Managed(u8).init(allocator);
    defer body.deinit();
    const r = try runStreamingRelay(allocator, "GET", "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello world", false, &body);
    try std.testing.expectEqual(@as(u16, 200), r.status);
    try std.testing.expectEqualStrings("length", r.framing_tag);
    try std.testing.expectEqualStrings("hello world", body.items);
    try std.testing.expect(r.reusable and !r.aborted);
}

test "streaming relay decodes a chunked body and stays reusable" {
    const allocator = std.testing.allocator;
    var body = std.array_list.Managed(u8).init(allocator);
    defer body.deinit();
    const r = try runStreamingRelay(allocator, "GET", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n", false, &body);
    try std.testing.expectEqualStrings("chunked", r.framing_tag);
    try std.testing.expectEqualStrings("hello world", body.items);
    try std.testing.expect(r.reusable and !r.aborted);
}

test "streaming relay handles a close-delimited body (not reusable)" {
    const allocator = std.testing.allocator;
    var body = std.array_list.Managed(u8).init(allocator);
    defer body.deinit();
    const r = try runStreamingRelay(allocator, "GET", "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nstreamed-to-eof", true, &body);
    try std.testing.expectEqualStrings("close", r.framing_tag);
    try std.testing.expectEqualStrings("streamed-to-eof", body.items);
    try std.testing.expect(!r.reusable and !r.aborted);
}

test "streaming relay treats 204 as bodiless" {
    const allocator = std.testing.allocator;
    var body = std.array_list.Managed(u8).init(allocator);
    defer body.deinit();
    const r = try runStreamingRelay(allocator, "GET", "HTTP/1.1 204 No Content\r\n\r\n", false, &body);
    try std.testing.expectEqual(@as(u16, 204), r.status);
    try std.testing.expectEqualStrings("none", r.framing_tag);
    try std.testing.expectEqual(@as(usize, 0), body.items.len);
    try std.testing.expect(r.reusable);
}

test "streaming relay reports abort on a truncated Content-Length body" {
    const allocator = std.testing.allocator;
    var body = std.array_list.Managed(u8).init(allocator);
    defer body.deinit();
    // Promises 20 bytes but only sends 5, then closes.
    const r = try runStreamingRelay(allocator, "GET", "HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\nhello", true, &body);
    try std.testing.expect(r.aborted and !r.reusable);
    try std.testing.expectEqual(@as(usize, 5), r.body_len);
}

test "streaming relay refuses reuse when bytes trail a Content-Length body" {
    const allocator = std.testing.allocator;
    var body = std.array_list.Managed(u8).init(allocator);
    defer body.deinit();
    // 5-byte body, but "EXTRA" remains buffered past the body boundary.
    const r = try runStreamingRelay(allocator, "GET", "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloEXTRA", false, &body);
    try std.testing.expectEqualStrings("hello", body.items);
    try std.testing.expect(!r.aborted);
    try std.testing.expect(!r.reusable); // socket out of sync — must not be pooled
}

test "streaming relay refuses reuse when bytes trail a 204 head" {
    const allocator = std.testing.allocator;
    var body = std.array_list.Managed(u8).init(allocator);
    defer body.deinit();
    const r = try runStreamingRelay(allocator, "GET", "HTTP/1.1 204 No Content\r\n\r\nEXTRA", false, &body);
    try std.testing.expectEqual(@as(u16, 204), r.status);
    try std.testing.expectEqual(@as(usize, 0), body.items.len);
    try std.testing.expect(!r.reusable);
}

test "streaming relay refuses reuse when bytes trail a chunked body" {
    const allocator = std.testing.allocator;
    var body = std.array_list.Managed(u8).init(allocator);
    defer body.deinit();
    // Complete chunked body + trailer, then a stray "EXTRA" past the terminator.
    const r = try runStreamingRelay(allocator, "GET", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\nEXTRA", false, &body);
    try std.testing.expectEqualStrings("hello", body.items);
    try std.testing.expect(!r.aborted);
    try std.testing.expect(!r.reusable);
}

test "streaming relay rejects a chunk not terminated by CRLF" {
    const allocator = std.testing.allocator;
    var body = std.array_list.Managed(u8).init(allocator);
    defer body.deinit();
    // Chunk data "hello" is followed by "XX" instead of CRLF.
    try std.testing.expectError(error.UpstreamProtocolError, runStreamingRelay(
        allocator,
        "GET",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhelloXX0\r\n\r\n",
        false,
        &body,
    ));
}

// ---------------------------------------------------------------------------
// Request-direction buffer accounting and HTTP/1 stall observability (#140).
// ---------------------------------------------------------------------------

/// Records everything the request-direction relays report, so a test can assert
/// both the transitions and that every gauge returns to zero at teardown.
const UploadBufferObserver = struct {
    reserved: usize = 0,
    peak_reserved: usize = 0,
    retained: usize = 0,
    pauses: u64 = 0,
    resumes: u64 = 0,
    stream_limit_exceeded: u64 = 0,
    aggregate_limit_exceeded: u64 = 0,
    last_aggregate_scope: ?proxy_buffer_account.Scope = null,

    fn observer(self: *UploadBufferObserver) proxy_buffer_account.Observer {
        return .{
            .context = self,
            .recordReservationFn = recordReservation,
            .releaseReservationFn = releaseReservation,
            .recordAggregateLimitExceededFn = recordAggregateLimitExceeded,
            .recordReadPauseFn = recordReadPause,
            .recordReadResumeFn = recordReadResume,
            .recordRetainedBytesFn = recordRetained,
            .releaseRetainedBytesFn = releaseRetained,
        };
    }

    fn recordReservation(
        context: *anyopaque,
        _: proxy_buffer_account.Direction,
        bytes: usize,
        _: bool,
        limit_exceeded: bool,
    ) void {
        const self: *UploadBufferObserver = @ptrCast(@alignCast(context));
        if (limit_exceeded) self.stream_limit_exceeded += 1;
        self.reserved += bytes;
        self.peak_reserved = @max(self.peak_reserved, self.reserved);
    }

    fn releaseReservation(context: *anyopaque, _: proxy_buffer_account.Direction, bytes: usize) void {
        const self: *UploadBufferObserver = @ptrCast(@alignCast(context));
        self.reserved -= bytes;
    }

    fn recordAggregateLimitExceeded(
        context: *anyopaque,
        _: proxy_buffer_account.Direction,
        scope: proxy_buffer_account.Scope,
    ) void {
        const self: *UploadBufferObserver = @ptrCast(@alignCast(context));
        self.aggregate_limit_exceeded += 1;
        self.last_aggregate_scope = scope;
    }

    fn recordReadPause(context: *anyopaque, _: proxy_buffer_account.Side) void {
        const self: *UploadBufferObserver = @ptrCast(@alignCast(context));
        self.pauses += 1;
    }

    fn recordReadResume(context: *anyopaque, _: proxy_buffer_account.Side) void {
        const self: *UploadBufferObserver = @ptrCast(@alignCast(context));
        self.resumes += 1;
    }

    fn recordRetained(context: *anyopaque, _: proxy_buffer_account.Direction, bytes: usize) void {
        const self: *UploadBufferObserver = @ptrCast(@alignCast(context));
        self.retained += bytes;
    }

    fn releaseRetained(context: *anyopaque, _: proxy_buffer_account.Direction, bytes: usize) void {
        const self: *UploadBufferObserver = @ptrCast(@alignCast(context));
        self.retained -= bytes;
    }
};

/// A client upload served from memory. `abort_after` makes the read fail once
/// that many bytes have been handed over, standing in for a client that
/// disappears mid-upload.
const FakeUploadSource = struct {
    data: []const u8,
    pos: usize = 0,
    abort_after: ?usize = null,

    pub fn read(self: *FakeUploadSource, buf: []u8) !usize {
        if (self.abort_after) |limit| {
            if (self.pos >= limit) return error.ConnectionResetByPeer;
        }
        const take = @min(buf.len, self.data.len - self.pos);
        @memcpy(buf[0..take], self.data[self.pos..][0..take]);
        self.pos += take;
        return take;
    }
};

fn uploadTestLimits(hard: usize) proxy_buffer_account.Limits {
    return .{
        .per_stream_low_watermark = hard / 4,
        .per_stream_high_watermark = hard / 2,
        .per_stream_hard_limit = hard,
        .per_origin_hard_limit = 0,
        .global_hard_limit = 0,
    };
}

/// Preflight then relay, in the order `sendStreamingProxyRequest` does, so
/// tests exercise the same reservation lifetime production uses.
fn runHttp1Upload(
    transport: anytype,
    fd: std.posix.fd_t,
    sb: StreamingRequestBody,
    downstream_conn: anytype,
    limits: proxy_buffer_account.Limits,
    observer: proxy_buffer_account.Observer,
    capacity: proxy_buffer_account.AggregateCapacity,
) !void {
    var reservation = try preflightUploadReservation(
        limits,
        observer,
        capacity,
        http1_upload_relay_bytes,
        uploadInitialBytesFootprint(sb),
    );
    defer reservation.releaseAll();
    try relayStreamingUploadToHttp1(transport, fd, sb, downstream_conn, null, &reservation, observer);
}

/// The HTTP/2 mirror of `runHttp1Upload`.
fn runHttp2Upload(
    conn: anytype,
    stream: anytype,
    sb: StreamingRequestBody,
    read_buf: []u8,
    downstream_conn: anytype,
    limits: proxy_buffer_account.Limits,
    observer: proxy_buffer_account.Observer,
    capacity: proxy_buffer_account.AggregateCapacity,
) !void {
    var reservation = try preflightUploadReservation(
        limits,
        observer,
        capacity,
        read_buf.len,
        uploadInitialBytesFootprint(sb),
    );
    defer reservation.releaseAll();
    try relayStreamingUploadToHttp2(conn, stream, sb, read_buf, downstream_conn, null, &reservation);
}

/// Drain `total` bytes from `fd` after `delay_ms`. The delay is what lets the
/// relay observe an origin that has stopped consuming.
fn slowUploadDrain(fd: std.posix.fd_t, delay_ms: u64, total: usize) void {
    // A bare `poll` with no descriptors, not `std.Io.sleep`: this runs on a raw
    // spawned thread with no Io context, and a sleep that silently no-ops would
    // let the drain keep pace with the relay so the stall under test would
    // never happen.
    var no_fds: [0]std.posix.pollfd = .{};
    _ = std.posix.poll(&no_fds, @intCast(delay_ms)) catch {};
    var buf: [4096]u8 = undefined;
    var drained: usize = 0;
    while (drained < total) {
        const n = std.c.read(fd, &buf, buf.len);
        if (n <= 0) return;
        drained += @intCast(n);
    }
}

/// Write into `fd` until it will not take another byte, and report how much
/// went in. Non-blocking for the duration, so a partially free send buffer
/// cannot park the caller with nobody draining. This is what makes a stall a
/// fact of the socket's state at the moment the relay looks at it, rather than
/// a race against a background reader.
fn fillSocketSendBuffer(fd: std.posix.fd_t) !usize {
    const flags = std.c.fcntl(fd, std.posix.F.GETFL, @as(c_int, 0));
    if (flags < 0) return error.SocketFillFailed;
    const nonblock: c_int = @bitCast(@as(u32, @bitCast(std.posix.O{ .NONBLOCK = true })));
    if (std.c.fcntl(fd, std.posix.F.SETFL, flags | nonblock) < 0) return error.SocketFillFailed;
    defer _ = std.c.fcntl(fd, std.posix.F.SETFL, flags);

    const chunk = [_]u8{'p'} ** 1024;
    var written: usize = 0;
    // Bounded: a platform that never reports a full buffer must fail the test,
    // not spin here forever.
    while (written < 8 * 1024 * 1024) {
        const n = std.c.write(fd, &chunk, chunk.len);
        if (n <= 0) return written;
        written += @intCast(n);
    }
    return error.SocketFillFailed;
}

test "http1 upload relay reports a slow origin as a downstream read pause" {
    const fds = try makeBlockingSocketpair();
    const client_fd = fds[0];
    const peer_fd = fds[1];
    defer _ = std.c.close(client_fd);
    defer _ = std.c.close(peer_fd);

    // Shrink both ends so the origin's window fills well before the upload is
    // done, whatever the platform default happens to be.
    const small: c_int = 4096;
    std.posix.setsockopt(client_fd, std.posix.SOL.SOCKET, std.posix.SO.SNDBUF, std.mem.asBytes(&small)) catch {};
    std.posix.setsockopt(peer_fd, std.posix.SOL.SOCKET, std.posix.SO.RCVBUF, std.mem.asBytes(&small)) catch {};

    const payload = try std.testing.allocator.alloc(u8, 64 * 1024);
    defer std.testing.allocator.free(payload);
    @memset(payload, 'u');

    // Leave the origin's window already full, so the relay's first look at the
    // socket is guaranteed to find a stall rather than racing the drainer for
    // one. The probe must agree, or the check below is not testing anything.
    const prefilled = try fillSocketSendBuffer(client_fd);
    try std.testing.expect(prefilled > 0);
    try std.testing.expectEqual(UpstreamWritability.blocked, pollUpstreamWritability(client_fd));

    const drainer = try std.Thread.spawn(.{}, slowUploadDrain, .{ peer_fd, @as(u64, 20), prefilled + payload.len });
    defer drainer.join();

    var counters = UploadBufferObserver{};
    var source = FakeUploadSource{ .data = payload };
    try runHttp1Upload(
        compat.netStreamFromFd(client_fd),
        client_fd,
        .{ .framing = .{ .length = payload.len } },
        &source,
        uploadTestLimits(1024 * 1024),
        counters.observer(),
        .{},
    );

    // The origin stopped draining, so downstream reads really were held back.
    try std.testing.expect(counters.pauses >= 1);
    // And every pause was resolved, not left dangling.
    try std.testing.expectEqual(counters.pauses, counters.resumes);
    // Peak relay memory is the fixed buffer, not the body.
    try std.testing.expectEqual(@as(usize, 16 * 1024), counters.peak_reserved);
    try std.testing.expectEqual(@as(usize, 0), counters.reserved);
    try std.testing.expectEqual(@as(usize, 0), counters.retained);
}

test "http1 upload relay leaves nothing reserved when the client aborts mid-upload" {
    const fds = try makeBlockingSocketpair();
    const client_fd = fds[0];
    const peer_fd = fds[1];
    defer _ = std.c.close(client_fd);
    defer _ = std.c.close(peer_fd);

    var counters = UploadBufferObserver{};
    var global = proxy_buffer_account.Aggregate.init(.global, 0);
    // Promises 8 KiB, delivers 4 KiB, then the client goes away.
    var source = FakeUploadSource{ .data = &[_]u8{'x'} ** 4096, .abort_after = 4096 };
    try std.testing.expectError(error.ClientAborted, runHttp1Upload(
        compat.netStreamFromFd(client_fd),
        client_fd,
        .{ .framing = .{ .length = 8192 } },
        &source,
        uploadTestLimits(1024 * 1024),
        counters.observer(),
        .{ .global = &global },
    ));

    try std.testing.expectEqual(@as(usize, 0), counters.reserved);
    try std.testing.expectEqual(@as(usize, 0), counters.retained);
    try std.testing.expectEqual(@as(usize, 0), global.currentBytes(.downstream_to_upstream));
    // Never stalled, so the pause counters stay untouched.
    try std.testing.expectEqual(@as(u64, 0), counters.pauses);
    try std.testing.expectEqual(@as(u64, 0), counters.resumes);
}

test "http1 upload relay rejects an over-limit in-flight upload as a client fault" {
    const fds = try makeBlockingSocketpair();
    const client_fd = fds[0];
    const peer_fd = fds[1];
    defer _ = std.c.close(client_fd);
    defer _ = std.c.close(peer_fd);

    var counters = UploadBufferObserver{};
    var source = FakeUploadSource{ .data = "" };
    // The relay buffer alone consumes the whole per-stream budget, so the bytes
    // that arrived with the request head have nowhere to go.
    try std.testing.expectError(error.RequestBufferLimitExceeded, runHttp1Upload(
        compat.netStreamFromFd(client_fd),
        client_fd,
        .{ .framing = .{ .length = 32 }, .initial_bytes = "inline-body-bytes" },
        &source,
        uploadTestLimits(16 * 1024),
        counters.observer(),
        .{},
    ));

    // Charged to the stream scope (a 413), not to an aggregate one (a 503).
    try std.testing.expectEqual(@as(u64, 1), counters.stream_limit_exceeded);
    try std.testing.expectEqual(@as(u64, 0), counters.aggregate_limit_exceeded);
    try std.testing.expectEqual(@as(usize, 0), counters.reserved);
    try std.testing.expectEqual(@as(usize, 0), counters.retained);
}

test "http1 upload relay refuses when a concurrent relay has taken the aggregate" {
    const fds = try makeBlockingSocketpair();
    const client_fd = fds[0];
    const peer_fd = fds[1];
    defer _ = std.c.close(client_fd);
    defer _ = std.c.close(peer_fd);

    const limits = uploadTestLimits(16 * 1024);
    var counters = UploadBufferObserver{};
    // Room for one relay buffer and a little more — the second upload is what
    // proves concurrency cannot multiply the per-stream bound.
    var global = proxy_buffer_account.Aggregate.init(.global, 24 * 1024);
    const capacity = proxy_buffer_account.AggregateCapacity{ .global = &global };

    var in_flight = ProxyBufferReservation.init(.downstream_to_upstream, limits, counters.observer(), capacity);
    try in_flight.reserve(16 * 1024);

    var source = FakeUploadSource{ .data = "" };
    try std.testing.expectError(error.ProxyBufferCapacityUnavailable, runHttp1Upload(
        compat.netStreamFromFd(client_fd),
        client_fd,
        .{ .framing = .{ .length = 0 } },
        &source,
        limits,
        counters.observer(),
        capacity,
    ));

    try std.testing.expectEqual(@as(u64, 1), counters.aggregate_limit_exceeded);
    try std.testing.expectEqual(proxy_buffer_account.Scope.global, counters.last_aggregate_scope.?);
    // The refused relay retained nothing; the reservation that did fit is intact.
    try std.testing.expectEqual(@as(usize, 16 * 1024), global.currentBytes(.downstream_to_upstream));

    in_flight.releaseAll();
    try std.testing.expectEqual(@as(usize, 0), global.currentBytes(.downstream_to_upstream));
    try std.testing.expectEqual(@as(usize, 0), counters.reserved);
    try std.testing.expectEqual(@as(usize, 0), counters.retained);
}

/// Has anything arrived on `fd` yet? Zero timeout — used to assert an origin
/// was left untouched, so it must not wait for something that will never come.
fn peerHasBytes(fd: std.posix.fd_t) !bool {
    var pfds = [_]std.posix.pollfd{.{ .fd = fd, .events = std.posix.POLL.IN, .revents = 0 }};
    const ready = try std.posix.poll(&pfds, 0);
    return ready != 0 and (pfds[0].revents & std.posix.POLL.IN) != 0;
}

test "http1 chunked upload accounts the raw request-head remainder and releases it as it drains" {
    const fds = try makeBlockingSocketpair();
    const client_fd = fds[0];
    const peer_fd = fds[1];
    defer _ = std.c.close(client_fd);
    defer _ = std.c.close(peer_fd);

    var counters = UploadBufferObserver{};
    var global = proxy_buffer_account.Aggregate.init(.global, 0);
    const limits = uploadTestLimits(1024 * 1024);
    const capacity = proxy_buffer_account.AggregateCapacity{ .global = &global };

    // The whole chunked body arrived with the request head. The decoder borrows
    // that raw slice — framing octets included — so all 14 bytes are retained
    // alongside the relay buffer even though only 5 are payload.
    const head_remainder = "5\r\nhello\r\n0\r\n\r\n";
    const sb = StreamingRequestBody{
        .framing = .chunked,
        .initial_bytes = head_remainder,
        .max_body_bytes = 1024,
    };
    try std.testing.expectEqual(@as(usize, head_remainder.len), uploadInitialBytesFootprint(sb));

    var source = FakeUploadSource{ .data = "" };
    var reservation = try preflightUploadReservation(
        limits,
        counters.observer(),
        capacity,
        http1_upload_relay_bytes,
        uploadInitialBytesFootprint(sb),
    );
    defer reservation.releaseAll();
    try std.testing.expectEqual(
        http1_upload_relay_bytes + head_remainder.len,
        counters.peak_reserved,
    );

    try relayStreamingUploadToHttp1(
        compat.netStreamFromFd(client_fd),
        client_fd,
        sb,
        &source,
        null,
        &reservation,
        counters.observer(),
    );

    // The relay gave the head remainder back as the decoder drained it, rather
    // than holding the peak until teardown — only the relay buffer is left.
    try std.testing.expectEqual(http1_upload_relay_bytes, reservation.account.snapshot().current);
    try std.testing.expectEqual(http1_upload_relay_bytes, global.currentBytes(.downstream_to_upstream));

    reservation.releaseAll();
    try std.testing.expectEqual(@as(usize, 0), counters.reserved);
    try std.testing.expectEqual(@as(usize, 0), counters.retained);
    try std.testing.expectEqual(@as(usize, 0), global.currentBytes(.downstream_to_upstream));

    // The re-chunked body did reach the origin.
    var seen: [64]u8 = undefined;
    const got = std.c.read(peer_fd, &seen, seen.len);
    try std.testing.expect(got > 0);
    try std.testing.expectEqualStrings("5\r\nhello\r\n0\r\n\r\n", seen[0..@intCast(got)]);
}

test "chunked request-head remainder counts against the aggregate scope" {
    const fds = try makeBlockingSocketpair();
    const client_fd = fds[0];
    const peer_fd = fds[1];
    defer _ = std.c.close(client_fd);
    defer _ = std.c.close(peer_fd);

    const limits = uploadTestLimits(64 * 1024);
    var counters = UploadBufferObserver{};
    var global = proxy_buffer_account.Aggregate.init(.global, 64 * 1024);
    const capacity = proxy_buffer_account.AggregateCapacity{ .global = &global };

    // Concurrent work already holds 40 KiB. The relay buffer still fits; the
    // request-head remainder is what tips the scope over — which it could only
    // do if that remainder is accounted at all.
    var in_flight = ProxyBufferReservation.init(.downstream_to_upstream, limits, counters.observer(), capacity);
    try in_flight.reserve(40 * 1024);

    const head_remainder = [_]u8{'z'} ** (12 * 1024);
    var source = FakeUploadSource{ .data = "" };
    try std.testing.expectError(error.ProxyBufferCapacityUnavailable, runHttp1Upload(
        compat.netStreamFromFd(client_fd),
        client_fd,
        .{ .framing = .chunked, .initial_bytes = &head_remainder, .max_body_bytes = 1 << 20 },
        &source,
        limits,
        counters.observer(),
        capacity,
    ));

    try std.testing.expectEqual(@as(u64, 1), counters.aggregate_limit_exceeded);
    try std.testing.expectEqual(proxy_buffer_account.Scope.global, counters.last_aggregate_scope.?);
    // The refused upload rolled back completely; the concurrent holder is intact.
    try std.testing.expectEqual(@as(usize, 40 * 1024), global.currentBytes(.downstream_to_upstream));

    in_flight.releaseAll();
    try std.testing.expectEqual(@as(usize, 0), global.currentBytes(.downstream_to_upstream));
    try std.testing.expectEqual(@as(usize, 0), counters.reserved);
    try std.testing.expectEqual(@as(usize, 0), counters.retained);
}

test "malformed chunked framing cannot leak the request-head reservation" {
    const fds = try makeBlockingSocketpair();
    const client_fd = fds[0];
    const peer_fd = fds[1];
    defer _ = std.c.close(client_fd);
    defer _ = std.c.close(peer_fd);

    var counters = UploadBufferObserver{};
    var global = proxy_buffer_account.Aggregate.init(.global, 0);
    var source = FakeUploadSource{ .data = "" };
    try std.testing.expectError(error.InvalidChunkedUpload, runHttp1Upload(
        compat.netStreamFromFd(client_fd),
        client_fd,
        // Not a chunk-size line.
        .{ .framing = .chunked, .initial_bytes = "not-hex\r\n", .max_body_bytes = 1024 },
        &source,
        uploadTestLimits(1024 * 1024),
        counters.observer(),
        .{ .global = &global },
    ));

    try std.testing.expectEqual(@as(usize, 0), counters.reserved);
    try std.testing.expectEqual(@as(usize, 0), counters.retained);
    try std.testing.expectEqual(@as(usize, 0), global.currentBytes(.downstream_to_upstream));
}

test "a client that vanishes mid-chunk releases the request-head reservation" {
    const fds = try makeBlockingSocketpair();
    const client_fd = fds[0];
    const peer_fd = fds[1];
    defer _ = std.c.close(client_fd);
    defer _ = std.c.close(peer_fd);

    var counters = UploadBufferObserver{};
    var global = proxy_buffer_account.Aggregate.init(.global, 0);
    // Announces a 16-byte chunk, supplies none of it, then goes away.
    var source = FakeUploadSource{ .data = "", .abort_after = 0 };
    try std.testing.expectError(error.ClientAborted, runHttp1Upload(
        compat.netStreamFromFd(client_fd),
        client_fd,
        .{ .framing = .chunked, .initial_bytes = "10\r\n", .max_body_bytes = 1024 },
        &source,
        uploadTestLimits(1024 * 1024),
        counters.observer(),
        .{ .global = &global },
    ));

    try std.testing.expectEqual(@as(usize, 0), counters.reserved);
    try std.testing.expectEqual(@as(usize, 0), counters.retained);
    try std.testing.expectEqual(@as(usize, 0), global.currentBytes(.downstream_to_upstream));
}

test "a broken upstream socket is not counted as backpressure" {
    const fds = try makeBlockingSocketpair();
    const client_fd = fds[0];
    const peer_fd = fds[1];
    defer _ = std.c.close(client_fd);

    // The origin is gone, not slow. `poll` still reports the descriptor ready
    // — for POLLERR/POLLHUP — so a naive readiness test would call this a full
    // send buffer and record a pause the write is about to invalidate.
    _ = std.c.close(peer_fd);

    var counters = UploadBufferObserver{};
    var stall = proxy_buffer_account.ReadStall.init(.downstream, counters.observer());
    try std.testing.expect(pollUpstreamWritability(client_fd) != .blocked);
    noteUpstreamWriteStall(client_fd, &stall);

    try std.testing.expectEqual(@as(u64, 0), counters.pauses);
    try std.testing.expectEqual(@as(u64, 0), counters.resumes);
    try std.testing.expect(!stall.paused);
}

test "http1 upload capacity is refused before the request head reaches the origin" {
    const fds = try makeBlockingSocketpair();
    const client_fd = fds[0];
    const peer_fd = fds[1];
    defer _ = std.c.close(client_fd);
    defer _ = std.c.close(peer_fd);

    const limits = uploadTestLimits(16 * 1024);
    var counters = UploadBufferObserver{};
    var global = proxy_buffer_account.Aggregate.init(.global, 16 * 1024);
    const capacity = proxy_buffer_account.AggregateCapacity{ .global = &global };

    // The process account is already spoken for, so this upload cannot be
    // admitted at all.
    var in_flight = ProxyBufferReservation.init(.downstream_to_upstream, limits, counters.observer(), capacity);
    try in_flight.reserve(16 * 1024);
    defer in_flight.releaseAll();

    var source = FakeUploadSource{ .data = "" };
    const uri = try std.Uri.parse("http://origin.test/upload");
    try std.testing.expectError(error.ProxyBufferCapacityUnavailable, sendStreamingProxyRequest(
        std.testing.allocator,
        compat.netStreamFromFd(client_fd),
        client_fd,
        uri,
        "POST",
        &.{},
        "",
        .{ .framing = .{ .length = 4096 } },
        &source,
        null,
        limits,
        counters.observer(),
        capacity,
    ));

    // The whole point: the origin never saw a request it would have had to
    // decide what to do with. A refusal after the head went out would leave a
    // real, possibly side-effecting request half-delivered.
    try std.testing.expect(!try peerHasBytes(peer_fd));
}

/// A prior-knowledge h2c origin that completes just enough handshake for the
/// pool to hand back a connection, then records everything else the client
/// sends. Used to prove a request the proxy refused locally never reached it.
const H2CapacityProbe = struct {
    listen_fd: std.posix.fd_t,
    recorded: [4096]u8 = undefined,
    len: usize = 0,
};

fn h2PrefaceOnlyOrigin(probe: *H2CapacityProbe) void {
    const conn = std.c.accept(probe.listen_fd, null, null);
    if (conn < 0) return;
    defer _ = std.c.close(conn);

    var preface: [24]u8 = undefined;
    var got: usize = 0;
    while (got < preface.len) {
        const n = std.c.read(conn, preface[got..].ptr, preface.len - got);
        if (n <= 0) return;
        got += @intCast(n);
    }
    // An empty SETTINGS frame is all `acquire` needs to consider the
    // connection usable.
    const settings = [_]u8{ 0, 0, 0, 0x04, 0, 0, 0, 0, 0 };
    _ = std.c.write(conn, &settings, settings.len);

    while (probe.len < probe.recorded.len) {
        var pfd = [_]std.posix.pollfd{.{ .fd = conn, .events = std.posix.POLL.IN, .revents = 0 }};
        const ready = std.posix.poll(&pfd, 500) catch return;
        if (ready == 0) return;
        const n = std.c.read(conn, probe.recorded[probe.len..].ptr, probe.recorded.len - probe.len);
        if (n <= 0) return;
        probe.len += @intCast(n);
    }
}

fn readExactlyFromFd(fd: std.posix.fd_t, out: []u8) bool {
    var got: usize = 0;
    while (got < out.len) {
        const n = std.c.read(fd, out[got..].ptr, out.len - got);
        if (n <= 0) return false;
        got += @intCast(n);
    }
    return true;
}

fn sleepMs(ms: u32) void {
    var no_fds: [0]std.posix.pollfd = .{};
    _ = std.posix.poll(&no_fds, @intCast(ms)) catch {};
}

/// Bind a loopback listener on an ephemeral port and report it.
fn listenLoopbackEphemeral() !struct { fd: std.posix.fd_t, port: u16 } {
    const listen_fd = std.c.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, std.posix.IPPROTO.TCP);
    if (listen_fd < 0) return error.SocketFailed;
    errdefer _ = std.c.close(listen_fd);
    _ = std.c.setsockopt(listen_fd, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, std.mem.asBytes(&@as(c_int, 1)), @sizeOf(c_int));
    const sin: std.c.sockaddr.in = .{
        .family = std.posix.AF.INET,
        .port = std.mem.nativeToBig(u16, 0),
        .addr = @bitCast([4]u8{ 127, 0, 0, 1 }),
        .zero = [8]u8{ 0, 0, 0, 0, 0, 0, 0, 0 },
    };
    if (std.c.bind(listen_fd, @ptrCast(&sin), @sizeOf(std.c.sockaddr.in)) != 0) return error.BindFailed;
    if (std.c.listen(listen_fd, 4) != 0) return error.ListenFailed;
    var bound: std.c.sockaddr.in = undefined;
    var bound_len: std.posix.socklen_t = @sizeOf(std.c.sockaddr.in);
    if (std.c.getsockname(listen_fd, @ptrCast(&bound), &bound_len) != 0) return error.SockNameFailed;
    return .{ .fd = listen_fd, .port = std.mem.bigToNative(u16, bound.port) };
}

/// An h2c origin that consumes a whole upload, answers with response headers,
/// and then holds the body back until told to release it. That gap is the
/// window where the upload has finished but the exchange has not, which is
/// exactly where a request-direction reservation must no longer be held.
const H2SlowResponseOrigin = struct {
    listen_fd: std.posix.fd_t,
    head_sent: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    release_body: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
};

fn h2SlowResponseServe(origin: *H2SlowResponseOrigin) void {
    const conn = std.c.accept(origin.listen_fd, null, null);
    if (conn < 0) return;
    defer _ = std.c.close(conn);

    var preface: [24]u8 = undefined;
    if (!readExactlyFromFd(conn, &preface)) return;
    const settings = [_]u8{ 0, 0, 0, 0x04, 0, 0, 0, 0, 0 };
    _ = std.c.write(conn, &settings, settings.len);

    // Drain frames until the request stream ends, remembering its id.
    var stream_id: u32 = 0;
    while (true) {
        var hdr: [9]u8 = undefined;
        if (!readExactlyFromFd(conn, &hdr)) return;
        const payload_len = (@as(usize, hdr[0]) << 16) | (@as(usize, hdr[1]) << 8) | @as(usize, hdr[2]);
        const typ = hdr[3];
        const flags = hdr[4];
        const sid = std.mem.readInt(u32, hdr[5..9], .big) & 0x7fff_ffff;
        var scratch: [4096]u8 = undefined;
        var remaining = payload_len;
        while (remaining > 0) {
            const take = @min(remaining, scratch.len);
            if (!readExactlyFromFd(conn, scratch[0..take])) return;
            remaining -= take;
        }
        if (typ == 0x01) stream_id = sid; // HEADERS
        if (typ == 0x00 and (flags & 0x01) != 0) break; // DATA with END_STREAM
    }
    if (stream_id == 0) return;

    // HEADERS, END_HEADERS, one byte of HPACK: `:status: 200` is static-table
    // index 8, so an indexed header field encodes the whole block.
    var head_frame = [_]u8{ 0, 0, 1, 0x01, 0x04, 0, 0, 0, 0, 0x88 };
    std.mem.writeInt(u32, head_frame[5..9], stream_id, .big);
    _ = std.c.write(conn, &head_frame, head_frame.len);
    origin.head_sent.store(true, .release);

    while (!origin.release_body.load(.acquire)) sleepMs(5);

    var body_frame = [_]u8{ 0, 0, 2, 0x00, 0x01, 0, 0, 0, 0, 'o', 'k' };
    std.mem.writeInt(u32, body_frame[5..9], stream_id, .big);
    _ = std.c.write(conn, &body_frame, body_frame.len);

    var drain: [256]u8 = undefined;
    while (true) {
        const got = std.c.read(conn, &drain, drain.len);
        if (got <= 0) break;
    }
}

/// Runs one `streamViaH2Pool` exchange on its own thread so the test can
/// observe accounting while the exchange is mid-flight.
const H2ExchangeCtx = struct {
    pool: *http.upstream_h2.H2ConnPool,
    port: u16,
    uri: std.Uri,
    read_buf: []u8,
    source: *FakeUploadSource,
    captured: *std.array_list.Managed(u8),
    security: *const http.security_headers.SecurityHeaders,
    limits: proxy_buffer_account.Limits,
    observer: proxy_buffer_account.Observer,
    global: *proxy_buffer_account.Aggregate,
    finished: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    failed: bool = false,
    status: u16 = 0,
};

fn runH2ExchangeThread(ctx: *H2ExchangeCtx) void {
    defer ctx.finished.store(true, .release);
    const result = streamViaH2Pool(
        std.testing.allocator,
        ctx.pool,
        null,
        "127.0.0.1",
        ctx.port,
        null, // prior-knowledge h2c
        ctx.uri,
        "POST",
        &.{},
        "",
        .{ .framing = .{ .length = 8 } },
        ctx.read_buf,
        ctx.source,
        CaptureWriter{ .list = ctx.captured },
        ctx.security,
        null,
        null,
        "lifetime-test",
        2000,
        5000,
        null,
        ctx.limits,
        ctx.observer,
        ctx.global,
    ) catch {
        ctx.failed = true;
        return;
    };
    ctx.status = result.status_code;
}

test "an http2 upload releases request-direction capacity before its response completes" {
    const listener = try listenLoopbackEphemeral();
    defer _ = std.c.close(listener.fd);

    var origin = H2SlowResponseOrigin{ .listen_fd = listener.fd };
    const origin_thread = try std.Thread.spawn(.{}, h2SlowResponseServe, .{&origin});

    var read_buf: [16 * 1024]u8 = undefined;
    const limits = uploadTestLimits(1024 * 1024);
    // Exactly one relay buffer fits per direction. The upload's claim is
    // therefore the only thing that can keep a second upload out.
    var global = proxy_buffer_account.Aggregate.init(.global, read_buf.len);

    var counters = UploadBufferObserver{};
    var source = FakeUploadSource{ .data = "upload!!" };
    var captured = std.array_list.Managed(u8).init(std.testing.allocator);
    defer captured.deinit();
    var security = http.security_headers.SecurityHeaders{};
    var url_buf: [64]u8 = undefined;
    const uri = try std.Uri.parse(try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/upload", .{listener.port}));

    var pool = http.upstream_h2.H2ConnPool.init(std.testing.allocator, .{});
    var ctx = H2ExchangeCtx{
        .pool = &pool,
        .port = listener.port,
        .uri = uri,
        .read_buf = &read_buf,
        .source = &source,
        .captured = &captured,
        .security = &security,
        .limits = limits,
        .observer = counters.observer(),
        .global = &global,
    };
    const exchange = try std.Thread.spawn(.{}, runH2ExchangeThread, .{&ctx});

    // The origin has taken the whole upload and answered with headers; the
    // response body is still being withheld, so the exchange is mid-flight.
    var waited: u32 = 0;
    while (!origin.head_sent.load(.acquire) and waited < 5000) : (waited += 5) sleepMs(5);
    try std.testing.expect(origin.head_sent.load(.acquire));

    // The upload finished, so its capacity must be back — even though the
    // exchange has not. Bounded wait, because the release happens on the
    // exchange thread just after the relay returns; the budget is well inside
    // the exchange's own read deadline so a regression fails here on the
    // reservation rather than later on a timeout.
    waited = 0;
    while (global.currentBytes(.downstream_to_upstream) != 0 and waited < 1000) : (waited += 5) sleepMs(5);
    // Checked first: it is what makes the next assertion meaningful — the
    // capacity came back while the exchange was still running, not because it
    // ended.
    try std.testing.expect(!ctx.finished.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), global.currentBytes(.downstream_to_upstream));

    // And the capacity is genuinely usable: a second upload can take it. With
    // the claim held for the whole exchange this reservation was refused, which
    // is the false `503 proxy_buffer_saturated` an unrelated client would see.
    var other = UploadBufferObserver{};
    var second_upload = ProxyBufferReservation.init(
        .downstream_to_upstream,
        limits,
        other.observer(),
        .{ .global = &global },
    );
    try second_upload.reserve(read_buf.len);
    second_upload.releaseAll();

    origin.release_body.store(true, .release);
    exchange.join();
    try std.testing.expect(!ctx.failed);
    try std.testing.expectEqual(@as(u16, 200), ctx.status);

    pool.deinit();
    origin_thread.join();

    try std.testing.expectEqual(@as(usize, 0), global.currentBytes(.downstream_to_upstream));
    try std.testing.expectEqual(@as(usize, 0), global.currentBytes(.upstream_to_downstream));
    try std.testing.expectEqual(@as(usize, 0), counters.reserved);
    try std.testing.expectEqual(@as(usize, 0), counters.retained);
}

/// Walk an HTTP/2 frame stream looking for one frame type. Frames are
/// length-prefixed, so this needs no protocol state.
fn h2StreamContainsFrameType(bytes: []const u8, wanted: u8) bool {
    var i: usize = 0;
    while (i + 9 <= bytes.len) {
        const payload_len = (@as(usize, bytes[i]) << 16) | (@as(usize, bytes[i + 1]) << 8) | @as(usize, bytes[i + 2]);
        if (bytes[i + 3] == wanted) return true;
        i += 9 + payload_len;
    }
    return false;
}

test "http2 upload capacity is refused before HEADERS reach the origin" {
    const listen_fd = std.c.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, std.posix.IPPROTO.TCP);
    try std.testing.expect(listen_fd >= 0);
    defer _ = std.c.close(listen_fd);
    _ = std.c.setsockopt(listen_fd, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, std.mem.asBytes(&@as(c_int, 1)), @sizeOf(c_int));
    const sin: std.c.sockaddr.in = .{
        .family = std.posix.AF.INET,
        .port = std.mem.nativeToBig(u16, 0),
        .addr = @bitCast([4]u8{ 127, 0, 0, 1 }),
        .zero = [8]u8{ 0, 0, 0, 0, 0, 0, 0, 0 },
    };
    try std.testing.expect(std.c.bind(listen_fd, @ptrCast(&sin), @sizeOf(std.c.sockaddr.in)) == 0);
    try std.testing.expect(std.c.listen(listen_fd, 4) == 0);
    var bound: std.c.sockaddr.in = undefined;
    var bound_len: std.posix.socklen_t = @sizeOf(std.c.sockaddr.in);
    try std.testing.expect(std.c.getsockname(listen_fd, @ptrCast(&bound), &bound_len) == 0);
    const port = std.mem.bigToNative(u16, bound.port);

    var probe = H2CapacityProbe{ .listen_fd = listen_fd };
    const origin = try std.Thread.spawn(.{}, h2PrefaceOnlyOrigin, .{&probe});

    const limits = uploadTestLimits(1024 * 1024);
    var counters = UploadBufferObserver{};
    // The process account is full before the request starts.
    var global = proxy_buffer_account.Aggregate.init(.global, 16 * 1024);
    var in_flight = ProxyBufferReservation.init(
        .downstream_to_upstream,
        limits,
        counters.observer(),
        .{ .global = &global },
    );
    try in_flight.reserve(16 * 1024);
    defer in_flight.releaseAll();

    var read_buf: [16 * 1024]u8 = undefined;
    var source = FakeUploadSource{ .data = "" };
    var captured = std.array_list.Managed(u8).init(std.testing.allocator);
    defer captured.deinit();
    var security = http.security_headers.SecurityHeaders{};
    var url_buf: [64]u8 = undefined;
    const uri = try std.Uri.parse(try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/upload", .{port}));

    {
        var pool = http.upstream_h2.H2ConnPool.init(std.testing.allocator, .{});
        defer pool.deinit();

        try std.testing.expectError(error.ProxyBufferCapacityUnavailable, streamViaH2Pool(
            std.testing.allocator,
            &pool,
            null,
            "127.0.0.1",
            port,
            null, // prior-knowledge h2c
            uri,
            "POST",
            &.{},
            "",
            .{ .framing = .{ .length = 4096 } },
            &read_buf,
            &source,
            CaptureWriter{ .list = &captured },
            &security,
            null,
            null,
            "test-correlation-id",
            2000,
            2000,
            null,
            limits,
            counters.observer(),
            &global,
        ));
    }
    origin.join();

    // The origin completed a connection but was never asked to do any work:
    // refusing after HEADERS would have left it holding a request whose body
    // never arrives, and any side effects that came with it.
    try std.testing.expect(!h2StreamContainsFrameType(probe.recorded[0..probe.len], 0x01));
    // Nothing beyond the deliberately-held reservation is outstanding: the
    // refused request rolled back everything it touched.
    try std.testing.expectEqual(@as(usize, 16 * 1024), counters.retained);
    try std.testing.expectEqual(@as(usize, 16 * 1024), global.currentBytes(.downstream_to_upstream));
}

const FakeH2UploadStream = struct { id: u32 = 1 };

const FakeH2UploadConn = struct {
    written: usize = 0,
    end_stream: bool = false,

    fn writeStreamingRequestBody(
        self: *FakeH2UploadConn,
        _: *FakeH2UploadStream,
        bytes: []const u8,
        end_stream: bool,
    ) !void {
        self.written += bytes.len;
        if (end_stream) self.end_stream = true;
    }
};

test "http2 upload relay reserves the relay buffer once, not once per DATA frame" {
    var conn = FakeH2UploadConn{};
    var stream = FakeH2UploadStream{};
    var counters = UploadBufferObserver{};
    var global = proxy_buffer_account.Aggregate.init(.global, 0);

    const payload = try std.testing.allocator.alloc(u8, 256 * 1024);
    defer std.testing.allocator.free(payload);
    @memset(payload, 'd');
    var read_buf: [16 * 1024]u8 = undefined;
    var source = FakeUploadSource{ .data = payload };

    try runHttp2Upload(
        &conn,
        &stream,
        .{ .framing = .{ .length = payload.len } },
        &read_buf,
        &source,
        uploadTestLimits(1024 * 1024),
        counters.observer(),
        .{ .global = &global },
    );

    try std.testing.expectEqual(payload.len, conn.written);
    try std.testing.expect(conn.end_stream);
    // 16 DATA frames went out, but only one buffer was ever owned.
    try std.testing.expectEqual(@as(usize, read_buf.len), counters.peak_reserved);
    try std.testing.expectEqual(@as(usize, 0), counters.reserved);
    try std.testing.expectEqual(@as(usize, 0), counters.retained);
    try std.testing.expectEqual(@as(usize, 0), global.currentBytes(.downstream_to_upstream));
}

test "http2 chunked upload accounts and releases the raw request-head remainder" {
    var conn = FakeH2UploadConn{};
    var stream = FakeH2UploadStream{};
    var counters = UploadBufferObserver{};
    var global = proxy_buffer_account.Aggregate.init(.global, 0);
    const limits = uploadTestLimits(1024 * 1024);
    const capacity = proxy_buffer_account.AggregateCapacity{ .global = &global };
    var read_buf: [16 * 1024]u8 = undefined;

    const head_remainder = "5\r\nhello\r\n0\r\n\r\n";
    const sb = StreamingRequestBody{
        .framing = .chunked,
        .initial_bytes = head_remainder,
        .max_body_bytes = 1024,
    };
    var source = FakeUploadSource{ .data = "" };

    var reservation = try preflightUploadReservation(
        limits,
        counters.observer(),
        capacity,
        read_buf.len,
        uploadInitialBytesFootprint(sb),
    );
    defer reservation.releaseAll();
    try std.testing.expectEqual(read_buf.len + head_remainder.len, counters.peak_reserved);

    try relayStreamingUploadToHttp2(&conn, &stream, sb, &read_buf, &source, null, &reservation);

    // Decoded payload went out as DATA; the raw framing octets were accounted
    // and then handed back as the decoder consumed them.
    try std.testing.expectEqual(@as(usize, 5), conn.written);
    try std.testing.expect(conn.end_stream);
    try std.testing.expectEqual(read_buf.len, reservation.account.snapshot().current);

    reservation.releaseAll();
    try std.testing.expectEqual(@as(usize, 0), counters.reserved);
    try std.testing.expectEqual(@as(usize, 0), counters.retained);
    try std.testing.expectEqual(@as(usize, 0), global.currentBytes(.downstream_to_upstream));
}

test "http2 upload relay releases the aggregate when the client aborts" {
    var conn = FakeH2UploadConn{};
    var stream = FakeH2UploadStream{};
    var counters = UploadBufferObserver{};
    var global = proxy_buffer_account.Aggregate.init(.global, 0);
    var read_buf: [16 * 1024]u8 = undefined;
    var source = FakeUploadSource{ .data = &[_]u8{'y'} ** 1024, .abort_after = 1024 };

    try std.testing.expectError(error.ClientAborted, runHttp2Upload(
        &conn,
        &stream,
        .{ .framing = .{ .length = 64 * 1024 } },
        &read_buf,
        &source,
        uploadTestLimits(1024 * 1024),
        counters.observer(),
        .{ .global = &global },
    ));

    try std.testing.expectEqual(@as(usize, 0), counters.reserved);
    try std.testing.expectEqual(@as(usize, 0), counters.retained);
    try std.testing.expectEqual(@as(usize, 0), global.currentBytes(.downstream_to_upstream));
}

/// Raw blocking responder: accepts one connection, drains the request, writes a
/// fixed 200 response, and closes. Uses std.c directly so the test never touches
/// the std.Io event loop.
fn rawHttpResponder(listen_fd: std.posix.fd_t) void {
    const conn = std.c.accept(listen_fd, null, null);
    if (conn < 0) return;
    defer _ = std.c.close(conn);
    var buf: [4096]u8 = undefined;
    _ = std.c.read(conn, &buf, buf.len);
    const response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nhello";
    _ = std.c.write(conn, response.ptr, response.len);
}

test "connectBlockingTcp + exchange round-trips a real TCP origin" {
    const allocator = std.testing.allocator;

    // Raw blocking listener (no event loop).
    const listen_fd = std.c.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, std.posix.IPPROTO.TCP);
    try std.testing.expect(listen_fd >= 0);
    defer _ = std.c.close(listen_fd);
    _ = std.c.setsockopt(listen_fd, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, std.mem.asBytes(&@as(c_int, 1)), @sizeOf(c_int));

    const sin: std.c.sockaddr.in = .{
        .family = std.posix.AF.INET,
        .port = std.mem.nativeToBig(u16, 0),
        .addr = @bitCast([4]u8{ 127, 0, 0, 1 }),
        .zero = [8]u8{ 0, 0, 0, 0, 0, 0, 0, 0 },
    };
    try std.testing.expect(std.c.bind(listen_fd, @ptrCast(&sin), @sizeOf(std.c.sockaddr.in)) == 0);
    try std.testing.expect(std.c.listen(listen_fd, 8) == 0);

    var bound: std.c.sockaddr.in = undefined;
    var bound_len: std.posix.socklen_t = @sizeOf(std.c.sockaddr.in);
    try std.testing.expect(std.c.getsockname(listen_fd, @ptrCast(&bound), &bound_len) == 0);
    const port = std.mem.bigToNative(u16, bound.port);
    try std.testing.expect(port != 0);

    const responder = try std.Thread.spawn(.{}, rawHttpResponder, .{listen_fd});
    defer responder.join();

    const uri = try std.Uri.parse("http://127.0.0.1/");
    var resp = try executeBoundedBufferedTcpHttpRequest(
        allocator,
        "127.0.0.1",
        port,
        null,
        uri,
        "GET",
        &.{},
        "",
        null,
        1 << 20,
        2_000,
        2_000,
        null,
        null,
        false,
    );
    defer resp.deinit(allocator);

    try std.testing.expectEqual(@as(u16, 200), resp.status_code);
    try std.testing.expectEqualStrings("hello", resp.body);
    try std.testing.expectEqualStrings("text/plain", resp.headerValue("content-type").?);
}

/// Raw blocking keep-alive responder: accepts one connection and serves `n`
/// framed responses on it (Content-Length, no `Connection: close`), so a
/// pooled client can reuse the connection across requests.
fn rawKeepAliveHttpResponder(listen_fd: std.posix.fd_t, n: usize) void {
    const conn = std.c.accept(listen_fd, null, null);
    if (conn < 0) return;
    defer _ = std.c.close(conn);
    var buf: [4096]u8 = undefined;
    var served: usize = 0;
    while (served < n) : (served += 1) {
        const got = std.posix.read(conn, buf[0..]) catch return;
        if (got == 0) return;
        const response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello";
        _ = std.c.write(conn, response.ptr, response.len);
    }
    // Drain until the client closes so our close never RSTs unread bytes.
    while (true) {
        const got = std.posix.read(conn, buf[0..]) catch return;
        if (got == 0) return;
    }
}

test "unix-socket upstream connections pool and reuse across requests (#239)" {
    const allocator = std.testing.allocator;

    var full_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    var rnd: [8]u8 = undefined;
    compat.randomBytes(&rnd);
    const full_path = try std.fmt.bufPrint(&full_path_buf, "/tmp/tardigrade-pool-{x}.sock", .{std.mem.readInt(u64, &rnd, .little)});
    var path_z: [std.fs.max_path_bytes]u8 = undefined;
    @memcpy(path_z[0..full_path.len], full_path);
    path_z[full_path.len] = 0;
    _ = std.c.unlink(@ptrCast(&path_z));
    defer _ = std.c.unlink(@ptrCast(&path_z));

    const listen_fd = std.c.socket(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0);
    try std.testing.expect(listen_fd >= 0);
    defer _ = std.c.close(listen_fd);
    var un = std.mem.zeroes(std.c.sockaddr.un);
    un.family = std.posix.AF.UNIX;
    try std.testing.expect(full_path.len < un.path.len);
    @memcpy(un.path[0..full_path.len], full_path);
    const un_len: std.posix.socklen_t = @intCast(@offsetOf(std.c.sockaddr.un, "path") + full_path.len + 1);
    try std.testing.expect(std.c.bind(listen_fd, @ptrCast(&un), un_len) == 0);
    try std.testing.expect(std.c.listen(listen_fd, 8) == 0);

    const responder = try std.Thread.spawn(.{}, rawKeepAliveHttpResponder, .{ listen_fd, @as(usize, 2) });
    defer responder.join();

    var pool = http.upstream_pool.UpstreamPool.init(allocator, .{});
    defer pool.deinit();

    const uri = try std.Uri.parse("http://localhost/");
    var i: usize = 0;
    while (i < 2) : (i += 1) {
        var resp = try executeBoundedBufferedUnixSocketHttpRequest(
            allocator,
            full_path,
            uri,
            "GET",
            &.{},
            "",
            null,
            1 << 20,
            2_000,
            2_000,
            &pool,
        );
        defer resp.deinit(allocator);
        try std.testing.expectEqual(@as(u16, 200), resp.status_code);
        try std.testing.expectEqualStrings("hello", resp.body);
    }

    // One connection served both requests: 1 new, 1 reused, keyed unix:<path>.
    const agg = pool.aggregateStats();
    try std.testing.expectEqual(@as(u64, 1), agg.new_total);
    try std.testing.expectEqual(@as(u64, 1), agg.reused_total);
    const snaps = try pool.snapshotHosts(allocator);
    defer http.upstream_pool.freeHostSnapshots(allocator, snaps);
    try std.testing.expectEqual(@as(usize, 1), snaps.len);
    try std.testing.expect(std.mem.startsWith(u8, snaps[0].host, "unix:/tmp/tardigrade-pool-"));
}

test "connectBlockingUnix + exchange round-trips a Unix-socket origin" {
    const allocator = std.testing.allocator;

    var full_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    var rnd: [8]u8 = undefined;
    compat.randomBytes(&rnd);
    const full_path = try std.fmt.bufPrint(&full_path_buf, "/tmp/tardigrade-test-{x}.sock", .{std.mem.readInt(u64, &rnd, .little)});
    var path_z: [std.fs.max_path_bytes]u8 = undefined;
    @memcpy(path_z[0..full_path.len], full_path);
    path_z[full_path.len] = 0;
    _ = std.c.unlink(@ptrCast(&path_z)); // best-effort: clear any stale socket
    defer _ = std.c.unlink(@ptrCast(&path_z));

    const listen_fd = std.c.socket(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0);
    try std.testing.expect(listen_fd >= 0);
    defer _ = std.c.close(listen_fd);

    var un = std.mem.zeroes(std.c.sockaddr.un);
    un.family = std.posix.AF.UNIX;
    try std.testing.expect(full_path.len < un.path.len);
    @memcpy(un.path[0..full_path.len], full_path);
    const un_len: std.posix.socklen_t = @intCast(@offsetOf(std.c.sockaddr.un, "path") + full_path.len + 1);
    try std.testing.expect(std.c.bind(listen_fd, @ptrCast(&un), un_len) == 0);
    try std.testing.expect(std.c.listen(listen_fd, 8) == 0);

    const responder = try std.Thread.spawn(.{}, rawHttpResponder, .{listen_fd});
    defer responder.join();

    const uri = try std.Uri.parse("http://localhost/");
    var resp = try executeBoundedBufferedUnixSocketHttpRequest(
        allocator,
        full_path,
        uri,
        "GET",
        &.{},
        "",
        null,
        1 << 20,
        2_000,
        2_000,
        null,
    );
    defer resp.deinit(allocator);

    try std.testing.expectEqual(@as(u16, 200), resp.status_code);
    try std.testing.expectEqualStrings("hello", resp.body);
}

// ---------------------------------------------------------------------------
// Response-direction per-origin buffer accounting for HTTP/1 origins (#140).
// ---------------------------------------------------------------------------

/// A downstream client whose socket is already gone. The response reservation
/// is taken before the head is written, so this fails with the reservation
/// live — the case that would leak it.
const FailingDownstreamWriter = struct {
    pub fn writeAll(_: FailingDownstreamWriter, _: []const u8) !void {
        return error.BrokenPipe;
    }
    pub fn print(_: FailingDownstreamWriter, comptime _: []const u8, _: anytype) !void {
        return error.BrokenPipe;
    }
};

/// One HTTP/1 response relay driven over a socketpair standing in for the
/// origin. `preload` is written to the origin end before the relay starts; the
/// test writes the rest (or closes) to control when the relay finishes.
const Http1ResponseRelay = struct {
    client_fd: std.posix.fd_t,
    origin_fd: std.posix.fd_t,
    read_buf: []u8,
    captured: std.array_list.Managed(u8),
    counters: UploadBufferObserver = .{},
    limits: proxy_buffer_account.Limits,
    capacity: proxy_buffer_account.AggregateCapacity,
    read_deadline_ms: u32 = 5000,
    cancel_token: ?*const CancellationToken = null,
    finished: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    err: ?anyerror = null,
    status: u16 = 0,
    upstream_aborted: bool = false,

    fn init(
        read_buf: []u8,
        limits: proxy_buffer_account.Limits,
        capacity: proxy_buffer_account.AggregateCapacity,
    ) !Http1ResponseRelay {
        const fds = try makeBlockingSocketpair();
        return .{
            .client_fd = fds[0],
            .origin_fd = fds[1],
            .read_buf = read_buf,
            .captured = std.array_list.Managed(u8).init(std.testing.allocator),
            .limits = limits,
            .capacity = capacity,
        };
    }

    fn deinit(self: *Http1ResponseRelay) void {
        self.captured.deinit();
        _ = std.c.close(self.client_fd);
        _ = std.c.close(self.origin_fd);
    }

    fn originSend(self: *Http1ResponseRelay, bytes: []const u8) void {
        _ = std.c.write(self.origin_fd, bytes.ptr, bytes.len);
    }

    fn originClose(self: *Http1ResponseRelay) void {
        _ = std.c.shutdown(self.origin_fd, std.posix.SHUT.WR);
    }

    fn run(self: *Http1ResponseRelay, downstream_writer: anytype) void {
        defer self.finished.store(true, .release);
        var security = http.security_headers.SecurityHeaders{};
        var source = FakeUploadSource{ .data = "" };
        var wrote_downstream = false;
        const uri = std.Uri.parse("http://origin.test/resource") catch unreachable;
        const res = streamProxyOverTransport(
            std.testing.allocator,
            compat.netStreamFromFd(self.client_fd),
            self.client_fd,
            self.read_buf,
            uri,
            "GET",
            &.{},
            "",
            null, // no streaming upload: this exercises the response direction
            &source,
            downstream_writer,
            &security,
            null,
            null,
            "origin-buffer-test",
            0,
            self.read_deadline_ms,
            self.cancel_token,
            &wrote_downstream,
            self.limits,
            self.counters.observer(),
            self.capacity,
        ) catch |err| {
            self.err = err;
            return;
        };
        self.status = res.result.status_code;
        self.upstream_aborted = res.result.upstream_aborted;
    }

    fn runCapturing(self: *Http1ResponseRelay) void {
        self.run(CaptureWriter{ .list = &self.captured });
    }

    /// Every scope this relay touched is back to zero, and so is the local
    /// accounting the metrics are derived from.
    fn expectNothingHeld(self: *const Http1ResponseRelay) !void {
        try std.testing.expectEqual(@as(usize, 0), self.counters.reserved);
        try std.testing.expectEqual(@as(usize, 0), self.counters.retained);
        if (self.capacity.origin) |origin| {
            try std.testing.expectEqual(@as(usize, 0), origin.currentBytes(.upstream_to_downstream));
        }
        if (self.capacity.global) |global| {
            try std.testing.expectEqual(@as(usize, 0), global.currentBytes(.upstream_to_downstream));
        }
    }
};

const h1_response_head = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n";

/// Wait (bounded) for `condition` to hold, so a regression fails the assertion
/// that follows rather than hanging the suite.
fn awaitCondition(context: anytype, condition: *const fn (@TypeOf(context)) bool) void {
    var waited: u32 = 0;
    while (!condition(context) and waited < 5000) : (waited += 5) sleepMs(5);
}

fn originHoldsTwoRelayBuffers(account: *proxy_buffer_account.Aggregate) bool {
    return account.currentBytes(.upstream_to_downstream) >= 2 * 16 * 1024;
}

fn originHoldsOneRelayBuffer(account: *proxy_buffer_account.Aggregate) bool {
    return account.currentBytes(.upstream_to_downstream) >= 16 * 1024;
}

fn relayFinished(relay: *Http1ResponseRelay) bool {
    return relay.finished.load(.acquire);
}

test "http1 response relay releases its origin reservation on success" {
    var origin = proxy_buffer_account.Aggregate.init(.origin, 64 * 1024);
    var global = proxy_buffer_account.Aggregate.init(.global, 0);
    var read_buf: [16 * 1024]u8 = undefined;

    var relay = try Http1ResponseRelay.init(
        &read_buf,
        uploadTestLimits(1024 * 1024),
        .{ .origin = &origin, .global = &global },
    );
    defer relay.deinit();

    relay.originSend(h1_response_head ++ "body");
    relay.runCapturing();

    try std.testing.expect(relay.err == null);
    try std.testing.expectEqual(@as(u16, 200), relay.status);
    // The relay buffer was charged to the origin while it ran, and only that.
    try std.testing.expectEqual(@as(usize, read_buf.len), relay.counters.peak_reserved);
    try relay.expectNothingHeld();
}

test "http1 response relay releases its origin reservation when the upstream aborts mid-body" {
    var origin = proxy_buffer_account.Aggregate.init(.origin, 64 * 1024);
    var global = proxy_buffer_account.Aggregate.init(.global, 0);
    var read_buf: [16 * 1024]u8 = undefined;

    var relay = try Http1ResponseRelay.init(
        &read_buf,
        uploadTestLimits(1024 * 1024),
        .{ .origin = &origin, .global = &global },
    );
    defer relay.deinit();

    // Promises four body bytes, sends one, then goes away.
    relay.originSend(h1_response_head ++ "b");
    relay.originClose();
    relay.runCapturing();

    try std.testing.expect(relay.err == null);
    try std.testing.expect(relay.upstream_aborted);
    try relay.expectNothingHeld();
}

test "http1 response relay releases its origin reservation on a read timeout" {
    var origin = proxy_buffer_account.Aggregate.init(.origin, 64 * 1024);
    var global = proxy_buffer_account.Aggregate.init(.global, 0);
    var read_buf: [16 * 1024]u8 = undefined;

    var relay = try Http1ResponseRelay.init(
        &read_buf,
        uploadTestLimits(1024 * 1024),
        .{ .origin = &origin, .global = &global },
    );
    defer relay.deinit();
    relay.read_deadline_ms = 100;

    // The head arrives, the body never does: the relay is holding its
    // reservation when the read deadline fires.
    relay.originSend(h1_response_head);
    relay.runCapturing();

    try std.testing.expect(relay.err != null);
    try relay.expectNothingHeld();
}

test "http1 response relay releases its origin reservation when the request is cancelled" {
    var origin = proxy_buffer_account.Aggregate.init(.origin, 64 * 1024);
    var global = proxy_buffer_account.Aggregate.init(.global, 0);
    var read_buf: [16 * 1024]u8 = undefined;

    var relay = try Http1ResponseRelay.init(
        &read_buf,
        uploadTestLimits(1024 * 1024),
        .{ .origin = &origin, .global = &global },
    );
    defer relay.deinit();

    var token = CancellationToken.init(0);
    token.cancel(.client_disconnect);
    relay.cancel_token = &token;

    relay.originSend(h1_response_head);
    relay.runCapturing();

    try std.testing.expectEqual(@as(?anyerror, error.RequestCancelled), relay.err);
    try relay.expectNothingHeld();
}

test "http1 response relay releases its origin reservation when the client aborts" {
    var origin = proxy_buffer_account.Aggregate.init(.origin, 64 * 1024);
    var global = proxy_buffer_account.Aggregate.init(.global, 0);
    var read_buf: [16 * 1024]u8 = undefined;

    var relay = try Http1ResponseRelay.init(
        &read_buf,
        uploadTestLimits(1024 * 1024),
        .{ .origin = &origin, .global = &global },
    );
    defer relay.deinit();

    relay.originSend(h1_response_head ++ "body");
    // The reservation is taken before the head is written downstream, so the
    // write failing means it is live at the moment the client vanishes.
    relay.run(FailingDownstreamWriter{});

    try std.testing.expectEqual(@as(?anyerror, error.ClientAborted), relay.err);
    try relay.expectNothingHeld();
}

test "concurrent http1 responses to one origin cannot exceed its buffer cap" {
    const relay_buffer_bytes = 16 * 1024;
    // Room for exactly two concurrent relay buffers. A third request to the
    // same origin is what proves concurrency cannot multiply the per-request
    // bound: nothing about one request alone would ever refuse it.
    var origin = proxy_buffer_account.Aggregate.init(.origin, 2 * relay_buffer_bytes);
    var global = proxy_buffer_account.Aggregate.init(.global, 0);
    const limits = uploadTestLimits(1024 * 1024);
    const capacity = proxy_buffer_account.AggregateCapacity{ .origin = &origin, .global = &global };

    var read_bufs: [3][relay_buffer_bytes]u8 = undefined;
    var relays: [3]Http1ResponseRelay = undefined;
    for (&relays, 0..) |*relay, i| {
        relay.* = try Http1ResponseRelay.init(&read_bufs[i], limits, capacity);
    }
    defer for (&relays) |*relay| relay.deinit();

    // Two relays are admitted and then park mid-response, holding their
    // reservations: each has its head but not its body.
    var threads: [3]std.Thread = undefined;
    relays[0].originSend(h1_response_head);
    threads[0] = try std.Thread.spawn(.{}, Http1ResponseRelay.runCapturing, .{&relays[0]});
    awaitCondition(&origin, originHoldsOneRelayBuffer);
    try std.testing.expectEqual(@as(usize, relay_buffer_bytes), origin.currentBytes(.upstream_to_downstream));

    relays[1].originSend(h1_response_head);
    threads[1] = try std.Thread.spawn(.{}, Http1ResponseRelay.runCapturing, .{&relays[1]});
    awaitCondition(&origin, originHoldsTwoRelayBuffers);
    try std.testing.expectEqual(@as(usize, 2 * relay_buffer_bytes), origin.currentBytes(.upstream_to_downstream));

    // The third meets a full origin. It is refused before its response head is
    // committed downstream, so the request can still become a clean 503.
    relays[2].originSend(h1_response_head);
    threads[2] = try std.Thread.spawn(.{}, Http1ResponseRelay.runCapturing, .{&relays[2]});
    awaitCondition(&relays[2], relayFinished);
    threads[2].join();

    try std.testing.expectEqual(@as(?anyerror, error.ProxyBufferCapacityUnavailable), relays[2].err);
    try std.testing.expectEqual(@as(usize, 0), relays[2].captured.items.len);
    // Refused at the origin scope specifically — the process scope is unlimited
    // here, so nothing but the per-origin cap could have stopped it.
    try std.testing.expectEqual(@as(u64, 1), relays[2].counters.aggregate_limit_exceeded);
    try std.testing.expectEqual(proxy_buffer_account.Scope.origin, relays[2].counters.last_aggregate_scope.?);
    try std.testing.expectEqual(@as(u64, 1), origin.limitExceededEvents(.upstream_to_downstream));
    // The cap held: the refusal never let the origin exceed it, and the two
    // admitted relays kept everything they had reserved.
    try std.testing.expectEqual(@as(usize, 2 * relay_buffer_bytes), origin.currentBytes(.upstream_to_downstream));
    try std.testing.expectEqual(@as(usize, 2 * relay_buffer_bytes), global.currentBytes(.upstream_to_downstream));

    // Let the parked relays finish; every scope must drain back to zero.
    for (relays[0..2]) |*relay| relay.originSend("body");
    threads[0].join();
    threads[1].join();

    for (relays[0..2]) |*relay| {
        try std.testing.expect(relay.err == null);
        try std.testing.expectEqual(@as(u16, 200), relay.status);
    }
    for (&relays) |*relay| try relay.expectNothingHeld();
    try std.testing.expectEqual(@as(usize, 0), origin.currentBytes(.upstream_to_downstream));
    try std.testing.expectEqual(@as(usize, 0), global.currentBytes(.upstream_to_downstream));

    // And the origin is usable again: the cap was a bound, not a latch.
    var reclaim = ProxyBufferReservation.init(.upstream_to_downstream, limits, relays[0].counters.observer(), capacity);
    try reclaim.reserve(relay_buffer_bytes);
    reclaim.releaseAll();
}

test "a cancelled http1 upload releases its origin reservation" {
    const fds = try makeBlockingSocketpair();
    const client_fd = fds[0];
    const peer_fd = fds[1];
    defer _ = std.c.close(client_fd);
    defer _ = std.c.close(peer_fd);

    var counters = UploadBufferObserver{};
    var origin = proxy_buffer_account.Aggregate.init(.origin, 64 * 1024);
    var global = proxy_buffer_account.Aggregate.init(.global, 0);

    var token = CancellationToken.init(0);
    token.cancel(.timeout);

    var source = FakeUploadSource{ .data = &[_]u8{'u'} ** 4096 };
    var reservation = try preflightUploadReservation(
        uploadTestLimits(1024 * 1024),
        counters.observer(),
        .{ .origin = &origin, .global = &global },
        http1_upload_relay_bytes,
        0,
    );
    defer reservation.releaseAll();
    try std.testing.expectEqual(@as(usize, http1_upload_relay_bytes), origin.currentBytes(.downstream_to_upstream));

    try std.testing.expectError(error.RequestCancelled, relayStreamingUploadToHttp1(
        compat.netStreamFromFd(client_fd),
        client_fd,
        .{ .framing = .{ .length = 4096 } },
        &source,
        &token,
        &reservation,
        counters.observer(),
    ));

    reservation.releaseAll();
    try std.testing.expectEqual(@as(usize, 0), counters.reserved);
    try std.testing.expectEqual(@as(usize, 0), counters.retained);
    try std.testing.expectEqual(@as(usize, 0), origin.currentBytes(.downstream_to_upstream));
    try std.testing.expectEqual(@as(usize, 0), global.currentBytes(.downstream_to_upstream));
}

// ---------------------------------------------------------------------------
// HTTP/2 response relay buffer accounting (#140).
// ---------------------------------------------------------------------------

/// An h2c origin that answers with a head plus one DATA frame and then holds
/// `END_STREAM` back. That leaves a stream whose queue is non-empty while the
/// relay is working, which is the state where the queue and the relay buffer
/// are two application-owned copies of the same bytes.
const H2GatedBodyOrigin = struct {
    listen_fd: std.posix.fd_t,
    release_end: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
};

fn h2GatedBodyServe(origin: *H2GatedBodyOrigin) void {
    const conn = std.c.accept(origin.listen_fd, null, null);
    if (conn < 0) return;
    defer _ = std.c.close(conn);

    var preface: [24]u8 = undefined;
    if (!readExactlyFromFd(conn, &preface)) return;
    const settings = [_]u8{ 0, 0, 0, 0x04, 0, 0, 0, 0, 0 };
    _ = std.c.write(conn, &settings, settings.len);

    var stream_id: u32 = 0;
    while (stream_id == 0) {
        var hdr: [9]u8 = undefined;
        if (!readExactlyFromFd(conn, &hdr)) return;
        const payload_len = (@as(usize, hdr[0]) << 16) | (@as(usize, hdr[1]) << 8) | @as(usize, hdr[2]);
        const typ = hdr[3];
        const sid = std.mem.readInt(u32, hdr[5..9], .big) & 0x7fff_ffff;
        var scratch: [4096]u8 = undefined;
        var remaining = payload_len;
        while (remaining > 0) {
            const take = @min(remaining, scratch.len);
            if (!readExactlyFromFd(conn, scratch[0..take])) return;
            remaining -= take;
        }
        if (typ == 0x01) stream_id = sid; // HEADERS
    }

    var head_frame = [_]u8{ 0, 0, 1, 0x01, 0x04, 0, 0, 0, 0, 0x88 };
    std.mem.writeInt(u32, head_frame[5..9], stream_id, .big);
    _ = std.c.write(conn, &head_frame, head_frame.len);

    // DATA without END_STREAM: the relay has bytes to move but the message is
    // not over, so the stream stays alive while the downstream write blocks.
    var body_frame = [_]u8{ 0, 0, 2, 0x00, 0x00, 0, 0, 0, 0, 'h', 'i' };
    std.mem.writeInt(u32, body_frame[5..9], stream_id, .big);
    _ = std.c.write(conn, &body_frame, body_frame.len);

    while (!origin.release_end.load(.acquire)) sleepMs(5);

    var end_frame = [_]u8{ 0, 0, 0, 0x00, 0x01, 0, 0, 0, 0 };
    std.mem.writeInt(u32, end_frame[5..9], stream_id, .big);
    _ = std.c.write(conn, &end_frame, end_frame.len);

    var drain: [256]u8 = undefined;
    while (true) {
        const got = std.c.read(conn, &drain, drain.len);
        if (got <= 0) break;
    }
}

/// A downstream client that stops reading once the response head has arrived,
/// standing in for a slow consumer. It parks the relay inside the body write —
/// after the bytes have been copied into the relay buffer and before
/// `acknowledgeStreamingBody` releases the queue's reservation, which is
/// exactly the window where both copies are owned at once.
const GatedChunkWriter = struct {
    captured: *std.array_list.Managed(u8),
    head_done: *std.atomic.Value(bool),
    blocked: *std.atomic.Value(bool),
    release: *std.atomic.Value(bool),

    fn gate(self: GatedChunkWriter) void {
        if (!self.head_done.load(.acquire)) return;
        self.blocked.store(true, .release);
        while (!self.release.load(.acquire)) sleepMs(2);
    }

    fn noteHeadEnd(self: GatedChunkWriter) void {
        if (std.mem.endsWith(u8, self.captured.items, "\r\n\r\n")) self.head_done.store(true, .release);
    }

    pub fn writeAll(self: GatedChunkWriter, bytes: []const u8) !void {
        self.gate();
        try self.captured.appendSlice(bytes);
        self.noteHeadEnd();
    }

    pub fn print(self: GatedChunkWriter, comptime fmt: []const u8, args: anytype) !void {
        self.gate();
        var buf: [64]u8 = undefined;
        try self.captured.appendSlice(try std.fmt.bufPrint(&buf, fmt, args));
        self.noteHeadEnd();
    }
};

const H2GatedExchangeCtx = struct {
    pool: *http.upstream_h2.H2ConnPool,
    port: u16,
    uri: std.Uri,
    read_buf: []u8,
    captured: *std.array_list.Managed(u8),
    security: *const http.security_headers.SecurityHeaders,
    limits: proxy_buffer_account.Limits,
    observer: proxy_buffer_account.Observer,
    global: *proxy_buffer_account.Aggregate,
    head_done: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    blocked: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    release: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    finished: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    failed: bool = false,
    status: u16 = 0,
};

fn runH2GatedExchangeThread(ctx: *H2GatedExchangeCtx) void {
    defer ctx.finished.store(true, .release);
    var source = FakeUploadSource{ .data = "" };
    const result = streamViaH2Pool(
        std.testing.allocator,
        ctx.pool,
        null,
        "127.0.0.1",
        ctx.port,
        null, // prior-knowledge h2c
        ctx.uri,
        "GET",
        &.{},
        "",
        null, // no upload: this is about the response relay buffer
        ctx.read_buf,
        &source,
        GatedChunkWriter{
            .captured = ctx.captured,
            .head_done = &ctx.head_done,
            .blocked = &ctx.blocked,
            .release = &ctx.release,
        },
        ctx.security,
        null,
        null,
        "h2-response-buffer-test",
        2000,
        10_000,
        null,
        ctx.limits,
        ctx.observer,
        ctx.global,
    ) catch {
        ctx.failed = true;
        return;
    };
    ctx.status = result.status_code;
}

test "an http2 response relay buffer is charged to the aggregate scopes while it relays" {
    const listener = try listenLoopbackEphemeral();
    defer _ = std.c.close(listener.fd);

    var origin_server = H2GatedBodyOrigin{ .listen_fd = listener.fd };
    const origin_thread = try std.Thread.spawn(.{}, h2GatedBodyServe, .{&origin_server});

    // Large enough that the stream queue's own retained allocation for two
    // body bytes cannot be mistaken for it.
    var read_buf: [64 * 1024]u8 = undefined;
    const limits = uploadTestLimits(1024 * 1024);
    // Room for two relay buffers. One is what the exchange takes; the second
    // is what a concurrent response would need, and must no longer be
    // available while this one is relaying.
    var global = proxy_buffer_account.Aggregate.init(.global, 2 * read_buf.len);

    var counters = UploadBufferObserver{};
    var captured = std.array_list.Managed(u8).init(std.testing.allocator);
    defer captured.deinit();
    var security = http.security_headers.SecurityHeaders{};
    var url_buf: [64]u8 = undefined;
    const uri = try std.Uri.parse(try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/download", .{listener.port}));

    var pool = http.upstream_h2.H2ConnPool.init(std.testing.allocator, .{
        .proxy_buffer_limits = blk: {
            var origin_limits = limits;
            origin_limits.per_origin_hard_limit = 2 * read_buf.len;
            break :blk origin_limits;
        },
    });
    // The same account the exchange will reserve against: the pool hands out a
    // pointer that is stable for its lifetime, so reading it here observes the
    // origin scope the relay is actually charged to rather than a stand-in.
    var origin_key_buf: [64]u8 = undefined;
    const origin_key = try std.fmt.bufPrint(&origin_key_buf, "h2c:127.0.0.1:{d}", .{listener.port});
    const origin = try pool.originBufferAccount(origin_key);

    var ctx = H2GatedExchangeCtx{
        .pool = &pool,
        .port = listener.port,
        .uri = uri,
        .read_buf = &read_buf,
        .captured = &captured,
        .security = &security,
        .limits = limits,
        .observer = counters.observer(),
        .global = &global,
    };
    const exchange = try std.Thread.spawn(.{}, runH2GatedExchangeThread, .{&ctx});

    // The client has the head and has stopped reading; the relay is parked
    // inside the body write, holding the relay buffer, with the queue's
    // reservation not yet acknowledged.
    var waited: u32 = 0;
    while (!ctx.blocked.load(.acquire) and waited < 10_000) : (waited += 5) sleepMs(5);
    try std.testing.expect(ctx.blocked.load(.acquire));

    // The relay buffer is represented in the process aggregate. Before it was
    // charged, this read only the stream queue's retained bytes for a two-byte
    // body, which is nowhere near a relay buffer.
    try std.testing.expect(global.currentBytes(.upstream_to_downstream) >= read_buf.len);
    // The origin scope carries it too, so one slow origin's relay buffers are
    // contained by its own limit and not only by the process ceiling.
    try std.testing.expect(origin.currentBytes(.upstream_to_downstream) >= read_buf.len);

    // And the ceiling actually accounts for it: a concurrent response needing
    // its own relay buffer no longer fits, which is the whole point — N slow
    // responses used to be able to hold N relay buffers beyond the configured
    // limit with nothing in the accounting to show for it.
    var other = UploadBufferObserver{};
    var concurrent = ProxyBufferReservation.init(
        .upstream_to_downstream,
        limits,
        other.observer(),
        .{ .global = &global },
    );
    try std.testing.expectError(
        error.ProxyBufferCapacityUnavailable,
        concurrent.reserve(read_buf.len),
    );
    try std.testing.expectEqual(@as(u64, 1), other.aggregate_limit_exceeded);

    // Let the client drain and the origin finish the message.
    ctx.release.store(true, .release);
    origin_server.release_end.store(true, .release);
    exchange.join();
    try std.testing.expect(!ctx.failed);
    try std.testing.expectEqual(@as(u16, 200), ctx.status);

    // Every scope returns to zero once the exchange ends. Read before
    // `pool.deinit()`, which frees the origin accounts.
    try std.testing.expectEqual(@as(usize, 0), origin.currentBytes(.upstream_to_downstream));
    try std.testing.expectEqual(@as(usize, 0), origin.currentBytes(.downstream_to_upstream));
    pool.deinit();
    origin_thread.join();

    try std.testing.expectEqual(@as(usize, 0), global.currentBytes(.upstream_to_downstream));
    try std.testing.expectEqual(@as(usize, 0), global.currentBytes(.downstream_to_upstream));
    try std.testing.expectEqual(@as(usize, 0), counters.reserved);
    try std.testing.expectEqual(@as(usize, 0), counters.retained);
    // The body really did reach the client, so this measured a working relay.
    try std.testing.expect(std.mem.find(u8, captured.items, "hi") != null);
}

test "an http2 stream cannot own more than its per-stream hard limit across queue and relay" {
    // The queue and the relay buffer are live at the same time, so each having
    // its own per-stream budget let one stream own two hard limits' worth with
    // neither budget reporting an exceedance. They now share one.
    const listener = try listenLoopbackEphemeral();
    defer _ = std.c.close(listener.fd);

    var origin_server = H2GatedBodyOrigin{ .listen_fd = listener.fd };
    const origin_thread = try std.Thread.spawn(.{}, h2GatedBodyServe, .{&origin_server});

    var read_buf: [16 * 1024]u8 = undefined;
    // A policy sized exactly the way config validation now requires: the hard
    // limit covers one full window plus one relay buffer, and no more. That
    // makes the shared budget's ceiling observable — anything above
    // `high + relay` would have to come from double-budgeting.
    const high = 16 * 1024;
    const limits = proxy_buffer_account.Limits{
        .per_stream_low_watermark = high / 2,
        .per_stream_high_watermark = high,
        .per_stream_hard_limit = high + read_buf.len,
        .per_origin_hard_limit = 0,
        .global_hard_limit = 0,
    };
    // Generous aggregates: this test is about the per-stream budget, so
    // nothing else may be what refuses.
    var global = proxy_buffer_account.Aggregate.init(.global, 0);

    var counters = UploadBufferObserver{};
    var captured = std.array_list.Managed(u8).init(std.testing.allocator);
    defer captured.deinit();
    var security = http.security_headers.SecurityHeaders{};
    var url_buf: [64]u8 = undefined;
    const uri = try std.Uri.parse(try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/download", .{listener.port}));

    var pool = http.upstream_h2.H2ConnPool.init(std.testing.allocator, .{ .proxy_buffer_limits = limits });
    var ctx = H2GatedExchangeCtx{
        .pool = &pool,
        .port = listener.port,
        .uri = uri,
        .read_buf = &read_buf,
        .captured = &captured,
        .security = &security,
        .limits = limits,
        .observer = counters.observer(),
        .global = &global,
    };
    const exchange = try std.Thread.spawn(.{}, runH2GatedExchangeThread, .{&ctx});

    var waited: u32 = 0;
    while (!ctx.blocked.load(.acquire) and waited < 10_000) : (waited += 5) sleepMs(5);
    try std.testing.expect(ctx.blocked.load(.acquire));

    // Parked mid-relay with both copies owned. The process gauge sees the
    // relay buffer and the queue's retained storage together, and that total
    // must be inside the one per-stream hard limit rather than inside two.
    const owned = global.currentBytes(.upstream_to_downstream);
    try std.testing.expect(owned >= read_buf.len); // the relay buffer is in there
    try std.testing.expect(owned <= limits.per_stream_hard_limit);

    ctx.release.store(true, .release);
    origin_server.release_end.store(true, .release);
    exchange.join();
    try std.testing.expect(!ctx.failed);
    try std.testing.expectEqual(@as(u16, 200), ctx.status);

    pool.deinit();
    origin_thread.join();

    try std.testing.expectEqual(@as(usize, 0), global.currentBytes(.upstream_to_downstream));
    try std.testing.expectEqual(@as(usize, 0), counters.reserved);
    try std.testing.expectEqual(@as(usize, 0), counters.retained);
}

test "an http2 stream budget refuses the relay buffer before the response is committed" {
    // The other side of the shared budget: when the stream's own limit has no
    // room for the relay buffer, the refusal has to land *before* the response
    // head is written, so the request can still become a clean 503 rather than
    // a committed status that gets truncated.
    const limits = proxy_buffer_account.Limits{
        .per_stream_low_watermark = 4 * 1024,
        .per_stream_high_watermark = 8 * 1024,
        .per_stream_hard_limit = 24 * 1024,
        .per_origin_hard_limit = 0,
        .global_hard_limit = 0,
    };
    var counters = UploadBufferObserver{};
    var stream_budget = proxy_buffer_account.Aggregate.init(.stream, limits.per_stream_hard_limit);
    const capacity = proxy_buffer_account.AggregateCapacity{ .stream = &stream_budget };

    // Stand in for a queue that has already taken most of the stream's budget.
    try stream_budget.reserve(.upstream_to_downstream, 16 * 1024);

    var relay = ProxyBufferReservation.init(.upstream_to_downstream, limits, counters.observer(), capacity);
    try std.testing.expectError(
        error.ProxyBufferCapacityUnavailable,
        relay.reserve(16 * 1024),
    );
    // Refused at the stream scope specifically — no aggregate above it is even
    // configured here, so nothing else could have refused it.
    try std.testing.expectEqual(@as(u64, 1), counters.aggregate_limit_exceeded);
    try std.testing.expectEqual(proxy_buffer_account.Scope.stream, counters.last_aggregate_scope.?);
    // The refusal rolled back cleanly; the queue's claim is untouched.
    try std.testing.expectEqual(@as(usize, 16 * 1024), stream_budget.currentBytes(.upstream_to_downstream));

    stream_budget.release(.upstream_to_downstream, 16 * 1024);
    try std.testing.expectEqual(@as(usize, 0), stream_budget.currentBytes(.upstream_to_downstream));
    try std.testing.expectEqual(@as(usize, 0), counters.reserved);
}

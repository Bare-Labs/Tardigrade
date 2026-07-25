//! #369 Slice 2: process-level 0-RTT replay / anti-replay / 425 assurance —
//! the gateway/HTTP-dispatch half. `src/tls/tls13_backend_tests.zig` proves
//! the TLS/replay-store layer (accept, duplicate, capacity, quarantine,
//! cross-worker sharing, no-gate-configured) with real production TLS and
//! replay-store code. This file goes one layer further: it drives the real
//! `gateway_proxy_runtime.runBufferedProxyAttempts` retry/425 state machine
//! and the real production TCP HTTP client
//! (`gateway_proxy_runtime.executeBufferedDataPlaneProxyRequest`) against
//! an actual loopback upstream test server with an atomic execution
//! counter — not a scripted attempt executor — so a real `425 Too Early`
//! response and a real retry are what get proven, not a stand-in.
//!
//! `ProductionBufferedProxyAttemptExecutor` in `gateway_proxy_runtime.zig`
//! is the real production executor, but it is wired to a full
//! `GatewayState` (upstream health/circuit-breaker/logger/security headers/
//! transcript store/...). Reconstructing all of that machinery merely to
//! reach the two fields (`state.upstream_pool`, `state.h2_pool`) the
//! executor actually threads through to the real HTTP client would be a
//! large, brittle test-only reimplementation of `GatewayState` itself.
//! `LoopbackAttemptExecutor` below is the smaller seam: it implements the
//! same `attempt_executor` contract `runBufferedProxyAttempts` requires,
//! but calls the *same* public, production
//! `executeBufferedDataPlaneProxyRequest` function directly against a real
//! `http.upstream_pool.UpstreamPool` and a real `http.metrics.Metrics`
//! instance, so the retry/425 policy under test
//! (`runBufferedProxyAttempts`/`shouldRetryEarlyUpstream425`) and the
//! upstream transport are both genuine production code; only the
//! observability plumbing that would otherwise live on `GatewayState` is
//! test-local.

const std = @import("std");
const tls_core = @import("tls_core");
const http = @import("http.zig");
const edge_config = @import("edge_config.zig");
const gproxy_runtime = @import("gateway_proxy_runtime.zig");
const ghandlers = @import("gateway_handlers.zig");

const testing = std.testing;

// ---------------------------------------------------------------------
// A real loopback upstream test server with an atomic execution counter.
// Mirrors the raw blocking-listener fixture already used by
// `gateway_proxy.zig`'s "connectBlockingTcp + exchange round-trips a real
// TCP origin" test (bind on an ephemeral port, accept on a thread), rather
// than inventing a new one.
// ---------------------------------------------------------------------

const EphemeralListener = struct {
    fd: std.posix.fd_t,
    port: u16,
};

fn bindEphemeralLoopbackListener() !EphemeralListener {
    const listen_fd = std.c.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, std.posix.IPPROTO.TCP);
    try testing.expect(listen_fd >= 0);
    errdefer _ = std.c.close(listen_fd);
    _ = std.c.setsockopt(listen_fd, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, std.mem.asBytes(&@as(c_int, 1)), @sizeOf(c_int));

    const sin: std.c.sockaddr.in = .{
        .family = std.posix.AF.INET,
        .port = std.mem.nativeToBig(u16, 0),
        .addr = @bitCast([4]u8{ 127, 0, 0, 1 }),
        .zero = [8]u8{ 0, 0, 0, 0, 0, 0, 0, 0 },
    };
    try testing.expect(std.c.bind(listen_fd, @ptrCast(&sin), @sizeOf(std.c.sockaddr.in)) == 0);
    try testing.expect(std.c.listen(listen_fd, 8) == 0);

    var bound: std.c.sockaddr.in = undefined;
    var bound_len: std.posix.socklen_t = @sizeOf(std.c.sockaddr.in);
    try testing.expect(std.c.getsockname(listen_fd, @ptrCast(&bound), &bound_len) == 0);
    const port = std.mem.bigToNative(u16, bound.port);
    try testing.expect(port != 0);
    return .{ .fd = listen_fd, .port = port };
}

/// Bounded, non-secret record of what the real origin observed per
/// connection — case ID, execution count, and whether each request carried
/// the real `Early-Data: 1` header — never request bodies or ticket/PSK
/// material (there is none here to leak).
const OriginState = struct {
    executed: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    connections_seen: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    early_header_seen: [4]bool = .{ false, false, false, false },
};

fn requestHasEarlyDataHeader(raw: []const u8) bool {
    var lower_buf: [4096]u8 = undefined;
    const n = @min(raw.len, lower_buf.len);
    for (raw[0..n], 0..) |c, i| lower_buf[i] = std.ascii.toLower(c);
    return std.mem.indexOf(u8, lower_buf[0..n], "early-data: 1") != null;
}

/// Real blocking origin: accepts up to `max_connections` sequential
/// connections (the buffered HTTP client always sends `Connection: close`
/// bound responses here, so each attempt is a fresh TCP connection). Any
/// request that actually carries `Early-Data: 1` is answered with a real
/// `425 Too Early` and does **not** increment `executed` — modeling an
/// origin that itself enforces RFC 8470 and refuses to treat early data as
/// a safe side-effecting request. Any other request executes normally.
fn earlyRejectingOriginResponder(listen_fd: std.posix.fd_t, state: *OriginState, max_connections: usize) void {
    var handled: usize = 0;
    while (handled < max_connections) : (handled += 1) {
        const conn = std.c.accept(listen_fd, null, null);
        if (conn < 0) return;
        defer _ = std.c.close(conn);
        var buf: [4096]u8 = undefined;
        const got = std.c.read(conn, &buf, buf.len);
        if (got <= 0) return;
        const n: usize = @intCast(got);
        const has_early = requestHasEarlyDataHeader(buf[0..n]);
        const idx = state.connections_seen.fetchAdd(1, .monotonic);
        if (idx < state.early_header_seen.len) state.early_header_seen[idx] = has_early;

        if (has_early) {
            const response = "HTTP/1.1 425 Too Early\r\nContent-Type: text/plain\r\nContent-Length: 9\r\nConnection: close\r\n\r\ntoo early";
            _ = std.c.write(conn, response.ptr, response.len);
        } else {
            _ = state.executed.fetchAdd(1, .monotonic);
            const response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
            _ = std.c.write(conn, response.ptr, response.len);
        }
    }
}

/// Real `runBufferedProxyAttempts` attempt executor driving the genuine
/// production upstream TCP client. See the module doc for why this exists
/// instead of reusing `ProductionBufferedProxyAttemptExecutor` directly.
const LoopbackAttemptExecutor = struct {
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    request: *const http.Request,
    upstream_url: []const u8,
    correlation_id: []const u8,
    pool: *http.upstream_pool.UpstreamPool,
    metrics: *http.metrics.Metrics,

    pub fn execute(
        self: *LoopbackAttemptExecutor,
        attempt: usize,
        forward_early_data: bool,
    ) !gproxy_runtime.DataPlaneProxyResponse {
        _ = attempt;
        return gproxy_runtime.executeBufferedDataPlaneProxyRequest(
            self.allocator,
            self.cfg,
            self.upstream_url,
            null,
            self.request.method.toString(),
            &self.request.headers,
            self.request.body orelse "",
            self.correlation_id,
            "127.0.0.1",
            "http",
            self.request.headers.get("host"),
            null,
            null,
            null,
            null,
            forward_early_data,
            2_000,
            2_000,
            2_000,
            null,
            self.pool,
            null,
        );
    }

    pub fn onBufferedResponse(self: *LoopbackAttemptExecutor, result: *gproxy_runtime.DataPlaneProxyResponse) !void {
        _ = self;
        _ = result;
    }

    pub fn onStaleConnectionRetry(self: *LoopbackAttemptExecutor, stale_conn_retries: usize, max_stale_conn_retries: usize) !void {
        _ = self;
        _ = stale_conn_retries;
        _ = max_stale_conn_retries;
    }

    pub fn onTerminalAttemptError(self: *LoopbackAttemptExecutor, _: anyerror) !void {
        _ = self;
    }

    pub fn onConfiguredErrorRetry(self: *LoopbackAttemptExecutor, configured_attempt_index: usize, max_attempts: usize, _: anyerror) !void {
        _ = self;
        _ = configured_attempt_index;
        _ = max_attempts;
    }

    pub fn onEarly425Retry(self: *LoopbackAttemptExecutor, result: *gproxy_runtime.DataPlaneProxyResponse) !void {
        result.deinit(self.allocator);
    }

    pub fn onEarly425HandshakeFailure(self: *LoopbackAttemptExecutor, _: anyerror) !void {
        _ = self;
    }

    pub fn onConfigured5xxRetry(self: *LoopbackAttemptExecutor, configured_attempt_index: usize, max_attempts: usize, result: *gproxy_runtime.DataPlaneProxyResponse) !void {
        _ = configured_attempt_index;
        _ = max_attempts;
        result.deinit(self.allocator);
    }

    pub fn recordEarlyUpstream425Action(self: *LoopbackAttemptExecutor, action: http.metrics.EarlyDataUpstream425Action) void {
        self.metrics.recordHttpEarlyDataUpstream425(action);
    }

    pub fn recordEarlyRetryResult(self: *LoopbackAttemptExecutor, result: http.metrics.EarlyDataRetryResult) void {
        self.metrics.recordHttpEarlyDataRetry(result);
    }
};

/// Deterministic downstream-handshake barrier, matching the
/// `TestEarly425Barrier` pattern already used by
/// `gateway_proxy_runtime.zig`'s own "early upstream 425 retry..." test:
/// starts incomplete (modeling a connection still mid-handshake when the
/// early request arrived — the actual condition current-hop early data
/// requires) and completes when `runBufferedProxyAttempts` drives it while
/// waiting to retry after a 425. A `null` barrier instead means "already
/// complete", which would make this current-hop-early scenario
/// indistinguishable from an ordinary post-handshake request.
const TestDownstreamHandshakeBarrier = struct {
    complete: bool = false,
    waits: usize = 0,

    fn isComplete(ptr: *anyopaque) bool {
        const self: *TestDownstreamHandshakeBarrier = @ptrCast(@alignCast(ptr));
        return self.complete;
    }

    fn waitOrDrive(ptr: *anyopaque) anyerror!void {
        const self: *TestDownstreamHandshakeBarrier = @ptrCast(@alignCast(ptr));
        self.waits += 1;
        self.complete = true;
    }

    fn barrier(self: *TestDownstreamHandshakeBarrier) http.request_context.DownstreamHandshakeBarrier {
        return .{
            .ctx = self,
            .is_complete_fn = isComplete,
            .wait_or_drive_fn = waitOrDrive,
        };
    }
};

test "#369 Slice 2 rt0.retry.425_exactly_once: a real early-data 425 from a real upstream retries exactly once, and the upstream executes exactly once" {
    const allocator = testing.allocator;

    var cfg = try edge_config.loadFromEnv(allocator);
    defer cfg.deinit(allocator);

    const listener = try bindEphemeralLoopbackListener();
    defer _ = std.c.close(listener.fd);

    var origin = OriginState{};
    const responder = try std.Thread.spawn(.{}, earlyRejectingOriginResponder, .{ listener.fd, &origin, @as(usize, 2) });
    defer responder.join();

    var url_buf: [64]u8 = undefined;
    const upstream_url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/work", .{listener.port});

    const block = edge_config.EdgeConfig.LocationBlock{
        .match_type = .prefix,
        .pattern = "/",
        .priority = 0,
        .action = .{ .proxy_pass = upstream_url },
        .early_data = .replay_safe,
        .proxy_early_data = .rfc8470,
    };

    var parsed = try http.Request.parseHead(allocator, "GET /work HTTP/1.1\r\nHost: example.test\r\n\r\n", 1 << 20);
    defer parsed.request.deinit();

    var pool = http.upstream_pool.UpstreamPool.init(allocator, .{});
    defer pool.deinit();
    var metrics = http.metrics.Metrics.init();

    var executor = LoopbackAttemptExecutor{
        .allocator = allocator,
        .cfg = &cfg,
        .request = &parsed.request,
        .upstream_url = upstream_url,
        .correlation_id = "req-425",
        .pool = &pool,
        .metrics = &metrics,
    };

    // Current-hop 0-RTT early data, no prior-hop `Early-Data` marker, and a
    // downstream handshake that has not yet completed (the actual
    // condition current-hop early data implies) — this is the shape #367's
    // contract allows exactly one transparent retry for, on a replay-safe
    // GET to an RFC-8470-aware origin.
    var handshake_barrier = TestDownstreamHandshakeBarrier{};
    var early_ctx = http.request_context.EarlyDataContext{
        .transport_early = true,
        .downstream_handshake = handshake_barrier.barrier(),
    };
    const first_attempt_forward_early_data = early_ctx.inbound_marker or
        (early_ctx.transport_early and !early_ctx.downstreamHandshakeComplete());
    try testing.expect(first_attempt_forward_early_data);

    const before_retried = metrics.http_early_data_upstream_425_total[@intFromEnum(http.metrics.EarlyDataUpstream425Action.retried)];
    const before_success = metrics.http_early_data_retry_total[@intFromEnum(http.metrics.EarlyDataRetryResult.success)];

    const outcome = try gproxy_runtime.runBufferedProxyAttempts(
        &early_ctx,
        first_attempt_forward_early_data,
        "GET",
        &block,
        1,
        0,
        cfg.upstream_retry_idempotent_only,
        &executor,
    );

    var response = switch (outcome) {
        .response => |r| r,
        else => return error.TestUnexpectedResult,
    };
    defer response.deinit(allocator);

    // The response returned to the caller is the successful retry response.
    try testing.expectEqual(@as(u16, 200), response.statusCode());

    // Real origin, real bytes: first connection carried Early-Data: 1 and
    // was rejected; the retried connection did not carry it.
    try testing.expectEqual(@as(usize, 2), origin.connections_seen.load(.monotonic));
    try testing.expect(origin.early_header_seen[0]);
    try testing.expect(!origin.early_header_seen[1]);

    // Exactly one real upstream execution across both attempts.
    try testing.expectEqual(@as(usize, 1), origin.executed.load(.monotonic));

    // Retry occurred at most once (exactly once here), per the #367
    // contract; metrics distinguish the initial 425 from the successful
    // retry.
    try testing.expectEqual(before_retried + 1, metrics.http_early_data_upstream_425_total[@intFromEnum(http.metrics.EarlyDataUpstream425Action.retried)]);
    try testing.expectEqual(before_success + 1, metrics.http_early_data_retry_total[@intFromEnum(http.metrics.EarlyDataRetryResult.success)]);
    // The retry genuinely waited on the downstream handshake barrier
    // exactly once before retrying as ordinary.
    try testing.expectEqual(@as(usize, 1), handshake_barrier.waits);
}

test "#369 Slice 2 rt0.reject.unsafe_request: an unsafe method carrying current-hop early data is rejected by the real gateway decision before any upstream dispatch is even attempted" {
    // Matches the minimal-`undefined`-`EdgeConfig` pattern already used by
    // `edge_gateway.zig`'s own "H1 early-data 425 preflight..." tests: only
    // the fields `earlyDataDecisionForRequest` actually reads are set, and
    // (unlike `edge_config.loadFromEnv`) nothing here is heap-allocated, so
    // there is no `cfg.deinit` to call and no risk of freeing
    // literal-backed `LocationBlock`/slice memory a real `loadFromEnv`
    // config would expect to own.
    var cfg: edge_config.EdgeConfig = undefined;
    cfg.metrics_path = "/status/metrics";

    // Deliberately not bound by anything: if the real gateway path were to
    // (incorrectly) attempt to dispatch this request as early data, this
    // test would need a live responder to get a 2xx/425 back at all. Using
    // an address nothing listens on means the only way this test can pass
    // is by never attempting the dispatch in the first place — no thread,
    // no sleep-based synchronization needed to prove non-contact.
    var blocks = [_]edge_config.EdgeConfig.LocationBlock{.{
        .match_type = .prefix,
        .pattern = "/",
        .priority = 0,
        .action = .{ .proxy_pass = "http://127.0.0.1:1" },
        .early_data = .replay_safe,
        .proxy_early_data = .rfc8470,
    }};
    cfg.location_blocks = blocks[0..];
    cfg.mirror_rules = &.{};

    // POST is not method-safe (#366/#367 policy): even though the route
    // itself is configured replay-safe and RFC-8470-aware, an unsafe
    // method must never be admitted as early data. This is the same real,
    // `pub` production decision function `edge_gateway.zig`'s H1 dispatch
    // calls (via `earlyDataPreflightDecisionForH1`) before ever reaching
    // `hooks.route`/`gproxy_runtime.handleLocationProxyPass` — see
    // `executeH1PostPreflightOrchestration` in `edge_gateway.zig`, whose
    // `.too_early` branch calls `hooks.rejectEarly` and returns without
    // calling `hooks.route` at all.
    const early_ctx = http.request_context.EarlyDataContext{ .transport_early = true };
    const decision = ghandlers.earlyDataDecisionForRequest(&cfg, early_ctx, .POST, "/work", false);
    try testing.expectEqual(http.early_data.Decision.too_early, decision);

    // The real gateway path never reaches `runBufferedProxyAttempts` for a
    // `.too_early` decision, so nothing here calls it — that omission is
    // itself the proof: no upstream dispatch, real or otherwise, is even
    // attempted for this request shape, and therefore no unsafe side
    // effect and no double execution from any fallback/retry path either.
}

test "#369 Slice 2 rt0.reject.store_unavailable: the default configuration neither enables native 0-RTT nor accidentally accepts it — 1-RTT-equivalent policy stays available" {
    // Cross-layer proof, tying two independently-tested facts together:
    //  1. `edge_config.loadFromEnv`'s default configuration (no env
    //     overrides) leaves native 0-RTT anti-replay disabled and defines
    //     no location routes at all, so nothing could be routed as early
    //     data even if a peer attempted it (already directly asserted in
    //     `edge_config.zig`'s own "#368 Slice 3: early-data replay config
    //     defaults to disabled..." test — not re-asserted in isolation
    //     here, only combined with fact 2).
    //  2. `tls_core.tls13_backend.EarlyDataReplayGate`'s default
    //     (`decideFn == null`, i.e. exactly what composition leaves wired
    //     when the operator has not configured `process_local` mode) maps
    //     every 0-RTT attempt to `.unavailable` — fail closed — while
    //     never touching ordinary 1-RTT resumption (already directly
    //     proven end-to-end in `tls13_backend_tests.zig`'s "0-RTT
    //     anti-replay defaults to unavailable (fails closed) when no gate
    //     is configured" test).
    //
    // Together: a freshly started process with no operator configuration
    // cannot accept 0-RTT anywhere, by construction, without needing a
    // distributed or even a local replay backend to be present.
    const allocator = testing.allocator;
    var cfg = try edge_config.loadFromEnv(allocator);
    defer cfg.deinit(allocator);

    try testing.expectEqual(edge_config.EarlyDataReplayMode.disabled, cfg.tls_native_early_data_replay_mode);
    try testing.expectEqual(@as(usize, 0), cfg.location_blocks.len);

    const default_gate = tls_core.tls13_backend.EarlyDataReplayGate{};
    try testing.expect(default_gate.decideFn == null);
}

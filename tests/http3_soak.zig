//! Bounded production H3 soak test (#247 Lane B).
//!
//! Drives `http.http3_runtime.Runtime` -- the same module `edge_gateway.zig`
//! wires into the live listener -- over real loopback UDP sockets with
//! several concurrent clients, each doing repeated connect -> multiple
//! requests -> clean close cycles, then asserts a bounded settle window
//! returns tracked connection/CID state to baseline with no unbounded
//! resident-memory or file-descriptor growth. See the "Bounded Soak
//! Contract" in docs/HTTP3_VALIDATION_EVIDENCE.md for the pass condition
//! this implements.
//!
//! `TARDIGRADE_SOAK_HEAVY=1` scales the round count from the PR-safe default
//! up to a heavier tier, the same convention `tests/integration.zig`'s
//! `soakHeavyEnabled` uses for its TLS-resumption soaks -- reimplemented
//! here rather than shared because this file is a separate build module
//! (it needs the `quic`/`http3`/`http3_runtime` imports that
//! `tests/integration.zig` does not have).
//!
//! Composition boundary (stated once rather than per assertion): this
//! harness constructs `http3_runtime.Runtime` directly with a synchronous
//! test handler, not the full `GatewayState`-wired production binary. It can
//! observe the runtime's own connection/CID/handshake/retry counters, but
//! not QPACK dynamic-table state, PTO totals, or worker-pool queue depth --
//! those are recorded onto `http.metrics.Metrics` only by the `GatewayState`
//! composition layer above this runtime. Reopen a QPACK/PTO/worker-queue
//! soak row only if that layer's own tests reveal a composition-specific gap
//! this harness could close. Likewise, active drain with an in-flight
//! request is already proven by "udp smoke: HTTP/3 runtime drain lets
//! admitted work finish and rejects new work" in `quic_h3_udp_smoke.zig`;
//! this file does not duplicate it. Controlled loss/reordering and
//! resumption/0-RTT reconnects are out of scope here too: the former needs a
//! dedicated host with netem/`CAP_NET_ADMIN` (see
//! `benchmarks/competitive/netem-impair.sh`), and this harness's `Config`
//! does not wire a `resumption_runtime`, so every reconnect here is a full
//! fresh handshake, not a resumed one.

const std = @import("std");
const quic = @import("quic");
const test_quic_crypto = @import("test_quic_crypto");
const http3 = @import("http3");
const tls_core = @import("tls_core");
const http3_runtime = @import("http3_runtime");
const compat = @import("zig_compat");
// Relative sibling import (like `tests/integration.zig`'s own use of this
// file): reuses the already-hardened spawn/wait/reap contract -- bounded
// deadline, process-group cleanup, size-capped stdout/stderr -- instead of
// `std.process.Child.run`, which does not exist in this Zig 0.16 std (its
// replacement is the `Io`-based `std.process.spawn` this module already
// wraps).
const bounded_process = @import("bounded_process.zig");

const connection = quic.connection;
const tls_backend = quic.tls_backend;
const Connection = connection.Connection;
const H3 = http3.conn.Conn(Connection);

const testing = std.testing;
const posix = std.posix;

const requests_per_round: usize = 2;
const worker_count: usize = 4;

fn soakHeavyEnabled() bool {
    const value = compat.getEnvVarOwned(std.heap.page_allocator, "TARDIGRADE_SOAK_HEAVY") catch return false;
    defer std.heap.page_allocator.free(value);
    return std.mem.eql(u8, value, "1");
}

// ---------------------------------------------------------------------------
// Loopback UDP socket helper -- duplicated from `quic_h3_udp_smoke.zig`
// rather than shared: neither file exposes its helpers as a library import,
// matching how `h3_interop_tool.zig` also rolls its own copy of this exact
// handful of lines rather than inventing a shared micro-module for them.
// ---------------------------------------------------------------------------

const UdpSocket = struct {
    fd: std.c.fd_t,
    addr: std.c.sockaddr.in,

    fn open() !UdpSocket {
        const fd = std.c.socket(posix.AF.INET, posix.SOCK.DGRAM, posix.IPPROTO.UDP);
        if (fd < 0) return error.SocketFailed;
        errdefer _ = std.c.close(fd);
        const descriptor_flags = std.c.fcntl(fd, std.c.F.GETFD, @as(c_int, 0));
        if (descriptor_flags >= 0) _ = std.c.fcntl(fd, std.c.F.SETFD, descriptor_flags | std.c.FD_CLOEXEC);
        const status_flags = std.c.fcntl(fd, std.c.F.GETFL, @as(c_int, 0));
        if (status_flags >= 0) _ = std.c.fcntl(fd, std.c.F.SETFL, status_flags | @as(c_int, @bitCast(posix.O{ .NONBLOCK = true })));
        var bind_addr = std.c.sockaddr.in{
            .family = posix.AF.INET,
            .port = 0,
            .addr = std.mem.nativeToBig(u32, 0x7f000001),
        };
        if (std.c.bind(fd, @ptrCast(&bind_addr), @sizeOf(std.c.sockaddr.in)) != 0) return error.BindFailed;
        var bound: std.c.sockaddr.in = undefined;
        var bound_len: std.c.socklen_t = @sizeOf(std.c.sockaddr.in);
        if (std.c.getsockname(fd, @ptrCast(&bound), &bound_len) != 0) return error.GetSockNameFailed;
        return .{ .fd = fd, .addr = bound };
    }

    fn close(self: *UdpSocket) void {
        _ = std.c.close(self.fd);
    }

    fn sendTo(self: *UdpSocket, peer: std.c.sockaddr.in, bytes: []const u8) !void {
        const sent = std.c.sendto(self.fd, bytes.ptr, bytes.len, 0, @ptrCast(&peer), @sizeOf(std.c.sockaddr.in));
        if (sent < 0 or @as(usize, @intCast(sent)) != bytes.len) return error.SendFailed;
    }

    fn recv(self: *UdpSocket, buf: []u8) !?[]u8 {
        const n = std.c.recvfrom(self.fd, buf.ptr, buf.len, 0, null, null);
        if (n < 0) {
            return switch (posix.errno(n)) {
                .AGAIN => null,
                else => error.RecvFailed,
            };
        }
        return buf[0..@intCast(n)];
    }
};

fn nowUs() u64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000 + @as(u64, @intCast(ts.nsec)) / 1_000;
}

fn addressFromSockaddrIn(sa: std.c.sockaddr.in) quic.udp.Address {
    const octets: [4]u8 = @bitCast(sa.addr);
    return quic.udp.Address.ip4(octets, std.mem.bigToNative(u16, sa.port));
}

fn sockaddrInFromAddress(addr: quic.udp.Address) std.c.sockaddr.in {
    var octets: [4]u8 = undefined;
    @memcpy(&octets, addr.slice());
    return .{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, addr.port),
        .addr = @bitCast(octets),
        .zero = [_]u8{0} ** 8,
    };
}

const test_challenge_entropy = [_]u8{0x5a} ** quic.path.path_challenge_len;

// ---------------------------------------------------------------------------
// Resource sampling -- reuses the exact RSS/open-fd sampling convention
// `benchmarks/run.sh` already established (`ps -o rss=`, then `/proc/<pid>/fd`
// or `lsof` for descriptor counts) against this test process's own pid,
// rather than inventing a second convention or a raw getrusage/procfs
// binding. `ps`/`sh` are already relied on elsewhere in this test suite
// (`tests/integration.zig`'s `opensslPresentedSubject`).
// ---------------------------------------------------------------------------

fn readRssKb(allocator: std.mem.Allocator, pid: std.c.pid_t) !u64 {
    var pid_buf: [32]u8 = undefined;
    const pid_str = try std.fmt.bufPrint(&pid_buf, "{d}", .{pid});
    var result = try bounded_process.run(allocator, .{
        .argv = &.{ "ps", "-o", "rss=", "-p", pid_str },
        .stdout_limit = 4096,
        .stderr_limit = 4096,
        .deadline_ms = 5_000,
    });
    defer result.deinit(allocator);
    const trimmed = std.mem.trim(u8, result.stdout, " \t\r\n");
    return std.fmt.parseInt(u64, trimmed, 10) catch 0;
}

fn readOpenFdCount(allocator: std.mem.Allocator, pid: std.c.pid_t) !u64 {
    var pid_buf: [32]u8 = undefined;
    const pid_str = try std.fmt.bufPrint(&pid_buf, "{d}", .{pid});
    const script = try std.fmt.allocPrint(allocator,
        \\if [ -d /proc/{s}/fd ]; then
        \\  find /proc/{s}/fd -maxdepth 1 -type l 2>/dev/null | wc -l | tr -d ' '
        \\elif command -v lsof >/dev/null 2>&1; then
        \\  lsof -n -P -p {s} 2>/dev/null | awk 'NR>1{{count+=1}} END{{print count+0}}'
        \\else
        \\  echo 0
        \\fi
    , .{ pid_str, pid_str, pid_str });
    defer allocator.free(script);
    var result = try bounded_process.run(allocator, .{
        .argv = &.{ "sh", "-c", script },
        .stdout_limit = 4096,
        .stderr_limit = 4096,
        .deadline_ms = 5_000,
    });
    defer result.deinit(allocator);
    const trimmed = std.mem.trim(u8, result.stdout, " \t\r\n");
    return std.fmt.parseInt(u64, trimmed, 10) catch 0;
}

const ResourceSample = struct {
    label: []const u8,
    rss_kb: u64,
    open_fds: u64,
    tracked_connections: usize,
    active_cid_routes: usize,
    native_connections: usize,
};

fn sampleResources(allocator: std.mem.Allocator, runtime: *http3_runtime.Runtime, label: []const u8) !ResourceSample {
    const pid = std.c.getpid();
    const snapshot = runtime.snapshot();
    const sample = ResourceSample{
        .label = label,
        .rss_kb = try readRssKb(allocator, pid),
        .open_fds = try readOpenFdCount(allocator, pid),
        .tracked_connections = snapshot.tracked_connections,
        .active_cid_routes = snapshot.active_cid_routes,
        .native_connections = snapshot.native_connections,
    };
    std.debug.print(
        "soak.h3.bounded_repeated_connections: {s} rss_kb={d} open_fds={d} tracked_connections={d} active_cid_routes={d} native_connections={d}\n",
        .{ sample.label, sample.rss_kb, sample.open_fds, sample.tracked_connections, sample.active_cid_routes, sample.native_connections },
    );
    return sample;
}

fn waitRuntimeSnapshot(
    runtime: *http3_runtime.Runtime,
    comptime predicate: fn (http3_runtime.Snapshot) bool,
) !http3_runtime.Snapshot {
    const deadline = nowUs() + 5_000_000;
    while (nowUs() < deadline) {
        const snapshot = runtime.snapshot();
        if (predicate(snapshot)) return snapshot;
        var ts = std.c.timespec{ .sec = 0, .nsec = 10 * std.time.ns_per_ms };
        _ = std.posix.system.nanosleep(&ts, &ts);
    }
    return error.TestTimedOut;
}

fn hasNoTrackedConnections(snapshot: http3_runtime.Snapshot) bool {
    return snapshot.tracked_connections == 0 and snapshot.active_cid_routes == 0;
}

// ---------------------------------------------------------------------------
// Request handler
// ---------------------------------------------------------------------------

const SoakHandlerState = struct {
    requests: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
};

fn soakHandler(
    _: std.mem.Allocator,
    request: *const http3_runtime.StreamRequest,
    response: *http3_runtime.Response,
    user_data: ?*anyopaque,
) anyerror!void {
    const state: *SoakHandlerState = @ptrCast(@alignCast(user_data.?));
    _ = state.requests.fetchAdd(1, .monotonic);
    try testing.expectEqualStrings("/soak", request.path);
    _ = response.setStatus(.ok).setBody("soak-response").setContentType("text/plain");
}

// ---------------------------------------------------------------------------
// Worker: one client socket driving repeated connect -> N requests -> clean
// close cycles against the shared runtime. `worker_count` of these are
// driven concurrently by one shared poll loop, covering both "multiple
// requests per connection" and "concurrent H3 connections" from the Bounded
// Soak Contract's workload list.
// ---------------------------------------------------------------------------

const WorkerPhase = enum { active, closing, round_done };

const Worker = struct {
    id: usize,
    allocator: std.mem.Allocator,
    socket: UdpSocket,
    runtime_addr: quic.udp.Address,
    round: usize = 0,
    rounds_target: usize,
    provider_storage: test_quic_crypto.HandshakeProviderStorage = .{},
    tls_backend: tls_backend.Tls13Backend = undefined,
    client: ?*Connection = null,
    h3: H3 = undefined,
    path: quic.path.PathKey = undefined,
    h3_started: bool = false,
    phase: WorkerPhase = .active,
    request_id: ?u64 = null,
    requests_sent_this_round: usize = 0,
    requests_completed_total: usize = 0,

    /// Deliberately does not call `beginRound` here: `beginRound` stashes a
    /// `tls_backend.Tls13Backend` on `self` and then hands `Connection.init`
    /// an interface capturing `&self.tls_backend` -- a self-referential
    /// pointer. Calling it before this value reaches its final resting
    /// place (the caller's `workers[i]` slot) would capture the address of
    /// this function's own stack frame, not the array slot; the connection
    /// would silently hold a dangling TLS backend pointer the moment
    /// `init` returned by value. Callers must place the returned `Worker`
    /// in its permanent location first, then call `beginRound` through a
    /// pointer into that location (see the `soak.h3.*` test below).
    fn init(allocator: std.mem.Allocator, id: usize, rounds_target: usize, runtime_addr: quic.udp.Address) !Worker {
        return Worker{
            .id = id,
            .allocator = allocator,
            .socket = try UdpSocket.open(),
            .runtime_addr = runtime_addr,
            .rounds_target = rounds_target,
        };
    }

    fn cids(self: *const Worker) struct { client_cid: [8]u8, odcid: [8]u8 } {
        var client_cid = [_]u8{0xc0} ** 8;
        var odcid = [_]u8{0x80} ** 8;
        client_cid[4] = @intCast(self.id);
        client_cid[5] = @intCast(self.round >> 8);
        client_cid[6] = @intCast(self.round);
        client_cid[7] = 0xc0;
        odcid[4] = @intCast(self.id);
        odcid[5] = @intCast(self.round >> 8);
        odcid[6] = @intCast(self.round);
        odcid[7] = 0x0d;
        return .{ .client_cid = client_cid, .odcid = odcid };
    }

    fn beginRound(self: *Worker) !void {
        const ids = self.cids();
        self.provider_storage = .{};
        self.tls_backend = tls_backend.Tls13Backend.initClient(
            .{ .hello_random = [_]u8{0xa5} ** 32 },
            self.provider_storage.init(0x7000 + self.id * 0x100 + self.round),
            .{ .pinned_certificate = tls_core.credentials.testdata.certificate_der },
        );
        self.path = .{
            .local = addressFromSockaddrIn(self.socket.addr),
            .remote = self.runtime_addr,
        };
        self.client = try Connection.init(self.allocator, .{
            .role = .client,
            .local_cid = &ids.client_cid,
            .original_destination_cid = &ids.odcid,
            .initial_secret_dcid = &ids.odcid,
            .tls = self.tls_backend.backend(),
            .crypto_provider = test_quic_crypto.testDefaultProvider(),
            .now_us = nowUs(),
            .initial_path = self.path,
        });
        self.h3 = H3.init(self.allocator, .client);
        self.h3_started = false;
        self.phase = .active;
        self.request_id = null;
        self.requests_sent_this_round = 0;
    }

    fn endRound(self: *Worker) void {
        self.h3.deinit();
        if (self.client) |c| c.deinit();
        self.client = null;
    }

    fn deinit(self: *Worker) void {
        if (self.client != null) self.endRound();
        self.socket.close();
    }

    fn flushTransmit(self: *Worker) !void {
        const client = self.client orelse return;
        var out: [2048]u8 = undefined;
        while (client.pollTransmitOnPath(&out, nowUs())) |t| {
            try self.socket.sendTo(sockaddrInFromAddress(t.path.remote), t.bytes);
        }
    }

    fn drainRecv(self: *Worker) !void {
        const client = self.client orelse return;
        var in: [2048]u8 = undefined;
        while (try self.socket.recv(&in)) |datagram| {
            try client.ingestOnPath(datagram, self.path, test_challenge_entropy, nowUs());
        }
    }

    /// Advances this worker's state machine by one iteration. Returns once
    /// per call; the shared loop calls this every iteration for every
    /// worker that has not finished all of its rounds.
    fn step(self: *Worker) !void {
        if (self.phase == .closing) {
            // The CONNECTION_CLOSE frame queued when the last response
            // arrived (previous iteration) already went out via
            // `flushTransmit` at the top of this iteration; tear down and
            // move on.
            self.endRound();
            self.round += 1;
            if (self.round >= self.rounds_target) {
                self.phase = .round_done;
            } else {
                try self.beginRound();
            }
            return;
        }

        const client = self.client orelse return;
        client.onTimeout(nowUs());

        if (!self.h3_started and client.isEstablished()) {
            try self.h3.start(client);
            self.h3_started = true;
        }
        if (!self.h3_started) return;
        try self.h3.pump(client);

        if (self.request_id == null) {
            var body_buf: [48]u8 = undefined;
            const body = try std.fmt.bufPrint(&body_buf, "soak-{d}-{d}-{d}", .{ self.id, self.round, self.requests_sent_this_round });
            self.request_id = try self.h3.sendRequest(client, .{
                .authority = "tardigrade.test",
                .path = "/soak",
                .body = body,
            });
        }
        if (self.request_id) |id| {
            if (try self.h3.pollResponse(id)) |response| {
                try testing.expectEqual(@as(u16, 200), response.status);
                try testing.expectEqualStrings("soak-response", response.body);
                self.h3.releaseResponse(id);
                self.request_id = null;
                self.requests_sent_this_round += 1;
                self.requests_completed_total += 1;
                if (self.requests_sent_this_round >= requests_per_round) {
                    client.close(0, "soak-round-done", nowUs());
                    self.phase = .closing;
                }
            }
        }
    }
};

test "soak.h3.bounded_repeated_connections" {
    const allocator = testing.allocator;

    var fixed = tls_core.credentials.FixedCredentialProvider.init(
        tls_core.credentials.testdata.identity(),
        tls_core.credentials.testdata.ignoredEntropy(),
    );
    defer fixed.deinit();
    var logger = http3_runtime.Logger.init(.err, "http3-soak-test");
    var handler_state = SoakHandlerState{};
    var runtime = try http3_runtime.Runtime.init(allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        .request_handler = soakHandler,
        .request_handler_ctx = &handler_state,
    });
    defer runtime.deinit();
    runtime.start();

    const rounds_per_worker: usize = if (soakHeavyEnabled()) 40 else 6;

    const before_sample = try sampleResources(allocator, &runtime, "before");

    var workers = try allocator.alloc(Worker, worker_count);
    defer allocator.free(workers);
    var workers_initialized: usize = 0;
    defer {
        for (workers[0..workers_initialized]) |*w| w.deinit();
    }
    for (0..worker_count) |i| {
        workers[i] = try Worker.init(allocator, i, rounds_per_worker, runtime.local_address);
        workers_initialized += 1;
        // Must run through `&workers[i]` (its permanent location), not on a
        // temporary -- see the doc comment on `Worker.init`.
        try workers[i].beginRound();
    }

    var pollfds_buf = try allocator.alloc(posix.pollfd, worker_count);
    defer allocator.free(pollfds_buf);

    var mid_sample: ?ResourceSample = null;
    const deadline = nowUs() + 60_000_000;
    var iterations: usize = 0;
    const max_iterations: usize = 400_000;

    while (nowUs() < deadline) : (iterations += 1) {
        try testing.expect(iterations < max_iterations);

        var finished: usize = 0;
        for (workers) |*w| {
            if (w.phase == .round_done) {
                finished += 1;
                continue;
            }
            try w.flushTransmit();
        }
        if (finished == worker_count) break;

        var poll_count: usize = 0;
        var next_wake: u64 = nowUs() + 20_000;
        for (workers) |*w| {
            if (w.phase == .round_done) continue;
            pollfds_buf[poll_count] = .{ .fd = w.socket.fd, .events = posix.POLL.IN, .revents = 0 };
            poll_count += 1;
            if (w.client) |c| {
                if (c.nextTimeoutUs()) |t| next_wake = @min(next_wake, t);
            }
        }
        const now = nowUs();
        const timeout_ms: i32 = @intCast(@min((next_wake -| now) / 1_000 + 1, 20));
        _ = try posix.poll(pollfds_buf[0..poll_count], timeout_ms);

        for (workers) |*w| {
            if (w.phase == .round_done) continue;
            try w.drainRecv();
        }

        for (workers) |*w| {
            if (w.phase == .round_done) continue;
            try w.step();
        }

        if (mid_sample == null) {
            var done_count: usize = 0;
            for (workers) |w| {
                if (w.phase == .round_done) done_count += 1;
            }
            if (done_count * 2 >= worker_count) {
                mid_sample = try sampleResources(allocator, &runtime, "mid");
            }
        }
    }

    const peak_sample = try sampleResources(allocator, &runtime, "peak");

    for (workers) |*w| w.deinit();
    workers_initialized = 0;

    _ = try waitRuntimeSnapshot(&runtime, hasNoTrackedConnections);
    const after_settle_sample = try sampleResources(allocator, &runtime, "after_settle");

    // Every planned request across every worker/round actually completed --
    // a soak that silently stalls partway through must fail loudly, not
    // "look stable" by doing less work than intended (docs/HTTP3_VALIDATION_
    // EVIDENCE.md: "do not describe the result only as looked stable").
    const expected_requests = worker_count * rounds_per_worker * requests_per_round;
    for (workers) |w| {
        try testing.expectEqual(rounds_per_worker * requests_per_round, w.requests_completed_total);
    }
    try testing.expectEqual(expected_requests, handler_state.requests.load(.monotonic));

    // Settle window: state that must drain completely returns exactly to
    // baseline once every worker has sent its final close and the runtime
    // has had a bounded window (waitRuntimeSnapshot above, 5s) to fold it.
    try testing.expectEqual(@as(usize, 0), after_settle_sample.tracked_connections);
    try testing.expectEqual(@as(usize, 0), after_settle_sample.active_cid_routes);
    try testing.expectEqual(@as(usize, 0), after_settle_sample.native_connections);

    // Open file descriptors are entirely test-harness-owned here (one UDP
    // socket per worker plus the runtime's own listener socket, all closed
    // by this point) -- after-settle must not exceed the pre-soak baseline.
    try testing.expect(after_settle_sample.open_fds <= before_sample.open_fds);

    // Resident memory: a monotonic leak grows roughly linearly with
    // iteration count, so it shows up as second-half growth comparable to
    // (or larger than) first-half growth. Bounded, expected high-water
    // retention (allocator arenas, QPACK/connection pools reaching their
    // steady-state size) shows up as most of the growth happening in the
    // first half and the second half plateauing. `rss_margin_kb` is
    // deliberately generous -- `ps`-reported RSS is page-granular and noisy
    // under a loaded CI host, and the PR-safe tier's low round count makes
    // this a coarse smoke bound rather than a precise leak detector; the
    // heavy tier (`TARDIGRADE_SOAK_HEAVY=1`, more rounds) gives the
    // meaningful signal.
    const mid = mid_sample orelse return error.MissingMidSample;
    const first_half_growth_kb = mid.rss_kb -| before_sample.rss_kb;
    const second_half_growth_kb = peak_sample.rss_kb -| mid.rss_kb;
    const rss_margin_kb: u64 = 8192;
    if (second_half_growth_kb > first_half_growth_kb + rss_margin_kb) {
        std.debug.print(
            "soak.h3.bounded_repeated_connections: possible monotonic RSS growth -- before={d}KB mid={d}KB peak={d}KB (first_half={d}KB second_half={d}KB margin={d}KB)\n",
            .{ before_sample.rss_kb, mid.rss_kb, peak_sample.rss_kb, first_half_growth_kb, second_half_growth_kb, rss_margin_kb },
        );
        return error.PossibleMonotonicRssGrowth;
    }
}

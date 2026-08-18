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
//! this file does not duplicate it. Controlled loss/reordering is out of
//! scope here too: it needs a dedicated host with netem/`CAP_NET_ADMIN`
//! (see `benchmarks/competitive/netem-impair.sh`). Reconnect/resumption
//! *is* in scope -- `soak.h3.bounded_resumed_reconnects` below wires a real
//! `tls_core.resumption_runtime.Runtime` into the server `Config` and
//! proves each reconnect actually offers and gets a PSK accepted (not just
//! that the reconnect itself succeeds, which would also be true of a full
//! fresh handshake). 0-RTT is not covered by that leg; it would need its
//! own early-data-specific admission assertions and is not required by
//! #247 Lane B's "reconnect/resumption where supported by the production
//! config" text.

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

// Real wall-clock ms (not a fixed test timestamp): `soak.h3.
// bounded_resumed_reconnects` below is a production-shaped soak, not a
// determinism-focused unit test, so ticket/lease freshness should be judged
// against real elapsed time the same way production composition
// (`edge_gateway.zig` et al.) does via this exact function.
fn nowUnixMsForResumption(_: *anyopaque) i64 {
    return compat.milliTimestamp();
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

// Both probes below fail closed (PR review, #247 Lane B): `bounded_process.run`
// only throws on allocation failure, never for a launch failure, timeout,
// signal, or non-zero exit -- those are all encoded in `result.outcome` and
// must be checked explicitly, or a probe that never ran can silently read
// back as `0` and make a resource-stability assertion pass on no evidence.
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
    if (result.outcome != .normal_exit) {
        std.debug.print("soak.h3: rss probe failed for pid {d}: {s}\n", .{ pid, result.diagnostic });
        return error.ResourceProbeFailed;
    }
    const trimmed = std.mem.trim(u8, result.stdout, " \t\r\n");
    if (trimmed.len == 0) {
        std.debug.print("soak.h3: rss probe for pid {d} returned no output\n", .{pid});
        return error.MalformedResourceProbe;
    }
    return std.fmt.parseInt(u64, trimmed, 10) catch {
        std.debug.print("soak.h3: rss probe for pid {d} returned malformed output: {s}\n", .{ pid, trimmed });
        return error.MalformedResourceProbe;
    };
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
        \\  echo "no fd probe backend available (no /proc, no lsof)" >&2
        \\  exit 3
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
    if (result.outcome != .normal_exit) {
        std.debug.print("soak.h3: open-fd probe failed for pid {d}: {s}\n", .{ pid, result.diagnostic });
        return error.ResourceProbeFailed;
    }
    const trimmed = std.mem.trim(u8, result.stdout, " \t\r\n");
    if (trimmed.len == 0) {
        std.debug.print("soak.h3: open-fd probe for pid {d} returned no output\n", .{pid});
        return error.MalformedResourceProbe;
    }
    return std.fmt.parseInt(u64, trimmed, 10) catch {
        std.debug.print("soak.h3: open-fd probe for pid {d} returned malformed output: {s}\n", .{ pid, trimmed });
        return error.MalformedResourceProbe;
    };
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
// Runtime-state high-water tracking (PR review, #247 Lane B): the final
// exact-zero settle assertion alone cannot distinguish "bounded state" from
// "a bug that retains every prior connection/CID while traffic continues,
// then releases them all once traffic stops" -- both look identical at
// settle. Sampling `runtime.snapshot()` every loop iteration (a cheap
// mutex-guarded struct copy, no subprocess) and tracking separate maxima for
// the true first and second halves of the planned workload catches sustained
// growth the settle-only check cannot.
// ---------------------------------------------------------------------------

const RuntimeHighWater = struct {
    tracked_connections: usize = 0,
    native_connections: usize = 0,
    active_cid_routes: usize = 0,

    fn observe(self: *RuntimeHighWater, snapshot: http3_runtime.Snapshot) void {
        self.tracked_connections = @max(self.tracked_connections, snapshot.tracked_connections);
        self.native_connections = @max(self.native_connections, snapshot.native_connections);
        self.active_cid_routes = @max(self.active_cid_routes, snapshot.active_cid_routes);
    }
};

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
    // Aggregate completed requests, not "workers fully done with every
    // round", is the workload's actual progress axis (PR review, #247 Lane
    // B): with a handful of roughly-synchronized workers, "half the workers
    // finished all their rounds" can land much later than 50% of total
    // requests -- observed in CI as a "mid" sample taken so late it was
    // barely distinguishable from the end of the run. Every first/second-half
    // split below (RSS/FD checkpoints and runtime-state high-water) uses this
    // same boundary.
    const total_planned_requests = worker_count * rounds_per_worker * requests_per_round;

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

    // Real-valued RSS/FD checkpoints at 25/50/75% of the actual workload,
    // rather than one "mid" sample plus a terminal sample mislabeled "peak"
    // (PR review): a bounded, small number of extra probe-subprocess spawns
    // (three, not one per loop iteration -- that would be far too expensive
    // over up to 400,000 iterations), enough to let `peak` below be a real
    // max-of-samples rather than just whatever the run happened to look like
    // at the very end.
    const RssCheckpoint = struct {
        label: []const u8,
        numerator: usize,
        denominator: usize,
        sample: ?ResourceSample = null,
    };
    var checkpoints = [_]RssCheckpoint{
        .{ .label = "checkpoint_25pct", .numerator = 1, .denominator = 4 },
        .{ .label = "checkpoint_50pct", .numerator = 1, .denominator = 2 },
        .{ .label = "checkpoint_75pct", .numerator = 3, .denominator = 4 },
    };

    var first_half_high_water: RuntimeHighWater = .{};
    var second_half_high_water: RuntimeHighWater = .{};

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

        var completed: usize = 0;
        for (workers) |w| completed += w.requests_completed_total;

        const snap = runtime.snapshot();
        if (completed * 2 >= total_planned_requests) {
            second_half_high_water.observe(snap);
        } else {
            first_half_high_water.observe(snap);
        }

        for (&checkpoints) |*cp| {
            if (cp.sample == null and completed * cp.denominator >= total_planned_requests * cp.numerator) {
                cp.sample = try sampleResources(allocator, &runtime, cp.label);
            }
        }
    }

    // Renamed from the old "peak" (PR review): this is only an end-of-
    // workload sample, taken once every worker has finished. The genuine
    // peak is computed below from `before` plus the checkpoints above.
    const end_workload_sample = try sampleResources(allocator, &runtime, "end_workload");

    for (workers) |*w| w.deinit();
    workers_initialized = 0;

    _ = try waitRuntimeSnapshot(&runtime, hasNoTrackedConnections);
    const after_settle_sample = try sampleResources(allocator, &runtime, "after_settle");

    // Every planned request across every worker/round actually completed --
    // a soak that silently stalls partway through must fail loudly, not
    // "look stable" by doing less work than intended (docs/HTTP3_VALIDATION_
    // EVIDENCE.md: "do not describe the result only as looked stable").
    for (workers) |w| {
        try testing.expectEqual(rounds_per_worker * requests_per_round, w.requests_completed_total);
    }
    try testing.expectEqual(total_planned_requests, handler_state.requests.load(.monotonic));

    // Settle window: state that must drain completely returns exactly to
    // baseline once every worker has sent its final close and the runtime
    // has had a bounded window (waitRuntimeSnapshot above, 5s) to fold it.
    try testing.expectEqual(@as(usize, 0), after_settle_sample.tracked_connections);
    try testing.expectEqual(@as(usize, 0), after_settle_sample.active_cid_routes);
    try testing.expectEqual(@as(usize, 0), after_settle_sample.native_connections);

    // Open file descriptors are entirely test-harness-owned here (one UDP
    // socket per worker plus the runtime's own listener socket, all closed
    // by this point) -- after-settle must not exceed the pre-soak baseline.
    // The measurement itself shells out to `find`/`lsof` per sample (see
    // `readOpenFdCount`), and that child's own pipe fds can still be mid-
    // teardown in this process's fd table for a few milliseconds after
    // `bounded_process.run` returns -- observed as a transient +1 on some
    // CI runners. Give that the same kind of bounded settle window already
    // used for runtime connection state above rather than failing on a
    // single noisy sample.
    var final_open_fds = after_settle_sample.open_fds;
    if (final_open_fds > before_sample.open_fds) {
        const fd_deadline = nowUs() + 2_000_000;
        while (final_open_fds > before_sample.open_fds and nowUs() < fd_deadline) {
            compat.sleepNs(50 * std.time.ns_per_ms);
            final_open_fds = try readOpenFdCount(allocator, std.c.getpid());
        }
        std.debug.print(
            "soak.h3.bounded_repeated_connections: after_settle open_fds re-sampled to {d} (baseline {d})\n",
            .{ final_open_fds, before_sample.open_fds },
        );
    }
    try testing.expect(final_open_fds <= before_sample.open_fds);

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
    const mid = checkpoints[1].sample orelse return error.MissingMidSample;
    var peak_rss_kb = before_sample.rss_kb;
    for (checkpoints) |cp| {
        if (cp.sample) |s| peak_rss_kb = @max(peak_rss_kb, s.rss_kb);
    }
    peak_rss_kb = @max(peak_rss_kb, end_workload_sample.rss_kb);
    const first_half_growth_kb = mid.rss_kb -| before_sample.rss_kb;
    const second_half_growth_kb = peak_rss_kb -| mid.rss_kb;
    const rss_margin_kb: u64 = 8192;
    if (second_half_growth_kb > first_half_growth_kb + rss_margin_kb) {
        std.debug.print(
            "soak.h3.bounded_repeated_connections: possible monotonic RSS growth -- before={d}KB mid={d}KB peak={d}KB (first_half={d}KB second_half={d}KB margin={d}KB)\n",
            .{ before_sample.rss_kb, mid.rss_kb, peak_rss_kb, first_half_growth_kb, second_half_growth_kb, rss_margin_kb },
        );
        return error.PossibleMonotonicRssGrowth;
    }

    // Runtime-state high-water plateau (PR review): the exact-zero settle
    // assertion above proves state eventually drains, but not that it stayed
    // bounded *while traffic was still flowing* -- a bug that keeps retaining
    // every prior connection/CID during the run and only releases them once
    // traffic stops would still pass a settle-only check. `high_water_margin`
    // is `worker_count * 4`: the server-loop reap pass that removes closed
    // connections is capped at 16 reclaims per pass (see `http3_runtime.zig`
    // `serve`'s `Reap` buffer), so a burst of near-simultaneous round
    // completions across `worker_count` workers can transiently lag by a few
    // passes before catching up -- expected bounded slack, not growth.
    const high_water_margin: usize = worker_count * 4;
    if (second_half_high_water.tracked_connections > first_half_high_water.tracked_connections + high_water_margin or
        second_half_high_water.native_connections > first_half_high_water.native_connections + high_water_margin or
        second_half_high_water.active_cid_routes > first_half_high_water.active_cid_routes + high_water_margin)
    {
        std.debug.print(
            "soak.h3.bounded_repeated_connections: possible sustained-traffic runtime-state growth -- " ++
                "first_half high-water tracked={d} native={d} cid_routes={d}; " ++
                "second_half high-water tracked={d} native={d} cid_routes={d} (margin={d})\n",
            .{
                first_half_high_water.tracked_connections,
                first_half_high_water.native_connections,
                first_half_high_water.active_cid_routes,
                second_half_high_water.tracked_connections,
                second_half_high_water.native_connections,
                second_half_high_water.active_cid_routes,
                high_water_margin,
            },
        );
        return error.PossibleRuntimeStateGrowth;
    }
}

// ---------------------------------------------------------------------------
// Resumption-enabled soak leg (#247 Lane B, PR review): "reconnect/resumption
// where supported by the production config" -- production `http3_runtime.
// Runtime.Config` exposes `resumption_runtime`, so leaving it unwired above
// was a self-imposed harness choice, not an unsupported capability. This
// leg wires a real `tls_core.resumption_runtime.Runtime` into the server
// `Config` (the exact field `http3_runtime.zig`'s `accept()` reads to install
// a PSK resolver, resume-compatibility policy, and resumption-decision
// observer on every accepted connection's backend -- see the block guarded
// by `if (self.resumption_runtime) |runtime|`), captures each connection's
// session ticket via the same ticket-consumer pattern `tests/quic_h3_e2e.zig`
// and `http3_runtime.zig`'s own resumption tests use, and offers it on the
// next reconnect via `setClientPskOfferLease` -- the same `ClientOfferLease`
// plumbing `connection.zig`'s "#488: resumption_runtime.Runtime drives a
// genuine resumed QUIC handshake" test exercises at the transport layer,
// driven here over real loopback UDP by a soak-shaped worker instead of a
// synthetic in-memory pump loop. It is a separate, smaller test rather than
// a mode flag on the primary `Worker`/`soak.h3.bounded_repeated_connections`
// above: the ticket-capture/offer state machine is a materially different
// shape (an extra "wait for the post-handshake ticket" phase between request
// completion and close), and keeping it separate does not put the primary
// soak's already-established pass/fail history at risk. It does reuse that
// test's low-level helpers (`UdpSocket`, `nowUs`, path/address conversion,
// `sampleResources`, `waitRuntimeSnapshot`, `hasNoTrackedConnections`)
// rather than re-inventing them.
// ---------------------------------------------------------------------------

const resumption_worker_count: usize = 2;

const ResumptionOutcomeCounts = struct {
    accepted: usize = 0,
    miss: usize = 0,
    full_handshake: usize = 0,
    incompatible: usize = 0,
    fatal: usize = 0,

    fn onOutcome(
        ctx: *anyopaque,
        transport: tls_core.resumption_runtime.Transport,
        outcome: tls_core.resumption_runtime.ResumptionOutcome,
    ) void {
        _ = transport;
        const self: *ResumptionOutcomeCounts = @ptrCast(@alignCast(ctx));
        switch (outcome) {
            .accepted => self.accepted += 1,
            .miss => self.miss += 1,
            .full_handshake => self.full_handshake += 1,
            .incompatible => self.incompatible += 1,
            .fatal => self.fatal += 1,
        }
    }
};

const ResumptionWorkerPhase = enum { active, awaiting_ticket, closing, round_done };

const ResumptionWorker = struct {
    id: usize,
    allocator: std.mem.Allocator,
    socket: UdpSocket,
    runtime_addr: quic.udp.Address,
    client_resumption: *tls_core.resumption_runtime.Runtime,
    round: usize = 0,
    rounds_target: usize,
    provider_storage: test_quic_crypto.HandshakeProviderStorage = .{},
    tls_backend: tls_backend.Tls13Backend = undefined,
    client: ?*Connection = null,
    h3: H3 = undefined,
    path: quic.path.PathKey = undefined,
    h3_started: bool = false,
    phase: ResumptionWorkerPhase = .active,
    request_id: ?u64 = null,
    requests_completed_total: usize = 0,
    ticket: TicketCapture = .{},
    // Target `ticket.count` value that means "this round's own fresh ticket
    // has arrived" -- set from `ticket.count + 1` at the top of each
    // `beginRound`. A monotonic counter, not a presence flag: the server's
    // post-handshake ticket for *this* round can arrive before this round's
    // own request/response finishes (observed arriving within the first few
    // iterations, well before the response), so there is no safe point at
    // which "a ticket is present" can be discarded as definitely stale --
    // only "fewer tickets have arrived than this round expects" is a safe
    // wait condition.
    ticket_target: usize = 0,
    awaiting_ticket_iterations: usize = 0,
    // Rounds after the first (round 0 only ever does a fresh handshake --
    // there is no ticket yet) that reached establishment with the server's
    // selected PSK actually authenticated client-side. Compared against
    // `resumption_worker_count * (rounds_target - 1)` after the loop: proof
    // every reconnect really resumed, not just that it reconnected.
    resumed_round_confirmations: usize = 0,

    const awaiting_ticket_max_iterations: usize = 4000;

    const TicketCapture = struct {
        state: tls_core.session.ClientTicketState = .{},
        present: bool = false,
        // Incremented, never reset, every time the consumer fires -- the
        // generation counter `ticket_target` above compares against.
        count: usize = 0,

        fn deinit(self: *TicketCapture) void {
            if (self.present) self.state.deinit();
            self.* = .{ .count = self.count };
        }
    };

    // `ctx` is the owning `ResumptionWorker`, not just its `TicketCapture` --
    // this must both retain the ticket locally (so `beginRound` can build a
    // `CandidateContext` from it) *and* insert it into `client_resumption`'s
    // own cache via `storeClientTicket`, matching the exact two-step shape
    // `http3_runtime.zig`'s and `connection.zig`'s own ticket-consumer test
    // helpers use: `beginRound`'s `lookupClientOffers` call reads the cache,
    // not this struct, so a consumer that only retained the ticket locally
    // would see every resumed round miss despite `self.ticket.present` being
    // true.
    fn onTicket(ctx: *anyopaque, ticket_state: *const tls_core.session.ClientTicketState) void {
        const self: *ResumptionWorker = @ptrCast(@alignCast(ctx));
        if (self.ticket.present) self.ticket.state.deinit();
        ticket_state.cloneInto(testing.allocator, &self.ticket.state) catch unreachable;
        self.ticket.present = true;
        self.ticket.count += 1;
        _ = self.client_resumption.storeClientTicket(ticket_state);
    }

    fn init(
        allocator: std.mem.Allocator,
        id: usize,
        rounds_target: usize,
        runtime_addr: quic.udp.Address,
        client_resumption: *tls_core.resumption_runtime.Runtime,
    ) !ResumptionWorker {
        return ResumptionWorker{
            .id = id,
            .allocator = allocator,
            .socket = try UdpSocket.open(),
            .runtime_addr = runtime_addr,
            .client_resumption = client_resumption,
            .rounds_target = rounds_target,
        };
    }

    fn cids(self: *const ResumptionWorker) struct { client_cid: [8]u8, odcid: [8]u8 } {
        var client_cid = [_]u8{0xe0} ** 8;
        var odcid = [_]u8{0x90} ** 8;
        client_cid[4] = @intCast(self.id);
        client_cid[5] = @intCast(self.round >> 8);
        client_cid[6] = @intCast(self.round);
        client_cid[7] = 0xe0;
        odcid[4] = @intCast(self.id);
        odcid[5] = @intCast(self.round >> 8);
        odcid[6] = @intCast(self.round);
        odcid[7] = 0x9e;
        return .{ .client_cid = client_cid, .odcid = odcid };
    }

    // Same self-referential-pointer caveat as the primary `Worker.init`'s
    // doc comment: place the returned value in its permanent slot before
    // calling `beginRound`.
    fn beginRound(self: *ResumptionWorker) !void {
        const ids = self.cids();
        self.provider_storage = .{};
        self.tls_backend = tls_backend.Tls13Backend.initClient(
            .{ .hello_random = [_]u8{0xb6} ** 32 },
            self.provider_storage.init(0x9000 + self.id * 0x100 + self.round),
            .{ .pinned_certificate = tls_core.credentials.testdata.certificate_der },
        );
        // Native QUIC 1-RTT resumption deliberately ignores connection-
        // specific transport/application snapshots for ordinary resumption
        // matching (see `http3_runtime.zig`'s identical policy, installed
        // automatically on the server side once `resumption_runtime` is
        // configured, and the precedent comment on the connection-level
        // `#488` test in `connection.zig`).
        try self.tls_backend.setResumeCompatibilityPolicy(.{ .transport = .ignore, .application = .ignore });
        try self.tls_backend.engine.setSessionTicketConsumer(self.allocator, tls_core.session.Limits.default, .{
            .ctx = self,
            .nowUnixMsFn = nowUnixMsForResumption,
            .onTicketFn = ResumptionWorker.onTicket,
        });
        // This round's own fresh ticket (captured for the *next* round's
        // offer) must arrive at least once more than have arrived so far.
        self.ticket_target = self.ticket.count + 1;
        if (self.round > 0) {
            if (!self.ticket.present) return error.MissingTicketForResumedRound;
            const candidate: tls_core.session.CandidateContext = .{
                .cipher_suite = self.ticket.state.common.cipher_suite,
                .server_name = if (self.ticket.state.common.server_name) |*s| s.slice() else null,
                .application_protocol = if (self.ticket.state.common.application_protocol) |*a| a.slice() else null,
                .auth_binding = self.ticket.state.common.auth_binding,
                .transport_compat = null,
                .application_compat = null,
            };
            var lookup = self.client_resumption.lookupClientOffers(candidate);
            defer lookup.deinit();
            if (lookup != .hit) return error.ExpectedResumptionOffer;
            try self.tls_backend.engine.setClientPskOfferLease(&lookup.hit, undefined, nowUnixMsForResumption);
        }
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
    }

    fn endRound(self: *ResumptionWorker) void {
        self.h3.deinit();
        if (self.client) |c| c.deinit();
        self.client = null;
    }

    fn deinit(self: *ResumptionWorker) void {
        if (self.client != null) self.endRound();
        self.ticket.deinit();
        self.socket.close();
    }

    fn flushTransmit(self: *ResumptionWorker) !void {
        const client = self.client orelse return;
        var out: [2048]u8 = undefined;
        while (client.pollTransmitOnPath(&out, nowUs())) |t| {
            try self.socket.sendTo(sockaddrInFromAddress(t.path.remote), t.bytes);
        }
    }

    fn drainRecv(self: *ResumptionWorker) !void {
        const client = self.client orelse return;
        var in: [2048]u8 = undefined;
        while (try self.socket.recv(&in)) |datagram| {
            try client.ingestOnPath(datagram, self.path, test_challenge_entropy, nowUs());
        }
    }

    fn step(self: *ResumptionWorker) !void {
        if (self.phase == .closing) {
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

        if (self.phase == .awaiting_ticket) {
            // The server's post-handshake `maybeIssueSessionTicket` fires
            // "best-effort, exactly-once" the moment a datagram is ingested
            // for an established connection -- often before this round's own
            // request/response even finishes -- but delivery of the
            // resulting NewSessionTicket still needs a few more send/recv
            // ticks to actually reach and get processed by this worker's
            // consumer, hence this bounded extra-pump phase rather than
            // closing the instant the response arrives.
            try self.h3.pump(client);
            if (self.ticket.count >= self.ticket_target) {
                client.close(0, "soak-round-done", nowUs());
                self.phase = .closing;
            } else {
                self.awaiting_ticket_iterations += 1;
                if (self.awaiting_ticket_iterations >= awaiting_ticket_max_iterations) {
                    return error.SessionTicketNeverArrived;
                }
            }
            return;
        }

        if (!self.h3_started and client.isEstablished()) {
            try self.h3.start(client);
            self.h3_started = true;
            if (self.round > 0) {
                // Client-side authoritative signal (RFC 8446): set when
                // ServerHello's `selected_identity` confirms the server
                // chose the offered PSK, before EncryptedExtensions even
                // arrives -- not an inference from "the reconnect worked",
                // which would also be true of a full fresh handshake.
                if (!self.tls_backend.engine.core.psk_authenticated) return error.ResumptionNotAccepted;
                self.resumed_round_confirmations += 1;
            }
        }
        if (!self.h3_started) return;
        try self.h3.pump(client);

        if (self.request_id == null) {
            var body_buf: [48]u8 = undefined;
            const body = try std.fmt.bufPrint(&body_buf, "resume-{d}-{d}", .{ self.id, self.round });
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
                self.requests_completed_total += 1;
                self.awaiting_ticket_iterations = 0;
                self.phase = .awaiting_ticket;
            }
        }
    }
};

test "soak.h3.bounded_resumed_reconnects" {
    const allocator = testing.allocator;

    var server_entropy = tls_core.production_crypto.OsEntropy{};
    var server_crypto_provider_state = tls_core.production_crypto.Provider.init(server_entropy.entropy());
    var server_resumption = try tls_core.resumption_runtime.Runtime.init(
        allocator,
        .{ .mode = .stateful },
        .{ .ctx = undefined, .nowUnixMsFn = nowUnixMsForResumption },
        server_crypto_provider_state.cryptoProvider(),
    );
    defer server_resumption.deinit();
    var outcome_counts = ResumptionOutcomeCounts{};
    server_resumption.setObserver(.{ .ctx = &outcome_counts, .onResumptionOutcomeFn = ResumptionOutcomeCounts.onOutcome });

    var client_entropy = tls_core.production_crypto.OsEntropy{};
    var client_crypto_provider_state = tls_core.production_crypto.Provider.init(client_entropy.entropy());
    var client_resumption = try tls_core.resumption_runtime.Runtime.init(
        allocator,
        .{ .mode = .stateful },
        .{ .ctx = undefined, .nowUnixMsFn = nowUnixMsForResumption },
        client_crypto_provider_state.cryptoProvider(),
    );
    defer client_resumption.deinit();

    var fixed = tls_core.credentials.FixedCredentialProvider.init(
        tls_core.credentials.testdata.identity(),
        tls_core.credentials.testdata.ignoredEntropy(),
    );
    defer fixed.deinit();
    var logger = http3_runtime.Logger.init(.err, "http3-soak-resume-test");
    var handler_state = SoakHandlerState{};
    var runtime = try http3_runtime.Runtime.init(allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        // The one line that actually enables this leg: everything else
        // (PSK resolver, resume-compatibility policy, resumption-decision
        // observer) is wired onto every accepted connection automatically
        // by `accept()` once this is non-null.
        .resumption_runtime = &server_resumption,
        .request_handler = soakHandler,
        .request_handler_ctx = &handler_state,
    });
    defer runtime.deinit();
    runtime.start();

    const rounds_per_worker: usize = if (soakHeavyEnabled()) 10 else 4;

    const before_sample = try sampleResources(allocator, &runtime, "before");

    var workers = try allocator.alloc(ResumptionWorker, resumption_worker_count);
    defer allocator.free(workers);
    var workers_initialized: usize = 0;
    defer {
        for (workers[0..workers_initialized]) |*w| w.deinit();
    }
    for (0..resumption_worker_count) |i| {
        workers[i] = try ResumptionWorker.init(allocator, i, rounds_per_worker, runtime.local_address, &client_resumption);
        workers_initialized += 1;
        try workers[i].beginRound();
    }

    var pollfds_buf = try allocator.alloc(posix.pollfd, resumption_worker_count);
    defer allocator.free(pollfds_buf);

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
        if (finished == resumption_worker_count) break;

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
    }

    for (workers) |*w| w.deinit();
    workers_initialized = 0;

    _ = try waitRuntimeSnapshot(&runtime, hasNoTrackedConnections);
    const after_settle_sample = try sampleResources(allocator, &runtime, "after_settle");

    // Every planned request completed and every reconnect (every round past
    // the first) genuinely resumed -- the primary point of this leg.
    var total_confirmed: usize = 0;
    for (workers) |w| {
        try testing.expectEqual(rounds_per_worker, w.requests_completed_total);
        total_confirmed += w.resumed_round_confirmations;
    }
    const expected_resumed_rounds = resumption_worker_count * (rounds_per_worker - 1);
    try testing.expectEqual(expected_resumed_rounds, total_confirmed);
    try testing.expectEqual(resumption_worker_count * rounds_per_worker, handler_state.requests.load(.monotonic));

    // Independent server-side confirmation via the production resumption
    // runtime's own observer (see the doc comment above `ResumptionWorker`):
    // every resumed round's PSK was actually accepted, never merely offered
    // and missed/rejected, and round 0's plain fresh handshake never even
    // reaches this observer (the server's PSK selection short-circuits
    // before notifying when the ClientHello carries no PSK extension at
    // all), so `full_handshake` staying zero is expected, not incidental.
    try testing.expectEqual(expected_resumed_rounds, outcome_counts.accepted);
    try testing.expectEqual(@as(usize, 0), outcome_counts.miss);
    try testing.expectEqual(@as(usize, 0), outcome_counts.incompatible);
    try testing.expectEqual(@as(usize, 0), outcome_counts.fatal);
    try testing.expectEqual(@as(usize, 0), outcome_counts.full_handshake);

    // Same bounded resource/settle checks as the primary soak, folded into
    // this leg per the PR review rather than only proving resumption in
    // isolation.
    try testing.expectEqual(@as(usize, 0), after_settle_sample.tracked_connections);
    try testing.expectEqual(@as(usize, 0), after_settle_sample.active_cid_routes);
    try testing.expectEqual(@as(usize, 0), after_settle_sample.native_connections);

    var final_open_fds = after_settle_sample.open_fds;
    if (final_open_fds > before_sample.open_fds) {
        const fd_deadline = nowUs() + 2_000_000;
        while (final_open_fds > before_sample.open_fds and nowUs() < fd_deadline) {
            compat.sleepNs(50 * std.time.ns_per_ms);
            final_open_fds = try readOpenFdCount(allocator, std.c.getpid());
        }
    }
    try testing.expect(final_open_fds <= before_sample.open_fds);
}

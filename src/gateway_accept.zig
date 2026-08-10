//! Listener accept-loop helpers. This module owns accepting ready sockets,
//! applying listener fd limits, and rejecting overloaded clients before they
//! enter the worker pool.
//!
//! Listener sharding: when `TARDIGRADE_LISTENER_SHARDS` > 1, the gateway
//! creates N sockets bound to the same address with the platform's
//! load-balanced reuse-port option and runs one independent accept loop per
//! shard, each on its own thread. This reduces accept-path contention and
//! improves CPU locality for high-connection-churn workloads.

const builtin = @import("builtin");
const compat = @import("zig_compat");
const std = @import("std");
const http = @import("http.zig");
const gc = @import("gateway_connection.zig");
const gs = @import("gateway_state.zig");

const GatewayState = gs.GatewayState;

/// Context passed to each per-shard accept thread.
pub const ShardAcceptContext = struct {
    listen_fd: std.posix.fd_t,
    shard_id: u16,
    worker_pool: *http.worker_pool.WorkerPool,
    state: *GatewayState,
};

/// Entry point for a per-shard accept thread.  Runs until shutdown is
/// requested, then returns.  The caller is responsible for joining the thread
/// and closing `ctx.listen_fd`.
pub fn runShardAcceptLoop(ctx: ShardAcceptContext) void {
    var pfd = [_]std.posix.pollfd{.{
        .fd = ctx.listen_fd,
        .events = std.posix.POLL.IN,
        .revents = 0,
    }};
    while (!http.shutdown.isShutdownRequested()) {
        // Poll with a 250 ms timeout so we check the shutdown flag periodically
        // instead of blocking indefinitely in accept().
        const ready = std.posix.poll(&pfd, 250) catch |err| switch (err) {
            error.SystemResources => {
                ctx.state.metricsRecordAcceptError(ctx.shard_id, .poll);
                continue;
            },
            else => {
                ctx.state.metricsRecordAcceptError(ctx.shard_id, .poll);
                ctx.state.logger.err(null, "poll error (shard {}): {}", .{ ctx.shard_id, err });
                return;
            },
        };
        if (ready == 0) continue; // timeout — loop and recheck shutdown flag
        if ((pfd[0].revents & std.posix.POLL.IN) != 0) {
            acceptReadyConnectionsShard(ctx.listen_fd, ctx.shard_id, ctx.worker_pool, ctx.state);
        }
    }
}

/// Accept all connections that are ready on `listen_fd`, recording metrics
/// under the given `shard_id`.  Returns after draining all ready connections
/// (EAGAIN) or when shutdown is requested.
pub fn acceptReadyConnectionsShard(listen_fd: std.posix.fd_t, shard_id: u16, worker_pool: *http.worker_pool.WorkerPool, state: *GatewayState) void {
    while (!http.shutdown.isShutdownRequested()) {
        var accepted_addr: std.c.sockaddr.storage = undefined;
        var addr_len: std.c.socklen_t = @sizeOf(std.c.sockaddr.storage);

        const client_fd = std.c.accept(listen_fd, @ptrCast(&accepted_addr), &addr_len);
        if (client_fd >= 0) {
            const flags = std.c.fcntl(client_fd, std.c.F.GETFL, @as(c_int, 0));
            if (flags >= 0) {
                const nonblock: c_int = @intCast(@as(u32, @bitCast(std.c.O{ .NONBLOCK = true })));
                _ = std.c.fcntl(client_fd, std.c.F.SETFL, flags | nonblock);
            }
            _ = std.c.fcntl(client_fd, std.c.F.SETFD, @as(c_int, 1)); // FD_CLOEXEC
        }
        if (client_fd < 0) {
            const e = std.posix.errno(client_fd);
            if (e == .AGAIN) return;
            if (e == .CONNABORTED) continue;
            state.metricsRecordAcceptError(shard_id, .accept);
            state.logger.err(null, "accept error (shard {}): {}", .{ shard_id, e });
            return;
        }

        state.metricsRecordAccept(shard_id);

        const owned_ip_key = gc.clientIpKeyFromAddress(state.allocator, &accepted_addr) catch null;
        defer if (owned_ip_key) |key| state.allocator.free(key);
        const ip_key = owned_ip_key orelse "unknown";

        const slot_result = state.tryAcquireConnectionSlot(client_fd, ip_key) catch |err| {
            state.logger.warn(null, "connection slot tracking error: {}", .{err});
            _ = std.c.close(client_fd);
            continue;
        };
        switch (slot_result) {
            .accepted => {},
            .over_ip_limit => {
                state.logger.warn(null, "per-IP connection limit reached for {s}", .{ip_key});
                state.metricsRecordErrorCode("overload");
                rejectOverloadedClient(client_fd);
                continue;
            },
            .over_global_limit => {
                state.logger.warn(null, "global active connection limit reached", .{});
                state.metricsRecordErrorCode("overload");
                rejectOverloadedClient(client_fd);
                continue;
            },
            .over_global_memory_limit => {
                state.logger.warn(null, "global connection memory estimate limit reached", .{});
                state.metricsRecordErrorCode("overload");
                rejectOverloadedClient(client_fd);
                continue;
            },
        }

        worker_pool.submit(client_fd) catch |err| {
            state.logger.warn(null, "worker queue submit failed: {}", .{err});
            state.metricsRecordQueueRejection();
            state.metricsRecordErrorCode("overload");
            state.releaseConnectionSlot(client_fd);
            rejectOverloadedClient(client_fd);
            continue;
        };
    }
}

/// Backward-compatible wrapper: accept ready connections on shard 0 (the
/// default single-listener path).
pub fn acceptReadyConnections(listen_fd: std.posix.fd_t, worker_pool: *http.worker_pool.WorkerPool, state: *GatewayState) void {
    acceptReadyConnectionsShard(listen_fd, 0, worker_pool, state);
}

/// Create a TCP listener socket bound to `host`:`port` with `SO_REUSEADDR`
/// and the platform's load-balanced reuse-port option.
///
/// Multiple sockets created with a load-balanced reuse-port option for the same
/// address allow the kernel to distribute incoming connections across
/// independent accept loops (listener sharding) without per-fd contention.
/// Callers should only use this path when `isReusePortSupported()` is true.
///
/// Returns a bound, listening file descriptor.  The caller owns the fd and
/// must close it when done.
pub fn createReusePortListenerFd(host: []const u8, port: u16) !std.posix.fd_t {
    const sock_addr = try compat.parseIpAddress(host, port);
    // Derive the address family from the first field of the generic sockaddr.
    const sa: *const std.c.sockaddr = @ptrCast(&sock_addr.storage);
    const family: u32 = @intCast(sa.family);

    const fd = std.c.socket(family, std.posix.SOCK.STREAM, std.posix.IPPROTO.TCP);
    if (fd < 0) return error.SocketCreationFailed;
    errdefer _ = std.c.close(fd);

    _ = std.c.fcntl(fd, std.c.F.SETFD, @as(c_int, 1)); // FD_CLOEXEC

    // SO_REUSEADDR: allow fast server restart without waiting out TIME_WAIT.
    try std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, std.mem.asBytes(&@as(c_int, 1)));

    try enableReusePortSharding(fd);

    const rc_bind = std.c.bind(fd, @ptrCast(&sock_addr.storage), sock_addr.len);
    if (rc_bind != 0) return error.BindFailed;

    const rc_listen = std.c.listen(fd, 128);
    if (rc_listen != 0) return error.ListenFailed;

    return fd;
}

/// Set the platform option that provides load-balanced duplicate listener
/// binding. Plain duplicate-bind options are intentionally not enough here:
/// sharding must distribute fresh TCP connections across the listener fds.
fn enableReusePortSharding(fd: std.posix.fd_t) !void {
    const option = reusePortShardingOption() orelse return error.ReusePortShardingUnsupported;
    try std.posix.setsockopt(fd, std.posix.SOL.SOCKET, option, std.mem.asBytes(&@as(c_int, 1)));
}

fn reusePortShardingOption() ?u32 {
    return switch (builtin.os.tag) {
        .linux => std.posix.SO.REUSEPORT,
        .freebsd => 0x00010000, // SO_REUSEPORT_LB
        else => null,
    };
}

/// Returns true on platforms with verified load-balanced reuse-port semantics.
pub fn isReusePortSupported() bool {
    return switch (builtin.os.tag) {
        .linux, .freebsd => true,
        else => false,
    };
}

/// Deterministic overload response sent to clients rejected at accept time
/// (global, per-IP, or memory connection-slot limits, or a saturated worker
/// queue). Kept as a single fixed byte string so every overload path returns an
/// identical, predictable 503 — see docs/OBSERVABILITY.md "Resource Limits and
/// Overload Behavior". When the socket cannot be written, the fd is closed
/// instead (no partial/ambiguous response is ever emitted).
pub const overload_response_503 =
    "HTTP/1.1 503 Service Unavailable\r\n" ++
    "Connection: close\r\n" ++
    "Content-Length: 0\r\n" ++
    "Retry-After: 1\r\n" ++
    "\r\n";

pub fn rejectOverloadedClient(client_fd: std.posix.fd_t) void {
    gc.setNonBlocking(client_fd, false) catch {}; // connection is usable in blocking mode; write and close still succeed
    const stream = compat.netStreamFromFd(client_fd);
    stream.writer().writeAll(overload_response_503) catch {}; // best-effort 503; client will time out if the write fails
    stream.close();
}

test "overload response is a deterministic 503 with close and retry hints" {
    const r = overload_response_503;
    try std.testing.expect(std.mem.startsWith(u8, r, "HTTP/1.1 503 Service Unavailable\r\n"));
    try std.testing.expect(std.mem.find(u8, r, "Connection: close\r\n") != null);
    try std.testing.expect(std.mem.find(u8, r, "Content-Length: 0\r\n") != null);
    try std.testing.expect(std.mem.find(u8, r, "Retry-After: 1\r\n") != null);
    // Response is a complete header block with no body: must end with a blank line.
    try std.testing.expect(std.mem.endsWith(u8, r, "\r\n\r\n"));
}

test "applyFdSoftLimit is a no-op for 0 and clamps to the hard limit" {
    switch (builtin.os.tag) {
        .linux, .macos, .freebsd, .netbsd, .openbsd, .dragonfly, .illumos, .ios, .tvos, .watchos, .visionos => {},
        else => return, // unsupported platform path returns null; nothing to assert
    }

    // 0 means "leave the OS default alone".
    try std.testing.expectEqual(@as(?u64, null), try applyFdSoftLimit(0));

    const limits = try std.posix.getrlimit(std.posix.rlimit_resource.NOFILE);
    const current_soft: u64 = @intCast(limits.cur);
    const hard: u64 = @intCast(limits.max);

    // Requesting the current soft limit is a no-op that returns it unchanged
    // (exercises the target == current early return without mutating the
    // process's real fd limit).
    if (current_soft > 0) {
        try std.testing.expectEqual(@as(?u64, current_soft), try applyFdSoftLimit(current_soft));
    }

    // A desired value above the hard cap is clamped to the hard limit, never
    // exceeding it. Restore the original limit afterward to avoid side effects.
    const raised = try applyFdSoftLimit(hard + 1_000_000);
    try std.testing.expectEqual(@as(?u64, hard), raised);
    std.posix.setrlimit(std.posix.rlimit_resource.NOFILE, limits) catch {};
}

pub fn applyFdSoftLimit(desired: u64) !?u64 {
    if (desired == 0) return null;
    switch (builtin.os.tag) {
        .linux, .macos, .freebsd, .netbsd, .openbsd, .dragonfly, .illumos, .ios, .tvos, .watchos, .visionos => {},
        else => return null,
    }

    var limits = try std.posix.getrlimit(std.posix.rlimit_resource.NOFILE);
    const current_soft: u64 = @intCast(limits.cur);
    const hard: u64 = @intCast(limits.max);
    const target: u64 = @min(desired, hard);
    if (target == current_soft) return target;

    limits.cur = @intCast(target);
    try std.posix.setrlimit(std.posix.rlimit_resource.NOFILE, limits);
    return target;
}

test "isReusePortSupported returns true only on load-balanced platforms" {
    switch (builtin.os.tag) {
        .linux,
        .freebsd,
        => try std.testing.expect(isReusePortSupported()),
        else => try std.testing.expect(!isReusePortSupported()),
    }
}

test "createReusePortListenerFd binds and listens on a free port" {
    if (!isReusePortSupported()) return; // skip on unsupported platforms

    // Bind to port 0 to let the kernel assign a free port.
    const fd = try createReusePortListenerFd("127.0.0.1", 0);
    defer _ = std.c.close(fd);

    // The fd must be a valid, listening socket — verify by getting the bound address.
    var bound: std.c.sockaddr.in = undefined;
    var bound_len: std.c.socklen_t = @sizeOf(std.c.sockaddr.in);
    try std.testing.expectEqual(@as(c_int, 0), std.c.getsockname(fd, @ptrCast(&bound), &bound_len));
    // Port 0 gets a non-zero OS-assigned port.
    try std.testing.expect(std.mem.bigToNative(u16, bound.port) > 0);
}

test "createReusePortListenerFd allows two sockets on the same port with SO_REUSEPORT" {
    if (!isReusePortSupported()) return; // skip on unsupported platforms

    // Bind the first socket to port 0 to get a kernel-assigned port.
    const fd1 = try createReusePortListenerFd("127.0.0.1", 0);
    defer _ = std.c.close(fd1);

    // Read the assigned port.
    var bound: std.c.sockaddr.in = undefined;
    var bound_len: std.c.socklen_t = @sizeOf(std.c.sockaddr.in);
    try std.testing.expectEqual(@as(c_int, 0), std.c.getsockname(fd1, @ptrCast(&bound), &bound_len));
    const port = std.mem.bigToNative(u16, bound.port);
    try std.testing.expect(port > 0);

    // A second socket on the exact same port must succeed (SO_REUSEPORT).
    const fd2 = try createReusePortListenerFd("127.0.0.1", port);
    defer _ = std.c.close(fd2);

    // Both fds are valid and distinct.
    try std.testing.expect(fd1 != fd2);
}

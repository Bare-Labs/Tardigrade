//! HTTP-independent UDP endpoint contract for pure Zig QUIC (#248).
//!
//! This layer owns datagram metadata, socket tuning hooks, deterministic time,
//! and future batching/pacing extension points. It must not import gateway or
//! HTTP request types; QUIC packet routing happens above it by DCID.

const std = @import("std");

pub const Ecn = enum {
    unavailable,
    not_ect,
    ect0,
    ect1,
    ce,
};

pub const AddressFamily = enum {
    ip4,
    ip6,
};

pub const Address = struct {
    family: AddressFamily,
    bytes: [16]u8 = [_]u8{0} ** 16,
    port: u16,
    scope_id: u32 = 0,

    pub fn ip4(octets: [4]u8, port: u16) Address {
        var address = Address{ .family = .ip4, .port = port };
        @memcpy(address.bytes[0..4], &octets);
        return address;
    }

    pub fn ip6(octets: [16]u8, port: u16, scope_id: u32) Address {
        return .{ .family = .ip6, .bytes = octets, .port = port, .scope_id = scope_id };
    }

    pub fn slice(self: *const Address) []const u8 {
        return switch (self.family) {
            .ip4 => self.bytes[0..4],
            .ip6 => self.bytes[0..16],
        };
    }

    pub fn eql(self: Address, other: Address) bool {
        return self.sameHost(other) and self.port == other.port;
    }

    /// Same IP address (family, octets, scope) regardless of port. A NAT
    /// rebinding usually changes only the port; a host change is a real
    /// migration (RFC 9308 §4.1).
    pub fn sameHost(self: Address, other: Address) bool {
        if (self.family != other.family) return false;
        if (self.scope_id != other.scope_id) return false;
        return std.mem.eql(u8, self.slice(), other.slice());
    }
};

pub const ReceivedDatagram = struct {
    /// Slice into the caller-provided receive scratch buffer. Valid only until
    /// that scratch buffer is reused or the next receive call writes into it.
    /// Connection state that outlives dispatch must copy packet bytes it needs.
    bytes: []const u8,
    local: ?Address = null,
    remote: Address,
    ecn: Ecn = .unavailable,
    received_at_us: u64,
};

pub const SendDatagram = struct {
    bytes: []const u8,
    local: ?Address = null,
    remote: Address,
    ecn: Ecn = .unavailable,
    /// Earliest instant this datagram may leave; `null` means send as soon as
    /// the endpoint can.
    ///
    /// Not a second pacing API (#256-C). The transport's schedule lives in
    /// `recovery.Pacer`, and `Connection.pollTransmitOnPath` already declines
    /// to build a paced datagram before it is eligible — so every datagram
    /// that reaches an endpoint is one the pacer has released, and this field
    /// is null on the production path. It stays for endpoints that queue
    /// ahead of the wire (batching, a test harness driving a fake clock),
    /// which need somewhere to carry the release time that
    /// `Connection.nextSendTimeUs` reports.
    send_at_us: ?u64 = null,
};

/// Requested socket buffer sizes. `null` leaves the kernel default alone —
/// which is the right answer for most deployments, since the default is
/// already sized for the host. See `EffectiveBufferTuning` for what a request
/// is actually worth: this is advisory, and a kernel is free to grant less.
pub const BufferTuning = struct {
    recv_bytes: ?usize = null,
    send_bytes: ?usize = null,
};

/// Bounds on a socket buffer request. The upper bound is not a policy opinion
/// about how much buffering is useful — kernels clamp long before this — it
/// keeps the request inside what the platform can actually represent, so an
/// operator typo cannot wrap into a negative size. The lower bound is below
/// every kernel minimum this code knows of, so it only catches values that
/// could not have been meant.
///
/// The upper bound is `INT_MAX / 2` rather than a round 1 GiB because the
/// `setsockopt` ABI takes a signed 32-bit size *and* Linux stores twice what
/// it is given: a request has to leave room for that doubling to stay
/// representable. Asking for 1 GiB exactly would be silently reduced by one
/// byte on Linux and then reported as a clamp forever — pointing the operator
/// at a `net.core.rmem_max` that was never the cause.
pub const min_buffer_bytes: usize = 2048;
pub const max_buffer_bytes: usize = @as(usize, std.math.maxInt(c_int)) / 2;

pub fn clampBufferBytes(requested: usize) usize {
    return std.math.clamp(requested, min_buffer_bytes, max_buffer_bytes);
}

/// What became of one socket buffer request. Socket buffer sizing is a
/// performance setting, not a correctness one: every outcome here is a
/// working listener, and none of them is a reason to fail startup. The
/// distinctions exist so an operator can tell "you got what you asked for"
/// from "the kernel silently gave you an eighth of it", which otherwise look
/// identical from outside the process.
pub const BufferTuningStatus = enum {
    /// Nothing was requested; the kernel default stands.
    default,
    /// The kernel granted at least the requested size.
    applied,
    /// The kernel accepted the request and granted less than was asked for —
    /// a system-wide ceiling (`net.core.rmem_max` on Linux,
    /// `kern.ipc.maxsockbuf` on Darwin/BSD) that only the host operator can
    /// raise. Worth a warning: the process is running with a buffer it did
    /// not choose.
    clamped,
    /// The kernel accepted the request but the size could not be read back,
    /// so nothing here is a measurement. Reported separately rather than
    /// being reported as `applied`, which would be a claim this code cannot
    /// support.
    unverified,
    /// The kernel refused the request outright. The default buffer stands.
    unsupported,
};

/// One `getsockopt` readback, in both the units the kernel reports it in and
/// the units the request was made in.
///
/// On most platforms these are the same number. Linux is the reason they are
/// separate fields: it stores `SO_RCVBUF`/`SO_SNDBUF` as *twice* the requested
/// size — the other half is per-datagram bookkeeping, not payload capacity —
/// and reports the doubled figure. Comparing that figure to the request would
/// call a grant of half what was asked for a success, which is exactly the
/// case this whole readback exists to catch.
///
/// Translating between the two is a property of the OS, not of QUIC, so the
/// caller that owns the socket owns the translation and this layer stays
/// OS-neutral.
pub const BufferReadback = struct {
    /// Exactly what `getsockopt` returned. `null` when the readback failed.
    /// This is the number to report: it is what the kernel will say if an
    /// operator checks the socket themselves.
    reported_bytes: ?usize = null,
    /// The same measurement restated in the units the request was made in, so
    /// it can be compared against it. `null` when nothing was requested or
    /// the readback failed.
    granted_bytes: ?usize = null,
};

/// One direction's tuning result. `effective_bytes` is what `getsockopt` read
/// back, never what was asked for: kernels adjust these requests and the
/// adjustment is the interesting part. `granted_bytes` is that same reading
/// made comparable to `requested_bytes` (see `BufferReadback`), and is what
/// the grant/clamp decision is made on.
pub const BufferOutcome = struct {
    requested_bytes: ?usize = null,
    /// `null` when the readback itself failed.
    effective_bytes: ?usize = null,
    /// `null` when nothing was requested, or when the readback failed.
    granted_bytes: ?usize = null,
    status: BufferTuningStatus = .default,
};

pub const EffectiveBufferTuning = struct {
    recv: BufferOutcome = .{},
    send: BufferOutcome = .{},
};

/// Classify one direction's tuning attempt from what the socket layer
/// observed: what was asked for, whether `setsockopt` accepted it, and what
/// `getsockopt` read back afterwards.
///
/// Deliberately platform-neutral and syscall-free so the policy is testable
/// without a socket — the caller owns the syscalls and the platform's readback
/// semantics, this owns the meaning.
pub fn classifyBufferOutcome(requested: ?usize, accepted: bool, readback: BufferReadback) BufferOutcome {
    const want = requested orelse return .{
        .effective_bytes = readback.reported_bytes,
        .status = .default,
    };
    if (!accepted) return .{
        .requested_bytes = want,
        .effective_bytes = readback.reported_bytes,
        .status = .unsupported,
    };
    const granted = readback.granted_bytes orelse return .{
        .requested_bytes = want,
        .effective_bytes = readback.reported_bytes,
        .status = .unverified,
    };
    return .{
        .requested_bytes = want,
        .effective_bytes = readback.reported_bytes,
        .granted_bytes = granted,
        .status = if (granted >= want) .applied else .clamped,
    };
}

pub const ReceiveError = error{
    WouldBlock,
    PacketTooLarge,
    SocketClosed,
    Unexpected,
};

pub const SendError = error{
    PacketTooLarge,
    SocketClosed,
    Unexpected,
};

pub const Clock = struct {
    ctx: *anyopaque,
    nowUsFn: *const fn (*anyopaque) u64,

    pub fn nowUs(self: Clock) u64 {
        return self.nowUsFn(self.ctx);
    }
};

pub const Endpoint = struct {
    ctx: *anyopaque,
    clock: Clock,
    recvFn: *const fn (*anyopaque, []u8, Clock) ReceiveError!ReceivedDatagram,
    sendFn: *const fn (*anyopaque, SendDatagram) SendError!void,
    tuneBuffersFn: *const fn (*anyopaque, BufferTuning) EffectiveBufferTuning,

    pub fn receive(self: Endpoint, scratch: []u8) ReceiveError!ReceivedDatagram {
        return self.recvFn(self.ctx, scratch, self.clock);
    }

    /// Send one complete UDP datagram. Short successful sends are not part of
    /// this contract; an implementation must translate them to an error.
    pub fn send(self: Endpoint, datagram: SendDatagram) SendError!void {
        try self.sendFn(self.ctx, datagram);
    }

    /// Advisory: a request the kernel refuses or trims still leaves a working
    /// endpoint, so this reports what happened rather than failing. The
    /// caller is expected to surface the result, not to act on it.
    pub fn tuneBuffers(self: Endpoint, tuning: BufferTuning) EffectiveBufferTuning {
        return self.tuneBuffersFn(self.ctx, tuning);
    }
};

pub const MaxConnectionIdLen = 20;

pub const ConnectionId = struct {
    bytes: [MaxConnectionIdLen]u8 = [_]u8{0} ** MaxConnectionIdLen,
    len: u8 = 0,

    pub fn init(raw: []const u8) !ConnectionId {
        if (raw.len == 0) return error.EmptyConnectionId;
        if (raw.len > MaxConnectionIdLen) return error.ConnectionIdTooLong;
        var id = ConnectionId{ .len = @intCast(raw.len) };
        @memcpy(id.bytes[0..raw.len], raw);
        return id;
    }

    pub fn slice(self: *const ConnectionId) []const u8 {
        return self.bytes[0..self.len];
    }
};

pub const RouteKey = struct {
    dcid: ConnectionId,
};

pub fn routeByDcid(dcid: []const u8) !RouteKey {
    return .{ .dcid = try ConnectionId.init(dcid) };
}

const FakeClock = struct {
    now_us: u64,

    fn now(ctx: *anyopaque) u64 {
        const self: *FakeClock = @ptrCast(@alignCast(ctx));
        return self.now_us;
    }
};

const FakeEndpoint = struct {
    clock: FakeClock,
    recv_payload: []const u8,
    remote: Address,
    last_sent_len: usize = 0,
    last_tuning: BufferTuning = .{},

    fn receive(ctx: *anyopaque, scratch: []u8, clock: Clock) ReceiveError!ReceivedDatagram {
        const self: *FakeEndpoint = @ptrCast(@alignCast(ctx));
        if (scratch.len < self.recv_payload.len) return error.PacketTooLarge;
        @memcpy(scratch[0..self.recv_payload.len], self.recv_payload);
        return .{
            .bytes = scratch[0..self.recv_payload.len],
            .remote = self.remote,
            .ecn = .ect0,
            .received_at_us = clock.nowUs(),
        };
    }

    fn send(ctx: *anyopaque, datagram: SendDatagram) SendError!void {
        const self: *FakeEndpoint = @ptrCast(@alignCast(ctx));
        self.last_sent_len = datagram.bytes.len;
    }

    fn tune(ctx: *anyopaque, tuning: BufferTuning) EffectiveBufferTuning {
        const self: *FakeEndpoint = @ptrCast(@alignCast(ctx));
        self.last_tuning = tuning;
        return .{
            .recv = classifyBufferOutcome(tuning.recv_bytes, true, .{
                .reported_bytes = tuning.recv_bytes,
                .granted_bytes = tuning.recv_bytes,
            }),
            .send = classifyBufferOutcome(tuning.send_bytes, true, .{
                .reported_bytes = tuning.send_bytes,
                .granted_bytes = tuning.send_bytes,
            }),
        };
    }

    fn endpoint(self: *FakeEndpoint) Endpoint {
        return .{
            .ctx = self,
            .clock = .{ .ctx = &self.clock, .nowUsFn = FakeClock.now },
            .recvFn = FakeEndpoint.receive,
            .sendFn = FakeEndpoint.send,
            .tuneBuffersFn = FakeEndpoint.tune,
        };
    }
};

test "UDP endpoint carries datagram metadata and deterministic time" {
    var fake = FakeEndpoint{
        .clock = .{ .now_us = 42_000 },
        .recv_payload = "packet",
        .remote = Address.ip4(.{ 127, 0, 0, 1 }, 4433),
    };
    const endpoint = fake.endpoint();
    var scratch: [64]u8 = undefined;
    const datagram = try endpoint.receive(&scratch);
    try std.testing.expectEqualSlices(u8, "packet", datagram.bytes);
    try std.testing.expectEqual(AddressFamily.ip4, datagram.remote.family);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 127, 0, 0, 1 }, datagram.remote.slice());
    try std.testing.expectEqual(@as(u16, 4433), datagram.remote.port);
    try std.testing.expectEqual(Ecn.ect0, datagram.ecn);
    try std.testing.expectEqual(@as(u64, 42_000), datagram.received_at_us);
}

test "UDP endpoint exposes send and buffer tuning hooks" {
    var fake = FakeEndpoint{
        .clock = .{ .now_us = 1 },
        .recv_payload = "",
        .remote = Address.ip4(.{ 127, 0, 0, 1 }, 4433),
    };
    const endpoint = fake.endpoint();
    try endpoint.send(.{
        .bytes = "hello",
        .remote = Address.ip4(.{ 127, 0, 0, 1 }, 4433),
        .send_at_us = 100,
    });
    const effective = endpoint.tuneBuffers(.{ .recv_bytes = 4 * 1024 * 1024, .send_bytes = 1024 * 1024 });
    try std.testing.expectEqual(@as(usize, 5), fake.last_sent_len);
    try std.testing.expectEqual(@as(?usize, 4 * 1024 * 1024), fake.last_tuning.recv_bytes);
    try std.testing.expectEqual(BufferTuningStatus.applied, effective.recv.status);
    try std.testing.expectEqual(@as(?usize, 1024 * 1024), effective.send.effective_bytes);
}

test "socket buffer tuning reports what the kernel did, not what was asked" {
    // Nothing requested: the kernel default stands, and reading it back is
    // still worth doing — benchmark metadata wants the number either way.
    const untouched = classifyBufferOutcome(null, false, .{ .reported_bytes = 212_992 });
    try std.testing.expectEqual(BufferTuningStatus.default, untouched.status);
    try std.testing.expectEqual(@as(?usize, null), untouched.requested_bytes);
    try std.testing.expectEqual(@as(?usize, 212_992), untouched.effective_bytes);

    // Exactly what was asked for (Darwin, BSD) is a grant.
    const exact = classifyBufferOutcome(4 * 1024 * 1024, true, .{
        .reported_bytes = 4 * 1024 * 1024,
        .granted_bytes = 4 * 1024 * 1024,
    });
    try std.testing.expectEqual(BufferTuningStatus.applied, exact.status);

    // The interesting case: `setsockopt` succeeded and the kernel still gave
    // a fraction of the request, because a system-wide ceiling
    // (`net.core.rmem_max`) outranks it. Silent without a readback.
    const ceiling = classifyBufferOutcome(64 * 1024 * 1024, true, .{
        .reported_bytes = 425_984,
        .granted_bytes = 212_992,
    });
    try std.testing.expectEqual(BufferTuningStatus.clamped, ceiling.status);
    try std.testing.expectEqual(@as(?usize, 64 * 1024 * 1024), ceiling.requested_bytes);
    try std.testing.expectEqual(@as(?usize, 425_984), ceiling.effective_bytes);
    try std.testing.expectEqual(@as(?usize, 212_992), ceiling.granted_bytes);

    // Accepted but unreadable is not `applied`: nothing was measured, and
    // claiming otherwise would invent a number the process never saw.
    const unverified = classifyBufferOutcome(4 * 1024 * 1024, true, .{});
    try std.testing.expectEqual(BufferTuningStatus.unverified, unverified.status);
    try std.testing.expectEqual(@as(?usize, null), unverified.effective_bytes);
    try std.testing.expectEqual(@as(?usize, null), unverified.granted_bytes);

    // Refused outright: the default buffer is what the socket has, and it is
    // reported rather than the request that failed.
    const refused = classifyBufferOutcome(4 * 1024 * 1024, false, .{ .reported_bytes = 212_992 });
    try std.testing.expectEqual(BufferTuningStatus.unsupported, refused.status);
    try std.testing.expectEqual(@as(?usize, 212_992), refused.effective_bytes);
}

test "a doubled Linux readback is judged in request units, not kernel units" {
    // Linux stores twice what was set and reports the doubled figure. Judging
    // a request against that figure would call any grant of more than half the
    // request a success — including the ones this readback exists to catch —
    // so the decision is made on the reading restated in request units, while
    // the raw kernel number is still what gets reported.

    // A true grant: 4 MiB set, 8 MiB reported, 4 MiB actually granted.
    const granted = classifyBufferOutcome(4 * 1024 * 1024, true, .{
        .reported_bytes = 8 * 1024 * 1024,
        .granted_bytes = 4 * 1024 * 1024,
    });
    try std.testing.expectEqual(BufferTuningStatus.applied, granted.status);
    try std.testing.expectEqual(@as(?usize, 8 * 1024 * 1024), granted.effective_bytes);
    try std.testing.expectEqual(@as(?usize, 4 * 1024 * 1024), granted.granted_bytes);

    // The false-positive window: a 300 KiB request on a host whose
    // `net.core.rmem_max` is 208 KiB. The kernel caps at the ceiling and
    // reports 416 KiB — larger than the request — while the operator got
    // barely two thirds of what they asked for.
    const capped = classifyBufferOutcome(307_200, true, .{
        .reported_bytes = 425_984,
        .granted_bytes = 212_992,
    });
    try std.testing.expectEqual(BufferTuningStatus.clamped, capped.status);
    try std.testing.expect(capped.effective_bytes.? > capped.requested_bytes.?);
    try std.testing.expect(capped.granted_bytes.? < capped.requested_bytes.?);
}

test "socket buffer requests stay inside the setsockopt ABI" {
    // `setsockopt(SO_RCVBUF)` takes a `c_int`. A request that wraps it would
    // be a negative size, so an operator typo is clamped to something the ABI
    // can express rather than being handed to the kernel as-is.
    try std.testing.expectEqual(max_buffer_bytes, clampBufferBytes(std.math.maxInt(usize)));
    try std.testing.expect(max_buffer_bytes <= std.math.maxInt(c_int));
    try std.testing.expectEqual(min_buffer_bytes, clampBufferBytes(1));
    try std.testing.expectEqual(@as(usize, 4 * 1024 * 1024), clampBufferBytes(4 * 1024 * 1024));

    // The bound has to survive *doubling*, not just the ABI: Linux stores
    // twice what it is given and caps the request at `INT_MAX / 2` first, so a
    // maximum that leaves no room for the doubling would be reduced by the
    // kernel and could never be granted in full.
    try std.testing.expect(max_buffer_bytes * 2 <= std.math.maxInt(c_int));
}

test "the maximum request is grantable, not permanently clamped by its own bound" {
    // The exact upper boundary must be able to come back `applied` on a host
    // whose ceiling permits it. A maximum the platform cannot represent would
    // report a one-byte clamp forever and send the operator after a sysctl
    // that was never the cause.
    const at_maximum = classifyBufferOutcome(max_buffer_bytes, true, .{
        // What Linux reports for a fully granted maximum: twice the request.
        .reported_bytes = max_buffer_bytes * 2,
        .granted_bytes = max_buffer_bytes,
    });
    try std.testing.expectEqual(BufferTuningStatus.applied, at_maximum.status);
    try std.testing.expectEqual(@as(?usize, max_buffer_bytes), at_maximum.granted_bytes);

    // And a host ceiling below it is still a clamp, so making the maximum
    // reachable did not cost the diagnostic.
    const capped_at_maximum = classifyBufferOutcome(max_buffer_bytes, true, .{
        .reported_bytes = 425_984,
        .granted_bytes = 212_992,
    });
    try std.testing.expectEqual(BufferTuningStatus.clamped, capped_at_maximum.status);
}

test "DCID routing key owns a bounded connection ID" {
    try std.testing.expectError(error.EmptyConnectionId, routeByDcid(""));
    try std.testing.expectError(error.ConnectionIdTooLong, routeByDcid("012345678901234567890"));
    var source = [_]u8{ 'a', 'b', 'c', 'd' };
    const key = try routeByDcid(&source);
    source[0] = 'z';
    try std.testing.expectEqualSlices(u8, "abcd", key.dcid.slice());
}

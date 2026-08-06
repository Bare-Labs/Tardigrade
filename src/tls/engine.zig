//! Protocol-neutral TLS 1.3 core shell shared by QUIC and future record mode.
//!
//! The current QUIC adapter still owns CRYPTO-frame transport and packet-key
//! installation. This core exposes transport-neutral configuration/state so the
//! TLS handshake and secret lifecycle can be exercised without importing QUIC,
//! HTTP, socket, or record-layer types.

const std = @import("std");
pub const state = @import("state.zig");
pub const events = @import("events.zig");
pub const handshake = @import("handshake.zig");
pub const key_schedule = @import("key_schedule.zig");
const messages = @import("messages.zig");
pub const transcript = @import("transcript.zig");

pub const EngineConfig = struct {
    role: state.Role,
    transport_mode: state.TransportMode,
};

pub const Engine = struct {
    config: EngineConfig,
    core: handshake.Core,
    input: handshake.Reassembler(16 * 1024),

    pub fn init(config: EngineConfig) Engine {
        return .{ .config = config, .core = handshake.Core.init(config.role), .input = .{} };
    }

    pub fn start(self: *Engine) handshake.Error!void {
        try self.core.start();
    }

    pub fn receiveHandshake(self: *Engine, raw: []const u8) handshake.Error!usize {
        try self.input.append(raw);
        var processed: usize = 0;
        while (try self.input.peek()) |message| {
            _ = try self.core.acceptReceived(message.raw);
            try self.input.discard(message.raw.len);
            processed += 1;
        }
        return processed;
    }

    pub fn handshakeState(self: *const Engine) state.HandshakeState {
        return self.core.handshake_state;
    }

    pub fn transcriptHash(self: *const Engine) transcript.Digest {
        return self.core.transcriptHash();
    }

    pub fn canUseRecordLayer(self: *const Engine) bool {
        return self.config.transport_mode == .record;
    }
};

pub fn Driver(comptime Transport: type) type {
    return struct {
        role: state.Role,
        backend: Transport.Backend,
        state: state.DriverState = .idle,
        failure_reason: ?Transport.Error = null,
        sink: Transport.EventSink = .{},

        const Self = @This();

        /// The result of `startOutcome`/`receiveOutcome`: unlike `start`/
        /// `receive`, a terminal error does not discard whatever the backend
        /// already emitted into the sink before failing (for example a fatal
        /// alert, or handshake bytes queued ahead of it) -- both are always
        /// available together.
        pub const Outcome = struct {
            sink: *Transport.EventSink,
            terminal_error: ?Transport.Error,
        };

        pub fn init(role: state.Role, backend: Transport.Backend) Self {
            return .{ .role = role, .backend = backend };
        }

        /// Start the backend and return the driver's internal event sink.
        /// The returned pointer and every event payload slice borrow storage
        /// owned by this driver; they stay valid only until the next `start` or
        /// `receive` call, both of which reset and overwrite the sink.
        pub fn start(self: *Self, params: Transport.TransportParametersType) Transport.Error!*Transport.EventSink {
            if (self.state != .idle) return self.fail(error.InvalidHandshakeState);
            self.state = .in_progress;
            self.sink.reset();
            self.backend.start(self.role, params, &self.sink) catch |err| return self.fail(err);
            return &self.sink;
        }

        /// Like `start`, but on backend failure returns the sink alongside the
        /// error instead of discarding it, so a caller that needs the backend's
        /// terminal output (e.g. a fatal alert emitted just before failing) can
        /// still reach it.
        pub fn startOutcome(self: *Self, params: Transport.TransportParametersType) Outcome {
            if (self.state == .failed) return .{ .sink = &self.sink, .terminal_error = self.failure_reason };
            if (self.state != .idle) {
                // Not already failed, but calling start() again is still
                // invalid (in progress or complete). Reset the sink before
                // marking failed so this invalid call cannot surface a
                // stale event batch -- including a copied traffic
                // secret -- from whatever the driver was doing before it.
                self.sink.reset();
                self.markFailed(error.InvalidHandshakeState);
                return .{ .sink = &self.sink, .terminal_error = self.failure_reason };
            }
            self.state = .in_progress;
            self.sink.reset();
            self.backend.start(self.role, params, &self.sink) catch |err| self.markFailed(err);
            return .{ .sink = &self.sink, .terminal_error = self.failure_reason };
        }

        /// Drive the backend with received handshake bytes and return the
        /// driver's internal event sink. The returned pointer and payload slices
        /// are borrowed only until the next `start` or `receive` call.
        pub fn receive(self: *Self, epoch: Transport.EpochType, bytes: []const u8) Transport.Error!*Transport.EventSink {
            if (self.state == .failed) return self.failure_reason.?;
            self.sink.reset();
            self.backend.receive(epoch, bytes, &self.sink) catch |err| return self.fail(err);
            return &self.sink;
        }

        /// Like `receive`, but on backend failure returns the sink alongside
        /// the error instead of discarding it. See `startOutcome`.
        pub fn receiveOutcome(self: *Self, epoch: Transport.EpochType, bytes: []const u8) Outcome {
            if (self.state == .failed) return .{ .sink = &self.sink, .terminal_error = self.failure_reason };
            self.sink.reset();
            self.backend.receive(epoch, bytes, &self.sink) catch |err| self.markFailed(err);
            return .{ .sink = &self.sink, .terminal_error = self.failure_reason };
        }

        pub fn complete(self: *Self) void {
            self.state = .complete;
        }

        pub fn isComplete(self: *const Self) bool {
            return self.state == .complete;
        }

        /// True while the backend has parked an asynchronous authentication
        /// operation (#334). The driver owner polls `resumeAuth` until this
        /// clears before treating the handshake as stalled.
        pub fn authPending(self: *const Self) bool {
            return self.backend.authPending();
        }

        /// Poll a parked authentication operation, returning the driver's event
        /// sink with whatever progress the backend emitted. Resets the sink like
        /// `receive`, so borrowed payload slices are valid only until the next
        /// `start`/`receive`/`resumeAuth`. On backend failure the driver is
        /// marked failed and the error returned.
        pub fn resumeAuth(self: *Self) Transport.Error!*Transport.EventSink {
            if (self.state == .failed) return self.failure_reason.?;
            self.sink.reset();
            self.backend.resumeAuth(&self.sink) catch |err| return self.fail(err);
            return &self.sink;
        }

        /// Like `resumeAuth`, but on backend failure returns the sink alongside
        /// the error (preserving any fatal alert emitted before failing), for
        /// production drivers that flush terminal output. See `receiveOutcome`.
        pub fn resumeAuthOutcome(self: *Self) Outcome {
            if (self.state == .failed) return .{ .sink = &self.sink, .terminal_error = self.failure_reason };
            self.sink.reset();
            self.backend.resumeAuth(&self.sink) catch |err| self.markFailed(err);
            return .{ .sink = &self.sink, .terminal_error = self.failure_reason };
        }

        pub fn failure(self: *const Self) ?Transport.Error {
            return self.failure_reason;
        }

        pub fn fail(self: *Self, err: Transport.Error) Transport.Error {
            self.markFailed(err);
            return err;
        }

        fn markFailed(self: *Self, err: Transport.Error) void {
            self.state = .failed;
            self.failure_reason = err;
        }

        /// Final teardown: securely wipes any traffic secrets still copied
        /// into the internal sink from the last `start`/`receive` call. Every
        /// owner of a `Driver` -- QUIC's handshake adapter and record mode
        /// alike -- must call this exactly once when the handshake object is
        /// discarded, whether it completed, failed, or was abandoned mid-flight.
        pub fn deinit(self: *Self) void {
            self.sink.deinit();
            self.backend.deinit();
        }
    };
}

test "core engine can be instantiated for record mode without record framing" {
    var engine = Engine.init(.{ .role = .server, .transport_mode = .record });
    try std.testing.expect(engine.canUseRecordLayer());
    try engine.start();
    try std.testing.expectEqual(state.HandshakeState.idle, engine.handshakeState());
}

test "engine drives protocol-neutral handshake state" {
    var engine = Engine.init(.{ .role = .server, .transport_mode = .record });
    try engine.start();
    // This shell is protocol-neutral and never selects a cipher suite on
    // its own (#564) — select a family explicitly so `transcriptHash()`
    // below reflects real hashed bytes rather than the empty pre-selection
    // digest.
    engine.core.transcript.selectFamily(.sha256);

    var buffer: [32]u8 = undefined;
    var writer = handshake.Writer{ .buf = &buffer };
    try writer.u8_(@intFromEnum(handshake.MessageType.client_hello));
    const length = try writer.reserve(3);
    writer.patch(3, length);
    _ = try engine.receiveHandshake(writer.written());
    try std.testing.expectEqual(state.HandshakeState.server_hello, engine.handshakeState());
    const transcript_hash = engine.transcriptHash();
    try std.testing.expectEqual(@as(usize, 32), transcript_hash.len);
    try std.testing.expect(!std.mem.allEqual(u8, transcript_hash.slice(), 0));
}

test "engine retains fragmented input and drains coalesced messages" {
    const valid_client_hello = [_]u8{ 1, 0, 0, 0 };
    const duplicate_client_hello = [_]u8{ 1, 0, 0, 0 };

    for (0..valid_client_hello.len + 1) |split| {
        var engine = Engine.init(.{ .role = .server, .transport_mode = .record });
        try engine.start();
        const first_count: usize = if (split == valid_client_hello.len) 1 else 0;
        const second_count: usize = if (split == valid_client_hello.len) 0 else 1;
        try std.testing.expectEqual(first_count, try engine.receiveHandshake(valid_client_hello[0..split]));
        try std.testing.expectEqual(second_count, try engine.receiveHandshake(valid_client_hello[split..]));
        try std.testing.expectEqual(state.HandshakeState.server_hello, engine.handshakeState());
    }

    var engine = Engine.init(.{ .role = .server, .transport_mode = .record });
    try engine.start();
    try std.testing.expectEqual(@as(usize, 1), try engine.receiveHandshake(&valid_client_hello));
    try std.testing.expectError(error.UnexpectedHandshakeMessage, engine.receiveHandshake(&duplicate_client_hello));

    var coalesced = Engine.init(.{ .role = .server, .transport_mode = .record });
    try coalesced.start();
    const complete_plus_partial = valid_client_hello ++ duplicate_client_hello[0..3].*;
    try std.testing.expectEqual(@as(usize, 1), try coalesced.receiveHandshake(&complete_plus_partial));
    try std.testing.expectError(error.UnexpectedHandshakeMessage, coalesced.receiveHandshake(duplicate_client_hello[3..]));
}

test "generic driver starts backend and stores emitted events" {
    const T = @import("transport.zig").Contract(void, enum { initial }, error{ InvalidHandshakeState, TransportBufferOverflow });
    const D = Driver(T);
    const Backend = struct {
        fn start(_: *anyopaque, role: state.Role, _: void, sink: *T.EventSink) T.Error!void {
            std.debug.assert(role == .client);
            try sink.emitHandshakeBytes(.initial, "hello");
        }

        fn receive(_: *anyopaque, _: T.EpochType, _: []const u8, _: *T.EventSink) T.Error!void {}
    };

    var context: u8 = 0;
    var driver = D.init(.client, .{
        .ptr = &context,
        .startFn = Backend.start,
        .receiveFn = Backend.receive,
    });
    const sink = try driver.start({});
    try std.testing.expectEqual(state.DriverState.in_progress, driver.state);
    try std.testing.expectEqual(@as(usize, 1), sink.len);
    try std.testing.expectEqualStrings("hello", sink.items[0].handshake_bytes.data);
}

test "generic driver records backend failure" {
    const T = @import("transport.zig").Contract(void, enum { initial }, error{ InvalidHandshakeState, TransportBufferOverflow });
    const D = Driver(T);
    const Backend = struct {
        fn start(_: *anyopaque, _: state.Role, _: void, _: *T.EventSink) T.Error!void {
            return error.TransportBufferOverflow;
        }

        fn receive(_: *anyopaque, _: T.EpochType, _: []const u8, _: *T.EventSink) T.Error!void {}
    };

    var context: u8 = 0;
    var driver = D.init(.server, .{
        .ptr = &context,
        .startFn = Backend.start,
        .receiveFn = Backend.receive,
    });
    try std.testing.expectError(error.TransportBufferOverflow, driver.start({}));
    try std.testing.expectEqual(state.DriverState.failed, driver.state);
    try std.testing.expectEqual(error.TransportBufferOverflow, driver.failure().?);
}

test "generic driver rejects repeated start calls" {
    const T = @import("transport.zig").Contract(void, enum { initial }, error{ InvalidHandshakeState, TransportBufferOverflow });
    const D = Driver(T);
    const Backend = struct {
        fn start(_: *anyopaque, _: state.Role, _: void, sink: *T.EventSink) T.Error!void {
            try sink.emitHandshakeBytes(.initial, "hello");
        }

        fn receive(_: *anyopaque, _: T.EpochType, _: []const u8, _: *T.EventSink) T.Error!void {}
    };

    var context: u8 = 0;
    var driver = D.init(.client, .{
        .ptr = &context,
        .startFn = Backend.start,
        .receiveFn = Backend.receive,
    });
    _ = try driver.start({});
    try std.testing.expectError(error.InvalidHandshakeState, driver.start({}));
    try std.testing.expectEqual(state.DriverState.failed, driver.state);
    try std.testing.expectEqual(error.InvalidHandshakeState, driver.failure().?);
}

test "generic driver rejects start after completion" {
    const T = @import("transport.zig").Contract(void, enum { initial }, error{ InvalidHandshakeState, TransportBufferOverflow });
    const D = Driver(T);
    const Backend = struct {
        fn start(_: *anyopaque, _: state.Role, _: void, _: *T.EventSink) T.Error!void {}
        fn receive(_: *anyopaque, _: T.EpochType, _: []const u8, _: *T.EventSink) T.Error!void {}
    };

    var context: u8 = 0;
    var driver = D.init(.server, .{
        .ptr = &context,
        .startFn = Backend.start,
        .receiveFn = Backend.receive,
    });
    _ = try driver.start({});
    driver.complete();
    try std.testing.expectError(error.InvalidHandshakeState, driver.start({}));
}

test "driver deinit securely wipes the last emitted traffic secret" {
    const T = @import("transport.zig").Contract(void, enum { handshake }, error{ InvalidHandshakeState, TransportBufferOverflow });
    const D = Driver(T);
    const Backend = struct {
        fn start(_: *anyopaque, _: state.Role, _: void, sink: *T.EventSink) T.Error!void {
            try sink.emitSecret(.handshake, .write, "last traffic secret before teardown");
        }
        fn receive(_: *anyopaque, _: T.EpochType, _: []const u8, _: *T.EventSink) T.Error!void {}
    };

    var context: u8 = 0;
    var driver = D.init(.client, .{
        .ptr = &context,
        .startFn = Backend.start,
        .receiveFn = Backend.receive,
    });
    const sink = try driver.start({});
    try std.testing.expect(sink.used > 0);
    const used = sink.used;

    driver.deinit();
    try std.testing.expectEqual(@as(usize, 0), driver.sink.used);
    for (driver.sink.scratch[0..used]) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
}

test "receiveOutcome carries a fatal alert emitted just before the backend fails" {
    const alerts = @import("alerts.zig");
    const T = @import("transport.zig").Contract(void, enum { initial }, error{ InvalidHandshakeState, TransportBufferOverflow, UnexpectedHandshakeMessage });
    const D = Driver(T);
    const Backend = struct {
        fn start(_: *anyopaque, _: state.Role, _: void, _: *T.EventSink) T.Error!void {}
        fn receive(_: *anyopaque, _: T.EpochType, _: []const u8, sink: *T.EventSink) T.Error!void {
            try sink.emitHandshakeBytes(.initial, "queued before failure");
            try sink.emitFatalAlert(alerts.fromHandshakeError(error.UnexpectedHandshakeMessage));
            return error.UnexpectedHandshakeMessage;
        }
    };

    var context: u8 = 0;
    var driver = D.init(.server, .{
        .ptr = &context,
        .startFn = Backend.start,
        .receiveFn = Backend.receive,
    });
    _ = try driver.start({});

    const outcome = driver.receiveOutcome(.initial, "malformed");
    try std.testing.expectEqual(error.UnexpectedHandshakeMessage, outcome.terminal_error.?);
    try std.testing.expect(outcome.sink.hasFatalAlert());
    try std.testing.expectEqualStrings("queued before failure", outcome.sink.items[0].handshake_bytes.data);
    try std.testing.expectEqual(state.DriverState.failed, driver.state);

    // Once failed, further calls keep surfacing the same terminal error and
    // sink contents rather than re-invoking the backend.
    const again = driver.receiveOutcome(.initial, "more");
    try std.testing.expectEqual(error.UnexpectedHandshakeMessage, again.terminal_error.?);
    try std.testing.expect(again.sink.hasFatalAlert());
}

test "startOutcome after backend failure keeps returning the same terminal error without re-invoking the backend" {
    const alerts = @import("alerts.zig");
    const T = @import("transport.zig").Contract(void, enum { initial }, error{ InvalidHandshakeState, TransportBufferOverflow, UnexpectedHandshakeMessage });
    const D = Driver(T);
    const Backend = struct {
        calls: usize = 0,

        fn start(ptr: *anyopaque, _: state.Role, _: void, sink: *T.EventSink) T.Error!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.calls += 1;
            try sink.emitFatalAlert(alerts.fromHandshakeError(error.UnexpectedHandshakeMessage));
            return error.UnexpectedHandshakeMessage;
        }
        fn receive(_: *anyopaque, _: T.EpochType, _: []const u8, _: *T.EventSink) T.Error!void {}
    };

    var backend = Backend{};
    var driver = D.init(.client, .{
        .ptr = &backend,
        .startFn = Backend.start,
        .receiveFn = Backend.receive,
    });

    const first = driver.startOutcome({});
    try std.testing.expectEqual(error.UnexpectedHandshakeMessage, first.terminal_error.?);
    try std.testing.expect(first.sink.hasFatalAlert());
    try std.testing.expectEqual(@as(usize, 1), backend.calls);

    const second = driver.startOutcome({});
    try std.testing.expectEqual(error.UnexpectedHandshakeMessage, second.terminal_error.?);
    try std.testing.expect(second.sink.hasFatalAlert());
    try std.testing.expectEqual(@as(usize, 1), backend.calls);
}

test "a second startOutcome after a successful start does not leak the prior event batch" {
    const T = @import("transport.zig").Contract(void, enum { handshake }, error{ InvalidHandshakeState, TransportBufferOverflow });
    const D = Driver(T);
    const Backend = struct {
        fn start(_: *anyopaque, _: state.Role, _: void, sink: *T.EventSink) T.Error!void {
            try sink.emitSecret(.handshake, .write, "should not survive a second start");
        }
        fn receive(_: *anyopaque, _: T.EpochType, _: []const u8, _: *T.EventSink) T.Error!void {}
    };

    var context: u8 = 0;
    var driver = D.init(.client, .{
        .ptr = &context,
        .startFn = Backend.start,
        .receiveFn = Backend.receive,
    });

    const first = driver.startOutcome({});
    try std.testing.expectEqual(@as(?T.Error, null), first.terminal_error);
    try std.testing.expectEqual(@as(usize, 1), first.sink.len);

    const second = driver.startOutcome({});
    try std.testing.expectEqual(error.InvalidHandshakeState, second.terminal_error.?);
    try std.testing.expectEqual(@as(usize, 0), second.sink.len);
    try std.testing.expectEqual(@as(usize, 0), second.sink.used);
}

test "driver deinit is safe after a failed handshake" {
    const T = @import("transport.zig").Contract(void, enum { initial }, error{ InvalidHandshakeState, TransportBufferOverflow });
    const D = Driver(T);
    const Backend = struct {
        fn start(_: *anyopaque, _: state.Role, _: void, sink: *T.EventSink) T.Error!void {
            try sink.emitHandshakeBytes(.initial, "partial before failure");
            return error.TransportBufferOverflow;
        }
        fn receive(_: *anyopaque, _: T.EpochType, _: []const u8, _: *T.EventSink) T.Error!void {}
    };

    var context: u8 = 0;
    var driver = D.init(.server, .{
        .ptr = &context,
        .startFn = Backend.start,
        .receiveFn = Backend.receive,
    });
    try std.testing.expectError(error.TransportBufferOverflow, driver.start({}));
    driver.deinit();
    try std.testing.expectEqual(@as(usize, 0), driver.sink.used);
}

test "fuzz: TLS protocol: handshake core and driver reject malformed ordering with sticky terminal errors" {
    try std.testing.fuzz({}, fuzzHandshakeCoreAndDriver, .{ .corpus = &.{
        "",
        &[_]u8{ 0, @intFromEnum(messages.MessageType.client_hello), 0, 0, 0 },
        &[_]u8{ 1, @intFromEnum(messages.MessageType.finished), 0, 0, 0 },
        &[_]u8{ 2, @intFromEnum(messages.MessageType.server_hello), 0, 0, 3, 'h', 'r', 'r' },
        &([_]u8{0xff} ** 96),
    } });
}

fn fuzzHandshakeCoreAndDriver(_: void, smith: *std.testing.Smith) !void {
    try exerciseKnownValidHrrProgression(smith);

    const DriverError = handshake.Error || error{TransportBufferOverflow};
    const T = @import("transport.zig").Contract(void, enum { handshake }, DriverError);
    const D = Driver(T);
    const Backend = struct {
        core: handshake.Core,
        calls: usize = 0,

        fn start(ptr: *anyopaque, role: state.Role, _: void, _: *T.EventSink) T.Error!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.calls += 1;
            self.core = handshake.Core.init(role);
            try self.core.start();
            self.core.transcript.selectFamily(.sha256);
        }

        fn receive(ptr: *anyopaque, _: T.EpochType, bytes: []const u8, _: *T.EventSink) T.Error!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.calls += 1;
            if (bytes.len == 0) return error.MalformedHandshake;
            const op = bytes[0] % 6;
            const raw = bytes[1..];
            switch (op) {
                0 => _ = try self.core.acceptReceived(raw),
                1 => try self.core.recordSent(raw),
                2 => _ = try self.core.acceptHelloRetryRequest(raw),
                3 => try self.core.recordHelloRetryRequest(raw),
                4 => try self.core.recordSecondClientHello(raw),
                else => _ = try self.core.acceptSecondClientHello(raw),
            }
        }
    };

    var backend = Backend{ .core = handshake.Core.init(if (smith.index(2) == 0) .client else .server) };
    var driver = D.init(if (smith.index(2) == 0) .client else .server, .{
        .ptr = &backend,
        .startFn = Backend.start,
        .receiveFn = Backend.receive,
    });
    defer driver.deinit();

    const start = driver.startOutcome({});
    try std.testing.expectEqual(@as(?T.Error, null), start.terminal_error);
    try std.testing.expectEqual(state.DriverState.in_progress, driver.state);

    var frame_storage: [128]u8 = undefined;
    const frame = try fuzzHandshakeFrame(smith, &frame_storage);
    var command_storage: [129]u8 = undefined;
    command_storage[0] = @intCast(smith.index(6));
    @memcpy(command_storage[1..][0..frame.len], frame);
    const command = command_storage[0 .. 1 + frame.len];

    const before_calls = backend.calls;
    const first = driver.receiveOutcome(.handshake, command);
    if (first.terminal_error) |err| {
        try std.testing.expectEqual(state.DriverState.failed, driver.state);
        try std.testing.expectEqual(err, driver.failure().?);
        const state_after_failure = backend.core.handshake_state;
        const lifecycle_after_failure = backend.core.handshake_lifecycle;
        const calls_after_failure = backend.calls;
        const sink_len_after_failure = first.sink.len;
        const sink_used_after_failure = first.sink.used;
        const again = driver.receiveOutcome(.handshake, command);
        try std.testing.expectEqual(err, again.terminal_error.?);
        try std.testing.expectEqual(calls_after_failure, backend.calls);
        try std.testing.expectEqual(sink_len_after_failure, again.sink.len);
        try std.testing.expectEqual(sink_used_after_failure, again.sink.used);
        try std.testing.expectEqual(state_after_failure, backend.core.handshake_state);
        try std.testing.expectEqual(lifecycle_after_failure, backend.core.handshake_lifecycle);
    } else {
        try std.testing.expect(backend.calls > before_calls);
        const repeated = driver.receiveOutcome(.handshake, command);
        const err = repeated.terminal_error orelse return error.TestExpectedError;
        try std.testing.expectEqual(error.UnexpectedHandshakeMessage, err);

        const calls_after_failure = backend.calls;
        const state_after_failure = backend.core.handshake_state;
        const sink_len_after_failure = repeated.sink.len;
        const sink_used_after_failure = repeated.sink.used;
        const again = driver.receiveOutcome(.handshake, command);
        try std.testing.expectEqual(err, again.terminal_error.?);
        try std.testing.expectEqual(calls_after_failure, backend.calls);
        try std.testing.expectEqual(sink_len_after_failure, again.sink.len);
        try std.testing.expectEqual(sink_used_after_failure, again.sink.used);
        try std.testing.expectEqual(state_after_failure, backend.core.handshake_state);
    }
}

fn exerciseKnownValidHrrProgression(smith: *std.testing.Smith) !void {
    var client = handshake.Core.init(.client);
    var server = handshake.Core.init(.server);
    try client.start();
    try server.start();
    client.transcript.selectFamily(if (smith.index(2) == 0) .sha256 else .sha384);
    server.transcript.selectFamily(client.transcript.family().?);

    var ch1_buf: [32]u8 = undefined;
    var hrr_buf: [32]u8 = undefined;
    var ch2_buf: [32]u8 = undefined;
    var sh_buf: [32]u8 = undefined;
    const ch1 = try messages.encode(.client_hello, "one", &ch1_buf);
    try client.recordSent(ch1);
    _ = try server.acceptReceived(ch1);
    const hrr = try messages.encode(.server_hello, "hrr", &hrr_buf);
    try server.recordHelloRetryRequest(hrr);
    _ = try client.acceptHelloRetryRequest(hrr);
    const ch2 = try messages.encode(.client_hello, "two", &ch2_buf);
    try client.recordSecondClientHello(ch2);
    _ = try server.acceptSecondClientHello(ch2);
    const sh = try messages.encode(.server_hello, "ok", &sh_buf);
    try server.recordSent(sh);
    _ = try client.acceptReceived(sh);

    try std.testing.expectEqual(handshake.RetryState.hrr_received, client.retry_state);
    try std.testing.expectEqual(handshake.RetryState.hrr_sent, server.retry_state);
    try std.testing.expect(client.transcriptHash().eql(&server.transcriptHash()));
}

fn fuzzHandshakeFrame(smith: *std.testing.Smith, out: []u8) ![]const u8 {
    const kinds = [_]messages.MessageType{ .client_hello, .server_hello, .encrypted_extensions, .certificate, .certificate_verify, .finished };
    var body: [32]u8 = undefined;
    const body_len = smith.index(body.len + 1);
    smith.bytes(body[0..body_len]);
    const frame = try messages.encode(kinds[smith.index(kinds.len)], body[0..body_len], out);
    if (smith.index(4) == 0 and frame.len > 0) {
        out[0] = 0xff;
    } else if (smith.index(4) == 0 and frame.len >= 4) {
        out[1] = 0xff;
        out[2] = 0xff;
        out[3] = 0xff;
    }
    return frame;
}

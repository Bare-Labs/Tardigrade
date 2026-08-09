const std = @import("std");

pub const Direction = enum {
    downstream_to_upstream,
    upstream_to_downstream,

    pub fn label(self: Direction) []const u8 {
        return switch (self) {
            .downstream_to_upstream => "downstream_to_upstream",
            .upstream_to_downstream => "upstream_to_downstream",
        };
    }
};

/// Which peer's reads a pause/resume transition applies to.
pub const Side = enum {
    downstream,
    upstream,

    pub fn label(self: Side) []const u8 {
        return switch (self) {
            .downstream => "downstream",
            .upstream => "upstream",
        };
    }
};

pub const Scope = enum {
    stream,
    connection,
    origin,
    global,

    pub fn label(self: Scope) []const u8 {
        return switch (self) {
            .stream => "stream",
            .connection => "connection",
            .origin => "origin",
            .global => "global",
        };
    }
};

pub const Limits = struct {
    per_stream_low_watermark: usize,
    per_stream_high_watermark: usize,
    per_stream_hard_limit: usize,
    per_origin_hard_limit: usize,
    global_hard_limit: usize,

    /// The shipped defaults, and the single source of truth for them:
    /// `edge_config` parses each environment override against these, and code
    /// that needs a valid policy without a config (tests, unpooled
    /// connections) uses them directly rather than inventing its own.
    pub fn defaults() Limits {
        return .{
            .per_stream_low_watermark = 256 * 1024,
            .per_stream_high_watermark = 768 * 1024,
            .per_stream_hard_limit = 1024 * 1024,
            .per_origin_hard_limit = 0,
            .global_hard_limit = 0,
        };
    }

    pub fn validate(self: Limits) !void {
        if (self.per_stream_low_watermark == 0 or
            self.per_stream_high_watermark == 0 or
            self.per_stream_hard_limit == 0)
        {
            return error.InvalidBufferLimits;
        }
        if (!(self.per_stream_low_watermark < self.per_stream_high_watermark and
            self.per_stream_high_watermark <= self.per_stream_hard_limit))
        {
            return error.InvalidBufferLimits;
        }
        if (self.per_origin_hard_limit != 0 and self.per_origin_hard_limit < self.per_stream_hard_limit) {
            return error.InvalidBufferLimits;
        }
        if (self.global_hard_limit != 0 and self.global_hard_limit < self.per_stream_hard_limit) {
            return error.InvalidBufferLimits;
        }
        // The high watermark becomes an HTTP/2 receive window verbatim; a value
        // that would have to be clamped would silently stop matching the
        // configured policy.
        if (self.per_stream_high_watermark > max_stream_receive_window) {
            return error.InvalidBufferLimits;
        }
    }
};

/// Largest window HTTP/2 flow control can advertise (RFC 9113 §6.9.1). The
/// per-stream policy is clamped to this when it is turned into a receive
/// window; `validate` rejects a high watermark that would need clamping.
pub const max_stream_receive_window: usize = 0x7FFF_FFFF;

/// The receive window a streaming HTTP/2 stream advertises: the per-stream high
/// watermark, so the peer stops sending exactly where the accounting model says
/// the queue is full. The hard limit (>= high) absorbs DATA already in flight
/// when the window closes.
pub fn streamReceiveWindow(limits: Limits) u31 {
    return @intCast(@min(limits.per_stream_high_watermark, max_stream_receive_window));
}

pub const Snapshot = struct {
    current: usize,
    high_watermark_events: u64,
    limit_exceeded_events: u64,
    above_high_watermark: bool,
};

pub const Observer = struct {
    context: *anyopaque,
    recordReservationFn: *const fn (*anyopaque, Direction, usize, bool, bool) void,
    releaseReservationFn: *const fn (*anyopaque, Direction, usize) void,
    /// Optional: a hard-limit rejection at an aggregate scope (origin/global).
    /// Per-stream rejections are reported through `recordReservationFn`.
    recordAggregateLimitExceededFn: ?*const fn (*anyopaque, Direction, Scope) void = null,
    /// Optional: reads on `side` stopped being credited because a queue rose to
    /// its high watermark, and resumed once it drained back below low.
    recordReadPauseFn: ?*const fn (*anyopaque, Side) void = null,
    recordReadResumeFn: ?*const fn (*anyopaque, Side) void = null,

    pub fn recordReservation(self: Observer, direction: Direction, bytes: usize, high_watermark: bool, limit_exceeded: bool) void {
        self.recordReservationFn(self.context, direction, bytes, high_watermark, limit_exceeded);
    }

    pub fn releaseReservation(self: Observer, direction: Direction, bytes: usize) void {
        self.releaseReservationFn(self.context, direction, bytes);
    }

    pub fn recordAggregateLimitExceeded(self: Observer, direction: Direction, scope: Scope) void {
        if (self.recordAggregateLimitExceededFn) |f| f(self.context, direction, scope);
    }

    pub fn recordReadPause(self: Observer, side: Side) void {
        if (self.recordReadPauseFn) |f| f(self.context, side);
    }

    pub fn recordReadResume(self: Observer, side: Side) void {
        if (self.recordReadResumeFn) |f| f(self.context, side);
    }
};

/// Which aggregate scope refused a reservation. Distinct errors so the caller
/// can label the metric without a second lookup.
pub const AggregateError = error{
    OriginBufferLimitExceeded,
    GlobalBufferLimitExceeded,
};

pub fn aggregateFailureScope(err: AggregateError) Scope {
    return switch (err) {
        error.OriginBufferLimitExceeded => .origin,
        error.GlobalBufferLimitExceeded => .global,
    };
}

/// Thread-safe reservation counter for a scope shared by many streams (one
/// upstream origin, or the whole process). Concurrent streams reserve here
/// *before* they may retain bytes, so concurrency cannot multiply the
/// per-stream bound without bound. A zero hard limit means "unlimited" and
/// keeps the counter as a pure gauge.
///
/// Lock-free: `reserve` is a compare-and-swap loop against the scope's current
/// byte count, so the HTTP/2 reader thread never blocks another origin's reader
/// on a shared mutex.
pub const Aggregate = struct {
    scope: Scope,
    hard_limit: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    current: [2]std.atomic.Value(usize) = .{
        std.atomic.Value(usize).init(0),
        std.atomic.Value(usize).init(0),
    },
    limit_exceeded_events: [2]std.atomic.Value(u64) = .{
        std.atomic.Value(u64).init(0),
        std.atomic.Value(u64).init(0),
    },

    pub fn init(scope: Scope, hard_limit: usize) Aggregate {
        return .{
            .scope = scope,
            .hard_limit = std.atomic.Value(usize).init(hard_limit),
        };
    }

    /// Apply a reloaded limit. Bytes already reserved above the new limit stay
    /// reserved; the next reservation is refused until the scope drains.
    pub fn setHardLimit(self: *Aggregate, hard_limit: usize) void {
        self.hard_limit.store(hard_limit, .monotonic);
    }

    pub fn hardLimit(self: *const Aggregate) usize {
        return self.hard_limit.load(.monotonic);
    }

    pub fn reserve(self: *Aggregate, direction: Direction, bytes: usize) error{BufferLimitExceeded}!void {
        const slot = &self.current[@intFromEnum(direction)];
        const limit = self.hard_limit.load(.monotonic);
        var current = slot.load(.monotonic);
        while (true) {
            const next = std.math.add(usize, current, bytes) catch {
                self.noteLimitExceeded(direction);
                return error.BufferLimitExceeded;
            };
            if (limit != 0 and next > limit) {
                self.noteLimitExceeded(direction);
                return error.BufferLimitExceeded;
            }
            if (slot.cmpxchgWeak(current, next, .monotonic, .monotonic)) |actual| {
                current = actual;
                continue;
            }
            return;
        }
    }

    pub fn release(self: *Aggregate, direction: Direction, bytes: usize) void {
        if (bytes == 0) return;
        const slot = &self.current[@intFromEnum(direction)];
        std.debug.assert(slot.load(.monotonic) >= bytes);
        _ = slot.fetchSub(bytes, .monotonic);
    }

    pub fn currentBytes(self: *const Aggregate, direction: Direction) usize {
        return self.current[@intFromEnum(direction)].load(.monotonic);
    }

    pub fn limitExceededEvents(self: *const Aggregate, direction: Direction) u64 {
        return self.limit_exceeded_events[@intFromEnum(direction)].load(.monotonic);
    }

    fn noteLimitExceeded(self: *Aggregate, direction: Direction) void {
        _ = self.limit_exceeded_events[@intFromEnum(direction)].fetchAdd(1, .monotonic);
    }
};

/// The aggregate scopes one stream's queued bytes must clear. Either member may
/// be null (a path with no origin identity, or a test harness), which makes
/// that scope unlimited and unaccounted.
pub const AggregateCapacity = struct {
    origin: ?*Aggregate = null,
    global: ?*Aggregate = null,

    /// Reserve at every configured scope, or nothing at all: a refusal at the
    /// origin scope rolls the global reservation back, so no scope is left
    /// holding bytes the stream never retained.
    pub fn reserve(self: AggregateCapacity, direction: Direction, bytes: usize) AggregateError!void {
        if (self.global) |g| {
            g.reserve(direction, bytes) catch return error.GlobalBufferLimitExceeded;
        }
        if (self.origin) |o| {
            o.reserve(direction, bytes) catch {
                if (self.global) |g| g.release(direction, bytes);
                return error.OriginBufferLimitExceeded;
            };
        }
    }

    pub fn release(self: AggregateCapacity, direction: Direction, bytes: usize) void {
        if (self.origin) |o| o.release(direction, bytes);
        if (self.global) |g| g.release(direction, bytes);
    }
};

/// Small owner-local accounting primitive for bytes currently retained by a
/// proxy body buffer or queue. Shared aggregate accounting remains outside this
/// type; callers record this object's transitions into the process metrics.
pub const Account = struct {
    direction: Direction,
    scope: Scope,
    limits: Limits,
    current: usize = 0,
    high_watermark_events: u64 = 0,
    limit_exceeded_events: u64 = 0,
    above_high_watermark: bool = false,

    pub fn init(direction: Direction, scope: Scope, limits: Limits) Account {
        std.debug.assert(scope == .stream);
        return .{
            .direction = direction,
            .scope = scope,
            .limits = limits,
        };
    }

    pub fn reserve(self: *Account, bytes: usize) !void {
        const next = std.math.add(usize, self.current, bytes) catch {
            self.limit_exceeded_events += 1;
            return error.BufferLimitExceeded;
        };
        if (next > self.limits.per_stream_hard_limit) {
            self.limit_exceeded_events += 1;
            return error.BufferLimitExceeded;
        }
        self.current = next;
        if (!self.above_high_watermark and self.current >= self.limits.per_stream_high_watermark) {
            self.above_high_watermark = true;
            self.high_watermark_events += 1;
        }
    }

    pub fn release(self: *Account, bytes: usize) !void {
        if (bytes > self.current) return error.BufferAccountingUnderflow;
        self.current -= bytes;
        if (self.above_high_watermark and self.current <= self.limits.per_stream_low_watermark) {
            self.above_high_watermark = false;
        }
    }

    pub fn releaseAll(self: *Account) void {
        self.current = 0;
        self.above_high_watermark = false;
    }

    pub fn snapshot(self: *const Account) Snapshot {
        return .{
            .current = self.current,
            .high_watermark_events = self.high_watermark_events,
            .limit_exceeded_events = self.limit_exceeded_events,
            .above_high_watermark = self.above_high_watermark,
        };
    }
};

test "proxy buffer account validates low high hard ordering" {
    try (Limits{
        .per_stream_low_watermark = 4,
        .per_stream_high_watermark = 8,
        .per_stream_hard_limit = 16,
        .per_origin_hard_limit = 0,
        .global_hard_limit = 0,
    }).validate();

    try std.testing.expectError(error.InvalidBufferLimits, (Limits{
        .per_stream_low_watermark = 8,
        .per_stream_high_watermark = 8,
        .per_stream_hard_limit = 16,
        .per_origin_hard_limit = 0,
        .global_hard_limit = 0,
    }).validate());

    try std.testing.expectError(error.InvalidBufferLimits, (Limits{
        .per_stream_low_watermark = 4,
        .per_stream_high_watermark = 8,
        .per_stream_hard_limit = 16,
        .per_origin_hard_limit = 12,
        .global_hard_limit = 0,
    }).validate());
}

test "proxy buffer account tracks high low transitions and release" {
    const limits = Limits{
        .per_stream_low_watermark = 4,
        .per_stream_high_watermark = 8,
        .per_stream_hard_limit = 16,
        .per_origin_hard_limit = 0,
        .global_hard_limit = 0,
    };
    var account = Account.init(.upstream_to_downstream, .stream, limits);

    try account.reserve(7);
    try std.testing.expectEqual(@as(usize, 7), account.snapshot().current);
    try std.testing.expect(!account.snapshot().above_high_watermark);

    try account.reserve(1);
    try std.testing.expect(account.snapshot().above_high_watermark);
    try std.testing.expectEqual(@as(u64, 1), account.snapshot().high_watermark_events);

    try account.release(3);
    try std.testing.expect(account.snapshot().above_high_watermark);
    try account.release(1);
    try std.testing.expect(!account.snapshot().above_high_watermark);

    try std.testing.expectError(error.BufferLimitExceeded, account.reserve(17));
    try std.testing.expectEqual(@as(u64, 1), account.snapshot().limit_exceeded_events);
    account.releaseAll();
    try std.testing.expectEqual(@as(usize, 0), account.snapshot().current);
}

test "stream receive window follows the configured high watermark" {
    try std.testing.expectEqual(@as(u31, 768 * 1024), streamReceiveWindow(.{
        .per_stream_low_watermark = 256 * 1024,
        .per_stream_high_watermark = 768 * 1024,
        .per_stream_hard_limit = 1024 * 1024,
        .per_origin_hard_limit = 0,
        .global_hard_limit = 0,
    }));

    try std.testing.expectError(error.InvalidBufferLimits, (Limits{
        .per_stream_low_watermark = 4,
        .per_stream_high_watermark = max_stream_receive_window + 1,
        .per_stream_hard_limit = max_stream_receive_window + 2,
        .per_origin_hard_limit = 0,
        .global_hard_limit = 0,
    }).validate());
}

test "aggregate enforces a hard limit and releases back to zero" {
    var aggregate = Aggregate.init(.origin, 32);

    try aggregate.reserve(.upstream_to_downstream, 24);
    try std.testing.expectEqual(@as(usize, 24), aggregate.currentBytes(.upstream_to_downstream));

    try std.testing.expectError(error.BufferLimitExceeded, aggregate.reserve(.upstream_to_downstream, 16));
    try std.testing.expectEqual(@as(u64, 1), aggregate.limitExceededEvents(.upstream_to_downstream));
    // The refused reservation retained nothing.
    try std.testing.expectEqual(@as(usize, 24), aggregate.currentBytes(.upstream_to_downstream));

    // Directions are accounted independently.
    try aggregate.reserve(.downstream_to_upstream, 32);
    try std.testing.expectEqual(@as(usize, 32), aggregate.currentBytes(.downstream_to_upstream));

    aggregate.release(.upstream_to_downstream, 24);
    aggregate.release(.downstream_to_upstream, 32);
    try std.testing.expectEqual(@as(usize, 0), aggregate.currentBytes(.upstream_to_downstream));
    try std.testing.expectEqual(@as(usize, 0), aggregate.currentBytes(.downstream_to_upstream));
}

test "aggregate with no hard limit stays a pure gauge" {
    var aggregate = Aggregate.init(.global, 0);
    try aggregate.reserve(.upstream_to_downstream, std.math.maxInt(usize) / 2);
    try std.testing.expectEqual(@as(u64, 0), aggregate.limitExceededEvents(.upstream_to_downstream));
    aggregate.release(.upstream_to_downstream, std.math.maxInt(usize) / 2);
    try std.testing.expectEqual(@as(usize, 0), aggregate.currentBytes(.upstream_to_downstream));
}

test "aggregate capacity rolls the global reservation back when the origin refuses" {
    var origin = Aggregate.init(.origin, 16);
    var global = Aggregate.init(.global, 1024);
    const capacity = AggregateCapacity{ .origin = &origin, .global = &global };

    try capacity.reserve(.upstream_to_downstream, 16);
    try std.testing.expectEqual(@as(usize, 16), global.currentBytes(.upstream_to_downstream));

    try std.testing.expectError(
        error.OriginBufferLimitExceeded,
        capacity.reserve(.upstream_to_downstream, 8),
    );
    // The global scope must not retain bytes for a reservation the origin refused.
    try std.testing.expectEqual(@as(usize, 16), global.currentBytes(.upstream_to_downstream));
    try std.testing.expectEqual(@as(usize, 16), origin.currentBytes(.upstream_to_downstream));

    capacity.release(.upstream_to_downstream, 16);
    try std.testing.expectEqual(@as(usize, 0), global.currentBytes(.upstream_to_downstream));
    try std.testing.expectEqual(@as(usize, 0), origin.currentBytes(.upstream_to_downstream));
}

test "aggregate capacity reports the refusing scope" {
    var origin = Aggregate.init(.origin, 1024);
    var global = Aggregate.init(.global, 8);
    const capacity = AggregateCapacity{ .origin = &origin, .global = &global };

    try std.testing.expectError(
        error.GlobalBufferLimitExceeded,
        capacity.reserve(.upstream_to_downstream, 9),
    );
    try std.testing.expectEqual(Scope.global, aggregateFailureScope(error.GlobalBufferLimitExceeded));
    try std.testing.expectEqual(Scope.origin, aggregateFailureScope(error.OriginBufferLimitExceeded));
    // A refusal at the first scope never touches the origin.
    try std.testing.expectEqual(@as(usize, 0), origin.currentBytes(.upstream_to_downstream));
}

test "unconfigured aggregate capacity is a no-op" {
    const capacity = AggregateCapacity{};
    try capacity.reserve(.upstream_to_downstream, std.math.maxInt(usize));
    capacity.release(.upstream_to_downstream, std.math.maxInt(usize));
}

test "proxy buffer account reports over-release without changing current" {
    const limits = Limits{
        .per_stream_low_watermark = 4,
        .per_stream_high_watermark = 8,
        .per_stream_hard_limit = 16,
        .per_origin_hard_limit = 0,
        .global_hard_limit = 0,
    };
    var account = Account.init(.upstream_to_downstream, .stream, limits);

    try account.reserve(6);
    try std.testing.expectError(error.BufferAccountingUnderflow, account.release(7));
    try std.testing.expectEqual(@as(usize, 6), account.snapshot().current);
}

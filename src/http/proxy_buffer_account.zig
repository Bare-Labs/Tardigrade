const std = @import("std");
const builtin = @import("builtin");

/// Test-only seam fired inside `Aggregate.reserve`, after the policy has been
/// read and approved and before the reservation commits. It exists so a test
/// can place a `setHardLimit` in that window deterministically instead of
/// trying to lose a race on purpose; production builds never contain the
/// branch. Set it and restore it with `defer` inside a single test.
pub var reserve_race_hook: ?*const fn () void = null;

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
    /// Optional: bytes entering or leaving the *aggregate* scopes. These track
    /// retained allocation, which is what the aggregate hard limits enforce and
    /// therefore what the aggregate current-byte gauge must report — it moves
    /// on a different schedule from the per-stream logical queue length, which
    /// drains ahead of the storage backing it.
    recordRetainedBytesFn: ?*const fn (*anyopaque, Direction, usize) void = null,
    releaseRetainedBytesFn: ?*const fn (*anyopaque, Direction, usize) void = null,

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

    pub fn recordRetainedBytes(self: Observer, direction: Direction, bytes: usize) void {
        if (bytes == 0) return;
        if (self.recordRetainedBytesFn) |f| f(self.context, direction, bytes);
    }

    pub fn releaseRetainedBytes(self: Observer, direction: Direction, bytes: usize) void {
        if (bytes == 0) return;
        if (self.releaseRetainedBytesFn) |f| f(self.context, direction, bytes);
    }
};

/// Whether reads on `side` are currently stopped because the opposite peer
/// cannot accept more bytes.
///
/// The synchronous HTTP/1 relay has no queue to hang a watermark off — it
/// simply blocks in `write` until the far side drains — so a blocked write *is*
/// its backpressure, and this is the only place it becomes observable. Only
/// state transitions are recorded: a relay whose peers keep draining never
/// touches the counters, and one that stalls repeatedly inside a single stall
/// emits one pause/resume pair rather than one per write.
pub const ReadStall = struct {
    side: Side,
    observer: Observer,
    paused: bool = false,
    pauses: u64 = 0,
    resumes: u64 = 0,

    pub fn init(side: Side, observer: Observer) ReadStall {
        return .{ .side = side, .observer = observer };
    }

    /// The next write cannot make progress, so reads on `side` have stopped.
    pub fn pause(self: *ReadStall) void {
        if (self.paused) return;
        self.paused = true;
        self.pauses += 1;
        self.observer.recordReadPause(self.side);
    }

    /// The write made progress, or the relay finished. Either way reads on
    /// `side` are no longer being held back, so a relay torn down mid-stall
    /// must call this: the pause/resume difference is meant to read as "how
    /// many relays are stalled right now", not to drift by one per abort.
    pub fn unpause(self: *ReadStall) void {
        if (!self.paused) return;
        self.paused = false;
        self.resumes += 1;
        self.observer.recordReadResume(self.side);
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
    /// reserved; every reservation that commits after this call is judged by
    /// the new limit. See `reserve` for how that ordering is made exact.
    pub fn setHardLimit(self: *Aggregate, hard_limit: usize) void {
        self.hard_limit.store(hard_limit, .seq_cst);
    }

    pub fn hardLimit(self: *const Aggregate) usize {
        return self.hard_limit.load(.seq_cst);
    }

    /// Reserve `bytes`, or fail without retaining any.
    ///
    /// Reservation and reload are linearizable against each other, which a
    /// single up-front policy read would not have been: a reserver that read
    /// the old (larger) limit, was then overtaken by a `setHardLimit` shrink,
    /// and only afterwards won its compare-and-swap would have committed under
    /// a policy that no longer existed — and with enough concurrent reservers
    /// in flight, several could do it at once and leave the scope above the
    /// limit a reload had just promised to enforce.
    ///
    /// Two things close that. The limit is re-read on every attempt, so a
    /// reserver that spins in the retry loop cannot carry a stale policy
    /// through it. And the commit is *revalidated*: after winning the CAS the
    /// reserver re-reads the limit, and rolls its own bytes back if a shrink
    /// beat it there. Sequentially consistent ordering on the limit and the
    /// CAS gives those a single total order, so a commit either precedes the
    /// shrink — and is exactly the "already reserved above the new limit" case
    /// the reload documents — or follows it and is refused.
    ///
    /// The fast path stays lock-free: an uncontended reservation with no
    /// concurrent reload is one CAS and two relaxed-cost loads, and the
    /// rollback is only ever reached by a reservation that genuinely raced a
    /// reload.
    pub fn reserve(self: *Aggregate, direction: Direction, bytes: usize) error{BufferLimitExceeded}!void {
        const slot = &self.current[@intFromEnum(direction)];
        var current = slot.load(.monotonic);
        while (true) {
            const limit = self.hard_limit.load(.seq_cst);
            const next = std.math.add(usize, current, bytes) catch {
                self.noteLimitExceeded(direction);
                return error.BufferLimitExceeded;
            };
            if (limit != 0 and next > limit) {
                self.noteLimitExceeded(direction);
                return error.BufferLimitExceeded;
            }
            // Test seam: the window this protocol has to be correct across is
            // exactly here — the policy has been read and approved, and the
            // commit has not happened yet. Compiled out entirely off the test
            // path, since `builtin.is_test` is comptime-known.
            if (comptime builtin.is_test) {
                if (reserve_race_hook) |hook| hook();
            }
            if (slot.cmpxchgWeak(current, next, .seq_cst, .seq_cst)) |actual| {
                current = actual;
                continue;
            }
            // Committed. A reload may have landed between the policy read
            // above and this commit; if it did, these bytes were never
            // admissible, so give them back rather than leave the scope over a
            // limit that is already in force.
            const limit_now = self.hard_limit.load(.seq_cst);
            if (limit_now != 0 and next > limit_now) {
                _ = slot.fetchSub(bytes, .seq_cst);
                self.noteLimitExceeded(direction);
                return error.BufferLimitExceeded;
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

var race_hook_target: ?*Aggregate = null;
var race_hook_limit: usize = 0;
var race_hook_fired: usize = 0;

/// Shrink the limit exactly once, from inside the commit window.
fn shrinkLimitOnce() void {
    if (race_hook_fired != 0) return;
    race_hook_fired += 1;
    race_hook_target.?.setHardLimit(race_hook_limit);
}

test "a reload landing inside the commit window refuses the racing reservation" {
    // The reservation reads a limit that admits it, a reload shrinks the limit
    // before the commit lands, and the commit then goes through. Without
    // revalidation those bytes would sit above a limit already in force — and
    // with many reservers in flight, several could do it at once, which is
    // precisely what `setHardLimit` promises cannot happen.
    var aggregate = Aggregate.init(.origin, 1024);
    try aggregate.reserve(.upstream_to_downstream, 512);

    race_hook_target = &aggregate;
    race_hook_limit = 640; // admits what is already held, not the next 512
    race_hook_fired = 0;
    reserve_race_hook = shrinkLimitOnce;
    defer reserve_race_hook = null;

    try std.testing.expectError(
        error.BufferLimitExceeded,
        aggregate.reserve(.upstream_to_downstream, 512),
    );
    try std.testing.expectEqual(@as(usize, 1), race_hook_fired);

    // Rolled back completely: the racing reservation retained nothing, and the
    // reservation that was already there is untouched.
    try std.testing.expectEqual(@as(usize, 512), aggregate.currentBytes(.upstream_to_downstream));
    try std.testing.expectEqual(@as(u64, 1), aggregate.limitExceededEvents(.upstream_to_downstream));
    try std.testing.expectEqual(@as(usize, 640), aggregate.hardLimit());

    // And the scope is still usable for what the new limit does admit.
    try aggregate.reserve(.upstream_to_downstream, 128);
    aggregate.release(.upstream_to_downstream, 640);
    try std.testing.expectEqual(@as(usize, 0), aggregate.currentBytes(.upstream_to_downstream));
}

test "a reload that lands after the commit leaves the reservation alone" {
    // The mirror case, and the reason revalidation cannot simply refuse
    // whenever the limit changed: bytes committed *before* the shrink are the
    // documented "already reserved above the new limit" case and must stay.
    var aggregate = Aggregate.init(.origin, 1024);
    try aggregate.reserve(.upstream_to_downstream, 1024);
    aggregate.setHardLimit(256);

    try std.testing.expectEqual(@as(usize, 1024), aggregate.currentBytes(.upstream_to_downstream));
    try std.testing.expectError(
        error.BufferLimitExceeded,
        aggregate.reserve(.upstream_to_downstream, 1),
    );
    aggregate.release(.upstream_to_downstream, 1024);
}

const reload_race_threads = 8;

const ReloadRaceCtx = struct {
    aggregate: *Aggregate,
    bytes: usize,
    /// One completed reserve-then-release attempt per slot, published so the
    /// reload side can tell when a thread can no longer be holding bytes it
    /// was admitted for under the previous policy.
    cycles: [reload_race_threads]std.atomic.Value(u64) = [_]std.atomic.Value(u64){std.atomic.Value(u64).init(0)} ** reload_race_threads,
    admissions: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    refusals: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    start: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    stop: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
};

fn reloadRaceReserver(ctx: *ReloadRaceCtx, slot: usize) void {
    while (!ctx.start.load(.acquire)) std.Thread.yield() catch {};
    while (!ctx.stop.load(.acquire)) {
        if (ctx.aggregate.reserve(.upstream_to_downstream, ctx.bytes)) |_| {
            _ = ctx.admissions.fetchAdd(1, .monotonic);
            std.Thread.yield() catch {};
            ctx.aggregate.release(.upstream_to_downstream, ctx.bytes);
        } else |_| {
            _ = ctx.refusals.fetchAdd(1, .monotonic);
        }
        // Published only after this thread is holding nothing.
        _ = ctx.cycles[slot].fetchAdd(1, .release);
        std.Thread.yield() catch {};
    }
}

test "concurrent reservations settle under a limit reloaded beneath them" {
    // The stress counterpart to the deterministic test above: real threads
    // hammering the CAS loop and the rollback path while the limit is shrunk
    // under them.
    //
    // The assertion has to be one an outside observer can actually make.
    // Sampling the scope right after a reload proves nothing, because bytes
    // admitted *before* it legitimately stay reserved for as long as their
    // holder keeps them. So this waits until every thread has completed a full
    // reserve/release cycle after the shrink — at which point nothing admitted
    // under the old policy can still be outstanding — and only then requires
    // the scope to be within the new limit. The ordering guarantee itself is
    // pinned deterministically by the commit-window test above; what this adds
    // is that the protocol holds up under contention without leaking,
    // double-releasing, or livelocking.
    const bytes = 64;
    const high = reload_race_threads * bytes;
    const low = bytes * 2;
    var aggregate = Aggregate.init(.origin, high);
    var ctx = ReloadRaceCtx{ .aggregate = &aggregate, .bytes = bytes };

    var threads: [reload_race_threads]std.Thread = undefined;
    for (&threads, 0..) |*thread, slot| {
        thread.* = try std.Thread.spawn(.{}, reloadRaceReserver, .{ &ctx, slot });
    }
    ctx.start.store(true, .release);

    var round: usize = 0;
    while (round < 25) : (round += 1) {
        aggregate.setHardLimit(low);

        // Wait for every thread to cycle twice: one cycle may have been in
        // flight across the store, the second is wholly under the new limit.
        var baseline: [reload_race_threads]u64 = undefined;
        for (&baseline, 0..) |*value, slot| value.* = ctx.cycles[slot].load(.acquire);
        for (baseline, 0..) |value, slot| {
            while (ctx.cycles[slot].load(.acquire) < value + 2) std.Thread.yield() catch {};
        }

        // Everything outstanding now was admitted under `low`.
        try std.testing.expect(aggregate.currentBytes(.upstream_to_downstream) <= low);

        aggregate.setHardLimit(high);
        std.Thread.yield() catch {};
    }
    ctx.stop.store(true, .release);
    for (threads) |thread| thread.join();

    // The run has to have actually exercised both outcomes, or it proves
    // nothing: refusals mean the shrunk limit really did bite.
    try std.testing.expect(ctx.admissions.load(.monotonic) > 0);
    try std.testing.expect(ctx.refusals.load(.monotonic) > 0);
    // Nothing leaked and nothing was released twice.
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

const CountingStallObserver = struct {
    pauses: u64 = 0,
    resumes: u64 = 0,

    fn observer(self: *CountingStallObserver) Observer {
        return .{
            .context = self,
            .recordReservationFn = ignoreReservation,
            .releaseReservationFn = ignoreRelease,
            .recordReadPauseFn = recordPause,
            .recordReadResumeFn = recordResume,
        };
    }

    fn ignoreReservation(_: *anyopaque, _: Direction, _: usize, _: bool, _: bool) void {}
    fn ignoreRelease(_: *anyopaque, _: Direction, _: usize) void {}

    fn recordPause(context: *anyopaque, _: Side) void {
        const self: *CountingStallObserver = @ptrCast(@alignCast(context));
        self.pauses += 1;
    }

    fn recordResume(context: *anyopaque, _: Side) void {
        const self: *CountingStallObserver = @ptrCast(@alignCast(context));
        self.resumes += 1;
    }
};

test "read stall records one pause resume pair per stall, not per write" {
    var counters = CountingStallObserver{};
    var stall = ReadStall.init(.downstream, counters.observer());

    // A relay that never stalls must leave the counters untouched.
    stall.unpause();
    try std.testing.expectEqual(@as(u64, 0), counters.pauses);
    try std.testing.expectEqual(@as(u64, 0), counters.resumes);

    // Repeated stalled writes inside one stall are a single transition.
    stall.pause();
    stall.pause();
    stall.pause();
    try std.testing.expectEqual(@as(u64, 1), counters.pauses);
    try std.testing.expectEqual(@as(u64, 0), counters.resumes);

    stall.unpause();
    stall.unpause();
    try std.testing.expectEqual(@as(u64, 1), counters.pauses);
    try std.testing.expectEqual(@as(u64, 1), counters.resumes);

    // A later stall is a new transition.
    stall.pause();
    stall.unpause();
    try std.testing.expectEqual(@as(u64, 2), counters.pauses);
    try std.testing.expectEqual(@as(u64, 2), counters.resumes);
    try std.testing.expectEqual(counters.pauses, stall.pauses);
    try std.testing.expectEqual(counters.resumes, stall.resumes);
}

test "read stall left paused at teardown balances when unpaused" {
    var counters = CountingStallObserver{};
    var stall = ReadStall.init(.downstream, counters.observer());
    stall.pause();
    // Teardown while stalled (client abort, cancellation): the relay is gone,
    // so it is no longer holding reads back.
    stall.unpause();
    try std.testing.expectEqual(counters.pauses, counters.resumes);
    try std.testing.expect(!stall.paused);
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

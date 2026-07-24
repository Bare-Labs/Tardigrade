//! Process-local anti-replay store for accepted native TLS/QUIC 0-RTT early
//! data (#368, Slice 1). This module owns replay-key storage, atomic claim
//! semantics, recording-window retention/expiration, capacity behavior, and
//! startup quarantine — it does not touch the #366/#497 `EarlyDataReplayGate`
//! seam in `tls13_backend.zig`, and replay state is deliberately kept out of
//! `resumption_runtime.zig` (wiring this store into the gate is Slice 2).
//!
//! Normative reference: RFC 9846 §8. The guarantee this store implements a
//! single-process instance of: after a replay key is successfully claimed,
//! every later claim of that same key within its recording window is
//! rejected — for 0-RTT only. A rejection from this store must never fail an
//! otherwise-valid PSK/session resumption handshake, only its early-data
//! attempt; ordinary 1-RTT resumption is the caller's concern, not this
//! module's.
//!
//! Do not store raw tickets, PSKs, binders, ClientHello bytes, request
//! bodies, or other bearer/secret material here — only the one-way ticket
//! identity fingerprint (`Key`) and a retention deadline.

const std = @import("std");
const zig_compat = @import("zig_compat");

/// One-way digest of an offered ticket's opaque wire identity — the
/// existing `tls13_backend.EarlyDataReplayCandidate.ticket_identity_fingerprint`
/// is the canonical source. Never the raw ticket, PSK, or binder.
pub const Key = [32]u8;

/// Hard ceiling no `Limits.max_entries` may exceed, regardless of
/// configuration.
pub const hard_max_entries: usize = 1_048_576;

pub const Limits = struct {
    max_entries: usize = 65_536,

    pub fn validate(self: Limits) error{InvalidLimits}!void {
        if (self.max_entries == 0 or self.max_entries > hard_max_entries) return error.InvalidLimits;
    }
};

pub const Claim = struct {
    key: Key,
    /// Absolute server-wall-clock deadline through which this key must
    /// remain authoritative for the currently validated freshness window
    /// (derived by the caller from the already-validated ticket-age/skew
    /// policy — this store never re-derives ticket freshness itself).
    /// Inclusive: a claim received exactly at this deadline is still
    /// protected.
    retain_until_unix_ms: u64,
};

pub const ClaimResult = enum {
    accepted,
    duplicate,
    rejected_capacity,
    unavailable,
};

/// Bounded closed-enum outcome vocabulary for metrics/logging. Distinct from
/// `ClaimResult`: `.unavailable` covers both a genuinely unavailable store
/// (e.g. allocation failure) and the startup-quarantine window, but
/// observers need to tell those apart, so quarantine gets its own event.
/// Never pass a fingerprint, ticket, or other high-cardinality value to an
/// observer — only this closed set.
pub const Event = enum {
    accepted,
    duplicate,
    capacity_rejected,
    expired,
    unavailable,
    startup_quarantine,
};

var empty_observer_dummy: u8 = 0;

/// Non-secret observer seam. Every call site below computes its result
/// inside a locked block and notifies only after that block (and therefore
/// the mutex) has been released, so a re-entrant observer calling back into
/// the same store cannot deadlock.
pub const Observer = struct {
    ctx: *anyopaque = @ptrCast(@constCast(&empty_observer_dummy)),
    onEventFn: ?*const fn (ctx: *anyopaque, event: Event) void = null,

    pub fn notify(self: Observer, event: Event) void {
        if (self.onEventFn) |f| f(self.ctx, event);
    }
};

/// Pluggable replay-store contract: the seam every future distributed
/// backend must satisfy with the same atomicity guarantee as `LocalStore` —
/// one authoritative `claim` call, never a separate contains()-then-insert().
/// A distributed implementation must return `.unavailable` on any timeout,
/// network failure, or ambiguous commit unless it can prove the key was
/// atomically claimed, and must never use raw ticket/PSK/binder/request
/// material as the storage key or value.
pub const Store = struct {
    ctx: *anyopaque,
    claimFn: *const fn (ctx: *anyopaque, claim: Claim) ClaimResult,

    pub fn claim(self: Store, c: Claim) ClaimResult {
        return self.claimFn(self.ctx, c);
    }
};

const Entry = struct {
    retain_until_unix_ms: u64,
};

/// Bounded, mutex-guarded, process-local replay store. One instance is
/// meant to be shared (via `store()`) across every native TCP worker and the
/// H3 runtime in a process (Slice 2 composition) — a thread/worker-local
/// store is not an acceptable production path.
pub const LocalStore = struct {
    allocator: std.mem.Allocator,
    limits: Limits,
    quarantine_duration_ms: u64,
    mutex: zig_compat.Mutex = .{},
    entries: std.AutoHashMapUnmanaged(Key, Entry) = .empty,
    observer: Observer = .{},
    /// Normally `start_unix_ms + quarantine_duration_ms`; re-armed to
    /// `high_water_unix_ms + quarantine_duration_ms` if a later `claim`
    /// observes wall-clock time moving backward, so a clock correction can
    /// never shorten the window that was already committed to (a minimal,
    /// deliberately conservative stand-in for a monotonic elapsed-time
    /// source — see the module doc).
    quarantine_until_unix_ms: u64,
    /// Highest wall-clock `now_unix_ms` this store has ever observed, used
    /// only to detect backward clock movement.
    high_water_unix_ms: u64,

    pub fn init(
        allocator: std.mem.Allocator,
        limits: Limits,
        quarantine_duration_ms: u64,
        now_unix_ms: u64,
    ) error{InvalidLimits}!LocalStore {
        try limits.validate();
        return .{
            .allocator = allocator,
            .limits = limits,
            .quarantine_duration_ms = quarantine_duration_ms,
            .quarantine_until_unix_ms = now_unix_ms +| quarantine_duration_ms,
            .high_water_unix_ms = now_unix_ms,
        };
    }

    pub fn deinit(self: *LocalStore) void {
        self.entries.deinit(self.allocator);
    }

    pub fn setObserver(self: *LocalStore, observer: Observer) void {
        self.observer = observer;
    }

    pub fn count(self: *LocalStore) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.entries.count();
    }

    /// Adapts this store to the generic `Store` contract. The trampoline
    /// supplies wall-clock `now` at the call boundary since `Store.claimFn`
    /// carries no time parameter by design; callers that need determinism
    /// (tests, concurrency checks) should call `claim` directly with an
    /// explicit `now_unix_ms` instead of going through this adapter.
    pub fn store(self: *LocalStore) Store {
        return .{ .ctx = self, .claimFn = trampolineClaim };
    }

    fn trampolineClaim(ctx: *anyopaque, c: Claim) ClaimResult {
        const self: *LocalStore = @ptrCast(@alignCast(ctx));
        return self.claim(c, @intCast(zig_compat.milliTimestamp()));
    }

    /// Atomic claim: the duplicate check and insertion happen under one
    /// mutex acquisition. `now_unix_ms` is caller-supplied wall-clock time,
    /// taken explicitly (rather than read internally) so tests are
    /// deterministic without a separate clock abstraction — matching
    /// `session_cache.zig`'s `now_unix_ms` convention.
    pub fn claim(self: *LocalStore, c: Claim, now_unix_ms: u64) ClaimResult {
        var expired_removed: usize = 0;
        var event: Event = .unavailable;
        var result: ClaimResult = undefined;
        {
            self.mutex.lock();
            defer self.mutex.unlock();
            result = self.claimLocked(c, now_unix_ms, &expired_removed, &event);
        }

        var i: usize = 0;
        while (i < expired_removed) : (i += 1) self.observer.notify(.expired);
        self.observer.notify(event);
        return result;
    }

    fn claimLocked(
        self: *LocalStore,
        c: Claim,
        now_unix_ms: u64,
        expired_removed: *usize,
        event: *Event,
    ) ClaimResult {
        if (now_unix_ms < self.high_water_unix_ms) {
            // Backward wall-clock movement: conservatively re-enter the
            // full quarantine window rather than trust the reduced
            // elapsed time.
            self.quarantine_until_unix_ms = self.high_water_unix_ms +| self.quarantine_duration_ms;
        } else {
            self.high_water_unix_ms = now_unix_ms;
        }

        if (now_unix_ms < self.quarantine_until_unix_ms) {
            event.* = .startup_quarantine;
            return .unavailable;
        }

        if (self.entries.getPtr(c.key)) |entry_ptr| {
            // Inclusive boundary: `now == retain_until` is still protected.
            if (now_unix_ms <= entry_ptr.retain_until_unix_ms) {
                event.* = .duplicate;
                return .duplicate;
            }
            _ = self.entries.remove(c.key);
            expired_removed.* += 1;
        }

        if (self.entries.count() < self.limits.max_entries) {
            return self.insertLocked(c, event);
        }

        // At capacity: prune only genuinely expired entries — an unexpired
        // entry must never be evicted to admit a new key (that would turn
        // memory pressure into a replay bypass) — and retry.
        expired_removed.* += self.sweepExpiredLocked(now_unix_ms);

        if (self.entries.count() < self.limits.max_entries) {
            return self.insertLocked(c, event);
        }

        event.* = .capacity_rejected;
        return .rejected_capacity;
    }

    fn insertLocked(self: *LocalStore, c: Claim, event: *Event) ClaimResult {
        self.entries.ensureUnusedCapacity(self.allocator, 1) catch {
            event.* = .unavailable;
            return .unavailable;
        };
        self.entries.putAssumeCapacity(c.key, .{ .retain_until_unix_ms = c.retain_until_unix_ms });
        event.* = .accepted;
        return .accepted;
    }

    /// Removes every entry whose recording deadline has genuinely passed
    /// (`retain_until_unix_ms < now_unix_ms`); never touches an unexpired
    /// entry. Returns the number removed. A collection failure under
    /// memory pressure just stops the sweep early (a partial sweep is
    /// always safe: it never evicts anything live).
    fn sweepExpiredLocked(self: *LocalStore, now_unix_ms: u64) usize {
        var victims: std.ArrayListUnmanaged(Key) = .empty;
        defer victims.deinit(self.allocator);

        var it = self.entries.iterator();
        while (it.next()) |kv| {
            if (kv.value_ptr.retain_until_unix_ms < now_unix_ms) {
                victims.append(self.allocator, kv.key_ptr.*) catch break;
            }
        }
        for (victims.items) |k| _ = self.entries.remove(k);
        return victims.items.len;
    }
};

const testing = std.testing;

fn testLimits(max_entries: usize) Limits {
    return .{ .max_entries = max_entries };
}

fn keyOf(byte: u8) Key {
    var k: Key = [_]u8{0} ** 32;
    k[0] = byte;
    return k;
}

test "Limits.validate rejects zero and above-hard-cap max_entries" {
    try testing.expectError(error.InvalidLimits, (Limits{ .max_entries = 0 }).validate());
    try testing.expectError(error.InvalidLimits, (Limits{ .max_entries = hard_max_entries + 1 }).validate());
    try (Limits{ .max_entries = hard_max_entries }).validate();
}

test "invalid limits fail initialization" {
    try testing.expectError(error.InvalidLimits, LocalStore.init(testing.allocator, .{ .max_entries = 0 }, 0, 0));
    try testing.expectError(error.InvalidLimits, LocalStore.init(testing.allocator, .{ .max_entries = hard_max_entries + 1 }, 0, 0));
}

test "first claim is accepted" {
    var store = try LocalStore.init(testing.allocator, testLimits(4), 0, 1_000);
    defer store.deinit();
    try testing.expectEqual(ClaimResult.accepted, store.claim(.{ .key = keyOf(1), .retain_until_unix_ms = 2_000 }, 1_000));
}

test "repeated claim before deadline is duplicate" {
    var store = try LocalStore.init(testing.allocator, testLimits(4), 0, 1_000);
    defer store.deinit();
    try testing.expectEqual(ClaimResult.accepted, store.claim(.{ .key = keyOf(1), .retain_until_unix_ms = 2_000 }, 1_000));
    try testing.expectEqual(ClaimResult.duplicate, store.claim(.{ .key = keyOf(1), .retain_until_unix_ms = 2_000 }, 1_500));
}

test "repeated claim exactly at the deadline is still duplicate (inclusive boundary)" {
    var store = try LocalStore.init(testing.allocator, testLimits(4), 0, 1_000);
    defer store.deinit();
    try testing.expectEqual(ClaimResult.accepted, store.claim(.{ .key = keyOf(1), .retain_until_unix_ms = 2_000 }, 1_000));
    try testing.expectEqual(ClaimResult.duplicate, store.claim(.{ .key = keyOf(1), .retain_until_unix_ms = 2_000 }, 2_000));
}

test "claim after the deadline expires the old entry and a new claim can be accepted" {
    var store = try LocalStore.init(testing.allocator, testLimits(4), 0, 1_000);
    defer store.deinit();
    try testing.expectEqual(ClaimResult.accepted, store.claim(.{ .key = keyOf(1), .retain_until_unix_ms = 2_000 }, 1_000));
    try testing.expectEqual(ClaimResult.accepted, store.claim(.{ .key = keyOf(1), .retain_until_unix_ms = 5_000 }, 2_001));
}

test "two different keys are independent" {
    var store = try LocalStore.init(testing.allocator, testLimits(4), 0, 1_000);
    defer store.deinit();
    try testing.expectEqual(ClaimResult.accepted, store.claim(.{ .key = keyOf(1), .retain_until_unix_ms = 2_000 }, 1_000));
    try testing.expectEqual(ClaimResult.accepted, store.claim(.{ .key = keyOf(2), .retain_until_unix_ms = 2_000 }, 1_000));
    try testing.expectEqual(ClaimResult.duplicate, store.claim(.{ .key = keyOf(1), .retain_until_unix_ms = 2_000 }, 1_500));
    try testing.expectEqual(ClaimResult.duplicate, store.claim(.{ .key = keyOf(2), .retain_until_unix_ms = 2_000 }, 1_500));
}

test "a full store rejects a new key with rejected_capacity" {
    var store = try LocalStore.init(testing.allocator, testLimits(2), 0, 1_000);
    defer store.deinit();
    try testing.expectEqual(ClaimResult.accepted, store.claim(.{ .key = keyOf(1), .retain_until_unix_ms = 5_000 }, 1_000));
    try testing.expectEqual(ClaimResult.accepted, store.claim(.{ .key = keyOf(2), .retain_until_unix_ms = 5_000 }, 1_000));
    try testing.expectEqual(ClaimResult.rejected_capacity, store.claim(.{ .key = keyOf(3), .retain_until_unix_ms = 5_000 }, 1_000));
}

test "expired entries may be reclaimed at capacity" {
    var store = try LocalStore.init(testing.allocator, testLimits(2), 0, 1_000);
    defer store.deinit();
    try testing.expectEqual(ClaimResult.accepted, store.claim(.{ .key = keyOf(1), .retain_until_unix_ms = 1_500 }, 1_000));
    try testing.expectEqual(ClaimResult.accepted, store.claim(.{ .key = keyOf(2), .retain_until_unix_ms = 5_000 }, 1_000));
    // key 1 has now expired; the capacity sweep should reclaim its slot.
    try testing.expectEqual(ClaimResult.accepted, store.claim(.{ .key = keyOf(3), .retain_until_unix_ms = 5_000 }, 1_600));
    try testing.expectEqual(@as(usize, 2), store.count());
}

test "unexpired entries are never evicted to admit a new key" {
    var store = try LocalStore.init(testing.allocator, testLimits(2), 0, 1_000);
    defer store.deinit();
    try testing.expectEqual(ClaimResult.accepted, store.claim(.{ .key = keyOf(1), .retain_until_unix_ms = 5_000 }, 1_000));
    try testing.expectEqual(ClaimResult.accepted, store.claim(.{ .key = keyOf(2), .retain_until_unix_ms = 5_000 }, 1_000));
    try testing.expectEqual(ClaimResult.rejected_capacity, store.claim(.{ .key = keyOf(3), .retain_until_unix_ms = 5_000 }, 1_200));
    // Both original keys must still be protected — neither was evicted to
    // admit the rejected key.
    try testing.expectEqual(ClaimResult.duplicate, store.claim(.{ .key = keyOf(1), .retain_until_unix_ms = 5_000 }, 1_300));
    try testing.expectEqual(ClaimResult.duplicate, store.claim(.{ .key = keyOf(2), .retain_until_unix_ms = 5_000 }, 1_300));
    try testing.expectEqual(@as(usize, 2), store.count());
}

test "startup quarantine rejects claims as unavailable without recording anything" {
    var store = try LocalStore.init(testing.allocator, testLimits(4), 60_000, 1_000);
    defer store.deinit();
    try testing.expectEqual(ClaimResult.unavailable, store.claim(.{ .key = keyOf(1), .retain_until_unix_ms = 100_000 }, 1_000));
    try testing.expectEqual(ClaimResult.unavailable, store.claim(.{ .key = keyOf(1), .retain_until_unix_ms = 100_000 }, 60_999));
    try testing.expectEqual(@as(usize, 0), store.count());
}

test "first claim immediately after quarantine can succeed" {
    var store = try LocalStore.init(testing.allocator, testLimits(4), 60_000, 1_000);
    defer store.deinit();
    try testing.expectEqual(ClaimResult.accepted, store.claim(.{ .key = keyOf(1), .retain_until_unix_ms = 200_000 }, 61_000));
}

test "backward wall-clock movement re-arms the quarantine window" {
    var store = try LocalStore.init(testing.allocator, testLimits(4), 60_000, 100_000);
    defer store.deinit();
    // Quarantine (100_000 + 60_000) is already over.
    try testing.expectEqual(ClaimResult.accepted, store.claim(.{ .key = keyOf(1), .retain_until_unix_ms = 300_000 }, 160_000));
    // Wall clock jumps backward — conservatively re-enter quarantine rather
    // than trust the (now unreliable) elapsed time.
    try testing.expectEqual(ClaimResult.unavailable, store.claim(.{ .key = keyOf(2), .retain_until_unix_ms = 300_000 }, 50_000));
    // Re-armed relative to the highest wall-clock time actually observed
    // (160_000), not the regressed value.
    try testing.expectEqual(ClaimResult.unavailable, store.claim(.{ .key = keyOf(3), .retain_until_unix_ms = 300_000 }, 219_999));
    try testing.expectEqual(ClaimResult.accepted, store.claim(.{ .key = keyOf(3), .retain_until_unix_ms = 300_000 }, 220_000));
}

test "quarantine deadline arithmetic saturates instead of wrapping on overflow" {
    const near_max = std.math.maxInt(u64) - 10;
    var store = try LocalStore.init(testing.allocator, testLimits(4), 1_000, near_max);
    defer store.deinit();
    // Without saturating arithmetic this would wrap to a tiny value and
    // let 0-RTT out of quarantine immediately; it must instead fail closed.
    try testing.expectEqual(ClaimResult.unavailable, store.claim(.{ .key = keyOf(1), .retain_until_unix_ms = near_max }, near_max));
}

test "allocation failure during insert fails closed as unavailable" {
    var store = try LocalStore.init(testing.allocator, testLimits(4), 0, 1_000);
    defer store.deinit();
    var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    const original_allocator = store.allocator;
    store.allocator = failing.allocator();
    const result = store.claim(.{ .key = keyOf(1), .retain_until_unix_ms = 5_000 }, 1_000);
    store.allocator = original_allocator;
    try testing.expectEqual(ClaimResult.unavailable, result);
    try testing.expectEqual(@as(usize, 0), store.count());
}

test "observer callbacks run without the store mutex held (reentrant-safe)" {
    const ReentrantCtx = struct {
        store: *LocalStore,
        reentered: bool = false,
    };
    const reentrantObserver = struct {
        fn call(ctx: *anyopaque, event: Event) void {
            const rctx: *ReentrantCtx = @ptrCast(@alignCast(ctx));
            if (event == .accepted and !rctx.reentered) {
                rctx.reentered = true;
                // Re-entering claim() from inside the observer callback
                // would deadlock if the mutex were still held at notify
                // time.
                _ = rctx.store.claim(.{ .key = keyOf(99), .retain_until_unix_ms = 5_000 }, 1_000);
            }
        }
    }.call;

    var store = try LocalStore.init(testing.allocator, testLimits(4), 0, 1_000);
    defer store.deinit();
    var rctx = ReentrantCtx{ .store = &store };
    store.setObserver(.{ .ctx = &rctx, .onEventFn = reentrantObserver });

    const result = store.claim(.{ .key = keyOf(1), .retain_until_unix_ms = 5_000 }, 1_000);
    try testing.expectEqual(ClaimResult.accepted, result);
    try testing.expect(rctx.reentered);
    try testing.expectEqual(@as(usize, 2), store.count());
}

test "store() adapts LocalStore to the generic Store contract" {
    var local = try LocalStore.init(testing.allocator, testLimits(4), 0, 0);
    defer local.deinit();
    const iface = local.store();
    const result = iface.claim(.{ .key = keyOf(1), .retain_until_unix_ms = std.math.maxInt(u64) });
    try testing.expectEqual(ClaimResult.accepted, result);
}

const ConcurrentClaimTask = struct {
    store: *LocalStore,
    start: *std.atomic.Value(bool),
    key: Key,
    now_unix_ms: u64,
    accepted: *std.atomic.Value(usize),
    duplicate: *std.atomic.Value(usize),

    fn run(self: *ConcurrentClaimTask) void {
        while (!self.start.load(.acquire)) {}
        const result = self.store.claim(.{ .key = self.key, .retain_until_unix_ms = self.now_unix_ms + 10_000 }, self.now_unix_ms);
        switch (result) {
            .accepted => _ = self.accepted.fetchAdd(1, .monotonic),
            .duplicate => _ = self.duplicate.fetchAdd(1, .monotonic),
            else => {},
        }
    }
};

test "concurrent claims of the same key produce exactly one accepted" {
    const n = 32;
    var store = try LocalStore.init(testing.allocator, testLimits(64), 0, 1_000);
    defer store.deinit();

    var start = std.atomic.Value(bool).init(false);
    var accepted = std.atomic.Value(usize).init(0);
    var duplicate = std.atomic.Value(usize).init(0);
    var tasks: [n]ConcurrentClaimTask = undefined;
    var threads: [n]std.Thread = undefined;

    for (&tasks, 0..) |*task, i| {
        task.* = .{ .store = &store, .start = &start, .key = keyOf(7), .now_unix_ms = 1_000, .accepted = &accepted, .duplicate = &duplicate };
        threads[i] = try std.Thread.spawn(.{}, ConcurrentClaimTask.run, .{task});
    }
    start.store(true, .release);
    for (&threads) |t| t.join();

    try testing.expectEqual(@as(usize, 1), accepted.load(.monotonic));
    try testing.expectEqual(@as(usize, n - 1), duplicate.load(.monotonic));
    try testing.expectEqual(@as(usize, 1), store.count());
}

test "concurrent claims of distinct keys are race-free and stay within capacity" {
    const n = 40;
    var store = try LocalStore.init(testing.allocator, testLimits(n), 0, 1_000);
    defer store.deinit();

    var start = std.atomic.Value(bool).init(false);
    var accepted = std.atomic.Value(usize).init(0);
    var duplicate = std.atomic.Value(usize).init(0);
    var tasks: [n]ConcurrentClaimTask = undefined;
    var threads: [n]std.Thread = undefined;

    for (&tasks, 0..) |*task, i| {
        task.* = .{ .store = &store, .start = &start, .key = keyOf(@intCast(i + 1)), .now_unix_ms = 1_000, .accepted = &accepted, .duplicate = &duplicate };
        threads[i] = try std.Thread.spawn(.{}, ConcurrentClaimTask.run, .{task});
    }
    start.store(true, .release);
    for (&threads) |t| t.join();

    try testing.expectEqual(@as(usize, n), accepted.load(.monotonic));
    try testing.expectEqual(@as(usize, 0), duplicate.load(.monotonic));
    try testing.expectEqual(@as(usize, n), store.count());
}

test "restart with a fresh store rejects 0-RTT during quarantine but ordinary resumption is a separate concern" {
    // This module never touches 1-RTT resumption eligibility — a rejection
    // here only ever means "this store is not vouching for 0-RTT yet",
    // which the caller (tls13_backend.zig) maps to a decision that leaves
    // ordinary resumption untouched.
    var store = try LocalStore.init(testing.allocator, testLimits(4), 30_000, 0);
    defer store.deinit();
    try testing.expectEqual(ClaimResult.unavailable, store.claim(.{ .key = keyOf(1), .retain_until_unix_ms = 60_000 }, 0));
    try testing.expectEqual(ClaimResult.accepted, store.claim(.{ .key = keyOf(1), .retain_until_unix_ms = 90_000 }, 30_000));
}

test "capacity and expiration events are observable through the closed Event vocabulary" {
    const Recorder = struct {
        events: [8]Event = undefined,
        count: usize = 0,

        fn call(ctx: *anyopaque, event: Event) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            if (self.count < self.events.len) {
                self.events[self.count] = event;
                self.count += 1;
            }
        }
    };

    var store = try LocalStore.init(testing.allocator, testLimits(1), 0, 1_000);
    defer store.deinit();
    var recorder = Recorder{};
    store.setObserver(.{ .ctx = &recorder, .onEventFn = Recorder.call });

    try testing.expectEqual(ClaimResult.accepted, store.claim(.{ .key = keyOf(1), .retain_until_unix_ms = 1_500 }, 1_000));
    try testing.expectEqual(ClaimResult.rejected_capacity, store.claim(.{ .key = keyOf(2), .retain_until_unix_ms = 5_000 }, 1_100));
    try testing.expectEqual(ClaimResult.accepted, store.claim(.{ .key = keyOf(2), .retain_until_unix_ms = 5_000 }, 1_600));

    // Third call sweeps key 1's now-expired entry before inserting key 2,
    // so it reports both `.expired` (for the swept entry) and `.accepted`
    // (for the new one) — expired notifications always precede the final
    // outcome for that call (see `claim`'s notify loop).
    try testing.expectEqual(@as(usize, 4), recorder.count);
    try testing.expectEqual(Event.accepted, recorder.events[0]);
    try testing.expectEqual(Event.capacity_rejected, recorder.events[1]);
    try testing.expectEqual(Event.expired, recorder.events[2]);
    try testing.expectEqual(Event.accepted, recorder.events[3]);
}

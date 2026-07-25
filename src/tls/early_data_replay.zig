//! Process-local anti-replay store for accepted native TLS/QUIC 0-RTT early
//! data (#368). Slice 1 landed replay-key storage, atomic claim semantics,
//! recording-window retention/expiration, capacity behavior, and startup
//! quarantine. Slice 2 (`GateAdapter` below) wires a `Store` into the
//! #366/#497 `EarlyDataReplayGate` seam in `tls13_backend.zig` — replay
//! state itself stays deliberately out of `resumption_runtime.zig`.
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
const tls13_backend = @import("tls13_backend.zig");

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

/// Maps a `Store`'s outcome vocabulary onto the TLS-layer decision
/// `tls13_backend.EarlyDataReplayGate` expects: only `.duplicate` is a
/// proven replay (`.replay`); a genuinely unavailable store, startup
/// quarantine, and capacity exhaustion are all "this store cannot vouch for
/// 0-RTT right now" (`.unavailable`) — every one of these rejects only
/// early data, never an otherwise-valid PSK/session resumption.
fn mapClaimResult(result: ClaimResult) tls13_backend.EarlyDataReplayDecision {
    return switch (result) {
        .accepted => .allow,
        .duplicate => .replay,
        .rejected_capacity, .unavailable => .unavailable,
    };
}

/// Adapts any `Store` implementation — the bounded `LocalStore` today, a
/// future distributed backend eventually — to the
/// `tls13_backend.EarlyDataReplayGate` seam (#368 Slice 2). Composition owns
/// exactly one `Store` and wraps it in exactly one `GateAdapter`, then
/// installs the resulting gate into every native TLS backend that can
/// accept early data (native TCP and QUIC/H3), so worker-local duplicate
/// acceptance is impossible.
pub const GateAdapter = struct {
    backing: Store,

    pub fn init(backing: Store) GateAdapter {
        return .{ .backing = backing };
    }

    pub fn gate(self: *GateAdapter) tls13_backend.EarlyDataReplayGate {
        return .{ .ctx = self, .decideFn = decide };
    }

    fn decide(ctx: *anyopaque, candidate: tls13_backend.EarlyDataReplayCandidate) tls13_backend.EarlyDataReplayDecision {
        const self: *GateAdapter = @ptrCast(@alignCast(ctx));
        return mapClaimResult(self.backing.claim(.{
            .key = candidate.ticket_identity_fingerprint,
            .retain_until_unix_ms = candidate.retain_until_unix_ms,
        }));
    }
};

/// #368 Slice 3: a scripted, single-threaded fake of a *future* distributed
/// `Store` backend. Not a real networked implementation (no Redis/etcd/DB —
/// see the module doc) and, unlike a real distributed backend, this fake's
/// `.commit` path is a plain contains()-then-insert() rather than a genuinely
/// atomic CAS — safe here only because tests drive it from one thread. Its
/// only purpose is proving that `GateAdapter`/`tls13_backend.zig` depend
/// solely on the `Store.claim()` *contract* (accepted/duplicate/unavailable)
/// and never on `LocalStore`-specific internals: a real distributed backend
/// must still independently satisfy true cross-node atomicity, an
/// expiry/TTL no shorter than `Claim.retain_until_unix_ms`, and must map
/// every timeout, network failure, ambiguous/partial commit, or replication
/// uncertainty to `.unavailable` unless it can prove the claim outcome
/// (never `.accepted` before an authoritative commit).
pub const FakeDistributedOutcome = enum {
    /// Simulates a normal atomic commit: first claim of a key succeeds,
    /// a repeated claim of an already-committed key is `.duplicate`.
    commit,
    /// Simulates a request that timed out before the backend could prove
    /// whether the claim committed.
    timeout,
    /// Simulates a network failure reaching the backend.
    network_failure,
    /// Simulates a partial/ambiguous commit the backend cannot prove either
    /// way (e.g. replication uncertainty).
    ambiguous_commit,
};

pub const FakeDistributedStore = struct {
    allocator: std.mem.Allocator,
    /// Scripted per-call outcome; tests mutate this directly between calls
    /// to simulate a backend's behavior changing (e.g. healthy, then a
    /// timeout).
    mode: FakeDistributedOutcome = .commit,
    committed: std.AutoHashMapUnmanaged(Key, void) = .empty,

    pub fn init(allocator: std.mem.Allocator) FakeDistributedStore {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *FakeDistributedStore) void {
        self.committed.deinit(self.allocator);
    }

    pub fn store(self: *FakeDistributedStore) Store {
        return .{ .ctx = self, .claimFn = trampolineClaim };
    }

    fn trampolineClaim(ctx: *anyopaque, c: Claim) ClaimResult {
        const self: *FakeDistributedStore = @ptrCast(@alignCast(ctx));
        return self.claim(c);
    }

    fn claim(self: *FakeDistributedStore, c: Claim) ClaimResult {
        switch (self.mode) {
            .timeout, .network_failure, .ambiguous_commit => return .unavailable,
            .commit => {},
        }
        if (self.committed.contains(c.key)) return .duplicate;
        self.committed.put(self.allocator, c.key, {}) catch return .unavailable;
        return .accepted;
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
    /// Entries removed (duplicate-then-expired, or reclaimed at capacity)
    /// since the last tombstone compaction. `AutoHashMapUnmanaged` deletes
    /// leave a tombstone behind, so a long-lived store with heavy
    /// expire/reclaim churn across diverse keys would otherwise let probe
    /// length grow without bound even though logical occupancy never
    /// exceeds `limits.max_entries`. See `noteRemovalLocked`.
    removed_since_rehash: usize = 0,

    pub const InitError = error{ InvalidLimits, OutOfMemory };

    /// Reserves table capacity for the full configured `limits.max_entries`
    /// up front so the ordinary claim hot path — insert, remove, and the
    /// at-capacity reclaim — never depends on further allocator growth
    /// (see `claimLocked`/`reclaimOneExpiredLocked`).
    pub fn init(
        allocator: std.mem.Allocator,
        limits: Limits,
        quarantine_duration_ms: u64,
        now_unix_ms: u64,
    ) InitError!LocalStore {
        try limits.validate();
        var self: LocalStore = .{
            .allocator = allocator,
            .limits = limits,
            .quarantine_duration_ms = quarantine_duration_ms,
            .quarantine_until_unix_ms = now_unix_ms +| quarantine_duration_ms,
            .high_water_unix_ms = now_unix_ms,
        };
        try self.entries.ensureTotalCapacity(allocator, @intCast(limits.max_entries));
        return self;
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
            self.noteRemovalLocked();
            expired_removed.* += 1;
        }

        // The caller (`tls13_backend.zig`) derived `c.retain_until_unix_ms`
        // from an earlier wall-clock read at TLS-freshness-check time;
        // `Store.claim`'s trampoline takes a *second*, later wall-clock
        // reading for `now_unix_ms`. At the exact accepted negative-skew
        // boundary those two reads can straddle `retain_until_unix_ms`
        // itself. Inserting a claim whose own deadline has already passed
        // relative to `now_unix_ms` would record an entry that looks
        // already-expired to every subsequent claim of the same key —
        // silently reopening the exact replay window #368 requires closed.
        // Fail closed instead of recording anything.
        if (now_unix_ms > c.retain_until_unix_ms) {
            event.* = .unavailable;
            return .unavailable;
        }

        if (self.entries.count() < self.limits.max_entries) {
            return self.insertLocked(c, event);
        }

        // At capacity: this claim only needs one free slot, so reclaim at
        // most one genuinely expired entry — an unexpired entry must never
        // be evicted to admit a new key (that would turn memory pressure
        // into a replay bypass) — and retry. Allocation-free: capacity was
        // fully reserved in `init`.
        if (self.reclaimOneExpiredLocked(now_unix_ms)) {
            expired_removed.* += 1;
            return self.insertLocked(c, event);
        }

        event.* = .capacity_rejected;
        return .rejected_capacity;
    }

    fn insertLocked(self: *LocalStore, c: Claim, event: *Event) ClaimResult {
        // Always a no-op in practice: `init` reserves capacity for
        // `limits.max_entries` and this is only reached when
        // `entries.count() < limits.max_entries`, so removals (which give
        // capacity back — see `hash_map.zig`'s `available` bookkeeping)
        // keep enough headroom for one more insert without growing.
        // Kept as a defensive, fail-closed guard rather than an unchecked
        // `putAssumeCapacity` given how security-sensitive this store is.
        self.entries.ensureUnusedCapacity(self.allocator, 1) catch {
            event.* = .unavailable;
            return .unavailable;
        };
        self.entries.putAssumeCapacity(c.key, .{ .retain_until_unix_ms = c.retain_until_unix_ms });
        event.* = .accepted;
        return .accepted;
    }

    /// Reclaims exactly one genuinely expired entry
    /// (`retain_until_unix_ms < now_unix_ms`) to admit the current claim;
    /// never touches an unexpired entry. A single claim only ever needs one
    /// free slot, so this scans and removes at most one match rather than
    /// collecting a victim list — no allocation, so it stays safe to call
    /// while every native worker sharing this store is serialized behind
    /// the same mutex. Returns whether a slot was reclaimed.
    fn reclaimOneExpiredLocked(self: *LocalStore, now_unix_ms: u64) bool {
        var victim: ?Key = null;
        var it = self.entries.iterator();
        while (it.next()) |kv| {
            if (kv.value_ptr.retain_until_unix_ms < now_unix_ms) {
                victim = kv.key_ptr.*;
                break;
            }
        }
        const key = victim orelse return false;
        _ = self.entries.remove(key);
        self.noteRemovalLocked();
        return true;
    }

    /// Tracks removals since the last tombstone compaction and rehashes
    /// in place (no allocation) once churn reaches half the configured
    /// capacity, so no long-lived diverse-key expire/reclaim pattern can
    /// degrade lookup/insert probe length without bound.
    fn noteRemovalLocked(self: *LocalStore) void {
        self.removed_since_rehash += 1;
        const threshold = @max(@as(usize, 1), self.limits.max_entries / 2);
        if (self.removed_since_rehash >= threshold) {
            self.entries.rehash(std.hash_map.AutoContext(Key){});
            self.removed_since_rehash = 0;
        }
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

/// Wider-range variant of `keyOf` for tests that need more than 256
/// distinct keys (e.g. long-running churn tests).
fn keyOfU32(value: u32) Key {
    var k: Key = [_]u8{0} ** 32;
    std.mem.writeInt(u32, k[0..4], value, .little);
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

test "a claim whose own deadline has already passed relative to now fails closed instead of recording an already-expired entry" {
    // Guards the exact clock-boundary gap between the TLS-layer's earlier
    // freshness-check read (which produced `retain_until_unix_ms = T`) and
    // `Store.claim`'s later wall-clock read (`now_unix_ms = T + 1`):
    // inserting anyway would record a key that looks already-expired to
    // every subsequent claimant, letting a second concurrent replay of the
    // same key also be accepted once it, too, observes the entry as
    // expired and reclaims it.
    var store = try LocalStore.init(testing.allocator, testLimits(4), 0, 1_000);
    defer store.deinit();
    try testing.expectEqual(ClaimResult.unavailable, store.claim(.{ .key = keyOf(1), .retain_until_unix_ms = 1_000 }, 1_001));
    try testing.expectEqual(@as(usize, 0), store.count());

    // A second "concurrent" claim of the same key, at the same stale
    // `now`, must not be recorded either — nothing was ever inserted for
    // the first claim to protect against replay of the second.
    try testing.expectEqual(ClaimResult.unavailable, store.claim(.{ .key = keyOf(1), .retain_until_unix_ms = 1_000 }, 1_001));
    try testing.expectEqual(@as(usize, 0), store.count());

    // A fresh claim whose deadline has not yet passed still succeeds
    // normally — this only guards claims that are stale on arrival.
    try testing.expectEqual(ClaimResult.accepted, store.claim(.{ .key = keyOf(1), .retain_until_unix_ms = 1_001 }, 1_001));
}

test "an already-stale claim also fails closed against a live entry it would otherwise expire and replace" {
    // Same boundary gap, but with a *prior* live entry for the same key
    // already present: the duplicate check must still win first (the key
    // remains claimed), rather than the stale-deadline guard tearing down
    // protection that was already established.
    var store = try LocalStore.init(testing.allocator, testLimits(4), 0, 1_000);
    defer store.deinit();
    try testing.expectEqual(ClaimResult.accepted, store.claim(.{ .key = keyOf(1), .retain_until_unix_ms = 5_000 }, 1_000));
    try testing.expectEqual(ClaimResult.duplicate, store.claim(.{ .key = keyOf(1), .retain_until_unix_ms = 1_000 }, 1_001));
    try testing.expectEqual(@as(usize, 1), store.count());
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

test "allocation failure while reserving startup capacity fails init closed" {
    var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    try testing.expectError(error.OutOfMemory, LocalStore.init(failing.allocator(), testLimits(4), 0, 0));
}

test "long-lived fill/expire/reclaim/insert churn across distinct keys stays bounded with zero further allocations" {
    // `init` reserves capacity for the full configured bound up front, and
    // both the at-capacity reclaim and the tombstone-compaction rehash it
    // triggers are allocation-free — so once a store is up, no amount of
    // long-lived, diverse-key expire/reclaim churn should ever need to
    // allocate again. Disabling the allocator entirely after the initial
    // fill is what actually proves that, rather than merely asserting on
    // results.
    const limit = 8;
    var store = try LocalStore.init(testing.allocator, testLimits(limit), 0, 0);
    defer store.deinit();

    var next_key: u32 = 1;
    var now: u64 = 0;
    var i: usize = 0;
    while (i < limit) : (i += 1) {
        // Every fill entry expires the instant `now` advances at all.
        try testing.expectEqual(ClaimResult.accepted, store.claim(.{ .key = keyOfU32(next_key), .retain_until_unix_ms = now }, now));
        next_key += 1;
    }
    try testing.expectEqual(@as(usize, limit), store.count());

    var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    const original_allocator = store.allocator;
    store.allocator = failing.allocator();
    defer store.allocator = original_allocator;

    var cycle: usize = 0;
    while (cycle < 500) : (cycle += 1) {
        now += 1;
        const result = store.claim(.{ .key = keyOfU32(next_key), .retain_until_unix_ms = now }, now);
        try testing.expectEqual(ClaimResult.accepted, result);
        try testing.expectEqual(@as(usize, limit), store.count());
        next_key += 1;
    }
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

// ---------------------------------------------------------------------
// #368 Slice 2: `GateAdapter` — adapting `Store` to the TLS-layer
// `EarlyDataReplayGate` seam.
// ---------------------------------------------------------------------

test "mapClaimResult: only duplicate maps to replay; capacity and unavailable both fail closed to unavailable" {
    try testing.expectEqual(tls13_backend.EarlyDataReplayDecision.allow, mapClaimResult(.accepted));
    try testing.expectEqual(tls13_backend.EarlyDataReplayDecision.replay, mapClaimResult(.duplicate));
    try testing.expectEqual(tls13_backend.EarlyDataReplayDecision.unavailable, mapClaimResult(.rejected_capacity));
    try testing.expectEqual(tls13_backend.EarlyDataReplayDecision.unavailable, mapClaimResult(.unavailable));
}

test "GateAdapter.gate() drives a real LocalStore: allow, then replay, preserving the candidate's key/deadline" {
    var store = try LocalStore.init(testing.allocator, testLimits(4), 0, 1_000);
    defer store.deinit();
    var adapter = GateAdapter.init(store.store());
    const gate = adapter.gate();

    const candidate: tls13_backend.EarlyDataReplayCandidate = .{
        .ticket_identity_fingerprint = keyOf(9),
        .retain_until_unix_ms = std.math.maxInt(u64),
    };
    try testing.expectEqual(tls13_backend.EarlyDataReplayDecision.allow, gate.decideFn.?(gate.ctx, candidate));
    try testing.expectEqual(tls13_backend.EarlyDataReplayDecision.replay, gate.decideFn.?(gate.ctx, candidate));
    try testing.expectEqual(@as(usize, 1), store.count());
}

test "GateAdapter.gate() surfaces startup quarantine as unavailable, never as replay" {
    // `Store.claim` (unlike `LocalStore.claim` called directly) reads real
    // wall-clock time at the trampoline boundary — see `store()`'s doc
    // comment — so the store must be seeded from that same clock for a
    // quarantine window to still be open moments later in this test.
    var store = try LocalStore.init(testing.allocator, testLimits(4), 60_000, @intCast(zig_compat.milliTimestamp()));
    defer store.deinit();
    var adapter = GateAdapter.init(store.store());
    const gate = adapter.gate();

    const candidate: tls13_backend.EarlyDataReplayCandidate = .{
        .ticket_identity_fingerprint = keyOf(1),
        .retain_until_unix_ms = 5_000,
    };
    try testing.expectEqual(tls13_backend.EarlyDataReplayDecision.unavailable, gate.decideFn.?(gate.ctx, candidate));
    try testing.expectEqual(@as(usize, 0), store.count());
}

test "GateAdapter.gate() surfaces capacity exhaustion as unavailable without evicting the live entry" {
    var store = try LocalStore.init(testing.allocator, testLimits(1), 0, 1_000);
    defer store.deinit();
    var adapter = GateAdapter.init(store.store());
    const gate = adapter.gate();

    const first: tls13_backend.EarlyDataReplayCandidate = .{
        .ticket_identity_fingerprint = keyOf(1),
        .retain_until_unix_ms = std.math.maxInt(u64),
    };
    const second: tls13_backend.EarlyDataReplayCandidate = .{
        .ticket_identity_fingerprint = keyOf(2),
        .retain_until_unix_ms = std.math.maxInt(u64),
    };
    try testing.expectEqual(tls13_backend.EarlyDataReplayDecision.allow, gate.decideFn.?(gate.ctx, first));
    try testing.expectEqual(tls13_backend.EarlyDataReplayDecision.unavailable, gate.decideFn.?(gate.ctx, second));
    // The first key must still be protected — capacity exhaustion never
    // evicts a live entry to admit a new one.
    try testing.expectEqual(tls13_backend.EarlyDataReplayDecision.replay, gate.decideFn.?(gate.ctx, first));
}

// ---------------------------------------------------------------------
// #368 Slice 3: `FakeDistributedStore` — deterministic proof of the future
// distributed-store contract, independent of `LocalStore`.
// ---------------------------------------------------------------------

test "FakeDistributedStore: first claim of a key is accepted, a repeated claim of the same key is duplicate" {
    var fake = FakeDistributedStore.init(testing.allocator);
    defer fake.deinit();
    try testing.expectEqual(ClaimResult.accepted, fake.claim(.{ .key = keyOf(1), .retain_until_unix_ms = std.math.maxInt(u64) }));
    try testing.expectEqual(ClaimResult.duplicate, fake.claim(.{ .key = keyOf(1), .retain_until_unix_ms = std.math.maxInt(u64) }));
    // A different key is independent.
    try testing.expectEqual(ClaimResult.accepted, fake.claim(.{ .key = keyOf(2), .retain_until_unix_ms = std.math.maxInt(u64) }));
}

test "FakeDistributedStore: simulated timeout, network failure, and ambiguous commit all fail closed to unavailable, never accepted" {
    var fake = FakeDistributedStore.init(testing.allocator);
    defer fake.deinit();

    fake.mode = .timeout;
    try testing.expectEqual(ClaimResult.unavailable, fake.claim(.{ .key = keyOf(1), .retain_until_unix_ms = std.math.maxInt(u64) }));

    fake.mode = .network_failure;
    try testing.expectEqual(ClaimResult.unavailable, fake.claim(.{ .key = keyOf(1), .retain_until_unix_ms = std.math.maxInt(u64) }));

    fake.mode = .ambiguous_commit;
    try testing.expectEqual(ClaimResult.unavailable, fake.claim(.{ .key = keyOf(1), .retain_until_unix_ms = std.math.maxInt(u64) }));

    // None of the failed attempts committed anything: the key is still
    // available for a genuine first claim once the backend recovers.
    fake.mode = .commit;
    try testing.expectEqual(ClaimResult.accepted, fake.claim(.{ .key = keyOf(1), .retain_until_unix_ms = std.math.maxInt(u64) }));
}

test "GateAdapter over a fake distributed Store (not LocalStore) drives the same allow/replay/unavailable decisions — composition depends only on the Store contract" {
    var fake = FakeDistributedStore.init(testing.allocator);
    defer fake.deinit();
    var adapter = GateAdapter.init(fake.store());
    const gate = adapter.gate();

    const candidate: tls13_backend.EarlyDataReplayCandidate = .{
        .ticket_identity_fingerprint = keyOf(9),
        .retain_until_unix_ms = std.math.maxInt(u64),
    };
    // First claim on a healthy backend: allow.
    try testing.expectEqual(tls13_backend.EarlyDataReplayDecision.allow, gate.decideFn.?(gate.ctx, candidate));
    // Repeated claim of the same key: proven replay.
    try testing.expectEqual(tls13_backend.EarlyDataReplayDecision.replay, gate.decideFn.?(gate.ctx, candidate));

    // A distributed failure never maps to `.allow` — even for a fresh key.
    fake.mode = .network_failure;
    const other: tls13_backend.EarlyDataReplayCandidate = .{
        .ticket_identity_fingerprint = keyOf(10),
        .retain_until_unix_ms = std.math.maxInt(u64),
    };
    try testing.expectEqual(tls13_backend.EarlyDataReplayDecision.unavailable, gate.decideFn.?(gate.ctx, other));
}

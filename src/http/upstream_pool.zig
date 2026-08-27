//! Owned upstream connection pool (#141).
//!
//! A single shared, mutex-guarded map of `host:port → { idle connections,
//! per-host counters }` reused across all worker threads. Restores keep-alive
//! reuse on top of the manual bounded transport from #196. See
//! `docs/UPSTREAM_POOLING.md` for the design rationale and deferred work.
//!
//! Scope: HTTP/1.1 over TCP, plain or TLS (#141 Phase 1c). For TLS the pooled
//! entry owns the native `UpstreamTlsConn`; the key is scheme-prefixed so plain and
//! TLS connections to the same host are never confused. Unix-socket pooling is
//! deferred. The caller owns the HTTP exchange and decides reusability before
//! calling `release`.
//!
//! Phase 1b adds per-upstream counters (new/reused/idle/active/stale), an
//! `active` gauge (connections currently checked out), and a connect-latency
//! histogram, surfaced as per-upstream labelled Prometheus series.

const std = @import("std");
const compat = @import("zig_compat");
const upstream_tls = @import("upstream_tls.zig");
const proxy_buffer_account = @import("proxy_buffer_account.zig");

pub const Config = struct {
    enabled: bool = true,
    /// Maximum idle connections cached per origin.
    max_idle_per_host: usize = 32,
    /// Evict an idle connection unused for at least this long.
    idle_timeout_ms: u64 = 90_000,
    /// Hard cap on total connection age (0 = unlimited).
    max_lifetime_ms: u64 = 0,
    /// Hard cap on concurrently checked-out connections per origin
    /// (0 = unlimited). Enforced **fail-fast** (#239): `checkout`/`reserveSlot`
    /// return `error.UpstreamAtCapacity` instead of queueing, and the proxy
    /// maps it to 503 `upstream_saturated`. In the thread-per-connection
    /// worker model, blocking here would let one slow origin absorb the whole
    /// worker pool — queueing/watermark semantics are #140's scope.
    max_active_per_host: usize = 0,
    /// Opt-in benchmark instrumentation for shared-pool mutex wait time.
    lock_contention_metrics_enabled: bool = false,
    /// Proxy buffer policy for HTTP/1 origins (#140). Only
    /// `per_origin_hard_limit` is read here — the per-stream watermarks belong
    /// to the relay, not the pool. Update through `setProxyBufferLimits`, never
    /// by writing this field: a request must not push its own config snapshot
    /// into shared state, or one that started before a reload would land here
    /// afterwards and restore the superseded limit.
    ///
    /// Unlike the rest of `Config`, this field is mutable at runtime and is
    /// guarded by `origin_buffers_mutex` — the same lock as the accounts it
    /// initializes.
    proxy_buffer_limits: proxy_buffer_account.Limits = proxy_buffer_account.Limits.defaults(),
};

/// Identifier of the worker thread that last released a connection. Used purely
/// to classify a reuse as local (same thread parked and reclaimed it) vs
/// cross-worker (one thread parked it, another reclaimed it — the shared-pool
/// behaviour #147 set out to measure). Not used for socket ownership.
pub fn currentWorkerId() u64 {
    return @intCast(std.Thread.getCurrentId());
}

/// A pooled connection: an owned transport plus age bookkeeping. `stream` may
/// wrap a raw fd (data-plane, via `netStreamFromFd`) or an event-loop stream
/// (FastCGI, via `connectUnixSocket`/`tcpConnectToHost`). For TLS upstreams
/// `tls` holds the heap-owned native `UpstreamTlsConn` (allocated with the pool's
/// allocator); the pool deinits and frees it when the connection is closed.
/// `tls` is null for plain HTTP and FastCGI. `released_by` records the worker
/// that last parked it (set on `release`, read on `acquire`).
pub const PooledConn = struct {
    stream: compat.NetStream,
    tls: ?*upstream_tls.UpstreamTlsConn = null,
    created_ms: u64,
    last_used_ms: u64,
    released_by: u64 = 0,
};

/// Per-origin counters. `idle`/`active` are gauges; the rest are monotonic.
/// `reused_local_total` + `reused_cross_worker_total` partition `reused_total`.
pub const HostStats = struct {
    new_total: u64 = 0,
    reused_total: u64 = 0,
    reused_local_total: u64 = 0,
    reused_cross_worker_total: u64 = 0,
    stale_retries_total: u64 = 0,
    /// Checkouts rejected fail-fast at `max_active_per_host` (#239).
    at_capacity_total: u64 = 0,
    active: u64 = 0,
    idle: u64 = 0,
};

/// Aggregate (all-origin) counters, summed from the per-host map.
pub const Stats = struct {
    new_total: u64 = 0,
    reused_total: u64 = 0,
    reused_local_total: u64 = 0,
    reused_cross_worker_total: u64 = 0,
    stale_retries_total: u64 = 0,
    at_capacity_total: u64 = 0,
    idle: u64 = 0,
    active: u64 = 0,
};

pub const LockContentionStats = struct {
    wait_ns_total: u64 = 0,
    acquires_total: u64 = 0,
};

/// A copy of one origin's identity + counters for rendering. `host` is owned by
/// the caller and freed via `freeHostSnapshots`.
pub const HostSnapshot = struct {
    host: []u8,
    stats: HostStats,
};

/// A copy of one HTTP/1 origin's proxy buffer accounting for rendering (#140).
/// `origin` is the pool key (`http:host:port`, `https:host:port`, or
/// `unix:/path`), owned by the caller and freed via `freeOriginBufferSnapshots`.
///
/// Separate from `HostSnapshot` because the two maps do not have the same
/// membership: an origin accrues a buffer account whenever it is proxied to,
/// including when connection pooling is disabled and no host entry exists.
pub const OriginBufferSnapshot = struct {
    origin: []u8,
    /// Bytes this origin's relays currently hold, by direction. Request and
    /// response relay buffers clear the *same* per-origin limit, so reporting
    /// one direction would let the gauge read zero while the limit was being
    /// enforced against the other.
    buffered_bytes: [2]usize,
    buffer_limit_exceeded_total: [2]u64,

    pub fn bufferedBytes(self: *const OriginBufferSnapshot, direction: proxy_buffer_account.Direction) usize {
        return self.buffered_bytes[@intFromEnum(direction)];
    }

    pub fn bufferLimitExceeded(self: *const OriginBufferSnapshot, direction: proxy_buffer_account.Direction) u64 {
        return self.buffer_limit_exceeded_total[@intFromEnum(direction)];
    }
};

pub fn freeOriginBufferSnapshots(allocator: std.mem.Allocator, snaps: []OriginBufferSnapshot) void {
    for (snaps) |snap| allocator.free(snap.origin);
    allocator.free(snaps);
}

/// Connect-latency histogram buckets (milliseconds, cumulative `le` bounds).
pub const connect_latency_bounds_ms = [_]u64{ 1, 5, 10, 25, 50, 100, 250, 500, 1000 };

pub const ConnectLatencySnapshot = struct {
    /// Per-bucket (non-cumulative) counts; index `bounds.len` is the overflow.
    buckets: [connect_latency_bounds_ms.len + 1]u64,
    count: u64,
    sum_ms: u64,
};

/// Request-latency histogram buckets (milliseconds, cumulative `le` bounds).
/// Wider tail than connect latency: a request includes the full response
/// (buffered read or streaming relay), not just the TCP handshake.
pub const request_latency_bounds_ms = [_]u64{ 1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 10_000 };

/// One completed-exchange latency histogram (#145 — "upstream p99 by
/// protocol"). Recorded per negotiated protocol on successful exchanges only,
/// measured from starting the exchange on an acquired connection to the
/// response being fully received (buffered path) or fully relayed downstream
/// (streaming path).
pub const RequestLatencyHist = struct {
    /// Per-bucket (non-cumulative) counts; index `bounds.len` is the overflow.
    buckets: [request_latency_bounds_ms.len + 1]u64 = [_]u64{0} ** (request_latency_bounds_ms.len + 1),
    count: u64 = 0,
    sum_ms: u64 = 0,

    fn record(self: *RequestLatencyHist, latency_ms: u64) void {
        self.count += 1;
        self.sum_ms += latency_ms;
        for (request_latency_bounds_ms, 0..) |bound, i| {
            if (latency_ms <= bound) {
                self.buckets[i] += 1;
                return;
            }
        }
        self.buckets[request_latency_bounds_ms.len] += 1;
    }
};

pub const RequestLatencySnapshot = struct {
    h1: RequestLatencyHist,
    h2: RequestLatencyHist,
};

const HostEntry = struct {
    idle: std.ArrayList(PooledConn) = .empty,
    stats: HostStats = .{},
};

pub const UpstreamPool = struct {
    allocator: std.mem.Allocator,
    mutex: compat.Mutex = .{},
    config: Config,
    hosts: std.StringHashMap(HostEntry),
    /// Origin-scope proxy buffer aggregates (#140), one per origin ever
    /// proxied to. Held as pointers so an entry stays put across rehashes: a
    /// relay holds its aggregate for the life of a request, and the map may
    /// grow under it when an unrelated worker meets a new origin. Deliberately
    /// separate from `hosts` — an origin gets an account even when connection
    /// pooling is off, and a buffer account is not a connection statistic.
    ///
    /// Entries are never removed, for the same reason `hosts` keeps its own:
    /// the keys are configured origins, so the map is bounded by the
    /// configuration, and a live relay holds a pointer into an entry.
    origin_buffers: std.StringHashMap(*proxy_buffer_account.Aggregate),
    /// Guards `origin_buffers` alone. A separate lock from `mutex` on purpose:
    /// every streaming request looks its origin's account up, and that lookup
    /// must not join the checkout/release traffic on the shared pool mutex —
    /// nor be counted as pool-mutex contention by the benchmark metrics. Never
    /// held together with `mutex`, so there is no ordering to get wrong.
    origin_buffers_mutex: compat.Mutex = .{},
    connect_latency_buckets: [connect_latency_bounds_ms.len + 1]u64 = [_]u64{0} ** (connect_latency_bounds_ms.len + 1),
    connect_latency_count: u64 = 0,
    connect_latency_sum_ms: u64 = 0,
    /// Completed-exchange latency per negotiated protocol (#145), mutex-guarded
    /// like the connect-latency histogram.
    request_latency_h1: RequestLatencyHist = .{},
    request_latency_h2: RequestLatencyHist = .{},
    /// Upstream requests by negotiated application protocol (#145). Atomic so
    /// the hot proxy path need not take the pool mutex just to count.
    protocol_h1_requests: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    protocol_h2_requests: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    /// Count streaming uploads that requested h2/h2c but still had to use h1
    /// because the h2 pool was unavailable for the exchange.
    h2_streaming_upload_fallbacks: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    lock_wait_ns_total: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    lock_acquires_total: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    pub fn init(allocator: std.mem.Allocator, config: Config) UpstreamPool {
        return .{
            .allocator = allocator,
            .config = config,
            .hosts = std.StringHashMap(HostEntry).init(allocator),
            .origin_buffers = std.StringHashMap(*proxy_buffer_account.Aggregate).init(allocator),
        };
    }

    pub fn deinit(self: *UpstreamPool) void {
        var it = self.hosts.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.idle.items) |conn| self.closeConn(conn);
            entry.value_ptr.idle.deinit(self.allocator);
            self.allocator.free(entry.key_ptr.*);
        }
        self.hosts.deinit();
        // Safe only because every in-flight relay has finished: a live relay
        // holds a pointer into one of these accounts.
        var bit = self.origin_buffers.iterator();
        while (bit.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.origin_buffers.deinit();
        self.* = undefined;
    }

    /// The origin-scope proxy buffer aggregate for `key`, created on first use.
    /// The returned pointer is stable for the pool's lifetime, so a relay may
    /// hold it across retries and reconnects.
    ///
    /// Read-only with respect to policy: the hard limit comes from
    /// `config.proxy_buffer_limits`, which only `setProxyBufferLimits` writes.
    pub fn originBufferAccount(self: *UpstreamPool, key: []const u8) !*proxy_buffer_account.Aggregate {
        self.origin_buffers_mutex.lock();
        defer self.origin_buffers_mutex.unlock();
        const gop = try self.origin_buffers.getOrPut(key);
        if (!gop.found_existing) {
            errdefer _ = self.origin_buffers.remove(key);
            const account = try self.allocator.create(proxy_buffer_account.Aggregate);
            errdefer self.allocator.destroy(account);
            // A new origin starts under the policy in force right now, not the
            // aggregate type's unlimited default.
            account.* = proxy_buffer_account.Aggregate.init(.origin, self.config.proxy_buffer_limits.per_origin_hard_limit);
            gop.key_ptr.* = try self.allocator.dupe(u8, key);
            gop.value_ptr.* = account;
        }
        return gop.value_ptr.*;
    }

    /// Apply a reloaded proxy buffer policy. The per-origin hard limit takes
    /// effect immediately for every origin, including ones already carrying
    /// reservations: bytes already reserved above the new limit stay reserved,
    /// and the next reservation is refused until the origin drains.
    pub fn setProxyBufferLimits(self: *UpstreamPool, limits: proxy_buffer_account.Limits) void {
        self.origin_buffers_mutex.lock();
        defer self.origin_buffers_mutex.unlock();
        self.config.proxy_buffer_limits = limits;
        var it = self.origin_buffers.valueIterator();
        while (it.next()) |account| account.*.setHardLimit(limits.per_origin_hard_limit);
    }

    /// Snapshot per-origin buffer accounting for rendering. Caller frees with
    /// `freeOriginBufferSnapshots`.
    pub fn snapshotOriginBuffers(self: *UpstreamPool, allocator: std.mem.Allocator) ![]OriginBufferSnapshot {
        self.origin_buffers_mutex.lock();
        defer self.origin_buffers_mutex.unlock();
        var out = std.array_list.Managed(OriginBufferSnapshot).init(allocator);
        errdefer {
            for (out.items) |snap| allocator.free(snap.origin);
            out.deinit();
        }
        var it = self.origin_buffers.iterator();
        while (it.next()) |entry| {
            const account = entry.value_ptr.*;
            const origin = try allocator.dupe(u8, entry.key_ptr.*);
            errdefer allocator.free(origin);
            try out.append(.{
                .origin = origin,
                .buffered_bytes = .{
                    account.currentBytes(.downstream_to_upstream),
                    account.currentBytes(.upstream_to_downstream),
                },
                .buffer_limit_exceeded_total = .{
                    account.limitExceededEvents(.downstream_to_upstream),
                    account.limitExceededEvents(.upstream_to_downstream),
                },
            });
        }
        return out.toOwnedSlice();
    }

    fn isExpired(self: *const UpstreamPool, conn: PooledConn, now_ms: u64) bool {
        if (self.config.idle_timeout_ms > 0 and now_ms -| conn.last_used_ms >= self.config.idle_timeout_ms) return true;
        if (self.config.max_lifetime_ms > 0 and now_ms -| conn.created_ms >= self.config.max_lifetime_ms) return true;
        return false;
    }

    /// Whether an idle pooled connection already has something readable
    /// waiting on its raw fd -- unsolicited bytes the origin sent after
    /// releasing it back to the pool, or the origin having closed the
    /// connection outright.
    ///
    /// The existing framing fixes above only prove a connection was in sync
    /// *at the instant it was released*: a response that lands exactly on
    /// its declared Content-Length/chunked boundary is legitimately marked
    /// reusable, but a hostile or misbehaving origin can send a "ghost"
    /// response asynchronously *after* release, with no relationship to any
    /// request Tardigrade ever sent. Nothing at release time can observe
    /// that; it can only be caught by checking again right before the
    /// connection is handed to the next, unrelated caller (#673 review).
    /// Without this, that caller sends its request and then reads the
    /// stale ghost bytes as if they were its own response.
    ///
    /// A zero-timeout `poll()` is a conservative test for a **plain**
    /// connection: `POLLIN` means bytes are already queued, `POLLHUP`/
    /// `POLLERR` mean the peer is gone either way, and every byte on a
    /// plain connection's raw fd is necessarily application-layer, so any
    /// of these unambiguously means "do not reuse". A poll failure fails
    /// closed (treated as stale) rather than risking a false "clean" on an
    /// unexpected error.
    ///
    /// A **TLS** connection cannot use the same raw-fd poll: real TLS 1.3
    /// servers routinely send a `NewSessionTicket` (or other post-handshake,
    /// record-layer-only message) asynchronously right after the handshake,
    /// with no relationship to application data at all. That ciphertext
    /// shows up as `POLLIN` on the raw fd immediately, which would flag
    /// essentially every freshly-pooled TLS connection as "stale" and
    /// defeat TLS connection pooling outright (caught by an integration
    /// test asserting a second proxied HTTPS request reuses the pooled
    /// connection). Use `UpstreamTlsConn.readReady()` instead: it reports
    /// only already-decrypted, buffered plaintext the record layer has
    /// promoted to application data (`pending() > 0`), or a completed
    /// clean TLS shutdown (`close_notify`) — genuine signals that this
    /// connection actually has something an unrelated caller should not
    /// see, without decoding the mere presence of encrypted bytes as
    /// staleness.
    ///
    /// This does not catch every conceivable timing of a hostile TLS
    /// origin's ghost bytes (raw ciphertext that has arrived but not yet
    /// been fed through the record layer looks the same as "nothing
    /// pending" here) -- #673 review round 8 correctly flagged this gap and
    /// a nonblocking-drive-then-check variant
    /// (`UpstreamTlsConn.drainQueuedRecordsAndCheckReady()`) was built to
    /// close it. That variant passed locally and in this platform's CI, but
    /// broke `"native upstream https: two proxied requests reuse the
    /// pooled TLS connection"` on Linux ARM CI specifically (reused_total
    /// stayed at 0), indicating a cross-platform behavior difference in the
    /// drive loop that could not be safely root-caused without access to
    /// that environment. Reverted to `readReady()` -- proven stable across
    /// every CI platform -- rather than ship an active-draining approach
    /// with an unexplained platform-dependent failure mode. This is a
    /// strict improvement over having no TLS staleness check at all (the
    /// pre-round-7 state), even though it does not fully close the
    /// undriven-ghost-ciphertext gap; see `docs/SECURITY_TEST_PLAN.md`
    /// defect 27 for the honestly-scoped remaining gap.
    fn hasUnexpectedReadableBytes(conn: PooledConn) bool {
        if (conn.tls) |tls| return tls.drainQueuedRecordsAndCheckReady();
        var pfds = [_]std.posix.pollfd{.{
            .fd = conn.stream.handle,
            .events = std.posix.POLL.IN | std.posix.POLL.HUP | std.posix.POLL.ERR,
            .revents = 0,
        }};
        const n = std.posix.poll(&pfds, 0) catch return true;
        if (n == 0) return false;
        return (pfds[0].revents & (std.posix.POLL.IN | std.posix.POLL.HUP | std.posix.POLL.ERR)) != 0;
    }

    /// Close a connection: tear down the owned TLS connection (if any), then
    /// close the transport.
    fn closeConn(self: *UpstreamPool, conn: PooledConn) void {
        if (conn.tls) |t| {
            t.deinit();
            self.allocator.destroy(t);
        }
        conn.stream.close();
    }

    fn lock(self: *UpstreamPool) u64 {
        if (!self.config.lock_contention_metrics_enabled) {
            self.mutex.lock();
            return 0;
        }
        const start = compat.monotonicNanoTimestamp();
        self.mutex.lock();
        const end = compat.monotonicNanoTimestamp();
        return if (end > start) @intCast(end - start) else 0;
    }

    fn unlock(self: *UpstreamPool, waited_ns: u64) void {
        self.mutex.unlock();
        if (self.config.lock_contention_metrics_enabled) {
            _ = self.lock_wait_ns_total.fetchAdd(waited_ns, .monotonic);
            _ = self.lock_acquires_total.fetchAdd(1, .monotonic);
        }
    }

    fn lockForSnapshot(self: *UpstreamPool) void {
        self.mutex.lock();
    }

    fn unlockForSnapshot(self: *UpstreamPool) void {
        self.mutex.unlock();
    }

    /// Get or create the per-host entry for `key`, duping the key on insert.
    /// Returns null only on allocation failure. Caller holds the mutex.
    fn hostEntry(self: *UpstreamPool, key: []const u8) ?*HostEntry {
        const gop = self.hosts.getOrPut(key) catch return null;
        if (!gop.found_existing) {
            const owned_key = self.allocator.dupe(u8, key) catch {
                _ = self.hosts.remove(key);
                return null;
            };
            gop.key_ptr.* = owned_key;
            gop.value_ptr.* = .{};
        }
        return gop.value_ptr;
    }

    /// Reuse-or-reserve checkout with fail-fast active-cap enforcement (#239).
    /// Returns a still-fresh pooled connection (now counted `active`), or null
    /// after **reserving** an active slot for the caller to open a fresh
    /// connection — on that path the caller MUST call `noteNewConnection` once
    /// connected, or `releaseSlot` if the connect fails, so the reservation is
    /// not leaked. Reserving before connecting (rather than counting after) is
    /// what makes the cap a real hard cap: concurrent callers cannot race past
    /// it during their connect/handshake window.
    ///
    /// When the pool is disabled, returns null without reserving (the caller's
    /// fresh connection is untracked, as before). At `max_active_per_host`
    /// the checkout fails fast with `error.UpstreamAtCapacity` instead of
    /// queueing; see `Config.max_active_per_host` for the rationale.
    pub fn checkout(self: *UpstreamPool, key: []const u8, now_ms: u64) error{UpstreamAtCapacity}!?PooledConn {
        if (!self.config.enabled) return null;
        const lock_wait_ns = self.lock();
        defer self.unlock(lock_wait_ns);
        const entry = self.hostEntry(key) orelse return null; // OOM: proceed untracked
        if (self.config.max_active_per_host > 0 and entry.stats.active >= self.config.max_active_per_host) {
            entry.stats.at_capacity_total += 1;
            return error.UpstreamAtCapacity;
        }
        while (entry.idle.pop()) |conn| {
            if (self.isExpired(conn, now_ms)) {
                self.closeConn(conn);
                continue;
            }
            if (hasUnexpectedReadableBytes(conn)) {
                entry.stats.stale_retries_total += 1;
                self.closeConn(conn);
                continue;
            }
            entry.stats.reused_total += 1;
            if (conn.released_by == currentWorkerId()) {
                entry.stats.reused_local_total += 1;
            } else {
                entry.stats.reused_cross_worker_total += 1;
            }
            entry.stats.active += 1;
            entry.stats.idle = entry.idle.items.len;
            return conn;
        }
        entry.stats.idle = 0;
        entry.stats.active += 1; // reservation for the caller's fresh connection
        return null;
    }

    /// Reserve an active slot for a fresh connection without considering idle
    /// reuse (the stale-retry path deliberately wants a new connection). Same
    /// contract as `checkout`'s null return: pair with `noteNewConnection` or
    /// `releaseSlot`.
    pub fn reserveSlot(self: *UpstreamPool, key: []const u8) error{UpstreamAtCapacity}!void {
        if (!self.config.enabled) return;
        const lock_wait_ns = self.lock();
        defer self.unlock(lock_wait_ns);
        const entry = self.hostEntry(key) orelse return;
        if (self.config.max_active_per_host > 0 and entry.stats.active >= self.config.max_active_per_host) {
            entry.stats.at_capacity_total += 1;
            return error.UpstreamAtCapacity;
        }
        entry.stats.active += 1;
    }

    /// Undo a `checkout`/`reserveSlot` reservation after a fresh connect
    /// failed. No-op for untracked (disabled/OOM) checkouts.
    pub fn releaseSlot(self: *UpstreamPool, key: []const u8) void {
        const lock_wait_ns = self.lock();
        defer self.unlock(lock_wait_ns);
        const entry = self.hosts.getPtr(key) orelse return;
        if (entry.stats.active > 0) entry.stats.active -= 1;
    }

    /// Record that the caller opened a fresh connection for `key`. The active
    /// slot was already reserved by `checkout`/`reserveSlot`; this only counts.
    pub fn noteNewConnection(self: *UpstreamPool, key: []const u8) void {
        const lock_wait_ns = self.lock();
        defer self.unlock(lock_wait_ns);
        const entry = self.hostEntry(key) orelse return;
        entry.stats.new_total += 1;
    }

    /// Hand a checked-out connection back. It is returned to the idle pool when
    /// `reusable` and there is room and it has not aged out; otherwise it is
    /// closed. Either way the origin's `active` gauge is decremented.
    pub fn release(self: *UpstreamPool, key: []const u8, conn: PooledConn, reusable: bool, now_ms: u64) void {
        const lock_wait_ns = self.lock();
        defer self.unlock(lock_wait_ns);
        const entry = self.hostEntry(key) orelse {
            self.closeConn(conn);
            return;
        };
        if (entry.stats.active > 0) entry.stats.active -= 1;

        if (!self.config.enabled or !reusable or self.isExpired(conn, now_ms) or
            entry.idle.items.len >= self.config.max_idle_per_host)
        {
            self.closeConn(conn);
            return;
        }
        var updated = conn;
        updated.last_used_ms = now_ms;
        updated.released_by = currentWorkerId();
        entry.idle.append(self.allocator, updated) catch {
            self.closeConn(conn);
            return;
        };
        entry.stats.idle = entry.idle.items.len;
    }

    pub fn recordStaleRetry(self: *UpstreamPool, key: []const u8) void {
        const lock_wait_ns = self.lock();
        defer self.unlock(lock_wait_ns);
        const entry = self.hostEntry(key) orelse return;
        entry.stats.stale_retries_total += 1;
    }

    pub fn recordConnectLatency(self: *UpstreamPool, latency_ms: u64) void {
        const lock_wait_ns = self.lock();
        defer self.unlock(lock_wait_ns);
        self.connect_latency_count += 1;
        self.connect_latency_sum_ms += latency_ms;
        for (connect_latency_bounds_ms, 0..) |bound, i| {
            if (latency_ms <= bound) {
                self.connect_latency_buckets[i] += 1;
                return;
            }
        }
        self.connect_latency_buckets[connect_latency_bounds_ms.len] += 1;
    }

    /// Close and drop every idle connection that has aged out, refreshing each
    /// origin's idle gauge. Intended to run from the gateway maintenance tick.
    pub fn reapIdle(self: *UpstreamPool, now_ms: u64) void {
        const lock_wait_ns = self.lock();
        defer self.unlock(lock_wait_ns);
        var it = self.hosts.iterator();
        while (it.next()) |entry| {
            const list = &entry.value_ptr.idle;
            var i: usize = 0;
            while (i < list.items.len) {
                if (self.isExpired(list.items[i], now_ms)) {
                    self.closeConn(list.orderedRemove(i));
                } else {
                    i += 1;
                }
            }
            entry.value_ptr.stats.idle = list.items.len;
        }
    }

    /// Aggregate counters across all origins.
    pub fn aggregateStats(self: *UpstreamPool) Stats {
        self.lockForSnapshot();
        defer self.unlockForSnapshot();
        var agg = Stats{};
        var it = self.hosts.iterator();
        while (it.next()) |entry| {
            const s = entry.value_ptr.stats;
            agg.new_total += s.new_total;
            agg.reused_total += s.reused_total;
            agg.reused_local_total += s.reused_local_total;
            agg.reused_cross_worker_total += s.reused_cross_worker_total;
            agg.stale_retries_total += s.stale_retries_total;
            agg.at_capacity_total += s.at_capacity_total;
            agg.active += s.active;
            agg.idle += entry.value_ptr.idle.items.len;
        }
        return agg;
    }

    /// Snapshot per-origin counters for rendering. Caller frees with
    /// `freeHostSnapshots`.
    pub fn snapshotHosts(self: *UpstreamPool, allocator: std.mem.Allocator) ![]HostSnapshot {
        self.lockForSnapshot();
        defer self.unlockForSnapshot();
        var out = std.array_list.Managed(HostSnapshot).init(allocator);
        errdefer {
            for (out.items) |snap| allocator.free(snap.host);
            out.deinit();
        }
        var it = self.hosts.iterator();
        while (it.next()) |entry| {
            var stats = entry.value_ptr.stats;
            stats.idle = entry.value_ptr.idle.items.len;
            const host = try allocator.dupe(u8, entry.key_ptr.*);
            try out.append(.{ .host = host, .stats = stats });
        }
        return out.toOwnedSlice();
    }

    /// Count an upstream request by negotiated protocol (#145).
    pub fn recordProtocol(self: *UpstreamPool, is_h2: bool) void {
        if (is_h2) {
            _ = self.protocol_h2_requests.fetchAdd(1, .monotonic);
        } else {
            _ = self.protocol_h1_requests.fetchAdd(1, .monotonic);
        }
    }

    /// Total upstream requests served per negotiated protocol.
    pub fn protocolCounts(self: *const UpstreamPool) struct { h1: u64, h2: u64 } {
        return .{
            .h1 = self.protocol_h1_requests.load(.monotonic),
            .h2 = self.protocol_h2_requests.load(.monotonic),
        };
    }

    pub fn recordH2StreamingUploadFallback(self: *UpstreamPool) void {
        _ = self.h2_streaming_upload_fallbacks.fetchAdd(1, .monotonic);
    }

    pub fn h2StreamingUploadFallbacks(self: *const UpstreamPool) u64 {
        return self.h2_streaming_upload_fallbacks.load(.monotonic);
    }

    pub fn lockContentionStats(self: *const UpstreamPool) LockContentionStats {
        return .{
            .wait_ns_total = self.lock_wait_ns_total.load(.monotonic),
            .acquires_total = self.lock_acquires_total.load(.monotonic),
        };
    }

    pub fn connectLatencySnapshot(self: *UpstreamPool) ConnectLatencySnapshot {
        self.lockForSnapshot();
        defer self.unlockForSnapshot();
        return .{
            .buckets = self.connect_latency_buckets,
            .count = self.connect_latency_count,
            .sum_ms = self.connect_latency_sum_ms,
        };
    }

    /// Record one completed upstream exchange for the per-protocol latency
    /// histogram (#145 — "upstream p99 by protocol").
    pub fn recordRequestLatency(self: *UpstreamPool, is_h2: bool, latency_ms: u64) void {
        const lock_wait_ns = self.lock();
        defer self.unlock(lock_wait_ns);
        if (is_h2) {
            self.request_latency_h2.record(latency_ms);
        } else {
            self.request_latency_h1.record(latency_ms);
        }
    }

    pub fn requestLatencySnapshot(self: *UpstreamPool) RequestLatencySnapshot {
        self.lockForSnapshot();
        defer self.unlockForSnapshot();
        return .{ .h1 = self.request_latency_h1, .h2 = self.request_latency_h2 };
    }
};

pub fn freeHostSnapshots(allocator: std.mem.Allocator, snaps: []HostSnapshot) void {
    for (snaps) |snap| allocator.free(snap.host);
    allocator.free(snaps);
}

const testing = std.testing;

fn testPair() ![2]std.posix.fd_t {
    var fds: [2]std.posix.fd_t = undefined;
    try testing.expect(std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds) == 0);
    return fds;
}

test "checkout on an empty pool reserves a slot for a fresh connection" {
    var pool = UpstreamPool.init(testing.allocator, .{});
    defer pool.deinit();
    try testing.expect((try pool.checkout("a:1", 1000)) == null);
    var agg = pool.aggregateStats();
    try testing.expectEqual(@as(u64, 0), agg.reused_total);
    try testing.expectEqual(@as(u64, 1), agg.active); // the reservation
    pool.releaseSlot("a:1"); // fresh connect "failed" — undo
    agg = pool.aggregateStats();
    try testing.expectEqual(@as(u64, 0), agg.active);
}

test "max_active_per_host fails checkout fast and counts at_capacity" {
    var pool = UpstreamPool.init(testing.allocator, .{ .max_active_per_host = 2 });
    defer pool.deinit();
    try testing.expect((try pool.checkout("h:80", 0)) == null); // reserve 1
    try pool.reserveSlot("h:80"); // reserve 2 — at the cap now
    try testing.expectError(error.UpstreamAtCapacity, pool.checkout("h:80", 0));
    try testing.expectError(error.UpstreamAtCapacity, pool.reserveSlot("h:80"));
    const agg = pool.aggregateStats();
    try testing.expectEqual(@as(u64, 2), agg.active);
    try testing.expectEqual(@as(u64, 2), agg.at_capacity_total);
    // Releasing one slot frees capacity again.
    pool.releaseSlot("h:80");
    try testing.expect((try pool.checkout("h:80", 0)) == null);
    // Other origins are unaffected by this origin's saturation.
    try testing.expect((try pool.checkout("other:80", 0)) == null);
    pool.releaseSlot("other:80");
}

test "new connection then release pools it; acquire reuses and tracks active" {
    var pool = UpstreamPool.init(testing.allocator, .{});
    defer pool.deinit();
    const fds = try testPair();
    defer _ = std.c.close(fds[1]);

    try testing.expect((try pool.checkout("h:80", 1000)) == null); // reserve
    pool.noteNewConnection("h:80");
    try testing.expectEqual(@as(u64, 1), pool.aggregateStats().active);
    pool.release("h:80", .{ .stream = compat.netStreamFromFd(fds[0]), .created_ms = 1000, .last_used_ms = 1000 }, true, 1000);

    var agg = pool.aggregateStats();
    try testing.expectEqual(@as(u64, 0), agg.active);
    try testing.expectEqual(@as(u64, 1), agg.idle);
    try testing.expectEqual(@as(u64, 1), agg.new_total);

    const got = (try pool.checkout("h:80", 1500)) orelse return error.TestExpectedReuse;
    try testing.expectEqual(fds[0], got.stream.handle);
    agg = pool.aggregateStats();
    try testing.expectEqual(@as(u64, 1), agg.reused_total);
    try testing.expectEqual(@as(u64, 1), agg.active);
    try testing.expectEqual(@as(u64, 0), agg.idle);
    pool.release("h:80", got, false, 1500); // close it
    try testing.expectEqual(@as(u64, 0), pool.aggregateStats().active);
}

test "checkout discards an idle connection with an unsolicited ghost byte instead of reusing it (#673 review)" {
    // A hostile or misbehaving origin can send a "ghost" response
    // asynchronously, any time after Tardigrade released a connection back
    // to the pool -- with no relationship to any request Tardigrade ever
    // sent on it. The framing-level fixes elsewhere only prove a connection
    // was in sync at release time; only a check at the next checkout can
    // catch bytes that arrive after that.
    var pool = UpstreamPool.init(testing.allocator, .{});
    defer pool.deinit();
    const fds = try testPair();
    defer _ = std.c.close(fds[1]);

    try pool.reserveSlot("h:80");
    pool.noteNewConnection("h:80");
    pool.release("h:80", .{ .stream = compat.netStreamFromFd(fds[0]), .created_ms = 1000, .last_used_ms = 1000 }, true, 1000);
    try testing.expectEqual(@as(u64, 1), pool.aggregateStats().idle);

    // The origin ("fds[1]") sends an unsolicited ghost byte on the idle
    // connection before anyone checks it out again.
    const ghost = "G";
    _ = std.c.write(fds[1], ghost.ptr, ghost.len);

    // checkout() must not hand back the poisoned connection: it should
    // discard it and fall through to "no idle connection available"
    // (reserving a slot for a fresh one), exactly like popping an expired
    // connection does.
    const got = try pool.checkout("h:80", 1500);
    try testing.expect(got == null);
    const agg = pool.aggregateStats();
    try testing.expectEqual(@as(u64, 0), agg.idle);
    try testing.expectEqual(@as(u64, 0), agg.reused_total);
    try testing.expectEqual(@as(u64, 1), agg.stale_retries_total);
}

test "checkout discards an idle connection the origin already closed instead of reusing it" {
    var pool = UpstreamPool.init(testing.allocator, .{});
    defer pool.deinit();
    const fds = try testPair();

    try pool.reserveSlot("h:80");
    pool.noteNewConnection("h:80");
    pool.release("h:80", .{ .stream = compat.netStreamFromFd(fds[0]), .created_ms = 1000, .last_used_ms = 1000 }, true, 1000);
    // The origin closes its end while the connection sits idle.
    _ = std.c.close(fds[1]);

    const got = try pool.checkout("h:80", 1500);
    try testing.expect(got == null);
    try testing.expectEqual(@as(u64, 0), pool.aggregateStats().idle);
}

test "reuse on the releasing thread counts as local" {
    var pool = UpstreamPool.init(testing.allocator, .{});
    defer pool.deinit();
    const fds = try testPair();
    defer _ = std.c.close(fds[1]);

    try pool.reserveSlot("h:80");
    pool.noteNewConnection("h:80");
    pool.release("h:80", .{ .stream = compat.netStreamFromFd(fds[0]), .created_ms = 0, .last_used_ms = 0 }, true, 0);
    // Same thread reclaims it → local reuse.
    const got = (try pool.checkout("h:80", 1)) orelse return error.TestExpectedReuse;
    const agg = pool.aggregateStats();
    try testing.expectEqual(@as(u64, 1), agg.reused_total);
    try testing.expectEqual(@as(u64, 1), agg.reused_local_total);
    try testing.expectEqual(@as(u64, 0), agg.reused_cross_worker_total);
    pool.release("h:80", got, false, 1);
}

test "reuse after a different worker parked it counts as cross-worker" {
    var pool = UpstreamPool.init(testing.allocator, .{});
    defer pool.deinit();
    const fds = try testPair();
    defer _ = std.c.close(fds[1]);

    // Simulate a connection parked by another worker: release stamps the current
    // thread id, so forge a different one directly on the idle entry.
    try pool.reserveSlot("h:80");
    pool.noteNewConnection("h:80");
    pool.release("h:80", .{ .stream = compat.netStreamFromFd(fds[0]), .created_ms = 0, .last_used_ms = 0 }, true, 0);
    pool.hosts.getPtr("h:80").?.idle.items[0].released_by = currentWorkerId() +% 1;

    const got = (try pool.checkout("h:80", 1)) orelse return error.TestExpectedReuse;
    defer pool.release("h:80", got, false, 1); // close the checked-out fd
    const agg = pool.aggregateStats();
    try testing.expectEqual(@as(u64, 1), agg.reused_cross_worker_total);
    try testing.expectEqual(@as(u64, 0), agg.reused_local_total);
}

test "release drops a connection past the idle timeout" {
    var pool = UpstreamPool.init(testing.allocator, .{ .idle_timeout_ms = 1000 });
    defer pool.deinit();
    const fds = try testPair();
    defer _ = std.c.close(fds[1]);

    try pool.reserveSlot("h:80");
    pool.noteNewConnection("h:80");
    // released 2s later, past the 1s idle timeout → closed, not pooled.
    pool.release("h:80", .{ .stream = compat.netStreamFromFd(fds[0]), .created_ms = 0, .last_used_ms = 0 }, true, 2000);
    try testing.expectEqual(@as(u64, 0), pool.aggregateStats().idle);
}

test "release honors max_idle_per_host" {
    var pool = UpstreamPool.init(testing.allocator, .{ .max_idle_per_host = 1 });
    defer pool.deinit();
    const a = try testPair();
    const b = try testPair();
    defer _ = std.c.close(a[1]);
    defer _ = std.c.close(b[1]);

    pool.release("h:80", .{ .stream = compat.netStreamFromFd(a[0]), .created_ms = 0, .last_used_ms = 0 }, true, 0);
    pool.release("h:80", .{ .stream = compat.netStreamFromFd(b[0]), .created_ms = 0, .last_used_ms = 0 }, true, 0);
    try testing.expectEqual(@as(u64, 1), pool.aggregateStats().idle);
}

test "reapIdle evicts aged connections and refreshes the gauge" {
    var pool = UpstreamPool.init(testing.allocator, .{ .idle_timeout_ms = 1000 });
    defer pool.deinit();
    const fds = try testPair();
    defer _ = std.c.close(fds[1]);

    pool.release("h:80", .{ .stream = compat.netStreamFromFd(fds[0]), .created_ms = 0, .last_used_ms = 0 }, true, 0);
    pool.reapIdle(500);
    try testing.expectEqual(@as(u64, 1), pool.aggregateStats().idle);
    pool.reapIdle(2000);
    try testing.expectEqual(@as(u64, 0), pool.aggregateStats().idle);
}

test "request-latency histogram buckets by protocol" {
    var pool = UpstreamPool.init(testing.allocator, .{});
    defer pool.deinit();
    pool.recordRequestLatency(false, 3); // h1, <= 5 bucket
    pool.recordRequestLatency(true, 40); // h2, <= 50 bucket
    pool.recordRequestLatency(true, 99_999); // h2, overflow

    const snap = pool.requestLatencySnapshot();
    try testing.expectEqual(@as(u64, 1), snap.h1.count);
    try testing.expectEqual(@as(u64, 3), snap.h1.sum_ms);
    try testing.expectEqual(@as(u64, 1), snap.h1.buckets[1]); // le=5
    try testing.expectEqual(@as(u64, 2), snap.h2.count);
    try testing.expectEqual(@as(u64, 1), snap.h2.buckets[request_latency_bounds_ms.len]); // overflow
}

test "h2 streaming upload fallback counter is atomic and monotonic" {
    var pool = UpstreamPool.init(testing.allocator, .{});
    defer pool.deinit();
    try testing.expectEqual(@as(u64, 0), pool.h2StreamingUploadFallbacks());
    pool.recordH2StreamingUploadFallback();
    pool.recordH2StreamingUploadFallback();
    try testing.expectEqual(@as(u64, 2), pool.h2StreamingUploadFallbacks());
}

test "per-host snapshot and connect-latency histogram" {
    var pool = UpstreamPool.init(testing.allocator, .{});
    defer pool.deinit();
    pool.noteNewConnection("a:80");
    pool.noteNewConnection("b:80");
    pool.recordStaleRetry("a:80");
    pool.recordConnectLatency(3); // <= 5 bucket
    pool.recordConnectLatency(40); // <= 50 bucket
    pool.recordConnectLatency(5000); // overflow

    const snaps = try pool.snapshotHosts(testing.allocator);
    defer freeHostSnapshots(testing.allocator, snaps);
    try testing.expectEqual(@as(usize, 2), snaps.len);

    const lat = pool.connectLatencySnapshot();
    try testing.expectEqual(@as(u64, 3), lat.count);
    try testing.expectEqual(@as(u64, 5043), lat.sum_ms);
    try testing.expectEqual(@as(u64, 1), lat.buckets[connect_latency_bounds_ms.len]); // overflow
}

// ---------------------------------------------------------------------------
// Per-origin proxy buffer accounting for HTTP/1 origins (#140).
// ---------------------------------------------------------------------------

fn originLimits(per_origin_hard_limit: usize) proxy_buffer_account.Limits {
    var limits = proxy_buffer_account.Limits.defaults();
    limits.per_origin_hard_limit = per_origin_hard_limit;
    return limits;
}

test "origin buffer accounts are stable, per-origin, and start under the configured limit" {
    var pool = UpstreamPool.init(testing.allocator, .{ .proxy_buffer_limits = originLimits(4096) });
    defer pool.deinit();

    const a = try pool.originBufferAccount("http:origin-a:80");
    // The pointer a relay holds must survive the map growing under it.
    for (0..64) |i| {
        var key_buf: [64]u8 = undefined;
        _ = try pool.originBufferAccount(try std.fmt.bufPrint(&key_buf, "http:filler-{d}:80", .{i}));
    }
    try testing.expectEqual(a, try pool.originBufferAccount("http:origin-a:80"));
    try testing.expectEqual(@as(usize, 4096), a.hardLimit());

    // One origin's saturation leaves every other origin's capacity intact.
    try a.reserve(.upstream_to_downstream, 4096);
    try testing.expectError(error.BufferLimitExceeded, a.reserve(.upstream_to_downstream, 1));
    const b = try pool.originBufferAccount("http:origin-b:80");
    try b.reserve(.upstream_to_downstream, 4096);

    a.release(.upstream_to_downstream, 4096);
    b.release(.upstream_to_downstream, 4096);
    try testing.expectEqual(@as(usize, 0), a.currentBytes(.upstream_to_downstream));
}

test "a reloaded per-origin limit applies to origins that already exist" {
    var pool = UpstreamPool.init(testing.allocator, .{ .proxy_buffer_limits = originLimits(4096) });
    defer pool.deinit();

    const existing = try pool.originBufferAccount("http:origin:80");
    try existing.reserve(.upstream_to_downstream, 4096);

    pool.setProxyBufferLimits(originLimits(1024));
    // Bytes already reserved above the new limit stay reserved; the next
    // reservation is refused until the origin drains.
    try testing.expectEqual(@as(usize, 1024), existing.hardLimit());
    try testing.expectEqual(@as(usize, 4096), existing.currentBytes(.upstream_to_downstream));
    try testing.expectError(error.BufferLimitExceeded, existing.reserve(.upstream_to_downstream, 1));
    existing.release(.upstream_to_downstream, 4096);
    try existing.reserve(.upstream_to_downstream, 1024);
    existing.release(.upstream_to_downstream, 1024);

    // And an origin first seen after the reload starts under the new policy.
    const fresh = try pool.originBufferAccount("http:fresh:80");
    try testing.expectEqual(@as(usize, 1024), fresh.hardLimit());
}

test "origin buffer snapshot reports both directions and refusals" {
    var pool = UpstreamPool.init(testing.allocator, .{ .proxy_buffer_limits = originLimits(2048) });
    defer pool.deinit();

    const account = try pool.originBufferAccount("https:origin:443");
    try account.reserve(.downstream_to_upstream, 512);
    try account.reserve(.upstream_to_downstream, 1024);
    try testing.expectError(error.BufferLimitExceeded, account.reserve(.upstream_to_downstream, 2048));

    const snaps = try pool.snapshotOriginBuffers(testing.allocator);
    defer freeOriginBufferSnapshots(testing.allocator, snaps);
    try testing.expectEqual(@as(usize, 1), snaps.len);
    try testing.expectEqualStrings("https:origin:443", snaps[0].origin);
    try testing.expectEqual(@as(usize, 512), snaps[0].bufferedBytes(.downstream_to_upstream));
    try testing.expectEqual(@as(usize, 1024), snaps[0].bufferedBytes(.upstream_to_downstream));
    try testing.expectEqual(@as(u64, 0), snaps[0].bufferLimitExceeded(.downstream_to_upstream));
    try testing.expectEqual(@as(u64, 1), snaps[0].bufferLimitExceeded(.upstream_to_downstream));

    account.release(.downstream_to_upstream, 512);
    account.release(.upstream_to_downstream, 1024);
}

test "an origin gets a buffer account even when connection pooling is disabled" {
    // The account bounds memory, which is just as necessary without pooling.
    var pool = UpstreamPool.init(testing.allocator, .{ .enabled = false, .proxy_buffer_limits = originLimits(2048) });
    defer pool.deinit();

    const account = try pool.originBufferAccount("http:origin:80");
    try testing.expectEqual(@as(usize, 2048), account.hardLimit());

    // No host entry exists — checkout never ran — so the two maps genuinely
    // differ in membership and the buffer series cannot be folded into the
    // connection series.
    const hosts = try pool.snapshotHosts(testing.allocator);
    defer freeHostSnapshots(testing.allocator, hosts);
    try testing.expectEqual(@as(usize, 0), hosts.len);
    const buffers = try pool.snapshotOriginBuffers(testing.allocator);
    defer freeOriginBufferSnapshots(testing.allocator, buffers);
    try testing.expectEqual(@as(usize, 1), buffers.len);
}

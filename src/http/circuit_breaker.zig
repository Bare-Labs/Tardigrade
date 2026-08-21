const std = @import("std");
const compat = @import("zig_compat");

/// Circuit breaker states.
///
/// Closed → normal operation, requests pass through.
/// Open   → upstream considered down; requests fast-fail without calling upstream.
/// Half-Open → testing recovery; one probe request allowed; success closes, failure re-opens.
pub const State = enum { closed, open, half_open };

pub const Permit = union(enum) {
    ordinary,
    half_open: u64,
};

/// Circuit breaker configuration.
pub const Config = struct {
    /// Number of consecutive failures before opening the circuit (0 = disabled).
    threshold: u32 = 5,
    /// Number of successful probe requests needed to close from half-open.
    half_open_successes: u32 = 1,
    /// Milliseconds to wait in open state before transitioning to half-open.
    timeout_ms: u64 = 30_000,
};

/// Upstream circuit breaker.
///
/// Tracks failure/success rates and transitions between states to prevent
/// cascading failures when the upstream is unhealthy.
pub const CircuitBreaker = struct {
    state: State,
    failure_count: u32,
    success_count: u32,
    half_open_probe_in_flight: bool,
    half_open_generation: u64,
    /// Nanosecond timestamp of the last recorded failure.
    last_failure_ns: i128,
    config: Config,

    /// Create a circuit breaker with the given config.
    pub fn init(config: Config) CircuitBreaker {
        return .{
            .state = .closed,
            .failure_count = 0,
            .success_count = 0,
            .half_open_probe_in_flight = false,
            .half_open_generation = 0,
            .last_failure_ns = 0,
            .config = config,
        };
    }

    /// Returns whether a request may proceed to the upstream.
    ///
    /// Side effects: if the circuit is open and the recovery timeout has
    /// elapsed, transitions to half-open and allows one probe through.
    pub fn tryAcquirePermit(self: *CircuitBreaker) ?Permit {
        if (self.config.threshold == 0) return .ordinary; // disabled

        return switch (self.state) {
            .closed => .ordinary,
            .open => blk: {
                const now = compat.nanoTimestamp();
                const elapsed_ns = now - self.last_failure_ns;
                if (elapsed_ns < 0) break :blk null;
                const elapsed_ms: u64 = @intCast(@divFloor(elapsed_ns, std.time.ns_per_ms));
                if (elapsed_ms >= self.config.timeout_ms) {
                    self.state = .half_open;
                    self.success_count = 0;
                    self.half_open_probe_in_flight = true;
                    self.half_open_generation +%= 1;
                    if (self.half_open_generation == 0) self.half_open_generation = 1;
                    break :blk Permit{ .half_open = self.half_open_generation };
                }
                break :blk null;
            },
            .half_open => blk: {
                if (self.half_open_probe_in_flight) break :blk null;
                self.half_open_probe_in_flight = true;
                break :blk Permit{ .half_open = self.half_open_generation };
            },
        };
    }

    /// Release an admitted half-open probe when the request did not reach the
    /// upstream and therefore has no success/failure outcome to record.
    pub fn releasePermit(self: *CircuitBreaker, permit: Permit) void {
        if (self.config.threshold == 0) return;
        switch (permit) {
            .ordinary => {},
            .half_open => |generation| {
                if (self.state == .half_open and self.half_open_generation == generation) {
                    self.half_open_probe_in_flight = false;
                }
            },
        }
    }

    /// Record a successful upstream call.
    pub fn recordSuccessPermit(self: *CircuitBreaker, permit: Permit) void {
        if (self.config.threshold == 0) return;

        switch (permit) {
            .ordinary => {
                if (self.state == .closed) self.failure_count = 0;
            },
            .half_open => |generation| {
                if (self.state != .half_open or self.half_open_generation != generation) return;
                if (!self.half_open_probe_in_flight) return;
                self.half_open_probe_in_flight = false;
                self.success_count += 1;
                if (self.success_count >= self.config.half_open_successes) {
                    self.state = .closed;
                    self.failure_count = 0;
                    self.success_count = 0;
                    self.half_open_probe_in_flight = false;
                }
            },
        }
    }

    /// Record a failed upstream call (connection error or 5xx).
    pub fn recordFailurePermit(self: *CircuitBreaker, permit: Permit) void {
        if (self.config.threshold == 0) return;

        switch (permit) {
            .ordinary => {
                if (self.state == .closed) {
                    self.last_failure_ns = compat.nanoTimestamp();
                    self.failure_count += 1;
                    if (self.failure_count >= self.config.threshold) {
                        self.state = .open;
                        self.half_open_probe_in_flight = false;
                    }
                }
            },
            .half_open => |generation| {
                if (self.state != .half_open or self.half_open_generation != generation) return;
                self.last_failure_ns = compat.nanoTimestamp();
                self.state = .open;
                self.half_open_probe_in_flight = false;
            },
        }
    }

    /// Human-readable state label for logging.
    pub fn stateName(self: *const CircuitBreaker) []const u8 {
        return switch (self.state) {
            .closed => "closed",
            .open => "open",
            .half_open => "half-open",
        };
    }
};

// Tests

test "circuit breaker starts closed" {
    var cb = CircuitBreaker.init(.{});
    try std.testing.expectEqual(State.closed, cb.state);
    try std.testing.expect(cb.tryAcquirePermit() != null);
}

test "circuit breaker opens after threshold failures" {
    var cb = CircuitBreaker.init(.{ .threshold = 3 });

    cb.recordFailurePermit(.ordinary);
    try std.testing.expectEqual(State.closed, cb.state);
    try std.testing.expect(cb.tryAcquirePermit() != null);

    cb.recordFailurePermit(.ordinary);
    try std.testing.expectEqual(State.closed, cb.state);

    cb.recordFailurePermit(.ordinary);
    try std.testing.expectEqual(State.open, cb.state);
    try std.testing.expect(cb.tryAcquirePermit() == null);
}

test "circuit breaker success resets failure count" {
    var cb = CircuitBreaker.init(.{ .threshold = 3 });
    cb.recordFailurePermit(.ordinary);
    cb.recordFailurePermit(.ordinary);
    cb.recordSuccessPermit(.ordinary);
    try std.testing.expectEqual(@as(u32, 0), cb.failure_count);
    try std.testing.expectEqual(State.closed, cb.state);
}

test "circuit breaker disabled when threshold is 0" {
    var cb = CircuitBreaker.init(.{ .threshold = 0 });
    cb.recordFailurePermit(.ordinary);
    cb.recordFailurePermit(.ordinary);
    cb.recordFailurePermit(.ordinary);
    try std.testing.expectEqual(State.closed, cb.state);
    try std.testing.expect(cb.tryAcquirePermit() != null);
}

test "circuit breaker half-open closes on success" {
    var cb = CircuitBreaker.init(.{ .threshold = 1, .timeout_ms = 0, .half_open_successes = 1 });
    cb.recordFailurePermit(.ordinary);
    try std.testing.expectEqual(State.open, cb.state);

    // With timeout_ms = 0, tryAcquire should move to half-open immediately
    const permit = cb.tryAcquirePermit() orelse return error.TestExpectedHalfOpenPermit;
    try std.testing.expectEqual(State.half_open, cb.state);

    cb.recordSuccessPermit(permit);
    try std.testing.expectEqual(State.closed, cb.state);
}

test "circuit breaker permits only one half-open probe at a time" {
    var cb = CircuitBreaker.init(.{ .threshold = 1, .timeout_ms = 0, .half_open_successes = 1 });
    cb.recordFailurePermit(.ordinary);

    const permit = cb.tryAcquirePermit() orelse return error.TestExpectedHalfOpenPermit;
    try std.testing.expectEqual(State.half_open, cb.state);
    try std.testing.expect(cb.tryAcquirePermit() == null);

    cb.releasePermit(permit);
    const next_permit = cb.tryAcquirePermit() orelse return error.TestExpectedHalfOpenPermit;
    try std.testing.expect(cb.tryAcquirePermit() == null);

    cb.recordSuccessPermit(next_permit);
    try std.testing.expectEqual(State.closed, cb.state);
}

test "circuit breaker half-open re-opens on failure" {
    var cb = CircuitBreaker.init(.{ .threshold = 1, .timeout_ms = 0 });
    cb.recordFailurePermit(.ordinary);
    const permit = cb.tryAcquirePermit() orelse return error.TestExpectedHalfOpenPermit; // transition to half-open
    try std.testing.expectEqual(State.half_open, cb.state);

    cb.recordFailurePermit(permit);
    try std.testing.expectEqual(State.open, cb.state);
}

test "ordinary permit cannot complete or release a later half-open probe" {
    var cb = CircuitBreaker.init(.{ .threshold = 1, .timeout_ms = 0, .half_open_successes = 1 });
    const old_request = cb.tryAcquirePermit() orelse return error.TestExpectedOrdinaryPermit;
    cb.recordFailurePermit(.ordinary);
    const probe = cb.tryAcquirePermit() orelse return error.TestExpectedHalfOpenPermit;
    try std.testing.expectEqual(State.half_open, cb.state);

    cb.recordSuccessPermit(old_request);
    try std.testing.expectEqual(State.half_open, cb.state);
    try std.testing.expect(cb.tryAcquirePermit() == null);

    cb.recordFailurePermit(old_request);
    try std.testing.expectEqual(State.half_open, cb.state);
    try std.testing.expect(cb.tryAcquirePermit() == null);

    cb.releasePermit(old_request);
    try std.testing.expect(cb.tryAcquirePermit() == null);

    cb.recordSuccessPermit(probe);
    try std.testing.expectEqual(State.closed, cb.state);
}

test "half-open permit survives neutral retry without reacquiring" {
    var cb = CircuitBreaker.init(.{ .threshold = 1, .timeout_ms = 0, .half_open_successes = 1 });
    cb.recordFailurePermit(.ordinary);
    const probe = cb.tryAcquirePermit() orelse return error.TestExpectedHalfOpenPermit;
    try std.testing.expect(cb.tryAcquirePermit() == null);

    cb.recordSuccessPermit(probe);
    try std.testing.expectEqual(State.closed, cb.state);
}

test "stateName returns correct labels" {
    var cb = CircuitBreaker.init(.{ .threshold = 1 });
    try std.testing.expectEqualStrings("closed", cb.stateName());
    cb.recordFailurePermit(.ordinary);
    try std.testing.expectEqualStrings("open", cb.stateName());
}

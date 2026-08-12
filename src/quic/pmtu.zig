//! Datagram Packetization Layer PMTU Discovery for pure Zig QUIC (#256-B,
//! RFC 8899, RFC 9000 §14.3/§14.4).
//!
//! #256-A made the outbound datagram size a single authoritative value but
//! left `current_path_max` an *assertion*: an operator raising the knob told
//! the stack a path carried more than the RFC 9000 §14 floor, with nothing
//! measuring whether that was true. This module measures it, and — just as
//! importantly — notices when a size that used to work stops working.
//!
//! One `Controller` belongs to one network path. That is not incidental: the
//! whole point of the state here is "what does *this* path carry", so a
//! migration to a materially different path must start from the guaranteed
//! floor rather than inherit a value discovered somewhere else. `path.Path`
//! owns a controller per slot, so a new or recycled path slot is a new
//! controller by construction.
//!
//! Nothing here does I/O, builds packets, or knows about congestion control.
//! It answers three questions for the send path — what size may I send, is a
//! probe due, and how big — and consumes four facts back: a probe was sent,
//! acknowledged, or lost, and ordinary traffic succeeded or failed.

const std = @import("std");
const datagram = @import("datagram.zig");

/// The only datagram size RFC 9000 §14 guarantees every QUIC path carries, so
/// simultaneously the search floor and the size a black-hole fallback lands on.
pub const base_size: usize = datagram.base_size;

/// RFC 8899 MAX_PROBES: how many times one probe size is retried before the
/// size is treated as unreachable. A probe is a single datagram, so ordinary
/// congestive loss can swallow one or two without meaning anything about MTU.
pub const max_probes: u8 = 3;

/// The search stops once the remaining window is narrower than this. Chasing
/// the last few bytes of a path MTU costs probes and round trips for no
/// meaningful throughput, and an unbounded binary search would never converge
/// on an integer window.
pub const min_step: usize = 16;

/// RFC 8899 PMTU_RAISE_TIMER. Only armed after a black-hole fallback: an
/// ordinary converged search has nothing left to discover, so re-running it
/// would only produce a probe every ten minutes forever.
pub const raise_interval_us: u64 = 600 * std.time.us_per_s;

/// Consecutive pieces of black-hole evidence required before the send size is
/// pulled back to `base_size`. Each piece is already filtered (see
/// `onOrdinaryLoss` and `onProbeTimeout`); this is the count on top of that.
pub const black_hole_threshold: u8 = 3;

pub const State = enum {
    /// Nothing measured and nothing probing. Every controller starts here and
    /// stays until the connection enables it, which the QUIC mapping does once
    /// the handshake is confirmed (RFC 9000 §14.4 — before that the peer's
    /// receive capacity is unknown and the handshake needs its own sizing).
    disabled,
    /// A probe size is chosen or outstanding.
    searching,
    /// The window converged, or a black hole pulled the size back. `plpmtu`
    /// is the answer for this path until the raise timer or a reset.
    search_complete,
};

/// Why the send size changed, for the caller's diagnostics.
pub const SizeChange = enum {
    /// A probe of a larger size was acknowledged.
    raised,
    /// Evidence that the current size no longer traverses the path.
    black_hole,
};

pub const Controller = struct {
    state: State = .disabled,

    /// The size ordinary datagrams may use on this path: `base_size` until a
    /// probe of something larger has actually been acknowledged. Nothing but a
    /// delivered probe raises it, which is the whole difference from #256-A —
    /// the size on the wire is now measured rather than asserted.
    plpmtu: usize = base_size,

    /// Largest datagram this endpoint may emit on this path at all: the
    /// operator's configured send ceiling met with the peer's advertised
    /// receive capacity. A probe never exceeds it, so the search runs strictly
    /// inside `[base_size, ceiling]` and a configured maximum stays a maximum.
    ceiling: usize = base_size,
    /// RFC 8899 §5.3 optimistic search: the first probe on a path goes
    /// straight for the ceiling, so an operator who configured a size their
    /// path really carries gets exactly that in one round trip instead of a
    /// bisection that converges near it. Cleared once that probe is sent;
    /// everything after it bisects.
    optimistic: bool = true,
    /// Smallest size known not to traverse this path. The search never
    /// proposes it or anything larger. `maxInt` means nothing has failed yet.
    smallest_failed: usize = std.math.maxInt(usize),

    /// The size currently being probed for, zero when none is chosen.
    target_size: usize = 0,
    /// Packet number of the outstanding probe, null when none is in flight.
    /// Probe identity is the packet number rather than the size, so a stale
    /// ACK or loss for an earlier probe at the same size cannot resolve the
    /// current one.
    outstanding_pn: ?u64 = null,
    /// Consecutive losses at `target_size`.
    probe_count: u8 = 0,

    /// When the search may restart after a black-hole fallback.
    raise_at_us: ?u64 = null,

    /// Black-hole evidence: ordinary datagrams larger than `base_size`
    /// declared lost, and whether anything at all has been delivered since —
    /// "the big ones vanish while the small ones arrive" is the signature that
    /// separates an MTU black hole from plain congestion.
    oversized_losses: u8 = 0,
    smaller_delivered: bool = false,
    /// Consecutive PTO expirations while sending above the floor with nothing
    /// acknowledged in between. The other half of the signature, for the case
    /// where *everything* in flight is oversized so no small delivery can be
    /// observed.
    stalled_ptos: u8 = 0,

    probes_sent: u32 = 0,
    probes_acked: u32 = 0,
    probes_lost: u32 = 0,
    black_holes: u32 = 0,

    /// The size ordinary datagrams may use on this path.
    pub fn sendSize(self: Controller) usize {
        return self.plpmtu;
    }

    /// Adopt the largest datagram this endpoint may emit on this path
    /// (`datagram.Limits.probeCeiling()`). Cheap and idempotent — the send
    /// path calls it every poll, so a ceiling that only becomes real when the
    /// peer's transport parameters authenticate takes effect immediately.
    pub fn configure(self: *Controller, ceiling: usize) void {
        const next_ceiling = clamp(ceiling);
        if (next_ceiling == self.ceiling) return;
        self.ceiling = next_ceiling;
        // A ceiling below the current size binds immediately: the peer cannot
        // receive more than it advertised, whatever this path carries.
        if (self.plpmtu > next_ceiling) {
            self.plpmtu = next_ceiling;
            self.cancelProbe();
        }
        if (self.state != .disabled) self.reconsider();
    }

    /// Begin discovery on this path. The QUIC mapping calls this once the
    /// handshake is confirmed: the peer's receive capacity is authenticated by
    /// then, and completing the handshake is itself proof the path carries
    /// `base_size` (every Initial-bearing datagram was padded to it), which is
    /// exactly the RFC 8899 BASE-state confirmation this would otherwise owe.
    pub fn enable(self: *Controller, ceiling: usize) void {
        if (self.state != .disabled) return;
        self.configure(ceiling);
        self.state = .searching;
        self.reconsider();
    }

    /// Discard everything measured here. The caller uses this when the slot
    /// starts describing a materially different path; ordinarily a migration
    /// simply lands on a different `Path` whose controller was never used.
    pub fn reset(self: *Controller) void {
        const kept_ceiling = self.ceiling;
        self.* = .{ .ceiling = kept_ceiling };
    }

    /// The size of the probe datagram to send right now, or null when none is
    /// due: not searching, one already outstanding, or the window converged.
    /// Pure — the caller commits with `onProbeSent` only once the probe has
    /// actually passed its congestion and anti-amplification gates and gone
    /// out.
    pub fn nextProbeSize(self: *const Controller) ?usize {
        if (self.state != .searching) return null;
        if (self.outstanding_pn != null) return null;
        if (self.target_size != 0) return self.target_size;
        return self.proposedSize();
    }

    /// A probe of `nextProbeSize()` bytes went out as `packet_number`.
    pub fn onProbeSent(self: *Controller, size: usize, packet_number: u64) void {
        if (self.state != .searching) return;
        self.target_size = size;
        self.outstanding_pn = packet_number;
        self.optimistic = false;
        self.probes_sent +|= 1;
    }

    /// The outstanding probe was acknowledged: the path carries `target_size`,
    /// so it becomes the send size and the search window closes from below.
    /// Returns true when the send size actually moved.
    pub fn onProbeAcked(self: *Controller, packet_number: u64) bool {
        const outstanding = self.outstanding_pn orelse return false;
        if (outstanding != packet_number) return false;
        // A ceiling that dropped while the probe was in flight still binds:
        // the peer cannot receive more than it advertised, whatever arrived.
        const validated = @min(self.target_size, self.ceiling);
        self.outstanding_pn = null;
        self.target_size = 0;
        self.probe_count = 0;
        self.probes_acked +|= 1;
        const raised = validated > self.plpmtu;
        if (raised) self.plpmtu = validated;
        // A larger datagram just traversed the path, so whatever evidence had
        // accumulated against the smaller current size is stale.
        self.clearBlackHoleEvidence();
        self.reconsider();
        return raised;
    }

    /// The outstanding probe was declared lost. One loss is not evidence of an
    /// MTU limit — a probe is a single ack-eliciting datagram and congestion
    /// loses those routinely — so the same size is retried until `max_probes`
    /// attempts have failed, and only then is it recorded as unreachable.
    /// Deliberately does *not* feed black-hole detection: a probe is expected
    /// to be too big, that is what it is for.
    pub fn onProbeLost(self: *Controller, packet_number: u64) void {
        const outstanding = self.outstanding_pn orelse return;
        if (outstanding != packet_number) return;
        self.outstanding_pn = null;
        self.probes_lost +|= 1;
        self.probe_count +|= 1;
        if (self.probe_count < max_probes) return;
        self.noteFailed(self.target_size);
        self.target_size = 0;
        self.probe_count = 0;
        self.reconsider();
    }

    /// An ordinary (non-probe) datagram of `size` was acknowledged. A delivery
    /// larger than the floor proves the path still carries the current size
    /// and clears any accumulated black-hole evidence; a smaller one is the
    /// "and the small ones arrive" half of the black-hole signature.
    pub fn onOrdinaryAck(self: *Controller, size: usize) void {
        self.stalled_ptos = 0;
        if (size > base_size) {
            self.clearBlackHoleEvidence();
            return;
        }
        if (self.oversized_losses > 0) self.smaller_delivered = true;
    }

    /// An ordinary (non-probe) datagram of `size` was declared lost. Only a
    /// loss above the guaranteed floor is evidence about MTU at all — losing a
    /// 1200-byte datagram says nothing a fallback could fix.
    pub fn onOrdinaryLoss(self: *Controller, size: usize, now_us: u64) void {
        if (size <= base_size) return;
        self.oversized_losses +|= 1;
        self.evaluateBlackHole(now_us);
    }

    /// A PTO expired. Consecutive expirations while sending above the floor,
    /// with nothing acknowledged in between, is the black-hole case where no
    /// small delivery can ever be observed because every datagram in flight is
    /// oversized. Ignored entirely at the floor: 1200 bytes is guaranteed, so
    /// a stall there is congestion or an outage, and no fallback exists.
    pub fn onProbeTimeout(self: *Controller, now_us: u64) void {
        if (self.plpmtu <= base_size) return;
        self.stalled_ptos +|= 1;
        self.evaluateBlackHole(now_us);
    }

    /// The next moment `onTimeout` has something to do, or null.
    pub fn deadlineUs(self: Controller) ?u64 {
        return self.raise_at_us;
    }

    /// Re-open the search after a black-hole fallback has held for
    /// `raise_interval_us`. The window stays bounded below the size that black
    /// holed (`smallest_failed` survives), so this explores what the path
    /// carries *now* without walking back into the size that broke it.
    pub fn onTimeout(self: *Controller, now_us: u64) void {
        const deadline = self.raise_at_us orelse return;
        if (now_us < deadline) return;
        self.raise_at_us = null;
        if (self.state == .disabled) return;
        self.state = .searching;
        self.reconsider();
    }

    // -- internals -------------------------------------------------------

    fn clearBlackHoleEvidence(self: *Controller) void {
        self.oversized_losses = 0;
        self.smaller_delivered = false;
        self.stalled_ptos = 0;
    }

    fn evaluateBlackHole(self: *Controller, now_us: u64) void {
        const by_loss = self.oversized_losses >= black_hole_threshold and self.smaller_delivered;
        const by_stall = self.stalled_ptos >= black_hole_threshold;
        if (!by_loss and !by_stall) return;
        self.enterBlackHole(now_us);
    }

    /// Pull the send size back to the one size RFC 9000 §14 guarantees, and
    /// remember that the size we were using does not traverse this path. A
    /// false positive costs throughput until the raise timer; not falling back
    /// costs the connection, because Tardigrade's own retransmissions would
    /// keep re-sending the same oversized datagram until the idle timeout.
    fn enterBlackHole(self: *Controller, now_us: u64) void {
        const failed = self.plpmtu;
        self.clearBlackHoleEvidence();
        self.cancelProbe();
        if (failed > base_size) self.noteFailed(failed);
        self.plpmtu = base_size;
        self.black_holes +|= 1;
        self.state = .search_complete;
        self.raise_at_us = now_us +| raise_interval_us;
    }

    fn cancelProbe(self: *Controller) void {
        self.outstanding_pn = null;
        self.target_size = 0;
        self.probe_count = 0;
    }

    fn noteFailed(self: *Controller, size: usize) void {
        if (size == 0) return;
        self.smallest_failed = @min(self.smallest_failed, size);
    }

    /// The upper end of the search window: the endpoint/peer ceiling, held
    /// below anything already known to fail.
    fn searchHigh(self: Controller) usize {
        const below_failure = self.smallest_failed -| 1;
        return @max(self.plpmtu, @min(self.ceiling, below_failure));
    }

    /// The next size worth probing. The first probe on a path reaches straight
    /// for the ceiling (RFC 8899 §5.3), so a correctly configured path lands on
    /// exactly the configured size in one round trip; after that the window is
    /// bisected, biased upward so a window of exactly `min_step` still proposes
    /// the top of the range rather than stalling one byte below it.
    fn proposedSize(self: Controller) ?usize {
        const high = self.searchHigh();
        const low = self.plpmtu;
        if (high -| low < min_step) return null;
        if (self.optimistic) return high;
        return low + (high - low + 1) / 2;
    }

    /// Re-derive whether there is anything left to probe for. The one place
    /// the searching/complete transition is decided, so every caller that
    /// changes a bound, validates a size, or rules one out agrees.
    fn reconsider(self: *Controller) void {
        if (self.state == .disabled) return;
        if (self.outstanding_pn != null) return;
        if (self.proposedSize() != null) {
            self.state = .searching;
            return;
        }
        self.target_size = 0;
        self.state = .search_complete;
    }
};

/// Clamp a configured or advertised bound into the range this stack can
/// represent. Mirrors `datagram.zig`: below the RFC floor is raised rather
/// than honoured, since no QUIC endpoint may send less and Initial padding
/// needs it regardless.
fn clamp(value: usize) usize {
    return std.math.clamp(value, base_size, datagram.max_size);
}

const testing = std.testing;

fn enabled(ceiling: usize) Controller {
    var controller = Controller{};
    controller.enable(ceiling);
    return controller;
}

test "pmtu: a fresh controller sits at the one size RFC 9000 guarantees" {
    const controller = Controller{};
    try testing.expectEqual(State.disabled, controller.state);
    try testing.expectEqual(base_size, controller.sendSize());
    try testing.expectEqual(@as(?usize, null), controller.nextProbeSize());
}

test "pmtu: nothing probes before the connection enables discovery" {
    var controller = Controller{};
    controller.configure(datagram.max_size);
    try testing.expectEqual(@as(?usize, null), controller.nextProbeSize());
    controller.onProbeTimeout(1_000);
    try testing.expectEqual(@as(?u64, null), controller.deadlineUs());
}

test "pmtu: a ceiling at the floor leaves nothing to discover" {
    // The default configuration, and also the state before the peer's
    // transport parameters authenticate: `probeCeiling()` collapses to the
    // floor, so there is nothing to reach for and no probe is ever emitted.
    var controller = enabled(base_size);
    try testing.expectEqual(State.search_complete, controller.state);
    try testing.expectEqual(@as(?usize, null), controller.nextProbeSize());
    try testing.expectEqual(base_size, controller.sendSize());

    // Raising the ceiling opens the search.
    controller.configure(datagram.max_size);
    try testing.expectEqual(State.searching, controller.state);
    try testing.expect(controller.nextProbeSize() != null);
}

test "pmtu: the first probe reaches straight for the configured ceiling" {
    var controller = enabled(1452);
    // RFC 8899 §5.3 optimistic search: an operator whose path really carries
    // the configured size gets exactly it, not a bisection that lands near it.
    try testing.expectEqual(@as(usize, 1452), controller.nextProbeSize().?);
    // Idempotent while nothing has happened: the same probe is still due.
    try testing.expectEqual(@as(usize, 1452), controller.nextProbeSize().?);

    controller.onProbeSent(1452, 1);
    try testing.expect(controller.onProbeAcked(1));
    try testing.expectEqual(@as(usize, 1452), controller.sendSize());
    // Nothing above the ceiling is ever probed, so the search is done.
    try testing.expectEqual(State.search_complete, controller.state);
    try testing.expectEqual(@as(?usize, null), controller.nextProbeSize());
}

test "pmtu: the send size does not move while a probe is outstanding" {
    var controller = enabled(2048);
    const first = controller.nextProbeSize().?;
    controller.onProbeSent(first, 7);
    try testing.expectEqual(base_size, controller.sendSize());
    try testing.expectEqual(@as(?usize, null), controller.nextProbeSize());

    try testing.expect(controller.onProbeAcked(7));
    try testing.expectEqual(first, controller.sendSize());
}

test "pmtu: an acknowledgement for a different packet resolves nothing" {
    var controller = enabled(2048);
    const size = controller.nextProbeSize().?;
    controller.onProbeSent(size, 7);
    try testing.expect(!controller.onProbeAcked(8));
    try testing.expectEqual(base_size, controller.sendSize());
    controller.onProbeLost(8);
    try testing.expectEqual(@as(u8, 0), controller.probe_count);
    // The real probe is still outstanding and still resolvable.
    try testing.expect(controller.onProbeAcked(7));
}

test "pmtu: a lost probe is retried before its size is ruled out" {
    var controller = enabled(2048);
    const size = controller.nextProbeSize().?;

    var attempt: u8 = 0;
    while (attempt < max_probes - 1) : (attempt += 1) {
        controller.onProbeSent(size, attempt);
        controller.onProbeLost(attempt);
        // Same size, because one loss is congestion until proven otherwise.
        try testing.expectEqual(size, controller.nextProbeSize().?);
    }

    controller.onProbeSent(size, max_probes);
    controller.onProbeLost(max_probes);
    try testing.expectEqual(size, controller.smallest_failed);
    // The search continues below the size that failed, never at or above it.
    const next = controller.nextProbeSize().?;
    try testing.expect(next < size);
    try testing.expect(next > base_size);
    // A failed probe is not a black hole: the send size never moved.
    try testing.expectEqual(@as(u32, 0), controller.black_holes);
    try testing.expectEqual(base_size, controller.sendSize());
}

test "pmtu: the search converges and stops" {
    var controller = enabled(2048);
    var pn: u64 = 0;
    // Everything at or below 1452 traverses; anything above is dropped.
    while (controller.nextProbeSize()) |size| {
        controller.onProbeSent(size, pn);
        if (size <= 1452) {
            _ = controller.onProbeAcked(pn);
        } else {
            controller.onProbeLost(pn);
        }
        pn += 1;
        try testing.expect(pn < 64); // termination, not just convergence
    }
    try testing.expectEqual(State.search_complete, controller.state);
    const found = controller.sendSize();
    try testing.expect(found <= 1452);
    try testing.expect(found > 1452 - min_step);
    // Converged searches do not re-arm: there is nothing left to discover.
    try testing.expectEqual(@as(?u64, null), controller.deadlineUs());
}

test "pmtu: a lowered ceiling binds the discovered size immediately" {
    var controller = enabled(2048);
    const size = controller.nextProbeSize().?;
    controller.onProbeSent(size, 1);
    try testing.expect(controller.onProbeAcked(1));
    try testing.expectEqual(size, controller.sendSize());

    // Not negotiable: the ceiling caps the discovered value rather than being
    // averaged with it.
    controller.configure(1300);
    try testing.expectEqual(@as(usize, 1300), controller.sendSize());
    try testing.expectEqual(@as(?usize, null), controller.nextProbeSize());
}

test "pmtu: ordinary congestion loss alone is not a black hole" {
    var controller = enabled(2048);
    controller.onProbeSent(1452, 1);
    _ = controller.onProbeAcked(1);

    var i: u8 = 0;
    while (i < 3 * black_hole_threshold) : (i += 1) {
        // Big datagrams are disappearing, but so is everything else: nothing
        // is arriving to show the path still passes small packets.
        controller.onOrdinaryLoss(1452, 1_000);
    }
    try testing.expectEqual(@as(u32, 0), controller.black_holes);
    try testing.expectEqual(@as(usize, 1452), controller.sendSize());
}

test "pmtu: oversized loss while smaller traffic arrives falls back to the floor" {
    var controller = enabled(2048);
    controller.onProbeSent(1452, 1);
    _ = controller.onProbeAcked(1);

    var i: u8 = 0;
    while (i < black_hole_threshold) : (i += 1) {
        controller.onOrdinaryLoss(1452, 1_000);
        controller.onOrdinaryAck(base_size);
    }
    try testing.expectEqual(@as(u32, 1), controller.black_holes);
    try testing.expectEqual(base_size, controller.sendSize());
    try testing.expectEqual(@as(usize, 1452), controller.smallest_failed);
    try testing.expectEqual(@as(?u64, 1_000 + raise_interval_us), controller.deadlineUs());
}

test "pmtu: a delivery at the current size clears accumulated evidence" {
    var controller = enabled(2048);
    controller.onProbeSent(1452, 1);
    _ = controller.onProbeAcked(1);

    controller.onOrdinaryLoss(1452, 1_000);
    controller.onOrdinaryAck(base_size);
    controller.onOrdinaryLoss(1452, 1_000);
    // A big datagram arrived: the path carries this size after all.
    controller.onOrdinaryAck(1452);
    controller.onOrdinaryLoss(1452, 1_000);
    controller.onOrdinaryAck(base_size);
    try testing.expectEqual(@as(u32, 0), controller.black_holes);
    try testing.expectEqual(@as(usize, 1452), controller.sendSize());
}

test "pmtu: repeated PTO above the floor falls back when nothing arrives at all" {
    // The case `onOrdinaryLoss` cannot see: every datagram in flight is
    // oversized, so there is no small delivery to corroborate with.
    var controller = enabled(2048);
    controller.onProbeSent(1452, 1);
    _ = controller.onProbeAcked(1);

    var i: u8 = 0;
    while (i < black_hole_threshold) : (i += 1) controller.onProbeTimeout(500);
    try testing.expectEqual(base_size, controller.sendSize());
    try testing.expectEqual(@as(u32, 1), controller.black_holes);
}

test "pmtu: PTO at the guaranteed floor never triggers a fallback" {
    var controller = enabled(2048);
    var i: u8 = 0;
    while (i < 10 * black_hole_threshold) : (i += 1) controller.onProbeTimeout(500);
    try testing.expectEqual(@as(u32, 0), controller.black_holes);
    try testing.expectEqual(base_size, controller.sendSize());
}

test "pmtu: an acknowledgement interrupts a run of stalled PTOs" {
    var controller = enabled(2048);
    controller.onProbeSent(1452, 1);
    _ = controller.onProbeAcked(1);

    controller.onProbeTimeout(500);
    controller.onProbeTimeout(500);
    controller.onOrdinaryAck(base_size);
    controller.onProbeTimeout(500);
    controller.onProbeTimeout(500);
    try testing.expectEqual(@as(u32, 0), controller.black_holes);
}

test "pmtu: the raise timer re-searches below the size that black holed" {
    var controller = enabled(2048);
    controller.onProbeSent(1452, 1);
    _ = controller.onProbeAcked(1);
    var i: u8 = 0;
    while (i < black_hole_threshold) : (i += 1) controller.onProbeTimeout(500);
    const deadline = controller.deadlineUs().?;

    // Early wakeups change nothing, and the deadline stays armed.
    controller.onTimeout(deadline - 1);
    try testing.expectEqual(State.search_complete, controller.state);
    try testing.expectEqual(@as(?u64, deadline), controller.deadlineUs());

    controller.onTimeout(deadline);
    try testing.expectEqual(State.searching, controller.state);
    // Disarmed, so a caller folding this into a timer wheel cannot spin on it.
    try testing.expectEqual(@as(?u64, null), controller.deadlineUs());
    const size = controller.nextProbeSize().?;
    try testing.expect(size > base_size);
    try testing.expect(size < 1452);
}

test "pmtu: a fallback with no room left below it simply stays at the floor" {
    // Nothing between 1200 and the failed size is worth probing, so the raise
    // timer resolves to "still nothing to do" instead of proposing 1200 itself.
    var controller = enabled(base_size + min_step);
    controller.onProbeSent(controller.nextProbeSize().?, 1);
    try testing.expect(controller.onProbeAcked(1));
    var i: u8 = 0;
    while (i < black_hole_threshold) : (i += 1) controller.onProbeTimeout(500);
    try testing.expectEqual(base_size, controller.sendSize());

    controller.onTimeout(controller.deadlineUs().?);
    try testing.expectEqual(@as(?usize, null), controller.nextProbeSize());
    try testing.expectEqual(State.search_complete, controller.state);
}

test "pmtu: a reset returns the path to the guaranteed floor" {
    var controller = enabled(2048);
    const size = controller.nextProbeSize().?;
    controller.onProbeSent(size, 3);
    try testing.expect(controller.onProbeAcked(3));
    try testing.expect(controller.sendSize() > base_size);

    controller.reset();
    // A materially different path inherits no measurement, not even a
    // favourable one — that is the whole reason this state is per path.
    try testing.expectEqual(State.disabled, controller.state);
    try testing.expectEqual(base_size, controller.sendSize());
    try testing.expectEqual(@as(?usize, null), controller.nextProbeSize());
    try testing.expectEqual(@as(usize, std.math.maxInt(usize)), controller.smallest_failed);
}

test "pmtu: bounds outside the representable range are clamped, not trusted" {
    var controller = enabled(std.math.maxInt(usize));
    try testing.expectEqual(base_size, controller.sendSize());
    try testing.expectEqual(datagram.max_size, controller.ceiling);
    try testing.expectEqual(datagram.max_size, controller.nextProbeSize().?);

    controller.configure(0);
    try testing.expectEqual(base_size, controller.ceiling);
    try testing.expectEqual(@as(?usize, null), controller.nextProbeSize());
}

test {
    std.testing.refAllDecls(@This());
}

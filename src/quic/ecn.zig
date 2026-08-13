//! Explicit Congestion Notification for pure Zig QUIC (#256-E, RFC 9000 §13.4,
//! RFC 9002 §7).
//!
//! The wire pieces already existed before this module: `udp.Ecn` names the four
//! IP codepoints and `frame.zig` parses and encodes ACK_ECN. What was missing
//! is the part that decides anything — whether marking outbound packets is
//! working on *this* path, and whether the counters a peer reports back may be
//! believed.
//!
//! Both halves live here:
//!
//!  * `Counts` is the receive side: what arrived, per packet number space, so
//!    an ACK_ECN can report it (RFC 9000 §13.4.1). Pure bookkeeping.
//!  * `Controller` is the send side: it marks packets ECT(0), then checks the
//!    peer's feedback against what was actually sent, and turns marking off for
//!    the path the moment the feedback stops adding up.
//!
//! ECN is an optimisation that a surprising amount of deployed network gear
//! quietly breaks — by clearing the codepoint, by rewriting it, or by dropping
//! marked packets outright. So the design rule throughout is that **every
//! failure ends in plain non-ECN operation**, never in a connection error. A
//! false negative costs a congestion signal the stack would not have had
//! anyway; trusting bad feedback would cost correctness, because a CE count is
//! a congestion input and RFC 9000 §13.4.2 is explicit that it is attacker- and
//! middlebox-reachable.
//!
//! One `Controller` belongs to one network path, for the same reason
//! `pmtu.Controller` does: "does ECN survive here" is a property of the route,
//! and a migration must re-establish it rather than inherit an answer measured
//! somewhere else.
//!
//! Nothing here does I/O or touches sockets. The platform half — reading the IP
//! header's ECN field off a received datagram and asking the kernel to set it
//! on a sent one — belongs to whoever owns the socket, and it reports its
//! capability in by simply never calling `enable`.

const std = @import("std");
const udp = @import("udp.zig");

/// The codepoint this endpoint marks outbound packets with while ECN is in
/// use. ECT(0) rather than ECT(1): ECT(1) belongs to L4S (RFC 9331), whose
/// congestion response is not the RFC 9002 one implemented here, and RFC 9000
/// §13.4.2.1 lets an endpoint treat *any* reported ECT(1) as proof that
/// something on the path is rewriting codepoints.
pub const send_codepoint: udp.Ecn = .ect0;

/// How long the testing phase waits for the peer to confirm a marked packet
/// arrived marked, expressed in PTOs (RFC 9000 §13.4.2 uses 3×PTO for the
/// equivalent decision). The caller supplies the actual duration, since PTO
/// lives in recovery; this is the multiplier it should apply.
pub const testing_pto_multiplier: u64 = 3;

pub const State = enum {
    /// Marking is off: either nothing enabled it (the platform cannot set or
    /// read the codepoint) or validation failed on this path.
    disabled,
    /// Packets are being marked ECT(0), and no peer feedback has yet proven
    /// the marks survive the path. Congestion signals are *not* acted on in
    /// this state — an unvalidated CE report is exactly the input RFC 9000
    /// §13.4.2 warns is forgeable.
    testing,
    /// The peer has reported receiving marked packets consistent with what was
    /// sent. CE reports are now believed and drive congestion response.
    capable,
};

/// Why marking stopped on a path. Every one of these is an ordinary,
/// non-fatal outcome — the path keeps carrying QUIC, without ECN.
pub const FailureReason = enum {
    /// The peer acknowledged packets that went out marked, in an ACK frame
    /// carrying no ECN counts at all. Either the marks were stripped before
    /// the peer saw them or the peer is not reporting; both mean the feedback
    /// loop does not exist (RFC 9000 §13.4.2.1).
    missing_counts,
    /// A reported counter went backwards. Counters are monotonic by
    /// construction, so this is a broken or hostile peer.
    counts_regressed,
    /// The peer reported ECT(1), which this endpoint never sends. Something on
    /// the path is rewriting the codepoint.
    unsent_codepoint,
    /// The peer reported more marked arrivals than this endpoint has ever
    /// marked. The counts are not describing our traffic.
    counts_exceed_sent,
    /// Packets known to have gone out marked were acknowledged, and the
    /// ECT(0)+CE counts did not rise to match (RFC 9000 §13.4.2.1): the marks
    /// are being cleared in flight.
    insufficient_increase,
    /// The testing window closed with no usable feedback at all.
    testing_timeout,
};

/// Received ECN codepoints for one packet number space (RFC 9000 §13.4.1).
///
/// Per *space*, not per path, because that is the scope the peer's ACK frames
/// are in: an ACK acknowledges packet numbers in one space and reports the
/// counts for that space. Counting per path would produce numbers that no ACK
/// frame could correctly carry.
pub const Counts = struct {
    ect0: u64 = 0,
    ect1: u64 = 0,
    ce: u64 = 0,

    /// Count one *successfully authenticated* packet's codepoint. Called only
    /// after AEAD open succeeds, so an off-path attacker cannot inflate the
    /// counters this endpoint reports back — RFC 9000 §13.4.1 counts packets,
    /// not datagrams, and an unauthenticated packet is not one.
    pub fn record(self: *Counts, mark: udp.Ecn) void {
        switch (mark) {
            .ect0 => self.ect0 +|= 1,
            .ect1 => self.ect1 +|= 1,
            .ce => self.ce +|= 1,
            // `.not_ect` is an unmarked packet and `.unavailable` means the
            // receive path could not tell us — neither is a counter.
            .not_ect, .unavailable => {},
        }
    }

    /// Whether an ACK for this space must be an ACK_ECN. RFC 9000 §13.4.1
    /// requires the counts once any marked packet has been received, and there
    /// is nothing to say before that.
    pub fn any(self: Counts) bool {
        return self.ect0 != 0 or self.ect1 != 0 or self.ce != 0;
    }

    /// Discard the counters for a space whose keys were dropped.
    pub fn reset(self: *Counts) void {
        self.* = .{};
    }
};

/// The ECN counters carried by one received ACK_ECN frame.
pub const Feedback = struct {
    ect0: u64,
    ect1: u64,
    ce: u64,
};

/// What one ACK meant for ECN on a path.
pub const Outcome = struct {
    /// Newly reported CE marks. Non-zero only in `.capable`: an unvalidated
    /// report must never reach congestion control, or an attacker who can
    /// forge feedback could shrink the window at will.
    ce_increase: u64 = 0,
    /// This ACK is what promoted the path from `.testing` to `.capable`.
    validated: bool = false,
    /// This ACK turned marking off, for this reason.
    failed: ?FailureReason = null,
};

pub const Controller = struct {
    state: State = .disabled,
    /// Why marking is off, when it was ever on. Kept after failure so status
    /// and benchmark output can say which way ECN broke rather than only that
    /// it is not running.
    failure: ?FailureReason = null,

    /// Packets sent with `send_codepoint` on this path since marking began.
    marked_sent: u64 = 0,
    /// The peer's counters as they stood when this path started marking, and
    /// then the latest successfully validated report.
    ///
    /// The baseline is taken at `enable`, **before a single mark goes out**,
    /// which is what RFC 9000 Appendix A.4 does when it snapshots the packet
    /// number space's ECN counts as testing starts. Taking it from the first
    /// ACK_ECN to arrive instead would silently write off every mark already
    /// in flight: ten marked packets outstanding and a first report
    /// acknowledging two would leave the other eight unaccounted, and the next
    /// report that legitimately counted them would look like an over-claim.
    seen: Feedback = .{ .ect0 = 0, .ect1 = 0, .ce = 0 },
    /// Marked arrivals the peer has reported since the baseline, as ECT(0)+CE.
    /// Compared against what was actually marked, so a peer cannot claim more
    /// marked traffic than it was sent.
    reported: u64 = 0,

    /// When the testing phase gives up, or null when not testing.
    testing_deadline_us: ?u64 = null,

    /// Total CE marks believed (i.e. reported while `.capable`). The count a
    /// benchmark or status page should show: unvalidated reports are excluded
    /// because they never reached congestion control either.
    ce_observed: u64 = 0,

    /// The codepoint to put on the next outbound datagram for this path.
    /// `.not_ect` — an explicit "no ECT" rather than `.unavailable` — is what
    /// the send path asks the kernel for when marking is off, so a socket that
    /// carries a stale marking cannot leak one.
    pub fn sendCodepoint(self: Controller) udp.Ecn {
        return switch (self.state) {
            .disabled => .not_ect,
            .testing, .capable => send_codepoint,
        };
    }

    pub fn marking(self: Controller) bool {
        return self.state != .disabled;
    }

    /// Start marking on this path, taking `baseline` as the peer's counters as
    /// of right now (RFC 9000 Appendix A.4). Idempotent, so the send path can
    /// call it every poll; a path that already failed validation stays failed
    /// until `reset` (a new path incarnation) rather than re-enabling into the
    /// same broken route every poll.
    ///
    /// The testing window is *not* armed here. It is armed by the first marked
    /// packet actually leaving (`onMarkedSent`), because a connection that is
    /// simply idle has not tested anything: arming at enable would let three
    /// PTOs of silence record a permanent `testing_timeout` on a path that was
    /// never given a chance.
    pub fn enable(self: *Controller, baseline: Feedback) void {
        if (self.state != .disabled or self.failure != null) return;
        self.state = .testing;
        self.seen = baseline;
    }

    /// Stop marking on this path. Used both by validation failures here and by
    /// a caller that learns the platform cannot mark after all.
    pub fn disable(self: *Controller, reason: FailureReason) void {
        self.state = .disabled;
        self.failure = reason;
        self.testing_deadline_us = null;
    }

    /// One packet went out carrying `send_codepoint` on this path.
    ///
    /// The first one arms the testing window: that is the moment something is
    /// actually under test, and dating the deadline from `enable` instead
    /// would time out an idle connection that had not yet sent a thing.
    pub fn onMarkedSent(self: *Controller, now_us: u64, testing_window_us: u64) void {
        if (self.state == .testing and self.marked_sent == 0) {
            self.testing_deadline_us = now_us +| testing_window_us;
        }
        self.marked_sent +|= 1;
    }

    /// Apply one ACK's worth of peer feedback.
    ///
    /// `newly_acked_marked` is how many packets *this ACK newly acknowledged*
    /// that went out marked **on this path** — the quantity RFC 9000 §13.4.2.1
    /// requires the reported counts to account for. `feedback` is null when the
    /// ACK frame was a plain ACK rather than an ACK_ECN.
    ///
    /// The caller must only call this for an ACK that advanced the largest
    /// acknowledged packet number in the space. RFC 9000 §13.4.2.1 requires
    /// that an ACK which does not is left alone entirely: the peer's counters
    /// are cumulative, so a delayed ACK legitimately carries *older* ones, and
    /// judging those against what has since been reported would read ordinary
    /// reordering as hostile feedback. `Connection.processAck` owns that gate.
    ///
    /// Every rejection path here ends in `disable`, never in an error: the
    /// worst case for a false positive is a path that runs without ECN, which
    /// is where the vast majority of the internet already is.
    pub fn onAck(
        self: *Controller,
        newly_acked_marked: u64,
        feedback: ?Feedback,
    ) Outcome {
        if (self.state == .disabled) return .{};

        const counts = feedback orelse {
            // A plain ACK that acknowledges nothing we marked says nothing
            // either way — ACKs for unmarked traffic are ordinary. One that
            // acknowledges marked packets without counts is the feedback loop
            // failing (RFC 9000 §13.4.2.1).
            if (newly_acked_marked == 0) return .{};
            return self.fail(.missing_counts);
        };

        // Nothing this endpoint ever sends is ECT(1), so a non-zero report is
        // impossible for this connection whatever the baseline was. Checked as
        // an absolute rather than as growth: a baseline adopted from a report
        // that already contained ECT(1) would otherwise grandfather it in and
        // let validation succeed on counters known to be rewritten.
        if (counts.ect1 != 0) return self.fail(.unsent_codepoint);

        const baseline = self.seen;
        if (counts.ect0 < baseline.ect0 or counts.ce < baseline.ce) {
            return self.fail(.counts_regressed);
        }

        const ect0_increase = counts.ect0 - baseline.ect0;
        const ce_increase = counts.ce - baseline.ce;
        const marked_increase = ect0_increase +| ce_increase;

        // A peer cannot have received more marked packets than were marked.
        // Checked cumulatively against every mark this path has placed — the
        // baseline was taken before the first of them — so it holds across
        // reports that arrive in batches rather than only within one ACK.
        const reported = self.reported +| marked_increase;
        if (reported > self.marked_sent) return self.fail(.counts_exceed_sent);

        // RFC 9000 §13.4.2.1: packets that went out marked and are now
        // acknowledged must show up in the counts. CE counts too — a marked
        // packet that met congestion arrives as CE, not ECT(0).
        if (newly_acked_marked > 0 and marked_increase < newly_acked_marked) {
            return self.fail(.insufficient_increase);
        }

        self.seen = counts;
        self.reported = reported;

        var outcome = Outcome{};
        // Promotion needs evidence attributable to *this* path: an ACK that
        // newly acknowledged a packet this path marked, and counter growth to
        // go with it. Growth alone is not enough — the peer's counters are
        // per packet number space and span every path it has been reached on,
        // so an ACK covering another path's marks would otherwise validate a
        // route that is quietly stripping every codepoint. The connection's
        // epoch barrier is what makes this sufficient rather than merely
        // necessary; see `Connection.syncPathEcn`.
        if (self.state == .testing and newly_acked_marked > 0 and marked_increase > 0) {
            self.state = .capable;
            self.testing_deadline_us = null;
            outcome.validated = true;
        }
        // Congestion response only once the path is validated (RFC 9002 §7.1
        // is conditioned on exactly that). The promoting ACK counts: its marks
        // are the evidence that validated the path, so they are as trustworthy
        // as the next one's.
        if (self.state == .capable and ce_increase > 0) {
            self.ce_observed +|= ce_increase;
            outcome.ce_increase = ce_increase;
        }
        return outcome;
    }

    /// The moment `onTimeout` has something to do, or null.
    pub fn deadlineUs(self: Controller) ?u64 {
        return self.testing_deadline_us;
    }

    /// Close the testing window if it has expired. Returns the failure when
    /// this call is what ended marking.
    pub fn onTimeout(self: *Controller, now_us: u64) ?FailureReason {
        const deadline = self.testing_deadline_us orelse return null;
        if (now_us < deadline) return null;
        if (self.state != .testing) {
            self.testing_deadline_us = null;
            return null;
        }
        _ = self.fail(.testing_timeout);
        return .testing_timeout;
    }

    /// Forget everything measured here, including a previous failure. The
    /// caller uses this when the slot starts describing a genuinely different
    /// path, which is the one situation where a path that could not carry ECN
    /// deserves to be tried again.
    pub fn reset(self: *Controller) void {
        self.* = .{};
    }

    fn fail(self: *Controller, reason: FailureReason) Outcome {
        self.disable(reason);
        return .{ .failed = reason };
    }
};

// ---------------------------------------------------------------------------
// Tests. Deterministic and platform-neutral by construction — nothing here
// touches a socket, so the state machine is provable on every target even
// where the OS half is unavailable.
// ---------------------------------------------------------------------------

const testing = std.testing;

const no_counts = Feedback{ .ect0 = 0, .ect1 = 0, .ce = 0 };

/// A path whose markings demonstrably survive: enabled from a clean baseline,
/// two marks sent, both acknowledged and both counted.
fn validatedController() Controller {
    var controller = Controller{};
    controller.enable(no_counts);
    controller.onMarkedSent(0, 300_000);
    controller.onMarkedSent(0, 300_000);
    _ = controller.onAck(2, .{ .ect0 = 2, .ect1 = 0, .ce = 0 });
    return controller;
}

test "ecn: received codepoints accumulate per space and drive ACK_ECN" {
    var counts = Counts{};
    try testing.expect(!counts.any());
    counts.record(.not_ect);
    counts.record(.unavailable);
    // Neither an unmarked packet nor a receive path that cannot report is a
    // counter, so an ACK for this space is still a plain ACK.
    try testing.expect(!counts.any());

    counts.record(.ect0);
    counts.record(.ect0);
    counts.record(.ce);
    counts.record(.ect1);
    try testing.expect(counts.any());
    try testing.expectEqual(@as(u64, 2), counts.ect0);
    try testing.expectEqual(@as(u64, 1), counts.ect1);
    try testing.expectEqual(@as(u64, 1), counts.ce);

    counts.reset();
    try testing.expect(!counts.any());
}

test "ecn: marking is off until enabled and never marks after failure" {
    var controller = Controller{};
    try testing.expectEqual(udp.Ecn.not_ect, controller.sendCodepoint());
    try testing.expect(!controller.marking());

    controller.enable(no_counts);
    try testing.expectEqual(udp.Ecn.ect0, controller.sendCodepoint());
    try testing.expectEqual(State.testing, controller.state);

    controller.disable(.missing_counts);
    try testing.expectEqual(udp.Ecn.not_ect, controller.sendCodepoint());
    // Re-enabling into a path already known to break ECN would re-run the
    // whole testing window on every poll and mark traffic that is being
    // dropped or stripped. Only a new path incarnation gets another try.
    controller.enable(no_counts);
    try testing.expectEqual(State.disabled, controller.state);
    controller.reset();
    controller.enable(no_counts);
    try testing.expectEqual(State.testing, controller.state);
}

test "ecn: the baseline is taken before the first mark, not from the first report" {
    // The peer's counters already carry traffic from another path — they are
    // per packet number space and survive migration — so the baseline is that
    // history, snapshotted as this path starts marking.
    var controller = Controller{};
    controller.enable(.{ .ect0 = 900, .ect1 = 0, .ce = 3 });
    try testing.expectEqual(@as(u64, 900), controller.seen.ect0);

    controller.onMarkedSent(0, 300_000);
    const first = controller.onAck(1, .{ .ect0 = 901, .ect1 = 0, .ce = 3 });
    // Growth from that origin validates immediately: there is no wasted round
    // trip spent adopting a baseline that was already known.
    try testing.expect(first.validated);
    try testing.expectEqual(State.capable, controller.state);
}

test "ecn: marks outstanding before the first report are still accounted for" {
    // The regression behind taking the baseline at `enable`. Ten marked
    // packets go out; the first ACK_ECN acknowledges only two of them.
    var controller = Controller{};
    controller.enable(no_counts);
    var sent: usize = 0;
    while (sent < 10) : (sent += 1) controller.onMarkedSent(0, 300_000);

    const first = controller.onAck(2, .{ .ect0 = 2, .ect1 = 0, .ce = 0 });
    try testing.expect(first.validated);
    try testing.expectEqual(@as(?FailureReason, null), first.failed);

    // The remaining eight are acknowledged in later batches, with no further
    // sends. A baseline adopted from that first report would have written the
    // eight off as never sent, and this honest growth would read as an
    // over-claim — disabling ECN on a path that is working perfectly.
    const second = controller.onAck(3, .{ .ect0 = 5, .ect1 = 0, .ce = 0 });
    try testing.expectEqual(@as(?FailureReason, null), second.failed);
    const third = controller.onAck(5, .{ .ect0 = 10, .ect1 = 0, .ce = 0 });
    try testing.expectEqual(@as(?FailureReason, null), third.failed);
    try testing.expectEqual(State.capable, controller.state);
    try testing.expectEqual(@as(u64, 10), controller.reported);
}

test "ecn: a first report containing ECT(1) is rejected, not adopted" {
    // This endpoint never sends ECT(1) at all, so the check is on the absolute
    // value rather than on growth. Adopting a non-zero ECT(1) as the baseline
    // would grandfather in counters already known to be rewritten, and every
    // later report could then validate the path as long as ECT(1) held still.
    var controller = Controller{};
    controller.enable(no_counts);
    controller.onMarkedSent(0, 300_000);
    const outcome = controller.onAck(1, .{ .ect0 = 1, .ect1 = 4, .ce = 0 });
    try testing.expectEqual(@as(?FailureReason, .unsent_codepoint), outcome.failed);
    try testing.expectEqual(State.disabled, controller.state);
}

test "ecn: an ACK without counts for marked packets disables ECN" {
    var controller = Controller{};
    controller.enable(no_counts);
    controller.onMarkedSent(0, 300_000);

    // An ACK that acknowledges nothing we marked is not evidence either way.
    const unrelated = controller.onAck(0, null);
    try testing.expectEqual(@as(?FailureReason, null), unrelated.failed);
    try testing.expectEqual(State.testing, controller.state);

    const stripped = controller.onAck(1, null);
    try testing.expectEqual(@as(?FailureReason, .missing_counts), stripped.failed);
    try testing.expectEqual(State.disabled, controller.state);
    try testing.expectEqual(udp.Ecn.not_ect, controller.sendCodepoint());
}

test "ecn: promotion requires an acknowledgement of this path's own mark" {
    // Counter growth alone must not validate: the counters are per packet
    // number space and span every path the peer has been reached on, so growth
    // with nothing of this path's acknowledged is somebody else's evidence.
    var controller = Controller{};
    controller.enable(no_counts);
    controller.onMarkedSent(0, 300_000);
    controller.onMarkedSent(0, 300_000);

    // Growth arrives, but this ACK acknowledged none of this path's marks.
    // Whatever produced that growth, it was not evidence about this route.
    const foreign = controller.onAck(0, .{ .ect0 = 1, .ect1 = 0, .ce = 0 });
    try testing.expect(!foreign.validated);
    try testing.expectEqual(State.testing, controller.state);
    try testing.expectEqual(@as(u64, 0), foreign.ce_increase);

    // Growth *and* one of this path's own marks acknowledged: evidence at
    // last.
    const own = controller.onAck(1, .{ .ect0 = 2, .ect1 = 0, .ce = 0 });
    try testing.expect(own.validated);
    try testing.expectEqual(State.capable, controller.state);
}

test "ecn: CE reports reach congestion control only once validated" {
    var controller = Controller{};
    controller.enable(no_counts);
    controller.onMarkedSent(0, 300_000);

    // The promoting ACK: a mark demonstrably survived, and it arrived CE.
    const promoting = controller.onAck(1, .{ .ect0 = 0, .ect1 = 0, .ce = 1 });
    try testing.expect(promoting.validated);
    try testing.expectEqual(@as(u64, 1), promoting.ce_increase);
    try testing.expectEqual(State.capable, controller.state);

    controller.onMarkedSent(0, 300_000);
    const congested = controller.onAck(1, .{ .ect0 = 0, .ect1 = 0, .ce = 2 });
    try testing.expectEqual(@as(u64, 1), congested.ce_increase);
    try testing.expectEqual(@as(u64, 2), controller.ce_observed);
}

test "ecn: counts that go backwards disable ECN" {
    var controller = validatedController();
    controller.onMarkedSent(0, 300_000);
    const outcome = controller.onAck(1, .{ .ect0 = 1, .ect1 = 0, .ce = 0 });
    try testing.expectEqual(@as(?FailureReason, .counts_regressed), outcome.failed);
    try testing.expectEqual(@as(u64, 0), outcome.ce_increase);
}

test "ecn: a reported ECT(1) this endpoint never sends disables ECN" {
    var controller = validatedController();
    controller.onMarkedSent(0, 300_000);
    // Something on the path rewrote ECT(0) to ECT(1). The counts are no longer
    // describing what was sent, so nothing derived from them can be believed.
    const outcome = controller.onAck(1, .{ .ect0 = 3, .ect1 = 1, .ce = 0 });
    try testing.expectEqual(@as(?FailureReason, .unsent_codepoint), outcome.failed);
}

test "ecn: a peer cannot report more marked arrivals than were marked" {
    var controller = validatedController();
    controller.onMarkedSent(0, 300_000);
    // Three marked packets in total, and a report of twelve marked arrivals:
    // arithmetic that cannot describe this connection, and the classic way a
    // forged or confused ACK_ECN would try to manufacture congestion signals.
    const outcome = controller.onAck(1, .{ .ect0 = 12, .ect1 = 0, .ce = 0 });
    try testing.expectEqual(@as(?FailureReason, .counts_exceed_sent), outcome.failed);
    try testing.expectEqual(@as(u64, 0), outcome.ce_increase);
}

test "ecn: marks cleared in flight disable ECN" {
    var controller = Controller{};
    controller.enable(no_counts);

    // Four marked packets acknowledged, and the peer saw none of them marked:
    // a middlebox is clearing the codepoint (RFC 9000 §13.4.2.1).
    var sent: usize = 0;
    while (sent < 4) : (sent += 1) controller.onMarkedSent(0, 300_000);
    const outcome = controller.onAck(4, no_counts);
    try testing.expectEqual(@as(?FailureReason, .insufficient_increase), outcome.failed);
    try testing.expectEqual(State.disabled, controller.state);
}

test "ecn: a CE-marked delivery still accounts for its packet" {
    var controller = Controller{};
    controller.enable(no_counts);
    controller.onMarkedSent(0, 300_000);
    controller.onMarkedSent(0, 300_000);

    // Two marked packets acknowledged; one arrived ECT(0), the other met
    // congestion and arrived CE. The ECT(0) count alone is short of the two
    // acknowledged, so validation must count CE as well or every congested
    // path would look like a broken one.
    const outcome = controller.onAck(2, .{ .ect0 = 1, .ect1 = 0, .ce = 1 });
    try testing.expectEqual(@as(?FailureReason, null), outcome.failed);
    try testing.expect(outcome.validated);
    try testing.expectEqual(@as(u64, 1), outcome.ce_increase);
}

test "ecn: the testing window is armed by the first mark, not by enabling" {
    // A handshake-confirmed connection can sit idle. Arming at `enable` would
    // let three PTOs of silence record a permanent `testing_timeout` on a path
    // that was never given a chance to carry a single marked packet.
    var controller = Controller{};
    controller.enable(no_counts);
    try testing.expectEqual(@as(?u64, null), controller.deadlineUs());
    try testing.expectEqual(@as(?FailureReason, null), controller.onTimeout(10_000_000));
    try testing.expectEqual(State.testing, controller.state);

    // The first mark starts the clock, dated from when it actually went out.
    controller.onMarkedSent(10_000_000, 300_000);
    try testing.expectEqual(@as(?u64, 10_300_000), controller.deadlineUs());
    // Later marks do not push the deadline out, or a busy path that strips
    // every codepoint would never stop being tested.
    controller.onMarkedSent(10_200_000, 300_000);
    try testing.expectEqual(@as(?u64, 10_300_000), controller.deadlineUs());
}

test "ecn: the testing window closes on silence" {
    var controller = Controller{};
    controller.enable(no_counts);
    controller.onMarkedSent(1_000, 300_000);
    try testing.expectEqual(@as(?u64, 301_000), controller.deadlineUs());

    try testing.expectEqual(@as(?FailureReason, null), controller.onTimeout(300_999));
    try testing.expectEqual(State.testing, controller.state);

    try testing.expectEqual(@as(?FailureReason, .testing_timeout), controller.onTimeout(301_000));
    try testing.expectEqual(State.disabled, controller.state);
    try testing.expectEqual(@as(?u64, null), controller.deadlineUs());
    // Idempotent: a later timeout on a path that already gave up is silent.
    try testing.expectEqual(@as(?FailureReason, null), controller.onTimeout(999_999));
}

test "ecn: validation clears the testing deadline" {
    var controller = validatedController();
    try testing.expectEqual(State.capable, controller.state);
    try testing.expectEqual(@as(?u64, null), controller.deadlineUs());
    // A validated path is never retired by the testing timer.
    try testing.expectEqual(@as(?FailureReason, null), controller.onTimeout(std.math.maxInt(u64)));
    try testing.expectEqual(State.capable, controller.state);
}

test "ecn: a disabled controller ignores feedback entirely" {
    var controller = Controller{};
    // Nothing enabled marking, so nothing was marked, so no report about this
    // path can mean anything — including one claiming congestion.
    const outcome = controller.onAck(5, .{ .ect0 = 5, .ect1 = 0, .ce = 5 });
    try testing.expectEqual(@as(u64, 0), outcome.ce_increase);
    try testing.expectEqual(@as(?FailureReason, null), outcome.failed);
    try testing.expectEqual(State.disabled, controller.state);
}

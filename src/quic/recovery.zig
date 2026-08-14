//! QUIC loss detection and congestion control (#244, RFC 9002): ACK manager,
//! RTT estimator, loss detection, PTO, and a NewReno-baseline congestion
//! controller with pacing hooks.
//!
//! Consumes ACK frames decoded by `packet.zig` and the sent-packet metadata
//! recorded by `connection.zig`; drives retransmission and the send-allowance
//! that gates `stream.zig` output. Deliberately starts on a correct RFC 9002 /
//! NewReno baseline — BBR and aggressive optimizer work are explicitly deferred
//! (see the #240 non-goals).

const std = @import("std");

pub const max_ack_ranges = 32;
pub const max_tracked_packets = 128;
pub const max_ack_barrier_overflow_ranges = 128;
/// Fixed-array slots held back from ordinary STREAM/CRYPTO traffic so common
/// PTO and mandatory-PADDING recovery stays allocation-free. This is a
/// performance reserve, not a correctness bound: when the fixed tracker fills,
/// required recovery packets spill into `PacketTracker.recovery_overflow`.
pub const reserved_tracked_packets = 8;
/// The sender's maximum datagram size at connection start (RFC 9000 §14's
/// floor). RFC 9002 defines the NewReno windows in terms of the sender's
/// *current* maximum datagram size, so this is only the starting value:
/// `CongestionController.max_datagram_size` carries the live one and
/// `setMaxDatagramSize` tracks it as the path's send size changes (#256-A).
pub const initial_max_datagram_size: usize = 1200;
pub const initial_rtt_us: u64 = 333_000;
pub const timer_granularity_us: u64 = 1_000;
pub const packet_threshold: u64 = 3;
pub const default_max_ack_delay_us: u64 = 25_000;

/// How many maximum-size datagrams the pacer will let leave back to back
/// (#256-C). RFC 9002 §7.7 requires a sender to either pace or bound its
/// bursts; this bounds them at the initial window, so a connection whose
/// congestion window has grown to many times that still cannot hand the
/// network a window-sized burst in a single event-loop pass.
///
/// A packet count is only half the ceiling — `Pacer.burstBytes` also applies
/// `initialWindow`, which is what keeps the "initial window" claim true once
/// DPLPMTUD raises the datagram size past 1472.
pub const default_pacer_burst_packets: usize = 10;

const time_threshold_numerator: u64 = 9;
const time_threshold_denominator: u64 = 8;
/// The pacing gain `N` in RFC 9002 §7.7's rate `N * cwnd / smoothed_rtt`:
/// 2 while in slow start, 1.25 in congestion avoidance.
///
/// This phase split is Tardigrade's policy, not an RFC requirement. The final
/// RFC 9002 fixes the *shape* of the rate and asks only that `N` be a small
/// value above 1, offering 1.25 as an example; the explicit slow-start/
/// congestion-avoidance split comes from the earlier QUIC recovery drafts and
/// is what several deployed stacks still do. It is kept here for the reason
/// those drafts gave: slow start doubles the window every round trip, so
/// pacing it at 1.25x would hold the sender below the growth the window is
/// already granting, while congestion avoidance wants the smaller gain to
/// keep a full window from leaving as one burst.
const pacing_gain_slow_start_numerator: u64 = 2;
const pacing_gain_slow_start_denominator: u64 = 1;
const pacing_gain_avoidance_numerator: u64 = 5;
const pacing_gain_avoidance_denominator: u64 = 4;

pub const PacketNumberSpace = enum {
    initial,
    handshake,
    application,
};

pub const RecoveryEvent = enum {
    ack_range_inserted,
    packet_acked,
    packet_lost,
    pto_armed,
    congestion_event,
    persistent_congestion,
};

pub const Event = struct {
    kind: RecoveryEvent,
    space: ?PacketNumberSpace = null,
    packet_number: ?u64 = null,
    bytes_in_flight: usize = 0,
    congestion_window: usize = 0,
    rtt_us: ?u64 = null,
};

pub const EventSink = struct {
    context: ?*anyopaque = null,
    emitFn: ?*const fn (?*anyopaque, Event) void = null,

    pub fn emit(self: EventSink, event: Event) void {
        if (self.emitFn) |emit_fn| emit_fn(self.context, event);
    }
};

pub const AckRange = struct {
    first: u64,
    last: u64,

    pub fn init(first: u64, last: u64) AckRange {
        std.debug.assert(first <= last);
        return .{ .first = first, .last = last };
    }

    pub fn contains(self: AckRange, packet_number: u64) bool {
        return packet_number >= self.first and packet_number <= self.last;
    }

    pub fn len(self: AckRange) u64 {
        return self.last - self.first + 1;
    }
};

pub const AckFrameRange = struct {
    /// RFC 9000 ACK Range `Gap`: one less than the count of missing packet
    /// numbers between the previous range and this range.
    gap: u64,
    /// RFC 9000 ACK Range Length: one less than the count of acked packets in
    /// this range.
    length: u64,
};

pub const AckFrameModel = struct {
    largest_acknowledged: u64,
    ack_delay_us: u64,
    first_ack_range: u64,
    ranges: [max_ack_ranges - 1]AckFrameRange = undefined,
    range_count: usize = 0,
};

pub const AckRangeSet = struct {
    ranges: [max_ack_ranges]AckRange = undefined,
    count: usize = 0,

    pub fn clear(self: *AckRangeSet) void {
        self.count = 0;
    }

    pub fn contains(self: AckRangeSet, packet_number: u64) bool {
        for (self.ranges[0..self.count]) |range| {
            if (range.contains(packet_number)) return true;
            if (packet_number < range.first) return false;
        }
        return false;
    }

    pub fn insert(self: *AckRangeSet, packet_number: u64) error{TooManyAckRanges}!void {
        try self.insertRange(.{ .first = packet_number, .last = packet_number });
    }

    pub fn insertRange(self: *AckRangeSet, incoming: AckRange) error{TooManyAckRanges}!void {
        var merged = incoming;
        var index: usize = 0;
        while (index < self.count) {
            const current = self.ranges[index];
            if (merged.last +| 1 < current.first) break;
            if (current.last +| 1 < merged.first) {
                index += 1;
                continue;
            }
            merged.first = @min(merged.first, current.first);
            merged.last = @max(merged.last, current.last);
            self.removeAt(index);
        }
        if (self.count == max_ack_ranges) return error.TooManyAckRanges;
        var move = self.count;
        while (move > index) : (move -= 1) {
            self.ranges[move] = self.ranges[move - 1];
        }
        self.ranges[index] = merged;
        self.count += 1;
    }

    pub fn largest(self: AckRangeSet) ?u64 {
        if (self.count == 0) return null;
        return self.ranges[self.count - 1].last;
    }

    pub fn toAckFrame(self: AckRangeSet, ack_delay_us: u64) ?AckFrameModel {
        if (self.count == 0) return null;
        const largest_index = self.count - 1;
        const largest_range = self.ranges[largest_index];
        var frame = AckFrameModel{
            .largest_acknowledged = largest_range.last,
            .ack_delay_us = ack_delay_us,
            .first_ack_range = largest_range.len() - 1,
        };

        var previous_smallest = largest_range.first;
        var range_index = largest_index;
        while (range_index > 0) {
            range_index -= 1;
            const range = self.ranges[range_index];
            frame.ranges[frame.range_count] = .{
                .gap = previous_smallest - range.last - 2,
                .length = range.len() - 1,
            };
            frame.range_count += 1;
            previous_smallest = range.first;
        }
        return frame;
    }

    fn removeAt(self: *AckRangeSet, index: usize) void {
        var cursor = index;
        while (cursor + 1 < self.count) : (cursor += 1) {
            self.ranges[cursor] = self.ranges[cursor + 1];
        }
        self.count -= 1;
    }
};

pub const RttEstimator = struct {
    latest_rtt_us: ?u64 = null,
    smoothed_rtt_us: ?u64 = null,
    rttvar_us: ?u64 = null,
    min_rtt_us: ?u64 = null,
    max_ack_delay_us: u64 = default_max_ack_delay_us,

    pub fn init(max_ack_delay_us_value: u64) RttEstimator {
        return .{ .max_ack_delay_us = max_ack_delay_us_value };
    }

    pub fn hasSample(self: RttEstimator) bool {
        return self.smoothed_rtt_us != null;
    }

    pub fn update(self: *RttEstimator, latest_rtt_us_value: u64, ack_delay_us: u64) void {
        self.latest_rtt_us = latest_rtt_us_value;
        if (self.min_rtt_us == null or latest_rtt_us_value < self.min_rtt_us.?) {
            self.min_rtt_us = latest_rtt_us_value;
        }

        if (self.smoothed_rtt_us == null) {
            self.smoothed_rtt_us = latest_rtt_us_value;
            self.rttvar_us = latest_rtt_us_value / 2;
            return;
        }

        var adjusted_rtt = latest_rtt_us_value;
        const capped_ack_delay = @min(ack_delay_us, self.max_ack_delay_us);
        if (latest_rtt_us_value > self.min_rtt_us.? + capped_ack_delay) {
            adjusted_rtt -= capped_ack_delay;
        }

        const smoothed = self.smoothed_rtt_us.?;
        const variance_sample = absDiff(smoothed, adjusted_rtt);
        self.rttvar_us = (self.rttvar_us.? * 3 + variance_sample) / 4;
        self.smoothed_rtt_us = (smoothed * 7 + adjusted_rtt) / 8;
    }

    pub fn lossDelay(self: RttEstimator) u64 {
        const latest = self.latest_rtt_us orelse initial_rtt_us;
        const smoothed = self.smoothed_rtt_us orelse initial_rtt_us;
        const basis = @max(latest, smoothed);
        return @max(timer_granularity_us, ceilDiv(basis * time_threshold_numerator, time_threshold_denominator));
    }

    pub fn ptoDuration(self: RttEstimator, space: PacketNumberSpace) u64 {
        const smoothed = self.smoothed_rtt_us orelse initial_rtt_us;
        const variance = self.rttvar_us orelse initial_rtt_us / 2;
        const ack_delay = if (space == .application) self.max_ack_delay_us else 0;
        return smoothed + @max(4 * variance, timer_granularity_us) + ack_delay;
    }
};

pub const SentPacket = struct {
    space: PacketNumberSpace,
    packet_number: u64,
    time_sent_us: u64,
    size: usize,
    ack_eliciting: bool = true,
    in_flight: bool = true,
    lost: bool = false,
    /// A DPLPMTUD probe (#256-B). It is in flight and consumes congestion
    /// window like anything else, but RFC 9000 §14.4 is explicit that losing
    /// one is *not* a reliable congestion signal — an oversized datagram is
    /// expected to be dropped by a path too small for it, which says nothing
    /// about queue depth. Its bytes still leave the in-flight ledger; only the
    /// window reduction is withheld.
    pmtu_probe: bool = false,
    /// True when an RTT sample existed before this packet was sent. RFC 9002
    /// §7.6.2 requires persistent-congestion boundary packets to have been
    /// sent after at least one RTT sample was available.
    rtt_sample_available_at_send: bool = false,
};

pub const AckResult = struct {
    packet: SentPacket,
    rtt_sample_us: ?u64,
};

pub const LossResult = struct {
    packet_threshold_losses: usize = 0,
    time_threshold_losses: usize = 0,
    /// Every in-flight byte declared lost, probes included. This is the
    /// ledger figure — all of it must leave `bytes_in_flight`.
    lost_bytes: usize = 0,
    persistent_congestion: bool = false,
    earliest_lost_time_sent_us: ?u64 = null,
    largest_lost_time_sent_us: ?u64 = null,
    /// The subset of `lost_bytes` belonging to DPLPMTUD probes, which
    /// RFC 9000 §14.4 excludes from the congestion reaction.
    probe_lost_bytes: usize = 0,
    /// Send time of the most recent ordinary (non-probe) lost packet: the
    /// congestion event's timestamp, so a probe cannot start a recovery period
    /// on its own. Deliberately *not* accompanied by an aggregate lost size —
    /// DPLPMTUD evidence is per path, and a single number here would collapse
    /// losses from several paths into one (#256-B review).
    earliest_ordinary_lost_time_sent_us: ?u64 = null,
    largest_ordinary_lost_time_sent_us: ?u64 = null,
};

pub const PacketTracker = struct {
    const PersistentCandidate = struct {
        active: bool = false,
        start_us: u64 = 0,
        end_us: u64 = 0,
        boundaries_have_prior_rtt: bool = false,

        fn reset(self: *PersistentCandidate) void {
            self.* = .{};
        }

        fn seedFromLost(self: *PersistentCandidate, packet: SentPacket) void {
            self.* = .{
                .active = true,
                .start_us = packet.time_sent_us,
                .end_us = packet.time_sent_us,
                .boundaries_have_prior_rtt = packet.rtt_sample_available_at_send,
            };
        }
    };

    const AckedSendTimeRange = struct {
        start_us: u64 = 0,
        end_us: u64 = 0,

        fn fromSendTime(time_sent_us: u64) AckedSendTimeRange {
            return .{ .start_us = time_sent_us, .end_us = time_sent_us };
        }

        fn canMerge(self: AckedSendTimeRange, other: AckedSendTimeRange) bool {
            return self.start_us <= other.end_us +| 1 and other.start_us <= self.end_us +| 1;
        }

        fn merge(self: *AckedSendTimeRange, other: AckedSendTimeRange) void {
            self.start_us = @min(self.start_us, other.start_us);
            self.end_us = @max(self.end_us, other.end_us);
        }

        fn intersects(self: AckedSendTimeRange, candidate: PersistentCandidate) bool {
            return self.end_us >= candidate.start_us and self.start_us <= candidate.end_us;
        }
    };

    /// Fixed fast path. Ordinary traffic is bounded here and never consumes
    /// allocator-backed overflow.
    packets: [max_tracked_packets]SentPacket = undefined,
    count: usize = 0,
    /// Required recovery-only spill storage. PTO expiration is not evidence of
    /// loss, so a full fixed tracker cannot be made available by pretending an
    /// outstanding packet stopped being in flight. Instead, reserve overflow
    /// before building the recovery packet and keep tracking both originals and
    /// probes until normal ACK/loss/key-discard processing retires them.
    recovery_overflow: std.ArrayList(SentPacket) = .empty,
    bytes_in_flight: usize = 0,
    largest_acked: [3]?u64 = .{ null, null, null },
    persistent_candidates: [3]PersistentCandidate = .{ .{}, .{}, .{} },
    /// Exact ACK send-time barriers that can still intersect an unresolved
    /// persistent-congestion candidate or a packet that may become one. These
    /// are pruned by relevance rather than retained for the lifetime of the
    /// connection, so `max_tracked_packets` is a storage bound, not an ACK-count
    /// lifetime limit.
    acked_send_time_ranges: [3][max_tracked_packets]AckedSendTimeRange = [_][max_tracked_packets]AckedSendTimeRange{[_]AckedSendTimeRange{.{}} ** max_tracked_packets} ** 3,
    acked_send_time_range_counts: [3]usize = .{0} ** 3,
    acked_send_time_range_overflow: [3][max_ack_barrier_overflow_ranges]AckedSendTimeRange = [_][max_ack_barrier_overflow_ranges]AckedSendTimeRange{[_]AckedSendTimeRange{.{}} ** max_ack_barrier_overflow_ranges} ** 3,
    acked_send_time_range_overflow_counts: [3]usize = .{0} ** 3,

    pub fn deinit(self: *PacketTracker, allocator: std.mem.Allocator) void {
        self.recovery_overflow.deinit(allocator);
        self.recovery_overflow = .empty;
    }

    pub fn totalCount(self: *const PacketTracker) usize {
        return self.count + self.recovery_overflow.items.len;
    }

    pub fn ensureRecoveryCapacity(self: *PacketTracker, allocator: std.mem.Allocator, additional: usize) !void {
        const fixed_free = max_tracked_packets - self.count;
        const overflow_needed = additional -| fixed_free;
        if (overflow_needed > 0) {
            try self.recovery_overflow.ensureUnusedCapacity(allocator, overflow_needed);
        }
    }

    pub fn canTrackRecoveryPacket(self: *const PacketTracker) bool {
        return self.count < max_tracked_packets or self.recovery_overflow.items.len < self.recovery_overflow.capacity;
    }

    /// Ordinary insert: fixed tracker only.
    pub fn onPacketSent(self: *PacketTracker, packet: SentPacket) error{TooManyTrackedPackets}!void {
        if (self.count == max_tracked_packets) return error.TooManyTrackedPackets;
        self.packets[self.count] = packet;
        self.count += 1;
        if (packet.in_flight) self.bytes_in_flight += packet.size;
    }

    /// Required recovery insert after `ensureRecoveryCapacity` preflight.
    pub fn onPacketSentAssumeRecoveryCapacity(self: *PacketTracker, packet: SentPacket) void {
        if (self.count < max_tracked_packets) {
            self.packets[self.count] = packet;
            self.count += 1;
        } else {
            std.debug.assert(self.recovery_overflow.items.len < self.recovery_overflow.capacity);
            self.recovery_overflow.appendAssumeCapacity(packet);
        }
        if (packet.in_flight) self.bytes_in_flight += packet.size;
    }

    pub fn onAcked(self: *PacketTracker, space: PacketNumberSpace, packet_number: u64, now_us: u64) error{OutOfMemory}!?AckResult {
        var index: usize = 0;
        while (index < self.count) : (index += 1) {
            const packet = self.packets[index];
            if (packet.space != space or packet.packet_number != packet_number or packet.lost) continue;
            if (packet.in_flight) self.bytes_in_flight -= packet.size;
            self.noteLargestAcked(space, packet_number);
            self.removeAt(index);
            self.breakPersistentCandidateOnAck(space, packet.time_sent_us);
            self.retirePersistentCandidateOnAckBarrier(space, packet.time_sent_us);
            try self.noteAckedSendTime(space, packet.time_sent_us);
            return .{
                .packet = packet,
                .rtt_sample_us = if (packet.ack_eliciting) now_us - packet.time_sent_us else null,
            };
        }

        var overflow_index: usize = 0;
        while (overflow_index < self.recovery_overflow.items.len) : (overflow_index += 1) {
            const packet = self.recovery_overflow.items[overflow_index];
            if (packet.space != space or packet.packet_number != packet_number or packet.lost) continue;
            if (packet.in_flight) self.bytes_in_flight -= packet.size;
            self.noteLargestAcked(space, packet_number);
            _ = self.recovery_overflow.orderedRemove(overflow_index);
            self.breakPersistentCandidateOnAck(space, packet.time_sent_us);
            self.retirePersistentCandidateOnAckBarrier(space, packet.time_sent_us);
            try self.noteAckedSendTime(space, packet.time_sent_us);
            return .{
                .packet = packet,
                .rtt_sample_us = if (packet.ack_eliciting) now_us - packet.time_sent_us else null,
            };
        }
        return null;
    }

    fn noteLost(result: *LossResult, packet: SentPacket, threshold_lost: bool, time_lost: bool) void {
        if (threshold_lost) result.packet_threshold_losses += 1;
        if (time_lost) result.time_threshold_losses += 1;
        if (packet.in_flight) result.lost_bytes += packet.size;
        if (result.earliest_lost_time_sent_us == null or packet.time_sent_us < result.earliest_lost_time_sent_us.?) {
            result.earliest_lost_time_sent_us = packet.time_sent_us;
        }
        if (result.largest_lost_time_sent_us == null or packet.time_sent_us > result.largest_lost_time_sent_us.?) {
            result.largest_lost_time_sent_us = packet.time_sent_us;
        }
        if (packet.pmtu_probe) {
            if (packet.in_flight) result.probe_lost_bytes += packet.size;
            return;
        }
        if (result.earliest_ordinary_lost_time_sent_us == null or
            packet.time_sent_us < result.earliest_ordinary_lost_time_sent_us.?)
        {
            result.earliest_ordinary_lost_time_sent_us = packet.time_sent_us;
        }
        if (result.largest_ordinary_lost_time_sent_us == null or
            packet.time_sent_us > result.largest_ordinary_lost_time_sent_us.?)
        {
            result.largest_ordinary_lost_time_sent_us = packet.time_sent_us;
        }
    }

    fn isPersistentCandidatePacket(packet: SentPacket) bool {
        return !packet.pmtu_probe and packet.ack_eliciting and packet.in_flight;
    }

    fn observePersistentCandidate(self: *PacketTracker, space: PacketNumberSpace, packet: SentPacket) void {
        if (!isPersistentCandidatePacket(packet)) return;
        const idx = spaceIndex(space);
        var candidate = &self.persistent_candidates[idx];
        if (!candidate.active) {
            candidate.seedFromLost(packet);
            self.pruneAckedSendTimes(space);
            return;
        }
        const previous_end = candidate.end_us;
        var proposed = candidate.*;
        if (packet.time_sent_us < candidate.start_us) {
            proposed.start_us = packet.time_sent_us;
            proposed.boundaries_have_prior_rtt = proposed.boundaries_have_prior_rtt and packet.rtt_sample_available_at_send;
        } else if (packet.time_sent_us > candidate.end_us) {
            proposed.end_us = packet.time_sent_us;
            proposed.boundaries_have_prior_rtt = proposed.boundaries_have_prior_rtt and packet.rtt_sample_available_at_send;
        }
        if (self.hasAckedSendTimeInCandidate(space, proposed)) {
            if (packet.time_sent_us > previous_end) {
                candidate.seedFromLost(packet);
                self.pruneAckedSendTimes(space);
            } else {
                candidate.reset();
            }
            return;
        }
        candidate.* = proposed;
    }

    fn noteAckedSendTime(self: *PacketTracker, space: PacketNumberSpace, time_sent_us: u64) error{OutOfMemory}!void {
        self.pruneAckedSendTimes(space);
        try self.insertAckedSendTimeRange(space, .fromSendTime(time_sent_us));
        self.pruneAckedSendTimes(space);
    }

    fn insertAckedSendTimeRange(self: *PacketTracker, space: PacketNumberSpace, range: AckedSendTimeRange) error{OutOfMemory}!void {
        const idx = spaceIndex(space);
        var merged = range;
        var index: usize = 0;
        while (index < self.ackedSendTimeRangeCount(idx)) {
            if (!self.ackedSendTimeRangeAt(idx, index).canMerge(merged)) {
                index += 1;
                continue;
            }
            merged.merge(self.ackedSendTimeRangeAt(idx, index));
            self.removeAckedSendTimeRangeAt(idx, index);
        }
        try self.appendAckedSendTimeRange(idx, merged);
    }

    fn ackedSendTimeRangeCount(self: *const PacketTracker, idx: usize) usize {
        return self.acked_send_time_range_counts[idx] + self.acked_send_time_range_overflow_counts[idx];
    }

    fn ackedSendTimeRangeAt(self: *const PacketTracker, idx: usize, index: usize) AckedSendTimeRange {
        if (index < self.acked_send_time_range_counts[idx]) return self.acked_send_time_ranges[idx][index];
        return self.acked_send_time_range_overflow[idx][index - self.acked_send_time_range_counts[idx]];
    }

    fn appendAckedSendTimeRange(self: *PacketTracker, idx: usize, range: AckedSendTimeRange) error{OutOfMemory}!void {
        if (self.acked_send_time_range_counts[idx] < self.acked_send_time_ranges[idx].len) {
            self.acked_send_time_ranges[idx][self.acked_send_time_range_counts[idx]] = range;
            self.acked_send_time_range_counts[idx] += 1;
            return;
        }
        if (self.acked_send_time_range_overflow_counts[idx] == self.acked_send_time_range_overflow[idx].len) return error.OutOfMemory;
        self.acked_send_time_range_overflow[idx][self.acked_send_time_range_overflow_counts[idx]] = range;
        self.acked_send_time_range_overflow_counts[idx] += 1;
    }

    fn removeAckedSendTimeRangeAt(self: *PacketTracker, idx: usize, index: usize) void {
        if (index >= self.acked_send_time_range_counts[idx]) {
            self.removeAckedSendTimeRangeOverflowAt(idx, index - self.acked_send_time_range_counts[idx]);
            return;
        }
        std.mem.copyForwards(
            AckedSendTimeRange,
            self.acked_send_time_ranges[idx][index .. self.acked_send_time_range_counts[idx] - 1],
            self.acked_send_time_ranges[idx][index + 1 .. self.acked_send_time_range_counts[idx]],
        );
        self.acked_send_time_range_counts[idx] -= 1;
        if (self.acked_send_time_range_overflow_counts[idx] > 0) {
            self.acked_send_time_ranges[idx][self.acked_send_time_range_counts[idx]] = self.acked_send_time_range_overflow[idx][0];
            self.removeAckedSendTimeRangeOverflowAt(idx, 0);
            self.acked_send_time_range_counts[idx] += 1;
        }
    }

    fn removeAckedSendTimeRangeOverflowAt(self: *PacketTracker, idx: usize, index: usize) void {
        std.mem.copyForwards(
            AckedSendTimeRange,
            self.acked_send_time_range_overflow[idx][index .. self.acked_send_time_range_overflow_counts[idx] - 1],
            self.acked_send_time_range_overflow[idx][index + 1 .. self.acked_send_time_range_overflow_counts[idx]],
        );
        self.acked_send_time_range_overflow_counts[idx] -= 1;
    }

    fn hasTrackedPersistentCandidatePacketBefore(self: *const PacketTracker, space: PacketNumberSpace, barrier_time_us: u64) bool {
        for (self.packets[0..self.count]) |packet| {
            if (packet.space != space or packet.lost or !isPersistentCandidatePacket(packet)) continue;
            if (packet.time_sent_us < barrier_time_us) return true;
        }
        for (self.recovery_overflow.items) |packet| {
            if (packet.space != space or packet.lost or !isPersistentCandidatePacket(packet)) continue;
            if (packet.time_sent_us < barrier_time_us) return true;
        }
        return false;
    }

    /// An ACK sent after the current loss candidate is a hard barrier: no loss
    /// sent at or after that time can join the candidate without crossing an
    /// acknowledged packet. Once every still-outstanding packet that could
    /// extend the candidate before that barrier has resolved, the candidate can
    /// never grow again and its old ACK history is no longer relevant.
    fn retirePersistentCandidateOnAckBarrier(self: *PacketTracker, space: PacketNumberSpace, time_sent_us: u64) void {
        const idx = spaceIndex(space);
        var candidate = &self.persistent_candidates[idx];
        if (!candidate.active or time_sent_us <= candidate.end_us) return;
        if (self.hasTrackedPersistentCandidatePacketBefore(space, time_sent_us)) return;
        candidate.reset();
    }

    fn earliestTrackedPersistentCandidateSendTime(self: *const PacketTracker, space: PacketNumberSpace) ?u64 {
        var earliest: ?u64 = null;
        for (self.packets[0..self.count]) |packet| {
            if (packet.space != space or packet.lost or !isPersistentCandidatePacket(packet)) continue;
            earliest = if (earliest) |value| @min(value, packet.time_sent_us) else packet.time_sent_us;
        }
        for (self.recovery_overflow.items) |packet| {
            if (packet.space != space or packet.lost or !isPersistentCandidatePacket(packet)) continue;
            earliest = if (earliest) |value| @min(value, packet.time_sent_us) else packet.time_sent_us;
        }
        return earliest;
    }

    fn ackEvidenceFloor(self: *const PacketTracker, space: PacketNumberSpace) ?u64 {
        const candidate = self.persistent_candidates[spaceIndex(space)];
        if (candidate.active) return candidate.start_us;
        return self.earliestTrackedPersistentCandidateSendTime(space);
    }

    fn pruneAckedSendTimes(self: *PacketTracker, space: PacketNumberSpace) void {
        const idx = spaceIndex(space);
        const floor = self.ackEvidenceFloor(space) orelse {
            self.acked_send_time_range_counts[idx] = 0;
            self.acked_send_time_range_overflow_counts[idx] = 0;
            return;
        };

        var index: usize = 0;
        while (index < self.ackedSendTimeRangeCount(idx)) {
            const range = self.ackedSendTimeRangeAt(idx, index);
            if (range.end_us < floor) {
                self.removeAckedSendTimeRangeAt(idx, index);
                continue;
            }
            index += 1;
        }

        for (self.acked_send_time_ranges[idx][0..self.acked_send_time_range_counts[idx]]) |*range| {
            if (range.end_us < floor) continue;
            range.start_us = @max(range.start_us, floor);
        }
        for (self.acked_send_time_range_overflow[idx][0..self.acked_send_time_range_overflow_counts[idx]]) |*range| {
            if (range.end_us < floor) continue;
            range.start_us = @max(range.start_us, floor);
        }
    }

    fn hasAckedSendTimeInCandidate(self: *const PacketTracker, space: PacketNumberSpace, candidate: PersistentCandidate) bool {
        if (!candidate.active) return false;
        const idx = spaceIndex(space);
        for (self.acked_send_time_ranges[idx][0..self.acked_send_time_range_counts[idx]]) |range| {
            if (range.intersects(candidate)) return true;
        }
        for (self.acked_send_time_range_overflow[idx][0..self.acked_send_time_range_overflow_counts[idx]]) |range| {
            if (range.intersects(candidate)) return true;
        }
        return false;
    }

    fn breakPersistentCandidateOnAck(self: *PacketTracker, space: PacketNumberSpace, time_sent_us: u64) void {
        var candidate = &self.persistent_candidates[spaceIndex(space)];
        if (!candidate.active) return;
        if (time_sent_us >= candidate.start_us and time_sent_us <= candidate.end_us) candidate.reset();
    }

    fn persistentCongestionDuration(rtt: RttEstimator) ?u64 {
        const smoothed = rtt.smoothed_rtt_us orelse return null;
        const variance = rtt.rttvar_us orelse return null;
        return (smoothed + @max(4 * variance, timer_granularity_us) + rtt.max_ack_delay_us) * 3;
    }

    pub fn detectLost(self: *PacketTracker, space: PacketNumberSpace, now_us: u64, rtt: RttEstimator) LossResult {
        const largest = self.largest_acked[spaceIndex(space)] orelse return .{};
        const time_threshold = rtt.lossDelay();
        var result = LossResult{};

        var index: usize = 0;
        while (index < self.count) {
            const packet = self.packets[index];
            if (packet.space != space or packet.lost or packet.packet_number > largest) {
                index += 1;
                continue;
            }
            const threshold_lost = largest >= packet.packet_number + packet_threshold;
            const time_lost = now_us >= packet.time_sent_us and now_us - packet.time_sent_us >= time_threshold;
            if (!threshold_lost and !time_lost) {
                index += 1;
                continue;
            }
            noteLost(&result, packet, threshold_lost, time_lost);
            self.observePersistentCandidate(space, packet);
            if (packet.in_flight) self.bytes_in_flight -= packet.size;
            self.removeAt(index);
        }

        var overflow_index: usize = 0;
        while (overflow_index < self.recovery_overflow.items.len) {
            const packet = self.recovery_overflow.items[overflow_index];
            if (packet.space != space or packet.lost or packet.packet_number > largest) {
                overflow_index += 1;
                continue;
            }
            const threshold_lost = largest >= packet.packet_number + packet_threshold;
            const time_lost = now_us >= packet.time_sent_us and now_us - packet.time_sent_us >= time_threshold;
            if (!threshold_lost and !time_lost) {
                overflow_index += 1;
                continue;
            }
            noteLost(&result, packet, threshold_lost, time_lost);
            self.observePersistentCandidate(space, packet);
            if (packet.in_flight) self.bytes_in_flight -= packet.size;
            _ = self.recovery_overflow.orderedRemove(overflow_index);
        }
        self.pruneAckedSendTimes(space);
        const candidate = self.persistent_candidates[spaceIndex(space)];
        if (candidate.active and candidate.boundaries_have_prior_rtt) {
            if (persistentCongestionDuration(rtt)) |duration| {
                result.persistent_congestion = candidate.end_us >= candidate.start_us and candidate.end_us - candidate.start_us >= duration;
            }
        }
        return result;
    }

    /// RFC 9002 §6.4: discard both fixed and overflow entries for a packet
    /// number space whose keys are gone.
    pub fn dropSpace(self: *PacketTracker, space: PacketNumberSpace) usize {
        var removed: usize = 0;
        var index: usize = 0;
        while (index < self.count) {
            const packet = self.packets[index];
            if (packet.space != space) {
                index += 1;
                continue;
            }
            if (packet.in_flight) {
                removed += packet.size;
                self.bytes_in_flight -= packet.size;
            }
            self.removeAt(index);
        }

        var overflow_index: usize = 0;
        while (overflow_index < self.recovery_overflow.items.len) {
            const packet = self.recovery_overflow.items[overflow_index];
            if (packet.space != space) {
                overflow_index += 1;
                continue;
            }
            if (packet.in_flight) {
                removed += packet.size;
                self.bytes_in_flight -= packet.size;
            }
            _ = self.recovery_overflow.orderedRemove(overflow_index);
        }

        const idx = spaceIndex(space);
        self.largest_acked[idx] = null;
        self.persistent_candidates[idx].reset();
        self.acked_send_time_range_counts[idx] = 0;
        self.acked_send_time_range_overflow_counts[idx] = 0;
        return removed;
    }

    pub fn contains(self: *const PacketTracker, space: PacketNumberSpace, packet_number: u64) bool {
        for (self.packets[0..self.count]) |packet| {
            if (packet.space == space and packet.packet_number == packet_number) return true;
        }
        for (self.recovery_overflow.items) |packet| {
            if (packet.space == space and packet.packet_number == packet_number) return true;
        }
        return false;
    }

    pub fn hasAckElicitingInFlight(self: *const PacketTracker, space: PacketNumberSpace) bool {
        for (self.packets[0..self.count]) |packet| {
            if (packet.space == space and packet.in_flight and packet.ack_eliciting) return true;
        }
        for (self.recovery_overflow.items) |packet| {
            if (packet.space == space and packet.in_flight and packet.ack_eliciting) return true;
        }
        return false;
    }

    pub fn nextLossDeadline(self: *const PacketTracker, loss_delay: u64) ?u64 {
        var deadline: ?u64 = null;
        for (self.packets[0..self.count]) |packet| {
            const largest = self.largest_acked[spaceIndex(packet.space)] orelse continue;
            if (packet.lost or packet.packet_number > largest) continue;
            const candidate = packet.time_sent_us + loss_delay;
            deadline = if (deadline) |current| @min(current, candidate) else candidate;
        }
        for (self.recovery_overflow.items) |packet| {
            const largest = self.largest_acked[spaceIndex(packet.space)] orelse continue;
            if (packet.lost or packet.packet_number > largest) continue;
            const candidate = packet.time_sent_us + loss_delay;
            deadline = if (deadline) |current| @min(current, candidate) else candidate;
        }
        return deadline;
    }

    fn noteLargestAcked(self: *PacketTracker, space: PacketNumberSpace, packet_number: u64) void {
        const index = spaceIndex(space);
        if (self.largest_acked[index] == null or packet_number > self.largest_acked[index].?) {
            self.largest_acked[index] = packet_number;
        }
    }

    fn removeAt(self: *PacketTracker, index: usize) void {
        var cursor = index;
        while (cursor + 1 < self.count) : (cursor += 1) {
            self.packets[cursor] = self.packets[cursor + 1];
        }
        self.count -= 1;
    }
};

pub const CongestionController = struct {
    congestion_window: usize = initialWindow(initial_max_datagram_size),
    bytes_in_flight: usize = 0,
    ssthresh: usize = std.math.maxInt(usize),
    recovery_start_time_us: ?u64 = null,
    /// The sender's current maximum datagram size (RFC 9002 §B.2). Every
    /// NewReno window below is expressed in terms of it, so it must follow the
    /// size the packet builder actually emits rather than a compile-time
    /// constant (#256-A).
    max_datagram_size: usize = initial_max_datagram_size,
    /// RFC 9002 §7.7 pacing state (#256-C). Lives here because the pacing
    /// rate is a function of this controller's window: a reset that discards
    /// the window (path migration) must discard the schedule derived from it
    /// in the same step.
    pacer: Pacer = .{},

    pub fn initialWindow(max_datagram: usize) usize {
        return @min(10 * max_datagram, @max(2 * max_datagram, 14_720));
    }

    pub fn minWindow(self: CongestionController) usize {
        return 2 * self.max_datagram_size;
    }

    /// Adopt a new sender maximum datagram size. The congestion window is not
    /// recomputed — it reflects measured capacity, not the packet size — but
    /// it is lifted to the new minimum so a larger datagram can never be
    /// blocked by a floor derived from a smaller one.
    pub fn setMaxDatagramSize(self: *CongestionController, size: usize) void {
        if (size == 0 or size == self.max_datagram_size) return;
        self.max_datagram_size = size;
        const floor = self.minWindow();
        if (self.congestion_window < floor) self.congestion_window = floor;
    }

    pub fn onPacketSent(self: *CongestionController, bytes: usize) void {
        self.bytes_in_flight += bytes;
    }

    pub fn onPacketAcked(self: *CongestionController, packet: SentPacket) void {
        self.bytes_in_flight -|= packet.size;
        if (self.recovery_start_time_us) |start| {
            if (packet.time_sent_us <= start) return;
            self.recovery_start_time_us = null;
        }
        if (self.congestion_window < self.ssthresh) {
            self.congestion_window += packet.size;
        } else {
            self.congestion_window += @max(1, self.max_datagram_size * packet.size / self.congestion_window);
        }
    }

    pub fn onPacketsLost(self: *CongestionController, largest_lost_time_sent_us: u64, lost_bytes: usize, now_us: u64) void {
        if (lost_bytes == 0) return;
        self.bytes_in_flight -|= lost_bytes;
        self.onCongestionEvent(largest_lost_time_sent_us, now_us);
    }

    /// RFC 9002 §7.1/§B.5: halve the window and enter recovery, without
    /// touching the in-flight ledger.
    ///
    /// Split out for the ECN-CE case (#256-E), which is congestion evidence
    /// about a packet that *arrived*: its bytes were already released when it
    /// was acknowledged, and reclaiming them a second time here would
    /// under-count what is on the wire. The one-recovery-period-per-event rule
    /// is shared with loss, so a CE report and a loss for the same round trip
    /// halve the window once between them rather than twice.
    pub fn onCongestionEvent(self: *CongestionController, sent_time_us: u64, now_us: u64) void {
        if (self.recovery_start_time_us) |start| {
            if (sent_time_us <= start) return;
        }
        self.recovery_start_time_us = now_us;
        self.congestion_window = @max(self.congestion_window / 2, self.minWindow());
        self.ssthresh = self.congestion_window;
    }

    /// Release lost DPLPMTUD probe bytes from the in-flight ledger without a
    /// congestion event (RFC 9000 §14.4). The bytes were genuinely in flight
    /// and must be reclaimed, but a probe deliberately sized larger than the
    /// path is not evidence of congestion, and halving the window every time
    /// discovery overshoots would make probing cost throughput.
    pub fn onProbePacketsLost(self: *CongestionController, lost_bytes: usize) void {
        self.bytes_in_flight -|= lost_bytes;
    }

    pub fn onPersistentCongestion(self: *CongestionController) void {
        self.congestion_window = self.minWindow();
        self.ssthresh = self.congestion_window;
    }

    /// The pacing gain `N`, as an exact fraction so the schedule stays integer
    /// arithmetic. See `pacing_gain_slow_start_numerator` for why the split by
    /// phase is a local policy rather than something RFC 9002 prescribes.
    fn pacingGain(self: CongestionController) PacingGain {
        if (self.congestion_window < self.ssthresh) {
            return .{ .numerator = pacing_gain_slow_start_numerator, .denominator = pacing_gain_slow_start_denominator };
        }
        return .{ .numerator = pacing_gain_avoidance_numerator, .denominator = pacing_gain_avoidance_denominator };
    }

    /// The window the pacing rate is derived from. Floored at the minimum
    /// window so a controller driven to its floor still paces at a rate that
    /// makes forward progress rather than dividing by a collapsed number.
    fn pacingWindow(self: CongestionController) u64 {
        return @max(self.congestion_window, self.minWindow());
    }

    /// The pacing bucket's balance at `now_us`, in bytes (#256-C).
    ///
    /// Signed, and the sign carries meaning: a negative balance is *debt* left
    /// by a packet that bypassed the pacing gate. Exempt means "may send
    /// now", not "free from the schedule" — see `onPacingSent`.
    ///
    /// Pure by design: asking "may I send?" must not itself move the
    /// schedule, so the bucket is only ever advanced by `onPacingSent`, and
    /// two queries at the same instant give the same answer. The refill is
    /// computed from the last charge rather than accumulated tick by tick,
    /// which is what makes the schedule independent of how often the event
    /// loop happens to wake.
    pub fn pacingBalance(self: CongestionController, now_us: u64, rtt: RttEstimator) i64 {
        const burst: i64 = @intCast(self.pacer.burstBytes(self.max_datagram_size));
        // A pacer that has never sent starts full: the first flight of a
        // connection (and the first after an idle period, once
        // `onPacingSent`'s stamp has aged past a full burst's worth of
        // refill) is allowed the whole burst rather than being metered out
        // from an empty bucket.
        const since = self.pacer.updated_at_us orelse return burst;
        const elapsed = now_us -| since;
        const srtt = @max(rtt.smoothed_rtt_us orelse initial_rtt_us, 1);
        const gain = self.pacingGain();
        const gained = (@as(u128, elapsed) * gain.numerator * self.pacingWindow()) /
            (@as(u128, gain.denominator) * srtt);
        // Clamp the *gain* before adding it: a long idle period accrues more
        // credit than an i64 can hold, and the ceiling below discards all of
        // it anyway. Saturating addition then keeps a large gain from wrapping
        // a large debt.
        const earned: i64 = @intCast(@min(gained, @as(u128, std.math.maxInt(i64) / 2)));
        return @min(self.pacer.balance +| earned, burst);
    }

    /// Whether a `bytes`-sized congestion-controlled datagram is eligible to
    /// leave at `now_us` under the pacing schedule.
    pub fn pacingAllows(self: CongestionController, bytes: usize, now_us: u64, rtt: RttEstimator) bool {
        return self.pacingBalance(now_us, rtt) >= @as(i64, @intCast(bytes));
    }

    /// The earliest time `bytes` becomes eligible — `now_us` when it already
    /// is. When it is not, the result is strictly greater than `now_us`, so an
    /// event loop that sleeps until this deadline always makes progress
    /// instead of spinning on a deadline that has already passed.
    ///
    /// Anti-spin needs exactly one microsecond of headroom and gets it for
    /// free: the ceil-division below cannot return 0 while the deficit is
    /// non-zero. Deliberately *not* floored at `timer_granularity_us` — that
    /// constant is loss-detection timer resolution, and a fast path's pacing
    /// interval is legitimately far below it. A 1 ms floor on a 40 Mbit-plus
    /// path would round every release up and, against a bounded burst, cap the
    /// sender at `burst / 1 ms` no matter how much window and RTT allowed.
    pub fn pacingReleaseUs(self: CongestionController, bytes: usize, now_us: u64, rtt: RttEstimator) u64 {
        const balance = self.pacingBalance(now_us, rtt);
        const want: i64 = @intCast(bytes);
        if (balance >= want) return now_us;
        // Widened before subtracting: `balance` may be a debt, in which case
        // the wait covers repaying it *and* earning this packet's own credit.
        const deficit: u128 = @intCast(@as(i128, want) - @as(i128, balance));
        const srtt = @max(rtt.smoothed_rtt_us orelse initial_rtt_us, 1);
        const gain = self.pacingGain();
        const numerator = deficit * gain.denominator * srtt;
        const denominator = @as(u128, gain.numerator) * self.pacingWindow();
        const delay: u64 = @intCast(@min((numerator + denominator - 1) / denominator, @as(u128, std.math.maxInt(u32))));
        return now_us + @max(delay, 1);
    }

    /// Charge `bytes` to the pacing bucket at `now_us`. Called for every
    /// congestion-controlled packet that actually left, and only for those:
    /// a pure ACK is not in flight and is not metered here, which is what
    /// keeps acknowledgement latency independent of the send schedule.
    ///
    /// The charge can drive the balance negative, and deliberately so. Packets
    /// that bypass the pacing gate — PTO probes, Initial/Handshake flights,
    /// DPLPMTUD probes, candidate-path validation — still arrive here, and
    /// they routinely leave when the bucket cannot cover them. Clamping the
    /// balance at zero would discard that overdraft: the exempt packet would
    /// consume path capacity for free, and one interval later ordinary
    /// application data would be released as though it had never been sent.
    /// Carrying the debt makes that next packet wait for the rate its
    /// predecessor actually used. Exempt means "may send now", not "outside
    /// the schedule".
    pub fn onPacingSent(self: *CongestionController, bytes: usize, now_us: u64, rtt: RttEstimator) void {
        self.pacer.balance = self.pacingBalance(now_us, rtt) -| @as(i64, @intCast(bytes));
        // Never move the stamp backwards: a coalesced datagram's packets are
        // charged one after another with the same timestamp, and a caller
        // replaying an older `now_us` must not hand the bucket a second refill
        // for time it has already been credited.
        self.pacer.updated_at_us = @max(now_us, self.pacer.updated_at_us orelse now_us);
    }

    pub fn pacingHint(self: CongestionController, now_us: u64, rtt: RttEstimator) PacingHint {
        const allowance = self.congestion_window -| self.bytes_in_flight;
        const balance = self.pacingBalance(now_us, rtt);
        if (allowance == 0) {
            return .{
                .bytes_available = 0,
                .pacing_balance = balance,
                .next_send_time_us = now_us + rtt.ptoDuration(.application),
            };
        }
        return .{
            .bytes_available = allowance,
            .pacing_balance = balance,
            .next_send_time_us = self.pacingReleaseUs(@min(self.max_datagram_size, allowance), now_us, rtt),
        };
    }
};

const PacingGain = struct { numerator: u64, denominator: u64 };

/// Leaky-bucket pacer (#256-C). Credit accrues at the RFC 9002 §7.7 rate
/// `N * congestion_window / smoothed_rtt` and is spent by packets that leave;
/// the bucket's ceiling is what bounds a burst, so a sender whose window has
/// grown large still cannot empty it onto the wire in one pass.
///
/// Deliberately a token bucket rather than a rate estimator: BBR and any
/// other bandwidth model are out of scope here (#240 non-goals). This one only
/// ever *delays* traffic — congestion control and anti-amplification stay the
/// gates that can refuse it outright.
pub const Pacer = struct {
    /// Balance as of `updated_at_us`, in bytes. Signed: see
    /// `CongestionController.onPacingSent` for why an overdraft has to be
    /// carried rather than clamped away.
    balance: i64 = 0,
    /// When `balance` was last charged. Null until the first paced packet: an
    /// unused pacer is treated as full, not empty.
    updated_at_us: ?u64 = null,
    /// The burst ceiling, in maximum-size datagrams. Expressed in packets
    /// because that is the unit the bound is meaningful in — the byte ceiling
    /// follows the sender's current datagram size (#256-A/B) rather than
    /// being frozen at whatever it was when the connection started.
    burst_packets: usize = default_pacer_burst_packets,

    /// The ceiling in bytes, which is the NewReno *initial window* for the
    /// current datagram size — not simply `burst_packets * size`.
    ///
    /// The two part company above a 1472-byte datagram, because
    /// `initialWindow` carries RFC 9002 §7.2's absolute 14720-byte cap and a
    /// packet count does not. Once DPLPMTUD raises the path size to, say,
    /// 2048, ten packets would be 20480 bytes — half again the window a fresh
    /// connection is trusted with, handed to the path in one pass after every
    /// idle period. Taking the smaller of the two keeps the stated contract
    /// true at every datagram size this transport supports.
    pub fn burstBytes(self: Pacer, max_datagram_size: usize) usize {
        return @min(
            self.burst_packets * max_datagram_size,
            CongestionController.initialWindow(max_datagram_size),
        );
    }
};

pub const PacingHint = struct {
    /// Bytes the congestion window still permits in flight.
    bytes_available: usize,
    /// The pacing bucket's balance at the queried instant. Negative when a
    /// packet exempt from the pacing gate overdrew it.
    pacing_balance: i64,
    /// The earliest instant a maximum-size datagram may leave: the queried
    /// time when the sender is eligible now, the pacing release time when the
    /// bucket is short, and a PTO out when the window itself is full.
    next_send_time_us: u64,

    pub fn canSend(self: PacingHint) bool {
        return self.bytes_available > 0;
    }

    /// Whether a `bytes`-sized congestion-controlled datagram may leave right
    /// now: it needs both window and pacing credit.
    pub fn canSendNow(self: PacingHint, bytes: usize) bool {
        return self.bytes_available >= bytes and self.pacing_balance >= @as(i64, @intCast(bytes));
    }
};

pub const RecoveryController = struct {
    ack_ranges: [3]AckRangeSet = .{ .{}, .{}, .{} },
    rtt: RttEstimator = .{},
    tracker: PacketTracker = .{},
    congestion: CongestionController = .{},
    events: EventSink = .{},

    pub fn onPacketReceived(self: *RecoveryController, space: PacketNumberSpace, packet_number: u64) error{TooManyAckRanges}!void {
        try self.ack_ranges[spaceIndex(space)].insert(packet_number);
        self.events.emit(.{ .kind = .ack_range_inserted, .space = space, .packet_number = packet_number });
    }

    /// Whether `packet_number` has already been authenticated in `space` —
    /// query *before* `onPacketReceived` records it. An authenticated
    /// duplicate (distinct from an undecryptable one, which never reaches
    /// this point) must be inert: the driver (`connection.zig`) uses this to
    /// skip re-applying its frame effects, refreshing the idle timer, and
    /// crediting path/anti-amplification state for it — a duplicate proves
    /// nothing new about the peer or the path. Its packet number is already
    /// recorded from the prior `onPacketReceived` call that first saw it, so
    /// it's already covered by the next ACK regardless.
    pub fn wasReceived(self: *const RecoveryController, space: PacketNumberSpace, packet_number: u64) bool {
        return self.ack_ranges[spaceIndex(space)].contains(packet_number);
    }

    pub fn ackFrameForSpace(self: *const RecoveryController, space: PacketNumberSpace, ack_delay_us: u64) ?AckFrameModel {
        return self.ack_ranges[spaceIndex(space)].toAckFrame(ack_delay_us);
    }

    pub fn deinit(self: *RecoveryController, allocator: std.mem.Allocator) void {
        self.tracker.deinit(allocator);
    }

    /// Ordinary traffic remains fixed/bounded and stops before the recovery
    /// reserve. It never consumes allocator-backed recovery overflow.
    pub fn canTrackPacket(self: *const RecoveryController) bool {
        return self.tracker.count + reserved_tracked_packets < max_tracked_packets;
    }

    pub fn ensureRecoveryPacketCapacity(self: *RecoveryController, allocator: std.mem.Allocator, additional: usize) !void {
        try self.tracker.ensureRecoveryCapacity(allocator, additional);
    }

    pub fn canTrackRecoveryPacket(self: *const RecoveryController) bool {
        return self.tracker.canTrackRecoveryPacket();
    }

    pub fn onPacketSentAssumeCapacity(self: *RecoveryController, packet: SentPacket) void {
        std.debug.assert(self.canTrackRecoveryPacket());
        var tracked = packet;
        tracked.rtt_sample_available_at_send = self.rtt.smoothed_rtt_us != null;
        self.tracker.onPacketSentAssumeRecoveryCapacity(tracked);
        if (tracked.in_flight) self.chargeSend(tracked);
    }

    pub fn onPacketSent(self: *RecoveryController, packet: SentPacket) error{TooManyTrackedPackets}!void {
        var tracked = packet;
        tracked.rtt_sample_available_at_send = self.rtt.smoothed_rtt_us != null;
        try self.tracker.onPacketSent(tracked);
        if (tracked.in_flight) self.chargeSend(tracked);
    }

    /// Bill one in-flight packet to the congestion window and, in the same
    /// step, to the pacing bucket (#256-C). Handshake, PTO, DPLPMTUD-probe and
    /// path-validation traffic is charged like everything else even though
    /// none of it *waits* on the pacer: those bytes are genuinely on the wire,
    /// and a bucket that ignored them would let application data follow a
    /// handshake flight at a rate the path was never shown to support.
    ///
    /// The `in_flight` test at both call sites is also what exempts a pure ACK
    /// from the bucket entirely — not delayed by it and not charged to it,
    /// since an ACK-only packet is not congestion-controlled traffic.
    fn chargeSend(self: *RecoveryController, packet: SentPacket) void {
        self.congestion.onPacketSent(packet.size);
        self.congestion.onPacingSent(packet.size, packet.time_sent_us, self.rtt);
    }

    /// Whether a `bytes`-sized congestion-controlled datagram may leave at
    /// `now_us` under the pacing schedule (#256-C).
    pub fn pacingAllows(self: *const RecoveryController, bytes: usize, now_us: u64) bool {
        return self.congestion.pacingAllows(bytes, now_us, self.rtt);
    }

    /// The earliest instant a `bytes`-sized congestion-controlled datagram
    /// becomes eligible; `now_us` when it already is.
    pub fn pacingReleaseUs(self: *const RecoveryController, bytes: usize, now_us: u64) u64 {
        return self.congestion.pacingReleaseUs(bytes, now_us, self.rtt);
    }

    pub fn onAcked(self: *RecoveryController, space: PacketNumberSpace, packet_number: u64, now_us: u64, ack_delay_us: u64) error{OutOfMemory}!void {
        if (try self.tracker.onAcked(space, packet_number, now_us)) |acked| {
            self.congestion.onPacketAcked(acked.packet);
            if (acked.rtt_sample_us) |sample| self.rtt.update(sample, ack_delay_us);
            self.events.emit(.{
                .kind = .packet_acked,
                .space = space,
                .packet_number = packet_number,
                .bytes_in_flight = self.tracker.bytes_in_flight,
                .congestion_window = self.congestion.congestion_window,
                .rtt_us = self.rtt.smoothed_rtt_us,
            });
        }
    }

    pub fn detectLost(self: *RecoveryController, space: PacketNumberSpace, now_us: u64) LossResult {
        const result = self.tracker.detectLost(space, now_us, self.rtt);
        if (result.lost_bytes > 0) {
            // Probe bytes leave the ledger but drive no congestion event
            // (RFC 9000 §14.4), and the event's timestamp comes from ordinary
            // traffic so a probe cannot start a recovery period on its own.
            if (result.probe_lost_bytes > 0) self.congestion.onProbePacketsLost(result.probe_lost_bytes);
            const congestion_bytes = result.lost_bytes - result.probe_lost_bytes;
            if (congestion_bytes > 0) {
                self.congestion.onPacketsLost(result.largest_ordinary_lost_time_sent_us.?, congestion_bytes, now_us);
                if (result.persistent_congestion) self.congestion.onPersistentCongestion();
            }
            self.events.emit(.{
                .kind = .packet_lost,
                .space = space,
                .bytes_in_flight = self.tracker.bytes_in_flight,
                .congestion_window = self.congestion.congestion_window,
            });
            if (result.persistent_congestion) {
                self.events.emit(.{
                    .kind = .persistent_congestion,
                    .space = space,
                    .bytes_in_flight = self.tracker.bytes_in_flight,
                    .congestion_window = self.congestion.congestion_window,
                });
            }
        }
        return result;
    }

    /// Reinitialize path-dependent state after migrating to a path with new
    /// characteristics (RFC 9000 §9.4): the RTT estimate and congestion
    /// controller reset to their initial values, while packet/ACK tracking
    /// continues — packets in flight on the old path are still accounted for
    /// and can still be acknowledged or declared lost. Skip this for a NAT
    /// rebinding that only changed the peer's port; `path.zig` documents the
    /// policy.
    ///
    /// `bytes_in_flight` deliberately carries over: this endpoint has one
    /// send ledger, and old-path packets drain from it through the normal
    /// ack/loss paths (zeroing it would double-count capacity now and
    /// mis-decrement later). The cost is that a large old-path backlog can
    /// briefly gate sends on the fresh window until it drains — true
    /// per-path congestion isolation during concurrent validation needs
    /// per-path controllers, which is multipath-adjacent work outside #251.
    pub fn resetForPathMigration(self: *RecoveryController) void {
        self.rtt = RttEstimator.init(self.rtt.max_ack_delay_us);
        // A migration resets the measured window, not the sender's datagram
        // size: the packet builder is still emitting that size, and #256-B
        // revalidates the new path's PMTU separately. The pacer goes back to
        // its default with it (#256-C) — its rate is derived from the window
        // that was just discarded, and credit earned against the old path's
        // capacity says nothing about the new one.
        self.congestion = .{
            .bytes_in_flight = self.congestion.bytes_in_flight,
            .max_datagram_size = self.congestion.max_datagram_size,
            .congestion_window = CongestionController.initialWindow(self.congestion.max_datagram_size),
        };
    }

    /// RFC 9002 §6.4: drop a packet-number space's tracked packets and ACK
    /// state when its keys are discarded. Returns the in-flight bytes removed.
    pub fn onKeysDiscarded(self: *RecoveryController, space: PacketNumberSpace) usize {
        const removed = self.tracker.dropSpace(space);
        self.congestion.bytes_in_flight -|= removed;
        self.ack_ranges[spaceIndex(space)].clear();
        return removed;
    }
};

fn spaceIndex(space: PacketNumberSpace) usize {
    return switch (space) {
        .initial => 0,
        .handshake => 1,
        .application => 2,
    };
}

fn absDiff(a: u64, b: u64) u64 {
    return if (a >= b) a - b else b - a;
}

fn ceilDiv(numerator: u64, denominator: u64) u64 {
    return (numerator + denominator - 1) / denominator;
}

const testing = std.testing;

test "ACK range tracker merges gaps reordering and duplicate ACKs" {
    var ranges = AckRangeSet{};
    try ranges.insert(10);
    try ranges.insert(12);
    try ranges.insert(11);
    try ranges.insert(15);
    try ranges.insert(12);

    try testing.expectEqual(@as(usize, 2), ranges.count);
    try testing.expectEqual(AckRange.init(10, 12), ranges.ranges[0]);
    try testing.expectEqual(AckRange.init(15, 15), ranges.ranges[1]);
    try testing.expect(ranges.contains(11));
    try testing.expect(!ranges.contains(14));
    try testing.expectEqual(@as(u64, 15), ranges.largest().?);
}

test "ACK frame model emits QUIC gaps from descending ranges" {
    var ranges = AckRangeSet{};
    try ranges.insertRange(AckRange.init(1, 2));
    try ranges.insertRange(AckRange.init(5, 7));
    try ranges.insert(10);

    const frame = ranges.toAckFrame(123).?;
    try testing.expectEqual(@as(u64, 10), frame.largest_acknowledged);
    try testing.expectEqual(@as(u64, 123), frame.ack_delay_us);
    try testing.expectEqual(@as(u64, 0), frame.first_ack_range);
    try testing.expectEqual(@as(usize, 2), frame.range_count);
    try testing.expectEqual(AckFrameRange{ .gap = 1, .length = 2 }, frame.ranges[0]);
    try testing.expectEqual(AckFrameRange{ .gap = 1, .length = 1 }, frame.ranges[1]);
}

test "recovery controller keeps ACK ranges per packet-number space" {
    var recovery = RecoveryController{};
    try recovery.onPacketReceived(.initial, 1);
    try recovery.onPacketReceived(.application, 1);
    try recovery.onPacketReceived(.application, 2);

    const initial_ack = recovery.ackFrameForSpace(.initial, 0).?;
    try testing.expectEqual(@as(u64, 1), initial_ack.largest_acknowledged);
    try testing.expectEqual(@as(u64, 0), initial_ack.first_ack_range);
    try testing.expectEqual(@as(usize, 0), initial_ack.range_count);

    const application_ack = recovery.ackFrameForSpace(.application, 0).?;
    try testing.expectEqual(@as(u64, 2), application_ack.largest_acknowledged);
    try testing.expectEqual(@as(u64, 1), application_ack.first_ack_range);
    try testing.expectEqual(@as(usize, 0), application_ack.range_count);

    try testing.expect(recovery.ackFrameForSpace(.handshake, 0) == null);
}

test "RTT estimator caps ACK delay and maintains min RTT" {
    var rtt = RttEstimator.init(25_000);
    rtt.update(100_000, 500_000);
    try testing.expectEqual(@as(u64, 100_000), rtt.latest_rtt_us.?);
    try testing.expectEqual(@as(u64, 100_000), rtt.smoothed_rtt_us.?);
    try testing.expectEqual(@as(u64, 50_000), rtt.rttvar_us.?);
    try testing.expectEqual(@as(u64, 100_000), rtt.min_rtt_us.?);

    rtt.update(200_000, 50_000);
    try testing.expectEqual(@as(u64, 109_375), rtt.smoothed_rtt_us.?);
    try testing.expectEqual(@as(u64, 56_250), rtt.rttvar_us.?);
    try testing.expectEqual(@as(u64, 100_000), rtt.min_rtt_us.?);
}

test "PTO duration is packet-number-space aware" {
    var rtt = RttEstimator.init(25_000);
    rtt.update(100_000, 0);

    try testing.expectEqual(@as(u64, 300_000), rtt.ptoDuration(.initial));
    try testing.expectEqual(@as(u64, 300_000), rtt.ptoDuration(.handshake));
    try testing.expectEqual(@as(u64, 325_000), rtt.ptoDuration(.application));
}

test "packet tracker accounts bytes in flight across ACKs" {
    var tracker = PacketTracker{};
    try tracker.onPacketSent(.{ .space = .application, .packet_number = 1, .time_sent_us = 1_000, .size = 1200 });
    try tracker.onPacketSent(.{ .space = .application, .packet_number = 2, .time_sent_us = 2_000, .size = 800 });
    try testing.expectEqual(@as(usize, 2_000), tracker.bytes_in_flight);

    const acked = (try tracker.onAcked(.application, 1, 3_500)).?;
    try testing.expectEqual(@as(u64, 2_500), acked.rtt_sample_us.?);
    try testing.expectEqual(@as(usize, 800), tracker.bytes_in_flight);
    try testing.expectEqual(@as(usize, 1), tracker.count);
}

test "loss detection covers packet threshold and time threshold" {
    var tracker = PacketTracker{};
    var rtt = RttEstimator.init(0);
    rtt.update(100, 0);

    try tracker.onPacketSent(.{ .space = .application, .packet_number = 1, .time_sent_us = 0, .size = 100 });
    try tracker.onPacketSent(.{ .space = .application, .packet_number = 2, .time_sent_us = 10, .size = 100 });
    try tracker.onPacketSent(.{ .space = .application, .packet_number = 3, .time_sent_us = 20, .size = 100 });
    try tracker.onPacketSent(.{ .space = .application, .packet_number = 4, .time_sent_us = 30, .size = 100 });
    try tracker.onPacketSent(.{ .space = .application, .packet_number = 5, .time_sent_us = 40, .size = 100 });

    _ = try tracker.onAcked(.application, 5, 100);
    const threshold_loss = tracker.detectLost(.application, 100, rtt);
    try testing.expectEqual(@as(usize, 2), threshold_loss.packet_threshold_losses);
    try testing.expectEqual(@as(usize, 200), threshold_loss.lost_bytes);
    try testing.expectEqual(@as(u64, 10), threshold_loss.largest_lost_time_sent_us.?);
    try testing.expect(!threshold_loss.persistent_congestion);
    try testing.expectEqual(@as(usize, 200), tracker.bytes_in_flight);

    _ = try tracker.onAcked(.application, 4, 120);
    const time_loss = tracker.detectLost(.application, 2_000, rtt);
    try testing.expectEqual(@as(usize, 1), time_loss.time_threshold_losses);
    try testing.expectEqual(@as(usize, 100), time_loss.lost_bytes);
    try testing.expectEqual(@as(u64, 20), time_loss.largest_lost_time_sent_us.?);
    try testing.expect(!time_loss.persistent_congestion);
    try testing.expectEqual(@as(usize, 0), tracker.bytes_in_flight);
}

test "loss detection reports persistent congestion only for a real duration episode" {
    var tracker = PacketTracker{};
    var rtt = RttEstimator.init(0);
    rtt.update(100_000, 0);
    const duration = PacketTracker.persistentCongestionDuration(rtt).?;

    try tracker.onPacketSent(.{ .space = .application, .packet_number = 1, .time_sent_us = 0, .size = 100, .rtt_sample_available_at_send = true });
    try tracker.onPacketSent(.{ .space = .application, .packet_number = 2, .time_sent_us = duration, .size = 100, .rtt_sample_available_at_send = true });
    try tracker.onPacketSent(.{ .space = .application, .packet_number = 3, .time_sent_us = duration + 1, .size = 100, .rtt_sample_available_at_send = true });
    _ = try tracker.onAcked(.application, 3, duration + 2);

    const loss = tracker.detectLost(.application, duration * 2, rtt);
    try testing.expectEqual(@as(usize, 2), loss.time_threshold_losses);
    try testing.expect(loss.persistent_congestion);
}

test "persistent congestion ignores non-ack-eliciting boundaries and no-prior-rtt packets" {
    var rtt = RttEstimator.init(0);
    rtt.update(100_000, 0);
    const duration = PacketTracker.persistentCongestionDuration(rtt).?;

    var padding = PacketTracker{};
    try padding.onPacketSent(.{ .space = .application, .packet_number = 1, .time_sent_us = 0, .size = 100, .ack_eliciting = false, .rtt_sample_available_at_send = true });
    try padding.onPacketSent(.{ .space = .application, .packet_number = 2, .time_sent_us = duration, .size = 100, .ack_eliciting = false, .rtt_sample_available_at_send = true });
    try padding.onPacketSent(.{ .space = .application, .packet_number = 3, .time_sent_us = duration + 1, .size = 100, .rtt_sample_available_at_send = true });
    _ = try padding.onAcked(.application, 3, duration + 2);
    try testing.expect(!padding.detectLost(.application, duration * 2, rtt).persistent_congestion);

    var no_prior = PacketTracker{};
    try no_prior.onPacketSent(.{ .space = .application, .packet_number = 1, .time_sent_us = 0, .size = 100 });
    try no_prior.onPacketSent(.{ .space = .application, .packet_number = 2, .time_sent_us = duration, .size = 100 });
    try no_prior.onPacketSent(.{ .space = .application, .packet_number = 3, .time_sent_us = duration + 1, .size = 100, .rtt_sample_available_at_send = true });
    _ = try no_prior.onAcked(.application, 3, duration + 2);
    try testing.expect(!no_prior.detectLost(.application, duration * 2, rtt).persistent_congestion);
}

test "persistent congestion resets on ACK inside candidate interval" {
    var tracker = PacketTracker{};
    var rtt = RttEstimator.init(0);
    rtt.update(100_000, 0);
    const duration = PacketTracker.persistentCongestionDuration(rtt).?;

    try tracker.onPacketSent(.{ .space = .application, .packet_number = 1, .time_sent_us = 0, .size = 100, .rtt_sample_available_at_send = true });
    try tracker.onPacketSent(.{ .space = .application, .packet_number = 2, .time_sent_us = duration / 2, .size = 100, .rtt_sample_available_at_send = true });
    try tracker.onPacketSent(.{ .space = .application, .packet_number = 3, .time_sent_us = duration, .size = 100, .rtt_sample_available_at_send = true });
    try tracker.onPacketSent(.{ .space = .application, .packet_number = 4, .time_sent_us = duration + 1, .size = 100, .rtt_sample_available_at_send = true });
    _ = try tracker.onAcked(.application, 2, duration + 2);
    _ = try tracker.onAcked(.application, 4, duration + 3);
    try testing.expect(!tracker.detectLost(.application, duration * 2, rtt).persistent_congestion);
}

test "persistent congestion includes max_ack_delay outside application space" {
    var rtt = RttEstimator.init(25_000);
    rtt.update(100_000, 0);
    const duration = PacketTracker.persistentCongestionDuration(rtt).?;
    try testing.expect(duration > rtt.ptoDuration(.initial) * 3);

    var tracker = PacketTracker{};
    try tracker.onPacketSent(.{ .space = .initial, .packet_number = 1, .time_sent_us = 0, .size = 100, .rtt_sample_available_at_send = true });
    try tracker.onPacketSent(.{ .space = .initial, .packet_number = 2, .time_sent_us = rtt.ptoDuration(.initial) * 3, .size = 100, .rtt_sample_available_at_send = true });
    try tracker.onPacketSent(.{ .space = .initial, .packet_number = 3, .time_sent_us = duration + 1, .size = 100, .rtt_sample_available_at_send = true });
    _ = try tracker.onAcked(.initial, 3, duration + 2);
    try testing.expect(!tracker.detectLost(.initial, duration * 2, rtt).persistent_congestion);
}

test "persistent congestion can come from packet-threshold loss across calls" {
    var tracker = PacketTracker{};
    var rtt = RttEstimator.init(0);
    rtt.update(100_000, 0);
    const duration = PacketTracker.persistentCongestionDuration(rtt).?;

    try tracker.onPacketSent(.{ .space = .application, .packet_number = 1, .time_sent_us = 0, .size = 100, .rtt_sample_available_at_send = true });
    try tracker.onPacketSent(.{ .space = .application, .packet_number = 2, .time_sent_us = duration, .size = 100, .rtt_sample_available_at_send = true });
    try tracker.onPacketSent(.{ .space = .application, .packet_number = 3, .time_sent_us = duration + 1, .size = 100, .rtt_sample_available_at_send = true });
    try tracker.onPacketSent(.{ .space = .application, .packet_number = 4, .time_sent_us = duration + 2, .size = 100, .rtt_sample_available_at_send = true });
    try tracker.onPacketSent(.{ .space = .application, .packet_number = 5, .time_sent_us = duration + 3, .size = 100, .rtt_sample_available_at_send = true });
    _ = try tracker.onAcked(.application, 4, duration + 4);

    const first = tracker.detectLost(.application, duration + 4, rtt);
    try testing.expect(!first.persistent_congestion);
    _ = try tracker.onAcked(.application, 5, duration + 5);
    const second = tracker.detectLost(.application, duration + 6, rtt);
    try testing.expect(second.persistent_congestion);
}

test "persistent congestion split by ACK keeps current lost packet as new boundary" {
    var tracker = PacketTracker{};
    var rtt = RttEstimator.init(0);
    rtt.update(100_000, 0);
    const duration = PacketTracker.persistentCongestionDuration(rtt).?;

    try tracker.onPacketSent(.{ .space = .application, .packet_number = 1, .time_sent_us = 0, .size = 100, .rtt_sample_available_at_send = true });
    try tracker.onPacketSent(.{ .space = .application, .packet_number = 4, .time_sent_us = duration / 2, .size = 100, .rtt_sample_available_at_send = true });
    try tracker.onPacketSent(.{ .space = .application, .packet_number = 2, .time_sent_us = duration, .size = 100, .rtt_sample_available_at_send = true });
    try tracker.onPacketSent(.{ .space = .application, .packet_number = 3, .time_sent_us = duration * 2, .size = 100, .rtt_sample_available_at_send = true });
    try tracker.onPacketSent(.{ .space = .application, .packet_number = 6, .time_sent_us = duration * 2 + 1, .size = 100, .rtt_sample_available_at_send = true });

    _ = try tracker.onAcked(.application, 4, duration / 2 + 1);
    const first = tracker.detectLost(.application, duration + 1, rtt);
    try testing.expect(!first.persistent_congestion);

    _ = try tracker.onAcked(.application, 6, duration * 2 + 2);
    const second = tracker.detectLost(.application, duration * 3, rtt);
    try testing.expect(second.persistent_congestion);
}

test "persistent congestion ACK barrier is not evicted by unrelated ACKs" {
    var tracker = PacketTracker{};
    var rtt = RttEstimator.init(0);
    rtt.update(100_000, 0);
    const duration = PacketTracker.persistentCongestionDuration(rtt).?;
    const base: u64 = 100;

    try tracker.onPacketSent(.{ .space = .application, .packet_number = 1, .time_sent_us = base, .size = 100, .rtt_sample_available_at_send = true });
    try tracker.onPacketSent(.{ .space = .application, .packet_number = 4, .time_sent_us = base + 50, .size = 100, .rtt_sample_available_at_send = true });
    var pn: u64 = 5;
    while (pn < 21) : (pn += 1) {
        try tracker.onPacketSent(.{ .space = .application, .packet_number = pn, .time_sent_us = base - 50, .size = 100, .rtt_sample_available_at_send = true });
    }
    try tracker.onPacketSent(.{ .space = .application, .packet_number = 30, .time_sent_us = base + duration, .size = 100, .rtt_sample_available_at_send = true });
    try tracker.onPacketSent(.{ .space = .application, .packet_number = 31, .time_sent_us = base + duration * 2, .size = 100, .rtt_sample_available_at_send = true });
    try tracker.onPacketSent(.{ .space = .application, .packet_number = 34, .time_sent_us = base + duration * 2 + 1, .size = 100, .rtt_sample_available_at_send = true });

    _ = try tracker.onAcked(.application, 4, base + 51);
    const first = tracker.detectLost(.application, base + duration / 2, rtt);
    try testing.expect(!first.persistent_congestion);

    pn = 5;
    while (pn < 21) : (pn += 1) {
        _ = try tracker.onAcked(.application, pn, base + 52 + pn);
    }
    const middle = tracker.detectLost(.application, base + duration / 2 + 1, rtt);
    try testing.expect(!middle.persistent_congestion);

    _ = try tracker.onAcked(.application, 34, base + duration * 2 + 2);
    const second = tracker.detectLost(.application, base + duration * 3, rtt);
    try testing.expect(second.persistent_congestion);
}

test "persistent congestion remains detectable after more than tracker-capacity ACKs" {
    var tracker = PacketTracker{};
    var rtt = RttEstimator.init(0);
    rtt.update(100_000, 0);
    const duration = PacketTracker.persistentCongestionDuration(rtt).?;

    var pn: u64 = 1;
    while (pn <= max_tracked_packets + 8) : (pn += 1) {
        try tracker.onPacketSent(.{
            .space = .application,
            .packet_number = pn,
            .time_sent_us = pn,
            .size = 100,
            .rtt_sample_available_at_send = true,
        });
        _ = try tracker.onAcked(.application, pn, pn + 1);
    }
    try testing.expectEqual(@as(usize, 0), tracker.acked_send_time_range_counts[spaceIndex(.application)]);

    const base: u64 = 10_000_000;
    try tracker.onPacketSent(.{ .space = .application, .packet_number = pn, .time_sent_us = base, .size = 100, .rtt_sample_available_at_send = true });
    try tracker.onPacketSent(.{ .space = .application, .packet_number = pn + 1, .time_sent_us = base + duration, .size = 100, .rtt_sample_available_at_send = true });
    try tracker.onPacketSent(.{ .space = .application, .packet_number = pn + 2, .time_sent_us = base + duration + 1, .size = 100, .rtt_sample_available_at_send = true });
    _ = try tracker.onAcked(.application, pn + 2, base + duration + 2);

    const loss = tracker.detectLost(.application, base + duration * 2, rtt);
    try testing.expect(loss.persistent_congestion);
}

test "persistent congestion ACK ranges preserve gaps across tracker-capacity ACKs" {
    var tracker = PacketTracker{};
    defer tracker.deinit(testing.allocator);
    var rtt = RttEstimator.init(0);
    rtt.update(100_000, 0);
    const duration = PacketTracker.persistentCongestionDuration(rtt).?;
    const a: u64 = 1_000;
    const b = a + duration;
    const c = b + duration;

    tracker.observePersistentCandidate(.application, .{ .space = .application, .packet_number = 1, .time_sent_us = a, .size = 100, .rtt_sample_available_at_send = true });

    var offset: u64 = 1;
    while (offset <= 80) : (offset += 1) {
        try tracker.noteAckedSendTime(.application, a + offset);
    }
    offset = 1;
    while (offset <= 80) : (offset += 1) {
        try tracker.noteAckedSendTime(.application, c + offset);
    }
    try testing.expectEqual(@as(usize, 2), tracker.acked_send_time_range_counts[spaceIndex(.application)]);

    tracker.observePersistentCandidate(.application, .{ .space = .application, .packet_number = 2, .time_sent_us = b, .size = 100, .rtt_sample_available_at_send = true });
    try testing.expectEqual(@as(usize, 1), tracker.acked_send_time_range_counts[spaceIndex(.application)]);

    tracker.observePersistentCandidate(.application, .{ .space = .application, .packet_number = 3, .time_sent_us = c, .size = 100, .rtt_sample_available_at_send = true });
    const candidate = tracker.persistent_candidates[spaceIndex(.application)];
    try testing.expect(candidate.active);
    try testing.expectEqual(b, candidate.start_us);
    try testing.expectEqual(c, candidate.end_us);
    try testing.expect(!tracker.hasAckedSendTimeInCandidate(.application, candidate));
    try testing.expect(candidate.end_us - candidate.start_us >= duration);
}

test "persistent congestion stale candidate retires behind later ACK barrier" {
    var tracker = PacketTracker{};
    defer tracker.deinit(testing.allocator);

    tracker.observePersistentCandidate(.application, .{
        .space = .application,
        .packet_number = 1,
        .time_sent_us = 0,
        .size = 100,
        .rtt_sample_available_at_send = true,
    });

    var pn: u64 = 2;
    while (pn <= max_tracked_packets + max_ack_barrier_overflow_ranges + 64) : (pn += 1) {
        const sent_at = pn * 10;
        try tracker.onPacketSent(.{
            .space = .application,
            .packet_number = pn,
            .time_sent_us = sent_at,
            .size = 100,
            .rtt_sample_available_at_send = true,
        });
        _ = try tracker.onAcked(.application, pn, sent_at + 1);
    }

    const space_idx = spaceIndex(.application);
    try testing.expect(!tracker.persistent_candidates[space_idx].active);
    try testing.expectEqual(@as(usize, 0), tracker.acked_send_time_range_counts[space_idx]);
    try testing.expectEqual(@as(usize, 0), tracker.acked_send_time_range_overflow_counts[space_idx]);
}

test "persistent congestion candidate survives ACK while an earlier unresolved packet can extend it" {
    var tracker = PacketTracker{};
    var rtt = RttEstimator.init(0);
    rtt.update(100_000, 0);
    const duration = PacketTracker.persistentCongestionDuration(rtt).?;

    tracker.observePersistentCandidate(.application, .{
        .space = .application,
        .packet_number = 1,
        .time_sent_us = 0,
        .size = 100,
        .rtt_sample_available_at_send = true,
    });
    try tracker.onPacketSent(.{
        .space = .application,
        .packet_number = 2,
        .time_sent_us = duration,
        .size = 100,
        .rtt_sample_available_at_send = true,
    });
    try tracker.onPacketSent(.{
        .space = .application,
        .packet_number = 5,
        .time_sent_us = duration + 100,
        .size = 100,
        .rtt_sample_available_at_send = true,
    });

    _ = try tracker.onAcked(.application, 5, duration + 101);
    try testing.expect(tracker.persistent_candidates[spaceIndex(.application)].active);

    const loss = tracker.detectLost(.application, duration * 2, rtt);
    try testing.expect(loss.persistent_congestion);
}

test "persistent congestion ACK barriers spill beyond fixed tracker capacity" {
    var tracker = PacketTracker{};
    defer tracker.deinit(testing.allocator);

    tracker.observePersistentCandidate(.application, .{
        .space = .application,
        .packet_number = 1,
        .time_sent_us = 0,
        .size = 100,
        .rtt_sample_available_at_send = true,
    });
    // Keep one candidate-eligible packet unresolved before every later ACK
    // barrier. That makes the old candidate genuinely capable of extending,
    // so the barriers must remain exact rather than being retired for space.
    try tracker.onPacketSent(.{
        .space = .application,
        .packet_number = 10_000,
        .time_sent_us = 1,
        .size = 100,
        .rtt_sample_available_at_send = true,
    });

    var pn: u64 = 2;
    while (pn <= max_tracked_packets + 2) : (pn += 1) {
        const sent_at = pn * 10;
        try tracker.onPacketSent(.{
            .space = .application,
            .packet_number = pn,
            .time_sent_us = sent_at,
            .size = 100,
            .rtt_sample_available_at_send = true,
        });
        _ = try tracker.onAcked(.application, pn, sent_at + 1);
    }

    const space_idx = spaceIndex(.application);
    try testing.expectEqual(@as(usize, max_tracked_packets), tracker.acked_send_time_range_counts[space_idx]);
    try testing.expectEqual(@as(usize, 1), tracker.acked_send_time_range_overflow_counts[space_idx]);
    const candidate = tracker.persistent_candidates[space_idx];
    try testing.expect(tracker.hasAckedSendTimeInCandidate(.application, .{
        .active = true,
        .start_us = candidate.start_us,
        .end_us = (max_tracked_packets + 2) * 10,
        .boundaries_have_prior_rtt = true,
    }));
}

test "persistent congestion ACK barrier budget fails connection-locally" {
    var tracker = PacketTracker{};
    defer tracker.deinit(testing.allocator);

    tracker.observePersistentCandidate(.application, .{
        .space = .application,
        .packet_number = 1,
        .time_sent_us = 0,
        .size = 100,
        .rtt_sample_available_at_send = true,
    });
    try tracker.onPacketSent(.{
        .space = .application,
        .packet_number = 10_000,
        .time_sent_us = 1,
        .size = 100,
        .rtt_sample_available_at_send = true,
    });

    var pn: u64 = 2;
    while (pn <= max_tracked_packets + max_ack_barrier_overflow_ranges + 1) : (pn += 1) {
        const sent_at = pn * 10;
        try tracker.onPacketSent(.{
            .space = .application,
            .packet_number = pn,
            .time_sent_us = sent_at,
            .size = 100,
            .rtt_sample_available_at_send = true,
        });
        _ = try tracker.onAcked(.application, pn, sent_at + 1);
    }

    const overflowing_pn = max_tracked_packets + max_ack_barrier_overflow_ranges + 2;
    const sent_at = overflowing_pn * 10;
    try tracker.onPacketSent(.{
        .space = .application,
        .packet_number = overflowing_pn,
        .time_sent_us = sent_at,
        .size = 100,
        .rtt_sample_available_at_send = true,
    });
    try testing.expectError(error.OutOfMemory, tracker.onAcked(.application, overflowing_pn, sent_at + 1));

    const space_idx = spaceIndex(.application);
    try testing.expectEqual(@as(usize, max_tracked_packets), tracker.acked_send_time_range_counts[space_idx]);
    try testing.expectEqual(@as(usize, max_ack_barrier_overflow_ranges), tracker.acked_send_time_range_overflow_counts[space_idx]);
}

test "discarding Initial state clears persistent-congestion bookkeeping for Retry" {
    var controller = RecoveryController{};
    controller.rtt = RttEstimator.init(0);
    controller.rtt.update(100_000, 0);
    const duration = PacketTracker.persistentCongestionDuration(controller.rtt).?;

    try controller.onPacketSent(.{ .space = .initial, .packet_number = 0, .time_sent_us = 0, .size = 100 });
    try controller.onPacketSent(.{ .space = .initial, .packet_number = 1, .time_sent_us = duration, .size = 100 });
    try controller.onPacketSent(.{ .space = .initial, .packet_number = 2, .time_sent_us = duration + 1, .size = 100 });
    try controller.onAcked(.initial, 2, duration + 100_001, 0);
    try testing.expect(controller.detectLost(.initial, duration * 2).persistent_congestion);

    const idx = spaceIndex(.initial);
    try testing.expect(controller.tracker.persistent_candidates[idx].active);
    _ = controller.onKeysDiscarded(.initial);
    try testing.expect(controller.tracker.largest_acked[idx] == null);
    try testing.expect(!controller.tracker.persistent_candidates[idx].active);
    try testing.expectEqual(@as(usize, 0), controller.tracker.acked_send_time_range_counts[idx]);

    // Retry restarts the Initial packet number space. The replacement flight
    // must build a fresh loss episode rather than inheriting any old boundary
    // or ACK evidence.
    try controller.onPacketSent(.{ .space = .initial, .packet_number = 0, .time_sent_us = duration * 3, .size = 100 });
    try controller.onPacketSent(.{ .space = .initial, .packet_number = 1, .time_sent_us = duration * 4, .size = 100 });
    try controller.onPacketSent(.{ .space = .initial, .packet_number = 2, .time_sent_us = duration * 4 + 1, .size = 100 });
    try controller.onAcked(.initial, 2, duration * 4 + 100_001, 0);
    try testing.expect(controller.detectLost(.initial, duration * 5).persistent_congestion);
}

test "NewReno baseline halves cwnd and persistent congestion uses minimum window" {
    var cc = CongestionController{};
    const initial = cc.congestion_window;
    cc.onPacketSent(4_000);
    cc.onPacketAcked(.{ .space = .application, .packet_number = 1, .time_sent_us = 1_000, .size = 1_200 });
    try testing.expect(cc.congestion_window > initial);
    try testing.expectEqual(@as(usize, 2_800), cc.bytes_in_flight);

    cc.onPacketsLost(2_000, 1_200, 50_000);
    try testing.expectEqual(@as(usize, 1_600), cc.bytes_in_flight);
    try testing.expect(cc.congestion_window >= cc.minWindow());
    try testing.expectEqual(cc.congestion_window, cc.ssthresh);

    cc.onPersistentCongestion();
    try testing.expectEqual(cc.minWindow(), cc.congestion_window);
    try testing.expectEqual(cc.minWindow(), cc.ssthresh);
}

test "NewReno recovery period prevents repeated cwnd cuts and old ACK growth" {
    var cc = CongestionController{};
    const initial = cc.congestion_window;
    cc.onPacketSent(6_000);

    cc.onPacketsLost(2_000, 1_200, 50_000);
    const after_first_loss = cc.congestion_window;
    try testing.expect(after_first_loss < initial);
    try testing.expectEqual(@as(usize, 4_800), cc.bytes_in_flight);

    cc.onPacketsLost(2_000, 1_200, 60_000);
    try testing.expectEqual(after_first_loss, cc.congestion_window);
    try testing.expectEqual(@as(usize, 3_600), cc.bytes_in_flight);

    cc.onPacketAcked(.{ .space = .application, .packet_number = 1, .time_sent_us = 1_500, .size = 1_200 });
    try testing.expectEqual(after_first_loss, cc.congestion_window);
    try testing.expectEqual(@as(usize, 2_400), cc.bytes_in_flight);

    cc.onPacketAcked(.{ .space = .application, .packet_number = 5, .time_sent_us = 70_000, .size = 1_200 });
    try testing.expect(cc.congestion_window > after_first_loss);
    try testing.expect(cc.recovery_start_time_us == null);
    try testing.expectEqual(@as(usize, 1_200), cc.bytes_in_flight);
}

/// A controller parked in congestion avoidance with a 12 kB window and a
/// 100 ms smoothed RTT, so every pacing number below is exact:
/// `1.25 * 12_000 B / 0.1 s` is 150 kB/s, one 1200-byte datagram every 8 ms,
/// and the burst ceiling is `10 * 1200 = 12_000` bytes — ten datagrams.
fn pacingFixture() struct { cc: CongestionController, rtt: RttEstimator } {
    var rtt = RttEstimator.init(25_000);
    rtt.update(100_000, 0);
    return .{
        .cc = .{ .congestion_window = 12_000, .ssthresh = 12_000 },
        .rtt = rtt,
    };
}

test "pacing: a bounded burst leaves back to back, then the bucket is empty" {
    var fixture = pacingFixture();
    const cc = &fixture.cc;
    const now: u64 = 1_000_000;

    try testing.expectEqual(@as(i64, 12_000), cc.pacingBalance(now, fixture.rtt));

    // The whole burst leaves at one instant of the fake clock: nothing here
    // advances time, so the only thing that can stop the tenth datagram is the
    // bucket's ceiling.
    var sent: usize = 0;
    while (cc.pacingAllows(1_200, now, fixture.rtt)) : (sent += 1) {
        cc.onPacingSent(1_200, now, fixture.rtt);
        if (sent > default_pacer_burst_packets) break;
    }
    try testing.expectEqual(default_pacer_burst_packets, sent);
    try testing.expectEqual(@as(i64, 0), cc.pacingBalance(now, fixture.rtt));
    try testing.expect(!cc.pacingAllows(1_200, now, fixture.rtt));
}

test "pacing: the release schedule spaces datagrams at the RFC 9002 rate" {
    var fixture = pacingFixture();
    const cc = &fixture.cc;
    var now: u64 = 1_000_000;

    while (cc.pacingAllows(1_200, now, fixture.rtt)) cc.onPacingSent(1_200, now, fixture.rtt);

    // 1200 bytes at 150 kB/s is 8 ms, and the deadline is exact rather than
    // approximate: a datagram is refused at 7999 µs and released at 8000.
    const release = cc.pacingReleaseUs(1_200, now, fixture.rtt);
    try testing.expectEqual(now + 8_000, release);
    try testing.expect(!cc.pacingAllows(1_200, release - 1, fixture.rtt));
    try testing.expect(cc.pacingAllows(1_200, release, fixture.rtt));

    // And the spacing is a steady interval, not a one-off: each send moves the
    // next release exactly one interval on.
    var previous = now;
    var step: usize = 0;
    while (step < 4) : (step += 1) {
        now = cc.pacingReleaseUs(1_200, now, fixture.rtt);
        try testing.expectEqual(previous + 8_000, now);
        try testing.expect(cc.pacingAllows(1_200, now, fixture.rtt));
        cc.onPacingSent(1_200, now, fixture.rtt);
        // One datagram's worth of credit was earned and one was spent, so the
        // sender never banks a second burst while it is transmitting.
        try testing.expect(cc.pacingBalance(now, fixture.rtt) < 1_200);
        previous = now;
    }
}

test "pacing: an exempt packet carries its debt instead of sending for free" {
    var fixture = pacingFixture();
    const cc = &fixture.cc;
    const now: u64 = 1_000_000;
    while (cc.pacingAllows(1_200, now, fixture.rtt)) cc.onPacingSent(1_200, now, fixture.rtt);
    try testing.expectEqual(@as(i64, 0), cc.pacingBalance(now, fixture.rtt));

    // A PTO probe, handshake flight, DPLPMTUD probe or path-validation packet
    // bypasses the pacing gate — but it still puts 1200 bytes on the wire, and
    // `chargeSend` still bills it. With the bucket already empty the balance
    // has to go *negative*: clamping it at zero would hand the path a free
    // datagram's worth of rate.
    cc.onPacingSent(1_200, now, fixture.rtt);
    try testing.expectEqual(@as(i64, -1_200), cc.pacingBalance(now, fixture.rtt));

    // One ordinary interval later the debt is exactly repaid and nothing more,
    // so application data is *still* blocked — where a discarded overdraft
    // would have released it as though the exempt packet never existed.
    const one_interval = now + 8_000;
    try testing.expectEqual(@as(i64, 0), cc.pacingBalance(one_interval, fixture.rtt));
    try testing.expect(!cc.pacingAllows(1_200, one_interval, fixture.rtt));

    // It becomes eligible only after the debt *plus* its own credit has
    // accrued — two intervals, which is what the release time reports.
    try testing.expectEqual(now + 16_000, cc.pacingReleaseUs(1_200, now, fixture.rtt));
    try testing.expect(cc.pacingAllows(1_200, now + 16_000, fixture.rtt));
}

test "pacing: the burst ceiling stays the initial window at every datagram size" {
    var rtt = RttEstimator.init(25_000);
    rtt.update(100_000, 0);
    const pacer = Pacer{};

    // At and below 1472 bytes the packet count is the binding term, and ten
    // packets is exactly the initial window.
    try testing.expectEqual(@as(usize, 12_000), pacer.burstBytes(1_200));
    try testing.expectEqual(CongestionController.initialWindow(1_200), pacer.burstBytes(1_200));
    try testing.expectEqual(CongestionController.initialWindow(1_452), pacer.burstBytes(1_452));

    // Above it RFC 9002 §7.2's absolute 14720-byte cap takes over, and a plain
    // packet count would not know about it: ten 2048-byte datagrams are 20480
    // bytes, half again the window a fresh connection is trusted with.
    try testing.expect(10 * 2_048 > CongestionController.initialWindow(2_048));
    try testing.expectEqual(@as(usize, 14_720), pacer.burstBytes(2_048));

    // And the ceiling is what an idle restart actually gets, not just a
    // number: after DPLPMTUD raises the size, the restart burst is the initial
    // window rather than ten packets.
    var cc = CongestionController{ .congestion_window = 512 * 1024, .ssthresh = 512 * 1024 };
    cc.setMaxDatagramSize(2_048);
    const now: u64 = 1_000_000;
    var sent: usize = 0;
    while (cc.pacingAllows(2_048, now, rtt)) : (sent += 1) {
        cc.onPacingSent(2_048, now, rtt);
        if (sent > default_pacer_burst_packets) break;
    }
    try testing.expectEqual(@as(usize, 7), sent);
    try testing.expect(sent * 2_048 <= CongestionController.initialWindow(2_048));
}

test "pacing: a fast path keeps its sub-millisecond interval" {
    // 1.25 × 480 kB over a 10 ms RTT is 60 MB/s — one 1200-byte datagram every
    // 20 µs. Ordinary for a datacentre or loopback path, and two orders of
    // magnitude below `timer_granularity_us`.
    var cc = CongestionController{ .congestion_window = 480_000, .ssthresh = 480_000 };
    var rtt = RttEstimator.init(25_000);
    rtt.update(10_000, 0);
    var now: u64 = 1_000_000;
    while (cc.pacingAllows(1_200, now, rtt)) cc.onPacingSent(1_200, now, rtt);

    // `timer_granularity_us` is loss-detection resolution and has no business
    // here: flooring the release at 1 ms would underpace this path 50×.
    const release = cc.pacingReleaseUs(1_200, now, rtt);
    try testing.expectEqual(now + 20, release);
    try testing.expect(release - now < timer_granularity_us);

    // The consequence a floor would have, stated as throughput: one
    // millisecond of this schedule releases five bursts' worth. Floored at
    // 1 ms it could never exceed one, whatever the window and RTT said.
    const deadline = now + 1_000;
    var released: usize = 0;
    while (true) {
        now = cc.pacingReleaseUs(1_200, now, rtt);
        if (now > deadline) break;
        cc.onPacingSent(1_200, now, rtt);
        released += 1;
    }
    try testing.expectEqual(@as(usize, 50), released);
    try testing.expect(released > default_pacer_burst_packets);
}

test "pacing: an idle sender restarts with one burst, not with everything it missed" {
    var fixture = pacingFixture();
    const cc = &fixture.cc;
    const now: u64 = 1_000_000;

    while (cc.pacingAllows(1_200, now, fixture.rtt)) cc.onPacingSent(1_200, now, fixture.rtt);

    // Ten seconds idle is 1.5 MB of credit at this rate. The bucket keeps a
    // burst and discards the rest: without the ceiling, a connection that went
    // quiet would come back entitled to dump its whole idle period onto the
    // path in one pass.
    const after_idle = now + 10_000_000;
    try testing.expectEqual(@as(i64, 12_000), cc.pacingBalance(after_idle, fixture.rtt));

    var sent: usize = 0;
    while (cc.pacingAllows(1_200, after_idle, fixture.rtt)) : (sent += 1) {
        cc.onPacingSent(1_200, after_idle, fixture.rtt);
        if (sent > default_pacer_burst_packets) break;
    }
    try testing.expectEqual(default_pacer_burst_packets, sent);
}

test "pacing: the congestion window stays the harder gate" {
    var fixture = pacingFixture();
    const cc = &fixture.cc;
    const now: u64 = 1_000_000;

    // A full bucket over a full window sends nothing: pacing may delay
    // traffic, never authorise it.
    cc.bytes_in_flight = cc.congestion_window;
    const blocked = cc.pacingHint(now, fixture.rtt);
    try testing.expectEqual(@as(i64, 12_000), blocked.pacing_balance);
    try testing.expect(cc.pacingAllows(1_200, now, fixture.rtt));
    try testing.expect(!blocked.canSend());
    try testing.expect(!blocked.canSendNow(1_200));
    try testing.expectEqual(now + fixture.rtt.ptoDuration(.application), blocked.next_send_time_us);

    // Window room alone is not enough either — an empty bucket over an open
    // window reports the pacing release, not `now`.
    cc.bytes_in_flight = 0;
    while (cc.pacingAllows(1_200, now, fixture.rtt)) cc.onPacingSent(1_200, now, fixture.rtt);
    const paced = cc.pacingHint(now, fixture.rtt);
    try testing.expect(paced.canSend());
    try testing.expect(!paced.canSendNow(1_200));
    try testing.expectEqual(now + 8_000, paced.next_send_time_us);

    // Both open: send now.
    const ready = cc.pacingHint(now + 8_000, fixture.rtt);
    try testing.expect(ready.canSendNow(1_200));
    try testing.expectEqual(now + 8_000, ready.next_send_time_us);
}

test "pacing: slow start paces at 2x and congestion avoidance at 1.25x" {
    var fixture = pacingFixture();
    const cc = &fixture.cc;
    const now: u64 = 1_000_000;
    while (cc.pacingAllows(1_200, now, fixture.rtt)) cc.onPacingSent(1_200, now, fixture.rtt);

    // Congestion avoidance (cwnd == ssthresh): N = 1.25, 8 ms apart.
    try testing.expectEqual(now + 8_000, cc.pacingReleaseUs(1_200, now, fixture.rtt));

    // Slow start doubles the window every round trip, so pacing it at the
    // avoidance gain would hold the sender below the growth the window is
    // already granting: N = 2, 5 ms apart.
    cc.ssthresh = std.math.maxInt(usize);
    try testing.expectEqual(now + 5_000, cc.pacingReleaseUs(1_200, now, fixture.rtt));
}

test "pacing: only in-flight packets are metered, and a shrinking window slows the rate" {
    var controller = RecoveryController{};
    controller.rtt.update(100_000, 0);
    controller.congestion.congestion_window = 12_000;
    controller.congestion.ssthresh = 12_000;
    const now: u64 = 1_000_000;

    // A pure ACK is not congestion controlled, so it spends no credit —
    // acknowledgement latency must not depend on the send schedule.
    const before = controller.congestion.pacingBalance(now, controller.rtt);
    try controller.onPacketSent(.{
        .space = .application,
        .packet_number = 0,
        .time_sent_us = now,
        .size = 1_200,
        .ack_eliciting = false,
        .in_flight = false,
    });
    try testing.expectEqual(before, controller.congestion.pacingBalance(now, controller.rtt));

    // An in-flight packet is.
    try controller.onPacketSent(.{
        .space = .application,
        .packet_number = 1,
        .time_sent_us = now,
        .size = 1_200,
    });
    try testing.expectEqual(before - 1_200, controller.congestion.pacingBalance(now, controller.rtt));

    // Halving the window halves the pacing rate: the schedule is derived from
    // congestion control rather than running alongside it.
    const wide = controller.pacingReleaseUs(12_000, now);
    controller.congestion.congestion_window = 6_000;
    controller.congestion.ssthresh = 6_000;
    const narrow = controller.pacingReleaseUs(12_000, now);
    try testing.expectEqual(2 * (wide - now), narrow - now);
}

test "pacing: a path migration discards the schedule with the window it came from" {
    var controller = RecoveryController{};
    controller.rtt.update(100_000, 0);
    const now: u64 = 1_000_000;
    while (controller.pacingAllows(1_200, now)) {
        controller.congestion.onPacingSent(1_200, now, controller.rtt);
    }
    try testing.expect(!controller.pacingAllows(1_200, now));

    controller.resetForPathMigration();
    try testing.expect(controller.pacingAllows(1_200, now));
    try testing.expectEqual(
        @as(?u64, null),
        controller.congestion.pacer.updated_at_us,
    );
}

test "pacing hint exposes send allowance and blocked wake time" {
    var cc = CongestionController{};
    var rtt = RttEstimator.init(25_000);
    rtt.update(100_000, 0);

    var hint = cc.pacingHint(1_000, rtt);
    try testing.expect(hint.canSend());
    try testing.expectEqual(cc.congestion_window, hint.bytes_available);
    try testing.expectEqual(@as(u64, 1_000), hint.next_send_time_us);

    cc.bytes_in_flight = cc.congestion_window;
    hint = cc.pacingHint(1_000, rtt);
    try testing.expect(!hint.canSend());
    try testing.expectEqual(@as(usize, 0), hint.bytes_available);
    try testing.expectEqual(@as(u64, 326_000), hint.next_send_time_us);
}

test "recovery controller wires ACK RTT loss congestion and events" {
    const Recorder = struct {
        events: [8]Event = undefined,
        count: usize = 0,

        fn emit(ctx: ?*anyopaque, event: Event) void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            self.events[self.count] = event;
            self.count += 1;
        }
    };

    var recorder = Recorder{};
    var recovery = RecoveryController{
        .events = .{ .context = &recorder, .emitFn = Recorder.emit },
    };

    try recovery.onPacketSent(.{ .space = .application, .packet_number = 1, .time_sent_us = 0, .size = 1200 });
    try recovery.onPacketSent(.{ .space = .application, .packet_number = 2, .time_sent_us = 10, .size = 1200 });
    try recovery.onPacketSent(.{ .space = .application, .packet_number = 3, .time_sent_us = 20, .size = 1200 });
    try recovery.onPacketSent(.{ .space = .application, .packet_number = 4, .time_sent_us = 30, .size = 1200 });
    try recovery.onPacketReceived(.application, 4);
    try recovery.onAcked(.application, 4, 130, 0);
    const loss = recovery.detectLost(.application, 2_000);

    try testing.expectEqual(@as(u64, 100), recovery.rtt.latest_rtt_us.?);
    try testing.expectEqual(@as(usize, 3), loss.lost_bytes / 1200);
    try testing.expect(recorder.count >= 3);
    try testing.expectEqual(RecoveryEvent.ack_range_inserted, recorder.events[0].kind);
    try testing.expectEqual(RecoveryEvent.packet_acked, recorder.events[1].kind);
    try testing.expectEqual(RecoveryEvent.packet_lost, recorder.events[2].kind);
}

test {
    std.testing.refAllDecls(@This());
}

// ---------------------------------------------------------------------------
// #256-A: the sender's current maximum datagram size drives NewReno.
// ---------------------------------------------------------------------------

test "congestion: the initial and minimum windows follow the sender's datagram size" {
    // RFC 9002 §7.2/§7.3 express both in terms of the sender's current max
    // datagram size, so a 1452- or 2048-byte sender gets proportionally
    // larger windows than the 1200-byte floor.
    // min(10*mds, max(2*mds, 14720)) per RFC 9002 §7.2.
    try testing.expectEqual(@as(usize, 12_000), CongestionController.initialWindow(1200));
    try testing.expectEqual(@as(usize, 14_520), CongestionController.initialWindow(1452));
    try testing.expectEqual(@as(usize, 14_720), CongestionController.initialWindow(2048));

    var cc = CongestionController{};
    try testing.expectEqual(@as(usize, 2 * 1200), cc.minWindow());
    cc.setMaxDatagramSize(1452);
    try testing.expectEqual(@as(usize, 2 * 1452), cc.minWindow());
    cc.setMaxDatagramSize(2048);
    try testing.expectEqual(@as(usize, 2 * 2048), cc.minWindow());
}

test "congestion: adopting a larger datagram size lifts a window below the new floor" {
    var cc = CongestionController{};
    cc.congestion_window = 2 * initial_max_datagram_size;
    cc.setMaxDatagramSize(2048);
    // The window is measured capacity and is not rescaled, but it can never
    // sit below a floor that would block a single datagram pair.
    try testing.expectEqual(@as(usize, 2 * 2048), cc.congestion_window);
}

test "congestion: avoidance growth is proportional to the sender's datagram size" {
    const acked = SentPacket{ .space = .application, .packet_number = 1, .time_sent_us = 0, .size = 1200 };

    var small = CongestionController{ .congestion_window = 30_000, .ssthresh = 1_000, .bytes_in_flight = 1200 };
    small.onPacketAcked(acked);
    const small_growth = small.congestion_window - 30_000;

    var large = CongestionController{ .congestion_window = 30_000, .ssthresh = 1_000, .bytes_in_flight = 1200 };
    large.setMaxDatagramSize(2048);
    large.onPacketAcked(acked);
    const large_growth = large.congestion_window - 30_000;

    try testing.expectEqual(@as(usize, 1200 * 1200 / 30_000), small_growth);
    try testing.expectEqual(@as(usize, 2048 * 1200 / 30_000), large_growth);
    try testing.expect(large_growth > small_growth);
}

test "congestion: loss and persistent congestion respect the larger floor" {
    var cc = CongestionController{ .congestion_window = 40_000, .bytes_in_flight = 4_000 };
    cc.setMaxDatagramSize(2048);
    cc.onPacketsLost(10, 4_000, 100);
    try testing.expect(cc.congestion_window >= cc.minWindow());

    cc.onPersistentCongestion();
    try testing.expectEqual(@as(usize, 2 * 2048), cc.congestion_window);
    try testing.expectEqual(@as(usize, 2 * 2048), cc.ssthresh);
}

test "recovery: a path migration resets the window but keeps the sender's datagram size" {
    var controller = RecoveryController{};
    controller.congestion.setMaxDatagramSize(1452);
    controller.congestion.congestion_window = 90_000;
    controller.congestion.ssthresh = 40_000;
    controller.congestion.bytes_in_flight = 3_000;

    controller.resetForPathMigration();

    // The measured window is discarded (RFC 9002 §7.8) but the size the packet
    // builder is still emitting is not.
    try testing.expectEqual(@as(usize, 1452), controller.congestion.max_datagram_size);
    try testing.expectEqual(
        CongestionController.initialWindow(1452),
        controller.congestion.congestion_window,
    );
    try testing.expectEqual(@as(usize, std.math.maxInt(usize)), controller.congestion.ssthresh);
    try testing.expectEqual(@as(usize, 3_000), controller.congestion.bytes_in_flight);
}

test "recovery: a padded non-ack-eliciting packet is charged to the window" {
    var controller = RecoveryController{};
    try controller.onPacketSent(.{
        .space = .initial,
        .packet_number = 0,
        .time_sent_us = 0,
        .size = 1200,
        .ack_eliciting = false,
        .in_flight = true,
    });
    try testing.expectEqual(@as(usize, 1200), controller.congestion.bytes_in_flight);
}

// ---------------------------------------------------------------------------
// #256-B: a DPLPMTUD probe is in flight, but losing one is not congestion.
// ---------------------------------------------------------------------------

test "recovery: a lost PMTU probe returns its bytes without a congestion event" {
    var controller = RecoveryController{};
    const window_before = controller.congestion.congestion_window;

    try controller.onPacketSent(.{
        .space = .application,
        .packet_number = 1,
        .time_sent_us = 0,
        .size = 1_624,
        .pmtu_probe = true,
    });
    // A probe consumes window like anything else while it is outstanding.
    try testing.expectEqual(@as(usize, 1_624), controller.congestion.bytes_in_flight);

    // Later ordinary packets get through, which is what declares the probe
    // lost by packet threshold — exactly the black-hole-free case where the
    // path simply cannot carry the probed size.
    var pn: u64 = 2;
    while (pn <= 5) : (pn += 1) {
        try controller.onPacketSent(.{ .space = .application, .packet_number = pn, .time_sent_us = pn, .size = 100 });
    }
    try controller.onAcked(.application, 5, 1_000, 0);

    const loss = controller.detectLost(.application, 1_000);
    try testing.expectEqual(@as(usize, 1_624), loss.probe_lost_bytes);
    try testing.expect(loss.lost_bytes > loss.probe_lost_bytes);
    // The ordinary loss supplies the congestion event's timestamp; the probe
    // must not, or a probe could start a recovery period on its own.
    try testing.expectEqual(@as(?u64, 2), loss.largest_ordinary_lost_time_sent_us);
    // The window was cut once, by the ordinary loss — never by the probe.
    try testing.expect(controller.congestion.congestion_window < window_before);
    try testing.expectEqual(controller.congestion.congestion_window, controller.congestion.ssthresh);
    // Every lost byte, probe included, left both in-flight ledgers, leaving
    // only the two packets that are neither acked nor yet declared lost.
    try testing.expectEqual(@as(usize, 200), controller.tracker.bytes_in_flight);
    try testing.expectEqual(@as(usize, 200), controller.congestion.bytes_in_flight);
}

test "recovery: a probe lost on its own leaves the congestion window untouched" {
    var controller = RecoveryController{};
    controller.congestion.congestion_window = 30_000;
    controller.congestion.ssthresh = 30_000;

    try controller.onPacketSent(.{
        .space = .application,
        .packet_number = 1,
        .time_sent_us = 0,
        .size = 1_624,
        .pmtu_probe = true,
    });
    // Exactly `packet_threshold` newer packets, so the probe is the only thing
    // far enough behind the acknowledged one to be declared lost.
    try controller.onPacketSent(.{ .space = .application, .packet_number = 2, .time_sent_us = 10, .size = 200 });
    try controller.onPacketSent(.{ .space = .application, .packet_number = 3, .time_sent_us = 20, .size = 200 });
    try controller.onPacketSent(.{ .space = .application, .packet_number = 4, .time_sent_us = 30, .size = 200 });
    try controller.onAcked(.application, 4, 100, 0);
    const window_before = controller.congestion.congestion_window;
    const ssthresh_before = controller.congestion.ssthresh;

    const loss = controller.detectLost(.application, 100);
    try testing.expectEqual(@as(usize, 1_624), loss.lost_bytes);
    try testing.expectEqual(loss.lost_bytes, loss.probe_lost_bytes);
    try testing.expectEqual(@as(?u64, null), loss.largest_ordinary_lost_time_sent_us);
    try testing.expectEqual(window_before, controller.congestion.congestion_window);
    try testing.expectEqual(ssthresh_before, controller.congestion.ssthresh);
    try testing.expectEqual(@as(?u64, null), controller.congestion.recovery_start_time_us);
    try testing.expectEqual(@as(usize, 400), controller.congestion.bytes_in_flight);
}

test "recovery: ordinary traffic stays bounded while required recovery spills past the fixed tracker" {
    var controller = RecoveryController{};
    defer controller.deinit(testing.allocator);
    const ordinary_capacity = max_tracked_packets - reserved_tracked_packets;

    var i: usize = 0;
    while (i < ordinary_capacity) : (i += 1) {
        try testing.expect(controller.canTrackPacket());
        try controller.onPacketSent(.{
            .space = .application,
            .packet_number = i,
            .time_sent_us = i,
            .size = 100,
        });
    }
    try testing.expect(!controller.canTrackPacket());

    while (i < max_tracked_packets) : (i += 1) {
        try testing.expect(controller.canTrackRecoveryPacket());
        controller.onPacketSentAssumeCapacity(.{
            .space = .application,
            .packet_number = i,
            .time_sent_us = i,
            .size = 100,
        });
    }
    try testing.expect(!controller.canTrackRecoveryPacket());

    try controller.ensureRecoveryPacketCapacity(testing.allocator, 1);
    try testing.expect(controller.canTrackRecoveryPacket());
    controller.onPacketSentAssumeCapacity(.{
        .space = .application,
        .packet_number = max_tracked_packets,
        .time_sent_us = 9_999,
        .size = 123,
    });
    try testing.expectEqual(@as(usize, max_tracked_packets + 1), controller.tracker.totalCount());
    try testing.expectEqual(@as(usize, 1), controller.tracker.recovery_overflow.items.len);

    const before = controller.congestion.bytes_in_flight;
    try controller.onAcked(.application, max_tracked_packets, 10_100, 0);
    try testing.expectEqual(@as(usize, max_tracked_packets), controller.tracker.totalCount());
    try testing.expectEqual(@as(usize, 0), controller.tracker.recovery_overflow.items.len);
    try testing.expect(controller.congestion.bytes_in_flight < before);
}

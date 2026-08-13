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

const time_threshold_numerator: u64 = 9;
const time_threshold_denominator: u64 = 8;

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
    acked_send_times: [3][max_tracked_packets]u64 = [_][max_tracked_packets]u64{[_]u64{0} ** max_tracked_packets} ** 3,
    acked_send_time_counts: [3]usize = .{0} ** 3,
    /// If the exact array is temporarily saturated by ACKs that are all still
    /// relevant, retain the uncertain send-time extent instead of dropping the
    /// evidence. Intersecting candidates are conservatively split until their
    /// start advances beyond this extent; unlike the old permanent boolean,
    /// this uncertainty expires as soon as it is no longer relevant.
    acked_send_times_overflow_min_us: [3]?u64 = .{ null, null, null },
    acked_send_times_overflow_max_us: [3]?u64 = .{ null, null, null },

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

    pub fn onAcked(self: *PacketTracker, space: PacketNumberSpace, packet_number: u64, now_us: u64) ?AckResult {
        var index: usize = 0;
        while (index < self.count) : (index += 1) {
            const packet = self.packets[index];
            if (packet.space != space or packet.packet_number != packet_number or packet.lost) continue;
            if (packet.in_flight) self.bytes_in_flight -= packet.size;
            self.noteLargestAcked(space, packet_number);
            self.removeAt(index);
            self.breakPersistentCandidateOnAck(space, packet.time_sent_us);
            self.noteAckedSendTime(space, packet.time_sent_us);
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
            self.noteAckedSendTime(space, packet.time_sent_us);
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

    fn observePersistentCandidate(self: *PacketTracker, space: PacketNumberSpace, packet: SentPacket) void {
        if (packet.pmtu_probe or !packet.ack_eliciting or !packet.in_flight) return;
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

    fn noteAckedSendTime(self: *PacketTracker, space: PacketNumberSpace, time_sent_us: u64) void {
        const idx = spaceIndex(space);
        self.pruneAckedSendTimes(space);
        if (self.acked_send_time_counts[idx] < self.acked_send_times[idx].len) {
            self.acked_send_times[idx][self.acked_send_time_counts[idx]] = time_sent_us;
            self.acked_send_time_counts[idx] += 1;
        } else {
            const min = self.acked_send_times_overflow_min_us[idx];
            const max = self.acked_send_times_overflow_max_us[idx];
            self.acked_send_times_overflow_min_us[idx] = if (min) |value| @min(value, time_sent_us) else time_sent_us;
            self.acked_send_times_overflow_max_us[idx] = if (max) |value| @max(value, time_sent_us) else time_sent_us;
        }
        self.pruneAckedSendTimes(space);
    }

    fn earliestTrackedSendTime(self: *const PacketTracker, space: PacketNumberSpace) ?u64 {
        var earliest: ?u64 = null;
        for (self.packets[0..self.count]) |packet| {
            if (packet.space != space or packet.lost) continue;
            earliest = if (earliest) |value| @min(value, packet.time_sent_us) else packet.time_sent_us;
        }
        for (self.recovery_overflow.items) |packet| {
            if (packet.space != space or packet.lost) continue;
            earliest = if (earliest) |value| @min(value, packet.time_sent_us) else packet.time_sent_us;
        }
        return earliest;
    }

    fn ackEvidenceFloor(self: *const PacketTracker, space: PacketNumberSpace) ?u64 {
        const candidate = self.persistent_candidates[spaceIndex(space)];
        if (candidate.active) return candidate.start_us;
        return self.earliestTrackedSendTime(space);
    }

    fn pruneAckedSendTimes(self: *PacketTracker, space: PacketNumberSpace) void {
        const idx = spaceIndex(space);
        const floor = self.ackEvidenceFloor(space) orelse {
            self.acked_send_time_counts[idx] = 0;
            self.acked_send_times_overflow_min_us[idx] = null;
            self.acked_send_times_overflow_max_us[idx] = null;
            return;
        };

        var write_index: usize = 0;
        for (self.acked_send_times[idx][0..self.acked_send_time_counts[idx]]) |time_sent_us| {
            if (time_sent_us < floor) continue;
            self.acked_send_times[idx][write_index] = time_sent_us;
            write_index += 1;
        }
        self.acked_send_time_counts[idx] = write_index;

        if (self.acked_send_times_overflow_max_us[idx]) |overflow_max| {
            if (overflow_max < floor) {
                self.acked_send_times_overflow_min_us[idx] = null;
                self.acked_send_times_overflow_max_us[idx] = null;
            } else if (self.acked_send_times_overflow_min_us[idx]) |overflow_min| {
                if (overflow_min < floor) self.acked_send_times_overflow_min_us[idx] = floor;
            }
        }
    }

    fn hasAckedSendTimeInCandidate(self: *const PacketTracker, space: PacketNumberSpace, candidate: PersistentCandidate) bool {
        if (!candidate.active) return false;
        const idx = spaceIndex(space);
        for (self.acked_send_times[idx][0..self.acked_send_time_counts[idx]]) |time_sent_us| {
            if (time_sent_us >= candidate.start_us and time_sent_us <= candidate.end_us) return true;
        }
        if (self.acked_send_times_overflow_min_us[idx]) |overflow_min| {
            const overflow_max = self.acked_send_times_overflow_max_us[idx].?;
            if (overflow_max >= candidate.start_us and overflow_min <= candidate.end_us) return true;
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
        self.acked_send_time_counts[idx] = 0;
        self.acked_send_times_overflow_min_us[idx] = null;
        self.acked_send_times_overflow_max_us[idx] = null;
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
        if (self.recovery_start_time_us) |start| {
            if (largest_lost_time_sent_us <= start) return;
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

    pub fn pacingHint(self: CongestionController, now_us: u64, rtt: RttEstimator) PacingHint {
        const allowance = self.congestion_window -| self.bytes_in_flight;
        if (allowance > 0) return .{ .bytes_available = allowance, .next_send_time_us = now_us };
        return .{ .bytes_available = 0, .next_send_time_us = now_us + rtt.ptoDuration(.application) };
    }
};

pub const PacingHint = struct {
    bytes_available: usize,
    next_send_time_us: u64,

    pub fn canSend(self: PacingHint) bool {
        return self.bytes_available > 0;
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
        if (tracked.in_flight) self.congestion.onPacketSent(tracked.size);
    }

    pub fn onPacketSent(self: *RecoveryController, packet: SentPacket) error{TooManyTrackedPackets}!void {
        var tracked = packet;
        tracked.rtt_sample_available_at_send = self.rtt.smoothed_rtt_us != null;
        try self.tracker.onPacketSent(tracked);
        if (tracked.in_flight) self.congestion.onPacketSent(tracked.size);
    }

    pub fn onAcked(self: *RecoveryController, space: PacketNumberSpace, packet_number: u64, now_us: u64, ack_delay_us: u64) void {
        if (self.tracker.onAcked(space, packet_number, now_us)) |acked| {
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
        // revalidates the new path's PMTU separately.
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

    const acked = tracker.onAcked(.application, 1, 3_500).?;
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

    _ = tracker.onAcked(.application, 5, 100);
    const threshold_loss = tracker.detectLost(.application, 100, rtt);
    try testing.expectEqual(@as(usize, 2), threshold_loss.packet_threshold_losses);
    try testing.expectEqual(@as(usize, 200), threshold_loss.lost_bytes);
    try testing.expectEqual(@as(u64, 10), threshold_loss.largest_lost_time_sent_us.?);
    try testing.expect(!threshold_loss.persistent_congestion);
    try testing.expectEqual(@as(usize, 200), tracker.bytes_in_flight);

    _ = tracker.onAcked(.application, 4, 120);
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
    _ = tracker.onAcked(.application, 3, duration + 2);

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
    _ = padding.onAcked(.application, 3, duration + 2);
    try testing.expect(!padding.detectLost(.application, duration * 2, rtt).persistent_congestion);

    var no_prior = PacketTracker{};
    try no_prior.onPacketSent(.{ .space = .application, .packet_number = 1, .time_sent_us = 0, .size = 100 });
    try no_prior.onPacketSent(.{ .space = .application, .packet_number = 2, .time_sent_us = duration, .size = 100 });
    try no_prior.onPacketSent(.{ .space = .application, .packet_number = 3, .time_sent_us = duration + 1, .size = 100, .rtt_sample_available_at_send = true });
    _ = no_prior.onAcked(.application, 3, duration + 2);
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
    _ = tracker.onAcked(.application, 2, duration + 2);
    _ = tracker.onAcked(.application, 4, duration + 3);
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
    _ = tracker.onAcked(.initial, 3, duration + 2);
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
    _ = tracker.onAcked(.application, 4, duration + 4);

    const first = tracker.detectLost(.application, duration + 4, rtt);
    try testing.expect(!first.persistent_congestion);
    _ = tracker.onAcked(.application, 5, duration + 5);
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

    _ = tracker.onAcked(.application, 4, duration / 2 + 1);
    const first = tracker.detectLost(.application, duration + 1, rtt);
    try testing.expect(!first.persistent_congestion);

    _ = tracker.onAcked(.application, 6, duration * 2 + 2);
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

    _ = tracker.onAcked(.application, 4, base + 51);
    const first = tracker.detectLost(.application, base + duration / 2, rtt);
    try testing.expect(!first.persistent_congestion);

    pn = 5;
    while (pn < 21) : (pn += 1) {
        _ = tracker.onAcked(.application, pn, base + 52 + pn);
    }
    const middle = tracker.detectLost(.application, base + duration / 2 + 1, rtt);
    try testing.expect(!middle.persistent_congestion);

    _ = tracker.onAcked(.application, 34, base + duration * 2 + 2);
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
        _ = tracker.onAcked(.application, pn, pn + 1);
    }
    try testing.expectEqual(@as(usize, 0), tracker.acked_send_time_counts[spaceIndex(.application)]);
    try testing.expect(tracker.acked_send_times_overflow_min_us[spaceIndex(.application)] == null);

    const base: u64 = 10_000_000;
    try tracker.onPacketSent(.{ .space = .application, .packet_number = pn, .time_sent_us = base, .size = 100, .rtt_sample_available_at_send = true });
    try tracker.onPacketSent(.{ .space = .application, .packet_number = pn + 1, .time_sent_us = base + duration, .size = 100, .rtt_sample_available_at_send = true });
    try tracker.onPacketSent(.{ .space = .application, .packet_number = pn + 2, .time_sent_us = base + duration + 1, .size = 100, .rtt_sample_available_at_send = true });
    _ = tracker.onAcked(.application, pn + 2, base + duration + 2);

    const loss = tracker.detectLost(.application, base + duration * 2, rtt);
    try testing.expect(loss.persistent_congestion);
}

test "discarding Initial state clears persistent-congestion bookkeeping for Retry" {
    var controller = RecoveryController{};
    controller.rtt = RttEstimator.init(0);
    controller.rtt.update(100_000, 0);
    const duration = PacketTracker.persistentCongestionDuration(controller.rtt).?;

    try controller.onPacketSent(.{ .space = .initial, .packet_number = 0, .time_sent_us = 0, .size = 100 });
    try controller.onPacketSent(.{ .space = .initial, .packet_number = 1, .time_sent_us = duration, .size = 100 });
    try controller.onPacketSent(.{ .space = .initial, .packet_number = 2, .time_sent_us = duration + 1, .size = 100 });
    controller.onAcked(.initial, 2, duration + 100_001, 0);
    try testing.expect(controller.detectLost(.initial, duration * 2).persistent_congestion);

    const idx = spaceIndex(.initial);
    try testing.expect(controller.tracker.persistent_candidates[idx].active);
    _ = controller.onKeysDiscarded(.initial);
    try testing.expect(controller.tracker.largest_acked[idx] == null);
    try testing.expect(!controller.tracker.persistent_candidates[idx].active);
    try testing.expectEqual(@as(usize, 0), controller.tracker.acked_send_time_counts[idx]);
    try testing.expect(controller.tracker.acked_send_times_overflow_min_us[idx] == null);
    try testing.expect(controller.tracker.acked_send_times_overflow_max_us[idx] == null);

    // Retry restarts the Initial packet number space. The replacement flight
    // must build a fresh loss episode rather than inheriting any old boundary
    // or ACK evidence.
    try controller.onPacketSent(.{ .space = .initial, .packet_number = 0, .time_sent_us = duration * 3, .size = 100 });
    try controller.onPacketSent(.{ .space = .initial, .packet_number = 1, .time_sent_us = duration * 4, .size = 100 });
    try controller.onPacketSent(.{ .space = .initial, .packet_number = 2, .time_sent_us = duration * 4 + 1, .size = 100 });
    controller.onAcked(.initial, 2, duration * 4 + 100_001, 0);
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
    recovery.onAcked(.application, 4, 130, 0);
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
    controller.onAcked(.application, 5, 1_000, 0);

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
    controller.onAcked(.application, 4, 100, 0);
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
    controller.onAcked(.application, max_tracked_packets, 10_100, 0);
    try testing.expectEqual(@as(usize, max_tracked_packets), controller.tracker.totalCount());
    try testing.expectEqual(@as(usize, 0), controller.tracker.recovery_overflow.items.len);
    try testing.expect(controller.congestion.bytes_in_flight < before);
}

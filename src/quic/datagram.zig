//! The one authoritative outbound UDP datagram size for pure Zig QUIC
//! (#256-A).
//!
//! Datagram sizing used to be two independent knobs that could drift: the
//! transport config's `max_udp_payload_size` and the HTTP/3 runtime's
//! `max_datagram_size`, with the packet builder ignoring both in favour of a
//! hardcoded constant. This module owns the single set of bounds and the one
//! rule that combines them, so every surface derives its value from here.
//!
//! Nothing in this file does I/O or knows about paths, sockets, or packets;
//! it is a pure function of the three inputs in `Limits`.

const std = @import("std");

/// RFC 9000 §14: every QUIC path must be able to carry a 1200-byte UDP
/// payload, and §14.1 requires a datagram carrying an Initial packet to be
/// padded to at least that size. So it is simultaneously the floor of any
/// effective cap and the value the stack falls back to whenever nothing
/// larger has been established. Also the operator-facing default.
pub const base_size: usize = 1200;

/// Hard ceiling on any datagram this stack will emit, whatever an operator or
/// peer asks for. It bounds the per-packet plaintext scratch buffers in
/// `connection.zig` and the transmit/receive buffers in the HTTP/3 runtime,
/// so raising it means raising those too.
pub const max_size: usize = 2048;

/// The inputs to the outbound datagram limits.
///
/// These are *send*-side quantities. They are deliberately separate from the
/// `max_udp_payload_size` transport parameter an endpoint advertises, which is
/// what that endpoint is willing to *receive* (RFC 9000 §18.2) — an immutable
/// statement of receive capacity, not mutable path state. Only the peer's
/// advertisement appears here, as a ceiling on what we may send it.
pub const Limits = struct {
    /// The sender's current maximum datagram size for the active path: what
    /// this stack believes the path carries today. Starts at `base_size`, the
    /// only size RFC 9000 §14 guarantees. An operator may assert a larger
    /// value for a path whose MTU they control; #256-B replaces the assertion
    /// with measured DPLPMTUD state and black-hole fallback.
    current_path_max: u64 = base_size,
    /// The largest datagram this endpoint will ever emit, independent of what
    /// the path has been shown to carry. This is the ceiling a PMTU probe may
    /// reach for, so it must have headroom above `base_size` or #256-B could
    /// never discover anything.
    send_ceiling: u64 = max_size,
    /// The peer's advertised `max_udp_payload_size`: its receive capacity,
    /// once transport parameters have been authenticated. `null` before then,
    /// and treated as `base_size` — during the handshake we know least about
    /// both the peer and the path, so everything collapses to the size RFC
    /// 9000 §14 guarantees.
    peer_max: ?u64 = null,

    /// The largest ordinary UDP datagram that may be emitted. Never below
    /// `base_size` (Initial padding and the RFC floor both need it) and never
    /// above `max_size`.
    pub fn effective(self: Limits) usize {
        return @min(clampToRange(self.current_path_max), self.probeCeiling());
    }

    /// The largest datagram a PMTU probe (#256-B) may attempt. A probe is
    /// allowed to exceed `effective()` — exceeding the current path size is
    /// the point — but never this: the peer drops anything above its
    /// advertised receive capacity, and the local ceiling bounds our buffers.
    pub fn probeCeiling(self: Limits) usize {
        return @min(clampToRange(self.send_ceiling), clampToRange(self.peer_max orelse base_size));
    }
};

/// Clamp one advertised or configured bound into the representable range.
/// Values below `base_size` are raised rather than honoured: a peer
/// advertising less than 1200 is already rejected as an invalid transport
/// parameter, and we could not honour it anyway without violating the Initial
/// padding rule.
fn clampToRange(value: u64) usize {
    if (value <= base_size) return base_size;
    if (value >= max_size) return max_size;
    return @intCast(value);
}

const testing = std.testing;

test "datagram: defaults send at the RFC 9000 floor" {
    const limits = Limits{};
    try testing.expectEqual(base_size, limits.effective());
    // Pre-authentication the probe ceiling collapses too: the peer has not
    // yet said it can receive more.
    try testing.expectEqual(base_size, limits.probeCeiling());
}

test "datagram: an authenticated peer leaves probe headroom above the floor" {
    // The default send ceiling must let #256-B probe upward once the peer's
    // receive capacity is known; ordinary sends stay at the current path size.
    const limits = Limits{ .peer_max = max_size };
    try testing.expectEqual(base_size, limits.effective());
    try testing.expectEqual(max_size, limits.probeCeiling());
    try testing.expect(limits.probeCeiling() > limits.effective());
}

test "datagram: the current path size raises ordinary sends up to the ceiling" {
    try testing.expectEqual(
        @as(usize, 1452),
        (Limits{ .current_path_max = 1452, .peer_max = 65_527 }).effective(),
    );
    try testing.expectEqual(
        max_size,
        (Limits{ .current_path_max = 65_527, .peer_max = 65_527 }).effective(),
    );
}

test "datagram: nothing raises the send size until the peer's parameters arrive" {
    try testing.expectEqual(base_size, (Limits{ .current_path_max = 1500 }).effective());
    try testing.expectEqual(base_size, (Limits{ .send_ceiling = max_size }).probeCeiling());
}

test "datagram: the peer's advertised receive capacity lowers the send size" {
    const limits = Limits{ .current_path_max = 1500, .peer_max = 1300 };
    try testing.expectEqual(@as(usize, 1300), limits.effective());
    try testing.expectEqual(@as(usize, 1300), limits.probeCeiling());
}

test "datagram: a larger local path size never overrides a smaller peer limit" {
    const limits = Limits{ .current_path_max = max_size, .peer_max = base_size };
    try testing.expectEqual(base_size, limits.effective());
}

test "datagram: a larger peer capacity never raises past the local path size" {
    const limits = Limits{ .current_path_max = 1300, .peer_max = 65_527 };
    try testing.expectEqual(@as(usize, 1300), limits.effective());
}

test "datagram: the send ceiling bounds both ordinary sends and probes" {
    const limits = Limits{ .current_path_max = max_size, .send_ceiling = 1400, .peer_max = max_size };
    try testing.expectEqual(@as(usize, 1400), limits.effective());
    try testing.expectEqual(@as(usize, 1400), limits.probeCeiling());
}

test "datagram: probes may exceed the current path size but not the endpoint bounds" {
    const limits = Limits{ .current_path_max = base_size, .send_ceiling = 1500, .peer_max = 1400 };
    try testing.expectEqual(base_size, limits.effective());
    try testing.expectEqual(@as(usize, 1400), limits.probeCeiling());
}

test "datagram: out-of-range bounds are clamped rather than trusted" {
    try testing.expectEqual(base_size, (Limits{ .current_path_max = 0, .peer_max = 65_527 }).effective());
    try testing.expectEqual(base_size, (Limits{ .current_path_max = 1500, .peer_max = 0 }).effective());
    try testing.expectEqual(
        max_size,
        (Limits{
            .current_path_max = std.math.maxInt(u64),
            .peer_max = std.math.maxInt(u64),
        }).effective(),
    );
}

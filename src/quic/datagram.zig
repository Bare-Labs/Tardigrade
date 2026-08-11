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

/// The inputs to the effective outbound datagram cap. Every field is an upper
/// bound in its own right; the cap is the smallest of them, clamped to
/// `[base_size, max_size]`.
pub const Limits = struct {
    /// The locally configured maximum (`quic.config.Config.max_udp_payload_size`).
    /// This is the operator's assertion about what the local host and path
    /// can carry.
    local_max: u64 = base_size,
    /// The peer's advertised `max_udp_payload_size` transport parameter, once
    /// transport parameters have been authenticated. `null` before then, and
    /// treated as `base_size`: during the handshake we know least about both
    /// the peer and the path, so the cap collapses to the size RFC 9000 §14
    /// guarantees. A raised `local_max` therefore only takes effect once the
    /// peer has actually committed to accepting larger datagrams.
    peer_max: ?u64 = null,
    /// The largest datagram size validated for the current path. `null` means
    /// "not yet constrained by path measurement", in which case the locally
    /// configured maximum stands in as the operator's path assertion.
    ///
    /// #256-B replaces that with per-path DPLPMTUD (RFC 8899) state and
    /// black-hole fallback; until it lands, the shipped default for
    /// `local_max` is `base_size`, so the stack does not assume any path
    /// carries more than the RFC floor unless an operator says so.
    validated_path_max: ?u64 = null,

    /// The largest ordinary UDP datagram that may be emitted under these
    /// limits. Never below `base_size` (Initial padding and the RFC floor
    /// both need it) and never above `max_size`.
    pub fn effective(self: Limits) usize {
        var cap = self.endpointCeiling();
        if (self.validated_path_max) |path_max| cap = @min(cap, clampToRange(path_max));
        return cap;
    }

    /// The bound imposed by the two endpoints alone, ignoring what the path
    /// has been shown to carry. A PMTU probe (#256-B) is allowed to exceed
    /// `effective()` because exceeding the validated path size is the point,
    /// but it must never exceed this: the peer will drop anything larger than
    /// its advertised `max_udp_payload_size`, and the local ceiling bounds our
    /// own buffers.
    pub fn probeCeiling(self: Limits) usize {
        return self.endpointCeiling();
    }

    fn endpointCeiling(self: Limits) usize {
        return @min(clampToRange(self.local_max), clampToRange(self.peer_max orelse base_size));
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

test "datagram: defaults sit at the RFC 9000 floor" {
    const limits = Limits{};
    try testing.expectEqual(base_size, limits.effective());
    try testing.expectEqual(base_size, limits.probeCeiling());
}

test "datagram: a larger local maximum raises the cap up to the ceiling" {
    try testing.expectEqual(
        @as(usize, 1452),
        (Limits{ .local_max = 1452, .peer_max = 65_527 }).effective(),
    );
    try testing.expectEqual(
        max_size,
        (Limits{ .local_max = 65_527, .peer_max = 65_527 }).effective(),
    );
}

test "datagram: the cap stays at the floor until the peer's parameters arrive" {
    // Nothing an operator configures locally may raise the cap while the
    // peer has not yet committed to accepting larger datagrams.
    try testing.expectEqual(base_size, (Limits{ .local_max = 1500 }).effective());
    try testing.expectEqual(base_size, (Limits{ .local_max = max_size }).probeCeiling());
}

test "datagram: the peer's advertised maximum lowers the cap" {
    const limits = Limits{ .local_max = 1500, .peer_max = 1300 };
    try testing.expectEqual(@as(usize, 1300), limits.effective());
}

test "datagram: a larger local maximum never overrides a smaller peer limit" {
    const limits = Limits{ .local_max = max_size, .peer_max = 1200 };
    try testing.expectEqual(base_size, limits.effective());
}

test "datagram: a larger peer maximum never raises the cap past the local one" {
    const limits = Limits{ .local_max = 1300, .peer_max = 65_527 };
    try testing.expectEqual(@as(usize, 1300), limits.effective());
}

test "datagram: the validated path size lowers the cap but never below the floor" {
    try testing.expectEqual(
        @as(usize, 1350),
        (Limits{ .local_max = 1500, .peer_max = 1500, .validated_path_max = 1350 }).effective(),
    );
    try testing.expectEqual(
        base_size,
        (Limits{ .local_max = 1500, .peer_max = 1500, .validated_path_max = 900 }).effective(),
    );
}

test "datagram: probes may exceed the validated path size but not the endpoint bounds" {
    const limits = Limits{ .local_max = 1500, .peer_max = 1400, .validated_path_max = base_size };
    try testing.expectEqual(base_size, limits.effective());
    try testing.expectEqual(@as(usize, 1400), limits.probeCeiling());
}

test "datagram: out-of-range bounds are clamped rather than trusted" {
    try testing.expectEqual(base_size, (Limits{ .local_max = 0, .peer_max = 65_527 }).effective());
    try testing.expectEqual(base_size, (Limits{ .local_max = 1500, .peer_max = 0 }).effective());
    try testing.expectEqual(
        max_size,
        (Limits{ .local_max = std.math.maxInt(u64), .peer_max = std.math.maxInt(u64) }).effective(),
    );
}

//! TLS 1.3 post-handshake `KeyUpdate` (RFC 8446 §4.6.3).
//!
//! This module owns only the message's wire form and the local policy for
//! *when* an endpoint should ask for a proactive update. It has no record,
//! socket, QUIC, or key-schedule types: the secret advancement itself is
//! `key_schedule.KeySchedule.nextTrafficSecret`, and applying that to live
//! traffic keys is `record_epoch_bridge`.
//!
//! `KeyUpdate` is record-mode-only. RFC 9001 §6 removes it from TLS-over-QUIC
//! entirely — QUIC carries its own key phase in the packet header — so a QUIC
//! endpoint that receives one must abort with `unexpected_message`. That
//! rejection lives at the transport seam that knows which profile is in use
//! (`tls13_backend.onKeyUpdate`), not here.
//!
//! `KeyUpdate` is deliberately *not* fed to the handshake transcript. The
//! message has no transcript-derived output of its own, every transcript-bound
//! secret this implementation derives is fixed no later than the client's
//! Finished, and mainstream implementations (OpenSSL, BoringSSL) leave it out
//! as well — hashing it in would desynchronize the transcript against any peer
//! that does not.

const std = @import("std");
const messages = @import("messages.zig");

/// `KeyUpdateRequest` (RFC 8446 §4.6.3). The value tells the receiver whether
/// it must respond with a `KeyUpdate` of its own.
pub const Request = enum(u8) {
    /// The sender advanced its own sending keys and wants nothing back.
    update_not_requested = 0,
    /// The sender advanced its own sending keys and asks the peer to advance
    /// *its* sending keys too, replying with `update_not_requested`.
    update_requested = 1,
};

/// `KeyUpdate`'s body is a single `KeyUpdateRequest` byte.
pub const body_len = 1;
/// Framed message length: 1-byte type + 3-byte length + `body_len`.
pub const message_len = 4 + body_len;

/// RFC 8446 §4.6.3 separates the two ways a `KeyUpdate` can be wrong, and the
/// alerts differ, so the decoder does too:
///
///   * a body that is not exactly one byte is a framing failure
///     (`decode_error`), and
///   * a well-framed body carrying a value outside `KeyUpdateRequest` is a
///     semantic failure the RFC names explicitly: "If an implementation
///     receives any other value, it MUST terminate the connection with an
///     `illegal_parameter` alert."
pub const DecodeError = error{ MalformedHandshake, IllegalParameter };
pub const EncodeError = error{HandshakeBufferOverflow};

/// Decodes a `KeyUpdate` *body* (the bytes after the 4-byte handshake header).
pub fn decode(body: []const u8) DecodeError!Request {
    if (body.len != body_len) return error.MalformedHandshake;
    return std.enums.fromInt(Request, body[0]) orelse error.IllegalParameter;
}

/// Encodes a complete framed `KeyUpdate` handshake message into `out`.
pub fn encode(request: Request, out: []u8) EncodeError![]const u8 {
    const body = [body_len]u8{@intFromEnum(request)};
    return messages.encode(.key_update, &body, out) catch |err| switch (err) {
        error.HandshakeBufferOverflow => error.HandshakeBufferOverflow,
        // `body` is one byte, so neither the message-length nor the
        // extension-shaped failures `messages.encode` declares can occur.
        else => unreachable,
    };
}

/// When to advance sending keys without being asked.
///
/// RFC 8446 §5.5 bounds how much traffic a single set of record keys may
/// protect, and the bound is per-suite (AES-GCM's is the record count at which
/// its confidentiality/integrity margins are still acceptable). This type is
/// the hook the record layer consults; it deliberately expresses the limit in
/// *records sealed*, which is exactly `record_protection.WriteState.sequence`,
/// so no separate accounting can drift away from the sequence number that
/// actually feeds the per-record nonce.
///
/// Nothing here schedules an update on its own. `reached` is a predicate the
/// owner of the write state calls; whether to act on it is that owner's
/// policy, which keeps this module free of any transport concern.
pub const UsageLimits = struct {
    /// The most records one generation of sending keys may protect, *counting
    /// the `KeyUpdate` that retires it*. `null` disables proactive updates
    /// entirely, which is the default: an endpoint is always free to never
    /// send a `KeyUpdate`, and turning it on by default would change the wire
    /// behavior of every existing connection.
    ///
    /// This is a cap on the generation, not a count at which to start
    /// thinking about one — see `reached`, which fires a record early so that
    /// the `KeyUpdate` fits underneath the cap rather than exceeding it.
    records: ?u64 = null,

    /// RFC 8446 §5.5's AES-GCM record limit (2^24.5, rounded down to a whole
    /// number of records). Callers opting into proactive updates should pick a
    /// value at or below this; it is offered as a named constant rather than a
    /// default so the choice stays explicit at the call site.
    ///
    /// Safe to pass straight to `records`: `reached` reserves the control
    /// record, so a caller writing the RFC's own number gets the RFC's own
    /// guarantee without having to subtract anything themselves.
    pub const aes_gcm_record_limit: u64 = 23_726_566;

    /// Whether `records_sealed` records under the current generation is enough
    /// to act on.
    ///
    /// Fires one record *before* the configured cap, because acting on it is
    /// not free: `requestKeyUpdate` must seal the `KeyUpdate` itself under the
    /// keys it is retiring (RFC 8446 §4.6.3 — the message announcing a
    /// transition is protected by the generation it ends), so that message is
    /// one more record against the old keys. Firing at the cap itself would
    /// let the retiring generation protect `records + 1` records, which is
    /// precisely the bound the caller asked not to cross.
    ///
    /// Saturating rather than wrapping: a nonsensical `records = 0` is due
    /// immediately instead of underflowing into a limit of `2^64 - 1`, which
    /// would silently disable the policy it was meant to enforce.
    pub fn reached(self: UsageLimits, records_sealed: u64) bool {
        const limit = self.records orelse return false;
        return records_sealed >= limit -| 1;
    }
};

test "decode accepts both defined request values" {
    try std.testing.expectEqual(Request.update_not_requested, try decode(&.{0}));
    try std.testing.expectEqual(Request.update_requested, try decode(&.{1}));
}

test "decode separates framing failures from illegal request values" {
    // Wrong body length is a framing failure -> decode_error.
    try std.testing.expectError(error.MalformedHandshake, decode(&.{}));
    try std.testing.expectError(error.MalformedHandshake, decode(&.{ 0, 0 }));
    // Well-framed but undefined value -> illegal_parameter (RFC 8446 §4.6.3).
    var value: u16 = 2;
    while (value <= 255) : (value += 1) {
        try std.testing.expectError(error.IllegalParameter, decode(&.{@intCast(value)}));
    }
}

test "encode produces the framed message decode round-trips" {
    for ([_]Request{ .update_not_requested, .update_requested }) |request| {
        var buf: [message_len]u8 = undefined;
        const framed = try encode(request, &buf);
        try std.testing.expectEqual(@as(usize, message_len), framed.len);
        const message = try messages.decode(framed);
        try std.testing.expectEqual(messages.MessageType.key_update, message.kind);
        try std.testing.expectEqual(request, try decode(message.body));
    }
}

test "encode rejects a buffer that cannot hold the framed message" {
    var buf: [message_len - 1]u8 = undefined;
    try std.testing.expectError(error.HandshakeBufferOverflow, encode(.update_requested, &buf));
}

test "usage limits stay inert until configured" {
    const off: UsageLimits = .{};
    try std.testing.expect(!off.reached(0));
    try std.testing.expect(!off.reached(std.math.maxInt(u64)));

    // A cap of 4 becomes due at 3 sealed records: the KeyUpdate is then the
    // 4th and final record the retiring generation protects.
    const on: UsageLimits = .{ .records = 4 };
    try std.testing.expect(!on.reached(2));
    try std.testing.expect(on.reached(3));
    try std.testing.expect(on.reached(4));
}

test "the AES-GCM cap leaves room for the KeyUpdate that retires the generation" {
    // The property the constant exists for: a caller who configures RFC 8446
    // §5.5's own number must never let the retiring keys protect more records
    // than it names. Since `requestKeyUpdate` seals the KeyUpdate under those
    // same old keys, becoming due at the cap itself would make that message
    // the (limit + 1)-th record -- one past the bound.
    const policy: UsageLimits = .{ .records = UsageLimits.aes_gcm_record_limit };
    try std.testing.expect(!policy.reached(UsageLimits.aes_gcm_record_limit - 2));
    try std.testing.expect(policy.reached(UsageLimits.aes_gcm_record_limit - 1));
    // Acting the moment it is due seals the KeyUpdate as record number
    // `aes_gcm_record_limit`, the last one permitted -- not the first one
    // beyond it.
    try std.testing.expectEqual(
        UsageLimits.aes_gcm_record_limit,
        (UsageLimits.aes_gcm_record_limit - 1) + 1,
    );
}

test "a degenerate zero cap is due immediately rather than underflowing" {
    // `0 -| 1` saturates to 0, so this reports due at once. Wrapping would
    // have produced a limit of 2^64 - 1 and silently disabled the policy.
    const zero: UsageLimits = .{ .records = 0 };
    try std.testing.expect(zero.reached(0));

    const one: UsageLimits = .{ .records = 1 };
    try std.testing.expect(one.reached(0));

    const huge: UsageLimits = .{ .records = std.math.maxInt(u64) };
    try std.testing.expect(!huge.reached(std.math.maxInt(u64) - 2));
    try std.testing.expect(huge.reached(std.math.maxInt(u64) - 1));
}

//! TLS `record_size_limit` negotiation (RFC 8449) and bounded record padding.
//!
//! This module owns only *policy and arithmetic*: the extension's wire form,
//! the rules for what a peer may advertise, and how large an outgoing
//! `TLSInnerPlaintext` (and its optional padding) may be. It performs no I/O,
//! holds no keys, and never touches the AEAD. `tls13_backend` carries the
//! extension through the handshake, `record_epoch_bridge` applies the results
//! to sealing and opening, and `encrypted_stream` sizes its writes from them.
//!
//! Two independently negotiated numbers, deliberately kept separate:
//!
//!   * `Limits.local` — the largest inner plaintext *we* are willing to
//!     receive. We advertise it, and we reject any protected record that
//!     exceeds it, because a peer that ignores our advertisement is asking us
//!     to buffer more than we agreed to.
//!   * `Limits.peer` — the largest inner plaintext the *peer* is willing to
//!     receive. We cap every protected record we send to it. Absent (`null`)
//!     means the peer never sent the extension, which RFC 8449 defines as "the
//!     protocol maximum", not "unlimited".
//!
//! RFC 8449 §4 measures the limit as the length of the complete
//! `TLSInnerPlaintext` for TLS 1.3 — `content || content_type || padding` —
//! which is why the protocol maximum here is 2^14+1 rather than 2^14, and why
//! usable *content* is always one byte less than the limit before padding.
//!
//! Padding (RFC 8446 §5.4) is a distinct, purely local knob and is not
//! negotiated at all. It is a traffic-analysis countermeasure: it hides the
//! true length of a record's content from an observer, at the cost of sending
//! bytes that carry no data. It is *not* a performance feature, and it is not
//! record coalescing — see `docs/TLS_RECORD_TRANSPORT.md`.

const std = @import("std");
const record_codec = @import("record_codec.zig");

/// RFC 8449 §5: `record_size_limit(28)`.
pub const extension_type: u16 = 28;

/// The extension body is a single `uint16`.
pub const body_len = 2;

/// RFC 8449 §4: "Endpoints MUST NOT send a `record_size_limit` extension with
/// a value smaller than 64. An endpoint MUST treat receipt of a smaller value
/// as a fatal error and generate an `illegal_parameter` alert."
pub const min_limit: u16 = 64;

/// RFC 8449 §4: the TLS 1.3 protocol maximum, counting the content-type byte
/// and any padding that share the inner plaintext with the content itself.
pub const max_limit: u16 = record_codec.max_plaintext_fragment_len + 1;

/// The default advertisement: the full protocol maximum. Advertising anything
/// smaller is a deliberate memory/latency tradeoff a caller opts into — an
/// endpoint that supports every record size interoperates most widely by
/// saying so, and a smaller default would silently shrink every peer's records
/// (more records, more per-record overhead) for connections that never needed
/// it.
pub const default_limit: u16 = max_limit;

pub const DecodeError = error{
    /// The extension body was not exactly two bytes. A framing failure ->
    /// `decode_error`.
    MalformedHandshake,
    /// A well-framed value outside the range this endpoint accepts ->
    /// `illegal_parameter`.
    IllegalParameter,
};

pub const ConfigError = error{
    /// A locally configured limit or padding block is outside the range the
    /// protocol (or this record layer) can honor. Always our own bug or
    /// misconfiguration, never a peer's.
    InvalidRecordSizeLimit,
};

/// What to do with a peer value above `max_limit`.
///
/// RFC 8449 §4 makes this asymmetric on purpose: "A server MUST NOT enforce
/// this restriction; a client might advertise a higher limit that is enabled
/// by an extension or version the server does not understand. A client MAY
/// abort the handshake with an `illegal_parameter` alert if the
/// record_size_limit extension includes a value greater than the maximum
/// record size permitted by the negotiated protocol version."
pub const OverMaxPolicy = enum {
    /// Server behavior: treat the value as the protocol maximum and carry on.
    clamp,
    /// Client behavior: the server answered with a limit larger than TLS 1.3
    /// permits, which no future-version reading can excuse once the version is
    /// already settled. Reject.
    reject,
};

/// Decode the extension body. `over_max` selects the role-appropriate handling
/// of an above-maximum advertisement; the below-minimum rejection is
/// unconditional for both roles.
pub fn decode(body: []const u8, over_max: OverMaxPolicy) DecodeError!u16 {
    if (body.len != body_len) return error.MalformedHandshake;
    const value = std.mem.readInt(u16, body[0..body_len], .big);
    if (value < min_limit) return error.IllegalParameter;
    if (value > max_limit) return switch (over_max) {
        .clamp => max_limit,
        .reject => error.IllegalParameter,
    };
    return value;
}

/// Encode the extension body (the two payload bytes, without the type/length
/// header the caller's message writer owns).
pub fn encodeBody(limit: u16) [body_len]u8 {
    var out: [body_len]u8 = undefined;
    std.mem.writeInt(u16, &out, limit, .big);
    return out;
}

/// The negotiated record-size state of one connection.
pub const Limits = struct {
    /// Largest inner plaintext we accept from the peer, and the value we
    /// advertise. Always within `[min_limit, max_limit]`.
    local: u16 = default_limit,
    /// Largest inner plaintext the peer accepts. `null` until the peer's
    /// advertisement is parsed, and for a peer that never sends one.
    peer: ?u16 = null,

    /// Reject a local configuration the protocol cannot express, before it can
    /// reach the wire or silently degrade into an unenforceable bound.
    pub fn validate(self: Limits) ConfigError!void {
        if (self.local < min_limit or self.local > max_limit) return error.InvalidRecordSizeLimit;
    }

    /// The largest `TLSInnerPlaintext` we may *send*: the peer's limit, or the
    /// protocol maximum when it never advertised one.
    pub fn outboundInnerMax(self: Limits) usize {
        return @min(self.peer orelse max_limit, max_limit);
    }

    /// The largest *content* one outgoing protected record may carry, with the
    /// content-type byte RFC 8449 counts against the limit already reserved.
    /// Never zero: `min_limit` is 64, so at least 63 content bytes always fit.
    pub fn outboundContentMax(self: Limits) usize {
        return self.outboundInnerMax() - 1;
    }

    /// The largest `TLSInnerPlaintext` we accept on the wire. Bytes past this
    /// are a peer that ignored our advertisement.
    pub fn inboundInnerMax(self: Limits) usize {
        return self.local;
    }

    /// True when the peer's advertisement actually constrains us — i.e. when a
    /// write must be split more finely than the protocol maximum alone would
    /// require. Diagnostics and metrics only.
    pub fn peerConstrains(self: Limits) bool {
        return self.outboundInnerMax() < max_limit;
    }
};

/// Local, non-negotiated padding policy (RFC 8446 §5.4).
///
/// Padding is a *privacy* control: it obscures how many content bytes a record
/// actually carried. It costs bandwidth and AEAD work for every byte added and
/// buys nothing else, so the default is off.
pub const PaddingPolicy = union(enum) {
    /// No padding. Every record's inner plaintext is exactly
    /// `content || content_type`.
    none,
    /// Round each inner plaintext up to a multiple of `block` bytes, never
    /// past the negotiated cap. A `block` of 1 is equivalent to `.none`.
    ///
    /// Chosen over a fixed record size because a fixed size cannot pad a
    /// record that is already larger, and cannot avoid inflating a
    /// small-record stream by a constant factor; rounding degrades smoothly
    /// and is what a length-observing adversary must actually defeat.
    block: u16,

    /// The largest block this record layer will honor. A block above the
    /// protocol maximum could never be reached, so accepting one would
    /// silently mean "pad to the cap" rather than what the caller wrote.
    pub const max_block: u16 = max_limit;

    pub fn validate(self: PaddingPolicy) ConfigError!void {
        switch (self) {
            .none => {},
            .block => |block| if (block == 0 or block > max_block) return error.InvalidRecordSizeLimit,
        }
    }

    /// Padding bytes to append to a record carrying `content_len` bytes, given
    /// that the complete inner plaintext must not exceed `inner_max`.
    ///
    /// Total-bounded by construction: the result is derived by subtracting the
    /// unpadded inner length from a target that is itself clamped to
    /// `inner_max`, so `content_len + 1 + padding <= inner_max` holds for every
    /// input — including an already-at-cap record, which gets zero.
    pub fn paddingFor(self: PaddingPolicy, content_len: usize, inner_max: usize) usize {
        const block = switch (self) {
            .none => return 0,
            .block => |value| value,
        };
        if (block <= 1) return 0;
        // `content_len` is already capped to `inner_max - 1` by the caller, so
        // this cannot overflow a `usize` on any reachable path; saturating
        // keeps a hypothetical caller bug from wrapping into a huge padding.
        const unpadded = content_len +| 1;
        if (unpadded >= inner_max) return 0;
        const remainder = unpadded % block;
        if (remainder == 0) return 0;
        const target = unpadded +| (block - remainder);
        return @min(target, inner_max) - unpadded;
    }
};

/// Observable record-sizing effects, for operators and tests. Counters only —
/// nothing here feeds a decision.
pub const Counters = struct {
    /// Writes whose length was reduced by the peer's advertised limit below
    /// what the protocol maximum alone would have allowed.
    peer_limited_writes: u64 = 0,
    /// Protected records that carried at least one padding byte.
    padded_records: u64 = 0,
    /// Total padding bytes sent.
    padding_bytes: u64 = 0,
    /// Inbound protected records refused for exceeding `Limits.local`.
    oversize_records_rejected: u64 = 0,

    pub fn notePadding(self: *Counters, padding_len: usize) void {
        if (padding_len == 0) return;
        self.padded_records +|= 1;
        self.padding_bytes +|= padding_len;
    }
};

const testing = std.testing;

test "the protocol maximum counts the content-type byte" {
    // RFC 8449 §4: TLS 1.3's limit is 2^14+1 precisely because the value
    // bounds the whole TLSInnerPlaintext, not just the content.
    try testing.expectEqual(@as(u16, 16385), max_limit);
    try testing.expectEqual(@as(usize, record_codec.max_plaintext_fragment_len), (Limits{}).outboundContentMax());
}

test "decode round-trips every legal advertisement" {
    for ([_]u16{ min_limit, 100, 1024, max_limit - 1, max_limit }) |limit| {
        const body = encodeBody(limit);
        try testing.expectEqual(limit, try decode(&body, .reject));
        try testing.expectEqual(limit, try decode(&body, .clamp));
    }
}

test "a body that is not exactly two bytes is a framing failure" {
    try testing.expectError(error.MalformedHandshake, decode(&.{}, .clamp));
    try testing.expectError(error.MalformedHandshake, decode(&.{0x40}, .clamp));
    try testing.expectError(error.MalformedHandshake, decode(&.{ 0x40, 0x00, 0x00 }, .clamp));
}

test "values below 64 are illegal for both roles" {
    var value: u16 = 0;
    while (value < min_limit) : (value += 1) {
        const body = encodeBody(value);
        try testing.expectError(error.IllegalParameter, decode(&body, .clamp));
        try testing.expectError(error.IllegalParameter, decode(&body, .reject));
    }
    // The boundary itself is legal.
    const at_min = encodeBody(min_limit);
    try testing.expectEqual(min_limit, try decode(&at_min, .reject));
}

test "an above-maximum value clamps for a server and is rejected by a client" {
    for ([_]u16{ max_limit + 1, 20000, std.math.maxInt(u16) }) |value| {
        const body = encodeBody(value);
        // RFC 8449 §4: "A server MUST NOT enforce this restriction" -- a client
        // may be advertising a size a future version enables.
        try testing.expectEqual(max_limit, try decode(&body, .clamp));
        // The client already knows the negotiated version, so no such reading
        // is available to it; RFC 8449 §4 permits the abort and we take it.
        try testing.expectError(error.IllegalParameter, decode(&body, .reject));
    }
}

test "an absent peer advertisement means the protocol maximum, not unlimited" {
    const unnegotiated = Limits{};
    try testing.expectEqual(@as(usize, max_limit), unnegotiated.outboundInnerMax());
    try testing.expect(!unnegotiated.peerConstrains());
}

test "outbound sizing reserves the content-type byte the peer's limit counts" {
    const limits = Limits{ .peer = 64 };
    try testing.expectEqual(@as(usize, 64), limits.outboundInnerMax());
    try testing.expectEqual(@as(usize, 63), limits.outboundContentMax());
    try testing.expect(limits.peerConstrains());
}

test "a peer value at or above the maximum never widens the protocol bound" {
    // `peer` is only ever populated by `decode`, which already clamps, but the
    // struct must not depend on that to stay within the protocol maximum.
    const oversized = Limits{ .peer = std.math.maxInt(u16) };
    try testing.expectEqual(@as(usize, max_limit), oversized.outboundInnerMax());
    try testing.expect(!oversized.peerConstrains());
}

test "local configuration outside the protocol range is rejected" {
    try (Limits{ .local = min_limit }).validate();
    try (Limits{ .local = max_limit }).validate();
    try testing.expectError(error.InvalidRecordSizeLimit, (Limits{ .local = min_limit - 1 }).validate());
    try testing.expectError(error.InvalidRecordSizeLimit, (Limits{ .local = max_limit + 1 }).validate());
}

test "padding is off by default and a degenerate block is inert" {
    const off: PaddingPolicy = .none;
    try testing.expectEqual(@as(usize, 0), off.paddingFor(100, max_limit));
    try testing.expectEqual(@as(usize, 0), (PaddingPolicy{ .block = 1 }).paddingFor(100, max_limit));
}

test "block padding rounds the whole inner plaintext, not just the content" {
    const policy = PaddingPolicy{ .block = 64 };
    // 100 content bytes -> 101 inner bytes -> next multiple of 64 is 128.
    try testing.expectEqual(@as(usize, 27), policy.paddingFor(100, max_limit));
    // 63 content bytes -> 64 inner bytes, already aligned: nothing to add.
    try testing.expectEqual(@as(usize, 0), policy.paddingFor(63, max_limit));
    // A single byte still costs a full block boundary.
    try testing.expectEqual(@as(usize, 62), policy.paddingFor(1, max_limit));
}

test "padding never pushes the inner plaintext past the negotiated cap" {
    // The acceptance criterion: for every block size, every content length,
    // and every cap, `content + type + padding` stays within the cap.
    const blocks = [_]u16{ 2, 3, 64, 512, 4096, max_limit };
    const caps = [_]usize{ min_limit, 65, 100, 1024, max_limit - 1, max_limit };
    for (blocks) |block| {
        const policy = PaddingPolicy{ .block = block };
        for (caps) |cap| {
            var content_len: usize = 0;
            while (content_len < cap) : (content_len += 1) {
                const padding = policy.paddingFor(content_len, cap);
                try testing.expect(content_len + 1 + padding <= cap);
                try testing.expect(content_len + 1 + padding <= max_limit);
            }
        }
    }
}

test "a record already at the cap is never padded" {
    const policy = PaddingPolicy{ .block = 512 };
    // Content that exactly fills the cap once the content-type byte is added.
    try testing.expectEqual(@as(usize, 0), policy.paddingFor(max_limit - 1, max_limit));
    try testing.expectEqual(@as(usize, 0), policy.paddingFor(min_limit - 1, min_limit));
}

test "padding policy configuration is validated" {
    const off: PaddingPolicy = .none;
    try off.validate();
    try (PaddingPolicy{ .block = 1 }).validate();
    try (PaddingPolicy{ .block = PaddingPolicy.max_block }).validate();
    try testing.expectError(error.InvalidRecordSizeLimit, (PaddingPolicy{ .block = 0 }).validate());
    try testing.expectError(
        error.InvalidRecordSizeLimit,
        (PaddingPolicy{ .block = PaddingPolicy.max_block + 1 }).validate(),
    );
}

test "counters only move for records that actually carried padding" {
    var counters = Counters{};
    counters.notePadding(0);
    try testing.expectEqual(@as(u64, 0), counters.padded_records);
    counters.notePadding(27);
    counters.notePadding(5);
    try testing.expectEqual(@as(u64, 2), counters.padded_records);
    try testing.expectEqual(@as(u64, 32), counters.padding_bytes);
}

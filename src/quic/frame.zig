//! QUIC v1 frame codec (RFC 9000 §19): the wire encode/decode layer between
//! packet payloads and the connection driver. Pure functions over caller
//! buffers — no allocation, no connection state. The driver in
//! `connection.zig` owns which frames are legal at which encryption level and
//! what they do to connection state; this module only guarantees that every
//! decoded frame is structurally well-formed and every encoded frame is
//! exactly what RFC 9000 specifies.
//!
//! ACK frames convert to/from the `recovery.zig` models (`AckFrameModel` out,
//! `AckRangeSet` in) so recovery logic never sees wire bytes.

const std = @import("std");
const varint = @import("quic_varint");
const cid = @import("cid.zig");
const stream = @import("stream.zig");
const recovery = @import("recovery.zig");

pub const DecodeError = error{
    TruncatedFrame,
    UnknownFrameType,
    MalformedFrame,
};

pub const EncodeError = error{
    BufferTooShort,
};

// RFC 9000 §19 frame types.
pub const frame_padding: u64 = 0x00;
pub const frame_ping: u64 = 0x01;
pub const frame_ack: u64 = 0x02;
pub const frame_ack_ecn: u64 = 0x03;
pub const frame_reset_stream: u64 = 0x04;
pub const frame_stop_sending: u64 = 0x05;
pub const frame_crypto: u64 = 0x06;
pub const frame_new_token: u64 = 0x07;
pub const frame_stream_base: u64 = 0x08; // 0x08..0x0f: OFF=0x04, LEN=0x02, FIN=0x01
pub const frame_max_data: u64 = 0x10;
pub const frame_max_stream_data: u64 = 0x11;
pub const frame_max_streams_bidi: u64 = 0x12;
pub const frame_max_streams_uni: u64 = 0x13;
pub const frame_data_blocked: u64 = 0x14;
pub const frame_stream_data_blocked: u64 = 0x15;
pub const frame_streams_blocked_bidi: u64 = 0x16;
pub const frame_streams_blocked_uni: u64 = 0x17;
pub const frame_new_connection_id: u64 = 0x18;
pub const frame_retire_connection_id: u64 = 0x19;
pub const frame_path_challenge: u64 = 0x1a;
pub const frame_path_response: u64 = 0x1b;
pub const frame_connection_close_transport: u64 = 0x1c;
pub const frame_connection_close_app: u64 = 0x1d;
pub const frame_handshake_done: u64 = 0x1e;

pub const path_data_len = 8;

pub const Ecn = struct {
    ect0: u64,
    ect1: u64,
    ce: u64,
};

/// A decoded ACK frame, converted to the bounded `recovery.AckRangeSet`.
/// Ranges beyond the set's capacity are dropped from the *low* end — the
/// highest packet numbers always survive, so forward progress (new data,
/// handshake completion) is never blocked; older packets simply retransmit.
pub const Ack = struct {
    ranges: recovery.AckRangeSet,
    ack_delay_raw: u64,
    largest_acknowledged: u64,
    ecn: ?Ecn = null,

    pub fn ackDelayUs(self: Ack, ack_delay_exponent: u6) u64 {
        return self.ack_delay_raw *| (@as(u64, 1) << ack_delay_exponent);
    }
};

pub const ConnectionClose = struct {
    error_code: u64,
    /// The frame type that provoked a transport close (0x1c); null for an
    /// application close (0x1d).
    frame_type: ?u64,
    reason: []const u8,
    is_application: bool,
};

pub const Frame = union(enum) {
    /// Run of PADDING bytes (coalesced during decode).
    padding: usize,
    ping,
    ack: Ack,
    reset_stream: stream.ResetStreamFrame,
    stop_sending: stream.StopSendingFrame,
    crypto: struct { offset: u64, data: []const u8 },
    new_token: struct { token: []const u8 },
    stream: stream.StreamFrame,
    max_data: u64,
    max_stream_data: struct { id: stream.StreamId, limit: u64 },
    max_streams_bidi: u64,
    max_streams_uni: u64,
    data_blocked: u64,
    stream_data_blocked: struct { id: stream.StreamId, limit: u64 },
    streams_blocked_bidi: u64,
    streams_blocked_uni: u64,
    new_connection_id: struct { frame: cid.NewConnectionIdFrame },
    retire_connection_id: cid.RetireConnectionIdFrame,
    path_challenge: [path_data_len]u8,
    path_response: [path_data_len]u8,
    connection_close: ConnectionClose,
    handshake_done,

    /// RFC 9002 §2: everything but ACK, PADDING, and CONNECTION_CLOSE elicits
    /// an acknowledgement.
    pub fn isAckEliciting(self: Frame) bool {
        return switch (self) {
            .padding, .ack, .connection_close => false,
            else => true,
        };
    }
};

pub const Decoded = struct {
    frame: Frame,
    len: usize,
};

/// Iterates the frames of one decrypted packet payload. Every structural
/// problem is a typed error; the caller decides protocol-level legality.
pub const Parser = struct {
    bytes: []const u8,
    pos: usize = 0,

    pub fn init(bytes: []const u8) Parser {
        return .{ .bytes = bytes };
    }

    pub fn next(self: *Parser) DecodeError!?Frame {
        if (self.pos == self.bytes.len) return null;
        const decoded = try decodeFrame(self.bytes[self.pos..]);
        self.pos += decoded.len;
        return decoded.frame;
    }
};

pub fn decodeFrame(bytes: []const u8) DecodeError!Decoded {
    var r = FrameReader{ .bytes = bytes };
    const frame_type = try r.int();
    switch (frame_type) {
        frame_padding => {
            // Coalesce the run: PADDING routinely fills most of an Initial.
            var run: usize = 1;
            while (r.pos < bytes.len and bytes[r.pos] == 0x00) : (r.pos += 1) run += 1;
            return .{ .frame = .{ .padding = run }, .len = r.pos };
        },
        frame_ping => return .{ .frame = .ping, .len = r.pos },
        frame_ack, frame_ack_ecn => {
            const largest = try r.int();
            const ack_delay = try r.int();
            const range_count = try r.int();
            const first_range = try r.int();
            if (first_range > largest) return error.MalformedFrame;

            var ranges = recovery.AckRangeSet{};
            // The set orders ranges ascending; wire order is descending from
            // `largest`. When the bounded set fills, the lowest (oldest)
            // ranges are dropped — but every wire range must still parse so
            // the frame boundary is found.
            ranges.insertRange(.{ .first = largest - first_range, .last = largest }) catch
                return error.MalformedFrame;
            var smallest = largest - first_range;
            var i: u64 = 0;
            while (i < range_count) : (i += 1) {
                const gap = try r.int();
                const range_len = try r.int();
                // next_last = smallest - gap - 2 (RFC 9000 §19.3.1)
                if (smallest < gap + 2) return error.MalformedFrame;
                const range_last = smallest - gap - 2;
                if (range_len > range_last) return error.MalformedFrame;
                const range_first = range_last - range_len;
                smallest = range_first;
                ranges.insertRange(.{ .first = range_first, .last = range_last }) catch {};
            }
            var ecn: ?Ecn = null;
            if (frame_type == frame_ack_ecn) {
                ecn = .{ .ect0 = try r.int(), .ect1 = try r.int(), .ce = try r.int() };
            }
            return .{
                .frame = .{ .ack = .{
                    .ranges = ranges,
                    .ack_delay_raw = ack_delay,
                    .largest_acknowledged = largest,
                    .ecn = ecn,
                } },
                .len = r.pos,
            };
        },
        frame_reset_stream => return .{
            .frame = .{ .reset_stream = .{
                .id = try r.int(),
                .app_error_code = try r.int(),
                .final_size = try r.int(),
            } },
            .len = r.pos,
        },
        frame_stop_sending => return .{
            .frame = .{ .stop_sending = .{
                .id = try r.int(),
                .app_error_code = try r.int(),
            } },
            .len = r.pos,
        },
        frame_crypto => {
            const offset = try r.int();
            const data = try r.lengthPrefixed();
            return .{ .frame = .{ .crypto = .{ .offset = offset, .data = data } }, .len = r.pos };
        },
        frame_new_token => {
            const token = try r.lengthPrefixed();
            if (token.len == 0) return error.MalformedFrame;
            return .{ .frame = .{ .new_token = .{ .token = token } }, .len = r.pos };
        },
        frame_stream_base...frame_stream_base + 0x07 => {
            const has_offset = frame_type & 0x04 != 0;
            const has_len = frame_type & 0x02 != 0;
            const fin = frame_type & 0x01 != 0;
            const id = try r.int();
            const offset: u64 = if (has_offset) try r.int() else 0;
            const data = if (has_len) try r.lengthPrefixed() else try r.rest();
            return .{
                .frame = .{ .stream = .{ .id = id, .offset = offset, .data = data, .fin = fin } },
                .len = r.pos,
            };
        },
        frame_max_data => return .{ .frame = .{ .max_data = try r.int() }, .len = r.pos },
        frame_max_stream_data => return .{
            .frame = .{ .max_stream_data = .{ .id = try r.int(), .limit = try r.int() } },
            .len = r.pos,
        },
        frame_max_streams_bidi => return .{ .frame = .{ .max_streams_bidi = try r.int() }, .len = r.pos },
        frame_max_streams_uni => return .{ .frame = .{ .max_streams_uni = try r.int() }, .len = r.pos },
        frame_data_blocked => return .{ .frame = .{ .data_blocked = try r.int() }, .len = r.pos },
        frame_stream_data_blocked => return .{
            .frame = .{ .stream_data_blocked = .{ .id = try r.int(), .limit = try r.int() } },
            .len = r.pos,
        },
        frame_streams_blocked_bidi => return .{ .frame = .{ .streams_blocked_bidi = try r.int() }, .len = r.pos },
        frame_streams_blocked_uni => return .{ .frame = .{ .streams_blocked_uni = try r.int() }, .len = r.pos },
        frame_new_connection_id => {
            const sequence = try r.int();
            const retire_prior_to = try r.int();
            if (retire_prior_to > sequence) return error.MalformedFrame;
            const cid_len = try r.byte();
            if (cid_len < 1 or cid_len > cid.max_generated_cid_len) return error.MalformedFrame;
            const cid_bytes = try r.fixed(cid_len);
            const token = try r.fixed(cid.stateless_reset_token_len);
            return .{
                .frame = .{ .new_connection_id = .{ .frame = .{
                    .sequence = sequence,
                    .retire_prior_to = retire_prior_to,
                    .cid = cid.ConnectionId.init(cid_bytes) catch return error.MalformedFrame,
                    .stateless_reset_token = token[0..cid.stateless_reset_token_len].*,
                } } },
                .len = r.pos,
            };
        },
        frame_retire_connection_id => return .{
            .frame = .{ .retire_connection_id = .{ .sequence = try r.int() } },
            .len = r.pos,
        },
        frame_path_challenge => return .{
            .frame = .{ .path_challenge = (try r.fixed(path_data_len))[0..path_data_len].* },
            .len = r.pos,
        },
        frame_path_response => return .{
            .frame = .{ .path_response = (try r.fixed(path_data_len))[0..path_data_len].* },
            .len = r.pos,
        },
        frame_connection_close_transport, frame_connection_close_app => {
            const is_app = frame_type == frame_connection_close_app;
            const error_code = try r.int();
            const provoking_type: ?u64 = if (is_app) null else try r.int();
            const reason = try r.lengthPrefixed();
            return .{
                .frame = .{ .connection_close = .{
                    .error_code = error_code,
                    .frame_type = provoking_type,
                    .reason = reason,
                    .is_application = is_app,
                } },
                .len = r.pos,
            };
        },
        frame_handshake_done => return .{ .frame = .handshake_done, .len = r.pos },
        else => return error.UnknownFrameType,
    }
}

const FrameReader = struct {
    bytes: []const u8,
    pos: usize = 0,

    fn int(self: *FrameReader) DecodeError!u64 {
        const decoded = varint.decode(self.bytes[self.pos..]) catch return error.TruncatedFrame;
        self.pos += decoded.len;
        return decoded.value;
    }

    fn byte(self: *FrameReader) DecodeError!u8 {
        if (self.pos == self.bytes.len) return error.TruncatedFrame;
        defer self.pos += 1;
        return self.bytes[self.pos];
    }

    fn fixed(self: *FrameReader, len: usize) DecodeError![]const u8 {
        if (len > self.bytes.len - self.pos) return error.TruncatedFrame;
        defer self.pos += len;
        return self.bytes[self.pos..][0..len];
    }

    fn lengthPrefixed(self: *FrameReader) DecodeError![]const u8 {
        const len = try self.int();
        if (len > self.bytes.len - self.pos) return error.TruncatedFrame;
        return self.fixed(@intCast(len));
    }

    fn rest(self: *FrameReader) DecodeError![]const u8 {
        return self.fixed(self.bytes.len - self.pos);
    }
};

// ---------------------------------------------------------------------------
// Encoders. Each returns the number of bytes written.
// ---------------------------------------------------------------------------

const FrameWriter = struct {
    buf: []u8,
    pos: usize = 0,

    fn int(self: *FrameWriter, value: u64) EncodeError!void {
        self.pos += varint.encode(value, self.buf[self.pos..]) catch return error.BufferTooShort;
    }

    fn bytes(self: *FrameWriter, data: []const u8) EncodeError!void {
        if (data.len > self.buf.len - self.pos) return error.BufferTooShort;
        @memcpy(self.buf[self.pos..][0..data.len], data);
        self.pos += data.len;
    }

    fn byte(self: *FrameWriter, value: u8) EncodeError!void {
        if (self.buf.len - self.pos < 1) return error.BufferTooShort;
        self.buf[self.pos] = value;
        self.pos += 1;
    }
};

pub fn encodePing(buf: []u8) EncodeError!usize {
    var w = FrameWriter{ .buf = buf };
    try w.int(frame_ping);
    return w.pos;
}

pub fn encodeHandshakeDone(buf: []u8) EncodeError!usize {
    var w = FrameWriter{ .buf = buf };
    try w.int(frame_handshake_done);
    return w.pos;
}

pub fn encodeCrypto(offset: u64, data: []const u8, buf: []u8) EncodeError!usize {
    var w = FrameWriter{ .buf = buf };
    try w.int(frame_crypto);
    try w.int(offset);
    try w.int(data.len);
    try w.bytes(data);
    return w.pos;
}

/// Bytes of framing overhead `encodeCrypto` adds in the worst case.
pub const max_crypto_overhead = 1 + 8 + 8;

/// STREAM with explicit offset and length; FIN from the grant.
pub fn encodeStream(id: stream.StreamId, offset: u64, data: []const u8, fin: bool, buf: []u8) EncodeError!usize {
    var w = FrameWriter{ .buf = buf };
    try w.int(frame_stream_base | 0x04 | 0x02 | @as(u64, @intFromBool(fin)));
    try w.int(id);
    try w.int(offset);
    try w.int(data.len);
    try w.bytes(data);
    return w.pos;
}

/// Bytes of framing overhead `encodeStream` adds in the worst case.
pub const max_stream_overhead = 1 + 8 + 8 + 8;

pub fn encodeAck(model: recovery.AckFrameModel, ack_delay_exponent: u6, buf: []u8) EncodeError!usize {
    return encodeAckFrame(model, null, ack_delay_exponent, buf);
}

/// RFC 9000 §19.3.2: the same ACK frame under type 0x03, with this endpoint's
/// received ECN counters appended (#256-E). Required rather than optional once
/// any marked packet has been received in the space — the peer's ECN validation
/// is built on these counts, and an ACK that omits them after a marked arrival
/// is exactly what tells the peer its marks are being stripped.
pub fn encodeAckEcn(
    model: recovery.AckFrameModel,
    counts: Ecn,
    ack_delay_exponent: u6,
    buf: []u8,
) EncodeError!usize {
    return encodeAckFrame(model, counts, ack_delay_exponent, buf);
}

fn encodeAckFrame(
    model: recovery.AckFrameModel,
    counts: ?Ecn,
    ack_delay_exponent: u6,
    buf: []u8,
) EncodeError!usize {
    var w = FrameWriter{ .buf = buf };
    try w.int(if (counts == null) frame_ack else frame_ack_ecn);
    try w.int(model.largest_acknowledged);
    try w.int(model.ack_delay_us >> ack_delay_exponent);
    try w.int(model.range_count);
    try w.int(model.first_ack_range);
    for (model.ranges[0..model.range_count]) |range| {
        try w.int(range.gap);
        try w.int(range.length);
    }
    if (counts) |ecn| {
        try w.int(ecn.ect0);
        try w.int(ecn.ect1);
        try w.int(ecn.ce);
    }
    return w.pos;
}

pub fn encodeResetStream(reset: stream.ResetStreamFrame, buf: []u8) EncodeError!usize {
    var w = FrameWriter{ .buf = buf };
    try w.int(frame_reset_stream);
    try w.int(reset.id);
    try w.int(reset.app_error_code);
    try w.int(reset.final_size);
    return w.pos;
}

pub fn encodeStopSending(stop: stream.StopSendingFrame, buf: []u8) EncodeError!usize {
    var w = FrameWriter{ .buf = buf };
    try w.int(frame_stop_sending);
    try w.int(stop.id);
    try w.int(stop.app_error_code);
    return w.pos;
}

pub fn encodeMaxData(limit: u64, buf: []u8) EncodeError!usize {
    var w = FrameWriter{ .buf = buf };
    try w.int(frame_max_data);
    try w.int(limit);
    return w.pos;
}

pub fn encodeMaxStreamData(id: stream.StreamId, limit: u64, buf: []u8) EncodeError!usize {
    var w = FrameWriter{ .buf = buf };
    try w.int(frame_max_stream_data);
    try w.int(id);
    try w.int(limit);
    return w.pos;
}

pub fn encodeMaxStreams(typ: stream.StreamType, limit: u64, buf: []u8) EncodeError!usize {
    var w = FrameWriter{ .buf = buf };
    try w.int(if (typ == .bidi) frame_max_streams_bidi else frame_max_streams_uni);
    try w.int(limit);
    return w.pos;
}

pub fn encodePathChallenge(data: [path_data_len]u8, buf: []u8) EncodeError!usize {
    var w = FrameWriter{ .buf = buf };
    try w.int(frame_path_challenge);
    try w.bytes(&data);
    return w.pos;
}

pub fn encodePathResponse(data: [path_data_len]u8, buf: []u8) EncodeError!usize {
    var w = FrameWriter{ .buf = buf };
    try w.int(frame_path_response);
    try w.bytes(&data);
    return w.pos;
}

/// Encode a NEW_CONNECTION_ID frame (type 0x18, RFC 9000 §19.15): sequence,
/// retire_prior_to, a length-prefixed CID (single byte, not a varint), and
/// the 16-byte stateless reset token.
pub fn encodeNewConnectionId(value: *const cid.NewConnectionIdFrame, buf: []u8) EncodeError!usize {
    var w = FrameWriter{ .buf = buf };
    try w.int(frame_new_connection_id);
    try w.int(value.sequence);
    try w.int(value.retire_prior_to);
    const cid_bytes = value.cid.slice();
    try w.byte(@intCast(cid_bytes.len));
    try w.bytes(cid_bytes);
    try w.bytes(&value.stateless_reset_token);
    return w.pos;
}

pub fn encodeRetireConnectionId(sequence: u64, buf: []u8) EncodeError!usize {
    var w = FrameWriter{ .buf = buf };
    try w.int(frame_retire_connection_id);
    try w.int(sequence);
    return w.pos;
}

pub const Close = struct {
    error_code: u64,
    /// Provoking frame type for a transport close; ignored for application.
    frame_type: u64 = 0,
    reason: []const u8 = "",
    is_application: bool = false,
};

pub fn encodeConnectionClose(close: Close, buf: []u8) EncodeError!usize {
    var w = FrameWriter{ .buf = buf };
    try w.int(if (close.is_application) frame_connection_close_app else frame_connection_close_transport);
    try w.int(close.error_code);
    if (!close.is_application) try w.int(close.frame_type);
    try w.int(close.reason.len);
    try w.bytes(close.reason);
    return w.pos;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn roundtripOne(encoded: []const u8) !Frame {
    const decoded = try decodeFrame(encoded);
    try testing.expectEqual(encoded.len, decoded.len);
    return decoded.frame;
}

test "padding runs coalesce and ping decodes" {
    const bytes = [_]u8{ 0x00, 0x00, 0x00, 0x01 };
    var parser = Parser.init(&bytes);
    const padding = (try parser.next()).?;
    try testing.expectEqual(@as(usize, 3), padding.padding);
    try testing.expect(!padding.isAckEliciting());
    const ping = (try parser.next()).?;
    try testing.expect(ping == .ping);
    try testing.expect(ping.isAckEliciting());
    try testing.expectEqual(@as(?Frame, null), try parser.next());
}

test "crypto and stream frames roundtrip" {
    var buf: [64]u8 = undefined;
    const clen = try encodeCrypto(7, "hello", &buf);
    const crypto_frame = try roundtripOne(buf[0..clen]);
    try testing.expectEqual(@as(u64, 7), crypto_frame.crypto.offset);
    try testing.expectEqualStrings("hello", crypto_frame.crypto.data);

    const slen = try encodeStream(4, 1024, "body", true, &buf);
    const stream_frame = try roundtripOne(buf[0..slen]);
    try testing.expectEqual(@as(u64, 4), stream_frame.stream.id);
    try testing.expectEqual(@as(u64, 1024), stream_frame.stream.offset);
    try testing.expect(stream_frame.stream.fin);
    try testing.expectEqualStrings("body", stream_frame.stream.data);
}

test "stream frame without offset or length uses implicit values" {
    // Type 0x09: no OFF, no LEN, FIN — data extends to the end of the payload.
    const bytes = [_]u8{ 0x09, 0x08, 'h', 'i' };
    const decoded = try decodeFrame(&bytes);
    try testing.expectEqual(@as(u64, 8), decoded.frame.stream.id);
    try testing.expectEqual(@as(u64, 0), decoded.frame.stream.offset);
    try testing.expect(decoded.frame.stream.fin);
    try testing.expectEqualStrings("hi", decoded.frame.stream.data);
}

test "ACK frame roundtrips through the recovery models" {
    var set = recovery.AckRangeSet{};
    try set.insertRange(.{ .first = 1, .last = 2 });
    try set.insertRange(.{ .first = 5, .last = 9 });
    const model = set.toAckFrame(1_000).?;

    var buf: [64]u8 = undefined;
    const len = try encodeAck(model, 3, &buf);
    const decoded = try roundtripOne(buf[0..len]);
    try testing.expect(decoded == .ack);
    const ack = decoded.ack;
    try testing.expectEqual(@as(u64, 9), ack.largest_acknowledged);
    try testing.expectEqual(@as(u64, 1_000), ack.ackDelayUs(3));
    try testing.expect(!decoded.isAckEliciting());
    try testing.expect(ack.ranges.contains(1));
    try testing.expect(ack.ranges.contains(2));
    try testing.expect(!ack.ranges.contains(3));
    try testing.expect(!ack.ranges.contains(4));
    try testing.expect(ack.ranges.contains(5));
    try testing.expect(ack.ranges.contains(9));
}

test "ACK frame with ECN counts parses" {
    // largest=3, delay=0, range_count=0, first_range=3, ect0=1, ect1=2, ce=3
    const bytes = [_]u8{ 0x03, 0x03, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03 };
    const decoded = try decodeFrame(&bytes);
    try testing.expectEqual(@as(u64, 1), decoded.frame.ack.ecn.?.ect0);
    try testing.expectEqual(@as(u64, 3), decoded.frame.ack.ecn.?.ce);
    try testing.expectEqual(bytes.len, decoded.len);
}

test "ACK_ECN roundtrips the received counters alongside the ranges (#256-E)" {
    var set = recovery.AckRangeSet{};
    try set.insertRange(.{ .first = 1, .last = 2 });
    try set.insertRange(.{ .first = 5, .last = 9 });
    const model = set.toAckFrame(1_000).?;

    var buf: [64]u8 = undefined;
    const len = try encodeAckEcn(model, .{ .ect0 = 17, .ect1 = 0, .ce = 4 }, 3, &buf);
    // The ECN counters ride on top of an otherwise identical frame, so the
    // type byte is the only structural difference from a plain ACK.
    try testing.expectEqual(@as(u8, frame_ack_ecn), buf[0]);
    const decoded = try roundtripOne(buf[0..len]);
    const ack = decoded.ack;
    try testing.expectEqual(@as(u64, 9), ack.largest_acknowledged);
    try testing.expect(ack.ranges.contains(1));
    try testing.expect(ack.ranges.contains(9));
    try testing.expectEqual(@as(u64, 17), ack.ecn.?.ect0);
    try testing.expectEqual(@as(u64, 0), ack.ecn.?.ect1);
    try testing.expectEqual(@as(u64, 4), ack.ecn.?.ce);

    // And a plain ACK still reports no counters at all, rather than zeros —
    // the peer's validation has to tell "nothing marked arrived" apart from
    // "this endpoint is not reporting".
    const plain_len = try encodeAck(model, 3, &buf);
    try testing.expectEqual(@as(?Ecn, null), (try roundtripOne(buf[0..plain_len])).ack.ecn);
}

test "malformed ACK ranges fail deterministically" {
    // first_range exceeds largest_acknowledged.
    try testing.expectError(error.MalformedFrame, decodeFrame(&[_]u8{ 0x02, 0x01, 0x00, 0x00, 0x02 }));
    // Gap underflows below packet number zero.
    try testing.expectError(error.MalformedFrame, decodeFrame(&[_]u8{ 0x02, 0x05, 0x00, 0x01, 0x00, 0x08, 0x00 }));
}

test "connection close frames roundtrip both variants" {
    var buf: [64]u8 = undefined;
    const tlen = try encodeConnectionClose(.{ .error_code = 0x0a, .frame_type = 0x06, .reason = "bad" }, &buf);
    const transport_close = try roundtripOne(buf[0..tlen]);
    try testing.expectEqual(@as(u64, 0x0a), transport_close.connection_close.error_code);
    try testing.expectEqual(@as(?u64, 0x06), transport_close.connection_close.frame_type);
    try testing.expect(!transport_close.connection_close.is_application);
    try testing.expect(!transport_close.isAckEliciting());
    try testing.expectEqualStrings("bad", transport_close.connection_close.reason);

    const alen = try encodeConnectionClose(.{ .error_code = 0x0100, .reason = "", .is_application = true }, &buf);
    const app_close = try roundtripOne(buf[0..alen]);
    try testing.expectEqual(@as(u64, 0x0100), app_close.connection_close.error_code);
    try testing.expectEqual(@as(?u64, null), app_close.connection_close.frame_type);
    try testing.expect(app_close.connection_close.is_application);
}

test "flow control and stream lifecycle frames roundtrip" {
    var buf: [64]u8 = undefined;
    var len = try encodeMaxData(1_000_000, &buf);
    try testing.expectEqual(@as(u64, 1_000_000), (try roundtripOne(buf[0..len])).max_data);

    len = try encodeMaxStreamData(4, 65_536, &buf);
    const msd = try roundtripOne(buf[0..len]);
    try testing.expectEqual(@as(u64, 4), msd.max_stream_data.id);
    try testing.expectEqual(@as(u64, 65_536), msd.max_stream_data.limit);

    len = try encodeMaxStreams(.bidi, 128, &buf);
    try testing.expectEqual(@as(u64, 128), (try roundtripOne(buf[0..len])).max_streams_bidi);
    len = try encodeMaxStreams(.uni, 3, &buf);
    try testing.expectEqual(@as(u64, 3), (try roundtripOne(buf[0..len])).max_streams_uni);

    len = try encodeResetStream(.{ .id = 4, .app_error_code = 0x0107, .final_size = 22 }, &buf);
    const reset = try roundtripOne(buf[0..len]);
    try testing.expectEqual(@as(u64, 0x0107), reset.reset_stream.app_error_code);
    try testing.expectEqual(@as(u64, 22), reset.reset_stream.final_size);

    len = try encodeStopSending(.{ .id = 8, .app_error_code = 0x0100 }, &buf);
    try testing.expectEqual(@as(u64, 8), (try roundtripOne(buf[0..len])).stop_sending.id);
}

test "NEW_CONNECTION_ID and RETIRE_CONNECTION_ID roundtrip" {
    // sequence=2 retire_prior_to=1 len=8 cid token(16)
    var bytes: [1 + 1 + 1 + 1 + 8 + 16]u8 = undefined;
    bytes[0] = 0x18;
    bytes[1] = 2;
    bytes[2] = 1;
    bytes[3] = 8;
    @memset(bytes[4..12], 0xab);
    @memset(bytes[12..28], 0xcd);
    const decoded = try decodeFrame(&bytes);
    try testing.expectEqual(bytes.len, decoded.len);
    const ncid = decoded.frame.new_connection_id.frame;
    try testing.expectEqual(@as(u64, 2), ncid.sequence);
    try testing.expectEqual(@as(u64, 1), ncid.retire_prior_to);
    try testing.expectEqual(@as(usize, 8), ncid.cid.slice().len);
    try testing.expectEqual(@as(u8, 0xcd), ncid.stateless_reset_token[0]);

    var buf: [16]u8 = undefined;
    const len = try encodeRetireConnectionId(7, &buf);
    try testing.expectEqual(@as(u64, 7), (try roundtripOne(buf[0..len])).retire_connection_id.sequence);
}

test "encodeNewConnectionId round-trips through decodeFrame" {
    var buf: [64]u8 = undefined;
    const value = cid.NewConnectionIdFrame{
        .sequence = 3,
        .retire_prior_to = 1,
        .cid = try cid.ConnectionId.init(&[_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 }),
        .stateless_reset_token = [_]u8{0xee} ** cid.stateless_reset_token_len,
    };
    const len = try encodeNewConnectionId(&value, &buf);
    const decoded = try roundtripOne(buf[0..len]);
    const ncid = decoded.new_connection_id.frame;
    try testing.expectEqual(@as(u64, 3), ncid.sequence);
    try testing.expectEqual(@as(u64, 1), ncid.retire_prior_to);
    try testing.expectEqualSlices(u8, value.cid.slice(), ncid.cid.slice());
    try testing.expectEqualSlices(u8, &value.stateless_reset_token, &ncid.stateless_reset_token);
}

test "encodeNewConnectionId fails deterministically on a too-short buffer" {
    const value = cid.NewConnectionIdFrame{
        .sequence = 0,
        .retire_prior_to = 0,
        .cid = try cid.ConnectionId.init(&[_]u8{ 1, 2, 3, 4 }),
        .stateless_reset_token = [_]u8{0} ** cid.stateless_reset_token_len,
    };
    var tiny: [4]u8 = undefined;
    try testing.expectError(error.BufferTooShort, encodeNewConnectionId(&value, &tiny));
}

test "NEW_CONNECTION_ID with retire_prior_to above sequence is malformed" {
    var bytes: [28]u8 = undefined;
    bytes[0] = 0x18;
    bytes[1] = 1; // sequence
    bytes[2] = 2; // retire_prior_to > sequence
    bytes[3] = 8;
    @memset(bytes[4..28], 0);
    try testing.expectError(error.MalformedFrame, decodeFrame(&bytes));
}

test "path challenge and response roundtrip" {
    var buf: [16]u8 = undefined;
    const data = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    var len = try encodePathChallenge(data, &buf);
    try testing.expectEqualSlices(u8, &data, &(try roundtripOne(buf[0..len])).path_challenge);
    len = try encodePathResponse(data, &buf);
    try testing.expectEqualSlices(u8, &data, &(try roundtripOne(buf[0..len])).path_response);
}

test "unknown frame types and truncations are typed errors" {
    try testing.expectError(error.UnknownFrameType, decodeFrame(&[_]u8{0x21}));
    try testing.expectError(error.TruncatedFrame, decodeFrame(&[_]u8{0x06})); // CRYPTO with nothing
    try testing.expectError(error.TruncatedFrame, decodeFrame(&[_]u8{ 0x06, 0x00, 0x05, 'x' })); // short data
    try testing.expectError(error.TruncatedFrame, decodeFrame(&[_]u8{0x1a})); // PATH_CHALLENGE short
    // HANDSHAKE_DONE is a bare type byte.
    const decoded = try decodeFrame(&[_]u8{0x1e});
    try testing.expect(decoded.frame == .handshake_done);
}

test "ACK arithmetic rejects overlap and underflow boundaries" {
    // largest=10, first_range=2 -> [8,10], then gap=0 range_len=2 -> [4,6].
    const valid = [_]u8{ 0x02, 10, 0, 1, 2, 0, 2 };
    const parsed = try decodeFrame(&valid);
    try testing.expect(parsed.frame.ack.ranges.contains(4));
    try testing.expect(parsed.frame.ack.ranges.contains(6));
    try testing.expect(!parsed.frame.ack.ranges.contains(7));
    try testing.expect(parsed.frame.ack.ranges.contains(8));
    try testing.expect(parsed.frame.ack.ranges.contains(10));

    // The second range would extend past its computed last packet.
    try testing.expectError(error.MalformedFrame, decodeFrame(&[_]u8{ 0x02, 10, 0, 1, 2, 0, 7 }));
    // The gap would underflow below packet number zero.
    try testing.expectError(error.MalformedFrame, decodeFrame(&[_]u8{ 0x02, 2, 0, 1, 0, 1, 0 }));
}

test "fixed-size frames reject exact-short truncations" {
    try testing.expectError(error.TruncatedFrame, decodeFrame(&[_]u8{ 0x1a, 1, 2, 3, 4, 5, 6, 7 }));
    try testing.expectError(error.TruncatedFrame, decodeFrame(&[_]u8{ 0x1b, 1, 2, 3, 4, 5, 6, 7 }));
    try testing.expectError(error.TruncatedFrame, decodeFrame(&[_]u8{ 0x18, 0, 0, 1, 0xaa } ++ [_]u8{0xbb} ** 15));
}

test "decoder covers frame families without production encoders" {
    try testing.expectError(error.MalformedFrame, decodeFrame(&[_]u8{ 0x07, 0x00 }));
    const new_token = try decodeFrame(&[_]u8{ 0x07, 0x03, 't', 'o', 'k' });
    try testing.expectEqualStrings("tok", new_token.frame.new_token.token);
    try testing.expectEqual(@as(usize, 5), new_token.len);

    try testing.expectEqual(@as(u64, 0x1234), (try decodeFrame(&[_]u8{ 0x14, 0x52, 0x34 })).frame.data_blocked);
    const stream_blocked = (try decodeFrame(&[_]u8{ 0x15, 0x04, 0x40, 0x80 })).frame.stream_data_blocked;
    try testing.expectEqual(@as(u64, 4), stream_blocked.id);
    try testing.expectEqual(@as(u64, 128), stream_blocked.limit);
    try testing.expectEqual(@as(u64, 5), (try decodeFrame(&[_]u8{ 0x16, 0x05 })).frame.streams_blocked_bidi);
    try testing.expectEqual(@as(u64, 7), (try decodeFrame(&[_]u8{ 0x17, 0x07 })).frame.streams_blocked_uni);

    const implicit = try decodeFrame(&[_]u8{ 0x08, 0x04, 'a', 'b' });
    try testing.expectEqual(@as(u64, 4), implicit.frame.stream.id);
    try testing.expectEqual(@as(u64, 0), implicit.frame.stream.offset);
    try testing.expect(!implicit.frame.stream.fin);
    try testing.expectEqualStrings("ab", implicit.frame.stream.data);
    try testing.expectEqual(@as(usize, 4), implicit.len);
}

test "ACK ECN and arithmetic boundaries consume exactly or fail typed" {
    const ack_ecn = [_]u8{ 0x03, 10, 0, 1, 2, 0, 2, 1, 2, 3 };
    const parsed = try decodeFrame(&ack_ecn);
    try testing.expectEqual(ack_ecn.len, parsed.len);
    try testing.expect(parsed.frame.ack.ranges.contains(4));
    try testing.expect(parsed.frame.ack.ranges.contains(6));
    try testing.expect(parsed.frame.ack.ranges.contains(8));
    try testing.expect(parsed.frame.ack.ranges.contains(10));
    try testing.expectEqual(@as(u64, 1), parsed.frame.ack.ecn.?.ect0);
    try testing.expectEqual(@as(u64, 2), parsed.frame.ack.ecn.?.ect1);
    try testing.expectEqual(@as(u64, 3), parsed.frame.ack.ecn.?.ce);

    try testing.expectError(error.TruncatedFrame, decodeFrame(ack_ecn[0 .. ack_ecn.len - 1]));
    try testing.expectError(error.MalformedFrame, decodeFrame(&[_]u8{ 0x02, 0, 0, 1, 0, 0, 1 }));

    var huge_gap: [16]u8 = undefined;
    var pos: usize = 0;
    pos += try varint.encode(frame_ack, huge_gap[pos..]);
    pos += try varint.encode(5, huge_gap[pos..]);
    pos += try varint.encode(0, huge_gap[pos..]);
    pos += try varint.encode(1, huge_gap[pos..]);
    pos += try varint.encode(0, huge_gap[pos..]);
    pos += try varint.encode(4611686018427387903, huge_gap[pos..]);
    pos += try varint.encode(0, huge_gap[pos..]);
    try testing.expectError(error.MalformedFrame, decodeFrame(huge_gap[0..pos]));
}

test "fuzz: frame decoder preserves bounded consumption and slice invariants" {
    try testing.fuzz({}, fuzzFrameDecodeInvariants, .{ .corpus = &.{
        "",
        "\x00",
        "\x01",
        "\x02\x00\x00\x00\x00",
        "\x03\x03\x00\x00\x03\x01\x02\x03",
        "\x06\x00\x00",
        "\x07\x01x",
        "\x08\x00payload",
        "\x0f\x04\x00\x03abc",
        "\x18\x00\x00\x08abcdefgh0123456789abcdef",
        "\x1a12345678",
        "\x1c\x00\x06\x00",
        "\x1e",
        "\x21",
        "\xff\xff\xff\xff\xff\xff\xff\xff",
    } });
}

test "fuzz: canonical frame encoders round-trip supported families" {
    try testing.fuzz({}, fuzzCanonicalFrameRoundTrip, .{ .corpus = &.{
        "\x00",
        "\x01\x02\x03\x04",
        "\xff\x00\x7f\x40",
        "\x18\x01\x00\x08",
    } });
}

test "parser accepts valid prefix before typed malformed tail" {
    var parser = Parser.init(&.{ 0x01, 0x21 });
    const ping = (try parser.next()).?;
    try testing.expect(ping == .ping);
    try testing.expectError(error.UnknownFrameType, parser.next());
}

test "every decoded frame length covers exactly the consumed bytes" {
    // A payload with several frames back to back must parse to the end.
    var buf: [128]u8 = undefined;
    var pos: usize = 0;
    pos += try encodePing(buf[pos..]);
    pos += try encodeCrypto(0, "abc", buf[pos..]);
    pos += try encodeMaxData(5, buf[pos..]);
    pos += try encodeHandshakeDone(buf[pos..]);
    var parser = Parser.init(buf[0..pos]);
    var count: usize = 0;
    while (try parser.next()) |_| count += 1;
    try testing.expectEqual(@as(usize, 4), count);
}

test {
    std.testing.refAllDecls(@This());
}

fn fuzzFrameDecodeInvariants(_: void, smith: *testing.Smith) !void {
    var buf: [512]u8 = undefined;
    const len = smith.slice(&buf);
    const input = buf[0..len];

    const decoded = decodeFrame(input) catch return;
    try testing.expect(decoded.len > 0);
    try testing.expect(decoded.len <= input.len);
    try expectFrameSlicesWithin(input, decoded.frame);

    var parser = Parser.init(input);
    var last_pos: usize = 0;
    var count: usize = 0;
    while (true) {
        const maybe_frame = parser.next() catch return;
        const frame = maybe_frame orelse break;
        try testing.expect(parser.pos > last_pos);
        try testing.expect(parser.pos <= input.len);
        try expectFrameSlicesWithin(input, frame);
        last_pos = parser.pos;
        count += 1;
    }
    try testing.expect(count > 0);
}

fn fuzzCanonicalFrameRoundTrip(_: void, smith: *testing.Smith) !void {
    var data: [32]u8 = undefined;
    const data_len = smith.slice(&data);
    const id = @as(u64, smith.value(u16));
    const limit = @as(u64, smith.value(u32));
    var buf: [256]u8 = undefined;

    switch (smith.value(u5) % 15) {
        0 => {
            const frame = try roundtripOne(buf[0..try encodePing(&buf)]);
            try testing.expect(frame == .ping);
        },
        1 => {
            const frame = try roundtripOne(buf[0..try encodeHandshakeDone(&buf)]);
            try testing.expect(frame == .handshake_done);
        },
        2 => {
            const offset = @as(u64, smith.value(u16));
            const frame = try roundtripOne(buf[0..try encodeCrypto(offset, data[0..data_len], &buf)]);
            try testing.expectEqual(offset, frame.crypto.offset);
            try testing.expectEqualSlices(u8, data[0..data_len], frame.crypto.data);
        },
        3 => {
            const offset = @as(u64, smith.value(u16));
            const fin = smith.value(u1) == 1;
            const frame = try roundtripOne(buf[0..try encodeStream(id, offset, data[0..data_len], fin, &buf)]);
            try testing.expectEqual(id, frame.stream.id);
            try testing.expectEqual(offset, frame.stream.offset);
            try testing.expectEqual(fin, frame.stream.fin);
            try testing.expectEqualSlices(u8, data[0..data_len], frame.stream.data);
        },
        4 => {
            const frame = try roundtripOne(buf[0..try encodeMaxData(limit, &buf)]);
            try testing.expectEqual(limit, frame.max_data);
        },
        5 => {
            const frame = try roundtripOne(buf[0..try encodeMaxStreamData(id, limit, &buf)]);
            try testing.expectEqual(id, frame.max_stream_data.id);
            try testing.expectEqual(limit, frame.max_stream_data.limit);
        },
        6 => {
            const frame = try roundtripOne(buf[0..try encodeMaxStreams(.bidi, limit, &buf)]);
            try testing.expectEqual(limit, frame.max_streams_bidi);
        },
        7 => {
            const frame = try roundtripOne(buf[0..try encodeMaxStreams(.uni, limit, &buf)]);
            try testing.expectEqual(limit, frame.max_streams_uni);
        },
        8 => {
            const app_error_code = @as(u64, smith.value(u16));
            const frame = try roundtripOne(buf[0..try encodeResetStream(.{ .id = id, .app_error_code = app_error_code, .final_size = limit }, &buf)]);
            try testing.expectEqual(id, frame.reset_stream.id);
            try testing.expectEqual(app_error_code, frame.reset_stream.app_error_code);
            try testing.expectEqual(limit, frame.reset_stream.final_size);
        },
        9 => {
            const app_error_code = @as(u64, smith.value(u16));
            const frame = try roundtripOne(buf[0..try encodeStopSending(.{ .id = id, .app_error_code = app_error_code }, &buf)]);
            try testing.expectEqual(id, frame.stop_sending.id);
            try testing.expectEqual(app_error_code, frame.stop_sending.app_error_code);
        },
        10 => {
            var path_data: [path_data_len]u8 = undefined;
            @memset(&path_data, 0);
            _ = smith.slice(&path_data);
            const challenge = try roundtripOne(buf[0..try encodePathChallenge(path_data, &buf)]);
            try testing.expectEqualSlices(u8, &path_data, &challenge.path_challenge);
            const response = try roundtripOne(buf[0..try encodePathResponse(path_data, &buf)]);
            try testing.expectEqualSlices(u8, &path_data, &response.path_response);
        },
        11 => {
            var set = recovery.AckRangeSet{};
            const largest = @as(u64, smith.value(u16)) + 2;
            try set.insertRange(.{ .first = largest - 2, .last = largest });
            if (smith.value(u1) == 1 and largest >= 5) {
                try set.insertRange(.{ .first = 0, .last = 1 });
            }
            const ack_delay_us = @as(u64, smith.value(u16)) * 8;
            const model = set.toAckFrame(ack_delay_us).?;
            const frame = try roundtripOne(buf[0..try encodeAck(model, 3, &buf)]);
            try testing.expectEqual(model.largest_acknowledged, frame.ack.largest_acknowledged);
            try testing.expectEqual(ack_delay_us, frame.ack.ackDelayUs(3));
            try testing.expect(frame.ack.ranges.contains(largest));
            try testing.expect(frame.ack.ranges.contains(largest - 2));
            if (largest >= 5 and set.contains(0)) {
                try testing.expect(frame.ack.ranges.contains(0));
                try testing.expect(frame.ack.ranges.contains(1));
            }
        },
        12 => {
            var cid_bytes: [8]u8 = undefined;
            @memset(&cid_bytes, 0);
            _ = smith.slice(&cid_bytes);
            const value = cid.NewConnectionIdFrame{
                .sequence = @as(u64, smith.value(u16)) + 1,
                .retire_prior_to = 0,
                .cid = try cid.ConnectionId.init(&cid_bytes),
                .stateless_reset_token = [_]u8{smith.value(u8)} ** cid.stateless_reset_token_len,
            };
            const frame = try roundtripOne(buf[0..try encodeNewConnectionId(&value, &buf)]);
            const decoded = frame.new_connection_id.frame;
            try testing.expectEqual(value.sequence, decoded.sequence);
            try testing.expectEqual(value.retire_prior_to, decoded.retire_prior_to);
            try testing.expectEqualSlices(u8, value.cid.slice(), decoded.cid.slice());
            try testing.expectEqualSlices(u8, &value.stateless_reset_token, &decoded.stateless_reset_token);
        },
        13 => {
            const sequence = @as(u64, smith.value(u32));
            const frame = try roundtripOne(buf[0..try encodeRetireConnectionId(sequence, &buf)]);
            try testing.expectEqual(sequence, frame.retire_connection_id.sequence);
        },
        else => {
            const is_app = smith.value(u1) == 1;
            const reason = data[0..@min(data_len, 16)];
            const error_code = @as(u64, smith.value(u16));
            const frame_type = frame_stream_base | @as(u64, smith.value(u3));
            const frame = try roundtripOne(buf[0..try encodeConnectionClose(.{
                .error_code = error_code,
                .frame_type = frame_type,
                .reason = reason,
                .is_application = is_app,
            }, &buf)]);
            try testing.expectEqual(error_code, frame.connection_close.error_code);
            try testing.expectEqual(is_app, frame.connection_close.is_application);
            try testing.expectEqual(if (is_app) null else frame_type, frame.connection_close.frame_type);
            try testing.expectEqualSlices(u8, reason, frame.connection_close.reason);
        },
    }
}

fn expectFrameSlicesWithin(input: []const u8, frame: Frame) !void {
    switch (frame) {
        .crypto => |crypto| try expectSliceWithin(input, crypto.data),
        .new_token => |new_token| try expectSliceWithin(input, new_token.token),
        .stream => |stream_frame| try expectSliceWithin(input, stream_frame.data),
        .connection_close => |close| try expectSliceWithin(input, close.reason),
        else => {},
    }
}

fn expectSliceWithin(input: []const u8, slice: []const u8) !void {
    if (slice.len == 0) return;
    const input_start = @intFromPtr(input.ptr);
    const input_end = input_start + input.len;
    const slice_start = @intFromPtr(slice.ptr);
    const slice_end = slice_start + slice.len;
    try testing.expect(slice_start >= input_start);
    try testing.expect(slice_end <= input_end);
}

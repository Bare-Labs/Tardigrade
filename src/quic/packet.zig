//! QUIC packet layer (#243): long/short packet headers, packet number
//! encoding/reconstruction, coalesced-datagram iteration, and Retry integrity
//! verification. The varint codec lives in `varint.zig`; the frame codec in
//! `frame.zig`; packet/header protection (crypto) with the TLS adapter
//! (#249). Long-header types: Initial, 0-RTT, Handshake, Retry; short header
//! for the 1-RTT application space (RFC 9000 §17).

const std = @import("std");
const varint = @import("quic_varint");
const secrets = @import("crypto_secrets");

/// Largest valid packet number (RFC 9000 §17.1: 2^62 - 1).
pub const max_packet_number: u64 = (1 << 62) - 1;
const max_reconstructable_packet_number_delta: u64 = (1 << 31) - 1;

/// Minimal number of bytes (1..4) needed to encode `full_pn` such that a peer
/// who has acknowledged up to `largest_acked` can reconstruct it. Pass null for
/// `largest_acked` when no packet has been acknowledged yet. (RFC 9000 §A.2)
pub fn packetNumberLength(full_pn: u64, largest_acked: ?u64) u3 {
    std.debug.assert(full_pn <= max_packet_number);
    // A packet being sent always has a higher number than anything acked.
    if (largest_acked) |acked| std.debug.assert(acked < full_pn);
    const num_unacked: u64 = if (largest_acked) |acked| full_pn - acked else full_pn + 1;
    // Need enough bits so the window (2 * num_unacked) is representable.
    const min_bits: usize = @as(usize, 64) - @clz(num_unacked * 2);
    const num_bytes = (min_bits + 7) / 8;
    return @intCast(std.math.clamp(num_bytes, 1, 4));
}

/// The `pn_length` low-order bytes of `full_pn`, big-endian, as sent on the
/// wire. `pn_length` is 1..4.
pub fn truncatePacketNumber(full_pn: u64, pn_length: u3) u32 {
    std.debug.assert(full_pn <= max_packet_number);
    std.debug.assert(pn_length >= 1 and pn_length <= 4);
    const bits: u6 = @as(u6, pn_length) * 8;
    if (bits >= 32) return @truncate(full_pn);
    const mask: u64 = (@as(u64, 1) << bits) - 1;
    return @intCast(full_pn & mask);
}

/// Reconstruct the full packet number from a truncated one, given the largest
/// packet number successfully processed in the same space and the number of
/// bits that were sent. (RFC 9000 §A.3)
pub fn decodePacketNumber(largest_pn: u64, truncated_pn: u64, pn_nbits: u6) u64 {
    std.debug.assert(largest_pn <= max_packet_number);
    // Packet numbers are sent as 1..4 bytes.
    std.debug.assert(pn_nbits == 8 or pn_nbits == 16 or pn_nbits == 24 or pn_nbits == 32);
    std.debug.assert(truncated_pn < (@as(u64, 1) << pn_nbits));
    const expected_pn = largest_pn + 1;
    const pn_win: u64 = @as(u64, 1) << pn_nbits;
    const pn_hwin = pn_win / 2;
    const pn_mask = pn_win - 1;
    const candidate_pn = (expected_pn & ~pn_mask) | truncated_pn;
    if (candidate_pn <= expected_pn -% pn_hwin and candidate_pn < max_packet_number + 1 - pn_win and expected_pn >= pn_hwin) {
        return candidate_pn + pn_win;
    }
    if (candidate_pn > expected_pn + pn_hwin and candidate_pn >= pn_win) {
        return candidate_pn - pn_win;
    }
    return candidate_pn;
}

// ---------------------------------------------------------------------------
// Header codec (RFC 9000 §17) and coalesced-datagram iteration (§12.2).
// ---------------------------------------------------------------------------

pub const quic_v1: u32 = 0x00000001;
pub const max_cid_len = 20;
pub const retry_integrity_tag_len = 16;

pub const HeaderError = error{
    TruncatedPacket,
    /// The RFC 9000 fixed bit was zero (or a VN/Retry packet was malformed).
    MalformedPacket,
    /// Long-header connection ID longer than QUIC v1 permits.
    InvalidConnectionId,
};

pub const PacketKind = enum {
    initial,
    zero_rtt,
    handshake,
    retry,
    version_negotiation,
    one_rtt,
};

/// One parsed (still protected) packet at the front of a datagram slice.
/// Offsets are relative to the slice handed to `parsePacket`; `packet_len`
/// is where the next coalesced packet begins.
pub const ParsedPacket = struct {
    kind: PacketKind,
    version: u32 = 0,
    dcid: []const u8,
    scid: []const u8 = &.{},
    /// Initial packets: the address-validation token.
    token: []const u8 = &.{},
    /// Protected packets: offset of the (protected) packet number field.
    pn_offset: usize = 0,
    /// Total length of this packet, including header and payload/tag.
    packet_len: usize = 0,
    /// Retry packets: the Retry token (integrity tag excluded).
    retry_token: []const u8 = &.{},
    /// Retry packets: the 16-byte integrity tag.
    retry_tag: []const u8 = &.{},
    /// Version negotiation packets: raw list of 4-byte supported versions.
    supported_versions: []const u8 = &.{},
};

/// Parse the packet at the start of `bytes`. Short headers carry no CID
/// length, so the caller supplies its own local CID length. Nothing here
/// removes protection; the caller decides what it can decrypt.
pub fn parsePacket(bytes: []const u8, short_dcid_len: usize) HeaderError!ParsedPacket {
    if (bytes.len == 0) return error.TruncatedPacket;
    const first = bytes[0];
    if (first & 0x80 == 0) {
        // Short header (1-RTT).
        if (first & 0x40 == 0) return error.MalformedPacket;
        if (bytes.len < 1 + short_dcid_len) return error.TruncatedPacket;
        return .{
            .kind = .one_rtt,
            .dcid = bytes[1..][0..short_dcid_len],
            .pn_offset = 1 + short_dcid_len,
            .packet_len = bytes.len,
        };
    }

    var pos: usize = 1;
    if (bytes.len < pos + 4) return error.TruncatedPacket;
    const version = std.mem.readInt(u32, bytes[pos..][0..4], .big);
    pos += 4;

    if (bytes.len < pos + 1) return error.TruncatedPacket;
    const dcid_len = bytes[pos];
    pos += 1;
    if (dcid_len > max_cid_len) return error.InvalidConnectionId;
    if (bytes.len < pos + dcid_len) return error.TruncatedPacket;
    const dcid = bytes[pos..][0..dcid_len];
    pos += dcid_len;

    if (bytes.len < pos + 1) return error.TruncatedPacket;
    const scid_len = bytes[pos];
    pos += 1;
    if (scid_len > max_cid_len) return error.InvalidConnectionId;
    if (bytes.len < pos + scid_len) return error.TruncatedPacket;
    const scid = bytes[pos..][0..scid_len];
    pos += scid_len;

    if (version == 0) {
        // Version negotiation (§17.2.1): the rest is a list of u32 versions.
        const rest = bytes[pos..];
        if (rest.len == 0 or rest.len % 4 != 0) return error.MalformedPacket;
        return .{
            .kind = .version_negotiation,
            .dcid = dcid,
            .scid = scid,
            .supported_versions = rest,
            .packet_len = bytes.len,
        };
    }
    if (first & 0x40 == 0) return error.MalformedPacket;

    const long_type: u2 = @intCast((first >> 4) & 0x3);
    switch (long_type) {
        0b11 => {
            // Retry (§17.2.5): token then 16-byte integrity tag; never coalesced.
            const rest = bytes[pos..];
            if (rest.len < retry_integrity_tag_len) return error.TruncatedPacket;
            return .{
                .kind = .retry,
                .version = version,
                .dcid = dcid,
                .scid = scid,
                .retry_token = rest[0 .. rest.len - retry_integrity_tag_len],
                .retry_tag = rest[rest.len - retry_integrity_tag_len ..],
                .packet_len = bytes.len,
            };
        },
        else => {},
    }

    var token: []const u8 = &.{};
    if (long_type == 0b00) {
        const token_len = varint.decode(bytes[pos..]) catch return error.TruncatedPacket;
        pos += token_len.len;
        if (token_len.value > bytes.len - pos) return error.TruncatedPacket;
        token = bytes[pos..][0..@intCast(token_len.value)];
        pos += token.len;
    }
    const length = varint.decode(bytes[pos..]) catch return error.TruncatedPacket;
    pos += length.len;
    if (length.value > bytes.len - pos) return error.TruncatedPacket;

    return .{
        .kind = switch (long_type) {
            0b00 => .initial,
            0b01 => .zero_rtt,
            0b10 => .handshake,
            0b11 => unreachable,
        },
        .version = version,
        .dcid = dcid,
        .scid = scid,
        .token = token,
        .pn_offset = pos,
        .packet_len = pos + @as(usize, @intCast(length.value)),
    };
}

pub const LongHeaderKind = enum(u2) {
    initial = 0b00,
    zero_rtt = 0b01,
    handshake = 0b10,
};

pub const WrittenLongHeader = struct {
    /// Offset where the packet number begins.
    pn_offset: usize,
    /// Offset of the 2-byte Length varint, patched after payload sealing.
    length_offset: usize,
};

/// Write an Initial/Handshake/0-RTT long header with a 2-byte Length varint
/// placeholder. `pn_len` is encoded into the first byte's low bits.
pub fn writeLongHeader(
    kind: LongHeaderKind,
    version: u32,
    dcid: []const u8,
    scid: []const u8,
    token: []const u8,
    pn_len: u3,
    out: []u8,
) error{BufferTooShort}!WrittenLongHeader {
    std.debug.assert(pn_len >= 1 and pn_len <= 4);
    std.debug.assert(dcid.len <= max_cid_len and scid.len <= max_cid_len);
    var pos: usize = 0;
    const need_min = 1 + 4 + 1 + dcid.len + 1 + scid.len;
    if (out.len < need_min) return error.BufferTooShort;
    out[pos] = 0x80 | 0x40 | (@as(u8, @intFromEnum(kind)) << 4) | @as(u8, pn_len - 1);
    pos += 1;
    std.mem.writeInt(u32, out[pos..][0..4], version, .big);
    pos += 4;
    out[pos] = @intCast(dcid.len);
    pos += 1;
    @memcpy(out[pos..][0..dcid.len], dcid);
    pos += dcid.len;
    out[pos] = @intCast(scid.len);
    pos += 1;
    @memcpy(out[pos..][0..scid.len], scid);
    pos += scid.len;
    if (kind == .initial) {
        pos += varint.encode(token.len, out[pos..]) catch return error.BufferTooShort;
        if (token.len > out.len - pos) return error.BufferTooShort;
        @memcpy(out[pos..][0..token.len], token);
        pos += token.len;
    }
    const length_offset = pos;
    if (out.len < pos + 2) return error.BufferTooShort;
    pos += 2; // Length placeholder, always a 2-byte varint
    return .{ .pn_offset = pos, .length_offset = length_offset };
}

/// Patch the Length field written by `writeLongHeader` once the packet number
/// length and sealed payload length are known.
pub fn patchLongHeaderLength(out: []u8, length_offset: usize, value: usize) void {
    std.debug.assert(value < 0x4000);
    std.mem.writeInt(u16, out[length_offset..][0..2], @as(u16, @intCast(value)) | 0x4000, .big);
}

/// Write a short (1-RTT) header. Returns the packet number offset.
pub fn writeShortHeader(
    dcid: []const u8,
    key_phase: u1,
    pn_len: u3,
    out: []u8,
) error{BufferTooShort}!usize {
    std.debug.assert(pn_len >= 1 and pn_len <= 4);
    if (out.len < 1 + dcid.len) return error.BufferTooShort;
    out[0] = 0x40 | (@as(u8, key_phase) << 2) | @as(u8, pn_len - 1);
    @memcpy(out[1..][0..dcid.len], dcid);
    return 1 + dcid.len;
}

// RFC 9001 §5.8: fixed AEAD key/nonce for the QUIC v1 Retry integrity tag.
const retry_integrity_key_v1 = [16]u8{
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
};
const retry_integrity_nonce_v1 = [12]u8{
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
};
/// Largest Retry body (header + token, excluding the tag) this module builds
/// a pseudo-packet for.
const max_retry_pseudo_body_len = 1500;

/// Compute the RFC 9001 §5.8 Retry integrity tag over the pseudo-packet
/// (`ODCID length || ODCID || Retry packet without tag`). Shared by
/// `writeRetryV1` (compute) and `verifyRetryIntegrity` (compare), so there is
/// exactly one implementation of the AAD construction.
pub fn computeRetryIntegrityTag(original_dcid: []const u8, retry_body: []const u8) error{ InvalidConnectionId, RetryBodyTooLong }![retry_integrity_tag_len]u8 {
    if (original_dcid.len > max_cid_len) return error.InvalidConnectionId;
    if (retry_body.len > max_retry_pseudo_body_len) return error.RetryBodyTooLong;
    const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;

    var pseudo: [1 + max_cid_len + max_retry_pseudo_body_len]u8 = undefined;
    pseudo[0] = @intCast(original_dcid.len);
    @memcpy(pseudo[1..][0..original_dcid.len], original_dcid);
    @memcpy(pseudo[1 + original_dcid.len ..][0..retry_body.len], retry_body);
    const aad = pseudo[0 .. 1 + original_dcid.len + retry_body.len];

    var tag: [retry_integrity_tag_len]u8 = undefined;
    var empty_out: [0]u8 = undefined;
    Aes128Gcm.encrypt(&empty_out, &tag, "", aad, retry_integrity_nonce_v1, retry_integrity_key_v1);
    return tag;
}

/// Verify the integrity tag of a parsed Retry packet against the DCID the
/// client sent in its first Initial (RFC 9001 §5.8). `retry_packet` is the
/// full packet including the tag.
pub fn verifyRetryIntegrity(retry_packet: []const u8, original_dcid: []const u8) bool {
    if (retry_packet.len < retry_integrity_tag_len) return false;
    const body_len = retry_packet.len - retry_integrity_tag_len;
    const expected = computeRetryIntegrityTag(original_dcid, retry_packet[0..body_len]) catch return false;
    const received = retry_packet[body_len..][0..retry_integrity_tag_len];
    return secrets.constantTimeEqual(&expected, received);
}

/// Write a complete QUIC v1 Retry packet (RFC 9000 §17.2.5): first byte, the
/// fixed `version = 1`, the Retry packet's DCID (the client's Initial SCID)
/// and SCID (the server-chosen Retry SCID), the opaque token, and the
/// trailing RFC 9001 §5.8 integrity tag computed over `original_dcid` and
/// everything written before the tag. Retry packets are never coalesced and
/// carry no packet number.
pub fn writeRetryV1(
    original_dcid: []const u8,
    client_scid: []const u8,
    retry_scid: []const u8,
    token: []const u8,
    out: []u8,
) error{ BufferTooShort, InvalidConnectionId, RetryBodyTooLong, EmptyToken, RetryScidNotDistinct }![]const u8 {
    if (client_scid.len > max_cid_len or retry_scid.len > max_cid_len) return error.InvalidConnectionId;
    // A Retry with no token defeats the point of Retry (there is nothing for
    // a conforming client to echo back), and a Retry SCID equal to the
    // client's original DCID is indistinguishable from "no Retry happened" —
    // #387 requires a server-chosen SCID distinct from it.
    if (token.len == 0) return error.EmptyToken;
    if (std.mem.eql(u8, original_dcid, retry_scid)) return error.RetryScidNotDistinct;

    var pos: usize = 0;
    const header_len = 1 + 4 + 1 + client_scid.len + 1 + retry_scid.len + token.len;
    if (out.len < header_len + retry_integrity_tag_len) return error.BufferTooShort;

    // Long header, fixed bit set, type = 0b11 (Retry); the low 4 bits are
    // unused for Retry and may be any value on send (RFC 9000 §17.2.5).
    out[pos] = 0x80 | 0x40 | (0b11 << 4);
    pos += 1;
    std.mem.writeInt(u32, out[pos..][0..4], quic_v1, .big);
    pos += 4;
    // Retry DCID = the client's Initial SCID; Retry SCID = our fresh CID.
    out[pos] = @intCast(client_scid.len);
    pos += 1;
    @memcpy(out[pos..][0..client_scid.len], client_scid);
    pos += client_scid.len;
    out[pos] = @intCast(retry_scid.len);
    pos += 1;
    @memcpy(out[pos..][0..retry_scid.len], retry_scid);
    pos += retry_scid.len;
    @memcpy(out[pos..][0..token.len], token);
    pos += token.len;

    const tag = try computeRetryIntegrityTag(original_dcid, out[0..pos]);
    @memcpy(out[pos..][0..retry_integrity_tag_len], &tag);
    pos += retry_integrity_tag_len;
    return out[0..pos];
}

const testing = std.testing;

test "decodePacketNumber matches RFC 9000 A.3 example" {
    try testing.expectEqual(@as(u64, 0xa82f9b32), decodePacketNumber(0xa82f30ea, 0x9b32, 16));
}

test "truncate then reconstruct round-trips across a window" {
    // A peer at largest_pn reconstructs recent packet numbers exactly.
    const largest: u64 = 0xa82f30ea;
    var pn: u64 = largest + 1;
    while (pn < largest + 500) : (pn += 7) {
        const len = packetNumberLength(pn, largest);
        const trunc = truncatePacketNumber(pn, len);
        const nbits: u6 = @as(u6, len) * 8;
        try testing.expectEqual(pn, decodePacketNumber(largest, trunc, nbits));
    }
}

test "packetNumberLength at exact RFC threshold boundaries" {
    try testing.expectEqual(@as(u3, 1), packetNumberLength(100, 99));
    try testing.expectEqual(@as(u3, 1), packetNumberLength(0, null));
    // Boundaries where the required length steps up (largest_acked = 0).
    try testing.expectEqual(@as(u3, 1), packetNumberLength(127, 0));
    try testing.expectEqual(@as(u3, 2), packetNumberLength(128, 0));
    try testing.expectEqual(@as(u3, 2), packetNumberLength(32767, 0));
    try testing.expectEqual(@as(u3, 3), packetNumberLength(32768, 0));
    try testing.expectEqual(@as(u3, 3), packetNumberLength(8388607, 0));
    try testing.expectEqual(@as(u3, 4), packetNumberLength(8388608, 0));
}

test "truncatePacketNumber keeps the low-order bytes" {
    try testing.expectEqual(@as(u32, 0x9b32), truncatePacketNumber(0xa82f9b32, 2));
    try testing.expectEqual(@as(u32, 0x2f9b32), truncatePacketNumber(0xa82f9b32, 3));
    try testing.expectEqual(@as(u32, 0xa82f9b32), truncatePacketNumber(0xa82f9b32, 4));
    try testing.expectEqual(@as(u32, 0x32), truncatePacketNumber(0xa82f9b32, 1));
}

test "fuzz: packet number truncation reconstructs recent sends" {
    try testing.fuzz({}, fuzzPacketNumberRoundTrip, .{ .corpus = &.{
        "\x00\x00\x00\x00\x00\x00",
        "\x00\x00\x00\x01\x00\x01",
        "\x00\x00\x7f\xff\x00\x01",
        "\x00\x80\x00\x00\x00\x07",
        "\x3f\xff\xff\xff\xff\xff\xff\xfe\x00\x00\x00\x01",
        "\xff\xff\xff\xff\xff\xff",
    } });
}

test "packet number reconstruction covers upper legal range boundaries" {
    try expectPacketNumberRoundTrip(max_packet_number - 1, max_packet_number);
    try expectPacketNumberRoundTrip(max_packet_number - 255, max_packet_number);
    try expectPacketNumberRoundTrip(max_packet_number - 65535, max_packet_number);
    try expectPacketNumberRoundTrip(max_packet_number - 16_777_215, max_packet_number);
    try expectPacketNumberRoundTrip(max_packet_number - max_reconstructable_packet_number_delta, max_packet_number);
}

test "fuzz: packet parser preserves bounded slice and progress invariants" {
    try testing.fuzz({}, fuzzPacketParserInvariants, .{ .corpus = &.{
        "",
        "\x00",
        "\x40\x01\x02\x03\x04",
        "\x80\x00\x00\x00\x00",
        "\x80\x00\x00\x00\x00\x00\x00\x00\x00",
        "\xc0\x00\x00\x00\x01\x08\x01\x02\x03\x04\x05\x06\x07\x08\x00\x00\x01\x00",
        "\xd0\x00\x00\x00\x01\x00\x00\x01\x00",
        "\xe0\x00\x00\x00\x01\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x14",
        "\xf0\x00\x00\x00\x01\x00\x00abcdefghijklmnop",
        "\x80\x00\x00\x00\x00\x01a\x01b\x00\x00\x00\x01",
    } });
}

test "fuzz: packet writers round-trip public parser fields" {
    try testing.fuzz({}, fuzzPacketWriterRoundTrip, .{ .corpus = &.{
        "\x00",
        "\x01\x02\x03\x04",
        "\xff\x00\x7f\x40",
        "\x14\x00\x14\x01",
    } });
}

test "coalesced parser stops at the first invalid packet without losing progress" {
    var buf: [128]u8 = undefined;
    const dcid = [_]u8{0x11} ** 8;
    const scid = [_]u8{0x22} ** 8;
    const written = try writeLongHeader(.initial, quic_v1, &dcid, &scid, "", 1, &buf);
    patchLongHeaderLength(&buf, written.length_offset, 1 + 16);
    const first_end = written.pn_offset + 1 + 16;
    @memset(buf[written.pn_offset..first_end], 0xaa);
    buf[first_end] = 0x80;
    buf[first_end + 1] = 0x00;

    const parsed = try parsePacket(buf[0 .. first_end + 2], dcid.len);
    try testing.expectEqual(first_end, parsed.packet_len);
    try testing.expectError(error.TruncatedPacket, parsePacket(buf[parsed.packet_len .. first_end + 2], dcid.len));
}

test "long header roundtrips through parsePacket" {
    var buf: [128]u8 = undefined;
    const dcid = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const scid = [_]u8{ 9, 10, 11 };
    const written = try writeLongHeader(.initial, quic_v1, &dcid, &scid, "tok", 2, &buf);
    // Simulate a sealed payload of 30 bytes after the 2-byte packet number.
    const payload_len = 2 + 30;
    patchLongHeaderLength(&buf, written.length_offset, payload_len);
    const total = written.pn_offset + payload_len;
    @memset(buf[written.pn_offset..total], 0xaa);

    const parsed = try parsePacket(buf[0..total], 8);
    try testing.expectEqual(PacketKind.initial, parsed.kind);
    try testing.expectEqual(quic_v1, parsed.version);
    try testing.expectEqualSlices(u8, &dcid, parsed.dcid);
    try testing.expectEqualSlices(u8, &scid, parsed.scid);
    try testing.expectEqualStrings("tok", parsed.token);
    try testing.expectEqual(written.pn_offset, parsed.pn_offset);
    try testing.expectEqual(total, parsed.packet_len);
}

test "coalesced packets split on the long-header Length field" {
    var buf: [256]u8 = undefined;
    const dcid = [_]u8{1} ** 8;
    const scid = [_]u8{2} ** 8;
    const first = try writeLongHeader(.initial, quic_v1, &dcid, &scid, "", 1, &buf);
    patchLongHeaderLength(&buf, first.length_offset, 1 + 20);
    const first_end = first.pn_offset + 1 + 20;
    @memset(buf[first.pn_offset..first_end], 0xbb);
    const second = try writeLongHeader(.handshake, quic_v1, &dcid, &scid, "", 1, buf[first_end..]);
    patchLongHeaderLength(buf[first_end..], second.length_offset, 1 + 17);
    const second_end = first_end + second.pn_offset + 1 + 17;
    @memset(buf[first_end + second.pn_offset .. second_end], 0xcc);

    const one = try parsePacket(buf[0..second_end], 8);
    try testing.expectEqual(PacketKind.initial, one.kind);
    try testing.expectEqual(first_end, one.packet_len);
    const two = try parsePacket(buf[one.packet_len..second_end], 8);
    try testing.expectEqual(PacketKind.handshake, two.kind);
    try testing.expectEqual(second_end - first_end, two.packet_len);
}

test "coalesced parser preserves valid prefixes around malformed packets" {
    var buf: [384]u8 = undefined;
    const dcid = [_]u8{0x51} ** 8;
    const scid = [_]u8{0x52} ** 8;

    const initial = try writeLongHeader(.initial, quic_v1, &dcid, &scid, "", 1, &buf);
    patchLongHeaderLength(&buf, initial.length_offset, 1 + 16);
    const initial_end = initial.pn_offset + 1 + 16;
    @memset(buf[initial.pn_offset..initial_end], 0xa1);

    const handshake = try writeLongHeader(.handshake, quic_v1, &dcid, &scid, "", 2, buf[initial_end..]);
    patchLongHeaderLength(buf[initial_end..], handshake.length_offset, 2 + 16);
    const handshake_end = initial_end + handshake.pn_offset + 2 + 16;
    @memset(buf[initial_end + handshake.pn_offset .. handshake_end], 0xa2);

    buf[handshake_end] = 0x80;
    buf[handshake_end + 1] = 0x00;

    const one = try parsePacket(buf[0 .. handshake_end + 2], dcid.len);
    try testing.expectEqual(initial_end, one.packet_len);
    const two = try parsePacket(buf[one.packet_len .. handshake_end + 2], dcid.len);
    try testing.expectEqual(PacketKind.handshake, two.kind);
    try testing.expectEqual(handshake_end - initial_end, two.packet_len);
    try testing.expectError(error.TruncatedPacket, parsePacket(buf[one.packet_len + two.packet_len .. handshake_end + 2], dcid.len));

    var invalid_first: [256]u8 = undefined;
    invalid_first[0] = 0xc0;
    std.mem.writeInt(u32, invalid_first[1..5], quic_v1, .big);
    invalid_first[5] = max_cid_len + 1;
    @memset(invalid_first[6..][0 .. max_cid_len + 1], 0);
    const valid_start = 6 + max_cid_len + 1;
    const valid = try writeLongHeader(.handshake, quic_v1, &dcid, &scid, "", 1, invalid_first[valid_start..]);
    patchLongHeaderLength(invalid_first[valid_start..], valid.length_offset, 1);
    invalid_first[valid_start + valid.pn_offset] = 0xa3;
    const invalid_first_end = valid_start + valid.pn_offset + 1;
    try testing.expectError(error.InvalidConnectionId, parsePacket(invalid_first[0..invalid_first_end], dcid.len));
}

test "short header parses with caller-provided DCID length" {
    var buf: [64]u8 = undefined;
    const dcid = [_]u8{7} ** 8;
    const pn_offset = try writeShortHeader(&dcid, 1, 2, &buf);
    try testing.expectEqual(@as(usize, 9), pn_offset);
    @memset(buf[pn_offset..][0..20], 0xdd);
    const parsed = try parsePacket(buf[0 .. pn_offset + 20], dcid.len);
    try testing.expectEqual(PacketKind.one_rtt, parsed.kind);
    try testing.expectEqualSlices(u8, &dcid, parsed.dcid);
    try testing.expectEqual(pn_offset, parsed.pn_offset);
}

test "long header parser covers CID, version-list, and length boundaries" {
    var buf: [192]u8 = undefined;
    const max_dcid = [_]u8{0xd1} ** max_cid_len;
    const max_scid = [_]u8{0xd2} ** max_cid_len;

    const written = try writeLongHeader(.initial, quic_v1, &max_dcid, &max_scid, "", 1, &buf);
    patchLongHeaderLength(&buf, written.length_offset, 1);
    buf[written.pn_offset] = 0xaa;
    const parsed = try parsePacket(buf[0 .. written.pn_offset + 1], max_dcid.len);
    try testing.expectEqual(PacketKind.initial, parsed.kind);
    try testing.expectEqualSlices(u8, &max_dcid, parsed.dcid);
    try testing.expectEqualSlices(u8, &max_scid, parsed.scid);
    try testing.expectEqual(@as(usize, written.pn_offset + 1), parsed.packet_len);

    buf[0] = 0xc0;
    std.mem.writeInt(u32, buf[1..5], 0, .big);
    buf[5] = 0;
    buf[6] = 0;
    try testing.expectError(error.MalformedPacket, parsePacket(buf[0..7], 0));
    std.mem.writeInt(u32, buf[7..11], quic_v1, .big);
    const vn = try parsePacket(buf[0..11], 0);
    try testing.expectEqual(PacketKind.version_negotiation, vn.kind);
    try testing.expectEqual(@as(usize, 4), vn.supported_versions.len);
    try testing.expectError(error.MalformedPacket, parsePacket(buf[0..10], 0));

    const one_over = [_]u8{ 0xc0, 0, 0, 0, 1, max_cid_len + 1 } ++ [_]u8{0} ** (max_cid_len + 1);
    try testing.expectError(error.InvalidConnectionId, parsePacket(&one_over, 0));
    const scid_one_over = [_]u8{ 0xc0, 0, 0, 0, 1, 0, max_cid_len + 1 } ++ [_]u8{0} ** (max_cid_len + 1);
    try testing.expectError(error.InvalidConnectionId, parsePacket(&scid_one_over, 0));

    const len_exact = try writeLongHeader(.handshake, quic_v1, &.{}, &.{}, "", 1, &buf);
    patchLongHeaderLength(&buf, len_exact.length_offset, 1);
    buf[len_exact.pn_offset] = 0xbb;
    try testing.expectEqual(len_exact.pn_offset + 1, (try parsePacket(buf[0 .. len_exact.pn_offset + 1], 0)).packet_len);
    try testing.expectError(error.TruncatedPacket, parsePacket(buf[0..len_exact.pn_offset], 0));

    buf[len_exact.length_offset] = 0xff;
    buf[len_exact.length_offset + 1] = 0xff;
    buf[len_exact.length_offset + 2] = 0xff;
    buf[len_exact.length_offset + 3] = 0xff;
    buf[len_exact.length_offset + 4] = 0xff;
    buf[len_exact.length_offset + 5] = 0xff;
    buf[len_exact.length_offset + 6] = 0xff;
    buf[len_exact.length_offset + 7] = 0xff;
    try testing.expectError(error.TruncatedPacket, parsePacket(buf[0 .. len_exact.length_offset + 8], 0));
}

test "fixed-bit violations and truncations are typed errors" {
    try testing.expectError(error.TruncatedPacket, parsePacket(&.{}, 8));
    // Short header with fixed bit clear.
    try testing.expectError(error.MalformedPacket, parsePacket(&[_]u8{0x00} ** 12, 8));
    // Long header truncated in the version field.
    try testing.expectError(error.TruncatedPacket, parsePacket(&[_]u8{ 0xc0, 0x00 }, 8));
    // Long header with an oversized DCID length.
    try testing.expectError(error.InvalidConnectionId, parsePacket(&[_]u8{ 0xc0, 0, 0, 0, 1, 21 } ++ [_]u8{0} ** 30, 8));
}

test "Retry packet parses and RFC 9001 A.4 integrity tag verifies" {
    // RFC 9001 Appendix A.4 sample Retry packet for ODCID 0x8394c8f03e515708.
    const retry = [_]u8{
        0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xf0, 0x67, 0xa5, 0x50, 0x2a,
        0x42, 0x62, 0xb5, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x04, 0xa2, 0x65, 0xba,
        0x2e, 0xff, 0x4d, 0x82, 0x90, 0x58, 0xfb, 0x3f, 0x0f, 0x24, 0x96, 0xba,
    };
    const odcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const parsed = try parsePacket(&retry, 8);
    try testing.expectEqual(PacketKind.retry, parsed.kind);
    try testing.expectEqualStrings("token", parsed.retry_token);
    try testing.expectEqualSlices(u8, retry[7..15], parsed.scid);
    try testing.expect(verifyRetryIntegrity(&retry, &odcid));
    try testing.expect(!verifyRetryIntegrity(&retry, &[_]u8{0} ** 8));
    var tampered = retry;
    tampered[tampered.len - 1] ^= 1;
    try testing.expect(!verifyRetryIntegrity(&tampered, &odcid));
}

test "writeRetryV1 round-trips through parsePacket and verifyRetryIntegrity" {
    const odcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8 };
    const retry_scid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4 };
    const token = "opaque-retry-token";

    var buf: [128]u8 = undefined;
    const written = try writeRetryV1(&odcid, &client_scid, &retry_scid, token, &buf);

    const parsed = try parsePacket(written, 8);
    try testing.expectEqual(PacketKind.retry, parsed.kind);
    try testing.expectEqual(quic_v1, parsed.version);
    try testing.expectEqualSlices(u8, &client_scid, parsed.dcid);
    try testing.expectEqualSlices(u8, &retry_scid, parsed.scid);
    try testing.expectEqualStrings(token, parsed.retry_token);
    try testing.expect(verifyRetryIntegrity(written, &odcid));

    // Wrong ODCID must fail integrity verification.
    try testing.expect(!verifyRetryIntegrity(written, &client_scid));

    // Any tamper to the written packet must fail integrity verification.
    var tampered: [128]u8 = undefined;
    @memcpy(tampered[0..written.len], written);
    tampered[written.len - 1] ^= 0x01;
    try testing.expect(!verifyRetryIntegrity(tampered[0..written.len], &odcid));
}

test "writeRetryV1 rejects an empty token and a Retry SCID matching the client's original DCID" {
    const odcid = [_]u8{0x01} ** 8;
    const client_scid = [_]u8{0x02} ** 8;
    const retry_scid = [_]u8{0x03} ** 8;
    var buf: [128]u8 = undefined;

    // An empty token gives a conforming client nothing to echo back.
    try testing.expectError(error.EmptyToken, writeRetryV1(&odcid, &client_scid, &retry_scid, "", &buf));

    // A Retry SCID identical to the client's original DCID is indistinguishable
    // from no Retry having happened at all — the server must choose a fresh one.
    try testing.expectError(error.RetryScidNotDistinct, writeRetryV1(&odcid, &client_scid, &odcid, "tok", &buf));
}

test "writeRetryV1 rejects oversized connection IDs and short output buffers" {
    const odcid = [_]u8{0x01} ** 8;
    const client_scid = [_]u8{0x02} ** 8;
    const retry_scid = [_]u8{0x03} ** 8;
    const oversized_cid = [_]u8{0xff} ** (max_cid_len + 1);

    var buf: [128]u8 = undefined;
    try testing.expectError(error.InvalidConnectionId, writeRetryV1(&odcid, &oversized_cid, &retry_scid, "tok", &buf));
    try testing.expectError(error.InvalidConnectionId, writeRetryV1(&odcid, &client_scid, &oversized_cid, "tok", &buf));

    // A zero-length CID pair still round-trips, but a too-small output buffer
    // must fail deterministically rather than write a truncated packet.
    var tiny: [8]u8 = undefined;
    try testing.expectError(error.BufferTooShort, writeRetryV1(&odcid, &client_scid, &retry_scid, "tok", &tiny));

    var exact: [1 + 4 + 1 + 8 + 1 + 8 + 3 + retry_integrity_tag_len]u8 = undefined;
    const written = try writeRetryV1(&odcid, &client_scid, &retry_scid, "tok", &exact);
    try testing.expectEqual(exact.len, written.len);
}

test "version negotiation packet exposes the version list" {
    var buf: [64]u8 = undefined;
    buf[0] = 0x80;
    std.mem.writeInt(u32, buf[1..5], 0, .big);
    buf[5] = 4;
    @memset(buf[6..10], 0x11); // dcid
    buf[10] = 4;
    @memset(buf[11..15], 0x22); // scid
    std.mem.writeInt(u32, buf[15..19], 0x00000001, .big);
    std.mem.writeInt(u32, buf[19..23], 0x6b3343cf, .big);
    const parsed = try parsePacket(buf[0..23], 8);
    try testing.expectEqual(PacketKind.version_negotiation, parsed.kind);
    try testing.expectEqual(@as(usize, 8), parsed.supported_versions.len);
}

fn fuzzPacketNumberRoundTrip(_: void, smith: *testing.Smith) !void {
    const largest = smith.value(u64) & max_packet_number;
    if (largest == max_packet_number) return;
    const remaining = max_packet_number - largest;
    const max_delta = @min(remaining, max_reconstructable_packet_number_delta);
    const delta = 1 + (@as(u64, smith.value(u32)) % max_delta);
    const full = largest + delta;
    try expectPacketNumberRoundTrip(largest, full);
}

fn expectPacketNumberRoundTrip(largest: u64, full: u64) !void {
    try testing.expect(largest < full);
    try testing.expect(full <= max_packet_number);
    const len = packetNumberLength(full, largest);
    try testing.expect(len >= 1 and len <= 4);
    const truncated = truncatePacketNumber(full, len);
    const bits: u6 = @as(u6, len) * 8;
    try testing.expect(truncated < (@as(u64, 1) << bits));
    try testing.expectEqual(full, decodePacketNumber(largest, truncated, bits));
}

fn fuzzPacketWriterRoundTrip(_: void, smith: *testing.Smith) !void {
    switch (smith.value(u2)) {
        0 => try fuzzLongHeaderWriterRoundTrip(smith),
        1 => try fuzzShortHeaderWriterRoundTrip(smith),
        else => try fuzzRetryWriterRoundTrip(smith),
    }
}

fn fuzzLongHeaderWriterRoundTrip(smith: *testing.Smith) !void {
    var dcid_storage: [max_cid_len]u8 = undefined;
    var scid_storage: [max_cid_len]u8 = undefined;
    var token_storage: [32]u8 = undefined;
    @memset(&dcid_storage, 0);
    @memset(&scid_storage, 0);
    @memset(&token_storage, 0);
    const dcid_len = @as(usize, smith.value(u8)) % (max_cid_len + 1);
    const scid_len = @as(usize, smith.value(u8)) % (max_cid_len + 1);
    const token_len = @as(usize, smith.value(u8)) % (token_storage.len + 1);
    _ = smith.slice(&dcid_storage);
    _ = smith.slice(&scid_storage);
    _ = smith.slice(&token_storage);
    const dcid = dcid_storage[0..dcid_len];
    const scid = scid_storage[0..scid_len];
    const token = token_storage[0..token_len];
    const kind: LongHeaderKind = switch (smith.value(u2) % 3) {
        0 => .initial,
        1 => .zero_rtt,
        else => .handshake,
    };
    const pn_len = @as(u3, smith.value(u2)) + 1;
    var version = smith.value(u32);
    if (version == 0) version = quic_v1;
    const length_value = @as(usize, pn_len) + (@as(usize, smith.value(u8)) % 48);

    var buf: [256]u8 = undefined;
    const written = try writeLongHeader(kind, version, dcid, scid, token, pn_len, &buf);
    patchLongHeaderLength(&buf, written.length_offset, length_value);
    const total = written.pn_offset + length_value;
    @memset(buf[written.pn_offset..total], smith.value(u8));

    const parsed = try parsePacket(buf[0..total], dcid.len);
    try testing.expectEqual(switch (kind) {
        .initial => PacketKind.initial,
        .zero_rtt => PacketKind.zero_rtt,
        .handshake => PacketKind.handshake,
    }, parsed.kind);
    try testing.expectEqual(version, parsed.version);
    try testing.expectEqualSlices(u8, dcid, parsed.dcid);
    try testing.expectEqualSlices(u8, scid, parsed.scid);
    try testing.expectEqualSlices(u8, if (kind == .initial) token else &.{}, parsed.token);
    try testing.expectEqual(written.pn_offset, parsed.pn_offset);
    try testing.expectEqual(total, parsed.packet_len);
}

fn fuzzShortHeaderWriterRoundTrip(smith: *testing.Smith) !void {
    var dcid_storage: [max_cid_len]u8 = undefined;
    @memset(&dcid_storage, 0);
    _ = smith.slice(&dcid_storage);
    const dcid_len = @as(usize, smith.value(u8)) % (max_cid_len + 1);
    const dcid = dcid_storage[0..dcid_len];
    const key_phase = smith.value(u1);
    const pn_len = @as(u3, smith.value(u2)) + 1;
    const payload_len = @as(usize, smith.value(u8)) % 48;

    var buf: [128]u8 = undefined;
    const pn_offset = try writeShortHeader(dcid, key_phase, pn_len, &buf);
    const total = pn_offset + payload_len;
    @memset(buf[pn_offset..total], smith.value(u8));

    const parsed = try parsePacket(buf[0..total], dcid.len);
    try testing.expectEqual(PacketKind.one_rtt, parsed.kind);
    try testing.expectEqualSlices(u8, dcid, parsed.dcid);
    try testing.expectEqual(pn_offset, parsed.pn_offset);
    try testing.expectEqual(total, parsed.packet_len);
}

fn fuzzRetryWriterRoundTrip(smith: *testing.Smith) !void {
    var odcid_storage: [max_cid_len]u8 = undefined;
    var client_scid_storage: [max_cid_len]u8 = undefined;
    var retry_scid_storage: [max_cid_len]u8 = undefined;
    var token_storage: [32]u8 = undefined;
    @memset(&odcid_storage, 0x11);
    @memset(&client_scid_storage, 0x22);
    @memset(&retry_scid_storage, 0x33);
    @memset(&token_storage, 0x44);
    _ = smith.slice(&odcid_storage);
    _ = smith.slice(&client_scid_storage);
    _ = smith.slice(&retry_scid_storage);
    _ = smith.slice(&token_storage);
    const odcid_len = @as(usize, smith.value(u8)) % (max_cid_len + 1);
    const client_scid_len = @as(usize, smith.value(u8)) % (max_cid_len + 1);
    const retry_scid_len = @as(usize, smith.value(u8)) % (max_cid_len + 1);
    const token_len = 1 + (@as(usize, smith.value(u8)) % token_storage.len);
    const odcid = odcid_storage[0..odcid_len];
    const client_scid = client_scid_storage[0..client_scid_len];
    const retry_scid = retry_scid_storage[0..retry_scid_len];
    const token = token_storage[0..token_len];
    if (std.mem.eql(u8, odcid, retry_scid)) return;

    var buf: [128]u8 = undefined;
    const written = try writeRetryV1(odcid, client_scid, retry_scid, token, &buf);
    const parsed = try parsePacket(written, client_scid.len);
    try testing.expectEqual(PacketKind.retry, parsed.kind);
    try testing.expectEqual(quic_v1, parsed.version);
    try testing.expectEqualSlices(u8, client_scid, parsed.dcid);
    try testing.expectEqualSlices(u8, retry_scid, parsed.scid);
    try testing.expectEqualSlices(u8, token, parsed.retry_token);
    try testing.expectEqual(@as(usize, retry_integrity_tag_len), parsed.retry_tag.len);
    try testing.expectEqual(written.len, parsed.packet_len);
    try testing.expect(verifyRetryIntegrity(written, odcid));
}

fn fuzzPacketParserInvariants(_: void, smith: *testing.Smith) !void {
    var buf: [512]u8 = undefined;
    const len = smith.slice(&buf);
    const short_dcid_len = @as(usize, smith.value(u8)) % (max_cid_len + 2);
    const input = buf[0..len];

    var pos: usize = 0;
    var parsed_count: usize = 0;
    while (pos < input.len and parsed_count < 8) : (parsed_count += 1) {
        const parsed = parsePacket(input[pos..], short_dcid_len) catch return;
        try expectParsedPacketSlicesWithin(input[pos..], parsed);
        try testing.expect(parsed.packet_len > 0);
        try testing.expect(parsed.packet_len <= input.len - pos);
        pos += parsed.packet_len;
    }
    try testing.expect(parsed_count <= 8);
}

fn expectParsedPacketSlicesWithin(input: []const u8, parsed: ParsedPacket) !void {
    try expectSliceWithin(input, parsed.dcid);
    try expectSliceWithin(input, parsed.scid);
    try expectSliceWithin(input, parsed.token);
    try expectSliceWithin(input, parsed.retry_token);
    try expectSliceWithin(input, parsed.retry_tag);
    try expectSliceWithin(input, parsed.supported_versions);
    if (parsed.kind != .version_negotiation and parsed.kind != .retry) {
        try testing.expect(parsed.pn_offset <= parsed.packet_len);
    }
    if (parsed.kind == .retry) {
        try testing.expectEqual(@as(usize, retry_integrity_tag_len), parsed.retry_tag.len);
    }
    if (parsed.kind == .version_negotiation) {
        try testing.expect(parsed.supported_versions.len > 0);
        try testing.expectEqual(@as(usize, 0), parsed.supported_versions.len % 4);
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

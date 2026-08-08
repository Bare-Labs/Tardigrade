//! DER decoder regression and adversarial tests (#339).

const std = @import("std");
const der = @import("der.zig");
const oid = @import("oid.zig");
const time = @import("time.zig");

const testing = std.testing;

const Builder = struct {
    buf: std.ArrayList(u8),

    fn init() Builder {
        return .{ .buf = std.ArrayList(u8).empty };
    }

    fn deinit(self: *Builder, allocator: std.mem.Allocator) void {
        self.buf.deinit(allocator);
    }

    fn appendTlv(self: *Builder, allocator: std.mem.Allocator, tag: der.Tag, content: []const u8) !void {
        var tag_buf: [8]u8 = undefined;
        const tag_len = try der.encodeTag(tag, &tag_buf);
        try self.buf.appendSlice(allocator, tag_buf[0..tag_len]);
        var len_buf: [9]u8 = undefined;
        const len_written = try der.encodeLength(content.len, &len_buf);
        try self.buf.appendSlice(allocator, len_buf[0..len_written]);
        try self.buf.appendSlice(allocator, content);
    }

    fn toOwnedSlice(self: *Builder, allocator: std.mem.Allocator) ![]u8 {
        return self.buf.toOwnedSlice(allocator);
    }
};

fn appendIntegerContent(out: *std.ArrayList(u8), allocator: std.mem.Allocator, value: []const u8) !void {
    try out.appendSlice(allocator, value);
}

test "canonical positive fixtures for X.509 building blocks" {
    const allocator = testing.allocator;
    var b = Builder.init();
    defer b.deinit(allocator);

    // AlgorithmIdentifier-like SEQUENCE { OID, NULL }
    var inner = std.ArrayList(u8).empty;
    defer inner.deinit(allocator);
    var oid_buf: [32]u8 = undefined;
    const oid_len = try oid.encodeComponents(&oid.well_known.rsa_encryption, &oid_buf);
    var oid_builder = Builder.init();
    defer oid_builder.deinit(allocator);
    try oid_builder.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.object_identifier), false), oid_buf[0..oid_len]);
    try inner.appendSlice(allocator, oid_builder.buf.items);
    var null_builder = Builder.init();
    defer null_builder.deinit(allocator);
    try null_builder.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.null), false), &.{});
    try inner.appendSlice(allocator, null_builder.buf.items);
    try b.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.sequence), true), inner.items);

    const encoded = try b.toOwnedSlice(allocator);
    defer allocator.free(encoded);

    var reader = der.Reader.init(encoded, der.default_limits);
    var seq = try reader.readSequence();
    const alg_oid = try seq.readObjectIdentifier();
    try testing.expectEqual(@as(usize, 7), alg_oid.len);
    for (alg_oid.components(), 0..) |component, i| {
        try testing.expectEqual(oid.well_known.rsa_encryption[i], component);
    }
    try seq.readNull();
    try seq.expectEnd();
    try reader.expectEnd();
}

test "INTEGER positive and negative minimal encodings" {
    const allocator = testing.allocator;
    const cases = [_]struct { bytes: []const u8, negative: bool }{
        .{ .bytes = &.{0x00}, .negative = false },
        .{ .bytes = &.{0x01}, .negative = false },
        .{ .bytes = &.{ 0x00, 0x80 }, .negative = false },
        .{ .bytes = &.{0xff}, .negative = true },
        .{ .bytes = &.{ 0xff, 0x7f }, .negative = true },
    };
    for (cases) |c| {
        var b = Builder.init();
        defer b.deinit(allocator);
        var inner = std.ArrayList(u8).empty;
        defer inner.deinit(allocator);
        try appendIntegerContent(&inner, allocator, c.bytes);
        try b.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.integer), false), inner.items);
        const encoded = try b.toOwnedSlice(allocator);
        defer allocator.free(encoded);
        var reader = der.Reader.init(encoded, der.default_limits);
        const value = try reader.readInteger();
        try testing.expectEqual(c.negative, value.isNegative());
        try reader.expectEnd();
    }
}

test "BOOLEAN, BIT STRING, strings, and times" {
    const allocator = testing.allocator;
    var b = Builder.init();
    defer b.deinit(allocator);

    try b.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.boolean), false), &.{0xff});
    try b.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.bit_string), false), &.{ 0x00, 0xA0 });
    try b.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.octet_string), false), "deadbeef");
    try b.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.utf8_string), false), "café");
    try b.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.printable_string), false), "Test CA");
    try b.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.ia5_string), false), "example.com");
    try b.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.utc_time), false), "240630120000Z");
    try b.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.generalized_time), false), "20240630120000Z");

    const encoded = try b.toOwnedSlice(allocator);
    defer allocator.free(encoded);

    var reader = der.Reader.init(encoded, der.default_limits);
    try testing.expect(try reader.readBoolean());
    const bits = try reader.readBitString();
    try testing.expectEqual(@as(u3, 0), bits.unused_bits);
    try testing.expectEqual(@as(u8, 0xA0), bits.data[0]);
    try testing.expectEqualStrings("deadbeef", try reader.readOctetString());
    try testing.expectEqualStrings("café", try reader.readUtf8String());
    try testing.expectEqualStrings("Test CA", try reader.readPrintableString());
    try testing.expectEqualStrings("example.com", try reader.readIa5String());
    const utc = try reader.readUtcTime();
    try testing.expectEqual(@as(u16, 2024), utc.year);
    const gen = try reader.readGeneralizedTime();
    try testing.expectEqual(@as(u16, 2024), gen.year);
    try reader.expectEnd();
}

test "explicit and implicit context-specific tagging" {
    const allocator = testing.allocator;
    var seq_content = std.ArrayList(u8).empty;
    defer seq_content.deinit(allocator);

    var int_tlv = Builder.init();
    defer int_tlv.deinit(allocator);
    try int_tlv.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.integer), false), &.{0x2a});
    var explicit = Builder.init();
    defer explicit.deinit(allocator);
    try explicit.appendTlv(allocator, der.Tag.contextSpecific(0, true), int_tlv.buf.items);
    try seq_content.appendSlice(allocator, explicit.buf.items);

    var implicit = Builder.init();
    defer implicit.deinit(allocator);
    try implicit.appendTlv(allocator, der.Tag.contextSpecific(1, false), "implicit");
    try seq_content.appendSlice(allocator, implicit.buf.items);

    var outer = Builder.init();
    defer outer.deinit(allocator);
    try outer.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.sequence), true), seq_content.items);
    const encoded = try outer.toOwnedSlice(allocator);
    defer allocator.free(encoded);

    var reader = der.Reader.init(encoded, der.default_limits);
    var seq = try reader.readSequence();
    const explicit_elem = try seq.readExplicitContext(0);
    try testing.expect(explicit_elem.tag.number == @intFromEnum(der.UniversalTag.integer));
    try testing.expectEqual(@as(u8, 0x2a), explicit_elem.content[0]);

    const implicit_elem = try seq.readContextSpecific(1, false);
    try testing.expectEqualStrings("implicit", implicit_elem.content);
    try seq.expectEnd();
}

test "truncated tag and length" {
    const allocator = testing.allocator;
    try testing.expectError(error.Truncated, parseOne(allocator, &.{}));
    try testing.expectError(error.Truncated, parseOne(allocator, &.{0x30}));
    try testing.expectError(error.Truncated, parseOne(allocator, &.{ 0x30, 0x82 }));
    try testing.expectError(error.Truncated, parseOne(allocator, &.{ 0x30, 0x82, 0x01 }));
}

fn parseOne(allocator: std.mem.Allocator, input: []const u8) !void {
    return parseOneWithLimits(allocator, input, der.default_limits);
}

fn parseOneWithLimits(allocator: std.mem.Allocator, input: []const u8, limits: der.Limits) !void {
    var reader = der.Reader.init(input, limits);
    _ = try reader.readElement();
    try reader.expectEnd();
    _ = allocator;
}

test "high tag number edge cases" {
    const allocator = testing.allocator;
    // Tag 31 must use extended form; single-byte 0x1f is reserved as lead-in.
    try testing.expectError(error.InvalidTag, parseOne(allocator, &.{ 0x1f, 0x00, 0x00 }));

    var b = Builder.init();
    defer b.deinit(allocator);
    try b.appendTlv(allocator, der.Tag.universal(31, false), &.{0x00});
    const encoded = try b.toOwnedSlice(allocator);
    defer allocator.free(encoded);
    var reader = der.Reader.init(encoded, der.default_limits);
    const elem = try reader.readElement();
    try testing.expectEqual(@as(u32, 31), elem.tag.number);
}

test "indefinite length rejected" {
    const allocator = testing.allocator;
    try testing.expectError(error.IndefiniteLength, parseOne(allocator, &.{ 0x30, 0x80, 0x00, 0x00 }));
    try testing.expectError(error.IndefiniteLength, parseOne(allocator, &.{ 0x04, 0x80 }));
}

test "non-minimal long-form lengths rejected" {
    const allocator = testing.allocator;
    // Length 1 encoded as 0x81 0x01
    try testing.expectError(error.NonMinimalLength, parseOne(allocator, &.{ 0x04, 0x81, 0x01, 0x00 }));
    // Length 0x80 encoded with leading zero byte 0x82 0x00 0x80
    var long_len_input: [4 + 0x80]u8 = undefined;
    long_len_input[0] = 0x04;
    long_len_input[1] = 0x82;
    long_len_input[2] = 0x00;
    long_len_input[3] = 0x80;
    @memset(long_len_input[4..], 0);
    try testing.expectError(error.NonMinimalLength, parseOne(allocator, &long_len_input));
}

test "length beyond input and overflow" {
    const allocator = testing.allocator;
    try testing.expectError(error.LengthBeyondInput, parseOne(allocator, &.{ 0x04, 0x05, 0x01, 0x02 }));
    try testing.expectError(error.LengthOverflow, parseOneWithLimits(allocator, &.{ 0x04, 0x84, 0x00, 0x10, 0x00, 0x00 }, .{ .max_element_len = 1024 }));
}

test "excessive nesting and element count" {
    const allocator = testing.allocator;
    // Three nested empty SEQUENCEs: 30 06 30 04 30 02 30 00
    const deep = [_]u8{ 0x30, 0x06, 0x30, 0x04, 0x30, 0x02, 0x30, 0x00 };
    var reader = der.Reader.init(&deep, .{ .max_depth = 2 });
    var level1 = try reader.readSequence();
    var level2 = try level1.readSequence();
    try testing.expectError(error.NestingLimit, level2.readSequence());

    var b = Builder.init();
    defer b.deinit(allocator);
    var payload = std.ArrayList(u8).empty;
    defer payload.deinit(allocator);
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        var item = Builder.init();
        defer item.deinit(allocator);
        try item.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.null), false), &.{});
        try payload.appendSlice(allocator, item.buf.items);
    }
    try b.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.sequence), true), payload.items);
    const encoded = try b.toOwnedSlice(allocator);
    defer allocator.free(encoded);
    var elem_reader = der.Reader.init(encoded, .{ .max_elements = 4 });
    var seq = try elem_reader.readSequence();
    try seq.readNull();
    try seq.readNull();
    try seq.readNull();
    try testing.expectError(error.ElementCountLimit, seq.readNull());
}

test "element count limit is shared across nested sibling containers" {
    const allocator = testing.allocator;

    var first_payload = std.ArrayList(u8).empty;
    defer first_payload.deinit(allocator);
    var second_payload = std.ArrayList(u8).empty;
    defer second_payload.deinit(allocator);
    var i: usize = 0;
    while (i < 2) : (i += 1) {
        var item = Builder.init();
        defer item.deinit(allocator);
        try item.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.null), false), &.{});
        try first_payload.appendSlice(allocator, item.buf.items);
        try second_payload.appendSlice(allocator, item.buf.items);
    }

    var outer_payload = std.ArrayList(u8).empty;
    defer outer_payload.deinit(allocator);
    var first_seq = Builder.init();
    defer first_seq.deinit(allocator);
    try first_seq.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.sequence), true), first_payload.items);
    try outer_payload.appendSlice(allocator, first_seq.buf.items);
    var second_seq = Builder.init();
    defer second_seq.deinit(allocator);
    try second_seq.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.sequence), true), second_payload.items);
    try outer_payload.appendSlice(allocator, second_seq.buf.items);

    var outer = Builder.init();
    defer outer.deinit(allocator);
    try outer.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.sequence), true), outer_payload.items);
    const encoded = try outer.toOwnedSlice(allocator);
    defer allocator.free(encoded);

    var reader = der.Reader.init(encoded, .{ .max_elements = 5 });
    var seq = try reader.readSequence();
    var first = try seq.readSequence();
    try first.readNull();
    try first.readNull();
    try first.expectEnd();
    var second = try seq.readSequence();
    try testing.expectError(error.ElementCountLimit, second.readNull());
}

test "short-form lengths honor max element length" {
    const allocator = testing.allocator;
    try testing.expectError(error.LengthOverflow, parseOneWithLimits(allocator, &.{ 0x04, 0x05, 1, 2, 3, 4, 5 }, .{ .max_element_len = 4 }));
}

test "non-minimal INTEGER encodings rejected" {
    const allocator = testing.allocator;
    try testing.expectError(error.MalformedInteger, parseInteger(allocator, &.{ 0x00, 0x01 }));
    try testing.expectError(error.MalformedInteger, parseInteger(allocator, &.{ 0xff, 0xff }));
    try testing.expectError(error.MalformedInteger, parseInteger(allocator, &.{}));
}

test "constructed encodings for primitive universal types rejected" {
    const allocator = testing.allocator;
    try testing.expectError(error.UnexpectedTag, parseIntegerTlv(allocator, &.{ 0x22, 0x01, 0x01 }));
    try testing.expectError(error.UnexpectedTag, parseBooleanTlv(allocator, &.{ 0x21, 0x01, 0xff }));
    try testing.expectError(error.UnexpectedTag, parseBitStringTlv(allocator, &.{ 0x23, 0x02, 0x00, 0x80 }));
    try testing.expectError(error.UnexpectedTag, parseOidTlv(allocator, &.{ 0x26, 0x03, 0x55, 0x04, 0x03 }));
    try testing.expectError(error.UnexpectedTag, parseUtcTlv(allocator, "\x37\x0d240101000000Z"));
    try testing.expectError(error.UnexpectedTag, parseGenTlv(allocator, "\x38\x0f20240101000000Z"));
    try testing.expectError(error.InvalidTag, parseOne(allocator, &.{ 0x00, 0x00 }));
}

test "invalid BOOLEAN values" {
    const allocator = testing.allocator;
    try testing.expectError(error.MalformedBoolean, parseBoolean(allocator, &.{0x01}));
    try testing.expectError(error.MalformedBoolean, parseBoolean(allocator, &.{ 0x00, 0x00 }));
}

test "invalid BIT STRING unused bits" {
    const allocator = testing.allocator;
    try testing.expectError(error.MalformedBitString, parseBitString(allocator, &.{}));
    try testing.expectError(error.MalformedBitString, parseBitString(allocator, &.{8}));
    try testing.expectError(error.MalformedBitString, parseBitString(allocator, &.{ 0x01, 0x03 }));
}

test "malformed OID and component overflow" {
    const allocator = testing.allocator;
    try testing.expectError(error.MalformedOid, parseOid(allocator, &.{}));
    try testing.expectError(error.MalformedOid, parseOid(allocator, &.{ 0x55, 0x80 }));
    // Non-minimal base128 for zero
    try testing.expectError(error.MalformedOid, parseOid(allocator, &.{ 0x55, 0x80, 0x00 }));
}

test "invalid time syntax" {
    const allocator = testing.allocator;
    try testing.expectError(error.MalformedTime, parseUtc(allocator, "24010100000"));
    try testing.expectError(error.MalformedTime, parseUtc(allocator, "2401010000Z"));
    try testing.expectError(error.MalformedTime, parseUtc(allocator, "240101000000"));
    try testing.expectError(error.MalformedTime, parseGen(allocator, "2024010100000Z"));
    try testing.expectError(error.MalformedTime, parseGen(allocator, "202401010000Z"));
}

test "diagnostic read captures typed error offsets" {
    try expectDiagnostic(&.{ 0x1f, 0x00, 0x00 }, error.InvalidTag, 1);
    try expectDiagnostic(&.{ 0x30, 0x82, 0x01 }, error.Truncated, 2);
    try expectDiagnostic(&.{ 0x04, 0x81, 0x01, 0x00 }, error.NonMinimalLength, 2);

    const child_boundary = [_]u8{ 0x30, 0x03, 0x04, 0x05, 0x00 };
    var reader = der.Reader.init(&child_boundary, der.default_limits);
    var child = try reader.readSequence();
    const diag = child.readElementDiagnostic();
    switch (diag) {
        .element => return error.TestExpectedError,
        .err => |parse_err| {
            try testing.expectEqual(error.LengthBeyondInput, parse_err.err);
            try testing.expectEqual(@as(usize, 4), parse_err.offset);
        },
    }
}

test "trailing bytes and child boundary escape" {
    const allocator = testing.allocator;
    var b = Builder.init();
    defer b.deinit(allocator);
    try b.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.null), false), &.{});
    try b.buf.append(allocator, 0x00);
    const encoded = try b.toOwnedSlice(allocator);
    defer allocator.free(encoded);
    var reader = der.Reader.init(encoded, der.default_limits);
    try reader.readNull();
    try testing.expectError(error.TrailingData, reader.expectEnd());

    var seq_b = Builder.init();
    defer seq_b.deinit(allocator);
    try seq_b.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.sequence), true), &.{});
    const seq_bytes = try seq_b.toOwnedSlice(allocator);
    defer allocator.free(seq_bytes);
    var seq_reader = der.Reader.init(seq_bytes, der.default_limits);
    var child = try seq_reader.readSequence();
    try child.expectEnd();
    try seq_reader.expectEnd();
}

test "empty and zero-length values" {
    const allocator = testing.allocator;
    var b = Builder.init();
    defer b.deinit(allocator);
    try b.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.sequence), true), &.{});
    try b.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.octet_string), false), &.{});
    const encoded = try b.toOwnedSlice(allocator);
    defer allocator.free(encoded);
    var reader = der.Reader.init(encoded, der.default_limits);
    var seq = try reader.readSequence();
    try seq.expectEnd();
    try testing.expectEqual(@as(usize, 0), (try reader.readOctetString()).len);
    try reader.expectEnd();
}

test "length encode/decode round-trip" {
    const allocator = testing.allocator;
    const lengths = [_]usize{ 0, 1, 127, 128, 255, 256 };
    for (lengths) |len| {
        var content = std.ArrayList(u8).empty;
        defer content.deinit(allocator);
        try content.appendNTimes(allocator, 0, len);
        var b = Builder.init();
        defer b.deinit(allocator);
        try b.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.octet_string), false), content.items);
        const encoded = try b.toOwnedSlice(allocator);
        defer allocator.free(encoded);
        var reader = der.Reader.init(encoded, der.default_limits);
        const value = try reader.readOctetString();
        try testing.expectEqual(len, value.len);
        try reader.expectEnd();
    }
}

// Seeds promoted from PKI differential mismatch minimization (#348) join the
// hand-written corpus automatically.
const reduced_corpus_seeds = blk: {
    const reduced_corpus = @import("pki_reduced_corpus");
    var seeds: [reduced_corpus.entries.len][]const u8 = undefined;
    for (reduced_corpus.entries, &seeds) |entry, *seed| seed.* = entry.seed;
    break :blk seeds;
};

test "fuzz: PKI: DER parser never panics or leaks on arbitrary input" {
    try testing.fuzz({}, fuzzDerParse, .{ .corpus = &([_][]const u8{
        "",
        "\x30\x00",
        "\x02\x01\x01",
        "\x30\x80\x00\x00",
        "\x04\x81\x01\x00",
        "\x06\x03\x55\x04\x03",
        "\x17\x0d\x32\x34\x30\x36\x30\x31\x30\x30\x30\x30\x30\x30\x5a",
        "\x18\x0f\x32\x30\x32\x34\x30\x36\x30\x31\x30\x30\x30\x30\x30\x30\x5a",
        "\xa0\x03\x02\x01\x2a",
        @embedFile("pki_malformed_der"),
    } ++ reduced_corpus_seeds) });
}

fn fuzzDerParse(_: void, smith: *testing.Smith) !void {
    var buf: [8192]u8 = undefined;
    const len = smith.slice(&buf);
    der.fuzzParseInput(buf[0..len]);
}

// --- #492 mutation-driven parser/state safety targets -----------------------
//
// These complement the `fuzzParseInput` smoke target above (and #348's
// semantic differential corpus, which stays the owner of "does this decision
// match OpenSSL"): they assert the structural contract `der.zig` documents —
// borrowed views never escape the caller's buffer, the cursor only advances
// inside its region, exact consumption is enforced, and every configured
// bound actually stops work at the byte it claims to.

/// Every `Element` view is a borrow from the caller's buffer, never a copy
/// and never a pointer into recycled parser state.
fn expectContained(input: []const u8, view: []const u8) !void {
    const input_start = @intFromPtr(input.ptr);
    const view_start = @intFromPtr(view.ptr);
    try testing.expect(view_start >= input_start);
    try testing.expect(view_start - input_start + view.len <= input.len);
}

/// Recursive descent bounded by `limits.max_depth`, which the reader itself
/// enforces, so this cannot recurse deeper than the configured depth.
fn walkElements(reader: *der.Reader, input: []const u8) !void {
    while (reader.remaining() > 0) {
        const before = reader.currentOffset();
        const elem = reader.readElement() catch {
            // Even a failed parse must leave the cursor inside its region.
            try testing.expect(reader.currentOffset() >= before);
            try testing.expect(reader.currentOffset() <= reader.end);
            return;
        };
        const after = reader.currentOffset();
        try testing.expect(after > before);
        try testing.expect(after <= reader.end);
        try expectContained(input, elem.encoded);
        try expectContained(input, elem.content);
        // The header is at least a tag byte and a length byte, the content
        // ends exactly where the cursor now is, and `content_offset` is an
        // absolute index into the root input.
        try testing.expect(elem.encoded.len >= elem.content.len + 2);
        try testing.expectEqual(after, elem.content_offset + elem.content.len);
        try testing.expectEqual(input.ptr + elem.content_offset, elem.content.ptr);
        try testing.expectEqual(input.ptr + before, elem.encoded.ptr);

        if (elem.tag.constructed) {
            var child = reader.childReader(elem.content_offset, elem.content.len) catch continue;
            try testing.expect(child.start >= reader.start);
            try testing.expect(child.end <= reader.end);
            try walkElements(&child, input);
        }
    }
}

/// Typed decoders reached directly, so their views get the same containment
/// treatment as `readElement`'s.
fn walkTyped(input: []const u8, limits: der.Limits, smith: *testing.Smith) !void {
    var reader = der.Reader.init(input, limits);
    var steps: usize = 0;
    while (reader.remaining() > 0 and steps < 64) : (steps += 1) {
        const before = reader.currentOffset();
        switch (smith.index(13)) {
            0 => {
                const view = reader.readInteger() catch break;
                try expectContained(input, view.content);
                try testing.expect(view.content.len <= limits.max_integer_bytes);
            },
            1 => _ = reader.readBoolean() catch break,
            2 => _ = reader.readNull() catch break,
            3 => try expectContained(input, reader.readOctetString() catch break),
            4 => {
                const view = reader.readBitString() catch break;
                try expectContained(input, view.data);
            },
            5 => {
                const value = reader.readObjectIdentifier() catch break;
                try testing.expect(value.components().len <= limits.max_oid_components);
            },
            6 => _ = reader.readUtcTime() catch break,
            7 => _ = reader.readGeneralizedTime() catch break,
            8 => try expectContained(input, reader.readUtf8String() catch break),
            9 => try expectContained(input, reader.readPrintableString() catch break),
            10 => try expectContained(input, reader.readIa5String() catch break),
            11 => {
                const child = reader.readSequence() catch break;
                try testing.expect(child.end <= reader.end);
                try testing.expectEqual(child.start, child.offset);
            },
            else => {
                const elem = reader.readExplicitContext(@intCast(smith.index(4))) catch break;
                try expectContained(input, elem.encoded);
            },
        }
        try testing.expect(reader.currentOffset() > before);
        try testing.expect(reader.currentOffset() <= input.len);
    }
}

test "fuzz: PKI: DER decoding keeps every view inside the input and the cursor inside its region" {
    try testing.fuzz({}, fuzzDerCursorSafety, .{ .corpus = &([_][]const u8{
        "",
        "\x30\x00",
        "\x30\x03\x02\x01\x01",
        "\x30\x06\x30\x04\x30\x02\x30\x00",
        "\x02\x02\x00\x01",
        "\x03\x02\x07\x80",
        "\x06\x03\x55\x04\x03",
        "\x04\x81\x80" ++ ("\x00" ** 128),
        "\xa0\x03\x02\x01\x2a",
        "\x30\x02\x05\x00\xff",
        @embedFile("pki_malformed_der"),
    } ++ reduced_corpus_seeds) });
}

fn fuzzDerCursorSafety(_: void, smith: *testing.Smith) !void {
    // Small enough that the quadratic truncate-at-every-byte sweep below
    // stays a bounded amount of work per case.
    var buf: [256]u8 = undefined;
    const len = smith.slice(&buf);
    const input = buf[0..len];

    const limits: der.Limits = .{
        .max_depth = 1 + smith.index(8),
        .max_element_len = 1 + smith.index(1024),
        .max_elements = 1 + smith.index(64),
        .max_oid_components = 2 + smith.index(31),
        .max_integer_bytes = 1 + smith.index(256),
    };

    var reader = der.Reader.init(input, limits);
    try walkElements(&reader, input);
    try walkTyped(input, limits, smith);

    // Truncation at every byte: no prefix may panic, escape its buffer, or
    // report an element that runs past the bytes actually present.
    var prefix_len: usize = 0;
    while (prefix_len < input.len) : (prefix_len += 1) {
        const prefix = input[0..prefix_len];
        var prefix_reader = der.Reader.init(prefix, limits);
        try walkElements(&prefix_reader, prefix);
        der.fuzzParseInput(prefix);
    }

    // `readElementDiagnostic` reports an offset inside the input (or exactly
    // at its end, where a truncation is detected) and never invents one.
    var diagnostic_reader = der.Reader.init(input, limits);
    switch (diagnostic_reader.readElementDiagnostic()) {
        .element => |elem| try expectContained(input, elem.encoded),
        .err => |parse_error| try testing.expect(parse_error.offset <= input.len),
    }

    // Exact consumption: a reader that stopped short of its end must say so.
    var consume_reader = der.Reader.init(input, limits);
    if (consume_reader.readElement()) |elem| {
        if (elem.encoded.len == input.len) {
            try consume_reader.expectEnd();
        } else {
            try testing.expectError(error.TrailingData, consume_reader.expectEnd());
        }
    } else |_| {}

    try expectChildReaderRejectsSyntheticOffsets(input, limits, smith);
}

/// `childReader` is a public entry point whose offset/length pair does *not*
/// have to come from a successful `readElement`, so wire-derived values alone
/// can never reach the machine-width boundaries the issue's
/// "integer/offset overflow-adjacent cases" asks for: a DER length is capped
/// by `max_element_len` long before it approaches `maxInt(usize)`. These
/// offsets are therefore synthesized directly, per the shared contract's rule
/// that a target supplies synthetic caller limits when wire input cannot
/// reach them.
fn expectChildReaderRejectsSyntheticOffsets(input: []const u8, limits: der.Limits, smith: *testing.Smith) !void {
    const max = std.math.maxInt(usize);
    const offsets = [_]usize{ 0, 1, input.len, max, max - 1, max / 2 + 1 };
    const lengths = [_]usize{ 0, 1, 2, input.len, max, max - 1, max / 2 + 1 };

    // A generous depth budget, so `NestingLimit` cannot mask the bounds check
    // this is actually probing.
    var reader = der.Reader.init(input, .{
        .max_depth = 32,
        .max_element_len = limits.max_element_len,
        .max_elements = limits.max_elements,
    });
    for (offsets) |content_offset| {
        for (lengths) |content_len| {
            // The sum must be evaluated without wrapping — that is the whole
            // point — so the oracle computes it in a wider type.
            const wide_end = @as(u128, content_offset) + @as(u128, content_len);
            const in_bounds = content_offset >= reader.start and wide_end <= input.len;
            if (reader.childReader(content_offset, content_len)) |child| {
                try testing.expect(in_bounds);
                try testing.expectEqual(content_offset, child.start);
                try testing.expectEqual(content_offset, child.offset);
                try testing.expectEqual(content_offset + content_len, child.end);
                // A child that claims to be inside the input really is.
                try testing.expect(child.end <= input.len);
                try testing.expect(child.remaining() == content_len);
            } else |err| {
                try testing.expect(!in_bounds);
                try testing.expectEqual(error.LengthBeyondInput, err);
            }
        }
    }

    // Mutation-driven variant: arbitrary offset/length pairs, including ones
    // straddling the wrap boundary, must never panic or produce a reader that
    // escapes the input.
    for (0..8) |_| {
        const content_offset = max - smith.index(4) * (max / 3);
        const content_len = max - smith.index(4) * (max / 3);
        if (reader.childReader(content_offset, content_len)) |child| {
            try testing.expect(child.end <= input.len);
        } else |err| {
            try testing.expectEqual(error.LengthBeyondInput, err);
        }
    }
}

test "childReader rejects an offset and length whose sum overflows machine width" {
    // Found 2026-08-08 while wiring #492's synthetic overflow-adjacent DER
    // oracle: `childReader` computed `content_offset + content_len` unchecked,
    // which panicked in checked builds and wrapped into an apparently
    // in-bounds bounded reader under `-Doptimize=ReleaseFast`.
    var reader = der.Reader.init(&[_]u8{ 0x30, 0x00 }, der.default_limits);
    const max = std.math.maxInt(usize);
    try testing.expectError(error.LengthBeyondInput, reader.childReader(max, 2));
    try testing.expectError(error.LengthBeyondInput, reader.childReader(2, max));
    try testing.expectError(error.LengthBeyondInput, reader.childReader(max, max));
    try testing.expectError(error.LengthBeyondInput, reader.childReader(max / 2 + 1, max / 2 + 1));
    // The in-bounds neighbours of those cases still work, so the new check
    // cannot have been implemented by rejecting everything.
    const child = try reader.childReader(2, 0);
    try testing.expectEqual(@as(usize, 2), child.start);
    try testing.expectEqual(@as(usize, 2), child.end);
}

/// Innermost NULL wrapped in `depth` SEQUENCEs, written back-to-front into
/// `out`. Every level stays in short-form length range for the depths used.
fn buildNested(depth: usize, out: []u8) []u8 {
    var end = out.len;
    end -= 2;
    out[end] = 0x05;
    out[end + 1] = 0x00;
    var content_len: usize = 2;
    var level: usize = 0;
    while (level < depth) : (level += 1) {
        end -= 2;
        out[end] = 0x30;
        out[end + 1] = @intCast(content_len);
        content_len += 2;
    }
    return out[end..];
}

/// Descend through every constructed element, returning the depth reached.
fn descendNested(input: []const u8, limits: der.Limits) der.Error!usize {
    var reader = der.Reader.init(input, limits);
    var depth: usize = 0;
    while (true) {
        const elem = try reader.readElement();
        if (!elem.tag.constructed) return depth;
        reader = try reader.childReader(elem.content_offset, elem.content.len);
        depth += 1;
    }
}

test "fuzz: PKI: DER length, depth, object-size, and element-count bounds hold at every boundary" {
    try testing.fuzz({}, fuzzDerBounds, .{ .corpus = &.{
        "",
        &[_]u8{ 0, 0, 0, 0 },
        &[_]u8{ 1, 127, 8, 4 },
        &[_]u8{ 4, 128, 32, 2 },
        &([_]u8{0xff} ** 16),
    } });
}

fn fuzzDerBounds(_: void, smith: *testing.Smith) !void {
    // --- Nesting depth ------------------------------------------------------
    const max_depth = 1 + smith.index(12);
    const depth = smith.index(16);
    var nested_storage: [2 + 2 * 16]u8 = undefined;
    const nested = buildNested(depth, &nested_storage);
    const depth_limits: der.Limits = .{ .max_depth = max_depth, .max_elements = 256 };
    if (depth <= max_depth) {
        try testing.expectEqual(depth, try descendNested(nested, depth_limits));
    } else {
        try testing.expectError(error.NestingLimit, descendNested(nested, depth_limits));
    }

    // --- Short/long-form and non-minimal lengths ----------------------------
    const content_len = smith.index(600);
    var element_storage: [16 + 600]u8 = undefined;
    var length_buf: [9]u8 = undefined;
    const length_len = try der.encodeLength(content_len, &length_buf);
    element_storage[0] = 0x04;
    @memcpy(element_storage[1..][0..length_len], length_buf[0..length_len]);
    @memset(element_storage[1 + length_len ..][0..content_len], 0x5a);
    const canonical = element_storage[0 .. 1 + length_len + content_len];

    // Exactly at the configured maximum object size the element decodes;
    // one byte over is `LengthOverflow`, never a wrap or a short read.
    const at_max: der.Limits = .{ .max_element_len = content_len };
    var at_max_reader = der.Reader.init(canonical, at_max);
    const at_max_elem = try at_max_reader.readElement();
    try testing.expectEqual(content_len, at_max_elem.content.len);
    try at_max_reader.expectEnd();

    if (content_len > 0) {
        const under_max: der.Limits = .{ .max_element_len = content_len - 1 };
        var under_reader = der.Reader.init(canonical, under_max);
        try testing.expectError(error.LengthOverflow, under_reader.readElement());
    }

    // A declared length one past the bytes actually present is
    // `LengthBeyondInput`, at every truncation point.
    if (canonical.len > 1) {
        var short_reader = der.Reader.init(canonical[0 .. canonical.len - 1], .{});
        try testing.expectError(
            if (content_len == 0) error.Truncated else error.LengthBeyondInput,
            short_reader.readElement(),
        );
    }

    // Long form where short form would do, and a redundant leading zero, are
    // both non-minimal.
    if (content_len < 128) {
        const padded = [_]u8{ 0x04, 0x81, @intCast(content_len) };
        var padded_reader = der.Reader.init(&padded, .{});
        try testing.expectError(error.NonMinimalLength, padded_reader.readElement());
    } else if (content_len <= 0xff) {
        const padded = [_]u8{ 0x04, 0x82, 0x00, @intCast(content_len) };
        var padded_reader = der.Reader.init(&padded, .{});
        try testing.expectError(error.NonMinimalLength, padded_reader.readElement());
    }

    // Indefinite length, an over-wide length, and a length that would
    // overflow a 64-bit accumulator are all rejected before any allocation
    // or arithmetic on the declared size.
    var indefinite_reader = der.Reader.init(&[_]u8{ 0x30, 0x80, 0x00, 0x00 }, .{});
    try testing.expectError(error.IndefiniteLength, indefinite_reader.readElement());
    var wide_reader = der.Reader.init(&([_]u8{ 0x04, 0x89 } ++ [_]u8{0xff} ** 9), .{});
    try testing.expectError(error.InvalidLength, wide_reader.readElement());
    var overflow_reader = der.Reader.init(&([_]u8{ 0x04, 0x88 } ++ [_]u8{0xff} ** 8), .{});
    try testing.expectError(error.LengthOverflow, overflow_reader.readElement());

    // --- Trailing data / exact consumption ----------------------------------
    const trailing = smith.index(4);
    if (canonical.len + trailing <= element_storage.len) {
        @memset(element_storage[canonical.len..][0..trailing], 0x00);
        var trailing_reader = der.Reader.init(element_storage[0 .. canonical.len + trailing], at_max);
        _ = try trailing_reader.readElement();
        if (trailing == 0) {
            try trailing_reader.expectEnd();
        } else {
            try testing.expectError(error.TrailingData, trailing_reader.expectEnd());
        }
    }

    // --- Element count ------------------------------------------------------
    const max_elements = 1 + smith.index(16);
    const sibling_count = smith.index(24);
    var siblings_storage: [2 * 24]u8 = undefined;
    var index: usize = 0;
    while (index < sibling_count) : (index += 1) {
        siblings_storage[index * 2] = 0x05;
        siblings_storage[index * 2 + 1] = 0x00;
    }
    var count_reader = der.Reader.init(siblings_storage[0 .. sibling_count * 2], .{ .max_elements = max_elements });
    var read: usize = 0;
    while (count_reader.remaining() > 0) {
        _ = count_reader.readElement() catch |err| {
            try testing.expectEqual(error.ElementCountLimit, err);
            break;
        };
        read += 1;
    }
    try testing.expectEqual(@min(sibling_count, max_elements), read);

    // --- INTEGER and OID component boundaries -------------------------------
    const integer_bytes = 1 + smith.index(8);
    var integer_storage: [2 + 8]u8 = undefined;
    integer_storage[0] = 0x02;
    integer_storage[1] = @intCast(integer_bytes);
    integer_storage[2] = 0x01;
    @memset(integer_storage[3..][0 .. integer_bytes - 1], 0x00);
    const integer_tlv = integer_storage[0 .. 2 + integer_bytes];
    var exact_integer = der.Reader.init(integer_tlv, .{ .max_integer_bytes = integer_bytes });
    try testing.expectEqual(integer_bytes, (try exact_integer.readInteger()).content.len);
    var tight_integer = der.Reader.init(integer_tlv, .{ .max_integer_bytes = integer_bytes - 1 });
    try testing.expectError(error.MalformedInteger, tight_integer.readInteger());

    const oid_components = 2 + smith.index(8);
    var oid_storage: [2 + 32]u8 = undefined;
    oid_storage[0] = 0x06;
    oid_storage[1] = @intCast(oid_components - 1);
    oid_storage[2] = 0x2a; // 1.2
    @memset(oid_storage[3..][0 .. oid_components - 2], 0x01);
    const oid_tlv = oid_storage[0 .. 2 + oid_components - 1];
    var exact_oid = der.Reader.init(oid_tlv, .{ .max_oid_components = oid_components });
    try testing.expectEqual(oid_components, (try exact_oid.readObjectIdentifier()).components().len);
    var tight_oid = der.Reader.init(oid_tlv, .{ .max_oid_components = oid_components - 1 });
    try testing.expectError(error.OidComponentLimit, tight_oid.readObjectIdentifier());
}

test "reduced differential DER seeds keep their exact DER parse outcome" {
    const reduced_corpus = @import("pki_reduced_corpus");
    for (reduced_corpus.entries) |entry| {
        switch (entry.expected) {
            .der_parse_error => |expected| {
                var reader = der.Reader.init(entry.seed, der.default_limits);
                const expected_error = if (std.mem.eql(u8, expected, "NonMinimalLength"))
                    error.NonMinimalLength
                else
                    return error.TestUnexpectedResult;
                try testing.expectError(expected_error, reader.readElement());
            },
            else => {},
        }
    }
}

fn parseInteger(allocator: std.mem.Allocator, content: []const u8) !void {
    var b = Builder.init();
    defer b.deinit(allocator);
    try b.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.integer), false), content);
    const encoded = try b.toOwnedSlice(allocator);
    defer allocator.free(encoded);
    var reader = der.Reader.init(encoded, der.default_limits);
    _ = try reader.readInteger();
}

fn parseIntegerTlv(_: std.mem.Allocator, input: []const u8) !void {
    var reader = der.Reader.init(input, der.default_limits);
    _ = try reader.readInteger();
}

fn parseBoolean(allocator: std.mem.Allocator, content: []const u8) !void {
    var b = Builder.init();
    defer b.deinit(allocator);
    try b.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.boolean), false), content);
    const encoded = try b.toOwnedSlice(allocator);
    defer allocator.free(encoded);
    var reader = der.Reader.init(encoded, der.default_limits);
    _ = try reader.readBoolean();
}

fn parseBooleanTlv(_: std.mem.Allocator, input: []const u8) !void {
    var reader = der.Reader.init(input, der.default_limits);
    _ = try reader.readBoolean();
}

fn parseBitString(allocator: std.mem.Allocator, content: []const u8) !void {
    var b = Builder.init();
    defer b.deinit(allocator);
    try b.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.bit_string), false), content);
    const encoded = try b.toOwnedSlice(allocator);
    defer allocator.free(encoded);
    var reader = der.Reader.init(encoded, der.default_limits);
    _ = try reader.readBitString();
}

fn parseBitStringTlv(_: std.mem.Allocator, input: []const u8) !void {
    var reader = der.Reader.init(input, der.default_limits);
    _ = try reader.readBitString();
}

fn parseOid(allocator: std.mem.Allocator, content: []const u8) !void {
    var b = Builder.init();
    defer b.deinit(allocator);
    try b.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.object_identifier), false), content);
    const encoded = try b.toOwnedSlice(allocator);
    defer allocator.free(encoded);
    var reader = der.Reader.init(encoded, der.default_limits);
    _ = try reader.readObjectIdentifier();
}

fn parseOidTlv(_: std.mem.Allocator, input: []const u8) !void {
    var reader = der.Reader.init(input, der.default_limits);
    _ = try reader.readObjectIdentifier();
}

fn parseUtc(allocator: std.mem.Allocator, content: []const u8) !void {
    var b = Builder.init();
    defer b.deinit(allocator);
    try b.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.utc_time), false), content);
    const encoded = try b.toOwnedSlice(allocator);
    defer allocator.free(encoded);
    var reader = der.Reader.init(encoded, der.default_limits);
    _ = try reader.readUtcTime();
}

fn parseUtcTlv(_: std.mem.Allocator, input: []const u8) !void {
    var reader = der.Reader.init(input, der.default_limits);
    _ = try reader.readUtcTime();
}

fn parseGen(allocator: std.mem.Allocator, content: []const u8) !void {
    var b = Builder.init();
    defer b.deinit(allocator);
    try b.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.generalized_time), false), content);
    const encoded = try b.toOwnedSlice(allocator);
    defer allocator.free(encoded);
    var reader = der.Reader.init(encoded, der.default_limits);
    _ = try reader.readGeneralizedTime();
}

fn parseGenTlv(_: std.mem.Allocator, input: []const u8) !void {
    var reader = der.Reader.init(input, der.default_limits);
    _ = try reader.readGeneralizedTime();
}

fn expectDiagnostic(input: []const u8, expected_err: der.Error, expected_offset: usize) !void {
    var reader = der.Reader.init(input, der.default_limits);
    const diag = reader.readElementDiagnostic();
    switch (diag) {
        .element => return error.TestExpectedError,
        .err => |parse_err| {
            try testing.expectEqual(expected_err, parse_err.err);
            try testing.expectEqual(expected_offset, parse_err.offset);
        },
    }
}

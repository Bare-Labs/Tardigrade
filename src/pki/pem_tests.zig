//! PEM and certificate-chain loader regression and adversarial tests (#340).

const std = @import("std");
const der = @import("der.zig");
const pem = @import("pem.zig");

const testing = std.testing;

/// Minimal valid "certificate" DER for structural tests: SEQUENCE { INTEGER n }.
/// The loader only enforces the outer SEQUENCE shape; interior is #341.
fn minimalCertDer(n: u8) [5]u8 {
    return .{ 0x30, 0x03, 0x02, 0x01, n };
}

fn appendPemBlock(out: *std.ArrayList(u8), allocator: std.mem.Allocator, label: []const u8, der_bytes: []const u8, line_ending: []const u8) !void {
    const encoder = std.base64.standard.Encoder;
    const encoded = try allocator.alloc(u8, encoder.calcSize(der_bytes.len));
    defer allocator.free(encoded);
    _ = encoder.encode(encoded, der_bytes);

    try out.appendSlice(allocator, "-----BEGIN ");
    try out.appendSlice(allocator, label);
    try out.appendSlice(allocator, "-----");
    try out.appendSlice(allocator, line_ending);
    var rest: []const u8 = encoded;
    while (rest.len > 0) {
        const take = @min(rest.len, 64);
        try out.appendSlice(allocator, rest[0..take]);
        try out.appendSlice(allocator, line_ending);
        rest = rest[take..];
    }
    try out.appendSlice(allocator, "-----END ");
    try out.appendSlice(allocator, label);
    try out.appendSlice(allocator, "-----");
    try out.appendSlice(allocator, line_ending);
}

fn certPem(allocator: std.mem.Allocator, der_bytes: []const u8, line_ending: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try appendPemBlock(&out, allocator, "CERTIFICATE", der_bytes, line_ending);
    return out.toOwnedSlice(allocator);
}

test "single certificate loads and preserves exact DER bytes" {
    const allocator = testing.allocator;
    const cert = minimalCertDer(1);
    const text = try certPem(allocator, &cert, "\n");
    defer allocator.free(text);

    var chain = try pem.loadChainPem(allocator, text, .{});
    defer chain.deinit(allocator);

    try testing.expectEqual(@as(usize, 1), chain.certificates.len);
    try testing.expectEqualSlices(u8, &cert, chain.certificates[0].der);
}

test "multi-certificate chain preserves input order" {
    const allocator = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    const leaf = minimalCertDer(1);
    const intermediate = minimalCertDer(2);
    const root = minimalCertDer(3);
    try appendPemBlock(&out, allocator, "CERTIFICATE", &leaf, "\n");
    try appendPemBlock(&out, allocator, "CERTIFICATE", &intermediate, "\n");
    try appendPemBlock(&out, allocator, "CERTIFICATE", &root, "\n");

    var chain = try pem.loadChainPem(allocator, out.items, .{});
    defer chain.deinit(allocator);

    try testing.expectEqual(@as(usize, 3), chain.certificates.len);
    try testing.expectEqualSlices(u8, &leaf, chain.certificates[0].der);
    try testing.expectEqualSlices(u8, &intermediate, chain.certificates[1].der);
    try testing.expectEqualSlices(u8, &root, chain.certificates[2].der);
}

test "mixed surrounding text and OpenSSL-style annotations are ignored" {
    const allocator = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    const cert_a = minimalCertDer(1);
    const cert_b = minimalCertDer(2);
    try out.appendSlice(allocator, "# Root bundle exported 2026-07-12\n\n");
    try out.appendSlice(allocator, "subject=CN = Test Leaf\nissuer=CN = Test CA\n");
    try appendPemBlock(&out, allocator, "CERTIFICATE", &cert_a, "\n");
    try out.appendSlice(allocator, "\nsubject=CN = Test CA\n");
    try appendPemBlock(&out, allocator, "CERTIFICATE", &cert_b, "\n");
    try out.appendSlice(allocator, "trailing commentary, no dashes\n");

    var chain = try pem.loadChainPem(allocator, out.items, .{});
    defer chain.deinit(allocator);
    try testing.expectEqual(@as(usize, 2), chain.certificates.len);
    try testing.expectEqualSlices(u8, &cert_a, chain.certificates[0].der);
    try testing.expectEqualSlices(u8, &cert_b, chain.certificates[1].der);
}

test "CRLF and mixed line endings load identically to LF" {
    const allocator = testing.allocator;
    const cert = minimalCertDer(7);

    const crlf_text = try certPem(allocator, &cert, "\r\n");
    defer allocator.free(crlf_text);
    var crlf_chain = try pem.loadChainPem(allocator, crlf_text, .{});
    defer crlf_chain.deinit(allocator);
    try testing.expectEqualSlices(u8, &cert, crlf_chain.certificates[0].der);

    var mixed: std.ArrayList(u8) = .empty;
    defer mixed.deinit(allocator);
    const cert_b = minimalCertDer(8);
    try appendPemBlock(&mixed, allocator, "CERTIFICATE", &cert, "\r\n");
    try appendPemBlock(&mixed, allocator, "CERTIFICATE", &cert_b, "\n");
    var mixed_chain = try pem.loadChainPem(allocator, mixed.items, .{});
    defer mixed_chain.deinit(allocator);
    try testing.expectEqual(@as(usize, 2), mixed_chain.certificates.len);
}

test "missing final newline after END boundary still loads" {
    const allocator = testing.allocator;
    const cert = minimalCertDer(1);
    const text = try certPem(allocator, &cert, "\n");
    defer allocator.free(text);
    const trimmed = std.mem.trimEnd(u8, text, "\n");

    var chain = try pem.loadChainPem(allocator, trimmed, .{});
    defer chain.deinit(allocator);
    try testing.expectEqual(@as(usize, 1), chain.certificates.len);
}

test "non-certificate blocks are skipped but must be well-formed" {
    const allocator = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    const cert = minimalCertDer(1);
    const key_bytes = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    try appendPemBlock(&out, allocator, "PRIVATE KEY", &key_bytes, "\n");
    try appendPemBlock(&out, allocator, "CERTIFICATE", &cert, "\n");
    try appendPemBlock(&out, allocator, "EC PARAMETERS", &key_bytes, "\n");

    var chain = try pem.loadChainPem(allocator, out.items, .{});
    defer chain.deinit(allocator);
    try testing.expectEqual(@as(usize, 1), chain.certificates.len);
    try testing.expectEqualSlices(u8, &cert, chain.certificates[0].der);
}

test "input with no certificate blocks fails typed" {
    const allocator = testing.allocator;
    try testing.expectError(error.NoCertificates, pem.loadChainPem(allocator, "just some text\n", .{}));
    try testing.expectError(error.NoCertificates, pem.loadChainPem(allocator, "", .{}));

    // A lone skipped block is well-formed but yields an empty chain.
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    const key_bytes = [_]u8{ 0x01, 0x02 };
    try appendPemBlock(&out, allocator, "PRIVATE KEY", &key_bytes, "\n");
    try testing.expectError(error.NoCertificates, pem.loadChainPem(allocator, out.items, .{}));
}

test "malformed boundaries fail typed" {
    const allocator = testing.allocator;
    const cases = [_][]const u8{
        // Dashes but not a boundary.
        "-----GARBAGE-----\n",
        // Truncated BEGIN keyword.
        "-----BEGIN CERTIFICATE\n",
        // Missing closing dashes.
        "-----BEGIN CERTIFICATE---\nMTIz\n-----END CERTIFICATE-----\n",
        // Empty label.
        "-----BEGIN -----\n-----END -----\n",
        // Label with control character.
        "-----BEGIN CERT\tIFICATE-----\nMTIz\n-----END CERT\tIFICATE-----\n",
        // Label with doubled separator.
        "-----BEGIN NEW  CERTIFICATE-----\n-----END NEW  CERTIFICATE-----\n",
        // Label with trailing separator.
        "-----BEGIN CERTIFICATE- -----\n",
        // Trailing junk after the closing dashes.
        "-----BEGIN CERTIFICATE----- junk\nMTIz\n-----END CERTIFICATE-----\n",
        // END with no open block.
        "-----END CERTIFICATE-----\n",
        // Nested BEGIN inside an open block.
        "-----BEGIN CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\n",
    };
    for (cases) |case| {
        try testing.expectError(error.MalformedPemBoundary, pem.loadChainPem(allocator, case, .{}));
    }
}

test "mismatched END label fails typed" {
    const allocator = testing.allocator;
    try testing.expectError(error.MismatchedPemLabel, pem.loadChainPem(
        allocator,
        "-----BEGIN CERTIFICATE-----\nMAMCAQE=\n-----END PRIVATE KEY-----\n",
        .{},
    ));
    try testing.expectError(error.MismatchedPemLabel, pem.loadChainPem(
        allocator,
        "-----BEGIN PRIVATE KEY-----\nMAMCAQE=\n-----END CERTIFICATE-----\n",
        .{},
    ));
}

test "unterminated block fails typed" {
    const allocator = testing.allocator;
    try testing.expectError(error.UnterminatedPemBlock, pem.loadChainPem(
        allocator,
        "-----BEGIN CERTIFICATE-----\nMAMCAQE=\n",
        .{},
    ));
    try testing.expectError(error.UnterminatedPemBlock, pem.loadChainPem(
        allocator,
        "-----BEGIN PRIVATE KEY-----\nAAAA\n",
        .{},
    ));
}

test "strict base64 rejects malformed data" {
    const allocator = testing.allocator;
    const prefix = "-----BEGIN CERTIFICATE-----\n";
    const suffix = "-----END CERTIFICATE-----\n";
    const cases = [_][]const u8{
        // Invalid character.
        "MAMCAQ!=\n",
        // Interior space.
        "MAMC AQE=\n",
        // Blank line inside the block.
        "MAMC\n\nAQE=\n",
        // Length not a multiple of four (missing padding).
        "MAMCAQE\n",
        // Data after padding within the block.
        "MAMCAQE=\nAAAA\n",
        // Nonzero trailing bits (non-canonical final symbol).
        "MAMCAQF=\n",
        // Padding only.
        "====\n",
        // Bare CR inside a base64 line is not a line terminator.
        "MAMC\rAQE=\n",
        // Doubled CR before LF: only one CR belongs to the CRLF terminator.
        "MAMCAQE=\r\r\n",
    };
    for (cases) |body| {
        const text = try std.mem.concat(allocator, u8, &.{ prefix, body, suffix });
        defer allocator.free(text);
        try testing.expectError(error.InvalidPemBase64, pem.loadChainPem(allocator, text, .{}));
    }
}

test "doubled CR before LF on a boundary line fails typed" {
    const allocator = testing.allocator;
    try testing.expectError(error.MalformedPemBoundary, pem.loadChainPem(
        allocator,
        "-----BEGIN CERTIFICATE-----\r\r\nMAMCAQE=\r\n-----END CERTIFICATE-----\r\n",
        .{},
    ));
}

test "extreme caller-supplied limits do not overflow bound computation" {
    const allocator = testing.allocator;
    const cert = minimalCertDer(1);
    const text = try certPem(allocator, &cert, "\n");
    defer allocator.free(text);

    // max_certificate_len at maxInt must not wrap in the base64 bound; the
    // input is still bounded by max_input_len.
    var chain = try pem.loadChainPem(allocator, text, .{
        .max_certificate_len = std.math.maxInt(usize),
        .max_input_len = std.math.maxInt(usize),
        .max_certificates = std.math.maxInt(usize),
    });
    defer chain.deinit(allocator);
    try testing.expectEqualSlices(u8, &cert, chain.certificates[0].der);

    // Values just below the multiplication saturation point behave the same.
    var chain2 = try pem.loadChainPem(allocator, text, .{
        .max_certificate_len = std.math.maxInt(usize) / 4 * 3 + 1,
    });
    defer chain2.deinit(allocator);
    try testing.expectEqual(@as(usize, 1), chain2.certificates.len);

    var single = try pem.loadCertificateDer(allocator, &cert, .{
        .max_certificate_len = std.math.maxInt(usize),
        .max_input_len = std.math.maxInt(usize),
    });
    defer single.deinit(allocator);
    try testing.expectEqualSlices(u8, &cert, single.der);
}

test "empty certificate block fails typed" {
    const allocator = testing.allocator;
    try testing.expectError(error.EmptyPemBlock, pem.loadChainPem(
        allocator,
        "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n",
        .{},
    ));
}

test "decoded bytes that are not one DER SEQUENCE fail typed" {
    const allocator = testing.allocator;

    // INTEGER at top level instead of SEQUENCE.
    const not_sequence = [_]u8{ 0x02, 0x01, 0x01 };
    // Valid SEQUENCE followed by trailing bytes.
    const trailing = [_]u8{ 0x30, 0x03, 0x02, 0x01, 0x01, 0x00 };
    // Truncated SEQUENCE (length beyond content).
    const truncated = [_]u8{ 0x30, 0x10, 0x02, 0x01 };
    // BER indefinite length.
    const indefinite = [_]u8{ 0x30, 0x80, 0x00, 0x00 };

    for ([_][]const u8{ &not_sequence, &trailing, &truncated, &indefinite }) |bytes| {
        const text = try certPem(allocator, bytes, "\n");
        defer allocator.free(text);
        try testing.expectError(error.MalformedCertificateDer, pem.loadChainPem(allocator, text, .{}));
        try testing.expectError(error.MalformedCertificateDer, pem.loadCertificateDer(allocator, bytes, .{}));
    }
}

test "certificate count limit fails typed" {
    const allocator = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    const cert_a = minimalCertDer(1);
    const cert_b = minimalCertDer(2);
    try appendPemBlock(&out, allocator, "CERTIFICATE", &cert_a, "\n");
    try appendPemBlock(&out, allocator, "CERTIFICATE", &cert_b, "\n");

    try testing.expectError(error.TooManyCertificates, pem.loadChainPem(allocator, out.items, .{ .max_certificates = 1 }));

    var chain = try pem.loadChainPem(allocator, out.items, .{ .max_certificates = 2 });
    defer chain.deinit(allocator);
    try testing.expectEqual(@as(usize, 2), chain.certificates.len);
}

test "hostile oversized input fails before unbounded allocation" {
    const allocator = testing.allocator;

    // Input larger than max_input_len is rejected up front.
    const big = try allocator.alloc(u8, 1024);
    defer allocator.free(big);
    @memset(big, 'A');
    try testing.expectError(error.InputTooLarge, pem.loadChainPem(allocator, big, .{ .max_input_len = 512 }));
    try testing.expectError(error.InputTooLarge, pem.loadCertificateDer(allocator, big, .{ .max_input_len = 512 }));

    // A block whose base64 exceeds the per-certificate bound is rejected
    // during accumulation, before base64 decoding or DER validation.
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try out.appendSlice(allocator, "-----BEGIN CERTIFICATE-----\n");
    var i: usize = 0;
    while (i < 40) : (i += 1) {
        try out.appendSlice(allocator, "QUFB" ** 16);
        try out.appendSlice(allocator, "\n");
    }
    try out.appendSlice(allocator, "-----END CERTIFICATE-----\n");
    try testing.expectError(error.CertificateTooLarge, pem.loadChainPem(allocator, out.items, .{ .max_certificate_len = 1024 }));

    // Same bound applies to the decoded size of a DER buffer.
    const cert = minimalCertDer(1);
    try testing.expectError(error.CertificateTooLarge, pem.loadCertificateDer(allocator, &cert, .{ .max_certificate_len = 4 }));
}

test "loadCertificatePem accepts exactly one block" {
    const allocator = testing.allocator;
    const cert = minimalCertDer(5);
    const single = try certPem(allocator, &cert, "\n");
    defer allocator.free(single);

    var loaded = try pem.loadCertificatePem(allocator, single, .{});
    defer loaded.deinit(allocator);
    try testing.expectEqualSlices(u8, &cert, loaded.der);

    var two: std.ArrayList(u8) = .empty;
    defer two.deinit(allocator);
    try appendPemBlock(&two, allocator, "CERTIFICATE", &cert, "\n");
    try appendPemBlock(&two, allocator, "CERTIFICATE", &cert, "\n");
    try testing.expectError(error.TooManyCertificates, pem.loadCertificatePem(allocator, two.items, .{}));
}

test "loadCertificateDer copies exact bytes and rejects empty input" {
    const allocator = testing.allocator;
    const cert = minimalCertDer(9);

    var loaded = try pem.loadCertificateDer(allocator, &cert, .{});
    defer loaded.deinit(allocator);
    try testing.expectEqualSlices(u8, &cert, loaded.der);
    // Owned copy, not a view into the input.
    try testing.expect(loaded.der.ptr != @as([]const u8, &cert).ptr);

    try testing.expectError(error.NoCertificates, pem.loadCertificateDer(allocator, &.{}, .{}));
}

test "file helpers load PEM chains and DER certificates" {
    const allocator = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const cert_a = minimalCertDer(1);
    const cert_b = minimalCertDer(2);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try appendPemBlock(&out, allocator, "CERTIFICATE", &cert_a, "\n");
    try appendPemBlock(&out, allocator, "CERTIFICATE", &cert_b, "\n");

    try tmp.dir.writeFile(io, .{ .sub_path = "chain.pem", .data = out.items });
    try tmp.dir.writeFile(io, .{ .sub_path = "cert.der", .data = &cert_a });

    var chain = try pem.loadChainPemFile(allocator, io, tmp.dir, "chain.pem", .{});
    defer chain.deinit(allocator);
    try testing.expectEqual(@as(usize, 2), chain.certificates.len);
    try testing.expectEqualSlices(u8, &cert_a, chain.certificates[0].der);
    try testing.expectEqualSlices(u8, &cert_b, chain.certificates[1].der);

    var single = try pem.loadCertificateDerFile(allocator, io, tmp.dir, "cert.der", .{});
    defer single.deinit(allocator);
    try testing.expectEqualSlices(u8, &cert_a, single.der);

    try testing.expectError(error.FileNotFound, pem.loadChainPemFile(allocator, io, tmp.dir, "missing.pem", .{}));
    try testing.expectError(error.InputTooLarge, pem.loadChainPemFile(allocator, io, tmp.dir, "chain.pem", .{ .max_input_len = 8 }));
}

test "loader is leak-free across allocation failure points" {
    const cert_a = minimalCertDer(1);
    const cert_b = minimalCertDer(2);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    try appendPemBlock(&out, testing.allocator, "CERTIFICATE", &cert_a, "\n");
    try appendPemBlock(&out, testing.allocator, "CERTIFICATE", &cert_b, "\n");

    try testing.checkAllAllocationFailures(testing.allocator, struct {
        fn run(allocator: std.mem.Allocator, text: []const u8) !void {
            var chain = try pem.loadChainPem(allocator, text, .{});
            chain.deinit(allocator);
        }
    }.run, .{out.items});
}

test "fuzz entrypoint tolerates arbitrary input" {
    const allocator = testing.allocator;
    pem.fuzzLoadChainPem(allocator, "");
    pem.fuzzLoadChainPem(allocator, "-----BEGIN CERTIFICATE-----");
    pem.fuzzLoadChainPem(allocator, "-----BEGIN CERTIFICATE-----\n\x00\xff\n-----END CERTIFICATE-----\n");
    const cert = minimalCertDer(1);
    const text = try certPem(allocator, &cert, "\n");
    defer allocator.free(text);
    pem.fuzzLoadChainPem(allocator, text);
}

// --- #492 mutation-driven loader targets ------------------------------------
//
// Focused on parser/state safety, bounded resources, and ownership: the
// loader hands back copies, so a chain must survive its input buffer being
// scribbled over and freed, and every bound it advertises must be the exact
// point at which it refuses.

/// Fixed-capacity text builder. Overflowing writes truncate rather than
/// allocate, so a generated document can never amplify into unbounded work.
const TextBuilder = struct {
    buf: []u8,
    len: usize = 0,

    fn write(self: *TextBuilder, bytes: []const u8) void {
        const room = self.buf.len - self.len;
        const take = @min(room, bytes.len);
        @memcpy(self.buf[self.len..][0..take], bytes[0..take]);
        self.len += take;
    }

    fn slice(self: *const TextBuilder) []const u8 {
        return self.buf[0..self.len];
    }
};

/// Eight-byte `SEQUENCE { OCTET STRING }` whose content encodes `id`, so
/// generated certificates are byte-distinct and structurally valid.
fn syntheticCertDer(id: u32) [8]u8 {
    var out: [8]u8 = .{ 0x30, 0x06, 0x04, 0x04, 0, 0, 0, 0 };
    std.mem.writeInt(u32, out[4..8], id, .big);
    return out;
}

fn writeBase64Body(builder: *TextBuilder, der_bytes: []const u8, line_ending: []const u8) void {
    const encoder = std.base64.standard.Encoder;
    var encoded_storage: [512]u8 = undefined;
    const size = encoder.calcSize(der_bytes.len);
    if (size > encoded_storage.len) return;
    const encoded = encoder.encode(encoded_storage[0..size], der_bytes);
    var rest: []const u8 = encoded;
    while (rest.len > 0) {
        const take = @min(rest.len, 64);
        builder.write(rest[0..take]);
        builder.write(line_ending);
        rest = rest[take..];
    }
}

fn writeValidCertificateBlock(builder: *TextBuilder, id: u32, line_ending: []const u8) void {
    const bytes = syntheticCertDer(id);
    builder.write("-----BEGIN CERTIFICATE-----");
    builder.write(line_ending);
    writeBase64Body(builder, &bytes, line_ending);
    builder.write("-----END CERTIFICATE-----");
    builder.write(line_ending);
}

const fuzz_pem_limits: pem.Limits = .{
    .max_input_len = 4096,
    .max_certificate_len = 64,
    .max_certificates = 4,
    .der = .{ .max_depth = 4, .max_element_len = 64, .max_elements = 16 },
};

/// Chain contents must be owned copies, so nothing may point into the buffer
/// the caller handed in.
fn expectDisjoint(owned: []const u8, input: []const u8) !void {
    const owned_start = @intFromPtr(owned.ptr);
    const input_start = @intFromPtr(input.ptr);
    try testing.expect(owned_start + owned.len <= input_start or input_start + input.len <= owned_start);
}

fn loadChainForAllocationSweep(allocator: std.mem.Allocator, text: []const u8) !void {
    var chain = pem.loadChainPem(allocator, text, fuzz_pem_limits) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return,
    };
    chain.deinit(allocator);
}

test "fuzz: PKI: PEM chain loading is bounded and its owned chain outlives a mutated, freed input" {
    try testing.fuzz({}, fuzzPemChainLoading, .{ .corpus = &.{
        "",
        &[_]u8{ 0, 0 },
        &[_]u8{ 1, 4 },
        &[_]u8{ 1, 5 },
        &[_]u8{ 0, 3, 0, 0, 0, 0, 0, 0 },
        &([_]u8{0xff} ** 48),
        &([_]u8{0x11} ** 32),
    } });
}

fn fuzzPemChainLoading(_: void, smith: *testing.Smith) !void {
    const allocator = testing.allocator;
    var text_storage: [4096]u8 = undefined;
    var builder = TextBuilder{ .buf = &text_storage };

    // Half the cases generate only well-formed CERTIFICATE blocks, which
    // gives an exact oracle for the empty-chain and chain-count boundaries;
    // the other half generate hostile documents with no oracle beyond "do
    // not panic, do not leak, fail with a documented error".
    const well_formed = smith.index(2) == 0;
    const line_ending: []const u8 = if (smith.index(2) == 0) "\n" else "\r\n";
    const block_count = smith.index(fuzz_pem_limits.max_certificates + 3);

    if (well_formed) {
        for (0..block_count) |index| writeValidCertificateBlock(&builder, @intCast(index), line_ending);
    } else {
        const labels = [_][]const u8{
            "CERTIFICATE",
            "PRIVATE KEY",
            "X509 CRL",
            "CERTIFICATE ",
            " CERTIFICATE",
            "CERT--IFICATE",
            "",
            "CERTIFICATE\x00",
        };
        for (0..block_count) |index| {
            const begin_label = labels[smith.index(labels.len)];
            const end_label = if (smith.index(4) == 0) labels[smith.index(labels.len)] else begin_label;
            builder.write(if (smith.index(8) == 0) "----BEGIN " else "-----BEGIN ");
            builder.write(begin_label);
            builder.write("-----");
            builder.write(line_ending);
            switch (smith.index(6)) {
                // A duplicate of an earlier block's payload, exercising the
                // "same certificate twice" case explicitly.
                0 => writeBase64Body(&builder, &syntheticCertDer(0), line_ending),
                1 => writeBase64Body(&builder, &syntheticCertDer(@intCast(index)), line_ending),
                // Oversized: past `max_certificate_len`, so accumulation must
                // stop at the bound rather than growing with the input.
                2 => {
                    var big: [256]u8 = undefined;
                    big[0] = 0x30;
                    big[1] = 0x82;
                    std.mem.writeInt(u16, big[2..4], @intCast(big.len - 4), .big);
                    @memset(big[4..], 0x00);
                    writeBase64Body(&builder, &big, line_ending);
                },
                3 => {}, // Empty body.
                4 => {
                    var raw: [48]u8 = undefined;
                    smith.bytes(&raw);
                    builder.write(&raw);
                    builder.write(line_ending);
                },
                else => {
                    builder.write("!!!not base64===");
                    builder.write(line_ending);
                },
            }
            if (smith.index(8) != 0) {
                builder.write("-----END ");
                builder.write(end_label);
                builder.write("-----");
                builder.write(line_ending);
            }
            if (smith.index(4) == 0) {
                builder.write("subject=/CN=noise");
                builder.write(line_ending);
            }
        }
        var trailing: [32]u8 = undefined;
        const trailing_len = smith.index(trailing.len + 1);
        smith.bytes(trailing[0..trailing_len]);
        builder.write(trailing[0..trailing_len]);
    }

    // Load from a heap copy so the input can be scribbled over and freed
    // while the chain is still live.
    const input = try allocator.dupe(u8, builder.slice());
    var input_owned = true;
    defer if (input_owned) allocator.free(input);

    if (pem.loadChainPem(allocator, input, fuzz_pem_limits)) |loaded| {
        var chain = loaded;
        defer chain.deinit(allocator);
        try testing.expect(chain.certificates.len >= 1);
        try testing.expect(chain.certificates.len <= fuzz_pem_limits.max_certificates);

        var digests: [fuzz_pem_limits.max_certificates]u64 = undefined;
        for (chain.certificates, 0..) |certificate, index| {
            try testing.expect(certificate.der.len <= fuzz_pem_limits.max_certificate_len);
            try expectDisjoint(certificate.der, input);
            // Exactly one definite-length SEQUENCE, spanning the whole buffer.
            var reader = der.Reader.init(certificate.der, fuzz_pem_limits.der);
            const element = try reader.readElement();
            try testing.expect(element.tag.constructed);
            try testing.expectEqual(certificate.der.len, element.encoded.len);
            try reader.expectEnd();
            digests[index] = std.hash.Wyhash.hash(0, certificate.der);
        }

        if (well_formed) {
            try testing.expectEqual(block_count, chain.certificates.len);
        }

        // Mutate and free the input; the owned chain must be unchanged.
        @memset(input, 0xff);
        allocator.free(input);
        input_owned = false;
        for (chain.certificates, 0..) |certificate, index| {
            try testing.expectEqual(digests[index], std.hash.Wyhash.hash(0, certificate.der));
        }
    } else |err| {
        // The error set is closed by the compiler; these are the cases with
        // an exact oracle.
        if (well_formed) {
            if (block_count == 0) {
                try testing.expectEqual(error.NoCertificates, err);
            } else {
                try testing.expect(block_count > fuzz_pem_limits.max_certificates);
                try testing.expectEqual(error.TooManyCertificates, err);
            }
        } else switch (err) {
            error.InputTooLarge,
            error.CertificateTooLarge,
            error.TooManyCertificates,
            error.NoCertificates,
            error.MalformedPemBoundary,
            error.MismatchedPemLabel,
            error.UnterminatedPemBlock,
            error.InvalidPemBase64,
            error.EmptyPemBlock,
            error.MalformedCertificateDer,
            error.OutOfMemory,
            => {},
        }
    }

    const text = builder.slice();
    // `loadCertificatePem` is the exactly-one-block wrapper over the same
    // state machine and must never leak the chain it rejects.
    if (pem.loadCertificatePem(allocator, text, fuzz_pem_limits)) |loaded| {
        var certificate = loaded;
        certificate.deinit(allocator);
        if (well_formed) try testing.expectEqual(@as(usize, 1), block_count);
    } else |_| {}

    // Raw-DER loading over the same bytes: never a borrow of the input.
    if (pem.loadCertificateDer(allocator, text, fuzz_pem_limits)) |loaded| {
        var certificate = loaded;
        defer certificate.deinit(allocator);
        try expectDisjoint(certificate.der, text);
        try testing.expectEqualSlices(u8, text, certificate.der);
    } else |_| {}

    pem.fuzzLoadChainPem(allocator, text);

    // Allocation failure at every reachable point: `OutOfMemory` propagates,
    // nothing leaks, and no partially-owned chain escapes.
    try testing.checkAllAllocationFailures(allocator, loadChainForAllocationSweep, .{text});
}

test "reduced differential seeds load as raw DER exactly as their parse outcome predicts" {
    // #348's minimized hostile certificates are the highest-value seeds for
    // this surface too: they are exactly the DER payloads a PEM block would
    // decode to. `loadCertificateDer` only enforces the outer "exactly one
    // definite-length SEQUENCE" shape, so a seed whose defect is interior
    // (a duplicate extension, a corrupt signature) still loads, while one
    // whose defect is in the DER framing itself must not.
    const allocator = testing.allocator;
    const reduced_corpus = @import("pki_reduced_corpus");
    for (reduced_corpus.entries) |entry| {
        pem.fuzzLoadChainPem(allocator, entry.seed);
        if (pem.loadCertificateDer(allocator, entry.seed, .{})) |loaded| {
            var certificate = loaded;
            defer certificate.deinit(allocator);
            try testing.expect(entry.expected != .der_parse_error);
            try testing.expectEqualSlices(u8, entry.seed, certificate.der);
            try expectDisjoint(certificate.der, entry.seed);
        } else |err| {
            try testing.expectEqual(error.MalformedCertificateDer, err);
            try testing.expect(entry.expected == .der_parse_error);
        }
    }
}

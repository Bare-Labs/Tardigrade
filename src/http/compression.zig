const std = @import("std");

/// Minimum response body size to consider compressing (bytes).
/// Bodies smaller than this are not worth the CPU cost.
pub const DEFAULT_MIN_SIZE: usize = 256;

/// MIME types that should be compressed.
fn isCompressibleMime(mime: []const u8) bool {
    // Text types
    if (std.mem.startsWith(u8, mime, "text/")) return true;
    // JSON / XML / JS application types
    if (std.mem.find(u8, mime, "application/json") != null) return true;
    if (std.mem.find(u8, mime, "application/xml") != null) return true;
    if (std.mem.find(u8, mime, "application/javascript") != null) return true;
    if (std.mem.find(u8, mime, "application/x-javascript") != null) return true;
    if (std.mem.find(u8, mime, "application/xhtml+xml") != null) return true;
    if (std.mem.find(u8, mime, "application/rss+xml") != null) return true;
    if (std.mem.find(u8, mime, "application/atom+xml") != null) return true;
    if (std.mem.find(u8, mime, "image/svg+xml") != null) return true;
    if (std.mem.find(u8, mime, "application/wasm") != null) return true;
    // Already compressed — do NOT compress
    // image/png, image/jpeg, font/woff2, application/gzip, etc. are excluded by default
    return false;
}

pub const Encoding = enum {
    gzip,
    br,

    pub fn headerValue(self: Encoding) []const u8 {
        return switch (self) {
            .gzip => "gzip",
            .br => "br",
        };
    }
};

/// Configuration for response compression.
pub const CompressionConfig = struct {
    enabled: bool = true,
    /// Minimum body size to compress.
    min_size: usize = DEFAULT_MIN_SIZE,
    /// Reserved for a future native Brotli implementation. Runtime dynamic
    /// loading of libbrotlienc is forbidden by the production dependency
    /// boundary, so this flag does not enable Brotli today.
    brotli_enabled: bool = false,
    /// Brotli quality [0..11].
    brotli_quality: u32 = 5,
    /// Compression level.
    level: std.compress.flate.Compress.Options = std.compress.flate.Compress.Options.default,
};

/// Result of attempting compression.
pub const CompressionResult = struct {
    /// Compressed body (owned by allocator). Null if compression was skipped.
    body: ?[]u8,
    /// Whether compression was applied.
    compressed: bool,
    /// Applied encoding when compressed.
    encoding: ?Encoding = null,
};

fn parseEncodingQ(raw: []const u8) f32 {
    const part = std.mem.trim(u8, raw, " \t\r\n");
    if (part.len == 0) return 1.0;
    return std.fmt.parseFloat(f32, part) catch 0.0;
}

fn parseAcceptEncodingQ(accept_encoding: []const u8, token: []const u8) f32 {
    var it = std.mem.splitScalar(u8, accept_encoding, ',');
    while (it.next()) |entry_raw| {
        const entry = std.mem.trim(u8, entry_raw, " \t\r\n");
        if (entry.len == 0) continue;

        var seg_it = std.mem.splitScalar(u8, entry, ';');
        const enc = std.mem.trim(u8, seg_it.next() orelse "", " \t\r\n");
        if (!std.ascii.eqlIgnoreCase(enc, token)) continue;

        var q: f32 = 1.0;
        while (seg_it.next()) |param_raw| {
            const param = std.mem.trim(u8, param_raw, " \t\r\n");
            if (!std.ascii.startsWithIgnoreCase(param, "q=")) continue;
            q = parseEncodingQ(param[2..]);
        }
        return if (q < 0) 0 else q;
    }
    return -1.0;
}

fn pickEncoding(accept_encoding: ?[]const u8, enable_brotli: bool) ?Encoding {
    const ae = accept_encoding orelse return null;
    const br_q = if (enable_brotli) parseAcceptEncodingQ(ae, "br") else -1.0;
    const gzip_q = parseAcceptEncodingQ(ae, "gzip");
    const wildcard_q = parseAcceptEncodingQ(ae, "*");
    const identity_q = parseAcceptEncodingQ(ae, "identity");

    const br_effective = if (br_q >= 0) br_q else wildcard_q;
    const gzip_effective = if (gzip_q >= 0) gzip_q else wildcard_q;
    if (br_effective <= 0 and gzip_effective <= 0) {
        if (identity_q == 0) return null;
        return null;
    }
    if (br_effective >= gzip_effective and br_effective > 0) return .br;
    if (gzip_effective > 0) return .gzip;
    if (br_effective > 0) return .br;
    return null;
}

fn isLikelyGzip(body: []const u8) bool {
    return body.len >= 2 and body[0] == 0x1f and body[1] == 0x8b;
}

/// Compress a response body with gzip if beneficial.
///
/// Returns the compressed body or null if compression was skipped.
/// Caller owns the returned memory.
pub fn compressResponse(
    allocator: std.mem.Allocator,
    body: []const u8,
    content_type: ?[]const u8,
    accept_encoding: ?[]const u8,
    config: CompressionConfig,
) CompressionResult {
    // Check if compression is enabled
    if (!config.enabled) return .{ .body = null, .compressed = false };

    // Check body size threshold
    if (body.len < config.min_size) return .{ .body = null, .compressed = false };

    // Check client support / preferred encoding
    _ = config.brotli_enabled;
    _ = config.brotli_quality;
    const preferred = pickEncoding(accept_encoding, false) orelse return .{ .body = null, .compressed = false };

    // Check MIME type
    const mime = content_type orelse return .{ .body = null, .compressed = false };
    if (!isCompressibleMime(mime)) return .{ .body = null, .compressed = false };

    // gzip_static-like behavior: preserve already gzip-compressed payloads when accepted.
    if (preferred == .gzip and isLikelyGzip(body)) {
        const dup = allocator.dupe(u8, body) catch return .{ .body = null, .compressed = false };
        return .{ .body = dup, .compressed = true, .encoding = .gzip };
    }

    // Perform gzip compression using the new flate API
    var aw = std.Io.Writer.Allocating.initCapacity(allocator, @max(body.len, 64)) catch return .{ .body = null, .compressed = false, .encoding = null };
    var window_buf: [std.compress.flate.max_window_len * 2]u8 = undefined;
    const compress_ok = blk: {
        var c = std.compress.flate.Compress.init(
            &aw.writer,
            &window_buf,
            .gzip,
            config.level,
        ) catch break :blk false;
        c.writer.writeAll(body) catch break :blk false;
        c.finish() catch break :blk false;
        break :blk true;
    };
    if (!compress_ok) {
        var al = aw.toArrayList();
        al.deinit(allocator);
        return .{ .body = null, .compressed = false, .encoding = null };
    }

    var compressed_list = aw.toArrayList();

    // Only use compressed version if it's actually smaller
    if (compressed_list.items.len >= body.len) {
        compressed_list.deinit(allocator);
        return .{ .body = null, .compressed = false, .encoding = null };
    }

    return .{
        .body = compressed_list.toOwnedSlice(allocator) catch {
            compressed_list.deinit(allocator);
            return .{ .body = null, .compressed = false, .encoding = null };
        },
        .compressed = true,
        .encoding = .gzip,
    };
}

// Tests

test "pickEncoding ignores br when Brotli is unavailable" {
    try std.testing.expectEqual(Encoding.br, pickEncoding("gzip, br", true).?);
    try std.testing.expectEqual(Encoding.gzip, pickEncoding("gzip, br", false).?);
    try std.testing.expectEqual(Encoding.gzip, pickEncoding("gzip;q=0.8, br;q=0.2", true).?);
    try std.testing.expectEqual(Encoding.br, pickEncoding("gzip;q=0, br;q=0.5", true).?);
    try std.testing.expectEqual(Encoding.gzip, pickEncoding("gzip;q=0.8, br;q=1.0", false).?);
    try std.testing.expect(pickEncoding("br", false) == null);
    try std.testing.expect(pickEncoding("identity", true) == null);
    try std.testing.expect(pickEncoding(null, true) == null);
}

test "isCompressibleMime identifies compressible types" {
    try std.testing.expect(isCompressibleMime("text/html"));
    try std.testing.expect(isCompressibleMime("text/css"));
    try std.testing.expect(isCompressibleMime("text/plain"));
    try std.testing.expect(isCompressibleMime("application/json"));
    try std.testing.expect(isCompressibleMime("application/javascript"));
    try std.testing.expect(isCompressibleMime("application/xml"));
    try std.testing.expect(isCompressibleMime("image/svg+xml"));
    try std.testing.expect(isCompressibleMime("application/wasm"));
}

test "isCompressibleMime rejects non-compressible types" {
    try std.testing.expect(!isCompressibleMime("image/png"));
    try std.testing.expect(!isCompressibleMime("image/jpeg"));
    try std.testing.expect(!isCompressibleMime("font/woff2"));
    try std.testing.expect(!isCompressibleMime("application/gzip"));
    try std.testing.expect(!isCompressibleMime("application/octet-stream"));
}

test "compressResponse compresses text body" {
    const allocator = std.testing.allocator;
    // Create a body large enough to be worth compressing
    const body = "Hello, World! " ** 50; // 700 bytes of repetitive text

    const result = compressResponse(
        allocator,
        body,
        "text/html",
        "gzip, deflate",
        .{},
    );

    if (result.body) |compressed| {
        defer allocator.free(compressed);
        try std.testing.expect(result.compressed);
        try std.testing.expectEqual(Encoding.gzip, result.encoding.?);
        // Compressed size should be significantly smaller for repetitive data
        try std.testing.expect(compressed.len < body.len);
    } else {
        // Compression should have worked for this input
        return error.TestUnexpectedResult;
    }
}

test "compressResponse skips small bodies" {
    const allocator = std.testing.allocator;
    const result = compressResponse(
        allocator,
        "tiny",
        "text/html",
        "gzip",
        .{},
    );
    try std.testing.expect(!result.compressed);
    try std.testing.expect(result.body == null);
}

test "compressResponse skips when client does not accept gzip" {
    const allocator = std.testing.allocator;
    const body = "x" ** 500;
    const result = compressResponse(
        allocator,
        body,
        "text/html",
        "deflate, identity",
        .{},
    );
    try std.testing.expect(!result.compressed);
}

test "compressResponse preserves precompressed gzip payload" {
    const allocator = std.testing.allocator;
    // gzip magic bytes + dummy bytes
    const body = [_]u8{ 0x1f, 0x8b, 0x08, 0x00, 0x01, 0x02, 0x03 };
    const result = compressResponse(allocator, body[0..], "text/plain", "gzip", .{ .min_size = 0 });
    defer if (result.body) |b| allocator.free(b);
    try std.testing.expect(result.compressed);
    try std.testing.expectEqual(Encoding.gzip, result.encoding.?);
    try std.testing.expectEqualSlices(u8, body[0..], result.body.?);
}

test "compressResponse skips non-compressible MIME types" {
    const allocator = std.testing.allocator;
    const body = "x" ** 500;
    const result = compressResponse(
        allocator,
        body,
        "image/png",
        "gzip",
        .{},
    );
    try std.testing.expect(!result.compressed);
}

test "compressResponse skips when disabled" {
    const allocator = std.testing.allocator;
    const body = "x" ** 500;
    const result = compressResponse(
        allocator,
        body,
        "text/html",
        "gzip",
        .{ .enabled = false },
    );
    try std.testing.expect(!result.compressed);
}

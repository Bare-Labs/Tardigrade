//! Incremental RFC 9112 §7.1 chunked decoder for downstream request bodies
//! (#139).
//!
//! The buffered proxy path decodes a chunked upload in one shot via
//! `http.Request.parse`, which requires the whole body in memory. Streaming
//! uploads cannot do that, so this reader decodes the framing a slice at a
//! time: it owns no heap memory, borrows the bytes already read with the
//! request head, and pulls further bytes from the downstream connection only
//! as the caller drains them.
//!
//! The reader is deliberately transport-agnostic — `Conn` only needs
//! `read([]u8) !usize` — so it can be driven by a plain socket, a TLS
//! connection, or a test fixture.

const std = @import("std");

pub const Error = error{
    /// The downstream chunk framing is malformed (bad size line, missing
    /// CRLF, oversized chunk header, or a truncated trailer section).
    InvalidChunkedUpload,
    /// The decoded body exceeded the configured request-body maximum.
    ChunkedUploadTooLarge,
    /// The client stopped sending before the terminal chunk arrived.
    ClientAborted,
};

/// Largest accepted chunk-size line (including any chunk extensions) and
/// largest accepted trailer line. Both are bounded so a hostile client cannot
/// force unbounded buffering in the header scratch space.
pub const max_control_line_len = 1024;

/// Upper bound on trailer lines accepted after the terminal chunk. Trailers
/// are dropped rather than forwarded (they are hop-by-hop for this relay), but
/// they still have to be consumed so the connection framing stays in sync.
pub const max_trailer_lines = 32;

/// Incremental chunked-body reader over `Conn`.
///
/// `next` returns decoded payload slices and 0 exactly once, when the terminal
/// chunk and its trailer section have been consumed. Returned slices point
/// into the caller-supplied `out` buffer, so total relay memory stays bounded
/// by that buffer plus this reader's fixed scratch space.
pub fn Reader(comptime Conn: type) type {
    return struct {
        const Self = @This();

        conn: Conn,
        /// Bytes already read from the connection with the request head. They
        /// are consumed before the connection is touched again.
        pending: []const u8,
        /// Decoded payload budget; decoding fails once it is exceeded.
        max_body_bytes: usize,
        /// Scratch for one control line (chunk size or trailer).
        line_buf: [max_control_line_len]u8 = undefined,
        line_len: usize = 0,
        /// Payload bytes still owed by the chunk currently being decoded.
        chunk_remaining: usize = 0,
        decoded_bytes: usize = 0,
        finished: bool = false,

        pub fn init(conn: Conn, pending: []const u8, max_body_bytes: usize) Self {
            return .{ .conn = conn, .pending = pending, .max_body_bytes = max_body_bytes };
        }

        /// Total decoded payload bytes handed to the caller so far.
        pub fn decodedBytes(self: *const Self) usize {
            return self.decoded_bytes;
        }

        /// Raw request-head bytes still borrowed from the caller. The streaming
        /// relay reserves these as retained memory (#140) — framing octets
        /// included, since the decoder reads those out of the same slice — and
        /// releases the reservation as this drains to zero.
        pub fn pendingBytes(self: *const Self) usize {
            return self.pending.len;
        }

        /// Copy the next slice of decoded payload into `out`. Returns 0 once
        /// the terminal chunk and trailer section have been consumed; after
        /// that the connection is positioned at the next request.
        pub fn next(self: *Self, out: []u8) Error!usize {
            std.debug.assert(out.len > 0);
            if (self.finished) return 0;

            while (self.chunk_remaining == 0) {
                const size = try self.readChunkSize();
                if (size == 0) {
                    try self.consumeTrailers();
                    self.finished = true;
                    return 0;
                }
                if (size > self.max_body_bytes - self.decoded_bytes) return Error.ChunkedUploadTooLarge;
                self.chunk_remaining = size;
            }

            const want = @min(out.len, self.chunk_remaining);
            const n = try self.readBytes(out[0..want]);
            self.chunk_remaining -= n;
            self.decoded_bytes += n;
            if (self.chunk_remaining == 0) try self.expectCrlf();
            return n;
        }

        /// Read one CRLF-terminated control line into `line_buf`.
        fn readLine(self: *Self) Error!void {
            self.line_len = 0;
            var saw_cr = false;
            while (true) {
                var byte: [1]u8 = undefined;
                _ = try self.readBytes(&byte);
                if (saw_cr) {
                    if (byte[0] != '\n') return Error.InvalidChunkedUpload;
                    return;
                }
                if (byte[0] == '\r') {
                    saw_cr = true;
                    continue;
                }
                if (byte[0] == '\n') return Error.InvalidChunkedUpload; // bare LF
                if (self.line_len == self.line_buf.len) return Error.InvalidChunkedUpload;
                self.line_buf[self.line_len] = byte[0];
                self.line_len += 1;
            }
        }

        /// Parse a chunk-size line. Chunk extensions after `;` are ignored, as
        /// RFC 9112 §7.1.1 allows for a recipient that forwards no extensions.
        fn readChunkSize(self: *Self) Error!usize {
            try self.readLine();
            const line = self.line_buf[0..self.line_len];
            const hex = if (std.mem.indexOfScalar(u8, line, ';')) |idx| line[0..idx] else line;
            const trimmed = std.mem.trim(u8, hex, " \t");
            if (trimmed.len == 0) return Error.InvalidChunkedUpload;
            return std.fmt.parseInt(usize, trimmed, 16) catch Error.InvalidChunkedUpload;
        }

        /// Consume the (possibly empty) trailer section that closes the body.
        fn consumeTrailers(self: *Self) Error!void {
            var lines: usize = 0;
            while (lines <= max_trailer_lines) : (lines += 1) {
                try self.readLine();
                if (self.line_len == 0) return; // empty line terminates trailers
            }
            return Error.InvalidChunkedUpload;
        }

        fn expectCrlf(self: *Self) Error!void {
            var crlf: [2]u8 = undefined;
            _ = try self.readBytes(&crlf);
            if (crlf[0] != '\r' or crlf[1] != '\n') return Error.InvalidChunkedUpload;
        }

        /// Fill `out` completely from the pending prefix and then the
        /// connection. A short connection read before `out` is full means the
        /// client stopped mid-body.
        fn readBytes(self: *Self, out: []u8) Error!usize {
            var filled: usize = 0;
            if (self.pending.len > 0) {
                const take = @min(self.pending.len, out.len);
                @memcpy(out[0..take], self.pending[0..take]);
                self.pending = self.pending[take..];
                filled = take;
            }
            while (filled < out.len) {
                const n = self.conn.read(out[filled..]) catch return Error.ClientAborted;
                if (n == 0) return Error.ClientAborted;
                filled += n;
            }
            return filled;
        }
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Feeds a fixed script one bounded slice at a time so the tests exercise the
/// short-read paths a real socket produces.
const ScriptedConn = struct {
    data: []const u8,
    offset: usize = 0,
    max_read: usize = std.math.maxInt(usize),

    fn read(self: *ScriptedConn, out: []u8) !usize {
        const remaining = self.data.len - self.offset;
        if (remaining == 0) return 0;
        const n = @min(@min(out.len, remaining), self.max_read);
        @memcpy(out[0..n], self.data[self.offset..][0..n]);
        self.offset += n;
        return n;
    }
};

fn decodeAll(
    allocator: std.mem.Allocator,
    pending: []const u8,
    rest: []const u8,
    max_body_bytes: usize,
    max_read: usize,
    out_chunk: usize,
) ![]u8 {
    var conn = ScriptedConn{ .data = rest, .max_read = max_read };
    var reader = Reader(*ScriptedConn).init(&conn, pending, max_body_bytes);
    var decoded: std.ArrayList(u8) = .empty;
    errdefer decoded.deinit(allocator);
    var buf: [64]u8 = undefined;
    while (true) {
        const n = try reader.next(buf[0..out_chunk]);
        if (n == 0) break;
        try decoded.appendSlice(allocator, buf[0..n]);
    }
    return decoded.toOwnedSlice(allocator);
}

test "chunked upload reader decodes a body split across reads" {
    const allocator = std.testing.allocator;
    const body = "7\r\nHello, \r\n6\r\nWorld!\r\n0\r\n\r\n";
    for ([_]usize{ 1, 3, 64 }) |max_read| {
        for ([_]usize{ 1, 5, 64 }) |out_chunk| {
            const decoded = try decodeAll(allocator, "", body, 1024, max_read, out_chunk);
            defer allocator.free(decoded);
            try std.testing.expectEqualStrings("Hello, World!", decoded);
        }
    }
}

test "chunked upload reader consumes bytes buffered with the request head first" {
    const allocator = std.testing.allocator;
    const decoded = try decodeAll(allocator, "7\r\nHello, \r\n6\r\nWo", "rld!\r\n0\r\n\r\n", 1024, 64, 64);
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings("Hello, World!", decoded);
}

test "chunked upload reader ignores chunk extensions" {
    const allocator = std.testing.allocator;
    const decoded = try decodeAll(allocator, "", "5;name=value\r\nhello\r\n0\r\n\r\n", 1024, 64, 64);
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings("hello", decoded);
}

test "chunked upload reader consumes a trailer section" {
    const allocator = std.testing.allocator;
    const decoded = try decodeAll(allocator, "", "5\r\nhello\r\n0\r\nX-Checksum: abc\r\n\r\n", 1024, 64, 64);
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings("hello", decoded);
}

test "chunked upload reader leaves the connection positioned after the body" {
    var conn = ScriptedConn{ .data = "5\r\nhello\r\n0\r\n\r\nGET /next HTTP/1.1\r\n" };
    var reader = Reader(*ScriptedConn).init(&conn, "", 1024);
    var buf: [64]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 5), try reader.next(&buf));
    try std.testing.expectEqual(@as(usize, 0), try reader.next(&buf));
    try std.testing.expectEqualStrings("GET /next HTTP/1.1\r\n", conn.data[conn.offset..]);
}

test "chunked upload reader rejects malformed framing" {
    const allocator = std.testing.allocator;
    // Missing CRLF after the chunk payload.
    try std.testing.expectError(
        Error.InvalidChunkedUpload,
        decodeAll(allocator, "", "5\r\nhello0\r\n\r\n", 1024, 64, 64),
    );
    // Non-hex chunk size.
    try std.testing.expectError(
        Error.InvalidChunkedUpload,
        decodeAll(allocator, "", "zz\r\nhello\r\n0\r\n\r\n", 1024, 64, 64),
    );
    // Bare LF line ending.
    try std.testing.expectError(
        Error.InvalidChunkedUpload,
        decodeAll(allocator, "", "5\nhello\r\n0\r\n\r\n", 1024, 64, 64),
    );
    // Chunk-size line longer than the bounded scratch space.
    const long_line = "0" ** (max_control_line_len + 8) ++ "\r\n";
    try std.testing.expectError(
        Error.InvalidChunkedUpload,
        decodeAll(allocator, "", long_line, 1024, 64, 64),
    );
}

test "chunked upload reader reports client abort on truncated bodies" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(
        Error.ClientAborted,
        decodeAll(allocator, "", "5\r\nhel", 1024, 64, 64),
    );
    // Terminal chunk never arrives.
    try std.testing.expectError(
        Error.ClientAborted,
        decodeAll(allocator, "", "5\r\nhello\r\n", 1024, 64, 64),
    );
}

test "chunked upload reader enforces the decoded body budget" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(
        Error.ChunkedUploadTooLarge,
        decodeAll(allocator, "", "10\r\n0123456789abcdef\r\n0\r\n\r\n", 8, 64, 64),
    );
}

test "chunked upload reader rejects an unbounded trailer section" {
    const allocator = std.testing.allocator;
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);
    try body.appendSlice(allocator, "0\r\n");
    for (0..max_trailer_lines + 2) |_| {
        try body.appendSlice(allocator, "X-Trailer: v\r\n");
    }
    try body.appendSlice(allocator, "\r\n");
    try std.testing.expectError(
        Error.InvalidChunkedUpload,
        decodeAll(allocator, "", body.items, 1024, 64, 64),
    );
}

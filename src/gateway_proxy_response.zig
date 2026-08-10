//! HTTP reverse-proxy response serialization helpers.
//!
//! This module owns response formatting after an upstream result is already
//! known: security/header application, buffered and streamed response heads,
//! chunk serialization, and JSON API error replies. It performs no upstream
//! network I/O and no target URL resolution.

const compat = @import("zig_compat");
const std = @import("std");
const http = @import("http.zig");
const edge_config = @import("edge_config.zig");
const gph = @import("gateway_proxy_headers.zig");
const gs = @import("gateway_state.zig");

const GatewayState = gs.GatewayState;

pub fn upstreamReasonPhrase(status: std.http.Status) []const u8 {
    return status.phrase() orelse "";
}

pub fn applyResponseHeaders(state: *GatewayState, response: *http.Response) void {
    state.security_headers.apply(response);
    for (state.add_headers) |pair| {
        _ = response.setHeader(pair.name, pair.value);
    }
    if (state.http3_alt_svc) |value| {
        _ = response.setHeader("Alt-Svc", value);
    }
}

pub fn writeStreamedUpstreamResponse(
    writer: anytype,
    status_code: u16,
    reason: []const u8,
    content_type: []const u8,
    content_disposition: ?[]const u8,
    correlation_id: []const u8,
    security: *const http.security_headers.SecurityHeaders,
    alt_svc: ?[]const u8,
    sticky_set_cookie: ?[]const u8,
) !void {
    var header_buf: [4096]u8 = undefined;
    var header_stream = compat.fixedBufferStream(&header_buf);
    writeStreamedUpstreamResponseHead(
        header_stream.writer(),
        status_code,
        reason,
        content_type,
        content_disposition,
        correlation_id,
        security,
        alt_svc,
        sticky_set_cookie,
    ) catch {
        try writeStreamedUpstreamResponseHead(
            writer,
            status_code,
            reason,
            content_type,
            content_disposition,
            correlation_id,
            security,
            alt_svc,
            sticky_set_cookie,
        );
        return;
    };
    try writer.writeAll(header_stream.getWritten());
}

pub fn writeStreamedUpstreamResponseHead(
    writer: anytype,
    status_code: u16,
    reason: []const u8,
    content_type: []const u8,
    content_disposition: ?[]const u8,
    correlation_id: []const u8,
    security: *const http.security_headers.SecurityHeaders,
    alt_svc: ?[]const u8,
    sticky_set_cookie: ?[]const u8,
) !void {
    const phrase = if (reason.len > 0)
        reason
    else
        (@as(std.http.Status, @enumFromInt(status_code)).phrase() orelse "");

    try writer.print("HTTP/1.1 {d} {s}\r\n", .{ status_code, phrase });
    try writer.print("Server: {s}\r\n", .{http.SERVER_NAME});
    try writer.writeAll("Connection: close\r\n");
    try writer.writeAll("Transfer-Encoding: chunked\r\n");
    try writer.print("Content-Type: {s}\r\n", .{content_type});
    try gph.writeRequestIdHeaders(writer, correlation_id);
    if (content_disposition) |cd| {
        try writer.print("Content-Disposition: {s}\r\n", .{cd});
    }
    if (sticky_set_cookie) |cookie| {
        try writer.print("Set-Cookie: {s}\r\n", .{cookie});
    }

    try writeSecurityHeaders(writer, security);
    if (alt_svc) |value| try writer.print("Alt-Svc: {s}\r\n", .{value});
    try writer.writeAll("\r\n");
}

pub fn writeStreamedUpstreamResponseHeadFromHeaders(
    writer: anytype,
    status_code: u16,
    reason: []const u8,
    upstream_headers: anytype,
    body_allowed: bool,
    correlation_id: []const u8,
    security: *const http.security_headers.SecurityHeaders,
    alt_svc: ?[]const u8,
    sticky_set_cookie: ?[]const u8,
) !void {
    const phrase = if (reason.len > 0)
        reason
    else
        (@as(std.http.Status, @enumFromInt(status_code)).phrase() orelse "");

    try writer.print("HTTP/1.1 {d} {s}\r\n", .{ status_code, phrase });
    try writer.print("Server: {s}\r\n", .{http.SERVER_NAME});
    try writer.writeAll("Connection: close\r\n");
    if (body_allowed) try writer.writeAll("Transfer-Encoding: chunked\r\n");
    try gph.writeRequestIdHeaders(writer, correlation_id);
    for (upstream_headers) |header| {
        if (gph.shouldSkipUpstreamResponseHeader(header.name)) continue;
        try writer.print("{s}: {s}\r\n", .{ header.name, header.value });
    }
    if (sticky_set_cookie) |cookie| {
        try writer.print("Set-Cookie: {s}\r\n", .{cookie});
    }
    try writeSecurityHeadersFiltered(writer, security, upstream_headers);
    if (alt_svc) |value| try writer.print("Alt-Svc: {s}\r\n", .{value});
    try writer.writeAll("\r\n");
}

pub fn writeBufferedUpstreamResponse(
    writer: anytype,
    upstream_response: anytype,
    keep_alive: bool,
    correlation_id: []const u8,
    security: *const http.security_headers.SecurityHeaders,
    alt_svc: ?[]const u8,
    sticky_set_cookie: ?[]const u8,
) !void {
    var response_buf: [8192]u8 = undefined;
    var response_stream = compat.fixedBufferStream(&response_buf);
    writeBufferedUpstreamResponseHead(
        response_stream.writer(),
        upstream_response,
        keep_alive,
        correlation_id,
        security,
        alt_svc,
        sticky_set_cookie,
    ) catch {
        try writeBufferedUpstreamResponseHead(
            writer,
            upstream_response,
            keep_alive,
            correlation_id,
            security,
            alt_svc,
            sticky_set_cookie,
        );
        if (upstream_response.body.len > 0) try writer.writeAll(upstream_response.body);
        return;
    };
    const head_len = response_stream.getWritten().len;
    if (upstream_response.body.len > 0) {
        response_stream.writer().writeAll(upstream_response.body) catch {
            const written = response_stream.getWritten();
            const body_prefix_len = written.len - head_len;
            try writer.writeAll(written);
            try writer.writeAll(upstream_response.body[body_prefix_len..]);
            return;
        };
    }
    try writer.writeAll(response_stream.getWritten());
}

pub fn writeBufferedUpstreamResponseWithMetrics(
    writer: anytype,
    upstream_response: anytype,
    keep_alive: bool,
    correlation_id: []const u8,
    security: *const http.security_headers.SecurityHeaders,
    alt_svc: ?[]const u8,
    sticky_set_cookie: ?[]const u8,
    metrics: *http.metrics.Metrics,
    metrics_mutex: *compat.Mutex,
) !void {
    const result = writeBufferedUpstreamResponseMeasured(
        writer,
        upstream_response,
        keep_alive,
        correlation_id,
        security,
        alt_svc,
        sticky_set_cookie,
    ) catch |err| {
        recordResponseWriteMetric(metrics, metrics_mutex, attemptedWriterMode(@TypeOf(writer), upstream_response.body.len == 0), 0, true);
        return err;
    };
    recordResponseWriteMetric(metrics, metrics_mutex, result.mode, result.iovecs, false);
}

const BufferedWriteMeasurement = struct {
    mode: http.metrics.ResponseWriteMode,
    iovecs: usize = 0,
};

fn writeBufferedUpstreamResponseMeasured(
    writer: anytype,
    upstream_response: anytype,
    keep_alive: bool,
    correlation_id: []const u8,
    security: *const http.security_headers.SecurityHeaders,
    alt_svc: ?[]const u8,
    sticky_set_cookie: ?[]const u8,
) !BufferedWriteMeasurement {
    const Writer = @TypeOf(writer);
    if (comptime writerSupportsGatheredWrite(Writer)) {
        var scratch: [8192]u8 = undefined;
        const head = try buildBufferedUpstreamResponseHeadBounded(
            &scratch,
            upstream_response,
            keep_alive,
            correlation_id,
            security,
            alt_svc,
            sticky_set_cookie,
        );
        defer head.deinit();
        if (upstream_response.body.len == 0) {
            try writer.writeAll(head.bytes);
            return .{ .mode = .single_write };
        }
        const fragments = [_][]const u8{ head.bytes, upstream_response.body };
        return .{
            .mode = .writev,
            .iovecs = try writer.writeGatheredAll(&fragments),
        };
    }

    try writeBufferedUpstreamResponse(
        writer,
        upstream_response,
        keep_alive,
        correlation_id,
        security,
        alt_svc,
        sticky_set_cookie,
    );
    return .{ .mode = classifyWriterMode(Writer, upstream_response.body.len == 0) };
}

const HeaderBytes = struct {
    allocator: ?std.mem.Allocator = null,
    bytes: []u8,

    fn deinit(self: HeaderBytes) void {
        if (self.allocator) |allocator| allocator.free(self.bytes);
    }
};

fn buildBufferedUpstreamResponseHeadBounded(
    scratch: []u8,
    upstream_response: anytype,
    keep_alive: bool,
    correlation_id: []const u8,
    security: *const http.security_headers.SecurityHeaders,
    alt_svc: ?[]const u8,
    sticky_set_cookie: ?[]const u8,
) !HeaderBytes {
    var stream = compat.fixedBufferStream(scratch);
    writeBufferedUpstreamResponseHead(
        stream.writer(),
        upstream_response,
        keep_alive,
        correlation_id,
        security,
        alt_svc,
        sticky_set_cookie,
    ) catch {
        const fallback_allocator = std.heap.page_allocator;
        var allocating: std.Io.Writer.Allocating = .init(fallback_allocator);
        errdefer allocating.deinit();
        try writeBufferedUpstreamResponseHead(
            &allocating.writer,
            upstream_response,
            keep_alive,
            correlation_id,
            security,
            alt_svc,
            sticky_set_cookie,
        );
        return .{
            .allocator = fallback_allocator,
            .bytes = try allocating.toOwnedSlice(),
        };
    };
    return .{ .bytes = stream.getWritten() };
}

pub fn writeBufferedUpstreamResponseHead(
    writer: anytype,
    upstream_response: anytype,
    keep_alive: bool,
    correlation_id: []const u8,
    security: *const http.security_headers.SecurityHeaders,
    alt_svc: ?[]const u8,
    sticky_set_cookie: ?[]const u8,
) !void {
    const phrase = if (upstream_response.reason.len > 0)
        upstream_response.reason
    else
        (@as(std.http.Status, @enumFromInt(upstream_response.status_code)).phrase() orelse "");

    try writer.print("HTTP/1.1 {d} {s}\r\n", .{ upstream_response.status_code, phrase });
    try writer.print("Server: {s}\r\n", .{http.SERVER_NAME});
    try writer.print("Connection: {s}\r\n", .{if (keep_alive) "keep-alive" else "close"});
    try writer.print("Content-Length: {d}\r\n", .{upstream_response.body.len});
    try gph.writeRequestIdHeaders(writer, correlation_id);
    for (upstream_response.headers) |header| {
        // Defense-in-depth: skip any upstream header that should not be
        // forwarded even if parse-time filtering missed it (e.g. headers
        // populated through a code path that bypasses shouldSkipUpstreamResponseHeader).
        if (gph.shouldSkipUpstreamResponseHeader(header.name)) continue;
        try writer.print("{s}: {s}\r\n", .{ header.name, header.value });
    }
    if (sticky_set_cookie) |cookie| {
        try writer.print("Set-Cookie: {s}\r\n", .{cookie});
    }
    // Only inject security headers that the upstream did not already supply,
    // preventing duplicate / conflicting headers (e.g. double CSP).
    try writeSecurityHeadersFiltered(writer, security, upstream_response.headers);
    if (alt_svc) |value| try writer.print("Alt-Svc: {s}\r\n", .{value});
    try writer.writeAll("\r\n");
}

fn classifyWriterMode(comptime Writer: type, body_empty: bool) http.metrics.ResponseWriteMode {
    _ = body_empty;
    const name = @typeName(Writer);
    if (std.mem.indexOf(u8, name, "tls_termination.TlsConnection.Writer") != null or
        std.mem.indexOf(u8, name, "encrypted_stream_connection.EncryptedStreamHttpConnection.Writer") != null)
    {
        return .tls_buffered;
    }
    return .fallback;
}

fn attemptedWriterMode(comptime Writer: type, body_empty: bool) http.metrics.ResponseWriteMode {
    if (comptime writerSupportsGatheredWrite(Writer)) return if (body_empty) .single_write else .writev;
    return classifyWriterMode(Writer, body_empty);
}

fn writerSupportsGatheredWrite(comptime Writer: type) bool {
    return switch (@typeInfo(Writer)) {
        .pointer => |ptr| @hasDecl(ptr.child, "writeGatheredAll"),
        .@"struct", .@"enum", .@"union", .@"opaque" => @hasDecl(Writer, "writeGatheredAll"),
        else => false,
    };
}

fn recordResponseWriteMetric(
    metrics: *http.metrics.Metrics,
    metrics_mutex: *compat.Mutex,
    mode: http.metrics.ResponseWriteMode,
    iovecs: usize,
    failed: bool,
) void {
    metrics_mutex.lock();
    defer metrics_mutex.unlock();
    if (failed) {
        metrics.recordResponseWriteError(mode);
    } else {
        metrics.recordResponseWriteMode(mode, iovecs);
    }
}

pub fn computeHstsValue(allocator: std.mem.Allocator, cfg: *const edge_config.EdgeConfig) ![]u8 {
    if (!cfg.hsts_enabled or cfg.tls_cert_path.len == 0) return allocator.dupe(u8, "");
    const subs = if (cfg.hsts_include_subdomains) "; includeSubDomains" else "";
    const preload = if (cfg.hsts_preload) "; preload" else "";
    return std.fmt.allocPrint(allocator, "max-age={d}{s}{s}", .{ cfg.hsts_max_age, subs, preload });
}

pub fn writeSecurityHeaders(writer: anytype, sec: *const http.security_headers.SecurityHeaders) !void {
    const EmptyHeader = struct {
        name: []const u8,
        value: []const u8,
    };
    const empty: [0]EmptyHeader = .{};
    try writeSecurityHeadersFiltered(writer, sec, empty[0..]);
}

/// Like writeSecurityHeaders but skips any header already present in
/// `upstream_headers`, preventing duplicate / conflicting headers when the
/// upstream (e.g. a Rails app) already supplies its own security policy.
pub fn writeSecurityHeadersFiltered(
    writer: anytype,
    sec: *const http.security_headers.SecurityHeaders,
    upstream_headers: anytype,
) !void {
    const has = struct {
        fn header(headers: anytype, name: []const u8) bool {
            for (headers) |h| {
                if (std.ascii.eqlIgnoreCase(h.name, name)) return true;
            }
            return false;
        }
    }.header;

    if (sec.x_frame_options.len > 0 and !has(upstream_headers, "X-Frame-Options"))
        try writer.print("X-Frame-Options: {s}\r\n", .{sec.x_frame_options});
    if (sec.x_content_type_options.len > 0 and !has(upstream_headers, "X-Content-Type-Options"))
        try writer.print("X-Content-Type-Options: {s}\r\n", .{sec.x_content_type_options});
    if (sec.content_security_policy.len > 0 and !has(upstream_headers, "Content-Security-Policy"))
        try writer.print("Content-Security-Policy: {s}\r\n", .{sec.content_security_policy});
    if (sec.strict_transport_security.len > 0 and !has(upstream_headers, "Strict-Transport-Security"))
        try writer.print("Strict-Transport-Security: {s}\r\n", .{sec.strict_transport_security});
    if (sec.referrer_policy.len > 0 and !has(upstream_headers, "Referrer-Policy"))
        try writer.print("Referrer-Policy: {s}\r\n", .{sec.referrer_policy});
    if (sec.permissions_policy.len > 0 and !has(upstream_headers, "Permissions-Policy"))
        try writer.print("Permissions-Policy: {s}\r\n", .{sec.permissions_policy});
    if (sec.x_xss_protection.len > 0 and !has(upstream_headers, "X-XSS-Protection"))
        try writer.print("X-XSS-Protection: {s}\r\n", .{sec.x_xss_protection});
    if (sec.cross_origin_opener_policy.len > 0 and !has(upstream_headers, "Cross-Origin-Opener-Policy"))
        try writer.print("Cross-Origin-Opener-Policy: {s}\r\n", .{sec.cross_origin_opener_policy});
    if (sec.cross_origin_resource_policy.len > 0 and !has(upstream_headers, "Cross-Origin-Resource-Policy"))
        try writer.print("Cross-Origin-Resource-Policy: {s}\r\n", .{sec.cross_origin_resource_policy});
}

pub fn writeChunk(writer: anytype, bytes: []const u8) !void {
    try writer.print("{x}\r\n", .{bytes.len});
    try writer.writeAll(bytes);
    try writer.writeAll("\r\n");
}

pub fn responseBodyAllowed(method: []const u8, status_code: u16) bool {
    if (std.ascii.eqlIgnoreCase(method, "HEAD")) return false;
    return !(status_code >= 100 and status_code < 200) and status_code != 204 and status_code != 304;
}

pub fn buildApiErrorJson(allocator: std.mem.Allocator, code: []const u8, message: []const u8, request_id: ?[]const u8) ![]u8 {
    if (request_id) |rid| {
        return std.fmt.allocPrint(allocator, "{{\"code\":\"{s}\",\"message\":\"{s}\",\"request_id\":\"{s}\"}}", .{ code, message, rid });
    }
    return std.fmt.allocPrint(allocator, "{{\"code\":\"{s}\",\"message\":\"{s}\",\"request_id\":null}}", .{ code, message });
}

pub fn sendApiError(allocator: std.mem.Allocator, writer: anytype, status: http.Status, code: []const u8, message: []const u8, request_id: ?[]const u8, keep_alive: bool, state: *GatewayState) !void {
    const payload = try buildApiErrorJson(allocator, code, message, request_id);
    defer allocator.free(payload);

    var response = http.Response.json(allocator, payload);
    defer response.deinit();
    _ = response.setStatus(status).setConnection(keep_alive);
    if (request_id) |rid| {
        gph.setRequestIdHeaders(&response, rid);
    }
    applyResponseHeaders(state, &response);
    try response.writeWithMetrics(writer, &state.metrics, &state.metrics_mutex);
    state.metricsRecord(@intFromEnum(status));
    state.metricsRecordErrorCode(code);
}

const TestUpstreamHeader = struct {
    name: []const u8,
    value: []const u8,
};

const TestBufferedUpstreamResponse = struct {
    metadata_arena: std.heap.ArenaAllocator,
    status_code: u16,
    reason: []const u8,
    headers: []TestUpstreamHeader,
    body: []u8,

    fn deinit(self: *TestBufferedUpstreamResponse, allocator: std.mem.Allocator) void {
        self.metadata_arena.deinit();
        allocator.free(self.body);
        self.* = undefined;
    }
};

const TestGatheredProxyWriter = struct {
    allocator: std.mem.Allocator,
    output: std.ArrayList(u8) = .empty,
    writev_calls: usize = 0,
    writev_iovecs: usize = 0,
    write_all_calls: usize = 0,

    fn init(allocator: std.mem.Allocator) TestGatheredProxyWriter {
        return .{ .allocator = allocator };
    }

    fn deinit(self: *TestGatheredProxyWriter) void {
        self.output.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn writeAll(self: *TestGatheredProxyWriter, bytes: []const u8) !void {
        self.write_all_calls += 1;
        try self.output.appendSlice(self.allocator, bytes);
    }

    pub fn writeGatheredAll(self: *TestGatheredProxyWriter, fragments: []const []const u8) !usize {
        self.writev_calls += 1;
        self.writev_iovecs += fragments.len;
        for (fragments) |fragment| try self.output.appendSlice(self.allocator, fragment);
        return fragments.len;
    }
};

test "writeBufferedUpstreamResponse preserves oversized body bytes exactly" {
    const allocator = std.testing.allocator;
    const prefix = "/*! tailwindcss v4.1.4 | MIT License | synthetic */\n";
    const extra_len = 16 * 1024;
    const body = try allocator.alloc(u8, prefix.len + extra_len);
    defer allocator.free(body);
    @memcpy(body[0..prefix.len], prefix);
    for (body[prefix.len..], 0..) |*byte, idx| {
        byte.* = @intCast('a' + @as(u8, @intCast(idx % 26)));
    }

    var upstream_headers = [_]TestUpstreamHeader{
        .{ .name = "Content-Type", .value = "text/css" },
    };
    var response = TestBufferedUpstreamResponse{
        .metadata_arena = std.heap.ArenaAllocator.init(allocator),
        .status_code = 200,
        .reason = "OK",
        .headers = upstream_headers[0..],
        .body = body,
    };
    defer response.metadata_arena.deinit();

    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    try writeBufferedUpstreamResponse(
        &output.writer,
        &response,
        false,
        "req-large-body",
        &http.security_headers.SecurityHeaders.api,
        null,
        null,
    );

    const raw = output.written();
    const head_end = std.mem.find(u8, raw, "\r\n\r\n") orelse return error.InvalidHttpResponse;
    try std.testing.expectEqualStrings(body, raw[head_end + 4 ..]);
}

test "writeBufferedUpstreamResponse serializes a single forwarded response head" {
    const allocator = std.testing.allocator;
    const body = try allocator.dupe(u8, "pong");
    var upstream_headers = [_]TestUpstreamHeader{
        .{ .name = "Content-Type", .value = "text/plain" },
        .{ .name = "Location", .value = "/health" },
        .{ .name = "Server", .value = "python" },
        .{ .name = "X-Upstream-Test", .value = "1" },
    };

    var response = TestBufferedUpstreamResponse{
        .metadata_arena = std.heap.ArenaAllocator.init(allocator),
        .status_code = 200,
        .reason = "OK",
        .headers = upstream_headers[0..],
        .body = body,
    };
    defer response.deinit(allocator);

    var buf: [4096]u8 = undefined;
    var stream = compat.fixedBufferStream(&buf);
    try writeBufferedUpstreamResponse(
        stream.writer(),
        &response,
        true,
        "tg-1778460305668-bfebecb410803023",
        &http.security_headers.SecurityHeaders.api,
        null,
        "tg_sticky=proxy",
    );

    const output = stream.getWritten();
    try std.testing.expect(std.mem.startsWith(u8, output, "HTTP/1.1 200 OK\r\n"));
    try std.testing.expect(std.mem.find(u8, output, "Server: tardigrade\r\n") != null);
    try std.testing.expect(std.mem.find(u8, output, "Connection: keep-alive\r\n") != null);
    try std.testing.expect(std.mem.find(u8, output, "Content-Length: 4\r\n") != null);
    try std.testing.expect(std.mem.find(u8, output, "Content-Type: text/plain\r\n") != null);
    try std.testing.expect(std.mem.find(u8, output, "Location: /health\r\n") != null);
    try std.testing.expect(std.mem.find(u8, output, "X-Upstream-Test: 1\r\n") != null);
    try std.testing.expect(std.mem.find(u8, output, "Set-Cookie: tg_sticky=proxy\r\n") != null);
    try std.testing.expect(std.mem.find(u8, output, "X-Request-ID: tg-1778460305668-bfebecb410803023\r\n") != null);
    try std.testing.expect(std.mem.find(u8, output, "X-Correlation-ID: tg-1778460305668-bfebecb410803023\r\n") != null);
    try std.testing.expect(std.mem.find(u8, output, "Server: python\r\n") == null);
    try std.testing.expect(std.mem.endsWith(u8, output, "\r\n\r\npong"));
}

test "writeBufferedUpstreamResponseWithMetrics uses gathered write for data-plane body" {
    const allocator = std.testing.allocator;
    const body = try allocator.dupe(u8, "pong");
    var upstream_headers = [_]TestUpstreamHeader{
        .{ .name = "Content-Type", .value = "text/plain" },
    };
    var response = TestBufferedUpstreamResponse{
        .metadata_arena = std.heap.ArenaAllocator.init(allocator),
        .status_code = 200,
        .reason = "OK",
        .headers = upstream_headers[0..],
        .body = body,
    };
    defer response.deinit(allocator);

    var writer = TestGatheredProxyWriter.init(allocator);
    defer writer.deinit();
    var metrics = http.metrics.Metrics.init();
    var metrics_mutex = compat.Mutex{};

    try writeBufferedUpstreamResponseWithMetrics(
        &writer,
        &response,
        true,
        "req-gathered",
        &http.security_headers.SecurityHeaders.api,
        null,
        null,
        &metrics,
        &metrics_mutex,
    );

    try std.testing.expectEqual(@as(usize, 1), writer.writev_calls);
    try std.testing.expectEqual(@as(usize, 2), writer.writev_iovecs);
    try std.testing.expectEqual(@as(usize, 0), writer.write_all_calls);
    try std.testing.expect(std.mem.startsWith(u8, writer.output.items, "HTTP/1.1 200 OK\r\n"));
    try std.testing.expect(std.mem.endsWith(u8, writer.output.items, "pong"));
    try std.testing.expectEqual(@as(u64, 1), metrics.response_write_mode_total[0]);
    try std.testing.expectEqual(@as(u64, 2), metrics.response_writev_iovecs_total);
}

test "writeBufferedUpstreamResponse strips upstream Alt-Svc and emits effective policy once" {
    const allocator = std.testing.allocator;
    const body = try allocator.dupe(u8, "pong");
    var upstream_headers = [_]TestUpstreamHeader{
        .{ .name = "Content-Type", .value = "text/plain" },
        .{ .name = "Alt-Svc", .value = "h3=\":443\"; ma=86400" },
    };

    var response = TestBufferedUpstreamResponse{
        .metadata_arena = std.heap.ArenaAllocator.init(allocator),
        .status_code = 200,
        .reason = "OK",
        .headers = upstream_headers[0..],
        .body = body,
    };
    defer response.deinit(allocator);

    var buf: [4096]u8 = undefined;
    var stream = compat.fixedBufferStream(&buf);
    try writeBufferedUpstreamResponse(
        stream.writer(),
        &response,
        true,
        "req-alt-svc",
        &http.security_headers.SecurityHeaders.api,
        "clear",
        null,
    );

    const output = stream.getWritten();
    try std.testing.expect(std.mem.find(u8, output, "Alt-Svc: h3=\":443\"") == null);
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, output, "Alt-Svc:"));
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, output, "Alt-Svc: clear\r\n"));
    try std.testing.expect(std.mem.find(u8, output, "Alt-Svc: clear\r\n") != null);
}

test "writeStreamedUpstreamResponse emits effective Alt-Svc policy" {
    var buf: [4096]u8 = undefined;
    var stream = compat.fixedBufferStream(&buf);

    try writeStreamedUpstreamResponse(
        stream.writer(),
        200,
        "OK",
        "text/plain",
        null,
        "req-stream-alt-svc",
        &http.security_headers.SecurityHeaders.api,
        "h3=\":8443\"; ma=120",
        null,
    );

    const output = stream.getWritten();
    try std.testing.expect(std.mem.find(u8, output, "Transfer-Encoding: chunked\r\n") != null);
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, output, "Alt-Svc:"));
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, output, "Alt-Svc: h3=\":8443\"; ma=120\r\n"));
    try std.testing.expect(std.mem.find(u8, output, "Alt-Svc: h3=\":8443\"; ma=120\r\n") != null);
    try std.testing.expect(std.mem.endsWith(u8, output, "\r\n\r\n"));
}

test "writeStreamedUpstreamResponseHeadFromHeaders strips upstream Alt-Svc and emits effective policy once" {
    var upstream_headers = [_]TestUpstreamHeader{
        .{ .name = "Content-Type", .value = "text/plain" },
        .{ .name = "Alt-Svc", .value = "h3=\":443\"; ma=86400" },
        .{ .name = "Server", .value = "origin" },
    };
    var buf: [4096]u8 = undefined;
    var stream = compat.fixedBufferStream(&buf);

    try writeStreamedUpstreamResponseHeadFromHeaders(
        stream.writer(),
        200,
        "OK",
        upstream_headers[0..],
        true,
        "req-stream-headers-alt-svc",
        &http.security_headers.SecurityHeaders.api,
        "clear",
        null,
    );

    const output = stream.getWritten();
    try std.testing.expect(std.mem.find(u8, output, "Alt-Svc: h3=\":443\"") == null);
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, output, "Alt-Svc:"));
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, output, "Alt-Svc: clear\r\n"));
    try std.testing.expect(std.mem.find(u8, output, "Alt-Svc: clear\r\n") != null);
    try std.testing.expect(std.mem.find(u8, output, "Server: origin\r\n") == null);
    try std.testing.expect(std.mem.endsWith(u8, output, "\r\n\r\n"));
}

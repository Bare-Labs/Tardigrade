//! HTTP/3- and QPACK-vantage qlog events (#255).
//!
//! The symmetric half of `src/quic/qlog.zig`. It exists here, in `src/http3`,
//! because these events (`http3:*`) describe the *application*
//! mapping — SETTINGS, control-stream framing, HEADERS/DATA, GOAWAY, and QPACK
//! diagnostics — and must not leak into the transport package. Just
//! like the transport side it emits through an injected `Sink`; the concrete
//! qlog file writer lives at the composition root and interleaves this stream
//! with the transport stream into one trace.
//!
//! Scope note: only the events needed before external interop are modelled
//! here. The current HTTP/3 qlog draft no longer standardizes QPACK events, so
//! `qpack_state_updated` is emitted as a documented `tardigrade:*` extension.

const std = @import("std");
const http3_frame = @import("frame.zig");
const qpack = @import("qpack.zig");

/// qlog application-vantage namespaces owned by HTTP/3.
pub const Namespace = enum {
    http3,
    tardigrade,

    pub fn label(self: Namespace) []const u8 {
        return @tagName(self);
    }
};

/// H3 frame types we surface in traces (RFC 9114 §7.2).
pub const FrameType = enum {
    data,
    headers,
    settings,
    goaway,
    priority_update,
    push_promise,
    cancel_push,
    max_push_id,

    pub fn label(self: FrameType) []const u8 {
        return @tagName(self);
    }
};

pub const Direction = enum { created, parsed };
pub const Initiator = enum { local, remote };
pub const StreamType = enum {
    control,
    qpack_encode,
    qpack_decode,
    request,
    push,
    unknown,
};

/// QPACK stream state (RFC 9204 §2.1.2): a request stream becomes `blocked`
/// when it references a dynamic-table entry not yet acknowledged by the
/// encoder stream, and `unblocked` once the required insert count arrives.
pub const QpackState = enum { blocked, unblocked };

pub const HttpField = qpack.HeaderField;

pub const SettingName = enum {
    settings_qpack_max_table_capacity,
    settings_max_field_section_size,
    settings_qpack_blocked_streams,
    settings_enable_connect_protocol,
    settings_h3_datagram,
};

pub const HttpPriority = struct {
    urgency: u3,
    incremental: bool,
};

pub const Frame = union(enum) {
    data: struct {
        raw_length: ?usize = null,
    },
    headers: struct {
        headers: []const HttpField = &.{},
        raw_length: ?usize = null,
    },
    settings: struct {
        settings: ?http3_frame.Settings = null,
        raw_length: ?usize = null,
    },
    goaway: struct {
        id: u64,
        raw_length: ?usize = null,
    },
    priority_update: union(enum) {
        request: struct {
            stream_id: u64,
            priority_field_value: []const u8,
            raw_length: ?usize = null,
        },
        push: struct {
            push_id: u64,
            priority_field_value: []const u8,
            raw_length: ?usize = null,
        },
    },
    push_promise: struct {
        push_id: u64,
        headers: []const HttpField = &.{},
        raw_length: ?usize = null,
    },
    cancel_push: struct {
        push_id: u64,
        raw_length: ?usize = null,
    },
    max_push_id: struct {
        push_id: u64,
        raw_length: ?usize = null,
    },

    pub fn frameType(self: Frame) FrameType {
        return switch (self) {
            .data => .data,
            .headers => .headers,
            .settings => .settings,
            .goaway => .goaway,
            .priority_update => .priority_update,
            .push_promise => .push_promise,
            .cancel_push => .cancel_push,
            .max_push_id => .max_push_id,
        };
    }
};

pub const Event = union(enum) {
    /// http3:parameters_set (SETTINGS applied)
    parameters_set: struct {
        initiator: ?Initiator = null,
        max_field_section_size: ?u64 = null,
        max_table_capacity: ?u64 = null,
        blocked_streams_count: ?u64 = null,
    },
    /// http3:stream_type_set
    stream_type_set: struct {
        stream_id: u64,
        stream_type: StreamType,
    },
    /// http3:frame_created / http3:frame_parsed
    frame: struct {
        direction: Direction,
        stream_id: u64,
        frame: Frame,
    },
    /// http3:priority_updated
    priority_updated: struct {
        stream_id: u64,
        new: HttpPriority,
    },
    /// tardigrade:qpack_stream_state_updated (head-of-line blocking)
    qpack_state_updated: struct {
        state: QpackState,
        stream_id: u64,
    },

    pub fn namespace(self: Event) Namespace {
        return switch (self) {
            .parameters_set, .stream_type_set, .frame, .priority_updated => .http3,
            .qpack_state_updated => .tardigrade,
        };
    }

    pub fn name(self: Event) []const u8 {
        return switch (self) {
            .parameters_set => "parameters_set",
            .stream_type_set => "stream_type_set",
            .frame => |f| switch (f.direction) {
                .created => "frame_created",
                .parsed => "frame_parsed",
            },
            .priority_updated => "priority_updated",
            .qpack_state_updated => "qpack_stream_state_updated",
        };
    }
};

pub const Record = struct {
    time_us: u64,
    event: Event,
};

/// Injected emission seam — same shape as `quic.qlog.Sink`, so a composition
/// root can hold one of each and route both into the same trace file. A default
/// `.{}` is a no-op.
///
/// `emit_fn` returns `void`, so a concrete file sink cannot propagate write
/// errors here. Same contract as the transport sink: retain the first error
/// and/or count dropped records out-of-band so a truncated trace is detectable.
pub const Sink = struct {
    context: ?*anyopaque = null,
    emit_fn: ?*const fn (?*anyopaque, Record) void = null,

    pub fn emit(self: Sink, record: Record) void {
        if (self.emit_fn) |f| f(self.context, record);
    }

    pub fn log(self: Sink, time_us: u64, event: Event) void {
        self.emit(.{ .time_us = time_us, .event = event });
    }
};

/// JSON-SEQ record separator (RFC 7464), identical framing to the transport
/// side so both streams concatenate into one valid qlog JSON-SEQ file.
pub const record_separator: u8 = 0x1e;

const Buf = struct {
    buf: []u8,
    len: usize = 0,

    fn add(self: *Buf, comptime fmt: []const u8, args: anytype) error{NoSpaceLeft}!void {
        const written = try std.fmt.bufPrint(self.buf[self.len..], fmt, args);
        self.len += written.len;
    }

    fn slice(self: *const Buf) []const u8 {
        return self.buf[0..self.len];
    }
};

fn writeRawLength(b: *Buf, length: ?usize, need_comma: *bool) error{NoSpaceLeft}!void {
    if (length) |v| {
        if (need_comma.*) try b.add(",", .{});
        try b.add("\"raw\":{{\"length\":{d}}}", .{v});
        need_comma.* = true;
    }
}

fn writeHexNibble(b: *Buf, value: u8) error{NoSpaceLeft}!void {
    const c: u8 = if (value < 10) '0' + value else 'a' + (value - 10);
    try b.add("{c}", .{c});
}

fn writeHexBytes(b: *Buf, value: []const u8) error{NoSpaceLeft}!void {
    try b.add("\"", .{});
    for (value) |byte| {
        try writeHexNibble(b, byte >> 4);
        try writeHexNibble(b, byte & 0x0f);
    }
    try b.add("\"", .{});
}

fn writeJsonString(b: *Buf, value: []const u8) error{NoSpaceLeft}!void {
    try b.add("\"", .{});
    for (value) |byte| {
        switch (byte) {
            '"' => try b.add("\\\"", .{}),
            '\\' => try b.add("\\\\", .{}),
            0x08 => try b.add("\\b", .{}),
            0x0c => try b.add("\\f", .{}),
            '\n' => try b.add("\\n", .{}),
            '\r' => try b.add("\\r", .{}),
            '\t' => try b.add("\\t", .{}),
            else => if (byte >= 0x20) {
                try b.add("{c}", .{byte});
            } else {
                try b.add("\\u00", .{});
                try writeHexNibble(b, byte >> 4);
                try writeHexNibble(b, byte & 0x0f);
            },
        }
    }
    try b.add("\"", .{});
}

fn writeTextOrBytes(b: *Buf, text_key: []const u8, bytes_key: []const u8, value: []const u8) error{NoSpaceLeft}!void {
    if (std.unicode.utf8ValidateSlice(value)) {
        try b.add("\"{s}\":", .{text_key});
        try writeJsonString(b, value);
    } else {
        try b.add("\"{s}\":", .{bytes_key});
        try writeHexBytes(b, value);
    }
}

fn writeHeaders(b: *Buf, headers: []const HttpField) error{NoSpaceLeft}!void {
    try b.add("\"headers\":[", .{});
    for (headers, 0..) |field, i| {
        if (i != 0) try b.add(",", .{});
        try b.add("{{", .{});
        try writeTextOrBytes(b, "name", "name_bytes", field.name);
        try b.add(",", .{});
        try writeTextOrBytes(b, "value", "value_bytes", field.value);
        try b.add("}}", .{});
    }
    try b.add("]", .{});
}

fn writeSetting(b: *Buf, name: SettingName, value: u64, first: *bool) error{NoSpaceLeft}!void {
    if (!first.*) try b.add(",", .{});
    first.* = false;
    try b.add("{{\"name\":\"{s}\",\"value\":{d}}}", .{ @tagName(name), value });
}

fn writeSettings(b: *Buf, settings: ?http3_frame.Settings) error{NoSpaceLeft}!void {
    try b.add("\"settings\":[", .{});
    if (settings) |s| {
        var first = true;
        if (s.qpack_max_table_capacity != 0) try writeSetting(b, .settings_qpack_max_table_capacity, s.qpack_max_table_capacity, &first);
        if (s.max_field_section_size) |max| try writeSetting(b, .settings_max_field_section_size, max, &first);
        if (s.qpack_blocked_streams != 0) try writeSetting(b, .settings_qpack_blocked_streams, s.qpack_blocked_streams, &first);
        if (s.enable_connect_protocol) try writeSetting(b, .settings_enable_connect_protocol, 1, &first);
        if (s.h3_datagram) try writeSetting(b, .settings_h3_datagram, 1, &first);
    }
    try b.add("]", .{});
}

fn writeFrame(b: *Buf, frame: Frame) error{NoSpaceLeft}!void {
    try b.add("{{\"frame_type\":\"{s}\"", .{frame.frameType().label()});
    var need_comma = true;
    switch (frame) {
        .data => |d| try writeRawLength(b, d.raw_length, &need_comma),
        .headers => |d| {
            try b.add(",", .{});
            try writeHeaders(b, d.headers);
            try writeRawLength(b, d.raw_length, &need_comma);
        },
        .settings => |d| {
            try b.add(",", .{});
            try writeSettings(b, d.settings);
            try writeRawLength(b, d.raw_length, &need_comma);
        },
        .goaway => |d| {
            try b.add(",\"id\":{d}", .{d.id});
            try writeRawLength(b, d.raw_length, &need_comma);
        },
        .priority_update => |d| {
            switch (d) {
                .request => |r| {
                    try b.add(",\"stream_id\":{d},\"priority_field_value\":", .{r.stream_id});
                    try writeJsonString(b, r.priority_field_value);
                    try writeRawLength(b, r.raw_length, &need_comma);
                },
                .push => |p| {
                    try b.add(",\"push_id\":{d},\"priority_field_value\":", .{p.push_id});
                    try writeJsonString(b, p.priority_field_value);
                    try writeRawLength(b, p.raw_length, &need_comma);
                },
            }
        },
        .push_promise => |d| {
            try b.add(",\"push_id\":{d},", .{d.push_id});
            try writeHeaders(b, d.headers);
            try writeRawLength(b, d.raw_length, &need_comma);
        },
        .cancel_push => |d| {
            try b.add(",\"push_id\":{d}", .{d.push_id});
            try writeRawLength(b, d.raw_length, &need_comma);
        },
        .max_push_id => |d| {
            try b.add(",\"push_id\":{d}", .{d.push_id});
            try writeRawLength(b, d.raw_length, &need_comma);
        },
    }
    try b.add("}}", .{});
}

fn writeData(b: *Buf, event: Event) error{NoSpaceLeft}!void {
    switch (event) {
        .parameters_set => |d| {
            try b.add("{{", .{});
            var need_comma = false;
            if (d.initiator) |v| {
                try b.add("\"initiator\":\"{s}\"", .{@tagName(v)});
                need_comma = true;
            }
            if (d.max_field_section_size) |v| {
                if (need_comma) try b.add(",", .{});
                try b.add("\"max_field_section_size\":{d}", .{v});
                need_comma = true;
            }
            if (d.max_table_capacity) |v| {
                if (need_comma) try b.add(",", .{});
                try b.add("\"max_table_capacity\":{d}", .{v});
                need_comma = true;
            }
            if (d.blocked_streams_count) |v| {
                if (need_comma) try b.add(",", .{});
                try b.add("\"blocked_streams_count\":{d}", .{v});
            }
            try b.add("}}", .{});
        },
        .stream_type_set => |d| try b.add(
            "{{\"stream_id\":{d},\"stream_type\":\"{s}\"}}",
            .{ d.stream_id, @tagName(d.stream_type) },
        ),
        .frame => |d| {
            try b.add("{{\"stream_id\":{d},\"frame\":", .{d.stream_id});
            try writeFrame(b, d.frame);
            try b.add("}}", .{});
        },
        .priority_updated => |d| {
            try b.add("{{\"stream_id\":{d},\"new\":\"u={d}", .{ d.stream_id, d.new.urgency });
            if (d.new.incremental) try b.add(", i", .{});
            try b.add("\"}}", .{});
        },
        .qpack_state_updated => |d| try b.add(
            "{{\"stream_id\":{d},\"state\":\"{s}\"}}",
            .{ d.stream_id, @tagName(d.state) },
        ),
    }
}

/// Serialize one `Record` into `out` as a single qlog JSON-SEQ line. Same shape
/// as `quic.qlog.writeJson` so a merged trace is uniform.
pub fn writeJson(record: Record, out: []u8) error{NoSpaceLeft}![]const u8 {
    var b = Buf{ .buf = out };
    try b.add("{c}", .{record_separator});
    try b.add(
        "{{\"time\":{d}.{d:0>3},\"name\":\"{s}:{s}\",\"data\":",
        .{ record.time_us / 1000, record.time_us % 1000, record.event.namespace().label(), record.event.name() },
    );
    try writeData(&b, record.event);
    try b.add("}}\n", .{});
    return b.slice();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn expectJson(record: Record, needle: []const u8) !void {
    var buf: [2048]u8 = undefined;
    const line = try writeJson(record, &buf);
    try testing.expect(line[0] == record_separator);
    try testing.expect(line[line.len - 1] == '\n');
    try testing.expect(std.mem.indexOf(u8, line, needle) != null);
}

fn expectValidJson(record: Record) !void {
    var buf: [2048]u8 = undefined;
    const line = try writeJson(record, &buf);
    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, line[1 .. line.len - 1], .{});
    defer parsed.deinit();
}

test "qpack blocking is a Tardigrade extension event" {
    const ev = Event{ .qpack_state_updated = .{ .state = .blocked, .stream_id = 12 } };
    try testing.expectEqual(Namespace.tardigrade, ev.namespace());
    try expectJson(.{ .time_us = 42, .event = ev }, "\"name\":\"tardigrade:qpack_stream_state_updated\"");
    try expectJson(.{ .time_us = 42, .event = ev }, "\"state\":\"blocked\"");
}

test "frame direction chooses frame_created vs frame_parsed" {
    try expectJson(
        .{ .time_us = 0, .event = .{ .frame = .{ .direction = .created, .stream_id = 0, .frame = .{ .headers = .{ .headers = &.{.{ .name = ":status", .value = "200" }}, .raw_length = 20 } } } } },
        "\"name\":\"http3:frame_created\"",
    );
    try expectJson(
        .{ .time_us = 0, .event = .{ .frame = .{ .direction = .parsed, .stream_id = 3, .frame = .{ .goaway = .{ .id = 0 } } } } },
        "\"name\":\"http3:frame_parsed\"",
    );
}

test "parameters_set only emits present settings" {
    try expectJson(
        .{ .time_us = 0, .event = .{ .parameters_set = .{ .initiator = .remote, .blocked_streams_count = 16 } } },
        "{\"initiator\":\"remote\",\"blocked_streams_count\":16}",
    );
}

test "stream_type_set and representative frames use http3 names" {
    try expectJson(
        .{ .time_us = 0, .event = .{ .stream_type_set = .{ .stream_id = 2, .stream_type = .control } } },
        "\"name\":\"http3:stream_type_set\"",
    );
    try expectJson(
        .{ .time_us = 0, .event = .{ .frame = .{ .direction = .created, .stream_id = 0, .frame = .{ .settings = .{ .settings = .{ .qpack_blocked_streams = 16 } } } } } },
        "\"frame_type\":\"settings\"",
    );
    try expectJson(
        .{ .time_us = 0, .event = .{ .frame = .{ .direction = .created, .stream_id = 0, .frame = .{ .settings = .{ .settings = .{ .qpack_blocked_streams = 16, .max_field_section_size = 4096 } } } } } },
        "\"settings\":[{\"name\":\"settings_max_field_section_size\",\"value\":4096},{\"name\":\"settings_qpack_blocked_streams\",\"value\":16}]",
    );
    try expectJson(
        .{ .time_us = 0, .event = .{ .frame = .{ .direction = .parsed, .stream_id = 4, .frame = .{ .headers = .{ .headers = &.{.{ .name = ":path", .value = "/" }}, .raw_length = 32 } } } } },
        "\"headers\":[{\"name\":\":path\",\"value\":\"/\"}]",
    );
    try expectJson(
        .{ .time_us = 0, .event = .{ .frame = .{ .direction = .created, .stream_id = 0, .frame = .{ .goaway = .{ .id = 4 } } } } },
        "\"id\":4",
    );
}

test "frame JSON string fields are escaped and parseable" {
    const record = Record{ .time_us = 0, .event = .{ .frame = .{ .direction = .parsed, .stream_id = 4, .frame = .{ .headers = .{
        .headers = &.{.{ .name = "x\"name", .value = "a\\b\n" }},
        .raw_length = 12,
    } } } } };
    try expectJson(record, "\"name\":\"x\\\"name\"");
    try expectJson(record, "\"value\":\"a\\\\b\\n\"");
    try expectValidJson(record);
}

test "header fields with non UTF-8 bytes use byte-oriented qlog fields" {
    const record = Record{ .time_us = 0, .event = .{ .frame = .{ .direction = .parsed, .stream_id = 4, .frame = .{ .headers = .{
        .headers = &.{.{ .name = "x", .value = &.{ 0xff, 0x00, '"' } }},
        .raw_length = 12,
    } } } } };
    try expectJson(record, "\"name\":\"x\"");
    try expectJson(record, "\"value_bytes\":\"ff0022\"");
    try expectValidJson(record);
}

test "priority_update frames emit typed targets and escaped values" {
    const request = Record{ .time_us = 0, .event = .{ .frame = .{ .direction = .parsed, .stream_id = 0, .frame = .{ .priority_update = .{ .request = .{
        .stream_id = 8,
        .priority_field_value = "u=1\"",
        .raw_length = 9,
    } } } } } };
    try expectJson(request, "\"stream_id\":8,\"priority_field_value\":\"u=1\\\"\"");
    try expectValidJson(request);

    const push = Record{ .time_us = 0, .event = .{ .frame = .{ .direction = .created, .stream_id = 0, .frame = .{ .priority_update = .{ .push = .{
        .push_id = 3,
        .priority_field_value = "i",
        .raw_length = 5,
    } } } } } };
    try expectJson(push, "\"push_id\":3,\"priority_field_value\":\"i\"");
    try expectValidJson(push);
}

test "default sink is a no-op" {
    const sink = Sink{};
    sink.log(1, .{ .qpack_state_updated = .{ .state = .unblocked, .stream_id = 0 } });
}

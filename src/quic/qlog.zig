//! Transport-layer qlog event model and a minimal JSON-SEQ serializer (#255).
//!
//! This is the observability seam the pure-Zig QUIC transport emits through
//! *before* external interop. It defines:
//!
//!   * `Event`     — a closed union of the transport events qvis/qlog tooling
//!                   needs to explain handshake, loss, path, and flow-control
//!                   behaviour (RFC 9000/9002 vantage points).
//!   * `Record`    — an `Event` stamped with a monotonic time.
//!   * `Sink`      — the injected emission seam, mirroring
//!                   `recovery.EventSink`: an opaque context plus a function
//!                   pointer. The transport calls `sink.emit(record)` and never
//!                   learns what the sink does with it.
//!   * `writeJson` — turns one `Record` into a single qlog JSON-SEQ line
//!                   (RFC 7464: 0x1E record separator + JSON + '\n').
//!
//! ## Layering (the #255 "don't leak H3 into src/quic" decision)
//!
//! `src/quic` owns *only* transport-vantage events (the `quic:*` namespace
//! plus documented `tardigrade:*` debug extensions). HTTP/3- and
//! QPACK-vantage events live in `src/http3/qlog.zig` and are emitted from
//! `src/http3`. Neither package imports the other — the same boundary the
//! build graph already enforces (see build.zig: the smoke harness stitches the
//! two together, "so neither package learns about the other").
//!
//! The *concrete* qlog file writer therefore lives at the composition root
//! (the gateway h3 listener, or the `tests/quic_h3_smoke.zig` harness), which
//! owns both packages. It installs one `quic.qlog.Sink` and one
//! `http3.qlog.Sink`, and interleaves both event streams into a single qlog
//! trace. This keeps `src/quic` free of any HTTP/3 type while still producing a
//! unified trace file.
//!
//! ## Cost when disabled
//!
//! A default `Sink{}` has a null `emit_fn`; `emit` is a single null check and
//! return. Callers should still guard expensive event construction behind
//! `config.Observability.qlog_enabled` so the hot path pays nothing when qlog
//! is off (the default, per the issue's "disabled by default" requirement).

const std = @import("std");

pub const quic_event_schema_uri = "urn:ietf:params:qlog:events:quic-13";
pub const http3_event_schema_uri = "urn:ietf:params:qlog:events:http3-13";
pub const tardigrade_event_schema_uri = "https://bare.systems/tardigrade/qlog/events/debug-1";
pub const file_schema_uri = "urn:ietf:params:qlog:file:sequential";
pub const serialization_format = "application/qlog+json-seq";
pub const sqlog_suffix = ".sqlog";

/// qlog event namespace this transport emits. Application (`http3`) events are
/// intentionally absent: they belong to `src/http3`.
pub const Namespace = enum {
    quic,
    tardigrade,

    pub fn label(self: Namespace) []const u8 {
        return @tagName(self);
    }
};

/// QUIC packet types (RFC 9000 §17), named as qlog expects them.
pub const PacketType = enum {
    initial,
    zero_rtt,
    handshake,
    one_rtt,
    retry,
    version_negotiation,

    pub fn label(self: PacketType) []const u8 {
        return switch (self) {
            .zero_rtt => "0RTT",
            .one_rtt => "1RTT",
            else => @tagName(self),
        };
    }
};

/// Coarse handshake milestones, enough to localize a stalled handshake to a
/// key-installation / transport-parameter / confirmation stage.
pub const HandshakeStage = enum {
    started,
    initial_keys_installed,
    handshake_keys_installed,
    application_keys_installed,
    transport_parameters_authenticated,
    confirmed,
    failed,
};

/// Why a connection closed (drives `quic:connection_closed`).
pub const CloseReason = enum {
    idle_timeout,
    application_close,
    transport_error,
    stateless_reset,
    handshake_failure,
};

pub const CloseError = union(enum) {
    none,
    connection_unknown: u64,
    application_unknown: u64,
};

/// PATH_CHALLENGE / PATH_RESPONSE lifecycle phases (RFC 9000 §8.2).
pub const PathEventKind = enum {
    challenge_sent,
    challenge_received,
    response_sent,
    response_received,
    validated,
    failed,
};

pub const TupleEndpointInfo = struct {};

pub const KeyType = enum {
    server_initial_secret,
    client_initial_secret,
    server_handshake_secret,
    client_handshake_secret,
    server_0rtt_secret,
    client_0rtt_secret,
    server_1rtt_secret,
    client_1rtt_secret,
};

pub const KeyUpdateTrigger = enum {
    tls,
    local_update,
    remote_update,
};

pub const MigrationState = enum {
    probing_started,
    probing_abandoned,
    probing_successful,
    migration_started,
    migration_abandoned,
    migration_complete,
};

/// RESET_STREAM / STOP_SENDING direction (RFC 9000 §19.4, §19.5).
pub const StreamResetKind = enum {
    reset_sent,
    reset_received,
    stop_sending_sent,
    stop_sending_received,
};

pub const BlockedState = enum { blocked, unblocked };
pub const BlockedReason = enum {
    scheduling,
    pacing,
    amplification_protection,
    congestion_control,
    connection_flow_control,
    stream_flow_control,
    stream_id,
    application,
};

pub const DataBlocked = union(enum) {
    connection: struct {
        old: ?BlockedState = null,
        new: BlockedState,
        reason: ?BlockedReason = null,
    },
    stream: struct {
        stream_id: u64,
        old: ?BlockedState = null,
        new: BlockedState,
        reason: ?BlockedReason = null,
    },
};

/// Why an inbound packet was dropped. `decryption_failure` is the qlog
/// canonical trigger for AEAD deprotection failure — the #255 requirement that
/// deprotection failures are reported deterministically.
pub const DropTrigger = enum {
    decryption_failure,
    key_unavailable,
    connection_unknown,
    invalid,
    unsupported,
    duplicate,
    internal_error,
    rejected,
    general,
};

pub const RecoveryMetrics = struct {
    latest_rtt_ms: ?u64 = null,
    smoothed_rtt_ms: ?u64 = null,
    rtt_variance_ms: ?u64 = null,
    pto_count: ?u16 = null,
    congestion_window: ?u64 = null,
    bytes_in_flight: ?u64 = null,
};

/// The closed set of transport-vantage events. Data payloads are kept small and
/// copy-free (scalars/enums only) so emitting is cheap and the union never
/// borrows connection-owned buffers.
pub const Event = union(enum) {
    /// quic:connection_started
    connection_started: struct {
        local: TupleEndpointInfo = .{},
        remote: TupleEndpointInfo = .{},
        odcid_len: u8 = 0,
        scid_len: u8 = 0,
        dcid_len: u8 = 0,
    },
    /// quic:connection_closed
    connection_closed: struct {
        reason: CloseReason,
        close_error: CloseError = .none,
    },
    /// tardigrade:quic_handshake_progressed (progress milestone; not a
    /// standard qlog event, kept under a Tardigrade namespace for stage
    /// visibility)
    handshake_progressed: struct {
        stage: HandshakeStage,
    },
    /// quic:key_updated (1-RTT key-phase flip, RFC 9001 §6)
    key_updated: struct {
        key_type: KeyType,
        key_phase: ?u64 = null,
        trigger: ?KeyUpdateTrigger = null,
    },
    /// quic:packet_sent
    packet_sent: struct {
        packet_type: PacketType,
        packet_number: u64,
        length: usize,
        ack_eliciting: bool = false,
    },
    /// quic:packet_received
    packet_received: struct {
        packet_type: PacketType,
        packet_number: u64,
        length: usize,
    },
    /// quic:packet_lost
    packet_lost: struct {
        packet_type: PacketType,
        packet_number: ?u64 = null,
    },
    /// quic:recovery_metrics_updated
    recovery_metrics_updated: RecoveryMetrics,
    /// quic:packet_dropped (deprotection failure and other drops)
    packet_dropped: struct {
        packet_type: ?PacketType = null,
        trigger: DropTrigger,
        length: usize = 0,
    },
    /// tardigrade:quic_path_validation (PATH_CHALLENGE / PATH_RESPONSE)
    path_validation: struct {
        kind: PathEventKind,
        path_id: u8 = 0,
    },
    /// quic:migration_state_updated
    connection_migrated: struct {
        old: ?MigrationState = null,
        new: MigrationState,
    },
    /// tardigrade:quic_stream_reset (RESET_STREAM / STOP_SENDING)
    stream_reset: struct {
        kind: StreamResetKind,
        stream_id: u64,
        error_code: u64 = 0,
    },
    /// quic:connection_data_blocked_updated /
    /// quic:stream_data_blocked_updated (flow-control blocked)
    data_blocked: DataBlocked,

    pub fn namespace(self: Event) Namespace {
        return switch (self) {
            .connection_started,
            .connection_closed,
            .connection_migrated,
            .key_updated,
            .packet_lost,
            .recovery_metrics_updated,
            .packet_sent,
            .packet_received,
            .packet_dropped,
            .data_blocked,
            => .quic,
            .path_validation,
            .stream_reset,
            .handshake_progressed,
            => .tardigrade,
        };
    }

    /// The qlog event name within the namespace (the part after the `:`).
    pub fn name(self: Event) []const u8 {
        return switch (self) {
            .connection_started => "connection_started",
            .connection_closed => "connection_closed",
            .handshake_progressed => "quic_handshake_progressed",
            .key_updated => "key_updated",
            .packet_sent => "packet_sent",
            .packet_received => "packet_received",
            .packet_lost => "packet_lost",
            .recovery_metrics_updated => "recovery_metrics_updated",
            .packet_dropped => "packet_dropped",
            .path_validation => "quic_path_validation",
            .connection_migrated => "migration_state_updated",
            .stream_reset => "quic_stream_reset",
            .data_blocked => |d| switch (d) {
                .connection => "connection_data_blocked_updated",
                .stream => "stream_data_blocked_updated",
            },
        };
    }
};

/// An `Event` stamped with a monotonic microsecond time. qlog time is emitted
/// in milliseconds (the qlog default `time_units`), derived from `time_us`.
pub const Record = struct {
    time_us: u64,
    event: Event,
};

/// The injected emission seam. Mirrors `recovery.EventSink`: a default value
/// (`.{}`) is a no-op, so wiring qlog is opt-in and free when absent.
///
/// `emit_fn` returns `void` so transport emission stays infallible on the hot
/// path (a lost debug record must never fail a connection). The cost is that a
/// concrete file sink cannot propagate serialization / disk-full / permission
/// errors through this call. The **contract for concrete sinks** is therefore:
/// retain the first write error (and/or count dropped records) and expose it
/// out-of-band, so a truncated trace is detectable rather than silent. See
/// `docs/QUIC_QLOG.md`.
pub const Sink = struct {
    context: ?*anyopaque = null,
    emit_fn: ?*const fn (?*anyopaque, Record) void = null,

    pub fn emit(self: Sink, record: Record) void {
        if (self.emit_fn) |f| f(self.context, record);
    }

    /// Convenience: stamp an event and emit it in one call.
    pub fn log(self: Sink, time_us: u64, event: Event) void {
        self.emit(.{ .time_us = time_us, .event = event });
    }
};

/// JSON-SEQ record separator (RFC 7464 §2.2): each qlog line is 0x1E + JSON.
pub const record_separator: u8 = 0x1e;

/// A bounded, allocation-free JSON accumulator over a caller-owned buffer, in
/// the same spirit as the wire `Writer` in `tls_handshake.zig`.
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

fn boolText(value: bool) []const u8 {
    return if (value) "true" else "false";
}

fn writeJsonString(b: *Buf, value: []const u8) error{NoSpaceLeft}!void {
    try b.add("\"", .{});
    for (value) |c| {
        switch (c) {
            '"' => try b.add("\\\"", .{}),
            '\\' => try b.add("\\\\", .{}),
            0x08 => try b.add("\\b", .{}),
            0x0c => try b.add("\\f", .{}),
            '\n' => try b.add("\\n", .{}),
            '\r' => try b.add("\\r", .{}),
            '\t' => try b.add("\\t", .{}),
            0x00...0x07, 0x0b, 0x0e...0x1f => try b.add("\\u00{x:0>2}", .{c}),
            else => try b.add("{c}", .{c}),
        }
    }
    try b.add("\"", .{});
}

fn writeData(b: *Buf, event: Event) error{NoSpaceLeft}!void {
    switch (event) {
        .connection_started => |d| try b.add(
            "{{\"local\":{{}},\"remote\":{{}},\"tardigrade_odcid_length\":{d},\"tardigrade_scid_length\":{d},\"tardigrade_dcid_length\":{d}}}",
            .{ d.odcid_len, d.scid_len, d.dcid_len },
        ),
        .connection_closed => |d| {
            try b.add("{{\"reason\":\"{s}\"", .{@tagName(d.reason)});
            switch (d.close_error) {
                .none => {},
                .connection_unknown => |code| try b.add(",\"connection_error\":\"unknown\",\"error_code\":{d}", .{code}),
                .application_unknown => |code| try b.add(",\"application_error\":\"unknown\",\"error_code\":{d}", .{code}),
            }
            try b.add("}}", .{});
        },
        .handshake_progressed => |d| try b.add(
            "{{\"stage\":\"{s}\"}}",
            .{@tagName(d.stage)},
        ),
        .key_updated => |d| {
            try b.add("{{\"key_type\":\"{s}\"", .{@tagName(d.key_type)});
            if (d.key_phase) |phase| try b.add(",\"key_phase\":{d}", .{phase});
            if (d.trigger) |trigger| try b.add(",\"trigger\":\"{s}\"", .{@tagName(trigger)});
            try b.add("}}", .{});
        },
        .packet_sent => |d| try b.add(
            "{{\"header\":{{\"packet_type\":\"{s}\",\"packet_number\":{d}}},\"raw\":{{\"length\":{d}}},\"tardigrade_ack_eliciting\":{s}}}",
            .{ d.packet_type.label(), d.packet_number, d.length, boolText(d.ack_eliciting) },
        ),
        .packet_received => |d| try b.add(
            "{{\"header\":{{\"packet_type\":\"{s}\",\"packet_number\":{d}}},\"raw\":{{\"length\":{d}}}}}",
            .{ d.packet_type.label(), d.packet_number, d.length },
        ),
        .packet_lost => |d| {
            try b.add("{{\"header\":{{\"packet_type\":\"{s}\"", .{d.packet_type.label()});
            if (d.packet_number) |pn| try b.add(",\"packet_number\":{d}", .{pn});
            try b.add("}}}}", .{});
        },
        .recovery_metrics_updated => |d| {
            try b.add("{{", .{});
            var need_comma = false;
            if (d.latest_rtt_ms) |v| {
                try b.add("\"latest_rtt\":{d}", .{v});
                need_comma = true;
            }
            if (d.smoothed_rtt_ms) |v| {
                if (need_comma) try b.add(",", .{});
                try b.add("\"smoothed_rtt\":{d}", .{v});
                need_comma = true;
            }
            if (d.rtt_variance_ms) |v| {
                if (need_comma) try b.add(",", .{});
                try b.add("\"rtt_variance\":{d}", .{v});
                need_comma = true;
            }
            if (d.pto_count) |v| {
                if (need_comma) try b.add(",", .{});
                try b.add("\"pto_count\":{d}", .{v});
                need_comma = true;
            }
            if (d.congestion_window) |v| {
                if (need_comma) try b.add(",", .{});
                try b.add("\"congestion_window\":{d}", .{v});
                need_comma = true;
            }
            if (d.bytes_in_flight) |v| {
                if (need_comma) try b.add(",", .{});
                try b.add("\"bytes_in_flight\":{d}", .{v});
            }
            try b.add("}}", .{});
        },
        .packet_dropped => |d| {
            try b.add("{{\"trigger\":\"{s}\"", .{@tagName(d.trigger)});
            if (d.packet_type) |pt| try b.add(",\"header\":{{\"packet_type\":\"{s}\"}}", .{pt.label()});
            try b.add(",\"raw\":{{\"length\":{d}}}}}", .{d.length});
        },
        .path_validation => |d| try b.add(
            "{{\"phase\":\"{s}\",\"path_id\":{d}}}",
            .{ @tagName(d.kind), d.path_id },
        ),
        .connection_migrated => |d| {
            try b.add("{{", .{});
            if (d.old) |old| try b.add("\"old\":\"{s}\",", .{@tagName(old)});
            try b.add("\"new\":\"{s}\"}}", .{@tagName(d.new)});
        },
        .stream_reset => |d| try b.add(
            "{{\"direction\":\"{s}\",\"stream_id\":{d},\"error_code\":{d}}}",
            .{ @tagName(d.kind), d.stream_id, d.error_code },
        ),
        .data_blocked => |d| switch (d) {
            .connection => |blocked| {
                try b.add("{{", .{});
                var need_comma = false;
                if (blocked.old) |old| {
                    try b.add("\"old\":\"{s}\"", .{@tagName(old)});
                    need_comma = true;
                }
                if (need_comma) try b.add(",", .{});
                try b.add("\"new\":\"{s}\"", .{@tagName(blocked.new)});
                if (blocked.reason) |reason| try b.add(",\"reason\":\"{s}\"", .{@tagName(reason)});
                try b.add("}}", .{});
            },
            .stream => |blocked| {
                try b.add("{{\"stream_id\":{d}", .{blocked.stream_id});
                if (blocked.old) |old| try b.add(",\"old\":\"{s}\"", .{@tagName(old)});
                try b.add(",\"new\":\"{s}\"", .{@tagName(blocked.new)});
                if (blocked.reason) |reason| try b.add(",\"reason\":\"{s}\"", .{@tagName(reason)});
                try b.add("}}", .{});
            },
        },
    }
}

/// qlog vantage point: which endpoint recorded the trace (RFC 9000 roles).
pub const VantagePoint = enum { client, server };

/// The once-per-file qlog trace header. Only the composition root can fill this
/// in: `group_id` (the original DCID, as lowercase hex, tying every event to
/// one connection) and the `reference_time` baseline span both packages, so the
/// root — not the transport — owns it. `title` and `group_id` must be JSON-safe
/// (ASCII / hex); they are emitted verbatim without escaping.
pub const TraceHeader = struct {
    vantage_point: VantagePoint,
    group_id: []const u8 = "",
    title: []const u8 = "tardigrade-quic",
    description: []const u8 = "Tardigrade QUIC/HTTP-3 debug trace",
};

/// Serialize the qlog file header as the first JSON-SEQ record. A composition
/// root writes this once, then appends `writeJson` event records (from both
/// `quic` and `http3`) to form a complete `.sqlog` file qvis can consume.
/// Returns the written slice; a 512-byte buffer is enough.
pub fn writeTraceHeader(header: TraceHeader, out: []u8) error{NoSpaceLeft}![]const u8 {
    var b = Buf{ .buf = out };
    try b.add("{c}", .{record_separator});
    try b.add("{{\"file_schema\":\"{s}\",\"serialization_format\":\"{s}\",\"title\":", .{ file_schema_uri, serialization_format });
    try writeJsonString(&b, header.title);
    try b.add(",\"description\":", .{});
    try writeJsonString(&b, header.description);
    try b.add(",\"trace\":{{\"common_fields\":{{\"group_id\":", .{});
    try writeJsonString(&b, header.group_id);
    try b.add(",\"time_format\":\"relative_to_epoch\",\"reference_time\":{{\"clock_type\":\"monotonic\",\"epoch\":\"unknown\"}}}},\"vantage_point\":{{\"type\":\"{s}\"}},\"event_schemas\":[\"{s}\",\"{s}\",\"{s}\"]}}}}\n", .{ @tagName(header.vantage_point), quic_event_schema_uri, http3_event_schema_uri, tardigrade_event_schema_uri });
    return b.slice();
}

/// Serialize one `Record` into `out` as a single qlog JSON-SEQ line:
///
///     0x1E {"time":<ms>,"name":"<namespace>:<event>","data":{...}} \n
///
/// Returns the written slice. Errors only if `out` is too small; a 512-byte
/// buffer is comfortably enough for every event above.
pub fn writeJson(record: Record, out: []u8) error{NoSpaceLeft}![]const u8 {
    var b = Buf{ .buf = out };
    try b.add("{c}", .{record_separator});
    // qlog default time unit is milliseconds; keep microsecond precision.
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
    var buf: [512]u8 = undefined;
    const line = try writeJson(record, &buf);
    try testing.expect(line[0] == record_separator);
    try testing.expect(line[line.len - 1] == '\n');
    try testing.expect(std.mem.indexOf(u8, line, needle) != null);
}

test "namespace and name mapping stays aligned with qlog vantage points" {
    try testing.expectEqual(Namespace.quic, (Event{ .packet_sent = .{ .packet_type = .one_rtt, .packet_number = 0, .length = 0 } }).namespace());
    try testing.expectEqual(Namespace.quic, (Event{ .packet_lost = .{ .packet_type = .one_rtt } }).namespace());
    try testing.expectEqual(Namespace.quic, (Event{ .key_updated = .{ .key_type = .server_1rtt_secret, .key_phase = 1 } }).namespace());
    try testing.expectEqual(Namespace.quic, (Event{ .connection_migrated = .{ .new = .migration_complete } }).namespace());
    try testing.expectEqual(Namespace.tardigrade, (Event{ .stream_reset = .{ .kind = .reset_sent, .stream_id = 0 } }).namespace());
    try testing.expectEqualStrings("packet_dropped", (Event{ .packet_dropped = .{ .trigger = .decryption_failure } }).name());
}

test "packet_sent serializes to a quic JSON-SEQ line" {
    try expectJson(
        .{ .time_us = 1_234_567, .event = .{ .packet_sent = .{ .packet_type = .initial, .packet_number = 7, .length = 1200, .ack_eliciting = true } } },
        "\"name\":\"quic:packet_sent\"",
    );
    try expectJson(
        .{ .time_us = 1_234_567, .event = .{ .packet_sent = .{ .packet_type = .one_rtt, .packet_number = 7, .length = 1200 } } },
        "\"packet_type\":\"1RTT\"",
    );
}

test "deprotection failure is a packet_dropped with decryption_failure" {
    try expectJson(
        .{ .time_us = 0, .event = .{ .packet_dropped = .{ .packet_type = .one_rtt, .trigger = .decryption_failure, .length = 42 } } },
        "\"trigger\":\"decryption_failure\"",
    );
}

test "0-RTT key type serializes as a standard key_updated value" {
    try expectJson(
        .{ .time_us = 0, .event = .{ .key_updated = .{ .key_type = .server_0rtt_secret } } },
        "\"key_type\":\"server_0rtt_secret\"",
    );
}

test "connection_closed ties error_code to an unknown error category" {
    try expectJson(
        .{ .time_us = 0, .event = .{ .connection_closed = .{ .reason = .transport_error, .close_error = .{ .connection_unknown = 0x123 } } } },
        "\"connection_error\":\"unknown\",\"error_code\":291",
    );
    try expectJson(
        .{ .time_us = 0, .event = .{ .connection_closed = .{ .reason = .application_close, .close_error = .{ .application_unknown = 0x456 } } } },
        "\"application_error\":\"unknown\",\"error_code\":1110",
    );
}

test "trace header escapes free-form text fields" {
    var buf: [1024]u8 = undefined;
    const header = try writeTraceHeader(.{
        .vantage_point = .server,
        .group_id = "0011deadbeef",
        .title = "test \"trace\"",
        .description = "debug \\ trace\nnext",
    }, &buf);
    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, header[1 .. header.len - 1], .{});
    defer parsed.deinit();
    const root = parsed.value.object;
    try testing.expectEqualStrings("test \"trace\"", root.get("title").?.string);
    try testing.expectEqualStrings("debug \\ trace\nnext", root.get("description").?.string);
}

test "time is rendered in milliseconds with microsecond precision" {
    var buf: [512]u8 = undefined;
    const line = try writeJson(.{ .time_us = 1_002_003, .event = .{ .key_updated = .{ .key_type = .server_1rtt_secret, .key_phase = 1 } } }, &buf);
    try testing.expect(std.mem.indexOf(u8, line, "\"time\":1002.003") != null);
}

test "path, migration, stream reset and flow-control events serialize" {
    try expectJson(.{ .time_us = 5, .event = .{ .path_validation = .{ .kind = .response_received } } }, "\"phase\":\"response_received\"");
    try expectJson(.{ .time_us = 5, .event = .{ .connection_migrated = .{ .old = .migration_started, .new = .migration_complete } } }, "migration_state_updated");
    try expectJson(.{ .time_us = 5, .event = .{ .stream_reset = .{ .kind = .reset_received, .stream_id = 4, .error_code = 9 } } }, "\"stream_id\":4");
    try expectJson(.{ .time_us = 5, .event = .{ .data_blocked = .{ .stream = .{ .stream_id = 8, .new = .blocked, .reason = .stream_flow_control } } } }, "\"name\":\"quic:stream_data_blocked_updated\"");
    try expectJson(.{ .time_us = 5, .event = .{ .data_blocked = .{ .connection = .{ .new = .blocked, .reason = .connection_flow_control } } } }, "\"name\":\"quic:connection_data_blocked_updated\"");
}

test "recovery metrics serialize as a quic event" {
    try expectJson(
        .{ .time_us = 5, .event = .{ .recovery_metrics_updated = .{ .congestion_window = 12_000, .bytes_in_flight = 1_200, .pto_count = 2 } } },
        "\"name\":\"quic:recovery_metrics_updated\"",
    );
    try expectJson(
        .{ .time_us = 5, .event = .{ .recovery_metrics_updated = .{ .congestion_window = 12_000, .bytes_in_flight = 1_200, .pto_count = 2 } } },
        "\"bytes_in_flight\":1200",
    );
}

test "trace header then event forms a two-record JSON-SEQ stream" {
    var buf: [1024]u8 = undefined;
    const header = try writeTraceHeader(.{ .vantage_point = .server, .group_id = "0011deadbeef" }, &buf);
    const event = try writeJson(.{ .time_us = 2_500, .event = .{ .packet_sent = .{ .packet_type = .initial, .packet_number = 0, .length = 1200 } } }, buf[header.len..]);
    // Exactly two record separators, one per record.
    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, buf[0 .. header.len + event.len], &[_]u8{record_separator}));
    try testing.expect(std.mem.indexOf(u8, header, "\"file_schema\":\"urn:ietf:params:qlog:file:sequential\"") != null);
    try testing.expect(std.mem.indexOf(u8, header, "\"serialization_format\":\"application/qlog+json-seq\"") != null);
    try testing.expect(std.mem.indexOf(u8, header, "\"reference_time\":{\"clock_type\":\"monotonic\",\"epoch\":\"unknown\"}") != null);
    try testing.expect(std.mem.indexOf(u8, header, "\"event_schemas\":[\"urn:ietf:params:qlog:events:quic-13\",\"urn:ietf:params:qlog:events:http3-13\"") != null);
    try testing.expect(std.mem.indexOf(u8, header, "\"vantage_point\":{\"type\":\"server\"}") != null);
    try testing.expect(std.mem.indexOf(u8, header, "\"group_id\":\"0011deadbeef\"") != null);
    try testing.expect(std.mem.indexOf(u8, event, "quic:packet_sent") != null);
}

test "default sink is a no-op and log() stamps time" {
    const Collector = struct {
        var last: ?Record = null;
        fn emit(_: ?*anyopaque, record: Record) void {
            last = record;
        }
    };
    const noop = Sink{};
    noop.log(1, .{ .key_updated = .{ .key_type = .client_1rtt_secret, .key_phase = 0 } }); // must not crash

    Collector.last = null;
    const sink = Sink{ .emit_fn = Collector.emit };
    sink.log(99, .{ .connection_closed = .{ .reason = .idle_timeout } });
    try testing.expect(Collector.last != null);
    try testing.expectEqual(@as(u64, 99), Collector.last.?.time_us);
}

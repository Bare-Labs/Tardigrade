//! QUIC key-log compatibility wrapper.
//!
//! New transport-neutral key logging lives in `tls_core.keylog`. This module
//! preserves the pre-shared-TLS QUIC API exported through `quic.keylog`.

const std = @import("std");
const tls = @import("tls_adapter.zig");
const shared = @import("tls_core").keylog;

pub const client_random_len = shared.client_random_len;
pub const Context = shared.Context;
pub const Endpoint = shared.Endpoint;
pub const SharedEntry = shared.Entry;
pub const SharedLabel = shared.Label;
pub const SharedSink = shared.Sink;
pub const sharedLabelFor = shared.labelFor;
pub const writeSharedLine = shared.writeLine;

pub const Label = enum {
    client_early_traffic_secret,
    client_handshake_traffic_secret,
    server_handshake_traffic_secret,
    client_traffic_secret_0,
    server_traffic_secret_0,

    pub fn text(self: Label) []const u8 {
        return switch (self) {
            .client_early_traffic_secret => "CLIENT_EARLY_TRAFFIC_SECRET",
            .client_handshake_traffic_secret => "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
            .server_handshake_traffic_secret => "SERVER_HANDSHAKE_TRAFFIC_SECRET",
            .client_traffic_secret_0 => "CLIENT_TRAFFIC_SECRET_0",
            .server_traffic_secret_0 => "SERVER_TRAFFIC_SECRET_0",
        };
    }

    fn toShared(self: Label) shared.Label {
        return switch (self) {
            .client_early_traffic_secret => .{ .endpoint = .client, .epoch = .early },
            .client_handshake_traffic_secret => .{ .endpoint = .client, .epoch = .handshake },
            .server_handshake_traffic_secret => .{ .endpoint = .server, .epoch = .handshake },
            .client_traffic_secret_0 => .{ .endpoint = .client, .epoch = .application, .generation = 0 },
            .server_traffic_secret_0 => .{ .endpoint = .server, .epoch = .application, .generation = 0 },
        };
    }
};

pub fn labelFor(
    perspective: tls.Perspective,
    direction: tls.Direction,
    level: tls.EncryptionLevel,
) ?Label {
    const is_client_secret = switch (direction) {
        .write => perspective == .client,
        .read => perspective == .server,
    };
    return switch (level) {
        .initial => null,
        .zero_rtt => if (is_client_secret) .client_early_traffic_secret else null,
        .handshake => if (is_client_secret) .client_handshake_traffic_secret else .server_handshake_traffic_secret,
        .application => if (is_client_secret) .client_traffic_secret_0 else .server_traffic_secret_0,
    };
}

pub const Entry = struct {
    label: Label,
    client_random: []const u8,
    secret: []const u8,
};

pub const Sink = struct {
    context: ?*anyopaque = null,
    emit_fn: ?*const fn (?*anyopaque, Entry) void = null,

    pub fn emit(self: Sink, entry: Entry) void {
        if (self.emit_fn) |f| f(self.context, entry);
    }
};

pub fn writeLine(entry: Entry, out: []u8) error{ InvalidClientRandom, EmptySecret, NoSpaceLeft }![]const u8 {
    return shared.writeLine(.{
        .label = entry.label.toShared(),
        .client_random = entry.client_random,
        .secret = entry.secret,
    }, out);
}

const testing = std.testing;

test "legacy labelFor preserves generation-zero QUIC API" {
    try testing.expectEqual(Label.client_handshake_traffic_secret, labelFor(.client, .write, .handshake).?);
    try testing.expectEqual(Label.server_traffic_secret_0, labelFor(.server, .write, .application).?);
    try testing.expectEqual(Label.client_early_traffic_secret, labelFor(.client, .write, .zero_rtt).?);
    try testing.expectEqual(@as(?Label, null), labelFor(.server, .write, .zero_rtt));
}

test "legacy writeLine accepts legacy labels" {
    const random = [_]u8{0xab} ** client_random_len;
    const secret = [_]u8{ 0x00, 0x0f, 0xff };
    var buf: [256]u8 = undefined;
    const line = try writeLine(.{ .label = .client_traffic_secret_0, .client_random = &random, .secret = &secret }, &buf);
    try testing.expect(std.mem.startsWith(u8, line, "CLIENT_TRAFFIC_SECRET_0 "));
    try testing.expect(std.mem.endsWith(u8, line, " 000fff\n"));
}

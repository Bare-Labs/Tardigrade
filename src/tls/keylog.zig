//! TLS 1.3 NSS key-log support (#255).
//!
//! This module is transport-neutral: QUIC and future record-mode TLS both use
//! the same labels and line formatter, while callers own file handling and the
//! explicit debug-only enablement policy.

const std = @import("std");

const events = @import("events.zig");
const state = @import("state.zig");

pub const client_random_len = 32;

pub const Endpoint = enum { client, server };

pub const Label = struct {
    endpoint: Endpoint,
    epoch: enum { early, handshake, application },
    generation: u64 = 0,

    pub fn write(self: Label, out: []u8) error{NoSpaceLeft}![]const u8 {
        const side = switch (self.endpoint) {
            .client => "CLIENT",
            .server => "SERVER",
        };
        return switch (self.epoch) {
            .early => std.fmt.bufPrint(out, "{s}_EARLY_TRAFFIC_SECRET", .{side}),
            .handshake => std.fmt.bufPrint(out, "{s}_HANDSHAKE_TRAFFIC_SECRET", .{side}),
            .application => std.fmt.bufPrint(out, "{s}_TRAFFIC_SECRET_{d}", .{ side, self.generation }),
        } catch error.NoSpaceLeft;
    }
};

pub fn labelFor(
    role: state.Role,
    direction: events.SecretDirection,
    epoch: events.EncryptionEpoch,
    application_generation: u64,
) ?Label {
    const endpoint: Endpoint = switch (direction) {
        .write => if (role == .client) .client else .server,
        .read => if (role == .client) .server else .client,
    };
    return switch (epoch) {
        .initial => null,
        .zero_rtt => if (endpoint == .client) .{ .endpoint = .client, .epoch = .early } else null,
        .handshake => .{ .endpoint = endpoint, .epoch = .handshake },
        .application => .{ .endpoint = endpoint, .epoch = .application, .generation = application_generation },
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

pub const Context = struct {
    enabled: bool = false,
    role: state.Role = .server,
    client_random: [client_random_len]u8 = [_]u8{0} ** client_random_len,
    has_client_random: bool = false,
    sink: Sink = .{},
    read_application_generation: u64 = 0,
    write_application_generation: u64 = 0,

    pub fn setClientRandom(self: *Context, random: []const u8) error{InvalidClientRandom}!void {
        if (random.len != client_random_len) return error.InvalidClientRandom;
        @memcpy(&self.client_random, random);
        self.has_client_random = true;
    }

    pub fn emitSecret(self: *Context, epoch: events.EncryptionEpoch, direction: events.SecretDirection, secret: []const u8) void {
        if (!self.enabled) return;
        if (!self.has_client_random) return;
        const generation = switch (direction) {
            .read => self.read_application_generation,
            .write => self.write_application_generation,
        };
        const label = labelFor(self.role, direction, epoch, generation) orelse return;
        self.sink.emit(.{ .label = label, .client_random = &self.client_random, .secret = secret });
    }

    pub fn noteKeyUpdate(self: *Context, direction: events.SecretDirection) void {
        switch (direction) {
            .read => self.read_application_generation += 1,
            .write => self.write_application_generation += 1,
        }
    }
};

pub fn writeLine(entry: Entry, out: []u8) error{ InvalidClientRandom, EmptySecret, NoSpaceLeft }![]const u8 {
    if (entry.client_random.len != client_random_len) return error.InvalidClientRandom;
    if (entry.secret.len == 0) return error.EmptySecret;
    var label_buf: [64]u8 = undefined;
    const label = try entry.label.write(&label_buf);
    const needed = label.len + 1 + entry.client_random.len * 2 + 1 + entry.secret.len * 2 + 1;
    if (out.len < needed) return error.NoSpaceLeft;

    var i: usize = 0;
    @memcpy(out[i..][0..label.len], label);
    i += label.len;
    out[i] = ' ';
    i += 1;
    i += writeHex(entry.client_random, out[i..]);
    out[i] = ' ';
    i += 1;
    i += writeHex(entry.secret, out[i..]);
    out[i] = '\n';
    i += 1;
    return out[0..i];
}

fn writeHex(bytes: []const u8, out: []u8) usize {
    const hex = "0123456789abcdef";
    for (bytes, 0..) |b, idx| {
        out[idx * 2] = hex[b >> 4];
        out[idx * 2 + 1] = hex[b & 0x0f];
    }
    return bytes.len * 2;
}

const testing = std.testing;

test "labelFor maps role, direction, epoch, and generation" {
    try testing.expectEqual(@as(?Label, null), labelFor(.client, .write, .initial, 0));
    try testing.expectEqual(Label{ .endpoint = .client, .epoch = .early }, labelFor(.client, .write, .zero_rtt, 0).?);
    try testing.expectEqual(@as(?Label, null), labelFor(.server, .write, .zero_rtt, 0));
    try testing.expectEqual(Label{ .endpoint = .client, .epoch = .handshake }, labelFor(.server, .read, .handshake, 0).?);
    try testing.expectEqual(Label{ .endpoint = .server, .epoch = .application, .generation = 2 }, labelFor(.client, .read, .application, 2).?);
}

test "writeLine emits NSS-compatible labels including KeyUpdate generations" {
    const random = [_]u8{0xab} ** client_random_len;
    const secret = [_]u8{ 0x00, 0x0f, 0xff };
    var buf: [256]u8 = undefined;
    const line = try writeLine(.{
        .label = .{ .endpoint = .server, .epoch = .application, .generation = 3 },
        .client_random = &random,
        .secret = &secret,
    }, &buf);
    try testing.expect(std.mem.startsWith(u8, line, "SERVER_TRAFFIC_SECRET_3 "));
    try testing.expect(std.mem.endsWith(u8, line, " 000fff\n"));
}

test "writeLine validates client random and secret" {
    var buf: [256]u8 = undefined;
    try testing.expectError(error.InvalidClientRandom, writeLine(.{
        .label = .{ .endpoint = .client, .epoch = .handshake },
        .client_random = &[_]u8{0} ** (client_random_len - 1),
        .secret = &[_]u8{1},
    }, &buf));
    try testing.expectError(error.EmptySecret, writeLine(.{
        .label = .{ .endpoint = .client, .epoch = .handshake },
        .client_random = &[_]u8{0} ** client_random_len,
        .secret = &[_]u8{},
    }, &buf));
}

test "context disabled and missing random emit nothing" {
    const Capture = struct {
        count: usize = 0,
        fn emit(ctx: ?*anyopaque, _: Entry) void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            self.count += 1;
        }
    };
    var capture = Capture{};
    var ctx = Context{ .sink = .{ .context = &capture, .emit_fn = Capture.emit } };
    ctx.emitSecret(.handshake, .write, &[_]u8{1});
    try testing.expectEqual(@as(usize, 0), capture.count);

    ctx.enabled = true;
    ctx.emitSecret(.handshake, .write, &[_]u8{1});
    try testing.expectEqual(@as(usize, 0), capture.count);
}

test "context emits before caller resets or wipes event payloads" {
    const Capture = struct {
        count: usize = 0,
        label: ?Label = null,
        secret: [48]u8 = [_]u8{0} ** 48,
        secret_len: usize = 0,
        fn emit(ctx: ?*anyopaque, entry: Entry) void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            self.count += 1;
            self.label = entry.label;
            self.secret_len = entry.secret.len;
            @memcpy(self.secret[0..entry.secret.len], entry.secret);
        }
    };
    const random = [_]u8{0xcd} ** client_random_len;
    const secret = [_]u8{0x42} ** 48;
    var capture = Capture{};
    var ctx = Context{
        .enabled = true,
        .role = .server,
        .sink = .{ .context = &capture, .emit_fn = Capture.emit },
    };
    try ctx.setClientRandom(&random);
    ctx.noteKeyUpdate(.write);
    ctx.emitSecret(.application, .write, &secret);
    try testing.expectEqual(@as(usize, 1), capture.count);
    try testing.expectEqual(Label{ .endpoint = .server, .epoch = .application, .generation = 1 }, capture.label.?);
    try testing.expectEqualSlices(u8, &secret, capture.secret[0..capture.secret_len]);
}

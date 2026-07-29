//! Gateway-facing HTTP/3 helpers that sit above the native runtime
//! (`http3_runtime.zig`): Alt-Svc advertisement and the configuration status
//! string surfaced by the status API.

const std = @import("std");

pub const AltSvcMode = enum {
    off,
    auto,

    pub fn parse(value: []const u8) ?AltSvcMode {
        if (std.ascii.eqlIgnoreCase(value, "off")) return .off;
        if (std.ascii.eqlIgnoreCase(value, "auto")) return .auto;
        return null;
    }
};

pub const Advertisement = union(enum) {
    disabled,
    clear,
    active: struct {
        port: u16,
        max_age_seconds: u32,
    },
};

pub fn formatAltSvc(allocator: std.mem.Allocator, https_port: u16, max_age_seconds: u32) ![]u8 {
    return std.fmt.allocPrint(allocator, "h3=\":{d}\"; ma={d}", .{ https_port, max_age_seconds });
}

pub fn formatAdvertisement(allocator: std.mem.Allocator, advertisement: Advertisement) !?[]u8 {
    return switch (advertisement) {
        .disabled => null,
        .clear => try allocator.dupe(u8, "clear"),
        .active => |active| try formatAltSvc(allocator, active.port, active.max_age_seconds),
    };
}

pub fn configurationStatus(http3_enabled: bool, tls_ready: bool) []const u8 {
    if (!http3_enabled) return "disabled";
    if (!tls_ready) return "config_incomplete";
    return "configured";
}

test "http3 handler alt-svc formatting" {
    const value = try formatAltSvc(std.testing.allocator, 443, 300);
    defer std.testing.allocator.free(value);
    try std.testing.expectEqualStrings("h3=\":443\"; ma=300", value);
}

test "http3 handler formats advertisement states" {
    const disabled = try formatAdvertisement(std.testing.allocator, .disabled);
    try std.testing.expectEqual(@as(?[]u8, null), disabled);

    const clear = try formatAdvertisement(std.testing.allocator, .clear);
    defer std.testing.allocator.free(clear.?);
    try std.testing.expectEqualStrings("clear", clear.?);

    const active = try formatAdvertisement(std.testing.allocator, .{ .active = .{ .port = 8443, .max_age_seconds = 60 } });
    defer std.testing.allocator.free(active.?);
    try std.testing.expectEqualStrings("h3=\":8443\"; ma=60", active.?);
}

test "http3 handler configuration status reports expected states" {
    try std.testing.expectEqualStrings("disabled", configurationStatus(false, false));
    try std.testing.expectEqualStrings("config_incomplete", configurationStatus(true, false));
    try std.testing.expectEqualStrings("configured", configurationStatus(true, true));
}

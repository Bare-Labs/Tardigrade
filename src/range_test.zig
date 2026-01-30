const std = @import("std");

test "parseRangeHeader simple start-end" {
    const main = @import("main.zig");
    const r = main.parseRangeHeader("bytes=0-9", 100) orelse unreachable;
    try std.testing.expectEqual(@as(usize, 0), r.start);
    try std.testing.expectEqual(@as(usize, 9), r.end);
}

test "parseRangeHeader start-" {
    const main = @import("main.zig");
    const r = main.parseRangeHeader("bytes=10-", 100) orelse unreachable;
    try std.testing.expectEqual(@as(usize, 10), r.start);
    try std.testing.expectEqual(@as(usize, 99), r.end);
}

test "parseRangeHeader -suffix" {
    const main = @import("main.zig");
    const r = main.parseRangeHeader("bytes=-5", 100) orelse unreachable;
    try std.testing.expectEqual(@as(usize, 95), r.start);
    try std.testing.expectEqual(@as(usize, 99), r.end);
}

test "parseRangeHeader unsatisfiable" {
    const main = @import("main.zig");
    const r = main.parseRangeHeader("bytes=1000-2000", 100);
    try std.testing.expect(r == null);
}

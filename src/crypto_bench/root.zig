//! Entry point for the CryptoProvider/record/ticket-protection benchmark
//! suite (#378, epic #327-I). `zig build bench-crypto` runs this as an
//! executable and prints a JSON report; `zig build test-crypto-bench` runs
//! the same suites at a tiny iteration count as a fast correctness smoke
//! check (not a timing signal) that is safe under the default `zig build
//! test`.
//!
//! Deliberately out of scope, per the issue's own ownership boundaries:
//! QUIC packet-protection/header-protection benchmarks (blocked on #490
//! reconciling provider ownership) and an OpenSSL reference comparison
//! (optional — "where a fair independent comparison is stable and useful").
//! See docs/CRYPTO_BENCHMARKS.md.

const std = @import("std");
const compat = @import("zig_compat");
const harness = @import("harness.zig");
const primitives = @import("primitives.zig");
const record = @import("record.zig");
const ticket = @import("ticket.zig");

pub const Scale = harness.Scale;
pub const Measurement = harness.Measurement;

/// Advisory latency ceilings for a handful of "core repeated workloads"
/// (issue #378's "budgets" section). Deliberately generous — see
/// `harness.checkLatencyBudgets`'s doc comment for why these never fail the
/// build.
const latency_budgets = [_]harness.LatencyBudget{
    .{ .suite = "aead", .name = "seal", .max_ns_per_op = 50_000 },
    .{ .suite = "kex", .name = "derive_shared_secret", .max_ns_per_op = 2_000_000 },
    .{ .suite = "signature", .name = "verify", .max_ns_per_op = 5_000_000 },
    .{ .suite = "ticket", .name = "seal", .max_ns_per_op = 200_000 },
    .{ .suite = "ticket", .name = "resolve", .max_ns_per_op = 200_000 },
};

pub fn collect(allocator: std.mem.Allocator, scale: Scale) !harness.Reporter {
    var reporter = harness.Reporter{ .allocator = allocator };
    errdefer reporter.deinit();
    try primitives.run(allocator, &reporter, scale);
    try record.run(&reporter, scale);
    try ticket.run(allocator, &reporter, scale);
    return reporter;
}

pub fn main() !void {
    var debug: std.heap.DebugAllocator(.{}) = .init;
    defer std.debug.assert(debug.deinit() == .ok);
    const allocator = debug.allocator();

    var reporter = try collect(allocator, .full);
    defer reporter.deinit();

    harness.checkLatencyBudgets(reporter.items(), &latency_budgets);

    var stdout_buf: [8192]u8 = undefined;
    var stdout = std.Io.File.stdout().writer(compat.io(), &stdout_buf);
    try harness.writeJsonReport(&stdout.interface, harness.Metadata.current(), reporter.items());
    try stdout.flush();
}

test "crypto-bench: every workload runs and reports at least one measurement" {
    var reporter = try collect(std.testing.allocator, .smoke);
    defer reporter.deinit();
    try std.testing.expect(reporter.items().len > 0);
    for (reporter.items()) |m| {
        try std.testing.expect(m.iterations > 0);
    }
}

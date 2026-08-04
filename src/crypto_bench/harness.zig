//! Shared measurement/report plumbing for the CryptoProvider benchmark suite
//! (#378, epic #327-I). Every suite (`primitives.zig`, `record.zig`,
//! `ticket.zig`) times its own workloads with `monotonicNs` and reports
//! through the `Measurement`/`Report` types here so `root.zig` can print one
//! consistent JSON document regardless of which suite produced a result.

const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const compat = @import("zig_compat");

/// Zig 0.16 removed `std.time.Timer`; `std.Io.Clock.awake` is this
/// toolchain's monotonic (not wall-clock/NTP-adjustable) clock, matching
/// what `Timer` used to wrap. See the `Clock.awake` doc comment in
/// `std.Io` and `zig_compat.sleepNs`'s identical choice.
pub fn monotonicNs() i96 {
    return std.Io.Clock.awake.now(compat.io()).toNanoseconds();
}

/// How hard each suite should push. `smoke` runs a handful of iterations so
/// `zig build test-crypto-bench` finishes in well under a second per
/// workload and is safe to run under the default `zig build test` — it
/// exists to catch crashes/panics/API drift, not to produce trustworthy
/// timings. `full` runs enough iterations for the printed ns/op to be
/// meaningful and is what `zig build bench-crypto` uses.
pub const Scale = enum {
    smoke,
    full,

    pub fn iterations(self: Scale, full_iterations: usize) usize {
        return switch (self) {
            .smoke => @min(full_iterations, 5),
            .full => full_iterations,
        };
    }
};

/// A minimal allocation counter, wrapping a child allocator to report how
/// many allocations and bytes a workload performed. Only wired around calls
/// that take an `std.mem.Allocator` in the first place — the `CryptoProvider`
/// vtable (HKDF, AEAD, key exchange, verify) never does, so those workloads
/// are allocation-free by construction rather than by runtime measurement
/// (see `primitives.assertProviderVtableIsAllocatorFree` in primitives.zig).
pub const CountingAllocator = struct {
    child: std.mem.Allocator,
    allocations: usize = 0,
    frees: usize = 0,
    bytes_allocated: usize = 0,

    pub fn init(child: std.mem.Allocator) CountingAllocator {
        return .{ .child = child };
    }

    pub fn allocator(self: *CountingAllocator) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        const ptr = self.child.rawAlloc(len, alignment, ret_addr) orelse return null;
        self.allocations += 1;
        self.bytes_allocated += len;
        return ptr;
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        return self.child.rawResize(memory, alignment, new_len, ret_addr);
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        return self.child.rawRemap(memory, alignment, new_len, ret_addr);
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        self.frees += 1;
        self.child.rawFree(memory, alignment, ret_addr);
    }

    const vtable = std.mem.Allocator.VTable{
        .alloc = alloc,
        .resize = resize,
        .remap = remap,
        .free = free,
    };
};

/// One benchmarked workload's result. `suite` groups related workloads in
/// the report (`hash`, `hkdf`, `aead`, `kex`, `signature`, `secret`,
/// `record`, `ticket`); `name` identifies the specific workload within it.
pub const Measurement = struct {
    suite: []const u8,
    name: []const u8,
    algorithm: []const u8 = "",
    input_bytes: usize = 0,
    iterations: usize,
    ns_total: u64,
    allocations_per_op: f64 = 0,
    bytes_allocated_per_op: f64 = 0,
    note: []const u8 = "",

    pub fn nsPerOp(self: Measurement) f64 {
        return @as(f64, @floatFromInt(self.ns_total)) / @as(f64, @floatFromInt(self.iterations));
    }

    pub fn opsPerSec(self: Measurement) f64 {
        const ns_per_op = self.nsPerOp();
        if (ns_per_op <= 0) return 0;
        return 1_000_000_000.0 / ns_per_op;
    }
};

/// Times `iterations` calls to `step(context)`, discarding no work: callers
/// are responsible for making sure the loop body cannot be optimised away
/// (e.g. by folding a byte of real output into a `std.mem.doNotOptimizeAway`
/// call), matching the pattern every workload in `primitives.zig`/
/// `record.zig`/`ticket.zig` follows.
pub fn timeLoop(
    comptime Context: type,
    context: *Context,
    iterations: usize,
    comptime step: fn (*Context) anyerror!void,
) !u64 {
    var i: usize = 0;
    while (i < iterations) : (i += 1) try step(context);
    const start = monotonicNs();
    i = 0;
    while (i < iterations) : (i += 1) try step(context);
    const end = monotonicNs();
    return @intCast(end - start);
}

/// Environment metadata every benchmark result must be comparable against
/// (issue #378's "benchmark contract"): Tardigrade commit and version, Zig
/// version, OS/architecture, build mode, and provider kind. Deliberately
/// excludes anything from the workloads themselves (keys, nonces, ticket
/// identities) — only static build/environment facts belong here.
///
/// `tardigrade_commit` is the exact source revision (`build.zig`'s
/// `gitCommitSha`, embedded via `-Dcommit` / `git rev-parse HEAD`, or
/// `"unknown"` for a non-git source tree) — distinct from
/// `tardigrade_version`, which names a release and is not unique per
/// commit, so two builds sharing a version string still produce
/// distinguishable, attributable benchmark artifacts.
pub const Metadata = struct {
    tardigrade_version: []const u8,
    tardigrade_commit: []const u8,
    zig_version: []const u8,
    os: []const u8,
    arch: []const u8,
    optimize_mode: []const u8,
    provider_kind: []const u8,

    pub fn current() Metadata {
        return .{
            .tardigrade_version = build_options.version,
            .tardigrade_commit = build_options.commit,
            .zig_version = builtin.zig_version_string,
            .os = @tagName(builtin.os.tag),
            .arch = @tagName(builtin.cpu.arch),
            .optimize_mode = @tagName(builtin.mode),
            .provider_kind = "pure_zig",
        };
    }
};

/// Owns the growing measurement list so every suite function can just call
/// `out.append(.{...})` without threading an `std.mem.Allocator` parameter
/// through every workload function purely to satisfy Zig 0.16's unmanaged
/// `std.ArrayList.append(allocator, value)` signature.
pub const Reporter = struct {
    allocator: std.mem.Allocator,
    list: std.ArrayList(Measurement) = .empty,

    pub fn append(self: *Reporter, measurement: Measurement) !void {
        try self.list.append(self.allocator, measurement);
    }

    pub fn items(self: *const Reporter) []const Measurement {
        return self.list.items;
    }

    pub fn deinit(self: *Reporter) void {
        self.list.deinit(self.allocator);
    }
};

pub fn writeJsonReport(writer: anytype, metadata: Metadata, measurements: []const Measurement) !void {
    try writer.print(
        "{{\n  \"_meta\": {{\"benchmark\":\"crypto-provider\",\"tardigrade_version\":\"{s}\",\"tardigrade_commit\":\"{s}\",\"zig_version\":\"{s}\",\"os\":\"{s}\",\"arch\":\"{s}\",\"optimize_mode\":\"{s}\",\"provider_kind\":\"{s}\"}},\n  \"measurements\": [\n",
        .{
            metadata.tardigrade_version,
            metadata.tardigrade_commit,
            metadata.zig_version,
            metadata.os,
            metadata.arch,
            metadata.optimize_mode,
            metadata.provider_kind,
        },
    );
    for (measurements, 0..) |m, i| {
        try writer.print(
            "    {{\"suite\":\"{s}\",\"name\":\"{s}\",\"algorithm\":\"{s}\",\"input_bytes\":{d},\"iterations\":{d},\"ns_total\":{d},\"ns_per_op\":{d:.1},\"ops_per_sec\":{d:.1},\"allocations_per_op\":{d:.2},\"bytes_allocated_per_op\":{d:.2},\"note\":\"{s}\"}}",
            .{
                m.suite,
                m.name,
                m.algorithm,
                m.input_bytes,
                m.iterations,
                m.ns_total,
                m.nsPerOp(),
                m.opsPerSec(),
                m.allocations_per_op,
                m.bytes_allocated_per_op,
                m.note,
            },
        );
        try writer.writeAll(if (i + 1 < measurements.len) ",\n" else "\n");
    }
    try writer.writeAll("  ]\n}\n");
}

/// Advisory latency ceiling for one of the "core repeated workloads" issue
/// #378 asks for a regression budget on. These are deliberately generous —
/// meant to catch a gross regression (an accidental O(n^2), a lost
/// fast-path), not to gate CI on shared-hardware noise. A workload that
/// exceeds its ceiling prints a warning to stderr; it never fails the build
/// or the test, matching the issue's "budgets may be advisory/trend-based"
/// allowance.
pub const LatencyBudget = struct {
    suite: []const u8,
    name: []const u8,
    max_ns_per_op: f64,
};

pub fn checkLatencyBudgets(measurements: []const Measurement, budgets: []const LatencyBudget) void {
    for (budgets) |budget| {
        for (measurements) |m| {
            if (!std.mem.eql(u8, m.suite, budget.suite) or !std.mem.eql(u8, m.name, budget.name)) continue;
            const observed = m.nsPerOp();
            if (observed > budget.max_ns_per_op) {
                std.debug.print(
                    "crypto-bench advisory: {s}/{s} took {d:.1} ns/op, over the {d:.1} ns/op trend ceiling (informational only, does not fail the build)\n",
                    .{ budget.suite, budget.name, observed, budget.max_ns_per_op },
                );
            }
        }
    }
}

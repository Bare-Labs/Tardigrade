const std = @import("std");
const builtin = @import("builtin");
const compat = @import("zig_compat");

pub const default_deadline_ms: u32 = 10_000;
pub const extended_deadline_ms: u32 = 30_000;
/// `options.stdin` is written in one blocking `writeStreamingAll` call
/// before stdout/stderr draining (and its own deadline machinery) starts,
/// so it is not itself bounded by `deadline_ms` -- a child that never reads
/// stdin, or fills its own stdout/stderr pipe while waiting on it, could
/// block this call indefinitely. Capping `stdin` at this size (well under
/// the smallest realistic default pipe capacity, and at the POSIX
/// `PIPE_BUF` atomic-write guarantee) keeps the write a single, immediate,
/// non-blocking kernel buffer copy in practice instead of a real
/// deadlock risk. Bytes beyond it are a caller bug, not a runtime
/// condition to recover from -- see `run`'s `std.debug.assert`.
pub const max_stdin_len: usize = 4096;

pub const Outcome = union(enum) {
    normal_exit: u8,
    launch_failure,
    timeout,
    signal: std.posix.SIG,
    unexpected_exit_code: u8,
    stdout_limit_exceeded,
    stderr_limit_exceeded,
    malformed_validator_output,
};

pub const Options = struct {
    argv: []const []const u8,
    stdout_limit: usize,
    stderr_limit: usize,
    deadline_ms: u32 = default_deadline_ms,
    accepted_exit_codes: []const u8 = &.{0},
    cwd: std.process.Child.Cwd = .inherit,
    /// Bytes written to the child's stdin immediately after spawn, then the
    /// pipe is closed so the child sees EOF. `null` (the default) leaves
    /// stdin closed from the start, matching every existing caller. Must
    /// be at most `max_stdin_len` -- see that constant's doc comment for
    /// why this write is not itself deadline-bounded.
    stdin: ?[]const u8 = null,
    /// Bounded pause between writing `stdin` and closing the pipe. Some
    /// protocols (e.g. a TLS post-handshake NewSessionTicket, sent after the
    /// application response the child already read) deliver trailing data
    /// asynchronously; closing stdin the instant the write returns can race
    /// a peer process into shutting down before that trailing data arrives.
    /// `0` (the default) closes immediately, matching every existing caller.
    stdin_close_delay_ms: u32 = 0,
    /// Child environment. `null` (the default) inherits this process's own
    /// environment, matching every existing caller; pass an explicit map to
    /// run the child under a modified/constructed environment (e.g. a
    /// fixture-validation subcommand that needs specific `TARDIGRADE_*`
    /// variables set) while keeping the same bounded spawn/wait/reap
    /// contract as every other case this helper drives.
    environ_map: ?*const std.process.Environ.Map = null,
};

pub const Result = struct {
    outcome: Outcome,
    stdout: []u8,
    stderr: []u8,
    diagnostic: []u8,

    pub fn deinit(self: *Result, allocator: std.mem.Allocator) void {
        allocator.free(self.stdout);
        allocator.free(self.stderr);
        allocator.free(self.diagnostic);
        self.* = undefined;
    }

    pub fn malformedValidatorOutput(
        allocator: std.mem.Allocator,
        stdout: []const u8,
        stderr: []const u8,
        comptime fmt: []const u8,
        args: anytype,
    ) !Result {
        const owned_stdout = try boundedDupe(allocator, stdout, 2048);
        errdefer allocator.free(owned_stdout);
        const owned_stderr = try boundedDupe(allocator, stderr, 2048);
        errdefer allocator.free(owned_stderr);
        return .{
            .outcome = .malformed_validator_output,
            .stdout = owned_stdout,
            .stderr = owned_stderr,
            .diagnostic = try std.fmt.allocPrint(allocator, fmt, args),
        };
    }
};

pub fn run(allocator: std.mem.Allocator, options: Options) std.mem.Allocator.Error!Result {
    if (options.stdin) |input| std.debug.assert(input.len <= max_stdin_len);
    const io = compat.io();
    const deadline_end: ?std.Io.Clock.Timestamp = if (options.deadline_ms == 0)
        null
    else
        std.Io.Clock.Timestamp.fromNow(io, .{
            .raw = .fromMilliseconds(options.deadline_ms),
            .clock = .awake,
        });
    var child = std.process.spawn(io, .{
        .argv = options.argv,
        .stdin = if (options.stdin != null) .pipe else .ignore,
        .stdout = .pipe,
        .stderr = .pipe,
        .cwd = options.cwd,
        .pgid = 0,
        .environ_map = options.environ_map,
    }) catch |err| {
        return launchFailureResult(allocator, "launch failed: {s}", .{@errorName(err)});
    };
    const pgid = child.id.?;
    var reaped = false;
    defer if (!reaped) reapProcessGroup(&child, pgid);

    if (options.stdin) |input| {
        const stdin = child.stdin.?;
        stdin.writeStreamingAll(io, input) catch |err| {
            reapProcessGroup(&child, pgid);
            reaped = true;
            return launchFailureResult(allocator, "stdin write failed: {s}", .{@errorName(err)});
        };
        if (options.stdin_close_delay_ms > 0) compat.sleepNs(@as(u64, options.stdin_close_delay_ms) * std.time.ns_per_ms);
        stdin.close(io);
        child.stdin = null;
    }

    var multi_reader_buffer: std.Io.File.MultiReader.Buffer(2) = undefined;
    var multi_reader: std.Io.File.MultiReader = undefined;
    multi_reader.init(allocator, io, multi_reader_buffer.toStreams(), &.{ child.stdout.?, child.stderr.? });
    var reader_active = true;
    defer if (reader_active) multi_reader.deinit();

    const stdout_reader = multi_reader.reader(0);
    const stderr_reader = multi_reader.reader(1);
    const deadline: std.Io.Timeout = if (deadline_end) |timestamp|
        .{ .deadline = timestamp }
    else
        std.Io.Timeout.none;

    while (multi_reader.fill(64, deadline)) |_| {
        if (stdout_reader.buffered().len > options.stdout_limit) {
            return killedResult(
                allocator,
                &child,
                pgid,
                &reaped,
                &multi_reader,
                &reader_active,
                .stdout_limit_exceeded,
                options.stdout_limit,
                options.stderr_limit,
            );
        }
        if (stderr_reader.buffered().len > options.stderr_limit) {
            return killedResult(
                allocator,
                &child,
                pgid,
                &reaped,
                &multi_reader,
                &reader_active,
                .stderr_limit_exceeded,
                options.stdout_limit,
                options.stderr_limit,
            );
        }
    } else |err| switch (err) {
        error.EndOfStream => {},
        error.Timeout => {
            if (reapExitedChild(&child, pgid)) |term| {
                reaped = true;
                return resultForTerm(
                    allocator,
                    &multi_reader,
                    &reader_active,
                    term,
                    options.accepted_exit_codes,
                );
            }
            return killedResult(
                allocator,
                &child,
                pgid,
                &reaped,
                &multi_reader,
                &reader_active,
                .timeout,
                options.stdout_limit,
                options.stderr_limit,
            );
        },
        else => return killedResult(
            allocator,
            &child,
            pgid,
            &reaped,
            &multi_reader,
            &reader_active,
            .launch_failure,
            options.stdout_limit,
            options.stderr_limit,
        ),
    }

    multi_reader.checkAnyError() catch |err| switch (err) {
        error.OutOfMemory => {
            reapProcessGroup(&child, pgid);
            reaped = true;
            return error.OutOfMemory;
        },
        else => return killedResult(
            allocator,
            &child,
            pgid,
            &reaped,
            &multi_reader,
            &reader_active,
            .launch_failure,
            options.stdout_limit,
            options.stderr_limit,
        ),
    };

    const term = waitForExit(&child, pgid, deadline_end) catch |err| {
        reapProcessGroup(&child, pgid);
        reaped = true;
        return failureFromBuffered(
            allocator,
            &multi_reader,
            options.stdout_limit,
            options.stderr_limit,
            .launch_failure,
            "wait failed: {s}",
            .{@errorName(err)},
        );
    } orelse return killedResult(
        allocator,
        &child,
        pgid,
        &reaped,
        &multi_reader,
        &reader_active,
        .timeout,
        options.stdout_limit,
        options.stderr_limit,
    );
    reaped = true;

    return resultForTerm(allocator, &multi_reader, &reader_active, term, options.accepted_exit_codes);
}

fn waitForExit(
    child: *std.process.Child,
    pgid: std.posix.pid_t,
    deadline_end: ?std.Io.Clock.Timestamp,
) !?std.process.Child.Term {
    const pid = child.id.?;
    if (deadline_end == null) {
        const term = try child.wait(compat.io());
        terminateProcessGroup(pgid);
        return term;
    }

    while (true) {
        var status: if (builtin.link_libc) c_int else u32 = undefined;
        const waited = waitPidNoHang(pid, &status) catch |err| switch (err) {
            error.Interrupted => continue,
            else => return err,
        };
        if (waited == pid) {
            child.id = null;
            closeChildPipes(child);
            terminateProcessGroup(pgid);
            return statusToTerm(@bitCast(status));
        }
        if (std.Io.Clock.Timestamp.now(compat.io(), .awake).compare(.gte, deadline_end.?)) return null;
        compat.sleepNs(10 * std.time.ns_per_ms);
    }
}

fn reapExitedChild(child: *std.process.Child, pgid: std.posix.pid_t) ?std.process.Child.Term {
    const pid = child.id orelse return null;
    var status: if (builtin.link_libc) c_int else u32 = undefined;
    const waited = waitPidNoHang(pid, &status) catch |err| switch (err) {
        error.Interrupted => return null,
        else => return null,
    };
    if (waited != pid) return null;
    child.id = null;
    closeChildPipes(child);
    terminateProcessGroup(pgid);
    return statusToTerm(@bitCast(status));
}

fn waitPidNoHang(
    pid: std.posix.pid_t,
    status: *if (builtin.link_libc) c_int else u32,
) error{ Interrupted, WaitFailed }!std.posix.pid_t {
    const raw = std.posix.system.waitpid(pid, status, std.posix.W.NOHANG);
    return switch (std.posix.errno(raw)) {
        .SUCCESS => @intCast(raw),
        .INTR => error.Interrupted,
        else => error.WaitFailed,
    };
}

fn statusToTerm(status: u32) std.process.Child.Term {
    return if (std.posix.W.IFEXITED(status))
        .{ .exited = std.posix.W.EXITSTATUS(status) }
    else if (std.posix.W.IFSIGNALED(status))
        .{ .signal = std.posix.W.TERMSIG(status) }
    else if (std.posix.W.IFSTOPPED(status))
        .{ .stopped = std.posix.W.STOPSIG(status) }
    else
        .{ .unknown = status };
}

fn outcomeForTerm(term: std.process.Child.Term, accepted_exit_codes: []const u8) Outcome {
    return switch (term) {
        .exited => |code| if (isAcceptedExit(code, accepted_exit_codes))
            .{ .normal_exit = code }
        else
            .{ .unexpected_exit_code = code },
        .signal => |sig| .{ .signal = sig },
        .stopped => |sig| .{ .signal = sig },
        .unknown => .launch_failure,
    };
}

fn resultForTerm(
    allocator: std.mem.Allocator,
    multi_reader: *std.Io.File.MultiReader,
    reader_active: *bool,
    term: std.process.Child.Term,
    accepted_exit_codes: []const u8,
) std.mem.Allocator.Error!Result {
    const outcome = outcomeForTerm(term, accepted_exit_codes);
    const stdout = try multi_reader.toOwnedSlice(0);
    errdefer allocator.free(stdout);
    const stderr = try multi_reader.toOwnedSlice(1);
    errdefer allocator.free(stderr);
    reader_active.* = false;
    multi_reader.deinit();
    return .{
        .outcome = outcome,
        .stdout = stdout,
        .stderr = stderr,
        .diagnostic = try diagnosticFor(allocator, outcome, stdout, stderr),
    };
}

fn closeChildPipes(child: *std.process.Child) void {
    const io = compat.io();
    if (child.stdin) |stdin| {
        stdin.close(io);
        child.stdin = null;
    }
    if (child.stdout) |stdout| {
        stdout.close(io);
        child.stdout = null;
    }
    if (child.stderr) |stderr| {
        stderr.close(io);
        child.stderr = null;
    }
}

fn launchFailureResult(
    allocator: std.mem.Allocator,
    comptime fmt: []const u8,
    args: anytype,
) std.mem.Allocator.Error!Result {
    const stdout = try allocator.dupe(u8, "");
    errdefer allocator.free(stdout);
    const stderr = try allocator.dupe(u8, "");
    errdefer allocator.free(stderr);
    return .{
        .outcome = .launch_failure,
        .stdout = stdout,
        .stderr = stderr,
        .diagnostic = try std.fmt.allocPrint(allocator, fmt, args),
    };
}

fn killedResult(
    allocator: std.mem.Allocator,
    child: *std.process.Child,
    pgid: std.posix.pid_t,
    reaped: *bool,
    multi_reader: *std.Io.File.MultiReader,
    reader_active: *bool,
    outcome: Outcome,
    stdout_limit: usize,
    stderr_limit: usize,
) std.mem.Allocator.Error!Result {
    reapProcessGroup(child, pgid);
    reaped.* = true;

    const stdout = try boundedDupe(allocator, multi_reader.reader(0).buffered(), stdout_limit);
    errdefer allocator.free(stdout);
    const stderr = try boundedDupe(allocator, multi_reader.reader(1).buffered(), stderr_limit);
    errdefer allocator.free(stderr);
    reader_active.* = false;
    multi_reader.deinit();
    return .{
        .outcome = outcome,
        .stdout = stdout,
        .stderr = stderr,
        .diagnostic = try diagnosticFor(allocator, outcome, stdout, stderr),
    };
}

fn reapProcessGroup(child: *std.process.Child, pgid: std.posix.pid_t) void {
    terminateProcessGroup(pgid);
    child.kill(compat.io());
    terminateProcessGroup(pgid);
    waitForProcessGroupGone(pgid);
}

fn terminateProcessGroup(pid: std.posix.pid_t) void {
    std.posix.kill(-pid, .KILL) catch |err| switch (err) {
        error.ProcessNotFound => {},
        error.PermissionDenied => {},
        else => {},
    };
}

fn waitForProcessGroupGone(pgid: std.posix.pid_t) void {
    for (0..20) |_| {
        if (!processGroupExists(pgid)) return;
        compat.sleepNs(50 * std.time.ns_per_ms);
    }
}

fn processGroupExists(pgid: std.posix.pid_t) bool {
    std.posix.kill(-pgid, @enumFromInt(0)) catch |err| switch (err) {
        error.ProcessNotFound => return false,
        error.PermissionDenied => return true,
        else => return true,
    };
    return true;
}

fn failureFromBuffered(
    allocator: std.mem.Allocator,
    multi_reader: *std.Io.File.MultiReader,
    stdout_limit: usize,
    stderr_limit: usize,
    outcome: Outcome,
    comptime fmt: []const u8,
    args: anytype,
) std.mem.Allocator.Error!Result {
    const stdout = try boundedDupe(allocator, multi_reader.reader(0).buffered(), stdout_limit);
    errdefer allocator.free(stdout);
    const stderr = try boundedDupe(allocator, multi_reader.reader(1).buffered(), stderr_limit);
    errdefer allocator.free(stderr);
    return .{
        .outcome = outcome,
        .stdout = stdout,
        .stderr = stderr,
        .diagnostic = try std.fmt.allocPrint(allocator, fmt, args),
    };
}

fn diagnosticFor(allocator: std.mem.Allocator, outcome: Outcome, stdout: []const u8, stderr: []const u8) ![]u8 {
    const preferred = if (stderr.len != 0) stderr else stdout;
    const trimmed = std.mem.trim(u8, preferred, " \t\r\n");
    const detail = if (trimmed.len == 0) "no diagnostic" else trimmed[0..@min(trimmed.len, 2048)];
    return switch (outcome) {
        .normal_exit => allocator.dupe(u8, detail),
        .launch_failure => std.fmt.allocPrint(allocator, "process failure: {s}", .{detail}),
        .timeout => std.fmt.allocPrint(allocator, "process timed out: {s}", .{detail}),
        .signal => |sig| std.fmt.allocPrint(allocator, "process terminated by signal {d}: {s}", .{ @intFromEnum(sig), detail }),
        .unexpected_exit_code => |code| std.fmt.allocPrint(allocator, "unexpected exit code {d}: {s}", .{ code, detail }),
        .stdout_limit_exceeded => std.fmt.allocPrint(allocator, "stdout limit exceeded: {s}", .{detail}),
        .stderr_limit_exceeded => std.fmt.allocPrint(allocator, "stderr limit exceeded: {s}", .{detail}),
        .malformed_validator_output => std.fmt.allocPrint(allocator, "malformed validator output: {s}", .{detail}),
    };
}

fn boundedDupe(allocator: std.mem.Allocator, bytes: []const u8, limit: usize) ![]u8 {
    return allocator.dupe(u8, bytes[0..@min(bytes.len, limit)]);
}

fn isAcceptedExit(code: u8, accepted: []const u8) bool {
    for (accepted) |candidate| {
        if (candidate == code) return true;
    }
    return false;
}

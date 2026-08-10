const compat = @import("zig_compat");
const builtin = @import("builtin");
const std = @import("std");

pub const Backend = enum {
    epoll,
    kqueue,
    /// Linux-only, opt-in readiness-only `io_uring` poller (#148). Stands in
    /// for `epoll_wait` using `IORING_OP_POLL_ADD`/`IORING_OP_POLL_REMOVE`
    /// plus `IORING_OP_TIMEOUT` for `wait`'s bounded block. It deliberately
    /// does **not** submit accept/read/write operations: `accept()` and all
    /// request I/O stay outside the ring as blocking calls on worker threads,
    /// exactly as with `epoll`/`kqueue`. See `docs/EVENT_LOOP_BACKENDS.md`.
    io_uring,

    /// Parse an operator-supplied backend name. Returns null for unknown
    /// names so the caller can emit a config diagnostic listing valid values.
    pub fn parse(value: []const u8) ?Backend {
        if (std.ascii.eqlIgnoreCase(value, "epoll")) return .epoll;
        if (std.ascii.eqlIgnoreCase(value, "kqueue")) return .kqueue;
        if (std.ascii.eqlIgnoreCase(value, "io_uring") or std.ascii.eqlIgnoreCase(value, "io-uring")) return .io_uring;
        return null;
    }
};

pub const Event = struct {
    fd: std.posix.fd_t,
    readable: bool = false,
    writable: bool = false,
    errored: bool = false,
};

pub const Interest = packed struct {
    read: bool = false,
    write: bool = false,

    pub fn any(self: Interest) bool {
        return self.read or self.write;
    }
};

pub const EventLoop = struct {
    fd: std.posix.fd_t,
    backend: Backend,
    /// Only populated for `Backend.io_uring`. Heap-allocated so the poller's
    /// mutex and registration table keep a stable address even though callers
    /// pass `*EventLoop` around by pointer.
    ring: ?*IoUringPoller = null,

    pub fn init() !EventLoop {
        return if (builtin.os.tag == .linux) blk: {
            const linux = std.os.linux;
            const rc = linux.epoll_create1(@intCast(linux.EPOLL.CLOEXEC));
            if (linux.errno(rc) != .SUCCESS) return error.SystemResources;
            break :blk .{ .fd = @intCast(rc), .backend = .epoll };
        } else blk: {
            const fd = std.c.kqueue();
            if (fd < 0) return error.SystemResources;
            break :blk .{ .fd = fd, .backend = .kqueue };
        };
    }

    /// Initialize a specific backend, failing closed if it is unavailable.
    ///
    /// An operator who explicitly asks for a backend must learn at startup
    /// that their deployment target does not support it rather than discover
    /// a silent downgrade during an incident, so this never falls back to the
    /// platform default (`docs/EVENT_LOOP_BACKENDS.md`, "Failure modes and
    /// fallback policy"). `allocator` is only used by `.io_uring`.
    pub fn initBackend(allocator: std.mem.Allocator, backend: Backend, options: InitOptions) !EventLoop {
        const platform_default = try detectBackend();
        switch (backend) {
            .epoll, .kqueue => {
                if (backend != platform_default) return error.UnsupportedBackendForPlatform;
                return init();
            },
            .io_uring => {
                if (builtin.os.tag != .linux) return error.UnsupportedBackendForPlatform;
                return initIoUring(allocator, options.io_uring_entries);
            },
        }
    }

    pub fn deinit(self: *EventLoop) void {
        if (builtin.os.tag == .linux) {
            if (self.ring) |poller| {
                poller.deinit();
                self.* = undefined;
                return;
            }
        }
        _ = std.c.close(self.fd);
        self.* = undefined;
    }

    pub fn backendName(self: *const EventLoop) []const u8 {
        return switch (self.backend) {
            .epoll => "epoll",
            .kqueue => "kqueue",
            .io_uring => "io_uring",
        };
    }

    pub fn addReadFd(self: *EventLoop, fd: std.posix.fd_t) !void {
        return self.add(fd, .{ .read = true });
    }

    pub fn add(self: *EventLoop, fd: std.posix.fd_t, interest: Interest) !void {
        if (!interest.any()) return error.InvalidEventInterest;
        if (builtin.os.tag == .linux) {
            if (self.ring) |poller| return poller.add(fd, interest);
            const linux = std.os.linux;
            var event = linux.epoll_event{
                .events = epollEventsFor(interest),
                .data = .{ .fd = @intCast(fd) },
            };
            const rc = linux.epoll_ctl(@intCast(self.fd), linux.EPOLL.CTL_ADD, @intCast(fd), &event);
            if (linux.errno(rc) != .SUCCESS) return error.Unexpected;
        } else {
            try self.applyKqueueInterest(fd, interest, .add);
        }
    }

    pub fn modify(self: *EventLoop, fd: std.posix.fd_t, interest: Interest) !void {
        if (!interest.any()) return error.InvalidEventInterest;
        if (builtin.os.tag == .linux) {
            if (self.ring) |poller| return poller.modify(fd, interest);
            const linux = std.os.linux;
            var event = linux.epoll_event{
                .events = epollEventsFor(interest),
                .data = .{ .fd = @intCast(fd) },
            };
            const rc = linux.epoll_ctl(@intCast(self.fd), linux.EPOLL.CTL_MOD, @intCast(fd), &event);
            if (linux.errno(rc) != .SUCCESS) return error.Unexpected;
        } else {
            try self.applyKqueueInterest(fd, interest, .modify);
        }
    }

    /// Stop watching `fd` for readiness. Used to un-park a keepalive connection
    /// before dispatching it to a worker (#138), so the level-triggered backends
    /// do not keep re-firing while the worker drains the socket. Safe to call
    /// from a worker thread concurrently with `wait` on the loop thread, since
    /// both epoll_ctl and kevent change-list updates are thread-safe.
    pub fn removeReadFd(self: *EventLoop, fd: std.posix.fd_t) !void {
        return self.remove(fd);
    }

    pub fn remove(self: *EventLoop, fd: std.posix.fd_t) !void {
        if (builtin.os.tag == .linux) {
            if (self.ring) |poller| return poller.remove(fd);
            const linux = std.os.linux;
            // EPOLL_CTL_DEL ignores the event argument on modern kernels, but a
            // valid pointer is passed for portability with older ones.
            var event = linux.epoll_event{
                .events = 0,
                .data = .{ .fd = @intCast(fd) },
            };
            const rc = linux.epoll_ctl(@intCast(self.fd), linux.EPOLL.CTL_DEL, @intCast(fd), &event);
            if (linux.errno(rc) != .SUCCESS) return error.Unexpected;
        } else {
            try self.applyKqueueInterest(fd, .{}, .remove);
        }
    }

    pub fn wait(self: *EventLoop, out_events: []Event, timeout_ms: i32) !usize {
        if (out_events.len == 0) return 0;

        if (builtin.os.tag == .linux) {
            if (self.ring) |poller| return poller.wait(out_events, timeout_ms);
            return self.waitEpoll(out_events, timeout_ms);
        }
        return self.waitKqueue(out_events, timeout_ms);
    }

    fn waitEpoll(self: *EventLoop, out_events: []Event, timeout_ms: i32) usize {
        const linux = std.os.linux;
        var epoll_events: [64]linux.epoll_event = undefined;
        const cap = @min(out_events.len, epoll_events.len);
        const rc = linux.epoll_wait(@intCast(self.fd), epoll_events[0..cap].ptr, @intCast(cap), timeout_ms);
        if (linux.errno(rc) != .SUCCESS) return 0;
        const n: usize = @intCast(rc);

        for (epoll_events[0..n], 0..) |ev, idx| {
            const errored = (ev.events & (linux.EPOLL.HUP | linux.EPOLL.ERR)) != 0;
            out_events[idx] = .{
                .fd = @intCast(ev.data.fd),
                .readable = (ev.events & linux.EPOLL.IN) != 0 or errored,
                .writable = (ev.events & linux.EPOLL.OUT) != 0,
                .errored = errored,
            };
        }
        return n;
    }

    fn waitKqueue(self: *EventLoop, out_events: []Event, timeout_ms: i32) !usize {
        var kq_events: [128]std.c.Kevent = undefined;
        const requested = std.math.mul(usize, out_events.len, 2) catch out_events.len;
        const cap = @min(requested, kq_events.len);

        var ts: std.c.timespec = undefined;
        const timeout_ptr: ?*const std.c.timespec = if (timeout_ms < 0)
            null
        else blk: {
            const millis: u64 = @intCast(timeout_ms);
            ts = .{
                .sec = @intCast(millis / std.time.ms_per_s),
                .nsec = @intCast((millis % std.time.ms_per_s) * std.time.ns_per_ms),
            };
            break :blk &ts;
        };

        var dummy_ev: std.c.Kevent = undefined;
        const n = std.c.kevent(self.fd, @as([*]const std.c.Kevent, @ptrCast(&dummy_ev)), 0, kq_events[0..cap].ptr, @intCast(cap), timeout_ptr);
        if (n < 0) {
            // A blocking kevent is interrupted by any signal delivered to this
            // thread (EINTR) — common once background worker threads (e.g. the
            // HTTP/2 upstream readers) are active. Treat it as "no events" and
            // let the caller loop again, mirroring the epoll path.
            if (std.posix.errno(n) == .INTR) return 0;
            return error.Unexpected;
        }
        var out_len: usize = 0;
        for (kq_events[0..@intCast(n)]) |ev| {
            const errored = (ev.flags & (std.c.EV.ERROR | std.c.EV.EOF)) != 0;
            const fd: std.posix.fd_t = @intCast(ev.ident);
            const slot = findOrAppendByFd(out_events, &out_len, fd) orelse continue;
            slot.readable = slot.readable or ev.filter == std.c.EVFILT.READ or errored;
            slot.writable = slot.writable or ev.filter == std.c.EVFILT.WRITE;
            slot.errored = slot.errored or errored;
        }
        return out_len;
    }

    fn applyKqueueInterest(self: *EventLoop, fd: std.posix.fd_t, interest: Interest, op: enum { add, modify, remove }) !void {
        if (op == .modify or op == .remove) {
            try self.kqueueFilterChange(fd, std.c.EVFILT.READ, std.c.EV.DELETE, true);
            try self.kqueueFilterChange(fd, std.c.EVFILT.WRITE, std.c.EV.DELETE, true);
        }
        if (op == .remove) return;
        if (interest.read) try self.kqueueFilterChange(fd, std.c.EVFILT.READ, std.c.EV.ADD | std.c.EV.ENABLE, false);
        if (interest.write) try self.kqueueFilterChange(fd, std.c.EVFILT.WRITE, std.c.EV.ADD | std.c.EV.ENABLE, false);
    }

    fn kqueueFilterChange(
        self: *EventLoop,
        fd: std.posix.fd_t,
        filter: i16,
        flags: u16,
        ignore_missing: bool,
    ) !void {
        const changes = [_]std.c.Kevent{.{
            .ident = @intCast(fd),
            .filter = filter,
            .flags = flags,
            .fflags = 0,
            .data = 0,
            .udata = 0,
        }};
        const ret = std.c.kevent(self.fd, &changes, @intCast(changes.len), @as([*]std.c.Kevent, @ptrCast(@constCast(&changes))), 0, null);
        if (ret < 0) {
            if (ignore_missing and std.posix.errno(ret) == .NOENT) return;
            return error.Unexpected;
        }
    }
};

/// Fold a per-filter/per-completion readiness signal into the caller's
/// per-fd output slice. Shared by the kqueue and io_uring paths, both of
/// which can observe read and write readiness for one fd separately.
fn findOrAppendByFd(out_events: []Event, out_len: *usize, fd: std.posix.fd_t) ?*Event {
    for (out_events[0..out_len.*]) |*event| {
        if (event.fd == fd) return event;
    }
    if (out_len.* == out_events.len) return null;
    const slot = &out_events[out_len.*];
    slot.* = .{ .fd = fd };
    out_len.* += 1;
    return slot;
}

/// Default submission-queue depth for the `io_uring` backend.
///
/// Kept modest on purpose: on kernels older than 5.12 the ring's mmap'd
/// SQ/CQ memory is charged against `RLIMIT_MEMLOCK`, whose default soft limit
/// is commonly 64 KiB. At 256 entries the rings cost roughly 24 KiB (256
/// 64-byte SQEs plus 512 16-byte CQEs), which fits that default; much deeper
/// rings would make `io_uring_setup` fail with `ENOMEM` on stock 5.4-era
/// hosts. Operators who want a deeper ring can raise `RLIMIT_MEMLOCK` and set
/// `TARDIGRADE_EVENT_LOOP_IO_URING_ENTRIES`.
pub const default_io_uring_entries: u16 = 256;
pub const min_io_uring_entries: u16 = 64;
pub const max_io_uring_entries: u16 = 4096;

pub const InitOptions = struct {
    io_uring_entries: u16 = default_io_uring_entries,
};

/// Opaque on non-Linux targets so that referencing `?*IoUringPoller` as an
/// `EventLoop` field never drags `std.os.linux.IoUring` into analysis on
/// macOS/BSD builds.
const IoUringPoller = if (builtin.os.tag == .linux) IoUringPollerLinux else opaque {};

fn initIoUring(allocator: std.mem.Allocator, entries: u16) !EventLoop {
    const poller = try allocator.create(IoUringPollerLinux);
    errdefer allocator.destroy(poller);
    poller.* = try IoUringPollerLinux.init(allocator, entries);
    return .{ .fd = poller.ring.fd, .backend = .io_uring, .ring = poller };
}

/// Readiness-only `io_uring` poller (#148).
///
/// Emulates the level-triggered `add`/`modify`/`remove`/`wait` contract the
/// rest of the gateway already programs against, using only
/// `IORING_OP_POLL_ADD`, `IORING_OP_POLL_REMOVE` and `IORING_OP_TIMEOUT`.
/// Two behaviours of the ring have to be papered over to match `epoll`:
///
///  1. **`POLL_ADD` is one-shot.** `epoll` in level-triggered mode keeps
///     reporting a fd until the caller drains or removes it, and callers rely
///     on that (the listener fd is registered once and never re-added). Every
///     delivered completion is therefore immediately re-armed inside `wait`.
///  2. **Closing a fd does not unregister it.** `epoll` drops a fd from every
///     set when it is closed, and the gateway's close hooks rely on that —
///     they only release accounting slots. The ring keeps the poll armed and
///     this poller keeps its table entry, so `add` treats a surviving entry
///     for a fd it is asked to register as a stale one from a recycled fd
///     number, cancels it, and takes the fd over.
///  3. **The submission queue is not kernel-synchronized.** `epoll_ctl` is
///     safe to call from any thread while another sits in `epoll_wait`, and
///     `removeReadFd` documents that worker threads do exactly that. The SQ
///     is plain shared memory, so every userspace ring mutation here is taken
///     under `mutex`, and submitting threads call `io_uring_enter` themselves
///     (with `min_complete = 0`) so a newly armed poll takes effect even
///     while the loop thread is blocked in its own `io_uring_enter`.
///
/// A registration's `user_data` packs a monotonic 32-bit token above the fd.
/// `POLL_REMOVE` races with an already-completing poll, so a completion whose
/// token no longer matches the live registration is dropped rather than
/// reported against a fd the caller has since removed (and possibly closed).
///
/// **Known behavioural difference from `epoll`.** A `POLL_ADD` completion
/// carries the mask captured when the poll fired, whereas `epoll_wait` reports
/// whatever the fd's readiness is at the moment of the call. A fd registered
/// for both read and write can therefore be reported as only writable here
/// (sockets are almost always immediately writable) and become readable on a
/// following `wait`, where `epoll` would have coalesced both into one event.
/// No readiness is lost — the fd is re-armed immediately and the remaining
/// readiness surfaces on the next iteration — so this is safe for the
/// level-triggered, re-poll-until-drained consumers in `edge_gateway.zig`, but
/// it does mean a caller may need one extra loop iteration. Closing the gap
/// would require `IORING_POLL_ADD_LEVEL`, which is Linux 5.13+ and therefore
/// above this prototype's documented 5.4 floor.
const IoUringPollerLinux = struct {
    const linux = std.os.linux;

    /// A live registration's token occupies the high 32 bits and is handed
    /// out from `next_token`, which starts at 1 and never reaches these
    /// values in practice, so neither sentinel can collide with one.
    const timeout_user_data: u64 = std.math.maxInt(u64);
    const cancel_user_data: u64 = std.math.maxInt(u64) - 1;

    const Registration = struct {
        interest: Interest,
        token: u32,
    };

    allocator: std.mem.Allocator,
    ring: linux.IoUring,
    mutex: compat.Mutex = .{},
    registrations: std.AutoHashMapUnmanaged(std.posix.fd_t, Registration) = .empty,
    next_token: u32 = 1,

    fn init(allocator: std.mem.Allocator, entries: u16) !IoUringPollerLinux {
        if (entries < min_io_uring_entries or entries > max_io_uring_entries) {
            return error.InvalidIoUringRingSize;
        }
        var ring = linux.IoUring.init(entries, 0) catch |err| switch (err) {
            // `io_uring_setup` is commonly blocked outright by container
            // seccomp profiles (Docker's default profile denies it), which
            // surfaces as EPERM/ENOSYS rather than as a missing opcode.
            error.PermissionDenied, error.SystemOutdated => return error.IoUringUnavailable,
            error.SystemResources => return error.IoUringRingAllocationFailed,
            else => return error.IoUringUnavailable,
        };
        errdefer ring.deinit();

        try probeCapabilities(&ring);

        return .{ .allocator = allocator, .ring = ring };
    }

    /// Establish that the three opcodes this backend actually submits are
    /// present, rather than inferring them from a compile-time Linux check or
    /// from the fact that the ring was created at all.
    ///
    /// A successful `IoUring.init` only proves the 5.1 ring baseline.
    /// `IORING_OP_TIMEOUT` — which `wait`'s bounded block depends on — did not
    /// land until 5.4, so it has to be checked separately. `IORING_REGISTER_PROBE`
    /// is itself only available from 5.6, so kernels in the 5.1-5.5 window fall
    /// back to submitting a real already-expired timeout and confirming the
    /// kernel completes it with `-ETIME` instead of rejecting the opcode.
    fn probeCapabilities(ring: *linux.IoUring) !void {
        if (ring.get_probe()) |probe| {
            if (!probe.is_supported(.POLL_ADD)) return error.IoUringPollAddUnsupported;
            if (!probe.is_supported(.POLL_REMOVE)) return error.IoUringPollRemoveUnsupported;
            if (!probe.is_supported(.TIMEOUT)) return error.IoUringTimeoutUnsupported;
            return;
        } else |_| {
            // REGISTER_PROBE unavailable (pre-5.6): fall through to the
            // functional probe below.
        }

        const ts: linux.kernel_timespec = .{ .sec = 0, .nsec = 0 };
        _ = ring.timeout(timeout_user_data, &ts, 0, 0) catch return error.IoUringTimeoutUnsupported;
        _ = ring.submit_and_wait(1) catch return error.IoUringTimeoutUnsupported;
        const cqe = ring.copy_cqe() catch return error.IoUringTimeoutUnsupported;
        // An already-expired timeout completes with -ETIME. A kernel that does
        // not know the opcode rejects it with -EINVAL/-EOPNOTSUPP instead.
        // `cqe.res` carries the raw negated errno, and ETIME's numeric value
        // is architecture-dependent, so compare against the enum.
        if (cqe.res >= 0) return error.IoUringTimeoutUnsupported;
        const completion_errno: u32 = @intCast(-cqe.res);
        if (completion_errno != @intFromEnum(linux.E.TIME)) return error.IoUringTimeoutUnsupported;
    }

    fn deinit(self: *IoUringPollerLinux) void {
        const allocator = self.allocator;
        self.registrations.deinit(allocator);
        self.ring.deinit();
        allocator.destroy(self);
    }

    fn add(self: *IoUringPollerLinux, fd: std.posix.fd_t, interest: Interest) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Closing a fd removes it from every epoll set automatically, and this
        // codebase relies on that: both `parkedConnectionCloseHook` and
        // `activeConnectionCloseHook` only do accounting, so the keepalive idle
        // reaper and the active-connection reaper close registered fds without
        // unregistering them first. io_uring has no equivalent implicit
        // cleanup, so an entry still present here belongs to a closed fd whose
        // number the kernel has since recycled. Cancel that stale poll and take
        // the fd over, which is what the caller would have observed under
        // epoll — rather than reporting EEXIST for a connection it considers
        // brand new and failing to register it at all.
        if (self.registrations.getPtr(fd)) |stale| {
            self.cancelLocked(fd, stale.token) catch {};
            stale.interest = interest;
            stale.token = self.takeTokenLocked();
            try self.armLocked(fd, stale);
            try self.submitLocked();
            return;
        }

        const token = self.takeTokenLocked();
        try self.registrations.put(self.allocator, fd, .{ .interest = interest, .token = token });
        errdefer _ = self.registrations.remove(fd);

        const reg = self.registrations.getPtr(fd).?;
        try self.armLocked(fd, reg);
        try self.submitLocked();
    }

    fn modify(self: *IoUringPollerLinux, fd: std.posix.fd_t, interest: Interest) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Mirror EPOLL_CTL_MOD's ENOENT.
        const reg = self.registrations.getPtr(fd) orelse return error.Unexpected;

        // Cancel the in-flight poll and re-arm under a fresh token so a
        // completion already in flight for the old interest is discarded.
        try self.cancelLocked(fd, reg.token);
        reg.interest = interest;
        reg.token = self.takeTokenLocked();
        try self.armLocked(fd, reg);
        try self.submitLocked();
    }

    fn remove(self: *IoUringPollerLinux, fd: std.posix.fd_t) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Mirror EPOLL_CTL_DEL's ENOENT.
        const entry = self.registrations.fetchRemove(fd) orelse return error.Unexpected;
        try self.cancelLocked(fd, entry.value.token);
        try self.submitLocked();
    }

    fn wait(self: *IoUringPollerLinux, out_events: []Event, timeout_ms: i32) !usize {
        var ts: linux.kernel_timespec = undefined;
        var timer_armed = false;
        {
            self.mutex.lock();
            defer self.mutex.unlock();

            if (timeout_ms > 0) {
                const millis: u64 = @intCast(timeout_ms);
                ts = .{
                    .sec = @intCast(millis / std.time.ms_per_s),
                    .nsec = @intCast((millis % std.time.ms_per_s) * std.time.ns_per_ms),
                };
                // `count = 1` makes the timer complete as soon as one other
                // completion is posted, or when `ts` elapses — the same shape
                // as `epoll_wait(timeout)`, and self-completing either way so
                // no dangling timer has to be cancelled afterwards.
                if (self.ring.timeout(timeout_user_data, &ts, 1, 0)) |_| {
                    timer_armed = true;
                } else |_| {}
            }
            self.submitLocked() catch {};
        }

        // Never block without a timer to break it: a bounded wait whose timer
        // could not be queued degrades to a non-blocking poll rather than
        // hanging the loop thread past its caller's deadline.
        const may_block = if (timeout_ms > 0) timer_armed else timeout_ms < 0;

        // Block outside the lock so worker threads can keep arming and
        // cancelling polls while the loop thread waits.
        if (may_block and self.ring.cq_ready() == 0) {
            _ = self.ring.enter(0, 1, linux.IORING_ENTER_GETEVENTS) catch |err| switch (err) {
                // Signals reach this thread routinely once background workers
                // are running; treat it as "no events", mirroring the
                // epoll/kqueue paths.
                error.SignalInterrupt => return 0,
                else => return error.Unexpected,
            };
        }

        return self.reap(out_events);
    }

    fn reap(self: *IoUringPollerLinux, out_events: []Event) !usize {
        var cqes: [64]linux.io_uring_cqe = undefined;
        const cap = @min(out_events.len, cqes.len);

        self.mutex.lock();
        defer self.mutex.unlock();

        const copied = self.ring.copy_cqes(cqes[0..cap], 0) catch return error.Unexpected;
        var out_len: usize = 0;
        for (cqes[0..copied]) |cqe| {
            if (cqe.user_data == timeout_user_data or cqe.user_data == cancel_user_data) continue;

            const fd = decodeFd(cqe.user_data);
            const reg = self.registrations.getPtr(fd) orelse continue;
            // Stale completion for a registration that was removed or
            // re-armed under a new interest.
            if (reg.token != decodeToken(cqe.user_data)) continue;
            // A negative result is a negated errno, not a poll mask. The
            // common case is -ECANCELED, though a cancel normally also
            // removes or re-tokenizes the registration and so is already
            // filtered above. Anything else is a poll the kernel refused;
            // like the epoll path's error handling, this reports no readiness
            // and does not try to self-heal by re-arming.
            if (cqe.res < 0) continue;

            const mask: u32 = @intCast(cqe.res);
            const errored = (mask & (pollErr | pollHup)) != 0;
            if (findOrAppendByFd(out_events, &out_len, fd)) |slot| {
                slot.readable = slot.readable or (mask & pollIn) != 0 or errored;
                slot.writable = slot.writable or (mask & pollOut) != 0;
                slot.errored = slot.errored or errored;
            }

            // Re-arm: POLL_ADD is one-shot, but callers expect epoll's
            // level-triggered persistence. Dropping the re-arm on error is
            // safe in the same way the epoll path's errors are: the caller
            // sees no further readiness and the connection's own deadline
            // reaper reclaims it.
            self.armLocked(fd, reg) catch continue;
        }
        self.submitLocked() catch {};
        return out_len;
    }

    fn takeTokenLocked(self: *IoUringPollerLinux) u32 {
        const token = self.next_token;
        // Skip 0 on wrap so a zeroed user_data can never look like a live
        // registration.
        self.next_token = if (token == std.math.maxInt(u32) - 2) 1 else token + 1;
        return token;
    }

    fn armLocked(self: *IoUringPollerLinux, fd: std.posix.fd_t, reg: *const Registration) !void {
        const user_data = encodeUserData(fd, reg.token);
        const mask = pollMaskFor(reg.interest);
        // The only failure `get_sqe` reports is a full submission queue; flush
        // it to the kernel and retry once before giving up.
        _ = self.ring.poll_add(user_data, fd, mask) catch {
            try self.submitLocked();
            _ = self.ring.poll_add(user_data, fd, mask) catch return error.Unexpected;
        };
    }

    fn cancelLocked(self: *IoUringPollerLinux, fd: std.posix.fd_t, token: u32) !void {
        const target = encodeUserData(fd, token);
        _ = self.ring.poll_remove(cancel_user_data, target) catch {
            try self.submitLocked();
            _ = self.ring.poll_remove(cancel_user_data, target) catch return error.Unexpected;
        };
    }

    /// Push queued SQEs to the kernel without blocking. Called by whichever
    /// thread queued them, so a poll armed from a worker takes effect even
    /// while the loop thread is parked in `io_uring_enter`.
    fn submitLocked(self: *IoUringPollerLinux) !void {
        const to_submit = self.ring.flush_sq();
        if (to_submit == 0) return;
        _ = self.ring.enter(to_submit, 0, 0) catch |err| switch (err) {
            error.SignalInterrupt => return,
            else => return error.Unexpected,
        };
    }

    const pollIn: u32 = std.posix.POLL.IN;
    const pollOut: u32 = std.posix.POLL.OUT;
    const pollErr: u32 = std.posix.POLL.ERR;
    const pollHup: u32 = std.posix.POLL.HUP;

    fn pollMaskFor(interest: Interest) u32 {
        var mask: u32 = pollErr | pollHup;
        if (interest.read) mask |= pollIn;
        if (interest.write) mask |= pollOut;
        return mask;
    }

    fn encodeUserData(fd: std.posix.fd_t, token: u32) u64 {
        return (@as(u64, token) << 32) | @as(u64, @as(u32, @bitCast(fd)));
    }

    fn decodeFd(user_data: u64) std.posix.fd_t {
        return @bitCast(@as(u32, @truncate(user_data)));
    }

    fn decodeToken(user_data: u64) u32 {
        return @truncate(user_data >> 32);
    }
};

fn epollEventsFor(interest: Interest) u32 {
    const linux = std.os.linux;
    var events: u32 = linux.EPOLL.HUP | linux.EPOLL.ERR;
    if (interest.read) events |= linux.EPOLL.IN;
    if (interest.write) events |= linux.EPOLL.OUT;
    return events;
}

pub const TimerManager = struct {
    interval_ms: u64,
    next_tick_ms: u64,

    pub fn init(interval_ms: u64) TimerManager {
        const now = monotonicMs();
        return .{
            .interval_ms = interval_ms,
            .next_tick_ms = now + interval_ms,
        };
    }

    pub fn msUntilNextTick(self: *const TimerManager, now_ms: u64) i32 {
        if (self.interval_ms == 0) return -1;
        if (now_ms >= self.next_tick_ms) return 0;

        const delta = self.next_tick_ms - now_ms;
        return @intCast(@min(delta, @as(u64, std.math.maxInt(i32))));
    }

    pub fn consumeTick(self: *TimerManager, now_ms: u64) bool {
        if (self.interval_ms == 0) return false;
        if (now_ms < self.next_tick_ms) return false;

        while (self.next_tick_ms <= now_ms) {
            self.next_tick_ms += self.interval_ms;
        }
        return true;
    }
};

pub fn detectBackend() !Backend {
    return switch (builtin.os.tag) {
        .linux => .epoll,
        .macos, .ios, .tvos, .watchos, .visionos, .freebsd, .netbsd, .openbsd, .dragonfly => .kqueue,
        else => error.UnsupportedPlatform,
    };
}

pub fn monotonicMs() u64 {
    const now = compat.milliTimestamp();
    return if (now <= 0) 0 else @intCast(now);
}

test "detectBackend matches current platform" {
    const backend = try detectBackend();
    switch (builtin.os.tag) {
        .linux => try std.testing.expectEqual(Backend.epoll, backend),
        .macos, .ios, .tvos, .watchos, .visionos, .freebsd, .netbsd, .openbsd, .dragonfly => try std.testing.expectEqual(Backend.kqueue, backend),
        else => try std.testing.expect(false),
    }
}

test "timer manager ticks on interval" {
    var timer = TimerManager{
        .interval_ms = 100,
        .next_tick_ms = 1_000,
    };

    try std.testing.expectEqual(@as(i32, 100), timer.msUntilNextTick(900));
    try std.testing.expect(!timer.consumeTick(999));
    try std.testing.expect(timer.consumeTick(1_000));
    try std.testing.expectEqual(@as(u64, 1_100), timer.next_tick_ms);
}

test "event loop reports write readiness" {
    var loop = try EventLoop.init();
    defer loop.deinit();
    const fds = try testSocketPair();
    defer closeFd(fds[0]);
    defer closeFd(fds[1]);

    try loop.add(fds[0], .{ .write = true });
    defer loop.remove(fds[0]) catch {};

    var events: [4]Event = undefined;
    const count = try loop.wait(&events, 50);
    try std.testing.expect(count > 0);
    var saw_write = false;
    for (events[0..count]) |ev| {
        if (ev.fd == fds[0] and ev.writable) saw_write = true;
    }
    try std.testing.expect(saw_write);
}

test "event loop modify replaces write interest with read interest" {
    var loop = try EventLoop.init();
    defer loop.deinit();
    const fds = try testSocketPair();
    defer closeFd(fds[0]);
    defer closeFd(fds[1]);

    try loop.add(fds[0], .{ .write = true });
    defer loop.remove(fds[0]) catch {};
    try loop.modify(fds[0], .{ .read = true });

    var events: [4]Event = undefined;
    try std.testing.expectEqual(@as(usize, 0), try loop.wait(&events, 10));
    try writeFd(fds[1], "x");
    const count = try loop.wait(&events, 50);
    try std.testing.expect(count > 0);
    var saw_read = false;
    var saw_write = false;
    for (events[0..count]) |ev| {
        if (ev.fd != fds[0]) continue;
        saw_read = saw_read or ev.readable;
        saw_write = saw_write or ev.writable;
    }
    try std.testing.expect(saw_read);
    try std.testing.expect(!saw_write);
}

test "event loop coalesces simultaneous read and write readiness by fd" {
    var loop = try EventLoop.init();
    defer loop.deinit();
    const fds = try testSocketPair();
    defer closeFd(fds[0]);
    defer closeFd(fds[1]);

    try loop.add(fds[0], .{ .read = true, .write = true });
    defer loop.remove(fds[0]) catch {};
    try writeFd(fds[1], "x");

    var events: [1]Event = undefined;
    const count = try loop.wait(&events, 50);
    try std.testing.expectEqual(@as(usize, 1), count);
    try std.testing.expectEqual(fds[0], events[0].fd);
    try std.testing.expect(events[0].readable);
    try std.testing.expect(events[0].writable);
}

test "backend names parse and round-trip" {
    try std.testing.expectEqual(Backend.epoll, Backend.parse("epoll").?);
    try std.testing.expectEqual(Backend.kqueue, Backend.parse("KQUEUE").?);
    try std.testing.expectEqual(Backend.io_uring, Backend.parse("io_uring").?);
    try std.testing.expectEqual(Backend.io_uring, Backend.parse("io-uring").?);
    try std.testing.expect(Backend.parse("iouring") == null);
    try std.testing.expect(Backend.parse("") == null);

    inline for (.{ Backend.epoll, Backend.kqueue, Backend.io_uring }) |backend| {
        const loop = EventLoop{ .fd = -1, .backend = backend };
        try std.testing.expectEqual(backend, Backend.parse(loop.backendName()).?);
    }
}

test "explicitly requested platform-default backend initializes" {
    const expected = try detectBackend();
    var loop = try EventLoop.initBackend(std.testing.allocator, expected, .{});
    defer loop.deinit();
    try std.testing.expectEqual(expected, loop.backend);
}

test "explicitly requested backend fails closed when the platform cannot provide it" {
    // #148 fail-closed policy: an operator who names a backend must get a
    // startup error when it is unavailable, never a silent downgrade to the
    // platform default.
    const foreign: Backend = if (builtin.os.tag == .linux) .kqueue else .epoll;
    try std.testing.expectError(
        error.UnsupportedBackendForPlatform,
        EventLoop.initBackend(std.testing.allocator, foreign, .{}),
    );

    if (builtin.os.tag != .linux) {
        try std.testing.expectError(
            error.UnsupportedBackendForPlatform,
            EventLoop.initBackend(std.testing.allocator, .io_uring, .{}),
        );
    }
}

test "io_uring backend fails closed on an unusable ring size" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    try std.testing.expectError(
        error.InvalidIoUringRingSize,
        EventLoop.initBackend(std.testing.allocator, .io_uring, .{ .io_uring_entries = 1 }),
    );
    try std.testing.expectError(
        error.InvalidIoUringRingSize,
        EventLoop.initBackend(std.testing.allocator, .io_uring, .{ .io_uring_entries = max_io_uring_entries + 1 }),
    );
}

/// Build an io_uring-backed loop, or skip. Container seccomp profiles (the
/// Docker default among them) block `io_uring_setup` outright, and kernels
/// older than 5.4 lack `IORING_OP_TIMEOUT`; neither is a defect in this
/// backend, so those cases skip rather than fail.
fn testIoUringLoopOrSkip() !EventLoop {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    return EventLoop.initBackend(std.testing.allocator, .io_uring, .{}) catch |err| switch (err) {
        error.IoUringUnavailable,
        error.IoUringRingAllocationFailed,
        error.IoUringPollAddUnsupported,
        error.IoUringPollRemoveUnsupported,
        error.IoUringTimeoutUnsupported,
        => error.SkipZigTest,
        else => err,
    };
}

test "io_uring event loop reports write readiness" {
    var loop = try testIoUringLoopOrSkip();
    defer loop.deinit();
    const fds = try testSocketPair();
    defer closeFd(fds[0]);
    defer closeFd(fds[1]);

    try loop.add(fds[0], .{ .write = true });
    defer loop.remove(fds[0]) catch {};

    var events: [4]Event = undefined;
    const count = try loop.wait(&events, 50);
    try std.testing.expect(count > 0);
    var saw_write = false;
    for (events[0..count]) |ev| {
        if (ev.fd == fds[0] and ev.writable) saw_write = true;
    }
    try std.testing.expect(saw_write);
}

test "io_uring event loop modify replaces write interest with read interest" {
    var loop = try testIoUringLoopOrSkip();
    defer loop.deinit();
    const fds = try testSocketPair();
    defer closeFd(fds[0]);
    defer closeFd(fds[1]);

    try loop.add(fds[0], .{ .write = true });
    defer loop.remove(fds[0]) catch {};
    try loop.modify(fds[0], .{ .read = true });

    // The write poll armed by `add` may already have completed; `modify`
    // re-tokenizes the registration so that stale completion is discarded
    // rather than reported as spurious write readiness.
    var events: [4]Event = undefined;
    try std.testing.expectEqual(@as(usize, 0), try loop.wait(&events, 10));

    try writeFd(fds[1], "x");
    const count = try loop.wait(&events, 50);
    try std.testing.expect(count > 0);
    var saw_read = false;
    var saw_write = false;
    for (events[0..count]) |ev| {
        if (ev.fd != fds[0]) continue;
        saw_read = saw_read or ev.readable;
        saw_write = saw_write or ev.writable;
    }
    try std.testing.expect(saw_read);
    try std.testing.expect(!saw_write);
}

test "io_uring event loop re-arms one-shot polls so readiness persists" {
    var loop = try testIoUringLoopOrSkip();
    defer loop.deinit();
    const fds = try testSocketPair();
    defer closeFd(fds[0]);
    defer closeFd(fds[1]);

    try loop.add(fds[0], .{ .read = true, .write = true });
    defer loop.remove(fds[0]) catch {};
    try writeFd(fds[1], "x");

    // Nothing ever drains fds[0], so a level-triggered poller must keep
    // reporting it. Unlike epoll, a single POLL_ADD completion carries only
    // the mask captured when it fired, so read and write readiness may arrive
    // on separate iterations — but neither may be lost.
    var saw_read = false;
    var saw_write = false;
    var iterations: usize = 0;
    while (iterations < 8 and !(saw_read and saw_write)) : (iterations += 1) {
        var events: [4]Event = undefined;
        const count = try loop.wait(&events, 50);
        for (events[0..count]) |ev| {
            if (ev.fd != fds[0]) continue;
            saw_read = saw_read or ev.readable;
            saw_write = saw_write or ev.writable;
        }
    }
    try std.testing.expect(saw_read);
    try std.testing.expect(saw_write);
}

test "io_uring event loop stops reporting a removed fd" {
    var loop = try testIoUringLoopOrSkip();
    defer loop.deinit();
    const fds = try testSocketPair();
    defer closeFd(fds[0]);
    defer closeFd(fds[1]);

    try loop.add(fds[0], .{ .read = true });
    try writeFd(fds[1], "x");

    var events: [4]Event = undefined;
    _ = try loop.wait(&events, 50);

    // This is the un-park path (`removeReadFd`) that keeps a level-triggered
    // backend from re-firing while a worker drains the socket.
    try loop.remove(fds[0]);
    try std.testing.expectEqual(@as(usize, 0), try loop.wait(&events, 20));
    try std.testing.expectEqual(@as(usize, 0), try loop.wait(&events, 20));

    // Removing twice mirrors EPOLL_CTL_DEL's ENOENT.
    try std.testing.expectError(error.Unexpected, loop.remove(fds[0]));
}

test "io_uring event loop re-registers a fd whose number was recycled" {
    var loop = try testIoUringLoopOrSkip();
    defer loop.deinit();
    const fds = try testSocketPair();
    defer closeFd(fds[0]);
    defer closeFd(fds[1]);

    // The keepalive and active-connection reapers close registered fds without
    // unregistering them, because epoll would have dropped the registration on
    // close. Registering the same fd number again must therefore succeed and
    // apply the new interest, not fail the way EPOLL_CTL_ADD's EEXIST would.
    try loop.add(fds[0], .{ .read = true });
    try loop.add(fds[0], .{ .write = true });
    defer loop.remove(fds[0]) catch {};

    var events: [4]Event = undefined;
    const count = try loop.wait(&events, 50);
    try std.testing.expect(count > 0);
    var saw_write = false;
    for (events[0..count]) |ev| {
        if (ev.fd == fds[0] and ev.writable) saw_write = true;
    }
    try std.testing.expect(saw_write);

    // The stale first registration must not survive as a second live poll.
    try loop.remove(fds[0]);
    try std.testing.expectEqual(@as(usize, 0), try loop.wait(&events, 20));
}

fn testSocketPair() ![2]std.posix.fd_t {
    var fds: [2]std.posix.fd_t = undefined;
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const rc = linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &fds);
        if (linux.errno(rc) != .SUCCESS) return error.SocketPairFailed;
    } else {
        if (std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds) != 0) return error.SocketPairFailed;
    }
    errdefer closeFd(fds[0]);
    errdefer closeFd(fds[1]);
    return fds;
}

fn writeFd(fd: std.posix.fd_t, bytes: []const u8) !void {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const rc = linux.write(fd, bytes.ptr, bytes.len);
        if (linux.errno(rc) != .SUCCESS) return error.SocketWriteFailed;
        if (rc != bytes.len) return error.ShortWrite;
        return;
    }
    const rc = std.c.write(fd, bytes.ptr, bytes.len);
    if (rc < 0) return error.SocketWriteFailed;
    if (@as(usize, @intCast(rc)) != bytes.len) return error.ShortWrite;
}

fn closeFd(fd: std.posix.fd_t) void {
    if (builtin.os.tag == .linux) {
        _ = std.os.linux.close(fd);
    } else {
        _ = std.c.close(fd);
    }
}

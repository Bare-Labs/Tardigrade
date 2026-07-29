//! Native HTTP/3 downstream listener runtime (#328).
//!
//! Runs Tardigrade's HTTP/3 endpoint entirely on the native Zig QUIC/H3
//! stack: the connection driver in `src/quic/connection.zig` plus the H3
//! session glue in `src/http3/conn.zig`. One background thread owns one UDP
//! socket, routes datagrams to connections by Destination Connection ID,
//! schedules wakeups from the drivers' timer deadlines, and bridges decoded
//! requests to the gateway's `RequestHandler`.
//!
//! ngtcp2/nghttp3 are gone from the build (#328); they remain available only
//! as out-of-process interop peers under `scripts/interop/`.
//!
//! TLS identity: the runtime owns no certificate or key material. It borrows
//! a provider-neutral `tls_core.credentials.CredentialProvider` from the
//! composition root (#392) — the same provider instance that authenticates
//! native TCP TLS — and hands it to each accepted QUIC connection's TLS
//! backend. Without a provider the QUIC listener stays unbootstrapped with a
//! logged warning while TCP continues to serve.

const compat = @import("zig_compat");
const std = @import("std");
const early_data_policy = @import("early_data.zig");
const http3_session = @import("http3_session.zig");
const logger_mod = @import("logger.zig");
const metrics_mod = @import("metrics.zig");
const response_mod = @import("response.zig");
const shutdown = @import("shutdown.zig");
const stream_transport = @import("stream_transport");
const quic = @import("quic");
const http3 = @import("http3");
const tls_core = @import("tls_core");

const Connection = quic.connection.Connection;
const H3 = http3.conn.Conn(Connection);
const posix = std.posix;

pub const StreamRequest = http3_session.StreamRequest;
pub const Response = response_mod.Response;
pub const Logger = logger_mod.Logger;

pub const Http3RuntimeError = error{
    OutOfMemory,
    DependencyUnavailable,
    NotYetImplemented,
    BindFailed,
    TlsBootstrapFailed,
    InvalidH3Settings,
};

pub const RequestHandler = *const fn (
    allocator: std.mem.Allocator,
    request: *const http3_session.StreamRequest,
    response: *response_mod.Response,
    user_data: ?*anyopaque,
) anyerror!void;

pub const Config = struct {
    listen_host: []const u8,
    quic_port: u16,
    /// Borrowed local credential provider shared with the TCP TLS path. The
    /// owner must outlive this runtime and every QUIC connection it accepts.
    credential_provider: ?tls_core.credentials.CredentialProvider = null,
    /// #488: borrowed process-shared native resumption runtime, shared with
    /// the native TCP TLS path. `null` (the default) leaves resumption
    /// fully disabled for QUIC/H3: no resolver is installed on any accepted
    /// connection and no ticket is ever issued.
    resumption_runtime: ?*tls_core.resumption_runtime.Runtime = null,
    /// #368 Slice 2: borrowed process-shared anti-replay gate, the same
    /// instance shared with the native TCP TLS path — installed
    /// independently of `resumption_runtime` on every accepted connection's
    /// backend so QUIC/H3 can never fall back to worker-local replay
    /// bookkeeping. `null` (the default) leaves the backend's own default
    /// gate in place, which fails closed (`.unavailable`) for 0-RTT.
    early_data_replay_gate: ?tls_core.tls13_backend.EarlyDataReplayGate = null,
    tls_min_version: []const u8 = "1.3",
    tls_max_version: []const u8 = "1.3",
    enable_0rtt: bool = false,
    h3_settings: http3.frame.Settings = .{},
    connection_migration: bool = false,
    retry_policy: quic.config.RetryPolicy = .off,
    max_datagram_size: usize = 1350,
    request_handler: ?RequestHandler = null,
    request_handler_ctx: ?*anyopaque = null,
    early_data_compat_metrics_ctx: ?*anyopaque = null,
    early_data_compat_metrics_cb: ?*const fn (*anyopaque, metrics_mod.H3EarlyDataCompatDecision) void = null,
    /// #523: the QUIC/H3 server's authoritative 0-RTT accept/reject decision
    /// (`quic.connection.Event.early_data_decision`), bridged out of every
    /// accepted connection's `EventSink`. `null` (the default) leaves the
    /// event unobserved — never silently required.
    quic_early_data_decision_metrics_ctx: ?*anyopaque = null,
    quic_early_data_decision_metrics_cb: ?*const fn (*anyopaque, metrics_mod.QuicEarlyDataDecision) void = null,
    /// #523: per-packet 0-RTT authentication/admission outcomes
    /// (`quic.connection.Event.zero_rtt_packet`), bridged the same way.
    quic_zero_rtt_packet_metrics_ctx: ?*anyopaque = null,
    quic_zero_rtt_packet_metrics_cb: ?*const fn (*anyopaque, metrics_mod.QuicZeroRttPacketOutcome) void = null,
};

/// Half-open admission limits (#328 review). The native stack does not send
/// Retry, so an off-path spoofer can forge Initial packets. Rather than
/// implement address validation now, we bound the state a spoofer can pin: a
/// global connection cap, a per-source-IP cap, immediate teardown of an Initial
/// that authenticates nothing, and a handshake deadline well under the idle
/// timeout so half-open connections are reaped promptly.
const max_connections: usize = 1024;
const max_connections_per_source: u32 = 32;
const handshake_timeout_us: u64 = 10 * std.time.us_per_s;
const cid_generation_retries: usize = 16;

const ParkedH3Retry = struct {
    stream_id: u64,
    continuation: http3_session.StreamRequest.Early425RetryContinuation,

    fn deinit(self: *ParkedH3Retry, allocator: std.mem.Allocator) void {
        self.continuation.deinit(allocator);
        self.* = undefined;
    }
};

pub const Snapshot = struct {
    quic_port: u16 = 0,
    server_bootstrapped: bool = false,
    datagrams_seen: usize = 0,
    bytes_seen: usize = 0,
    zero_rtt_packets_seen: usize = 0,
    tracked_connections: usize = 0,
    native_connections: usize = 0,
    native_reads_attempted: usize = 0,
    native_read_calls: usize = 0,
    handshakes_completed: usize = 0,
    stream_bytes_received: usize = 0,
    stream_chunks_received: usize = 0,
    requests_completed: usize = 0,
    packets_emitted: usize = 0,
    bytes_emitted: usize = 0,
    migration_events: usize = 0,
    retry_packets_sent: usize = 0,
    retry_tokens_accepted: usize = 0,
    invalid_tokens: usize = 0,
    path_challenges_sent: usize = 0,
    path_validations_succeeded: usize = 0,
    path_validations_failed: usize = 0,
    path_response_mismatches: usize = 0,
    nat_rebindings: usize = 0,
    migrations: usize = 0,
    migrations_blocked: usize = 0,
    migrations_blocked_no_peer_cid: usize = 0,
    last_error_code: i32 = 0,

    pub fn handshakeState(self: Snapshot) []const u8 {
        if (!self.server_bootstrapped) return "bootstrap_incomplete";
        if (self.handshakes_completed > 0) return "complete";
        if (self.native_connections > 0) return "connection_created";
        if (self.datagrams_seen > 0) return "datagram_seen";
        return "idle";
    }
};

/// One accepted QUIC connection with its HTTP/3 session state.
const ConnEntry = struct {
    backend: *quic.tls_backend.Tls13Backend,
    conn: *Connection,
    h3: H3,
    h3_started: bool = false,
    /// Source IPv4 address of the Initial that opened the connection,
    /// immutable for the connection's lifetime. Used only for half-open
    /// admission accounting (increment/decrement/teardown) — never for
    /// routing egress, since the active path can now change and every
    /// `pollTransmitOnPath` datagram already carries its own destination.
    admission_source_ip: u32,
    cid_len: usize,
    /// Monotonic microseconds when the connection was accepted; used to reap
    /// connections that never complete the handshake.
    accepted_at_us: u64,
    owned_cids: [quic.cid.max_local_active_cids]quic.cid.ConnectionId = undefined,
    owned_cid_count: usize = 0,
    /// Set exactly once this connection has attempted post-handshake ticket
    /// issuance (successfully or not) — issuance is best-effort and must
    /// never be retried on the same connection (#488).
    ticket_issue_attempted: bool = false,
    last_path_metrics: quic.path.Metrics = .{},
    parked_h3_retries: std.ArrayList(ParkedH3Retry) = .empty,

    fn deinit(self: *ConnEntry, allocator: std.mem.Allocator) void {
        for (self.parked_h3_retries.items) |*parked| parked.deinit(allocator);
        self.parked_h3_retries.deinit(allocator);
        self.h3.deinit();
        self.conn.deinit();
        allocator.destroy(self.backend);
    }
};

pub const Runtime = struct {
    allocator: std.mem.Allocator,
    socket_fd: std.c.fd_t,
    thread: ?std.Thread,
    logger: *logger_mod.Logger,
    quic_port: u16,
    /// The actually-bound local UDP address (`getsockname` semantics), used
    /// as every connection's and `PathKey`'s local half. Resolved once at
    /// bind time so a `quic_port = 0` (OS-assigned ephemeral port) test still
    /// gets a real, routable local address instead of the requested `0`.
    local_address: quic.udp.Address,
    request_handler: ?RequestHandler,
    request_handler_ctx: ?*anyopaque,
    credential_provider: ?tls_core.credentials.CredentialProvider,
    resumption_runtime: ?*tls_core.resumption_runtime.Runtime,
    early_data_replay_gate: ?tls_core.tls13_backend.EarlyDataReplayGate,
    /// #523: whether the native QUIC 0-RTT carrier is actually composed and
    /// enabled — see `zeroRttCarrierEnabled`. Drives both `quic_config`'s
    /// `zero_rtt_enabled` gate and whether `accept()` installs a server
    /// early-data policy on new connections' TLS backends.
    zero_rtt_enabled: bool,
    retry_policy: quic.config.RetryPolicy,
    retry_tokens: quic.path.RetryTokens,
    stateless_reset_key: [32]u8,
    quic_config: quic.config.Config,
    h3_settings: http3.frame.Settings,
    h3_application_compat: [http3.early_data.encoded_snapshot_len]u8 = undefined,
    h3_application_compat_len: usize = 0,
    early_data_compat_metrics_ctx: ?*anyopaque = null,
    early_data_compat_metrics_cb: ?*const fn (*anyopaque, metrics_mod.H3EarlyDataCompatDecision) void = null,
    quic_early_data_decision_metrics_ctx: ?*anyopaque = null,
    quic_early_data_decision_metrics_cb: ?*const fn (*anyopaque, metrics_mod.QuicEarlyDataDecision) void = null,
    quic_zero_rtt_packet_metrics_ctx: ?*anyopaque = null,
    quic_zero_rtt_packet_metrics_cb: ?*const fn (*anyopaque, metrics_mod.QuicZeroRttPacketOutcome) void = null,
    snapshot_mutex: compat.Mutex = .{},
    snapshot_state: Snapshot,
    stopping: std.atomic.Value(bool),

    pub fn init(allocator: std.mem.Allocator, logger: *logger_mod.Logger, cfg: Config) Http3RuntimeError!Runtime {
        const address = compat.parseIpAddress(cfg.listen_host, cfg.quic_port) catch |err| {
            logger.warn(null, "http3: listen address parse failed: {s}", .{@errorName(err)});
            return error.BindFailed;
        };
        const sa_family = @as(*const std.c.sockaddr, @ptrCast(&address.storage)).family;
        const fd = openUdpSocket(sa_family);
        if (fd < 0) return error.BindFailed;
        errdefer _ = std.c.close(fd);

        posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&@as(c_int, 1))) catch {}; // REUSEADDR is advisory; bind proceeds regardless
        const bind_rc = std.c.bind(fd, @ptrCast(&address.storage), @intCast(address.len));
        if (bind_rc != 0) {
            logger.warn(null, "http3: udp bind failed: {s}", .{@tagName(posix.errno(bind_rc))});
            return error.BindFailed;
        }

        // Resolve the actually-bound local address/port (`getsockname`): with
        // `quic_port = 0` the OS assigns an ephemeral port only known now.
        var local_address = quic.udp.Address.ip4(.{ 0, 0, 0, 0 }, cfg.quic_port);
        if (sa_family == posix.AF.INET) {
            var bound: std.c.sockaddr.in = undefined;
            var bound_len: std.c.socklen_t = @sizeOf(std.c.sockaddr.in);
            if (std.c.getsockname(fd, @ptrCast(&bound), &bound_len) == 0) {
                local_address = addressFromSockaddrIn(bound);
            }
        }

        var runtime = Runtime{
            .allocator = allocator,
            .socket_fd = fd,
            .thread = null,
            .logger = logger,
            .quic_port = cfg.quic_port,
            .local_address = local_address,
            .request_handler = cfg.request_handler,
            .request_handler_ctx = cfg.request_handler_ctx,
            .credential_provider = cfg.credential_provider,
            .resumption_runtime = cfg.resumption_runtime,
            .early_data_replay_gate = cfg.early_data_replay_gate,
            .zero_rtt_enabled = zeroRttCarrierEnabled(cfg),
            .retry_policy = cfg.retry_policy,
            .retry_tokens = .{},
            .stateless_reset_key = undefined,
            .quic_config = quicConfigFrom(cfg),
            .h3_settings = cfg.h3_settings,
            .early_data_compat_metrics_ctx = cfg.early_data_compat_metrics_ctx,
            .early_data_compat_metrics_cb = cfg.early_data_compat_metrics_cb,
            .quic_early_data_decision_metrics_ctx = cfg.quic_early_data_decision_metrics_ctx,
            .quic_early_data_decision_metrics_cb = cfg.quic_early_data_decision_metrics_cb,
            .quic_zero_rtt_packet_metrics_ctx = cfg.quic_zero_rtt_packet_metrics_ctx,
            .quic_zero_rtt_packet_metrics_cb = cfg.quic_zero_rtt_packet_metrics_cb,
            .snapshot_state = .{ .quic_port = cfg.quic_port },
            .stopping = std.atomic.Value(bool).init(false),
        };
        var retry_key: [quic.path.token_key_len]u8 = undefined;
        compat.randomBytes(&retry_key);
        runtime.retry_tokens.keys.install(0, retry_key);
        compat.randomBytes(&runtime.stateless_reset_key);
        http3.frame.validateLocallySupportedSettings(runtime.h3_settings) catch return error.InvalidH3Settings;
        runtime.h3_application_compat_len = (http3.early_data.encodeSettingsSnapshot(
            runtime.h3_settings,
            &runtime.h3_application_compat,
        ) catch return error.InvalidH3Settings).len;

        if (cfg.enable_0rtt and !runtime.zero_rtt_enabled) {
            logger.warn(null, "http3: enable_0rtt requires both resumption_runtime and early_data_replay_gate to be configured; continuing with 0-RTT disabled", .{});
        }
        if (cfg.retry_policy == .address_validation) {
            logger.info(null, "http3: QUIC Retry address validation enabled", .{});
        }
        if (!std.mem.eql(u8, cfg.tls_min_version, "1.3") or !std.mem.eql(u8, cfg.tls_max_version, "1.3")) {
            logger.warn(null, "http3: native QUIC requires TLS 1.3; ignoring tls_min_version={s}/tls_max_version={s}", .{ cfg.tls_min_version, cfg.tls_max_version });
        }
        if (cfg.credential_provider == null) {
            logger.warn(null, "http3: no TLS credential provider configured; QUIC bootstrap incomplete.", .{});
        }
        runtime.snapshot_state.server_bootstrapped = runtime.credential_provider != null;
        return runtime;
    }

    pub fn start(self: *Runtime) void {
        if (self.thread != null) return;
        self.thread = std.Thread.spawn(.{}, loopMain, .{self}) catch null;
    }

    pub fn deinit(self: *Runtime) void {
        self.stopping.store(true, .release);
        if (self.thread) |thread| thread.join();
        _ = std.c.close(self.socket_fd);
        self.* = undefined;
    }

    pub fn snapshot(self: *Runtime) Snapshot {
        self.snapshot_mutex.lock();
        defer self.snapshot_mutex.unlock();
        return self.snapshot_state;
    }

    fn nowUs() u64 {
        var ts: std.c.timespec = undefined;
        _ = std.c.clock_gettime(.MONOTONIC, &ts);
        return @as(u64, @intCast(ts.sec)) * 1_000_000 + @as(u64, @intCast(ts.nsec)) / 1_000;
    }

    fn loopMain(self: *Runtime) void {
        self.serve() catch |err| {
            self.logger.warn(null, "http3: listener loop terminated: {s}", .{@errorName(err)});
        };
    }

    fn serve(self: *Runtime) !void {
        const allocator = self.allocator;
        var connections = std.AutoHashMap(u64, *ConnEntry).init(allocator);
        var routes = quic.cid.CidRoutingTable.init(allocator);
        // Half-open admission accounting, keyed on the source IPv4 address.
        var per_ip = std.AutoHashMap(u32, u32).init(allocator);
        var next_handle: u64 = 1;
        defer {
            var it = connections.valueIterator();
            while (it.next()) |entry| {
                entry.*.deinit(allocator);
                allocator.destroy(entry.*);
            }
            connections.deinit();
            routes.deinit();
            per_ip.deinit();
        }

        while (!self.stopping.load(.acquire) and !shutdown.isShutdownRequested()) {
            const now = nowUs();

            // 1) Timers and transmission for every connection.
            var wake_us: u64 = now + 100_000;
            {
                var out: [2048]u8 = undefined;
                var reap: [16]u64 = undefined;
                var reap_count: usize = 0;
                var it = connections.iterator();
                while (it.next()) |kv| {
                    const entry = kv.value_ptr.*;
                    entry.conn.onTimeout(now);
                    self.syncCidRoutes(entry, &routes);
                    self.maintainLocalCidRoutes(entry, kv.key_ptr.*, &routes);
                    self.foldPathMetrics(entry);
                    while (entry.conn.pollTransmitOnPath(&out, now)) |t| {
                        self.sendDatagram(sockaddrInFromAddress(t.path.remote), t.bytes);
                    }
                    self.pumpH3(entry, now);
                    while (entry.conn.pollTransmitOnPath(&out, now)) |t| {
                        self.sendDatagram(sockaddrInFromAddress(t.path.remote), t.bytes);
                    }
                    // Reap closed connections and half-open connections that
                    // blew the handshake deadline (spoofed/stalled Initials).
                    const stalled = !entry.conn.isEstablished() and now -| entry.accepted_at_us > handshake_timeout_us;
                    if (entry.conn.state() == .closed or stalled) {
                        if (reap_count < reap.len) {
                            reap[reap_count] = kv.key_ptr.*;
                            reap_count += 1;
                        }
                        continue;
                    }
                    if (entry.conn.nextTimeoutUs()) |deadline| wake_us = @min(wake_us, deadline);
                }
                for (reap[0..reap_count]) |handle| {
                    self.removeConnection(&connections, &routes, &per_ip, handle);
                }
            }

            // 2) Sleep until the earliest deadline or socket readability.
            const timeout_ms: i32 = @intCast(@min((wake_us -| nowUs()) / 1_000 + 1, 100));
            var fds = [_]posix.pollfd{
                .{ .fd = self.socket_fd, .events = posix.POLL.IN, .revents = 0 },
            };
            _ = posix.poll(&fds, timeout_ms) catch {};

            // 3) Ingest every waiting datagram.
            var buf: [2048]u8 = undefined;
            var from: std.c.sockaddr.storage = undefined;
            while (true) {
                var from_len: std.c.socklen_t = @sizeOf(std.c.sockaddr.storage);
                const n = std.c.recvfrom(self.socket_fd, &buf, buf.len, 0, @ptrCast(&from), &from_len);
                if (n < 0) {
                    const e = posix.errno(n);
                    if (e == .AGAIN) break;
                    if (e == .CONNREFUSED or e == .CONNRESET) continue;
                    break;
                }
                if (n == 0) continue;
                const datagram = buf[0..@intCast(n)];
                if (from.family != posix.AF.INET) continue;
                const peer: *const std.c.sockaddr.in = @ptrCast(&from);
                self.ingest(&connections, &routes, &per_ip, &next_handle, datagram, peer.*, nowUs());
            }
        }
    }

    fn ingest(
        self: *Runtime,
        connections: *std.AutoHashMap(u64, *ConnEntry),
        routes: *quic.cid.CidRoutingTable,
        per_ip: *std.AutoHashMap(u32, u32),
        next_handle: *u64,
        datagram: []const u8,
        peer: std.c.sockaddr.in,
        now: u64,
    ) void {
        self.noteDatagram(datagram.len);

        // Route by DCID. Long headers carry the DCID length; short headers
        // need the connection's own CID length, which the client chose per
        // connection — try each active length.
        var handle: ?u64 = null;
        var freshly_accepted = false;
        if (datagram.len > 0 and datagram[0] & 0x80 != 0) {
            if (quic.packet.parsePacket(datagram, 0)) |parsed| {
                handle = routes.lookup(parsed.dcid);
                if (handle == null and parsed.kind == .initial) {
                    handle = self.accept(connections, routes, per_ip, next_handle, parsed, peer, now);
                    freshly_accepted = handle != null;
                }
                if (parsed.kind == .zero_rtt) self.noteZeroRtt();
            } else |_| {
                return;
            }
        } else {
            var it = connections.iterator();
            while (it.next()) |kv| {
                const entry = kv.value_ptr.*;
                if (datagram.len < 1 + entry.cid_len) continue;
                if (routes.lookup(datagram[1..][0..entry.cid_len])) |found| {
                    handle = found;
                    break;
                }
            }
        }
        const found = handle orelse return;
        const entry = connections.get(found) orelse return;

        const was_established = entry.conn.isEstablished();
        // `packets_received` only advances after AEAD open succeeds, so its
        // delta tells us whether this datagram authenticated — without trusting
        // its source address.
        const packets_before = entry.conn.metrics.packets_received;
        // The path this datagram claims to arrive on. Unauthenticated packets
        // never create path state or move the active path (`ingestOnPath`
        // only credits/classifies post-AEAD), so recording it before ingest
        // is safe regardless of whether it turns out spoofed.
        const active_before = entry.conn.activePathKey();
        const ingress_remote = addressFromSockaddrIn(peer);
        const ingress_path = quic.path.PathKey{ .local = self.local_address, .remote = ingress_remote };
        var challenge_entropy: [quic.path.path_challenge_len]u8 = undefined;
        compat.randomBytes(&challenge_entropy);
        entry.conn.ingestOnPath(datagram, ingress_path, challenge_entropy, now) catch {
            if (freshly_accepted) self.removeConnection(connections, routes, per_ip, found);
            return;
        };
        self.syncCidRoutes(entry, routes);
        self.maintainLocalCidRoutes(entry, found, routes);
        self.foldPathMetrics(entry);
        const authenticated = entry.conn.metrics.packets_received > packets_before;
        switch (classifyIngest(freshly_accepted, authenticated, !active_before.remote.eql(ingress_remote))) {
            // A just-accepted connection whose first datagram authenticates
            // nothing is an unsolicited or spoofed Initial: drop the half-open
            // state now instead of holding it until the handshake deadline.
            .drop_unauthenticated => {
                self.removeConnection(connections, routes, per_ip, found);
                return;
            },
            // `Connection` owns migration validation; runtime counters fold
            // authoritative validated outcomes from `PathManager` metrics.
            .migrated => {},
            .keep => {},
        }

        if (!was_established and entry.conn.isEstablished()) {
            self.noteHandshakeComplete();
        }
        self.maybeIssueSessionTicket(entry);

        var out: [2048]u8 = undefined;
        while (entry.conn.pollTransmitOnPath(&out, now)) |t| {
            self.sendDatagram(sockaddrInFromAddress(t.path.remote), t.bytes);
        }
        self.pumpH3(entry, now);
        while (entry.conn.pollTransmitOnPath(&out, now)) |t| {
            self.sendDatagram(sockaddrInFromAddress(t.path.remote), t.bytes);
        }
    }

    fn accept(
        self: *Runtime,
        connections: *std.AutoHashMap(u64, *ConnEntry),
        routes: *quic.cid.CidRoutingTable,
        per_ip: *std.AutoHashMap(u32, u32),
        next_handle: *u64,
        parsed: quic.packet.ParsedPacket,
        peer: std.c.sockaddr.in,
        now: u64,
    ) ?u64 {
        const credential_provider = self.credential_provider orelse return null;
        if (parsed.dcid.len < 8 or parsed.scid.len == 0) return null;
        const retry_context: ?quic.path.RetryContext = switch (self.classifyRetry(routes, parsed, peer, now)) {
            .accept_unvalidated => null,
            .accept_validated => |ctx| ctx,
            .drop => return null,
        };
        // Bound half-open state before allocating anything for this Initial.
        if (!admissionAllowed(connections.count(), per_ip.get(peer.addr) orelse 0)) return null;
        const allocator = self.allocator;

        const backend = allocator.create(quic.tls_backend.Tls13Backend) catch return null;
        var entropy: quic.tls_backend.Entropy = undefined;
        compat.randomBytes(&entropy.hello_random);
        compat.randomBytes(&entropy.key_share_seed);
        backend.* = quic.tls_backend.Tls13Backend.initServerWithProvider(entropy, credential_provider);
        // #488: install the same process-shared server resolver used by
        // native TCP, before the handshake can start — `Connection.init`
        // below arms the responder.
        if (self.resumption_runtime) |runtime| {
            backend.setResumeCompatibilityPolicy(.{ .transport = .ignore, .application = .ignore }) catch {
                allocator.destroy(backend);
                return null;
            };
            backend.setEarlyDataApplicationCompat(.{
                .format_id = http3.early_data.format_id,
                .format_version = http3.early_data.format_version,
                .bytes = self.h3_application_compat[0..self.h3_application_compat_len],
            }) catch {
                allocator.destroy(backend);
                return null;
            };
            backend.setEarlyDataCompatibilityGate(.{
                .ctx = self,
                .decideFn = h3EarlyDataCompatibility,
            }) catch {
                allocator.destroy(backend);
                return null;
            };
            backend.setResumptionDecisionObserver(runtime.backendDecisionObserver(.quic)) catch {
                allocator.destroy(backend);
                return null;
            };
            if (runtime.serverResolver()) |resolver| {
                backend.setServerPskResolver(resolver) catch {
                    allocator.destroy(backend);
                    return null;
                };
            }
        }
        // #368 Slice 2: independent of `resumption_runtime` above — the
        // same process-scoped replay store shared with every native TCP
        // worker, not a per-connection or per-protocol concern.
        if (self.early_data_replay_gate) |gate| {
            backend.setEarlyDataReplayGate(gate) catch {
                allocator.destroy(backend);
                return null;
            };
            // #523: only actually enable the server's early-data accept path
            // once composition confirmed a resumption runtime, replay gate,
            // and the QUIC carrier are all present (`zeroRttCarrierEnabled`)
            // — mirrors `native_tls_connection.zig`'s identical gate for TCP.
            if (self.zero_rtt_enabled) {
                backend.setServerEarlyDataPolicy(.{ .enabled = true }) catch {
                    allocator.destroy(backend);
                    return null;
                };
            }
        }

        const conn = Connection.init(allocator, .{
            .role = .server,
            .config = self.quic_config,
            .local_cid = parsed.dcid,
            .original_destination_cid = if (retry_context) |ctx| ctx.original_dcid.slice() else parsed.dcid,
            .retry_source_cid = if (retry_context) |ctx| ctx.retry_scid.slice() else null,
            .initial_secret_dcid = if (retry_context) |ctx| ctx.retry_scid.slice() else parsed.dcid,
            .peer_cid = parsed.scid,
            .tls = backend.backend(),
            .now_us = now,
            .initial_path = .{ .local = self.local_address, .remote = addressFromSockaddrIn(peer) },
            .initial_address_validated = retry_context != null,
            .stateless_reset_key = self.stateless_reset_key,
            .events = .{ .context = self, .emitFn = quicConnectionEvent },
        }) catch {
            allocator.destroy(backend);
            return null;
        };

        const entry = allocator.create(ConnEntry) catch {
            conn.deinit();
            allocator.destroy(backend);
            return null;
        };
        entry.* = .{
            .backend = backend,
            .conn = conn,
            .h3 = H3.initWithSettings(allocator, .server, self.h3_settings),
            .admission_source_ip = peer.addr,
            .cid_len = parsed.dcid.len,
            .accepted_at_us = now,
        };

        const handle = next_handle.*;
        next_handle.* += 1;
        const cid = quic.cid.ConnectionId.init(parsed.dcid) catch {
            entry.deinit(allocator);
            allocator.destroy(entry);
            return null;
        };
        entry.owned_cids[0] = cid;
        entry.owned_cid_count = 1;
        routes.insert(cid, handle) catch {
            entry.deinit(allocator);
            allocator.destroy(entry);
            return null;
        };
        connections.put(handle, entry) catch {
            routes.remove(cid);
            entry.deinit(allocator);
            allocator.destroy(entry);
            return null;
        };
        incPerIp(per_ip, peer.addr) catch {
            _ = connections.remove(handle);
            routes.remove(cid);
            entry.deinit(allocator);
            allocator.destroy(entry);
            return null;
        };
        self.noteConnectionAccepted();
        if (retry_context != null) self.noteRetryTokenAccepted();
        return handle;
    }

    const RetryAcceptDecision = union(enum) {
        accept_unvalidated,
        accept_validated: quic.path.RetryContext,
        drop,
    };

    fn classifyRetry(
        self: *Runtime,
        routes: *quic.cid.CidRoutingTable,
        parsed: quic.packet.ParsedPacket,
        peer: std.c.sockaddr.in,
        now: u64,
    ) RetryAcceptDecision {
        if (self.retry_policy == .off) {
            return if (parsed.version == quic.packet.quic_v1) .accept_unvalidated else .drop;
        }
        const remote = addressFromSockaddrIn(peer);
        if (parsed.token.len == 0) {
            if (parsed.version != quic.packet.quic_v1) return .drop;
            self.issueRetry(routes, parsed, peer, remote, now);
            return .drop;
        }
        const ctx = self.retry_tokens.validateRetry(parsed.token, remote, now) catch {
            self.noteInvalidToken();
            self.logger.info(null, "http3: rejected invalid QUIC Retry token", .{});
            return .drop;
        };
        if (parsed.version != quic.packet.quic_v1 or ctx.quic_version != parsed.version or !std.mem.eql(u8, parsed.dcid, ctx.retry_scid.slice())) {
            self.noteInvalidToken();
            self.logger.info(null, "http3: rejected QUIC Retry token with mismatched version or Retry SCID", .{});
            return .drop;
        }
        return .{ .accept_validated = ctx };
    }

    fn issueRetry(
        self: *Runtime,
        routes: *quic.cid.CidRoutingTable,
        parsed: quic.packet.ParsedPacket,
        peer: std.c.sockaddr.in,
        remote: quic.udp.Address,
        now: u64,
    ) void {
        const retry_scid = self.generateRetryScid(routes, parsed.dcid.len, parsed.dcid) orelse return;
        var nonce: [quic.path.token_nonce_len]u8 = undefined;
        compat.randomBytes(&nonce);
        var token_buf: [quic.path.max_token_len]u8 = undefined;
        const token = self.retry_tokens.issueRetry(parsed.dcid, retry_scid.slice(), parsed.version, remote, now, nonce, &token_buf) catch return;
        var retry_buf: [512]u8 = undefined;
        const retry = quic.packet.writeRetryV1(parsed.dcid, parsed.scid, retry_scid.slice(), token, &retry_buf) catch return;
        self.sendDatagram(peer, retry);
        self.noteRetryPacketSent();
        self.logger.info(null, "http3: issued QUIC Retry for unvalidated Initial", .{});
    }

    fn generateRetryScid(self: *Runtime, routes: *quic.cid.CidRoutingTable, cid_len: usize, original_dcid: []const u8) ?quic.cid.ConnectionId {
        _ = self;
        var entropy: [quic.udp.MaxConnectionIdLen]u8 = undefined;
        for (0..cid_generation_retries) |_| {
            compat.randomBytes(&entropy);
            const candidate = quic.cid.generateCid(&entropy, @intCast(cid_len)) catch return null;
            if (std.mem.eql(u8, candidate.slice(), original_dcid)) continue;
            if (routes.contains(candidate)) continue;
            return candidate;
        }
        return null;
    }

    /// Remove a tracked connection: drop its CID route, release its per-source
    /// admission slot, and free its state. Safe to call with a stale handle.
    fn removeConnection(
        self: *Runtime,
        connections: *std.AutoHashMap(u64, *ConnEntry),
        routes: *quic.cid.CidRoutingTable,
        per_ip: *std.AutoHashMap(u32, u32),
        handle: u64,
    ) void {
        if (connections.fetchRemove(handle)) |kv| {
            for (kv.value.owned_cids[0..kv.value.owned_cid_count]) |cid| routes.remove(cid);
            decPerIp(per_ip, kv.value.admission_source_ip);
            kv.value.deinit(self.allocator);
            self.allocator.destroy(kv.value);
            self.noteConnectionClosed();
        }
    }

    fn syncCidRoutes(self: *Runtime, entry: *ConnEntry, routes: *quic.cid.CidRoutingTable) void {
        _ = self;
        var active: [quic.cid.max_local_active_cids]quic.cid.ConnectionId = undefined;
        const active_count = entry.conn.copyActiveLocalCids(&active);
        var i: usize = 0;
        while (i < entry.owned_cid_count) {
            if (!cidSliceContains(active[0..active_count], entry.owned_cids[i])) {
                routes.remove(entry.owned_cids[i]);
                entry.owned_cids[i] = entry.owned_cids[entry.owned_cid_count - 1];
                entry.owned_cid_count -= 1;
                continue;
            }
            i += 1;
        }
    }

    fn maintainLocalCidRoutes(self: *Runtime, entry: *ConnEntry, handle: u64, routes: *quic.cid.CidRoutingTable) void {
        _ = self;
        while (entry.conn.needsLocalCid() and entry.owned_cid_count < entry.owned_cids.len) {
            var cid_value: ?quic.cid.ConnectionId = null;
            var entropy: [quic.udp.MaxConnectionIdLen]u8 = undefined;
            for (0..cid_generation_retries) |_| {
                compat.randomBytes(&entropy);
                const candidate = quic.cid.generateCid(&entropy, @intCast(entry.cid_len)) catch return;
                if (routes.contains(candidate)) continue;
                cid_value = candidate;
                break;
            }
            const cid = cid_value orelse return;
            switch (registerLocalCidRoute(entry, handle, routes, cid)) {
                .registered => {},
                .collision => continue,
                .queue_failed => return,
            }
        }
    }

    const RegisterLocalCidRouteResult = enum {
        registered,
        collision,
        queue_failed,
    };

    fn registerLocalCidRoute(entry: *ConnEntry, handle: u64, routes: *quic.cid.CidRoutingTable, cid: quic.cid.ConnectionId) RegisterLocalCidRouteResult {
        routes.insert(cid, handle) catch |err| switch (err) {
            error.CidCollision => return .collision,
            error.OutOfMemory => return .queue_failed,
        };
        entry.conn.advertiseLocalCid(cid) catch {
            routes.remove(cid);
            return .queue_failed;
        };
        entry.owned_cids[entry.owned_cid_count] = cid;
        entry.owned_cid_count += 1;
        return .registered;
    }

    fn pumpH3(self: *Runtime, entry: *ConnEntry, now: u64) void {
        const established = entry.conn.isEstablished();
        // The control stream/SETTINGS flight only ever goes out once
        // established — QUIC packet building itself already refuses to
        // transmit any `.application`-space frame before `self.state_ ==
        // .established` (see `buildPacket`), so this is establishment-only
        // by construction, not just by this early return.
        if (established and !entry.h3_started) {
            entry.h3.start(entry.conn) catch return;
            entry.h3_started = true;
        }
        // #523: accepted 0-RTT STREAM bytes must reach H3 during the
        // early-data window, not sit unread until the handshake completes —
        // otherwise the replay-safe/425 request-safety decision never runs
        // as early data at all. Safe to pump pre-establishment even for an
        // ordinary (non-0-RTT) connection: `acceptStream`/`readStream` are
        // no-ops until something actually populated the stream layer, and
        // any response `serveRequest` queues still can't reach the wire
        // until `.application` packet building unlocks at establishment.
        if (!established and !self.zero_rtt_enabled) return;
        entry.h3.pump(entry.conn) catch |err| {
            // An H3-level protocol error closes the connection with the
            // specific RFC 9114 §8.1 code the session layer recorded.
            const code = entry.h3.closeCode();
            self.logger.warn(null, "http3: session error {s} (close code 0x{x}); closing connection", .{ @errorName(err), code });
            entry.conn.close(code, "h3 protocol error", now);
            return;
        };
        self.resumeParkedH3Retries(entry);
        while (true) {
            const incoming = entry.h3.pollRequest() catch {
                entry.conn.close(entry.h3.closeCode(), "h3 request error", now);
                return;
            } orelse break;
            self.serveRequest(entry, incoming, now);
        }
    }

    fn serveRequest(self: *Runtime, entry: *ConnEntry, incoming: H3.IncomingRequest, now: u64) void {
        _ = now;
        const allocator = self.allocator;
        const handler = self.request_handler orelse {
            entry.h3.sendResponse(entry.conn, incoming.stream_id, 404, &.{}, "") catch {};
            return;
        };

        var request = buildStreamRequest(allocator, incoming.exchange) catch {
            entry.h3.sendResponse(entry.conn, incoming.stream_id, 500, &.{}, "") catch {};
            entry.h3.finishRequest(incoming.stream_id);
            return;
        };
        defer request.deinit();
        request.stream_id = incoming.stream_id;
        request.transport_early = incoming.transport_early;
        request.downstream_handshake_complete = entry.conn.isEstablished();
        request.downstream_handshake = .{
            .ctx = entry.conn,
            .is_complete_fn = h3DownstreamHandshakeComplete,
            .wait_or_drive_fn = h3DownstreamWaitOrDriveHandshake,
        };
        var park_ctx = H3ParkContext{ .runtime = self, .entry = entry, .stream_id = incoming.stream_id };
        request.park_early_425_retry = .{
            .ctx = &park_ctx,
            .park_fn = parkH3Early425Retry,
        };

        var response = response_mod.Response.init(allocator);
        defer response.deinit();
        handler(allocator, &request, &response, self.request_handler_ctx) catch |err| {
            if (err == error.Http3RequestParked) return;
            self.logger.warn(null, "http3: request handler failed: {s}", .{@errorName(err)});
            entry.h3.sendResponse(entry.conn, incoming.stream_id, 500, &.{}, "") catch {};
            entry.h3.finishRequest(incoming.stream_id);
            return;
        };

        self.sendHandlerResponse(entry, incoming.stream_id, &response);
    }

    fn resumeParkedH3Retries(self: *Runtime, entry: *ConnEntry) void {
        self.resumeParkedH3RetriesForEntry(entry);
    }

    fn resumeParkedH3RetriesForEntry(self: *Runtime, entry: anytype) void {
        if (!entry.conn.isEstablished()) return;
        self.resumeEstablishedParkedH3Retries(entry);
    }

    fn resumeEstablishedParkedH3Retries(self: *Runtime, entry: anytype) void {
        while (entry.parked_h3_retries.items.len != 0) {
            var parked = entry.parked_h3_retries.orderedRemove(0);
            defer parked.deinit(self.allocator);

            var response = response_mod.Response.init(self.allocator);
            defer response.deinit();
            parked.continuation.run(self.allocator, &response) catch |err| {
                self.logger.warn(null, "http3: parked request retry failed: {s}", .{@errorName(err)});
                self.sendInternalErrorResponse(entry, parked.stream_id);
                continue;
            };
            self.sendHandlerResponse(entry, parked.stream_id, &response);
        }
    }

    fn sendHandlerResponse(self: *Runtime, entry: anytype, stream_id: u64, response: *const response_mod.Response) void {
        var headers_buf: [64]stream_transport.Header = undefined;
        var header_count: usize = 0;
        for (response.headers.iterator()) |header| {
            if (header_count == headers_buf.len) break;
            headers_buf[header_count] = .{ .name = header.name, .value = header.value };
            header_count += 1;
        }
        entry.h3.sendResponse(
            entry.conn,
            stream_id,
            response.status.code(),
            headers_buf[0..header_count],
            response.body orelse "",
        ) catch |err| {
            self.logger.warn(null, "http3: response send failed: {s}", .{@errorName(err)});
            entry.conn.resetStream(stream_id, 0x0102) catch {}; // H3_INTERNAL_ERROR
            entry.h3.finishRequest(stream_id);
            return;
        };
        self.noteRequestCompleted();
    }

    fn sendInternalErrorResponse(self: *Runtime, entry: anytype, stream_id: u64) void {
        entry.h3.sendResponse(entry.conn, stream_id, 500, &.{}, "") catch |err| {
            self.logger.warn(null, "http3: fallback response send failed: {s}", .{@errorName(err)});
            entry.conn.resetStream(stream_id, 0x0102) catch {}; // H3_INTERNAL_ERROR
            entry.h3.finishRequest(stream_id);
            return;
        };
        self.noteRequestCompleted();
    }

    fn sendDatagram(self: *Runtime, peer: std.c.sockaddr.in, datagram: []const u8) void {
        const sent = std.c.sendto(self.socket_fd, datagram.ptr, datagram.len, 0, @ptrCast(&peer), @sizeOf(std.c.sockaddr.in));
        if (sent >= 0 and @as(usize, @intCast(sent)) == datagram.len) {
            self.notePacketOut(datagram.len);
        }
    }

    fn h3DownstreamHandshakeComplete(ctx: *anyopaque) bool {
        const conn: *Connection = @ptrCast(@alignCast(ctx));
        return conn.isEstablished();
    }

    fn h3DownstreamWaitOrDriveHandshake(ctx: *anyopaque) anyerror!void {
        const conn: *Connection = @ptrCast(@alignCast(ctx));
        conn.driveAuthentication(nowUs());
    }

    const H3ParkContext = struct {
        runtime: *Runtime,
        entry: *ConnEntry,
        stream_id: u64,
    };

    fn parkH3Early425Retry(ctx: *anyopaque, continuation: http3_session.StreamRequest.Early425RetryContinuation) anyerror!void {
        const park_ctx: *H3ParkContext = @ptrCast(@alignCast(ctx));
        try park_ctx.entry.parked_h3_retries.append(park_ctx.runtime.allocator, .{
            .stream_id = park_ctx.stream_id,
            .continuation = continuation,
        });
    }

    /// #488: best-effort, exactly-once post-handshake ticket issuance for
    /// this connection. A failure here is swallowed rather than tearing
    /// down an otherwise usable connection — never retried afterward.
    fn maybeIssueSessionTicket(self: *Runtime, entry: *ConnEntry) void {
        if (entry.ticket_issue_attempted) return;
        const runtime = self.resumption_runtime orelse return;
        if (!entry.conn.isEstablished()) return;
        entry.ticket_issue_attempted = true;
        self.issueSessionTicket(entry, runtime) catch |err| {
            runtime.observer.ticketIssue(.quic, runtime.config.mode, switch (err) {
                error.StatefulCapacityRefused => .rejected,
                else => .failed,
            });
            return;
        };
        runtime.observer.ticketIssue(.quic, runtime.config.mode, .success);
    }

    fn issueSessionTicket(self: *Runtime, entry: *ConnEntry, runtime: *tls_core.resumption_runtime.Runtime) !void {
        const allocator = self.allocator;
        const now_unix_ms = runtime.nowUnixMs();

        var ticket_nonce: [8]u8 = undefined;
        try runtime.provider.randomBytes(&ticket_nonce);
        var age_add_bytes: [4]u8 = undefined;
        try runtime.provider.randomBytes(&age_add_bytes);
        const ticket_age_add = std.mem.readInt(u32, &age_add_bytes, .big);

        const limits = runtime.config.session_limits;
        var prepared = try entry.conn.prepareNewSessionTicket(allocator, .{
            .ticket_lifetime = runtime.config.ticket_lifetime_seconds,
            .ticket_age_add = ticket_age_add,
            .ticket_nonce = &ticket_nonce,
            .issued_at_unix_ms = now_unix_ms,
            // RFC 9001 §4.6.1: a QUIC NewSessionTicket that advertises 0-RTT
            // capability carries the fixed sentinel 0xffffffff — QUIC early
            // data isn't bounded by this TLS-record byte cap (that's the
            // job of QUIC flow control and `ServerEarlyDataPolicy`), and
            // the field must be omitted (`null`) entirely when the carrier
            // isn't actually composed, or a client would offer 0-RTT the
            // server can never accept.
            .max_early_data_size = if (self.zero_rtt_enabled) std.math.maxInt(u32) else null,
        }, limits);
        defer prepared.deinit();

        const scratch = try allocator.alloc(u8, runtime.maxIdentityLen());
        defer {
            std.crypto.secureZero(u8, scratch);
            allocator.free(scratch);
        }
        var identity = try runtime.createIdentity(&prepared.state, now_unix_ms, scratch);
        defer identity.deinit();

        entry.conn.emitPreparedNewSessionTicket(&prepared, identity.slice(), limits) catch |err| {
            runtime.rollbackIdentity(&identity);
            return err;
        };
    }

    fn h3EarlyDataCompatibility(ctx: *anyopaque, candidate: tls_core.tls13_backend.EarlyDataCompatibilityCandidate) tls_core.tls13_backend.EarlyDataCompatibilityDecision {
        const self: *Runtime = @ptrCast(@alignCast(ctx));

        // #523: the early-specific gate — deliberately independent of
        // `ResumeCompatibilityPolicy` (`accept()` sets `.transport = .ignore`
        // there so *ordinary* 1-RTT resumption never depends on transport
        // parameters) — is the only owner that may reject *early data
        // specifically* for a remembered QUIC transport snapshot that no
        // longer holds. RFC 9001 §4.6.1: an endpoint that accepts 0-RTT must
        // not have reduced any limit the client's early data would rely on
        // below what was remembered.
        const transport = candidate.remembered_transport orelse {
            self.recordH3EarlyDataCompat(.missing_state);
            return .transport_incompatible;
        };
        if (transport.format_id != quic_transport_parameters_extension_type or
            transport.format_version != quic_transport_parameters_compat_format_version)
        {
            self.recordH3EarlyDataCompat(.transport_incompatible);
            return .transport_incompatible;
        }
        const remembered_transport = quic.tls_backend.decodeTransportParameters(transport.bytes) catch {
            self.recordH3EarlyDataCompat(.transport_incompatible);
            return .transport_incompatible;
        };
        const current_transport = self.quic_config.transportParameters() catch {
            self.recordH3EarlyDataCompat(.transport_incompatible);
            return .transport_incompatible;
        };
        if (!quicEarlyDataTransportCompatible(remembered_transport, current_transport)) {
            self.recordH3EarlyDataCompat(.transport_incompatible);
            return .transport_incompatible;
        }

        const app = candidate.remembered_application orelse {
            self.recordH3EarlyDataCompat(.missing_state);
            return .application_incompatible;
        };

        return switch (http3.early_data.compatibility(.{
            .format_id = app.format_id,
            .format_version = app.format_version,
            .bytes = app.bytes,
        }, self.h3_settings)) {
            .compatible => blk: {
                self.recordH3EarlyDataCompat(.compatible);
                break :blk .compatible;
            },
            .missing_state => blk: {
                self.recordH3EarlyDataCompat(.missing_state);
                break :blk .application_incompatible;
            },
            .malformed_state, .settings_incompatible => blk: {
                self.recordH3EarlyDataCompat(.settings_incompatible);
                break :blk .application_incompatible;
            },
        };
    }

    fn recordH3EarlyDataCompat(self: *Runtime, decision: metrics_mod.H3EarlyDataCompatDecision) void {
        const cb = self.early_data_compat_metrics_cb orelse return;
        const cb_ctx = self.early_data_compat_metrics_ctx orelse return;
        cb(cb_ctx, decision);
    }

    fn recordQuicEarlyDataDecision(self: *Runtime, decision: metrics_mod.QuicEarlyDataDecision) void {
        const cb = self.quic_early_data_decision_metrics_cb orelse return;
        const cb_ctx = self.quic_early_data_decision_metrics_ctx orelse return;
        cb(cb_ctx, decision);
    }

    fn recordQuicZeroRttPacket(self: *Runtime, outcome: metrics_mod.QuicZeroRttPacketOutcome) void {
        const cb = self.quic_zero_rtt_packet_metrics_cb orelse return;
        const cb_ctx = self.quic_zero_rtt_packet_metrics_ctx orelse return;
        cb(cb_ctx, outcome);
    }

    /// #523: bridges `quic.connection.Event`s from every accepted
    /// connection into the composition root's metrics — without this,
    /// `accept()` would construct connections with no `EventSink` at all
    /// and the typed TLS decision / per-packet 0-RTT outcomes would be
    /// silently discarded. Path lifecycle events are logged with bounded
    /// enum/family context only; no connection IDs, tokens, packet payloads,
    /// or IP addresses are emitted.
    fn quicConnectionEvent(ctx: ?*anyopaque, event: quic.connection.Event) void {
        const self: *Runtime = @ptrCast(@alignCast(ctx.?));
        switch (event) {
            .early_data_decision => |decision| {
                const mapped: metrics_mod.QuicEarlyDataDecision = switch (decision) {
                    .not_attempted => return,
                    .accepted => .accepted,
                    .disabled => .disabled,
                    .ticket_not_capable => .ticket_not_capable,
                    .selected_identity_not_zero => .selected_identity_not_zero,
                    .age_skew => .age_skew,
                    .transport_incompatible => .transport_incompatible,
                    .application_incompatible => .application_incompatible,
                    .replay_rejected => .replay_rejected,
                    .replay_unavailable => .replay_unavailable,
                    .resource_limited => .resource_limited,
                };
                self.recordQuicEarlyDataDecision(mapped);
            },
            .zero_rtt_packet => |packet| {
                const mapped: metrics_mod.QuicZeroRttPacketOutcome = switch (packet.outcome) {
                    .accepted => .accepted,
                    .keys_unavailable => .keys_unavailable,
                    .authentication_failed => .authentication_failed,
                    .duplicate => .duplicate,
                    .malformed => .malformed,
                };
                self.recordQuicZeroRttPacket(mapped);
            },
            .path_validation_started => |path| {
                self.logger.info(null, "http3: QUIC path validation started change={s} family={s}", .{
                    @tagName(path.change),
                    @tagName(path.path.remote.family),
                });
            },
            .path_validation_succeeded => |path| {
                self.logger.info(null, "http3: QUIC path validation succeeded change={s} family={s}", .{
                    @tagName(path.change),
                    @tagName(path.path.remote.family),
                });
            },
            .path_validation_failed => |path| {
                self.logger.info(null, "http3: QUIC path validation failed change={s} family={s}", .{
                    @tagName(path.change),
                    @tagName(path.path.remote.family),
                });
            },
            .path_migration_blocked => |blocked| {
                self.logger.warn(null, "http3: QUIC path migration blocked change={s} reason={s} family={s}", .{
                    @tagName(blocked.change),
                    @tagName(blocked.reason),
                    @tagName(blocked.path.remote.family),
                });
            },
            .path_promoted => |path| {
                self.logger.info(null, "http3: QUIC path promoted change={s} family={s}", .{
                    @tagName(path.change),
                    @tagName(path.path.remote.family),
                });
            },
            else => {},
        }
    }

    fn noteConnectionAccepted(self: *Runtime) void {
        self.snapshot_mutex.lock();
        defer self.snapshot_mutex.unlock();
        self.snapshot_state.native_connections += 1;
        self.snapshot_state.tracked_connections += 1;
    }

    fn noteConnectionClosed(self: *Runtime) void {
        self.snapshot_mutex.lock();
        defer self.snapshot_mutex.unlock();
        self.snapshot_state.native_connections -|= 1;
        self.snapshot_state.tracked_connections -|= 1;
    }

    fn noteHandshakeComplete(self: *Runtime) void {
        self.snapshot_mutex.lock();
        defer self.snapshot_mutex.unlock();
        self.snapshot_state.handshakes_completed += 1;
    }

    fn noteRequestCompleted(self: *Runtime) void {
        self.snapshot_mutex.lock();
        defer self.snapshot_mutex.unlock();
        self.snapshot_state.requests_completed += 1;
    }

    fn foldPathMetrics(self: *Runtime, entry: *ConnEntry) void {
        const current = entry.conn.pathMetrics();
        const previous = entry.last_path_metrics;
        entry.last_path_metrics = current;

        self.snapshot_mutex.lock();
        defer self.snapshot_mutex.unlock();
        const nat = current.nat_rebindings -| previous.nat_rebindings;
        const migrations = current.migrations -| previous.migrations;
        self.snapshot_state.path_challenges_sent += @intCast(current.path_challenges_sent -| previous.path_challenges_sent);
        self.snapshot_state.path_validations_succeeded += @intCast(current.path_validations_succeeded -| previous.path_validations_succeeded);
        self.snapshot_state.path_validations_failed += @intCast(current.path_validations_failed -| previous.path_validations_failed);
        self.snapshot_state.path_response_mismatches += @intCast(current.path_response_mismatches -| previous.path_response_mismatches);
        self.snapshot_state.nat_rebindings += @intCast(nat);
        self.snapshot_state.migrations += @intCast(migrations);
        self.snapshot_state.migrations_blocked += @intCast(current.migrations_blocked -| previous.migrations_blocked);
        self.snapshot_state.migrations_blocked_no_peer_cid += @intCast(current.migrations_blocked_no_peer_cid -| previous.migrations_blocked_no_peer_cid);
        self.snapshot_state.migration_events += @intCast(nat +| migrations);
    }

    fn noteRetryPacketSent(self: *Runtime) void {
        self.snapshot_mutex.lock();
        defer self.snapshot_mutex.unlock();
        self.snapshot_state.retry_packets_sent += 1;
    }

    fn noteRetryTokenAccepted(self: *Runtime) void {
        self.snapshot_mutex.lock();
        defer self.snapshot_mutex.unlock();
        self.snapshot_state.retry_tokens_accepted += 1;
    }

    fn noteInvalidToken(self: *Runtime) void {
        self.snapshot_mutex.lock();
        defer self.snapshot_mutex.unlock();
        self.snapshot_state.invalid_tokens += 1;
    }

    fn noteDatagram(self: *Runtime, len: usize) void {
        self.snapshot_mutex.lock();
        defer self.snapshot_mutex.unlock();
        self.snapshot_state.datagrams_seen += 1;
        self.snapshot_state.bytes_seen += len;
    }

    fn noteZeroRtt(self: *Runtime) void {
        self.snapshot_mutex.lock();
        defer self.snapshot_mutex.unlock();
        self.snapshot_state.zero_rtt_packets_seen += 1;
    }

    fn notePacketOut(self: *Runtime, len: usize) void {
        self.snapshot_mutex.lock();
        defer self.snapshot_mutex.unlock();
        self.snapshot_state.packets_emitted += 1;
        self.snapshot_state.bytes_emitted += len;
    }
};

/// Convert the protocol-neutral `stream_transport.Exchange` into the
/// gateway-facing `StreamRequest`, preserving the `:path` query string and
/// mapping `:authority` to a Host header when absent.
fn buildStreamRequest(allocator: std.mem.Allocator, exchange: stream_transport.Exchange) !http3_session.StreamRequest {
    var assembler = http3_session.StreamAssembler.init(allocator);
    defer assembler.deinit();

    var fields: [72]http3_session.HeaderField = undefined;
    fields[0] = .{ .name = ":method", .value = exchange.request.method };
    fields[1] = .{ .name = ":path", .value = exchange.request.path };
    fields[2] = .{ .name = ":authority", .value = exchange.request.authority };
    var count: usize = 3;
    for (exchange.request.headers) |header| {
        if (count == fields.len) break;
        fields[count] = .{ .name = header.name, .value = header.value };
        count += 1;
    }
    try assembler.appendHeaderBlock(fields[0..count]);
    switch (exchange.body) {
        .buffered => |body| try assembler.appendBody(body),
        else => {},
    }
    return assembler.finish();
}

/// Map the operator-facing runtime config onto the native QUIC transport
/// config.
fn quicConfigFrom(cfg: Config) quic.config.Config {
    return .{
        .max_udp_payload_size = std.math.clamp(cfg.max_datagram_size, 1200, 2048),
        .zero_rtt_enabled = zeroRttCarrierEnabled(cfg),
        .retry_policy = cfg.retry_policy,
        .migration_policy = if (cfg.connection_migration) .full else .nat_rebinding_only,
    };
}

/// #523: the QUIC 0-RTT carrier may only be enabled once every dependency it
/// relies on is actually present — `enable_0rtt` alone must never install a
/// usable early-data path. Without a resumption runtime there is no PSK
/// resolver to select a session, and without the replay gate the backend's
/// default gate fails closed (`.unavailable`) for every attempt anyway, so
/// gating here keeps that fail-closed behavior visible instead of quietly
/// letting every 0-RTT attempt dead-end downstream.
/// TLS extension type carrying the QUIC transport-parameters extension —
/// matches what `quic.tls_backend` stamps as the remembered/current
/// transport-compat snapshot's `format_id`, without needing that internal
/// constant exported.
const quic_transport_parameters_extension_type: u16 = @intFromEnum(tls_core.algorithms.ExtensionType.quic_transport_parameters);

/// The snapshot format version `quic.tls_backend.localTransportCompat` /
/// `peerTransportCompat` stamp on every remembered-transport `CompatView`
/// (hardcoded `1` there) — validated here before decoding so a
/// version-mismatched snapshot from a future encoding change fails closed
/// as `.transport_incompatible` rather than being decoded under the wrong
/// assumptions.
const quic_transport_parameters_compat_format_version: u16 = 1;

/// RFC 9000 §7.4.1 / RFC 9001 §4.6.1's no-reduction set: a 0-RTT attempt is
/// only transport-compatible if none of the limits it depends on — or that
/// the client otherwise remembers as a standing guarantee from the prior
/// connection — have been reduced since the ticket was issued.
/// `initial_max_stream_data_bidi_local` and `active_connection_id_limit`
/// are included even though they don't gate the early-data window itself
/// (server never sends 0-RTT, and CIDs aren't consumed by 0-RTT admission):
/// RFC 9000 §7.4.1 requires the full remembered parameter set to hold, not
/// just the ones 0-RTT immediately exercises.
fn quicEarlyDataTransportCompatible(remembered: quic.config.TransportParameters, current: quic.config.TransportParameters) bool {
    return current.initial_max_data >= remembered.initial_max_data and
        current.initial_max_stream_data_bidi_local >= remembered.initial_max_stream_data_bidi_local and
        current.initial_max_stream_data_bidi_remote >= remembered.initial_max_stream_data_bidi_remote and
        current.initial_max_stream_data_uni >= remembered.initial_max_stream_data_uni and
        current.initial_max_streams_bidi >= remembered.initial_max_streams_bidi and
        current.initial_max_streams_uni >= remembered.initial_max_streams_uni and
        current.active_connection_id_limit >= remembered.active_connection_id_limit;
}

fn zeroRttCarrierEnabled(cfg: Config) bool {
    if (!cfg.enable_0rtt) return false;
    // A non-null dependency isn't necessarily a *usable* one: a resumption
    // runtime constructed with `.mode = .disabled` still exists but yields
    // no PSK resolver, and a default-constructed `EarlyDataReplayGate`
    // (`decideFn == null`) exists but fails closed on every attempt. Either
    // would leave `accept()` composing a carrier that can never actually
    // accept 0-RTT — check the thing that matters, not just presence.
    const runtime = cfg.resumption_runtime orelse return false;
    if (runtime.serverResolver() == null) return false;
    const gate = cfg.early_data_replay_gate orelse return false;
    if (gate.decideFn == null) return false;
    return true;
}

/// Convert a source/destination IPv4 `sockaddr_in` into the protocol-neutral
/// `quic.udp.Address` used for `PathKey` construction. `sin_addr`/`sin_port`
/// are already network-byte-order, so the address octets bit-cast directly
/// (a host-endian read would byte-swap them on little-endian) and only the
/// port needs an explicit big-to-native swap.
fn addressFromSockaddrIn(sa: std.c.sockaddr.in) quic.udp.Address {
    const octets: [4]u8 = @bitCast(sa.addr);
    return quic.udp.Address.ip4(octets, std.mem.bigToNative(u16, sa.port));
}

/// The inverse of `addressFromSockaddrIn`, for sending a `Transmit`'s
/// destination back out over the IPv4 UDP socket.
fn sockaddrInFromAddress(addr: quic.udp.Address) std.c.sockaddr.in {
    var octets: [4]u8 = undefined;
    @memcpy(&octets, addr.slice());
    return .{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, addr.port),
        .addr = @bitCast(octets),
        .zero = [_]u8{0} ** 8,
    };
}

/// Whether a new half-open connection may be admitted given the current global
/// and per-source connection counts. Bounds the state an off-path spoofer can
/// pin with forged Initials (the native stack sends no Retry).
fn admissionAllowed(total: usize, per_source: u32) bool {
    return total < max_connections and per_source < max_connections_per_source;
}

/// What to do with a tracked connection after ingesting a datagram, decided
/// purely from whether the datagram authenticated (the post-AEAD
/// `packets_received` delta), whether the connection was just accepted for this
/// datagram, and whether the source address differs from the connection's.
const IngestOutcome = enum {
    /// Process normally (transmit, pump H3).
    keep,
    /// A freshly accepted connection whose first datagram authenticated
    /// nothing — an unsolicited or spoofed Initial. Tear it down.
    drop_unauthenticated,
    /// An authenticated packet arrived from a new source. Record the migration
    /// event; the runtime does not follow it.
    migrated,
};

fn classifyIngest(freshly_accepted: bool, authenticated: bool, source_changed: bool) IngestOutcome {
    if (freshly_accepted and !authenticated) return .drop_unauthenticated;
    if (authenticated and !freshly_accepted and source_changed) return .migrated;
    return .keep;
}

fn incPerIp(per_ip: *std.AutoHashMap(u32, u32), addr: u32) !void {
    const gop = try per_ip.getOrPut(addr);
    if (!gop.found_existing) gop.value_ptr.* = 0;
    gop.value_ptr.* += 1;
}

fn decPerIp(per_ip: *std.AutoHashMap(u32, u32), addr: u32) void {
    if (per_ip.getPtr(addr)) |count| {
        count.* -= 1;
        if (count.* == 0) _ = per_ip.remove(addr);
    }
}

fn cidSliceContains(cids: []const quic.cid.ConnectionId, needle: quic.cid.ConnectionId) bool {
    for (cids) |cid| {
        if (std.mem.eql(u8, cid.slice(), needle.slice())) return true;
    }
    return false;
}

/// Create a non-blocking, close-on-exec UDP socket for `sa_family`. Returns a
/// negative fd on failure (caller inspects `errno`). macOS/BSD reject
/// `SOCK_CLOEXEC`/`SOCK_NONBLOCK` in the socket `type` argument (EPROTOTYPE),
/// unlike Linux, so the flags are applied with `fcntl` after creation to keep
/// the listener working on both platforms.
fn openUdpSocket(sa_family: u32) std.c.fd_t {
    const fd = std.c.socket(@intCast(sa_family), posix.SOCK.DGRAM, posix.IPPROTO.UDP);
    if (fd < 0) return fd;
    const descriptor_flags = std.c.fcntl(fd, std.c.F.GETFD, @as(c_int, 0));
    if (descriptor_flags >= 0) _ = std.c.fcntl(fd, std.c.F.SETFD, descriptor_flags | std.c.FD_CLOEXEC);
    const status_flags = std.c.fcntl(fd, std.c.F.GETFL, @as(c_int, 0));
    if (status_flags >= 0) _ = std.c.fcntl(fd, std.c.F.SETFL, status_flags | @as(c_int, @bitCast(posix.O{ .NONBLOCK = true })));
    return fd;
}

const testing = std.testing;

const RuntimeCidHarness = struct {
    client_backend: quic.tls_backend.Tls13Backend,
    server_backend: *quic.tls_backend.Tls13Backend,
    client: *Connection,
    entry: *ConnEntry,
    now_us: u64 = 1_000_000,

    const client_cid = [_]u8{ 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8 };
    const odcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_path = quic.path.PathKey{
        .local = quic.udp.Address.ip4(.{ 127, 0, 0, 1 }, 42_000),
        .remote = quic.udp.Address.ip4(.{ 127, 0, 0, 1 }, 42_001),
    };
    const server_path = quic.path.PathKey{
        .local = quic.udp.Address.ip4(.{ 127, 0, 0, 1 }, 42_001),
        .remote = quic.udp.Address.ip4(.{ 127, 0, 0, 1 }, 42_000),
    };
    const no_challenge = [_]u8{0} ** quic.path.path_challenge_len;

    fn init(allocator: std.mem.Allocator, credential_provider: tls_core.credentials.CredentialProvider) !*RuntimeCidHarness {
        const self = try allocator.create(RuntimeCidHarness);
        errdefer allocator.destroy(self);
        const server_backend = try allocator.create(quic.tls_backend.Tls13Backend);
        errdefer allocator.destroy(server_backend);
        const entry = try allocator.create(ConnEntry);
        errdefer allocator.destroy(entry);
        server_backend.* = quic.tls_backend.Tls13Backend.initServerWithProvider(
            .{ .hello_random = [_]u8{0x51} ** 32, .key_share_seed = [_]u8{0x22} ** 32 },
            credential_provider,
        );
        self.* = .{
            .client_backend = quic.tls_backend.Tls13Backend.initClient(
                .{ .hello_random = [_]u8{0xc1} ** 32, .key_share_seed = [_]u8{0x11} ** 32 },
                .{ .pinned_certificate = tls_core.credentials.testdata.certificate_der },
            ),
            .server_backend = server_backend,
            .client = undefined,
            .entry = entry,
        };
        self.client = try Connection.init(allocator, .{
            .role = .client,
            .local_cid = &client_cid,
            .original_destination_cid = &odcid,
            .initial_secret_dcid = &odcid,
            .peer_cid = &odcid,
            .tls = self.client_backend.backend(),
            .now_us = self.now_us,
            .initial_path = client_path,
        });
        errdefer self.client.deinit();
        const server = try Connection.init(allocator, .{
            .role = .server,
            .local_cid = &odcid,
            .original_destination_cid = &odcid,
            .initial_secret_dcid = &odcid,
            .peer_cid = &client_cid,
            .tls = server_backend.backend(),
            .now_us = self.now_us,
            .initial_path = server_path,
            .stateless_reset_key = [_]u8{0x44} ** 32,
        });
        entry.* = .{
            .backend = server_backend,
            .conn = server,
            .h3 = H3.initWithSettings(allocator, .server, .{}),
            .admission_source_ip = 0x0100007f,
            .cid_len = odcid.len,
            .accepted_at_us = self.now_us,
        };
        entry.owned_cids[0] = try quic.cid.ConnectionId.init(&odcid);
        entry.owned_cid_count = 1;
        try self.pump();
        return self;
    }

    fn deinit(self: *RuntimeCidHarness, allocator: std.mem.Allocator) void {
        self.client.deinit();
        self.entry.deinit(allocator);
        allocator.destroy(self.entry);
        allocator.destroy(self);
    }

    fn pump(self: *RuntimeCidHarness) !void {
        var rounds: usize = 0;
        while (rounds < 64) : (rounds += 1) {
            var progressed = false;
            var buf: [2048]u8 = undefined;
            while (self.client.pollTransmitOnPath(&buf, self.now_us)) |t| {
                try self.entry.conn.ingestOnPath(t.bytes, server_path, no_challenge, self.now_us);
                progressed = true;
                self.now_us += 500;
            }
            while (self.entry.conn.pollTransmitOnPath(&buf, self.now_us)) |t| {
                try self.client.ingestOnPath(t.bytes, client_path, no_challenge, self.now_us);
                progressed = true;
                self.now_us += 500;
            }
            if (!progressed) break;
        }
        try testing.expect(self.client.isEstablished());
        try testing.expect(self.entry.conn.isEstablished());
    }
};

test "stream request bridge maps exchange fields and Host" {
    const allocator = testing.allocator;
    var request = try buildStreamRequest(allocator, .{
        .request = .{
            .method = "POST",
            .scheme = "https",
            .authority = "example.com",
            .path = "/api?x=1",
            .headers = &.{.{ .name = "content-type", .value = "application/json" }},
        },
        .body = .{ .buffered = @constCast("{}") },
    });
    defer request.deinit();
    try testing.expectEqualStrings("POST", request.method);
    try testing.expectEqualStrings("/api?x=1", request.path);
    try testing.expectEqualStrings("example.com", request.authority.?);
    try testing.expectEqualStrings("example.com", request.headers.get("Host").?);
    try testing.expectEqualStrings("application/json", request.headers.get("content-type").?);
    try testing.expectEqualStrings("{}", request.body);
}

test "quicConfigFrom clamps datagram size into the work-buffer range" {
    // Below the QUIC minimum snaps up to 1200.
    try testing.expectEqual(@as(u64, 1200), quicConfigFrom(.{
        .listen_host = "::",
        .quic_port = 443,
        .max_datagram_size = 512,
    }).max_udp_payload_size);
    // Above the 2048-byte work buffer snaps down.
    try testing.expectEqual(@as(u64, 2048), quicConfigFrom(.{
        .listen_host = "::",
        .quic_port = 443,
        .max_datagram_size = 9000,
    }).max_udp_payload_size);
    // An in-range value passes through, and default migration allows validated
    // same-IP NAT rebinding while still advertising disable_active_migration.
    const mid = quicConfigFrom(.{ .listen_host = "::", .quic_port = 443, .max_datagram_size = 1350 });
    try testing.expectEqual(@as(u64, 1350), mid.max_udp_payload_size);
    try testing.expectEqual(quic.config.MigrationPolicy.nat_rebinding_only, mid.migration_policy);
    try testing.expectEqual(quic.config.RetryPolicy.off, mid.retry_policy);
    try testing.expectEqual(quic.config.MigrationPolicy.full, quicConfigFrom(.{
        .listen_host = "::",
        .quic_port = 443,
        .connection_migration = true,
    }).migration_policy);
    try testing.expectEqual(quic.config.RetryPolicy.address_validation, quicConfigFrom(.{
        .listen_host = "::",
        .quic_port = 443,
        .retry_policy = .address_validation,
    }).retry_policy);
}

test "http3 runtime: spare CID route is registered before NEW_CONNECTION_ID is pollable" {
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity());
    defer fixed.deinit();
    var logger = logger_mod.Logger.init(.err, "http3-cid-route-order-test");
    var runtime = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
    });
    defer runtime.deinit();
    var harness = try RuntimeCidHarness.init(testing.allocator, fixed.provider());
    defer harness.deinit(testing.allocator);

    var routes = quic.cid.CidRoutingTable.init(testing.allocator);
    defer routes.deinit();
    const handle: u64 = 7;
    const initial = harness.entry.owned_cids[0];
    try routes.insert(initial, handle);
    try testing.expect(routes.contains(initial));
    try testing.expectEqual(@as(usize, 1), harness.entry.owned_cid_count);
    try testing.expectEqual(@as(usize, 0), harness.entry.conn.pending_new_connection_ids.items.len);

    runtime.maintainLocalCidRoutes(harness.entry, handle, &routes);
    try testing.expectEqual(@as(usize, 2), harness.entry.owned_cid_count);
    try testing.expectEqual(@as(usize, 1), harness.entry.conn.pending_new_connection_ids.items.len);
    const spare = harness.entry.owned_cids[1];
    try testing.expect(routes.contains(spare));

    var out: [2048]u8 = undefined;
    _ = harness.entry.conn.pollTransmitOnPath(&out, harness.now_us) orelse return error.TestExpectedEqual;
    try testing.expectEqual(@as(usize, 0), harness.entry.conn.pending_new_connection_ids.items.len);
}

test "http3 runtime: CID route collision rolls back without stealing an existing route" {
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity());
    defer fixed.deinit();
    var harness = try RuntimeCidHarness.init(testing.allocator, fixed.provider());
    defer harness.deinit(testing.allocator);

    var routes = quic.cid.CidRoutingTable.init(testing.allocator);
    defer routes.deinit();
    const handle: u64 = 7;
    const collision_owner: u64 = 99;
    const candidate = try quic.cid.ConnectionId.init(&.{ 9, 8, 7, 6, 5, 4, 3, 2 });
    try routes.insert(harness.entry.owned_cids[0], handle);
    try routes.insert(candidate, collision_owner);

    const before_routes = routes.count();
    const before_owned = harness.entry.owned_cid_count;
    const before_pending = harness.entry.conn.pending_new_connection_ids.items.len;
    try testing.expectEqual(Runtime.RegisterLocalCidRouteResult.collision, Runtime.registerLocalCidRoute(harness.entry, handle, &routes, candidate));
    try testing.expectEqual(before_routes, routes.count());
    try testing.expectEqual(before_owned, harness.entry.owned_cid_count);
    try testing.expectEqual(before_pending, harness.entry.conn.pending_new_connection_ids.items.len);
    try testing.expectEqual(@as(?u64, collision_owner), routes.lookup(candidate.slice()));
}

test "http3 runtime: retired CIDs stop routing, replenish, and teardown removes every route" {
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity());
    defer fixed.deinit();
    var logger = logger_mod.Logger.init(.err, "http3-cid-teardown-test");
    var runtime = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
    });
    defer runtime.deinit();
    var harness = try RuntimeCidHarness.init(testing.allocator, fixed.provider());
    defer {
        harness.client.deinit();
        testing.allocator.destroy(harness);
    }

    var routes = quic.cid.CidRoutingTable.init(testing.allocator);
    defer routes.deinit();
    const handle: u64 = 7;
    const initial = harness.entry.owned_cids[0];
    try routes.insert(initial, handle);
    runtime.maintainLocalCidRoutes(harness.entry, handle, &routes);
    const spare = harness.entry.owned_cids[1];
    try testing.expect(routes.contains(spare));

    var out: [2048]u8 = undefined;
    _ = harness.entry.conn.pollTransmitOnPath(&out, harness.now_us) orelse return error.TestExpectedEqual;
    _ = try harness.entry.conn.local_cids.?.retire(.{ .sequence = 1 });
    runtime.syncCidRoutes(harness.entry, &routes);
    try testing.expect(!routes.contains(spare));
    try testing.expectEqual(@as(?u64, null), routes.lookup(spare.slice()));

    runtime.maintainLocalCidRoutes(harness.entry, handle, &routes);
    try testing.expectEqual(@as(usize, 2), harness.entry.owned_cid_count);
    try testing.expect(routes.contains(initial));
    const replacement = for (harness.entry.owned_cids[0..harness.entry.owned_cid_count]) |cid| {
        if (!std.mem.eql(u8, cid.slice(), initial.slice())) break cid;
    } else return error.TestExpectedEqual;
    try testing.expect(!std.mem.eql(u8, replacement.slice(), spare.slice()));
    try testing.expect(routes.contains(replacement));

    var connections = std.AutoHashMap(u64, *ConnEntry).init(testing.allocator);
    defer connections.deinit();
    var per_ip = std.AutoHashMap(u32, u32).init(testing.allocator);
    defer per_ip.deinit();
    const admission_ip = harness.entry.admission_source_ip;
    try connections.put(handle, harness.entry);
    try incPerIp(&per_ip, admission_ip);
    runtime.removeConnection(&connections, &routes, &per_ip, handle);
    try testing.expectEqual(@as(usize, 0), connections.count());
    try testing.expectEqual(@as(usize, 0), routes.count());
    try testing.expectEqual(@as(?u32, null), per_ip.get(admission_ip));
}

test "quicEarlyDataTransportCompatible (#523): rejects any reduced limit in the full RFC 9000 §7.4.1 set" {
    const base = quic.config.TransportParameters{
        .max_idle_timeout_ms = 1000,
        .active_connection_id_limit = 4,
        .max_udp_payload_size = 1200,
        .initial_max_data = 100,
        .initial_max_stream_data_bidi_local = 50,
        .initial_max_stream_data_bidi_remote = 50,
        .initial_max_stream_data_uni = 25,
        .initial_max_streams_bidi = 10,
        .initial_max_streams_uni = 5,
        .disable_active_migration = true,
    };

    // Identical parameters are always compatible.
    try testing.expect(quicEarlyDataTransportCompatible(base, base));

    // Raising every limit (including the two the second-pass review added)
    // stays compatible.
    var raised = base;
    raised.initial_max_data += 1;
    raised.active_connection_id_limit += 1;
    raised.initial_max_stream_data_bidi_local += 1;
    try testing.expect(quicEarlyDataTransportCompatible(base, raised));

    // Reducing `active_connection_id_limit` alone is rejected.
    var reduced_cid = base;
    reduced_cid.active_connection_id_limit -= 1;
    try testing.expect(!quicEarlyDataTransportCompatible(base, reduced_cid));

    // Reducing `initial_max_stream_data_bidi_local` alone is rejected.
    var reduced_bidi_local = base;
    reduced_bidi_local.initial_max_stream_data_bidi_local -= 1;
    try testing.expect(!quicEarlyDataTransportCompatible(base, reduced_bidi_local));
}

test "h3EarlyDataCompatibility (#523): rejects a remembered snapshot with the wrong format_version before decoding" {
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity());
    defer fixed.deinit();
    var logger = logger_mod.Logger.init(.err, "http3-transport-version-test");
    var runtime = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
    });
    defer runtime.deinit();

    const candidate: tls_core.tls13_backend.EarlyDataCompatibilityCandidate = .{
        .remembered_transport = .{
            .format_id = quic_transport_parameters_extension_type,
            .format_version = quic_transport_parameters_compat_format_version + 1,
            .bytes = "not even valid transport parameter bytes",
        },
    };
    try testing.expectEqual(
        tls_core.tls13_backend.EarlyDataCompatibilityDecision.transport_incompatible,
        Runtime.h3EarlyDataCompatibility(@ptrCast(&runtime), candidate),
    );
}

test "h3EarlyDataCompatibility (#523): rejects a live QUIC transport limit reduced below the remembered snapshot" {
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity());
    defer fixed.deinit();
    var logger = logger_mod.Logger.init(.err, "http3-transport-reduced-test");
    var runtime = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
    });
    defer runtime.deinit();

    const remembered_params = try runtime.quic_config.transportParameters();
    var encoded: [quic.tls_backend.max_transport_parameters_len]u8 = undefined;
    const encoded_bytes = try quic.tls_backend.encodeTransportParameters(remembered_params, &encoded);

    const candidate: tls_core.tls13_backend.EarlyDataCompatibilityCandidate = .{
        .remembered_transport = .{
            .format_id = quic_transport_parameters_extension_type,
            .format_version = quic_transport_parameters_compat_format_version,
            .bytes = encoded_bytes,
        },
    };

    // Identical to the live configuration: transport-compatible, so the
    // decision falls through to the application/H3-SETTINGS check next —
    // which fails closed as `.application_incompatible` here since this
    // candidate supplies no `remembered_application` at all. That's the
    // proof the transport check itself passed, not a transport rejection.
    try testing.expectEqual(
        tls_core.tls13_backend.EarlyDataCompatibilityDecision.application_incompatible,
        Runtime.h3EarlyDataCompatibility(@ptrCast(&runtime), candidate),
    );

    // Reduce a live limit below what was remembered.
    runtime.quic_config.initial_max_streams_bidi -= 1;
    try testing.expectEqual(
        tls_core.tls13_backend.EarlyDataCompatibilityDecision.transport_incompatible,
        Runtime.h3EarlyDataCompatibility(@ptrCast(&runtime), candidate),
    );
}

test "quicConfigFrom (#523): enable_0rtt alone never enables the 0-RTT carrier" {
    var entropy = tls_core.production_crypto.OsEntropy{};
    var provider_state = tls_core.production_crypto.Provider.init(entropy.entropy());
    var resumption = try tls_core.resumption_runtime.Runtime.init(
        testing.allocator,
        .{ .mode = .stateful },
        .{ .ctx = undefined, .nowUnixMsFn = fixedNowUnixMsForTest },
        provider_state.cryptoProvider(),
    );
    defer resumption.deinit();

    var store = try tls_core.early_data_replay.LocalStore.init(testing.allocator, .{}, 0, 0);
    defer store.deinit();
    var gate_adapter = tls_core.early_data_replay.GateAdapter.init(store.store());
    const gate = gate_adapter.gate();

    // No dependencies at all.
    try testing.expect(!quicConfigFrom(.{ .listen_host = "::", .quic_port = 443, .enable_0rtt = true }).zero_rtt_enabled);
    // Only a resumption runtime.
    try testing.expect(!quicConfigFrom(.{
        .listen_host = "::",
        .quic_port = 443,
        .enable_0rtt = true,
        .resumption_runtime = &resumption,
    }).zero_rtt_enabled);
    // Only a replay gate.
    try testing.expect(!quicConfigFrom(.{
        .listen_host = "::",
        .quic_port = 443,
        .enable_0rtt = true,
        .early_data_replay_gate = gate,
    }).zero_rtt_enabled);
    // Both dependencies present but `enable_0rtt` false (the default): still disabled.
    try testing.expect(!quicConfigFrom(.{
        .listen_host = "::",
        .quic_port = 443,
        .resumption_runtime = &resumption,
        .early_data_replay_gate = gate,
    }).zero_rtt_enabled);
    // Every dependency present: the carrier actually enables.
    try testing.expect(quicConfigFrom(.{
        .listen_host = "::",
        .quic_port = 443,
        .enable_0rtt = true,
        .resumption_runtime = &resumption,
        .early_data_replay_gate = gate,
    }).zero_rtt_enabled);
}

fn expectInvalidH3SettingsAtRuntimeInit(settings: http3.frame.Settings) !void {
    var logger = logger_mod.Logger.init(.err, "http3-invalid-settings-test");
    try testing.expectError(error.InvalidH3Settings, Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .h3_settings = settings,
    }));
}

test "runtime init rejects unsupported local H3 setting qpack_max_table_capacity" {
    try expectInvalidH3SettingsAtRuntimeInit(.{ .qpack_max_table_capacity = 1 });
}

test "runtime init rejects unsupported local H3 setting qpack_blocked_streams" {
    try expectInvalidH3SettingsAtRuntimeInit(.{ .qpack_blocked_streams = 1 });
}

test "runtime init rejects unsupported local H3 setting enable_connect_protocol" {
    try expectInvalidH3SettingsAtRuntimeInit(.{ .enable_connect_protocol = true });
}

test "runtime init rejects unsupported local H3 setting h3_datagram" {
    try expectInvalidH3SettingsAtRuntimeInit(.{ .h3_datagram = true });
}

test "runtime init rejects unsupported local H3 setting max_field_section_size" {
    try expectInvalidH3SettingsAtRuntimeInit(.{ .max_field_section_size = 1024 });
}

test "admissionAllowed enforces global and per-source caps at the boundary" {
    // Under both caps: admitted.
    try testing.expect(admissionAllowed(0, 0));
    try testing.expect(admissionAllowed(max_connections - 1, max_connections_per_source - 1));
    // At the global cap: rejected regardless of per-source count.
    try testing.expect(!admissionAllowed(max_connections, 0));
    try testing.expect(!admissionAllowed(max_connections + 1, 0));
    // At the per-source cap: rejected regardless of global room.
    try testing.expect(!admissionAllowed(0, max_connections_per_source));
    try testing.expect(!admissionAllowed(0, max_connections_per_source + 1));
    // Either cap alone is sufficient to reject.
    try testing.expect(!admissionAllowed(max_connections, max_connections_per_source));
}

test "classifyIngest routes spoofed Initials, migration, and normal traffic" {
    // Freshly accepted + first datagram authenticates nothing -> spoofed
    // Initial, torn down. The source-changed flag never overrides this: a
    // freshly accepted entry's peer is exactly the datagram's source.
    try testing.expectEqual(IngestOutcome.drop_unauthenticated, classifyIngest(true, false, false));
    try testing.expectEqual(IngestOutcome.drop_unauthenticated, classifyIngest(true, false, true));

    // Freshly accepted + authenticated (a legitimate Initial) -> keep and let
    // the handshake proceed.
    try testing.expectEqual(IngestOutcome.keep, classifyIngest(true, true, false));

    // Established connection, authenticated packet from a new source -> counted
    // as a migration attempt, not followed.
    try testing.expectEqual(IngestOutcome.migrated, classifyIngest(false, true, true));

    // Authenticated packet from the same source -> ordinary traffic.
    try testing.expectEqual(IngestOutcome.keep, classifyIngest(false, true, false));

    // Unauthenticated packet from a new source on an existing connection is
    // ignored (never promoted to a migration event): the source is untrusted.
    try testing.expectEqual(IngestOutcome.keep, classifyIngest(false, false, true));
    try testing.expectEqual(IngestOutcome.keep, classifyIngest(false, false, false));
}

test "per-source admission counter increments and prunes to empty" {
    var per_ip = std.AutoHashMap(u32, u32).init(testing.allocator);
    defer per_ip.deinit();
    try incPerIp(&per_ip, 0x0100007f);
    try incPerIp(&per_ip, 0x0100007f);
    try testing.expectEqual(@as(u32, 2), per_ip.get(0x0100007f).?);
    decPerIp(&per_ip, 0x0100007f);
    try testing.expectEqual(@as(u32, 1), per_ip.get(0x0100007f).?);
    decPerIp(&per_ip, 0x0100007f);
    try testing.expect(per_ip.get(0x0100007f) == null);
    // Decrementing an unknown address is a no-op, not a crash.
    decPerIp(&per_ip, 0xdeadbeef);
}

const TestParkedContinuationState = struct {
    run_calls: usize = 0,
    deinit_calls: usize = 0,
    fail_run: bool = false,

    fn run(ctx: *anyopaque, allocator: std.mem.Allocator, response: *response_mod.Response) !void {
        _ = allocator;
        const self: *TestParkedContinuationState = @ptrCast(@alignCast(ctx));
        self.run_calls += 1;
        if (self.fail_run) return error.TestParkedContinuationFailed;
        _ = response.setStatus(.ok).setBody("resumed");
    }

    fn deinit(ctx: *anyopaque, allocator: std.mem.Allocator) void {
        _ = allocator;
        const self: *TestParkedContinuationState = @ptrCast(@alignCast(ctx));
        self.deinit_calls += 1;
    }

    fn continuation(self: *TestParkedContinuationState) http3_session.StreamRequest.Early425RetryContinuation {
        return .{
            .ctx = self,
            .resume_fn = run,
            .deinit_fn = deinit,
        };
    }
};

const TestH3ResumeConn = struct {
    established: bool = false,
    reset_calls: usize = 0,
    last_reset_stream_id: u64 = 0,

    fn isEstablished(self: *TestH3ResumeConn) bool {
        return self.established;
    }

    fn resetStream(self: *TestH3ResumeConn, stream_id: u64, code: u64) !void {
        _ = code;
        self.reset_calls += 1;
        self.last_reset_stream_id = stream_id;
    }
};

const TestH3ResumeSession = struct {
    send_calls: usize = 0,
    ok_sends: usize = 0,
    internal_error_sends: usize = 0,
    finish_calls: usize = 0,
    send_fail: bool = false,
    last_status: u16 = 0,
    last_stream_id: u64 = 0,

    fn sendResponse(
        self: *TestH3ResumeSession,
        conn: *TestH3ResumeConn,
        stream_id: u64,
        status: u16,
        headers: []const stream_transport.Header,
        body: []const u8,
    ) !void {
        _ = conn;
        _ = headers;
        _ = body;
        self.send_calls += 1;
        self.last_status = status;
        self.last_stream_id = stream_id;
        if (status == 200) self.ok_sends += 1;
        if (status == 500) self.internal_error_sends += 1;
        if (self.send_fail) return error.StreamBackpressure;
    }

    fn finishRequest(self: *TestH3ResumeSession, stream_id: u64) void {
        self.finish_calls += 1;
        self.last_stream_id = stream_id;
    }
};

const TestH3ResumeEntry = struct {
    conn: *TestH3ResumeConn,
    h3: TestH3ResumeSession = .{},
    parked_h3_retries: std.ArrayList(ParkedH3Retry) = .empty,

    fn deinit(self: *TestH3ResumeEntry, allocator: std.mem.Allocator) void {
        for (self.parked_h3_retries.items) |*parked| parked.deinit(allocator);
        self.parked_h3_retries.deinit(allocator);
    }
};

test "parked H3 retry resumes only after connection establishment" {
    const allocator = testing.allocator;
    var logger = logger_mod.Logger.init(.err, "http3-parked-resume-test");
    var runtime = try Runtime.init(allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
    });
    defer runtime.deinit();

    var conn = TestH3ResumeConn{};
    var entry = TestH3ResumeEntry{ .conn = &conn };
    defer entry.deinit(allocator);
    var continuation = TestParkedContinuationState{};
    try entry.parked_h3_retries.append(allocator, .{
        .stream_id = 11,
        .continuation = continuation.continuation(),
    });

    runtime.resumeParkedH3RetriesForEntry(&entry);
    try testing.expectEqual(@as(usize, 1), entry.parked_h3_retries.items.len);
    try testing.expectEqual(@as(usize, 0), continuation.run_calls);
    try testing.expectEqual(@as(usize, 0), entry.h3.send_calls);

    conn.established = true;
    runtime.resumeParkedH3RetriesForEntry(&entry);
    try testing.expectEqual(@as(usize, 0), entry.parked_h3_retries.items.len);
    try testing.expectEqual(@as(usize, 1), continuation.run_calls);
    try testing.expectEqual(@as(usize, 1), continuation.deinit_calls);
    try testing.expectEqual(@as(usize, 1), entry.h3.send_calls);
    try testing.expectEqual(@as(u16, 200), entry.h3.last_status);
    try testing.expectEqual(@as(u64, 11), entry.h3.last_stream_id);
}

test "parked H3 retry fallback send failure resets and finishes stream once" {
    const allocator = testing.allocator;
    var logger = logger_mod.Logger.init(.err, "http3-parked-fallback-test");
    var runtime = try Runtime.init(allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
    });
    defer runtime.deinit();

    var conn = TestH3ResumeConn{ .established = true };
    var entry = TestH3ResumeEntry{
        .conn = &conn,
        .h3 = .{ .send_fail = true },
    };
    defer entry.deinit(allocator);
    var continuation = TestParkedContinuationState{ .fail_run = true };
    try entry.parked_h3_retries.append(allocator, .{
        .stream_id = 13,
        .continuation = continuation.continuation(),
    });

    runtime.resumeParkedH3RetriesForEntry(&entry);

    try testing.expectEqual(@as(usize, 0), entry.parked_h3_retries.items.len);
    try testing.expectEqual(@as(usize, 1), continuation.run_calls);
    try testing.expectEqual(@as(usize, 1), continuation.deinit_calls);
    try testing.expectEqual(@as(usize, 1), entry.h3.send_calls);
    try testing.expectEqual(@as(usize, 1), conn.reset_calls);
    try testing.expectEqual(@as(usize, 1), entry.h3.finish_calls);
    try testing.expectEqual(@as(u64, 13), conn.last_reset_stream_id);
    try testing.expectEqual(@as(u64, 13), entry.h3.last_stream_id);
}

test "failed parked H3 retry does not stop later parked retry" {
    const allocator = testing.allocator;
    var logger = logger_mod.Logger.init(.err, "http3-parked-drain-test");
    var runtime = try Runtime.init(allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
    });
    defer runtime.deinit();

    var conn = TestH3ResumeConn{ .established = true };
    var entry = TestH3ResumeEntry{ .conn = &conn };
    defer entry.deinit(allocator);
    var failed = TestParkedContinuationState{ .fail_run = true };
    var resumed = TestParkedContinuationState{};
    try entry.parked_h3_retries.append(allocator, .{
        .stream_id = 21,
        .continuation = failed.continuation(),
    });
    try entry.parked_h3_retries.append(allocator, .{
        .stream_id = 23,
        .continuation = resumed.continuation(),
    });

    runtime.resumeParkedH3RetriesForEntry(&entry);

    try testing.expectEqual(@as(usize, 0), entry.parked_h3_retries.items.len);
    try testing.expectEqual(@as(usize, 1), failed.run_calls);
    try testing.expectEqual(@as(usize, 1), failed.deinit_calls);
    try testing.expectEqual(@as(usize, 1), resumed.run_calls);
    try testing.expectEqual(@as(usize, 1), resumed.deinit_calls);
    try testing.expectEqual(@as(usize, 2), entry.h3.send_calls);
    try testing.expectEqual(@as(usize, 1), entry.h3.internal_error_sends);
    try testing.expectEqual(@as(usize, 1), entry.h3.ok_sends);
    try testing.expectEqual(@as(usize, 0), conn.reset_calls);
    try testing.expectEqual(@as(u64, 23), entry.h3.last_stream_id);
}

test "failed parked H3 retry reset path does not stop later parked retry" {
    const allocator = testing.allocator;
    var logger = logger_mod.Logger.init(.err, "http3-parked-reset-drain-test");
    var runtime = try Runtime.init(allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
    });
    defer runtime.deinit();

    var conn = TestH3ResumeConn{ .established = true };
    var entry = TestH3ResumeEntry{
        .conn = &conn,
        .h3 = .{ .send_fail = true },
    };
    defer entry.deinit(allocator);
    var failed = TestParkedContinuationState{ .fail_run = true };
    var resumed = TestParkedContinuationState{};
    try entry.parked_h3_retries.append(allocator, .{
        .stream_id = 31,
        .continuation = failed.continuation(),
    });
    try entry.parked_h3_retries.append(allocator, .{
        .stream_id = 33,
        .continuation = resumed.continuation(),
    });

    runtime.resumeParkedH3RetriesForEntry(&entry);

    try testing.expectEqual(@as(usize, 0), entry.parked_h3_retries.items.len);
    try testing.expectEqual(@as(usize, 1), failed.run_calls);
    try testing.expectEqual(@as(usize, 1), failed.deinit_calls);
    try testing.expectEqual(@as(usize, 1), resumed.run_calls);
    try testing.expectEqual(@as(usize, 1), resumed.deinit_calls);
    try testing.expectEqual(@as(usize, 2), entry.h3.send_calls);
    try testing.expectEqual(@as(usize, 2), conn.reset_calls);
    try testing.expectEqual(@as(usize, 2), entry.h3.finish_calls);
    try testing.expectEqual(@as(u64, 33), conn.last_reset_stream_id);
}

test "runtime borrows the credential provider and owns no key material" {
    // Structural guarantee (#392): the runtime has no owned identity, DER, or
    // key buffers to leak — only the borrowed provider handle.
    comptime {
        for (@typeInfo(Runtime).@"struct".fields) |field| {
            std.debug.assert(!std.mem.eql(u8, field.name, "identity"));
            std.debug.assert(!std.mem.eql(u8, field.name, "cert_der"));
            std.debug.assert(!std.mem.eql(u8, field.name, "key_der"));
        }
    }

    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity());
    defer fixed.deinit();
    var logger = logger_mod.Logger.init(.err, "http3-test");

    var runtime = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
    });
    try testing.expect(runtime.snapshot().server_bootstrapped);
    runtime.deinit();

    // Tearing the runtime down must not release the shared provider: the
    // same instance keeps serving native TCP TLS selections.
    var selection = tls_core.credentials.SelectionContext{
        .role = .server,
        .server_name = null,
        .peer_signature_schemes = &.{0x0807},
        .negotiated_version = 0x0304,
        .cipher_suite = 0x1301,
        .application_protocol = "h2",
        .auth_policy = .{},
    };
    switch (try fixed.provider().selectCredential(&selection)) {
        .complete => |credential| credential.release(),
        .pending => return error.TestUnexpectedPending,
    }

    var unbootstrapped = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
    });
    try testing.expect(!unbootstrapped.snapshot().server_bootstrapped);
    unbootstrapped.deinit();
}

fn fixedNowUnixMsForTest(_: *anyopaque) i64 {
    return 1000;
}

test "runtime borrows the resumption runtime and installs it per accepted connection" {
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity());
    defer fixed.deinit();
    var logger = logger_mod.Logger.init(.err, "http3-resumption-test");

    var entropy = tls_core.production_crypto.OsEntropy{};
    var provider_state = tls_core.production_crypto.Provider.init(entropy.entropy());
    var resumption = try tls_core.resumption_runtime.Runtime.init(
        testing.allocator,
        .{ .mode = .stateful },
        .{ .ctx = undefined, .nowUnixMsFn = fixedNowUnixMsForTest },
        provider_state.cryptoProvider(),
    );
    defer resumption.deinit();

    var runtime = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        .resumption_runtime = &resumption,
    });
    defer runtime.deinit();

    try testing.expectEqual(@as(?*tls_core.resumption_runtime.Runtime, &resumption), runtime.resumption_runtime);
}

test "runtime borrows the early-data replay gate independently of the resumption runtime" {
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity());
    defer fixed.deinit();
    var logger = logger_mod.Logger.init(.err, "http3-replay-gate-test");

    var store = try tls_core.early_data_replay.LocalStore.init(testing.allocator, .{}, 0, 0);
    defer store.deinit();
    var adapter = tls_core.early_data_replay.GateAdapter.init(store.store());
    const gate = adapter.gate();

    // No `resumption_runtime` supplied: the replay gate must still install,
    // proving it is not gated on resumption plumbing.
    var runtime = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        .early_data_replay_gate = gate,
    });
    defer runtime.deinit();

    const installed = runtime.early_data_replay_gate orelse return error.TestExpectedEqual;
    try testing.expectEqual(gate.ctx, installed.ctx);
    try testing.expectEqual(gate.decideFn, installed.decideFn);
}

test "runtime (#523): enable_0rtt enables the carrier only with complete composition, fails closed otherwise" {
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity());
    defer fixed.deinit();
    var logger = logger_mod.Logger.init(.err, "http3-0rtt-composition-test");

    var entropy = tls_core.production_crypto.OsEntropy{};
    var provider_state = tls_core.production_crypto.Provider.init(entropy.entropy());
    var resumption = try tls_core.resumption_runtime.Runtime.init(
        testing.allocator,
        .{ .mode = .stateful },
        .{ .ctx = undefined, .nowUnixMsFn = fixedNowUnixMsForTest },
        provider_state.cryptoProvider(),
    );
    defer resumption.deinit();

    var store = try tls_core.early_data_replay.LocalStore.init(testing.allocator, .{}, 0, 0);
    defer store.deinit();
    var gate_adapter = tls_core.early_data_replay.GateAdapter.init(store.store());
    const gate = gate_adapter.gate();

    // enable_0rtt requested but the replay gate is missing: fails closed.
    var incomplete = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        .resumption_runtime = &resumption,
        .enable_0rtt = true,
    });
    defer incomplete.deinit();
    try testing.expect(!incomplete.zero_rtt_enabled);
    try testing.expect(!incomplete.quic_config.zero_rtt_enabled);

    // `enable_0rtt = false` (the default) stays disabled even with full
    // composition otherwise present.
    var disabled = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        .resumption_runtime = &resumption,
        .early_data_replay_gate = gate,
    });
    defer disabled.deinit();
    try testing.expect(!disabled.zero_rtt_enabled);

    // Every dependency present: the carrier actually enables, and that same
    // decision reaches the QUIC transport config `accept()` hands every new
    // connection.
    var complete = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        .resumption_runtime = &resumption,
        .early_data_replay_gate = gate,
        .enable_0rtt = true,
    });
    defer complete.deinit();
    try testing.expect(complete.zero_rtt_enabled);
    try testing.expect(complete.quic_config.zero_rtt_enabled);
}

test "runtime (#523): a present-but-unusable resumption runtime or replay gate still fails closed" {
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity());
    defer fixed.deinit();
    var logger = logger_mod.Logger.init(.err, "http3-0rtt-usability-test");

    var entropy = tls_core.production_crypto.OsEntropy{};
    var provider_state = tls_core.production_crypto.Provider.init(entropy.entropy());

    // A `.mode = .disabled` resumption runtime is non-null but yields no PSK
    // resolver (`serverResolver() == null`) — `accept()` would install no
    // resolver at all, so the carrier must not report itself enabled.
    var disabled_mode_resumption = try tls_core.resumption_runtime.Runtime.init(
        testing.allocator,
        .{ .mode = .disabled },
        .{ .ctx = undefined, .nowUnixMsFn = fixedNowUnixMsForTest },
        provider_state.cryptoProvider(),
    );
    defer disabled_mode_resumption.deinit();

    var store = try tls_core.early_data_replay.LocalStore.init(testing.allocator, .{}, 0, 0);
    defer store.deinit();
    var gate_adapter = tls_core.early_data_replay.GateAdapter.init(store.store());
    const usable_gate = gate_adapter.gate();

    var disabled_mode = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        .resumption_runtime = &disabled_mode_resumption,
        .early_data_replay_gate = usable_gate,
        .enable_0rtt = true,
    });
    defer disabled_mode.deinit();
    try testing.expect(!disabled_mode.zero_rtt_enabled);

    // A default-constructed `EarlyDataReplayGate` (`decideFn == null`) is
    // non-null but fails closed (`.unavailable`) for every attempt on its
    // own — installing it doesn't make the carrier usable either.
    var usable_resumption = try tls_core.resumption_runtime.Runtime.init(
        testing.allocator,
        .{ .mode = .stateful },
        .{ .ctx = undefined, .nowUnixMsFn = fixedNowUnixMsForTest },
        provider_state.cryptoProvider(),
    );
    defer usable_resumption.deinit();

    var unconfigured_gate = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        .resumption_runtime = &usable_resumption,
        .early_data_replay_gate = .{},
        .enable_0rtt = true,
    });
    defer unconfigured_gate.deinit();
    try testing.expect(!unconfigured_gate.zero_rtt_enabled);

    // Sanity: both dependencies actually usable enables it, confirming the
    // two cases above are real negatives and not an over-broad check.
    var usable = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        .resumption_runtime = &usable_resumption,
        .early_data_replay_gate = usable_gate,
        .enable_0rtt = true,
    });
    defer usable.deinit();
    try testing.expect(usable.zero_rtt_enabled);
}

test "issueSessionTicket (#523): the production issuer advertises QUIC 0-RTT capability only when the carrier is enabled" {
    const allocator = testing.allocator;
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity());
    defer fixed.deinit();
    var logger = logger_mod.Logger.init(.err, "http3-ticket-issuance-test");

    var entropy = tls_core.production_crypto.OsEntropy{};
    var provider_state = tls_core.production_crypto.Provider.init(entropy.entropy());
    var resumption = try tls_core.resumption_runtime.Runtime.init(
        testing.allocator,
        .{ .mode = .stateful },
        .{ .ctx = undefined, .nowUnixMsFn = fixedNowUnixMsForTest },
        provider_state.cryptoProvider(),
    );
    defer resumption.deinit();

    var store = try tls_core.early_data_replay.LocalStore.init(testing.allocator, .{}, 0, 0);
    defer store.deinit();
    var gate_adapter = tls_core.early_data_replay.GateAdapter.init(store.store());
    const gate = gate_adapter.gate();

    var runtime = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        .resumption_runtime = &resumption,
        .early_data_replay_gate = gate,
        .enable_0rtt = true,
    });
    defer runtime.deinit();
    try testing.expect(runtime.zero_rtt_enabled);

    // Build a real, established client/server QUIC pair directly (not via
    // `runtime.accept()`, which needs a real UDP round trip) —
    // `prepareNewSessionTicket` requires a genuine post-handshake
    // resumption master secret, so there is no shortcut around a real
    // handshake. This mirrors `quic.connection`'s own private `TestPair`,
    // which isn't reachable from this file.
    const client_cid = [_]u8{ 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8 };
    const odcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_path = quic.path.PathKey{
        .local = quic.udp.Address.ip4(.{ 127, 0, 0, 1 }, 41_200),
        .remote = quic.udp.Address.ip4(.{ 127, 0, 0, 1 }, 41_201),
    };
    const server_path = quic.path.PathKey{
        .local = quic.udp.Address.ip4(.{ 127, 0, 0, 1 }, 41_201),
        .remote = quic.udp.Address.ip4(.{ 127, 0, 0, 1 }, 41_200),
    };
    const no_challenge = [_]u8{0} ** quic.path.path_challenge_len;

    var client_backend = try quic.tls_backend.Tls13Backend.initClientWithAllocator(
        allocator,
        .{ .hello_random = [_]u8{0xc1} ** 32, .key_share_seed = [_]u8{0x11} ** 32 },
        .{ .pinned_certificate = tls_core.credentials.testdata.certificate_der },
    );

    const Capture = struct {
        retained: tls_core.session.ClientTicketState = .{},
        count: usize = 0,

        fn now(_: *anyopaque) i64 {
            return 1000;
        }
        fn onTicket(ctx: *anyopaque, ticket: *const tls_core.session.ClientTicketState) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            ticket.cloneInto(testing.allocator, &self.retained) catch unreachable;
            self.count += 1;
        }
    };
    var capture = Capture{};
    defer capture.retained.deinit();
    try client_backend.engine.setSessionTicketConsumer(allocator, tls_core.session.Limits.default, .{
        .ctx = &capture,
        .nowUnixMsFn = Capture.now,
        .onTicketFn = Capture.onTicket,
    });

    const backend = try allocator.create(quic.tls_backend.Tls13Backend);
    backend.* = quic.tls_backend.Tls13Backend.initServerWithProvider(
        .{ .hello_random = [_]u8{0x51} ** 32, .key_share_seed = [_]u8{0x22} ** 32 },
        fixed.provider(),
    );

    const client = try Connection.init(allocator, .{
        .role = .client,
        .local_cid = &client_cid,
        .original_destination_cid = &odcid,
        .initial_secret_dcid = &odcid,
        .peer_cid = &odcid,
        .tls = client_backend.backend(),
        .now_us = 1_000_000,
        .initial_path = client_path,
    });
    defer client.deinit();
    const server_conn = try Connection.init(allocator, .{
        .role = .server,
        .local_cid = &odcid,
        .original_destination_cid = &odcid,
        .initial_secret_dcid = &odcid,
        .peer_cid = &client_cid,
        .tls = backend.backend(),
        .now_us = 1_000_000,
        .initial_path = server_path,
    });

    var entry = ConnEntry{
        .backend = backend,
        .conn = server_conn,
        .h3 = H3.initWithSettings(allocator, .server, .{}),
        .admission_source_ip = 0,
        .cid_len = odcid.len,
        .accepted_at_us = 1_000_000,
    };
    defer entry.deinit(allocator);

    var rounds: usize = 0;
    while (rounds < 64) : (rounds += 1) {
        var progressed = false;
        var buf: [2048]u8 = undefined;
        while (client.pollTransmitOnPath(&buf, 1_000_000)) |t| {
            try entry.conn.ingestOnPath(t.bytes, server_path, no_challenge, 1_000_000);
            progressed = true;
        }
        while (entry.conn.pollTransmitOnPath(&buf, 1_000_000)) |t| {
            try client.ingestOnPath(t.bytes, client_path, no_challenge, 1_000_000);
            progressed = true;
        }
        if (!progressed) break;
    }
    try testing.expect(client.isEstablished());
    try testing.expect(entry.conn.isEstablished());

    try runtime.issueSessionTicket(&entry, &resumption);

    // Deliver the queued NewSessionTicket CRYPTO data to the client.
    var rounds2: usize = 0;
    while (rounds2 < 16) : (rounds2 += 1) {
        var progressed = false;
        var buf: [2048]u8 = undefined;
        while (entry.conn.pollTransmitOnPath(&buf, 1_000_000)) |t| {
            try client.ingestOnPath(t.bytes, client_path, no_challenge, 1_000_000);
            progressed = true;
        }
        while (client.pollTransmitOnPath(&buf, 1_000_000)) |t| {
            try entry.conn.ingestOnPath(t.bytes, server_path, no_challenge, 1_000_000);
            progressed = true;
        }
        if (!progressed) break;
    }

    try testing.expectEqual(@as(usize, 1), capture.count);
    // #523: the production issuer must advertise QUIC 0-RTT capability with
    // the RFC 9001 §4.6.1 sentinel now that the carrier is actually
    // enabled — a ticket a resumed client can genuinely attempt 0-RTT with,
    // not one silently limited to resume-only.
    try testing.expectEqual(
        tls_core.session.EarlyDataPolicy{ .early_data_capable = std.math.maxInt(u32) },
        capture.retained.common.early_data,
    );
}

/// #523 test-only: seal a 0-RTT wire packet exactly the way a real client
/// sender would, mirroring `quic.connection`'s private `sealTestZeroRttPacket`
/// (not reachable from this file). Key derivation depends only on the
/// secret bytes, so a receiver with the same bytes installed at
/// `.zero_rtt read` genuinely decrypts this.
fn sealZeroRttPacketForTest(
    dcid: []const u8,
    scid: []const u8,
    secret: [quic.tls_adapter.traffic_secret_len]u8,
    pn: u64,
    plaintext: []const u8,
    out: []u8,
) []u8 {
    var sender = quic.tls_adapter.QuicTlsAdapter{};
    sender.setZeroRttEnabled(true);
    sender.installSecret(quic.tls_adapter.Secret.init(.zero_rtt, .write, &secret) catch unreachable);

    const pn_len: u3 = quic.packet.packetNumberLength(pn, null);
    const written = quic.packet.writeLongHeader(.zero_rtt, quic.packet.quic_v1, dcid, scid, "", pn_len, out) catch unreachable;
    const pn_offset = written.pn_offset;

    var padded: [1024]u8 = undefined;
    const sample_min = (4 - @as(usize, pn_len)) + quic.tls_adapter.header_protection_sample_len - quic.tls_adapter.packet_protection_tag_len;
    const padded_len = @max(plaintext.len, sample_min);
    @memcpy(padded[0..plaintext.len], plaintext);
    @memset(padded[plaintext.len..padded_len], 0);

    // The Length field precedes `pn_offset` and is covered by the AEAD
    // associated data, so it must be patched before sealing.
    quic.packet.patchLongHeaderLength(out, written.length_offset, pn_len + padded_len + quic.tls_adapter.packet_protection_tag_len);

    const truncated = quic.packet.truncatePacketNumber(pn, pn_len);
    var pn_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &pn_bytes, truncated, .big);
    @memcpy(out[pn_offset..][0..pn_len], pn_bytes[4 - @as(usize, pn_len) ..][0..pn_len]);

    const header = out[0 .. pn_offset + pn_len];
    const keys = sender.protectionKeys(.zero_rtt, .write).?;
    _ = sender.sealPacketPayload(.zero_rtt, .write, pn, header, padded[0..padded_len], out[pn_offset + pn_len ..]) catch unreachable;

    var sample: [quic.tls_adapter.header_protection_sample_len]u8 = undefined;
    @memcpy(&sample, out[pn_offset + 4 ..][0..quic.tls_adapter.header_protection_sample_len]);
    keys.applyHeaderProtection(&out[0], out[pn_offset..][0..pn_len], sample);

    return out[0 .. pn_offset + pn_len + padded_len + quic.tls_adapter.packet_protection_tag_len];
}

/// #523 test-only: encode a real HTTP/3 request (QPACK HEADERS frame, no
/// body) — the same primitives `http3.conn.Conn.sendRequest` uses — so the
/// production H3 request parser genuinely has to decode this, not a
/// synthetic shortcut.
fn buildH3RequestBytesForTest(method: []const u8, path: []const u8, authority: []const u8, out: []u8) []const u8 {
    var fields = [_]http3.qpack.HeaderField{
        .{ .name = ":method", .value = method },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = authority },
        .{ .name = ":path", .value = path },
    };
    var block: [256]u8 = undefined;
    const header_block = http3.qpack.encode(&fields, &block) catch unreachable;
    return http3.frame.encodeKnownFrame(.headers, header_block, out) catch unreachable;
}

/// #523 test-only: an embedder-shaped request handler using the actual
/// shared, transport-neutral early-data policy (`http.early_data.decide`,
/// the same primitive `gateway_handlers.zig`'s production routing uses) —
/// not a second, test-invented safety layer. `action_class = .local`
/// mirrors an origin server (not a reverse proxy), the shape
/// `http3_runtime.Config.request_handler` is meant for.
const TestEarlyDataHandlerState = struct {
    executed_local: usize = 0,
    rejected_too_early: usize = 0,
    last_method_buf: [8]u8 = undefined,
    last_method_len: usize = 0,
};

fn testEarlyDataAwareHandler(
    _: std.mem.Allocator,
    request: *const http3_session.StreamRequest,
    response: *response_mod.Response,
    user_data: ?*anyopaque,
) anyerror!void {
    const state: *TestEarlyDataHandlerState = @ptrCast(@alignCast(user_data.?));
    const decision = early_data_policy.decide(.{
        .replay_exposed = request.transport_early,
        .transport_early = request.transport_early,
        .inbound_marker = false,
        .method_safe = early_data_policy.methodSafe(request.method),
        .route_replay_safe = true,
        .action_class = .local,
        .proxy_origin_rfc8470 = false,
    });
    switch (decision) {
        .too_early => {
            state.rejected_too_early += 1;
            response.status = .too_early;
        },
        .ordinary, .execute_local => {
            state.executed_local += 1;
            const len = @min(request.method.len, state.last_method_buf.len);
            @memcpy(state.last_method_buf[0..len], request.method[0..len]);
            state.last_method_len = len;
            response.status = .ok;
        },
        .forward_rfc8470, .defer_until_handshake => unreachable, // action_class = .local never yields these
    }
}

test "http3 (#523): a replay-safe early request reaches the local handler exactly once; an unsafe one is rejected without dispatch; ordinary post-handshake requests still work" {
    const allocator = testing.allocator;
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity());
    defer fixed.deinit();
    var logger = logger_mod.Logger.init(.err, "http3-early-request-matrix-test");

    var server_entropy = tls_core.production_crypto.OsEntropy{};
    var server_provider_state = tls_core.production_crypto.Provider.init(server_entropy.entropy());
    var resumption = try tls_core.resumption_runtime.Runtime.init(
        testing.allocator,
        .{ .mode = .stateful },
        .{ .ctx = undefined, .nowUnixMsFn = fixedNowUnixMsForTest },
        server_provider_state.cryptoProvider(),
    );
    defer resumption.deinit();

    // A separate client-side runtime instance for storing/looking up the
    // client's own tickets — the server-side `resumption` above and this
    // one play distinct roles, exactly as they would across two real
    // processes, matching the pattern the #488 connection-level tests use.
    var client_entropy = tls_core.production_crypto.OsEntropy{};
    var client_provider_state = tls_core.production_crypto.Provider.init(client_entropy.entropy());
    var client_resumption = try tls_core.resumption_runtime.Runtime.init(
        testing.allocator,
        .{ .mode = .stateful },
        .{ .ctx = undefined, .nowUnixMsFn = fixedNowUnixMsForTest },
        client_provider_state.cryptoProvider(),
    );
    defer client_resumption.deinit();

    // `LocalStore`'s real `claim()` path reads real wall-clock time
    // (`trampolineClaim` → `zig_compat.milliTimestamp()`), while this
    // test's resumption clock is a small fixed value for determinism —
    // those would never agree on a retention window. An always-allow gate
    // still installs through the exact same `EarlyDataReplayGate` seam
    // production composition uses (proving that seam, not a second policy
    // layer); `LocalStore`'s own real-clock claim behavior has its own
    // dedicated test coverage elsewhere.
    const AlwaysAllow = struct {
        fn decide(_: *anyopaque, _: tls_core.tls13_backend.EarlyDataReplayCandidate) tls_core.tls13_backend.EarlyDataReplayDecision {
            return .allow;
        }
    };
    var replay_ctx: u8 = 0;
    const gate: tls_core.tls13_backend.EarlyDataReplayGate = .{ .ctx = &replay_ctx, .decideFn = AlwaysAllow.decide };

    var handler_state = TestEarlyDataHandlerState{};
    var runtime = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        .resumption_runtime = &resumption,
        .early_data_replay_gate = gate,
        .enable_0rtt = true,
        .request_handler = testEarlyDataAwareHandler,
        .request_handler_ctx = &handler_state,
    });
    defer runtime.deinit();
    try testing.expect(runtime.zero_rtt_enabled);

    // Phase 1: a real handshake, then a real ticket obtained from the
    // production issuance path (`runtime.issueSessionTicket`), not a
    // manually-constructed one.
    const client_cid = [_]u8{ 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8 };
    const odcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_path = quic.path.PathKey{
        .local = quic.udp.Address.ip4(.{ 127, 0, 0, 1 }, 41_300),
        .remote = quic.udp.Address.ip4(.{ 127, 0, 0, 1 }, 41_301),
    };
    const server_path = quic.path.PathKey{
        .local = quic.udp.Address.ip4(.{ 127, 0, 0, 1 }, 41_301),
        .remote = quic.udp.Address.ip4(.{ 127, 0, 0, 1 }, 41_300),
    };
    const no_challenge = [_]u8{0} ** quic.path.path_challenge_len;

    var client_backend = try quic.tls_backend.Tls13Backend.initClientWithAllocator(
        allocator,
        .{ .hello_random = [_]u8{0xc1} ** 32, .key_share_seed = [_]u8{0x11} ** 32 },
        .{ .pinned_certificate = tls_core.credentials.testdata.certificate_der },
    );

    const Capture = struct {
        runtime: *tls_core.resumption_runtime.Runtime,
        retained: tls_core.session.ClientTicketState = .{},
        stored: tls_core.session_cache.StoreResult = undefined,
        count: usize = 0,
        fn now(_: *anyopaque) i64 {
            return 1000;
        }
        fn onTicket(ctx: *anyopaque, ticket: *const tls_core.session.ClientTicketState) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            ticket.cloneInto(testing.allocator, &self.retained) catch unreachable;
            self.stored = self.runtime.storeClientTicket(ticket);
            self.count += 1;
        }
    };
    var capture = Capture{ .runtime = &client_resumption };
    defer capture.retained.deinit();
    try client_backend.engine.setSessionTicketConsumer(allocator, tls_core.session.Limits.default, .{
        .ctx = &capture,
        .nowUnixMsFn = Capture.now,
        .onTicketFn = Capture.onTicket,
    });

    const backend1 = try allocator.create(quic.tls_backend.Tls13Backend);
    backend1.* = quic.tls_backend.Tls13Backend.initServerWithProvider(
        .{ .hello_random = [_]u8{0x51} ** 32, .key_share_seed = [_]u8{0x22} ** 32 },
        fixed.provider(),
    );
    // Native QUIC 1-RTT resumption deliberately ignores connection-specific
    // transport/application snapshots for *ordinary* resumption matching
    // (mirrors `accept()`'s own `.transport = .ignore` — see
    // `h3EarlyDataCompatibility`'s doc comment) — without this, the ticket's
    // `common.transport_compat` gets stamped non-null and the phase-2
    // candidate lookup below (which intentionally supplies no
    // transport/application compat context) would miss on origin-digest
    // mismatch rather than genuinely testing 0-RTT compatibility.
    const resume_policy: tls_core.tls13_backend.Tls13Backend.ResumeCompatibilityPolicy = .{ .transport = .ignore, .application = .ignore };
    try client_backend.setResumeCompatibilityPolicy(resume_policy);
    try backend1.setResumeCompatibilityPolicy(resume_policy);

    const client1 = try Connection.init(allocator, .{
        .role = .client,
        .local_cid = &client_cid,
        .original_destination_cid = &odcid,
        .initial_secret_dcid = &odcid,
        .peer_cid = &odcid,
        .tls = client_backend.backend(),
        .now_us = 1_000_000,
        .initial_path = client_path,
    });
    defer client1.deinit();
    const server_conn1 = try Connection.init(allocator, .{
        .role = .server,
        .local_cid = &odcid,
        .original_destination_cid = &odcid,
        .initial_secret_dcid = &odcid,
        .peer_cid = &client_cid,
        .tls = backend1.backend(),
        .now_us = 1_000_000,
        .initial_path = server_path,
    });

    var entry1 = ConnEntry{
        .backend = backend1,
        .conn = server_conn1,
        .h3 = H3.initWithSettings(allocator, .server, .{}),
        .admission_source_ip = 0,
        .cid_len = odcid.len,
        .accepted_at_us = 1_000_000,
    };
    defer entry1.deinit(allocator);

    {
        var rounds: usize = 0;
        while (rounds < 64) : (rounds += 1) {
            var progressed = false;
            var buf: [2048]u8 = undefined;
            while (client1.pollTransmitOnPath(&buf, 1_000_000)) |t| {
                try entry1.conn.ingestOnPath(t.bytes, server_path, no_challenge, 1_000_000);
                progressed = true;
            }
            while (entry1.conn.pollTransmitOnPath(&buf, 1_000_000)) |t| {
                try client1.ingestOnPath(t.bytes, client_path, no_challenge, 1_000_000);
                progressed = true;
            }
            if (!progressed) break;
        }
    }
    try testing.expect(client1.isEstablished());
    try testing.expect(entry1.conn.isEstablished());

    try runtime.issueSessionTicket(&entry1, &resumption);
    {
        var rounds: usize = 0;
        while (rounds < 16) : (rounds += 1) {
            var progressed = false;
            var buf: [2048]u8 = undefined;
            while (entry1.conn.pollTransmitOnPath(&buf, 1_000_000)) |t| {
                try client1.ingestOnPath(t.bytes, client_path, no_challenge, 1_000_000);
                progressed = true;
            }
            while (client1.pollTransmitOnPath(&buf, 1_000_000)) |t| {
                try entry1.conn.ingestOnPath(t.bytes, server_path, no_challenge, 1_000_000);
                progressed = true;
            }
            if (!progressed) break;
        }
    }
    try testing.expectEqual(@as(usize, 1), capture.count);
    try testing.expectEqual(tls_core.session_cache.StoreResult.stored, capture.stored);

    // Phase 2: a fresh resumed connection actually attempting/accepting
    // 0-RTT, composed exactly the way `accept()` wires it in production.
    const candidate: tls_core.session.CandidateContext = .{
        .cipher_suite = capture.retained.common.cipher_suite,
        .server_name = if (capture.retained.common.server_name) |*s| s.slice() else null,
        .application_protocol = if (capture.retained.common.application_protocol) |*a| a.slice() else null,
        .auth_binding = capture.retained.common.auth_binding,
        .transport_compat = null,
        .application_compat = null,
    };
    var lookup = client_resumption.lookupClientOffers(candidate);
    defer lookup.deinit();
    try testing.expect(lookup == .hit);

    var client_backend2 = quic.tls_backend.Tls13Backend.initClient(
        .{ .hello_random = [_]u8{0xe1} ** 32, .key_share_seed = [_]u8{0x41} ** 32 },
        .{ .pinned_certificate = tls_core.credentials.testdata.certificate_der },
    );
    var clock_dummy: u8 = 0;
    const ClientClock = struct {
        fn now(_: *anyopaque) i64 {
            return 2000;
        }
    };
    try client_backend2.engine.setClientPskOfferLease(&lookup.hit, &clock_dummy, ClientClock.now);
    try client_backend2.setResumeCompatibilityPolicy(.{ .transport = .ignore, .application = .ignore });
    try client_backend2.setClientEarlyDataIntent(.{ .enabled = true, .max_bytes = 65536 });

    const backend2 = try allocator.create(quic.tls_backend.Tls13Backend);
    backend2.* = quic.tls_backend.Tls13Backend.initServerWithProvider(
        .{ .hello_random = [_]u8{0xe2} ** 32, .key_share_seed = [_]u8{0x42} ** 32 },
        fixed.provider(),
    );
    try backend2.setResumeCompatibilityPolicy(.{ .transport = .ignore, .application = .ignore });
    try backend2.setServerPskResolver(resumption.serverResolver().?);
    try backend2.setEarlyDataReplayGate(gate);
    try backend2.setServerEarlyDataPolicy(.{ .enabled = true });

    const client2 = try Connection.init(allocator, .{
        .role = .client,
        .config = .{ .zero_rtt_enabled = true },
        .local_cid = &client_cid,
        .original_destination_cid = &odcid,
        .initial_secret_dcid = &odcid,
        .peer_cid = &odcid,
        .tls = client_backend2.backend(),
        .now_us = 2_000_000,
        .initial_path = client_path,
    });
    defer client2.deinit();

    // There is no production client-side 0-RTT transmit path — the two
    // fabricated 0-RTT packets below are sealed by a throwaway sender
    // adapter operating entirely outside `client2`'s own connection state
    // (see `sealZeroRttPacketForTest`) — so without this, `client2`'s own
    // `StreamManager` would have no record of stream ids 40/44 at all. Once
    // established, the server refreshes send credit for every stream it
    // knows about (`StreamManager.refreshPeerParams`) and each early
    // request's H3 response travels back on that same bidi stream id, both
    // of which `client2` would otherwise reject as `error.UnknownStream`,
    // aborting the connection before it could ever serve a later request.
    // Bring `client2`'s stream layer up early — mirroring
    // `Connection.ensureEarlyStreamManager`, which never runs client-side
    // since a client never receives a `.zero_rtt`-level packet itself — and
    // seed it with placeholder `Stream` entries at exactly those two ids,
    // standing in for the state a real client would already have from
    // having opened them itself before transmitting its own early data.
    client2.streams = quic.stream.StreamManager.init(allocator, .client, client2.local_params, client2.local_params);
    inline for (.{ @as(quic.stream.StreamId, 40), @as(quic.stream.StreamId, 44) }) |placeholder_id| {
        const placeholder = try allocator.create(quic.stream.Stream);
        placeholder.* = .{
            .id = placeholder_id,
            .role = .client,
            .typ = .bidi,
            .init = .client,
            .initial_recv_window = client2.local_params.initial_max_stream_data_bidi_local,
            .max_recv_data = client2.local_params.initial_max_stream_data_bidi_local,
            .max_send_data = 0,
        };
        try client2.streams.?.streams.put(placeholder_id, placeholder);
    }

    const server_conn2 = try Connection.init(allocator, .{
        .role = .server,
        .config = .{ .zero_rtt_enabled = true },
        .local_cid = &odcid,
        .original_destination_cid = &odcid,
        .initial_secret_dcid = &odcid,
        .peer_cid = &client_cid,
        .tls = backend2.backend(),
        .now_us = 2_000_000,
        .initial_path = server_path,
    });

    var entry2 = ConnEntry{
        .backend = backend2,
        .conn = server_conn2,
        .h3 = H3.initWithSettings(allocator, .server, .{}),
        .admission_source_ip = 0,
        .cid_len = odcid.len,
        .accepted_at_us = 2_000_000,
    };
    defer entry2.deinit(allocator);

    // Drive only the client's first flight so the server accepts 0-RTT and
    // installs its read key, but is not yet established — the actual
    // early-data window this test targets.
    {
        var buf: [2048]u8 = undefined;
        while (client2.pollTransmitOnPath(&buf, 2_000_000)) |t| {
            try entry2.conn.ingestOnPath(t.bytes, server_path, no_challenge, 2_000_000);
        }
    }
    try testing.expect(!entry2.conn.isEstablished());
    try testing.expect(entry2.conn.adapter.protectionKeys(.zero_rtt, .read) != null);

    const real_secret = entry2.conn.adapter.secret(.zero_rtt, .read).?.slice()[0..quic.tls_adapter.traffic_secret_len].*;

    // Two real, QPACK-encoded 0-RTT H3 requests on distinct stream ids
    // (40/44, staying clear of the ids the client's own stream manager will
    // naturally hand out later for the ordinary post-handshake request) —
    // a replay-safe GET and a replay-unsafe POST.
    var get_h3: [128]u8 = undefined;
    const get_bytes = buildH3RequestBytesForTest("GET", "/safe", "example.com", &get_h3);
    var get_frame_buf: [160]u8 = undefined;
    const get_frame_len = try quic.frame.encodeStream(40, 0, get_bytes, true, &get_frame_buf);
    var get_wire: [512]u8 = undefined;
    const get_datagram = sealZeroRttPacketForTest(&odcid, &client_cid, real_secret, 0, get_frame_buf[0..get_frame_len], &get_wire);
    try entry2.conn.ingestOnPath(get_datagram, server_path, no_challenge, 2_000_000);

    var post_h3: [128]u8 = undefined;
    const post_bytes = buildH3RequestBytesForTest("POST", "/unsafe", "example.com", &post_h3);
    var post_frame_buf: [160]u8 = undefined;
    const post_frame_len = try quic.frame.encodeStream(44, 0, post_bytes, true, &post_frame_buf);
    var post_wire: [512]u8 = undefined;
    const post_datagram = sealZeroRttPacketForTest(&odcid, &client_cid, real_secret, 1, post_frame_buf[0..post_frame_len], &post_wire);
    try entry2.conn.ingestOnPath(post_datagram, server_path, no_challenge, 2_000_000);

    // The two fabricated 0-RTT packets above used application-space packet
    // numbers 0 and 1 through a throwaway sender adapter alongside (not
    // through) `client2`'s own transmit path — there is no real client
    // 0-RTT transmit path to drive instead (see `sealZeroRttPacketForTest`).
    // The server's ACKs for those packet numbers raise `client2`'s own
    // `largest_peer_acked` for this space once received; advance `client2`'s
    // own send counter to match what the server has already recorded as
    // used, so `client2`'s later real packets don't collide with (and get
    // authenticated as duplicates of, or worse — encoded with a packet
    // number `packetNumberLength` asserts is impossible relative to an
    // already-higher acked value — see RFC 9000 §17.1) those already-
    // consumed numbers.
    client2.next_pn[@intFromEnum(quic.recovery.PacketNumberSpace.application)] = 2;

    // Drive H3 during the early-data window — before establishment. This is
    // exactly `pumpH3`, the function the second-pass review's finding #2
    // required to work pre-establishment.
    runtime.pumpH3(&entry2, 2_000_000);

    // The safe GET reached the local-execution path exactly once; the
    // unsafe POST was rejected by the shared early-data policy without
    // ever reaching that path — proving the safety decision, not just
    // QUIC-level STREAM delivery.
    try testing.expectEqual(@as(usize, 1), handler_state.executed_local);
    try testing.expectEqualStrings("GET", handler_state.last_method_buf[0..handler_state.last_method_len]);
    try testing.expectEqual(@as(usize, 1), handler_state.rejected_too_early);

    // The rest of the handshake completes normally on the *same* connection
    // that just attempted 0-RTT — accepted/rejected early requests don't
    // derail ordinary 1-RTT completion. This is where the queued 425 for
    // the unsafe POST above (and the 200 for the safe GET) actually reach
    // the wire: the placeholder streams seeded above let `client2` accept
    // the server's MAX_STREAM_DATA credit renewal and each response's
    // STREAM frames on ids 40/44 without erroring `UnknownStream`.
    {
        var rounds: usize = 0;
        while (rounds < 64) : (rounds += 1) {
            var progressed = false;
            var buf: [2048]u8 = undefined;
            while (client2.pollTransmitOnPath(&buf, 2_000_000)) |t| {
                try entry2.conn.ingestOnPath(t.bytes, server_path, no_challenge, 2_000_000);
                progressed = true;
            }
            while (entry2.conn.pollTransmitOnPath(&buf, 2_000_000)) |t| {
                try client2.ingestOnPath(t.bytes, client_path, no_challenge, 2_000_000);
                progressed = true;
            }
            runtime.pumpH3(&entry2, 2_000_000);
            if (!progressed) break;
        }
    }
    try testing.expect(client2.isEstablished());
    try testing.expect(entry2.conn.isEstablished());

    // Ordinary (non-early) request post-handshake, on that *same*
    // connection: even an otherwise-unsafe method dispatches normally once
    // established, proving the 425 above was strictly an early-data-window
    // decision, not a permanent rejection of that route — and proving the
    // connection that attempted 0-RTT is itself genuinely usable
    // afterward, not just some other, cleaner connection. `openStream`
    // hands out id 0 (the first *real* client-opened bidi stream — the
    // placeholder ids 40/44 above bypassed `openLocal`'s counter entirely),
    // so there is no collision with the fabricated early streams.
    const ordinary_id = try client2.openStream(.bidi);
    var ordinary_h3: [128]u8 = undefined;
    const ordinary_bytes = buildH3RequestBytesForTest("POST", "/ordinary", "example.com", &ordinary_h3);
    _ = try client2.writeStream(ordinary_id, ordinary_bytes, true);
    {
        var rounds: usize = 0;
        while (rounds < 32) : (rounds += 1) {
            var progressed = false;
            var buf: [2048]u8 = undefined;
            while (client2.pollTransmitOnPath(&buf, 2_000_000)) |t| {
                try entry2.conn.ingestOnPath(t.bytes, server_path, no_challenge, 2_000_000);
                progressed = true;
            }
            while (entry2.conn.pollTransmitOnPath(&buf, 2_000_000)) |t| {
                try client2.ingestOnPath(t.bytes, client_path, no_challenge, 2_000_000);
                progressed = true;
            }
            runtime.pumpH3(&entry2, 2_000_000);
            if (!progressed) break;
        }
    }
    try testing.expectEqual(@as(usize, 2), handler_state.executed_local);
    try testing.expectEqualStrings("POST", handler_state.last_method_buf[0..handler_state.last_method_len]);
    try testing.expectEqual(@as(usize, 1), handler_state.rejected_too_early);

    // Handler counters only prove the local dispatch/rejection decision —
    // decode the actual bytes `client2` received on the wire to prove the
    // responses themselves were transmitted: the safe GET's 200 on stream
    // 40, and — the specific proof this review round required — the
    // unsafe POST's 425 on stream 44, showing the queued early-rejection
    // response genuinely reached the client once 1-RTT became
    // send-capable, not just that a counter was incremented server-side.
    try expectH3ResponseStatusForTest(client2, 40, "200");
    try expectH3ResponseStatusForTest(client2, 44, "425");
}

/// #523 test-only: read a stream to EOF-of-buffer and decode its first H3
/// frame as a QPACK HEADERS block, asserting `:status` matches `expected`.
fn expectH3ResponseStatusForTest(conn: *Connection, stream_id: quic.stream.StreamId, expected_status: []const u8) !void {
    var buf: [512]u8 = undefined;
    const result = try conn.readStream(stream_id, &buf);
    const raw = try http3.frame.decodeFrame(buf[0..result.len]);
    try testing.expectEqual(http3.frame.FrameType.headers, raw.typ);

    var fields: [8]http3.qpack.HeaderField = undefined;
    var scratch: [256]u8 = undefined;
    const count = try http3.qpack.decode(raw.payload, &fields, &scratch);
    for (fields[0..count]) |field| {
        if (std.mem.eql(u8, field.name, ":status")) {
            try testing.expectEqualStrings(expected_status, field.value);
            return;
        }
    }
    return error.MissingStatusField;
}

const H3EarlyDataRejectionScenario = struct {
    // Always an installed, decideFn-non-null gate — never absent. Production
    // `accept()` always wires a real gate (`zeroRttCarrierEnabled` refuses
    // to enable 0-RTT at all otherwise); modeling "the replay store is
    // unavailable" as literally no gate installed would test a composition
    // that can never occur in production. An operationally-unavailable
    // store is instead a real, installed gate whose `decide` always returns
    // `.unavailable` (see the replay-store-unavailable test below).
    replay_gate: tls_core.tls13_backend.EarlyDataReplayGate,
    mutate: *const fn (*Runtime) void,
    // The H3 SETTINGS snapshot `backend1` remembers into the ticket at
    // issuance time. Defaults to `.{}`, matching the runtime's own (always
    // default — see below) live `h3_settings` exactly, so every scenario
    // except the application-incompatible one is fully app-compatible and
    // isolates its own specific rejection reason. The application-
    // incompatible scenario overrides this to a *stricter remembered*
    // value instead of reducing the runtime's *live* settings: phase 2's
    // H3 session is initialized with `runtime.h3_settings` (mirroring
    // `accept()`), and that must stay within
    // `validateLocallySupportedSettings`'s bounds or the H3 session never
    // starts at all (see "H3 conn: start rejects unsupported
    // max_field_section_size" in `src/http3/conn.zig`) — silently breaking
    // the same-connection 1-RTT fallback this whole matrix is proving.
    remembered_app_settings: http3.frame.Settings = .{},
    expect_decision: metrics_mod.QuicEarlyDataDecision,
};

fn h3EarlyDataRejectionNoMutation(_: *Runtime) void {}

fn h3EarlyDataRejectionReduceTransportLimit(runtime: *Runtime) void {
    runtime.quic_config.initial_max_streams_bidi -= 1;
}

/// Shared production-shaped scaffold for #523's "0-RTT rejected -> same
/// resumed connection still serves a real H3 request over 1-RTT" matrix.
/// Phase 1 mirrors `accept()`'s exact composition (including the H3
/// application-compat snapshot installed at ticket-issuance time — omitting
/// it left a prior version of this test able to pass for the wrong
/// rejection reason, since a ticket with no remembered application state at
/// all resolves to `.application_incompatible` regardless of the transport
/// snapshot). Phase 2 wires the *real* `Runtime.h3EarlyDataCompatibility`
/// gate and the *real* `Runtime.quicConnectionEvent` bridge production uses,
/// so the typed early-data decision this asserts on is the one that would
/// actually reach metrics in production, not a synthetic stand-in.
fn expectH3EarlyDataRejectionFallsBackToRealRequest(scenario: H3EarlyDataRejectionScenario) !void {
    const allocator = testing.allocator;
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity());
    defer fixed.deinit();
    var logger = logger_mod.Logger.init(.err, "http3-early-request-rejection-matrix-test");

    var server_entropy = tls_core.production_crypto.OsEntropy{};
    var server_provider_state = tls_core.production_crypto.Provider.init(server_entropy.entropy());
    var resumption = try tls_core.resumption_runtime.Runtime.init(
        testing.allocator,
        .{ .mode = .stateful },
        .{ .ctx = undefined, .nowUnixMsFn = fixedNowUnixMsForTest },
        server_provider_state.cryptoProvider(),
    );
    defer resumption.deinit();

    var client_entropy = tls_core.production_crypto.OsEntropy{};
    var client_provider_state = tls_core.production_crypto.Provider.init(client_entropy.entropy());
    var client_resumption = try tls_core.resumption_runtime.Runtime.init(
        testing.allocator,
        .{ .mode = .stateful },
        .{ .ctx = undefined, .nowUnixMsFn = fixedNowUnixMsForTest },
        client_provider_state.cryptoProvider(),
    );
    defer client_resumption.deinit();

    var handler_state = TestEarlyDataHandlerState{};

    const DecisionCapture = struct {
        count: usize = 0,
        last: ?metrics_mod.QuicEarlyDataDecision = null,
        fn onDecision(ctx: *anyopaque, decision: metrics_mod.QuicEarlyDataDecision) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.count += 1;
            self.last = decision;
        }
    };
    var decision_capture = DecisionCapture{};

    const PacketCapture = struct {
        count: usize = 0,
        last: ?metrics_mod.QuicZeroRttPacketOutcome = null,
        fn onPacket(ctx: *anyopaque, outcome: metrics_mod.QuicZeroRttPacketOutcome) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.count += 1;
            self.last = outcome;
        }
    };
    var packet_capture = PacketCapture{};

    // The scenario's gate is the *runtime's own* configured gate — not a
    // separate placeholder — so this proves the full production ownership
    // chain: the process-shared gate configured on `Runtime` (what
    // `accept()` actually reads) is the one driving the TLS decision, not
    // just that some TLS backend behaves correctly with a gate handed to it
    // directly.
    var runtime = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        .resumption_runtime = &resumption,
        .early_data_replay_gate = scenario.replay_gate,
        .enable_0rtt = true,
        .request_handler = testEarlyDataAwareHandler,
        .request_handler_ctx = &handler_state,
        .quic_early_data_decision_metrics_ctx = &decision_capture,
        .quic_early_data_decision_metrics_cb = DecisionCapture.onDecision,
        .quic_zero_rtt_packet_metrics_ctx = &packet_capture,
        .quic_zero_rtt_packet_metrics_cb = PacketCapture.onPacket,
    });
    defer runtime.deinit();
    try testing.expect(runtime.zero_rtt_enabled);

    // Phase 1: a real handshake, then a real ticket obtained from the
    // production issuance path. `server_conn1` is explicitly constructed
    // with the runtime's own live `quic_config` (mirrors `accept()`'s
    // `.config = self.quic_config`) so the transport-parameters snapshot
    // the ticket remembers is exactly what `Runtime.h3EarlyDataCompatibility`
    // will later compare a possibly-mutated live config against.
    const client_cid = [_]u8{ 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8 };
    const odcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_path = quic.path.PathKey{
        .local = quic.udp.Address.ip4(.{ 127, 0, 0, 1 }, 41_310),
        .remote = quic.udp.Address.ip4(.{ 127, 0, 0, 1 }, 41_311),
    };
    const server_path = quic.path.PathKey{
        .local = quic.udp.Address.ip4(.{ 127, 0, 0, 1 }, 41_311),
        .remote = quic.udp.Address.ip4(.{ 127, 0, 0, 1 }, 41_310),
    };
    const no_challenge = [_]u8{0} ** quic.path.path_challenge_len;

    var client_backend = try quic.tls_backend.Tls13Backend.initClientWithAllocator(
        allocator,
        .{ .hello_random = [_]u8{0xc1} ** 32, .key_share_seed = [_]u8{0x11} ** 32 },
        .{ .pinned_certificate = tls_core.credentials.testdata.certificate_der },
    );

    const Capture = struct {
        runtime: *tls_core.resumption_runtime.Runtime,
        retained: tls_core.session.ClientTicketState = .{},
        stored: tls_core.session_cache.StoreResult = undefined,
        count: usize = 0,
        fn now(_: *anyopaque) i64 {
            return 1000;
        }
        fn onTicket(ctx: *anyopaque, ticket: *const tls_core.session.ClientTicketState) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            ticket.cloneInto(testing.allocator, &self.retained) catch unreachable;
            self.stored = self.runtime.storeClientTicket(ticket);
            self.count += 1;
        }
    };
    var capture = Capture{ .runtime = &client_resumption };
    defer capture.retained.deinit();
    try client_backend.engine.setSessionTicketConsumer(allocator, tls_core.session.Limits.default, .{
        .ctx = &capture,
        .nowUnixMsFn = Capture.now,
        .onTicketFn = Capture.onTicket,
    });

    const backend1 = try allocator.create(quic.tls_backend.Tls13Backend);
    backend1.* = quic.tls_backend.Tls13Backend.initServerWithProvider(
        .{ .hello_random = [_]u8{0x51} ** 32, .key_share_seed = [_]u8{0x22} ** 32 },
        fixed.provider(),
    );
    const resume_policy: tls_core.tls13_backend.Tls13Backend.ResumeCompatibilityPolicy = .{ .transport = .ignore, .application = .ignore };
    try client_backend.setResumeCompatibilityPolicy(resume_policy);
    try backend1.setResumeCompatibilityPolicy(resume_policy);
    // Mirror production `accept()`'s installation of the H3 application
    // compat snapshot at ticket-issuance time — without this, the ticket
    // has no remembered application state at all, and a scenario meant to
    // isolate one specific rejection reason could actually be passing for a
    // different one (`application_incompatible` via `missing_state`)
    // instead. Encoded fresh from `scenario.remembered_app_settings` rather
    // than reusing `runtime.h3_application_compat` directly: every scenario
    // but the application-incompatible one leaves this at `.{}`, which
    // encodes identically to the runtime's own default `h3_settings`, so
    // this is a distinction without a difference for them — but the
    // application-incompatible scenario needs a *stricter remembered*
    // snapshot than the (always locally-supported-default) live settings.
    var remembered_app_compat_buf: [http3.early_data.encoded_snapshot_len]u8 = undefined;
    const remembered_app_compat_bytes = try http3.early_data.encodeSettingsSnapshot(scenario.remembered_app_settings, &remembered_app_compat_buf);
    try backend1.setEarlyDataApplicationCompat(.{
        .format_id = http3.early_data.format_id,
        .format_version = http3.early_data.format_version,
        .bytes = remembered_app_compat_bytes,
    });

    const client1 = try Connection.init(allocator, .{
        .role = .client,
        .local_cid = &client_cid,
        .original_destination_cid = &odcid,
        .initial_secret_dcid = &odcid,
        .peer_cid = &odcid,
        .tls = client_backend.backend(),
        .now_us = 1_000_000,
        .initial_path = client_path,
    });
    defer client1.deinit();
    const server_conn1 = try Connection.init(allocator, .{
        .role = .server,
        .config = runtime.quic_config,
        .local_cid = &odcid,
        .original_destination_cid = &odcid,
        .initial_secret_dcid = &odcid,
        .peer_cid = &client_cid,
        .tls = backend1.backend(),
        .now_us = 1_000_000,
        .initial_path = server_path,
    });

    var entry1 = ConnEntry{
        .backend = backend1,
        .conn = server_conn1,
        .h3 = H3.initWithSettings(allocator, .server, .{}),
        .admission_source_ip = 0,
        .cid_len = odcid.len,
        .accepted_at_us = 1_000_000,
    };
    defer entry1.deinit(allocator);

    {
        var rounds: usize = 0;
        while (rounds < 64) : (rounds += 1) {
            var progressed = false;
            var buf: [2048]u8 = undefined;
            while (client1.pollTransmitOnPath(&buf, 1_000_000)) |t| {
                try entry1.conn.ingestOnPath(t.bytes, server_path, no_challenge, 1_000_000);
                progressed = true;
            }
            while (entry1.conn.pollTransmitOnPath(&buf, 1_000_000)) |t| {
                try client1.ingestOnPath(t.bytes, client_path, no_challenge, 1_000_000);
                progressed = true;
            }
            if (!progressed) break;
        }
    }
    try testing.expect(client1.isEstablished());
    try testing.expect(entry1.conn.isEstablished());

    try runtime.issueSessionTicket(&entry1, &resumption);
    {
        var rounds: usize = 0;
        while (rounds < 16) : (rounds += 1) {
            var progressed = false;
            var buf: [2048]u8 = undefined;
            while (entry1.conn.pollTransmitOnPath(&buf, 1_000_000)) |t| {
                try client1.ingestOnPath(t.bytes, client_path, no_challenge, 1_000_000);
                progressed = true;
            }
            while (client1.pollTransmitOnPath(&buf, 1_000_000)) |t| {
                try entry1.conn.ingestOnPath(t.bytes, server_path, no_challenge, 1_000_000);
                progressed = true;
            }
            if (!progressed) break;
        }
    }
    try testing.expectEqual(@as(usize, 1), capture.count);
    try testing.expectEqual(tls_core.session_cache.StoreResult.stored, capture.stored);

    // The scenario's specific mutation, applied only now — so the ticket
    // just issued above remembered the *pre*-mutation state.
    scenario.mutate(&runtime);

    // Phase 2: a fresh resumed connection attempting 0-RTT, wired with the
    // *real* `Runtime.h3EarlyDataCompatibility` gate and the *real*
    // `Runtime.quicConnectionEvent` bridge exactly as production's
    // `accept()` composes them — unlike the accepted-case test below, which
    // intentionally bypasses both (its `backend2` never installs either),
    // this proves the actual typed decision that would reach metrics.
    const candidate: tls_core.session.CandidateContext = .{
        .cipher_suite = capture.retained.common.cipher_suite,
        .server_name = if (capture.retained.common.server_name) |*s| s.slice() else null,
        .application_protocol = if (capture.retained.common.application_protocol) |*a| a.slice() else null,
        .auth_binding = capture.retained.common.auth_binding,
        .transport_compat = null,
        .application_compat = null,
    };
    var lookup = client_resumption.lookupClientOffers(candidate);
    defer lookup.deinit();
    try testing.expect(lookup == .hit);

    var client_backend2 = quic.tls_backend.Tls13Backend.initClient(
        .{ .hello_random = [_]u8{0xe1} ** 32, .key_share_seed = [_]u8{0x41} ** 32 },
        .{ .pinned_certificate = tls_core.credentials.testdata.certificate_der },
    );
    var clock_dummy: u8 = 0;
    const ClientClock = struct {
        fn now(_: *anyopaque) i64 {
            return 2000;
        }
    };
    try client_backend2.engine.setClientPskOfferLease(&lookup.hit, &clock_dummy, ClientClock.now);
    try client_backend2.setResumeCompatibilityPolicy(.{ .transport = .ignore, .application = .ignore });
    try client_backend2.setClientEarlyDataIntent(.{ .enabled = true, .max_bytes = 65536 });

    const backend2 = try allocator.create(quic.tls_backend.Tls13Backend);
    backend2.* = quic.tls_backend.Tls13Backend.initServerWithProvider(
        .{ .hello_random = [_]u8{0xe2} ** 32, .key_share_seed = [_]u8{0x42} ** 32 },
        fixed.provider(),
    );
    try backend2.setResumeCompatibilityPolicy(.{ .transport = .ignore, .application = .ignore });
    try backend2.setServerPskResolver(resumption.serverResolver().?);
    // Sourced from `runtime.early_data_replay_gate`, not `scenario.replay_gate`
    // directly — the same process-shared value `accept()` reads.
    try backend2.setEarlyDataReplayGate(runtime.early_data_replay_gate.?);
    try backend2.setServerEarlyDataPolicy(.{ .enabled = true });
    try backend2.setEarlyDataCompatibilityGate(.{ .ctx = &runtime, .decideFn = Runtime.h3EarlyDataCompatibility });

    const client2 = try Connection.init(allocator, .{
        .role = .client,
        .config = .{ .zero_rtt_enabled = true },
        .local_cid = &client_cid,
        .original_destination_cid = &odcid,
        .initial_secret_dcid = &odcid,
        .peer_cid = &odcid,
        .tls = client_backend2.backend(),
        .now_us = 2_000_000,
        .initial_path = client_path,
    });
    defer client2.deinit();
    const server_conn2 = try Connection.init(allocator, .{
        .role = .server,
        .config = runtime.quic_config,
        .local_cid = &odcid,
        .original_destination_cid = &odcid,
        .initial_secret_dcid = &odcid,
        .peer_cid = &client_cid,
        .tls = backend2.backend(),
        .now_us = 2_000_000,
        .initial_path = server_path,
        .events = .{ .context = &runtime, .emitFn = Runtime.quicConnectionEvent },
    });

    var entry2 = ConnEntry{
        .backend = backend2,
        .conn = server_conn2,
        // Mirrors `accept()`'s `self.h3_settings` (line ~585) — for the
        // application-incompatible scenario, `scenario.mutate` just changed
        // this live value, so phase 2's actual H3 session must run under
        // those same (mutated) SETTINGS, not silently fall back to defaults.
        .h3 = H3.initWithSettings(allocator, .server, runtime.h3_settings),
        .admission_source_ip = 0,
        .cid_len = odcid.len,
        .accepted_at_us = 2_000_000,
    };
    defer entry2.deinit(allocator);

    // Drive only the client's first flight — enough for the server to run
    // the resumption/early-data decision — then confirm 0-RTT was genuinely
    // rejected (no `.zero_rtt` read key installed) and that the *specific*
    // typed decision this scenario is testing is exactly what was recorded,
    // through the same production metrics bridge `accept()` uses.
    {
        var buf: [2048]u8 = undefined;
        while (client2.pollTransmitOnPath(&buf, 2_000_000)) |t| {
            try entry2.conn.ingestOnPath(t.bytes, server_path, no_challenge, 2_000_000);
        }
    }
    try testing.expect(entry2.conn.adapter.protectionKeys(.zero_rtt, .read) == null);
    try testing.expectEqual(@as(usize, 1), decision_capture.count);
    try testing.expectEqual(scenario.expect_decision, decision_capture.last.?);

    // Prove rejection actually suppresses early delivery, not just that no
    // read key exists: the client's own TLS engine still derives and would
    // use a real 0-RTT write secret regardless of what the server's gate
    // decides (it can't know the decision in advance) — extract that real
    // secret and seal a genuine QPACK-encoded H3 GET as an early 0-RTT
    // packet, exactly as a real client attempting (and having rejected)
    // early data would send. The server can't have a matching read key (see
    // above), so this must be dropped as `keys_unavailable` before ever
    // reaching the frame/H3 layer — not merely "no packet was sent".
    {
        const client_write_secret = client2.adapter.secret(.zero_rtt, .write).?.slice()[0..quic.tls_adapter.traffic_secret_len].*;
        var early_h3: [128]u8 = undefined;
        const early_bytes = buildH3RequestBytesForTest("GET", "/early-after-rejection", "example.com", &early_h3);
        var early_frame_buf: [160]u8 = undefined;
        const early_frame_len = try quic.frame.encodeStream(40, 0, early_bytes, true, &early_frame_buf);
        var early_wire: [512]u8 = undefined;
        const early_datagram = sealZeroRttPacketForTest(&odcid, &client_cid, client_write_secret, 0, early_frame_buf[0..early_frame_len], &early_wire);
        try entry2.conn.ingestOnPath(early_datagram, server_path, no_challenge, 2_000_000);
        runtime.pumpH3(&entry2, 2_000_000);
    }
    try testing.expectEqual(@as(usize, 1), packet_capture.count);
    try testing.expectEqual(metrics_mod.QuicZeroRttPacketOutcome.keys_unavailable, packet_capture.last.?);
    try testing.expectEqual(@as(usize, 0), handler_state.executed_local);
    try testing.expectEqual(@as(usize, 0), handler_state.rejected_too_early);

    // The rest of the handshake completes normally as ordinary 1-RTT
    // resumption on this *same* connection — rejection is strictly an
    // early-data-window decision, not a rejection of the connection itself.
    {
        var rounds: usize = 0;
        while (rounds < 64) : (rounds += 1) {
            var progressed = false;
            var buf: [2048]u8 = undefined;
            while (client2.pollTransmitOnPath(&buf, 2_000_000)) |t| {
                try entry2.conn.ingestOnPath(t.bytes, server_path, no_challenge, 2_000_000);
                progressed = true;
            }
            while (entry2.conn.pollTransmitOnPath(&buf, 2_000_000)) |t| {
                try client2.ingestOnPath(t.bytes, client_path, no_challenge, 2_000_000);
                progressed = true;
            }
            if (!progressed) break;
        }
    }
    try testing.expect(client2.isEstablished());
    try testing.expect(entry2.conn.isEstablished());

    // A real H3 request over 1-RTT, on this *same* connection that just had
    // its 0-RTT attempt rejected — the same-connection fallback proof the
    // review asked for, through `Runtime.pumpH3` and the shared handler.
    const request_id = try client2.openStream(.bidi);
    var request_h3: [128]u8 = undefined;
    const request_bytes = buildH3RequestBytesForTest("GET", "/after-rejection", "example.com", &request_h3);
    _ = try client2.writeStream(request_id, request_bytes, true);
    {
        var rounds: usize = 0;
        while (rounds < 32) : (rounds += 1) {
            var progressed = false;
            var buf: [2048]u8 = undefined;
            while (client2.pollTransmitOnPath(&buf, 2_000_000)) |t| {
                try entry2.conn.ingestOnPath(t.bytes, server_path, no_challenge, 2_000_000);
                progressed = true;
            }
            while (entry2.conn.pollTransmitOnPath(&buf, 2_000_000)) |t| {
                try client2.ingestOnPath(t.bytes, client_path, no_challenge, 2_000_000);
                progressed = true;
            }
            runtime.pumpH3(&entry2, 2_000_000);
            if (!progressed) break;
        }
    }
    try testing.expectEqual(@as(usize, 1), handler_state.executed_local);
    try testing.expectEqualStrings("GET", handler_state.last_method_buf[0..handler_state.last_method_len]);
    try testing.expectEqual(@as(usize, 0), handler_state.rejected_too_early);
}

test "http3 (#523): replay-rejected 0-RTT falls back to a real H3 request over 1-RTT, same connection" {
    const AlwaysReplay = struct {
        fn decide(_: *anyopaque, _: tls_core.tls13_backend.EarlyDataReplayCandidate) tls_core.tls13_backend.EarlyDataReplayDecision {
            return .replay;
        }
    };
    var replay_ctx: u8 = 0;
    try expectH3EarlyDataRejectionFallsBackToRealRequest(.{
        .replay_gate = .{ .ctx = &replay_ctx, .decideFn = AlwaysReplay.decide },
        .mutate = h3EarlyDataRejectionNoMutation,
        .expect_decision = .replay_rejected,
    });
}

test "http3 (#523): replay-store-unavailable 0-RTT falls back to a real H3 request over 1-RTT, same connection" {
    // Models an operationally-unavailable replay store (e.g. the process
    // shared store failing open a lookup) as a real, installed gate whose
    // `decide` always reports `.unavailable` — not the absence of a gate,
    // which `zeroRttCarrierEnabled` never lets a production composition
    // reach in the first place.
    const AlwaysUnavailable = struct {
        fn decide(_: *anyopaque, _: tls_core.tls13_backend.EarlyDataReplayCandidate) tls_core.tls13_backend.EarlyDataReplayDecision {
            return .unavailable;
        }
    };
    var replay_ctx: u8 = 0;
    try expectH3EarlyDataRejectionFallsBackToRealRequest(.{
        .replay_gate = .{ .ctx = &replay_ctx, .decideFn = AlwaysUnavailable.decide },
        .mutate = h3EarlyDataRejectionNoMutation,
        .expect_decision = .replay_unavailable,
    });
}

test "http3 (#523): transport-incompatible 0-RTT rejected by the real Runtime.h3EarlyDataCompatibility gate falls back to a real H3 request over 1-RTT, same connection" {
    const AlwaysAllow = struct {
        fn decide(_: *anyopaque, _: tls_core.tls13_backend.EarlyDataReplayCandidate) tls_core.tls13_backend.EarlyDataReplayDecision {
            return .allow;
        }
    };
    var replay_ctx: u8 = 0;
    try expectH3EarlyDataRejectionFallsBackToRealRequest(.{
        .replay_gate = .{ .ctx = &replay_ctx, .decideFn = AlwaysAllow.decide },
        .mutate = h3EarlyDataRejectionReduceTransportLimit,
        .expect_decision = .transport_incompatible,
    });
}

test "http3 (#523): application-incompatible (H3 SETTINGS) 0-RTT rejected by the real Runtime.h3EarlyDataCompatibility gate falls back to a real H3 request over 1-RTT, same connection" {
    const AlwaysAllow = struct {
        fn decide(_: *anyopaque, _: tls_core.tls13_backend.EarlyDataReplayCandidate) tls_core.tls13_backend.EarlyDataReplayDecision {
            return .allow;
        }
    };
    var replay_ctx: u8 = 0;
    try expectH3EarlyDataRejectionFallsBackToRealRequest(.{
        .replay_gate = .{ .ctx = &replay_ctx, .decideFn = AlwaysAllow.decide },
        .mutate = h3EarlyDataRejectionNoMutation,
        // A stricter *remembered* QPACK dynamic-table capacity than the
        // live (always-default, `qpack_max_table_capacity == 0`) settings
        // phase 2 actually runs under: `qpackMaxTableCompatible` treats
        // `remembered == 0` as vacuously compatible, so this field can only
        // ever produce `.settings_incompatible` by remembering *more* than
        // the always-zero live default — never by reducing the live side
        // (see `H3EarlyDataRejectionScenario.remembered_app_settings`).
        .remembered_app_settings = .{ .qpack_max_table_capacity = 4096 },
        .expect_decision = .application_incompatible,
    });
}

test "accept() (#523): wires an EventSink into every accepted connection so 0-RTT events reach metrics instead of being silently discarded" {
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity());
    defer fixed.deinit();
    var logger = logger_mod.Logger.init(.err, "http3-event-wiring-test");

    const Capture = struct {
        decisions: usize = 0,
        packets: usize = 0,

        fn onDecision(ctx: *anyopaque, _: metrics_mod.QuicEarlyDataDecision) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.decisions += 1;
        }
        fn onPacket(ctx: *anyopaque, _: metrics_mod.QuicZeroRttPacketOutcome) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.packets += 1;
        }
    };
    var capture = Capture{};

    var runtime = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        .quic_early_data_decision_metrics_ctx = &capture,
        .quic_early_data_decision_metrics_cb = Capture.onDecision,
        .quic_zero_rtt_packet_metrics_ctx = &capture,
        .quic_zero_rtt_packet_metrics_cb = Capture.onPacket,
    });
    defer runtime.deinit();

    var connections = std.AutoHashMap(u64, *ConnEntry).init(testing.allocator);
    defer {
        var it = connections.valueIterator();
        while (it.next()) |entry| {
            entry.*.deinit(testing.allocator);
            testing.allocator.destroy(entry.*);
        }
        connections.deinit();
    }
    var routes = quic.cid.CidRoutingTable.init(testing.allocator);
    defer routes.deinit();
    var per_ip = std.AutoHashMap(u32, u32).init(testing.allocator);
    defer per_ip.deinit();
    var next_handle: u64 = 1;

    const dcid = [_]u8{0x11} ** 8;
    const scid = [_]u8{0x22} ** 8;
    const parsed = quic.packet.ParsedPacket{
        .kind = .initial,
        .version = quic.packet.quic_v1,
        .dcid = &dcid,
        .scid = &scid,
    };
    const peer = std.c.sockaddr.in{ .family = posix.AF.INET, .port = 0, .addr = 0, .zero = [_]u8{0} ** 8 };

    const handle = runtime.accept(&connections, &routes, &per_ip, &next_handle, parsed, peer, 1_000_000);
    try testing.expect(handle != null);
    const entry = connections.get(handle.?).?;

    // Prove `accept()` genuinely attached a non-default `EventSink` (not
    // just left it at its `.{}` no-op default) by emitting directly through
    // it — this is what a real handshake's `Event.early_data_decision` /
    // `Event.zero_rtt_packet` emissions from inside `Connection` would
    // otherwise reach and, before this fix, never did.
    entry.conn.events.emit(.{ .early_data_decision = .disabled });
    entry.conn.events.emit(.{ .zero_rtt_packet = .{ .outcome = .keys_unavailable, .size = 0 } });
    try testing.expectEqual(@as(usize, 1), capture.decisions);
    try testing.expectEqual(@as(usize, 1), capture.packets);
}

fn deinitTestConnections(connections: *std.AutoHashMap(u64, *ConnEntry), allocator: std.mem.Allocator) void {
    var it = connections.valueIterator();
    while (it.next()) |entry| {
        entry.*.deinit(allocator);
        allocator.destroy(entry.*);
    }
    connections.deinit();
}

fn testPeerSockaddr(port: u16) std.c.sockaddr.in {
    return .{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, port),
        .addr = @bitCast([4]u8{ 127, 0, 0, 1 }),
        .zero = [_]u8{0} ** 8,
    };
}

test "http3 runtime Retry sends tokenless Initials without allocating connection state" {
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity());
    defer fixed.deinit();
    var logger = logger_mod.Logger.init(.err, "http3-retry-tokenless-test");
    var runtime = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        .retry_policy = .address_validation,
    });
    defer runtime.deinit();

    var connections = std.AutoHashMap(u64, *ConnEntry).init(testing.allocator);
    defer deinitTestConnections(&connections, testing.allocator);
    var routes = quic.cid.CidRoutingTable.init(testing.allocator);
    defer routes.deinit();
    var per_ip = std.AutoHashMap(u32, u32).init(testing.allocator);
    defer per_ip.deinit();
    var next_handle: u64 = 1;

    const odcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{0x22} ** 8;
    const parsed = quic.packet.ParsedPacket{
        .kind = .initial,
        .version = quic.packet.quic_v1,
        .dcid = &odcid,
        .scid = &client_scid,
        .token = &.{},
    };

    const handle = runtime.accept(&connections, &routes, &per_ip, &next_handle, parsed, testPeerSockaddr(44_330), 1_000_000);
    try testing.expectEqual(@as(?u64, null), handle);
    try testing.expectEqual(@as(usize, 0), connections.count());
    try testing.expectEqual(@as(usize, 0), routes.count());
    try testing.expectEqual(@as(usize, 0), per_ip.count());
    const snapshot = runtime.snapshot();
    try testing.expectEqual(@as(usize, 1), snapshot.retry_packets_sent);
    try testing.expectEqual(@as(usize, 0), snapshot.retry_tokens_accepted);
    try testing.expectEqual(@as(usize, 0), snapshot.invalid_tokens);
    try testing.expectEqual(@as(usize, 0), snapshot.tracked_connections);
}

test "http3 runtime Retry drops invalid tokens without sending a second Retry" {
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity());
    defer fixed.deinit();
    var logger = logger_mod.Logger.init(.err, "http3-retry-invalid-token-test");
    var runtime = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        .retry_policy = .address_validation,
    });
    defer runtime.deinit();

    var connections = std.AutoHashMap(u64, *ConnEntry).init(testing.allocator);
    defer deinitTestConnections(&connections, testing.allocator);
    var routes = quic.cid.CidRoutingTable.init(testing.allocator);
    defer routes.deinit();
    var per_ip = std.AutoHashMap(u32, u32).init(testing.allocator);
    defer per_ip.deinit();
    var next_handle: u64 = 1;

    const retry_scid = [_]u8{0x44} ** 8;
    const client_scid = [_]u8{0x22} ** 8;
    const parsed = quic.packet.ParsedPacket{
        .kind = .initial,
        .version = quic.packet.quic_v1,
        .dcid = &retry_scid,
        .scid = &client_scid,
        .token = "tampered",
    };

    const handle = runtime.accept(&connections, &routes, &per_ip, &next_handle, parsed, testPeerSockaddr(44_331), 1_000_000);
    try testing.expectEqual(@as(?u64, null), handle);
    try testing.expectEqual(@as(usize, 0), connections.count());
    const snapshot = runtime.snapshot();
    try testing.expectEqual(@as(usize, 0), snapshot.retry_packets_sent);
    try testing.expectEqual(@as(usize, 0), snapshot.retry_tokens_accepted);
    try testing.expectEqual(@as(usize, 1), snapshot.invalid_tokens);
}

test "http3 runtime Retry accepts validated tokens with split CID roles and validated path" {
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity());
    defer fixed.deinit();
    var logger = logger_mod.Logger.init(.err, "http3-retry-valid-token-test");
    var runtime = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        .retry_policy = .address_validation,
    });
    defer runtime.deinit();

    var connections = std.AutoHashMap(u64, *ConnEntry).init(testing.allocator);
    defer deinitTestConnections(&connections, testing.allocator);
    var routes = quic.cid.CidRoutingTable.init(testing.allocator);
    defer routes.deinit();
    var per_ip = std.AutoHashMap(u32, u32).init(testing.allocator);
    defer per_ip.deinit();
    var next_handle: u64 = 1;

    const now: u64 = 1_000_000;
    const odcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const retry_scid = [_]u8{ 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48 };
    const client_scid = [_]u8{0x22} ** 8;
    const peer = testPeerSockaddr(44_332);
    var token_buf: [quic.path.max_token_len]u8 = undefined;
    const token = try runtime.retry_tokens.issueRetry(
        &odcid,
        &retry_scid,
        quic.packet.quic_v1,
        addressFromSockaddrIn(peer),
        now,
        [_]u8{0x59} ** quic.path.token_nonce_len,
        &token_buf,
    );
    const parsed = quic.packet.ParsedPacket{
        .kind = .initial,
        .version = quic.packet.quic_v1,
        .dcid = &retry_scid,
        .scid = &client_scid,
        .token = token,
    };

    const handle = runtime.accept(&connections, &routes, &per_ip, &next_handle, parsed, peer, now + 500);
    try testing.expect(handle != null);
    const entry = connections.get(handle.?).?;
    try testing.expectEqual(@as(usize, 1), connections.count());
    try testing.expectEqual(@as(usize, 1), routes.count());
    try testing.expect(routes.contains(try quic.cid.ConnectionId.init(&retry_scid)));
    try testing.expectEqualStrings(&retry_scid, entry.conn.localCid());
    try testing.expectEqualStrings(&odcid, entry.conn.original_dcid.slice());
    try testing.expect(entry.conn.retry_scid != null);
    try testing.expectEqualStrings(&retry_scid, entry.conn.retry_scid.?.slice());
    try testing.expect(entry.conn.paths.activePath().anti_amplification.validated);
    const snapshot = runtime.snapshot();
    try testing.expectEqual(@as(usize, 0), snapshot.retry_packets_sent);
    try testing.expectEqual(@as(usize, 1), snapshot.retry_tokens_accepted);
    try testing.expectEqual(@as(usize, 0), snapshot.invalid_tokens);
    try testing.expectEqual(@as(usize, 1), snapshot.tracked_connections);
}

test "http3 runtime Retry rejects valid tokens replayed with the wrong Retry SCID" {
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity());
    defer fixed.deinit();
    var logger = logger_mod.Logger.init(.err, "http3-retry-wrong-scid-test");
    var runtime = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        .retry_policy = .address_validation,
    });
    defer runtime.deinit();

    var connections = std.AutoHashMap(u64, *ConnEntry).init(testing.allocator);
    defer deinitTestConnections(&connections, testing.allocator);
    var routes = quic.cid.CidRoutingTable.init(testing.allocator);
    defer routes.deinit();
    var per_ip = std.AutoHashMap(u32, u32).init(testing.allocator);
    defer per_ip.deinit();
    var next_handle: u64 = 1;

    const now: u64 = 1_000_000;
    const odcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const retry_scid = [_]u8{ 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48 };
    const wrong_retry_scid = [_]u8{ 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68 };
    const client_scid = [_]u8{0x22} ** 8;
    const peer = testPeerSockaddr(44_333);
    var token_buf: [quic.path.max_token_len]u8 = undefined;
    const token = try runtime.retry_tokens.issueRetry(
        &odcid,
        &retry_scid,
        quic.packet.quic_v1,
        addressFromSockaddrIn(peer),
        now,
        [_]u8{0x5a} ** quic.path.token_nonce_len,
        &token_buf,
    );
    const parsed = quic.packet.ParsedPacket{
        .kind = .initial,
        .version = quic.packet.quic_v1,
        .dcid = &wrong_retry_scid,
        .scid = &client_scid,
        .token = token,
    };

    const handle = runtime.accept(&connections, &routes, &per_ip, &next_handle, parsed, peer, now + 500);
    try testing.expectEqual(@as(?u64, null), handle);
    try testing.expectEqual(@as(usize, 0), connections.count());
    try testing.expectEqual(@as(usize, 0), routes.count());
    try testing.expectEqual(@as(usize, 0), per_ip.count());
    const snapshot = runtime.snapshot();
    try testing.expectEqual(@as(usize, 0), snapshot.retry_packets_sent);
    try testing.expectEqual(@as(usize, 0), snapshot.retry_tokens_accepted);
    try testing.expectEqual(@as(usize, 1), snapshot.invalid_tokens);
}

test "http3 runtime Retry counts valid tokens replayed with the wrong QUIC version as invalid" {
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity());
    defer fixed.deinit();
    var logger = logger_mod.Logger.init(.err, "http3-retry-wrong-version-test");
    var runtime = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        .retry_policy = .address_validation,
    });
    defer runtime.deinit();

    var connections = std.AutoHashMap(u64, *ConnEntry).init(testing.allocator);
    defer deinitTestConnections(&connections, testing.allocator);
    var routes = quic.cid.CidRoutingTable.init(testing.allocator);
    defer routes.deinit();
    var per_ip = std.AutoHashMap(u32, u32).init(testing.allocator);
    defer per_ip.deinit();
    var next_handle: u64 = 1;

    const now: u64 = 1_000_000;
    const odcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const retry_scid = [_]u8{ 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48 };
    const client_scid = [_]u8{0x22} ** 8;
    const peer = testPeerSockaddr(44_334);
    var token_buf: [quic.path.max_token_len]u8 = undefined;
    const token = try runtime.retry_tokens.issueRetry(
        &odcid,
        &retry_scid,
        quic.packet.quic_v1,
        addressFromSockaddrIn(peer),
        now,
        [_]u8{0x5b} ** quic.path.token_nonce_len,
        &token_buf,
    );
    const parsed = quic.packet.ParsedPacket{
        .kind = .initial,
        .version = 0xff00_001d,
        .dcid = &retry_scid,
        .scid = &client_scid,
        .token = token,
    };

    const handle = runtime.accept(&connections, &routes, &per_ip, &next_handle, parsed, peer, now + 500);
    try testing.expectEqual(@as(?u64, null), handle);
    try testing.expectEqual(@as(usize, 0), connections.count());
    try testing.expectEqual(@as(usize, 0), routes.count());
    try testing.expectEqual(@as(usize, 0), per_ip.count());
    const snapshot = runtime.snapshot();
    try testing.expectEqual(@as(usize, 0), snapshot.retry_packets_sent);
    try testing.expectEqual(@as(usize, 0), snapshot.retry_tokens_accepted);
    try testing.expectEqual(@as(usize, 1), snapshot.invalid_tokens);
}

test "runtime resolves the actual bound local address, including an OS-assigned port, from quic_port = 0" {
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity());
    defer fixed.deinit();
    var logger = logger_mod.Logger.init(.err, "http3-port0-test");

    // `quic_port = 0` asks the OS for an ephemeral port; every connection's
    // and PathKey's local half must reflect the address `getsockname`
    // actually resolved, not the requested `0` (#515 required test: UDP
    // port-0 local-address resolution round-trips through runtime PathKey
    // construction).
    var runtime = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
    });
    defer runtime.deinit();

    try testing.expectEqual(quic.udp.AddressFamily.ip4, runtime.local_address.family);
    try testing.expectEqualSlices(u8, &[_]u8{ 127, 0, 0, 1 }, runtime.local_address.slice());
    try testing.expect(runtime.local_address.port != 0);
    // The configured (requested) port is unaffected; only the resolved
    // local address reflects what the OS actually bound.
    try testing.expectEqual(@as(u16, 0), runtime.quic_port);
}

test "sockaddr_in <-> quic.udp.Address conversion round-trips family, octets, and port" {
    const original = std.c.sockaddr.in{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, 44_321),
        .addr = @bitCast([4]u8{ 198, 51, 100, 7 }),
    };
    const address = addressFromSockaddrIn(original);
    try testing.expectEqual(quic.udp.AddressFamily.ip4, address.family);
    try testing.expectEqualSlices(u8, &[_]u8{ 198, 51, 100, 7 }, address.slice());
    try testing.expectEqual(@as(u16, 44_321), address.port);

    // Every `Transmit.path.remote` a connection returns is sent through this
    // exact conversion (`sendDatagram(sockaddrInFromAddress(t.path.remote),
    // t.bytes)`, never a cached or fixed peer): round-tripping it back must
    // reproduce the original wire address exactly.
    const round_tripped = sockaddrInFromAddress(address);
    try testing.expectEqual(original.family, round_tripped.family);
    try testing.expectEqual(original.port, round_tripped.port);
    try testing.expectEqual(original.addr, round_tripped.addr);
}

test {
    std.testing.refAllDecls(@This());
}

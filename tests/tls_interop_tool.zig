//! Record-transport interoperability and conformance driver (#338).
//!
//! Runs the shared TLS 1.3 engine -- the same `Tls13Backend` the production
//! native listener uses, behind the same `PureZigRecordStream` -- as either a
//! client or a server over a real TCP socket, against an out-of-process
//! external implementation (`openssl s_server`/`s_client`,
//! `gnutls-serv`/`gnutls-cli`, ...). Nothing foreign links into Tardigrade;
//! peers are separate processes started by the runner script.
//!
//! The negotiation tuple comes from `tls_interop_matrix`, the same vocabulary
//! `h3_interop_tool` uses for the QUIC transport, so one matrix row exercises
//! one engine configuration regardless of which transport carries it.
//!
//! Usage:
//!   tls_interop_tool server --port N --cert C --key K [options]
//!   tls_interop_tool client --host H --port N [--pin C | --insecure] [options]
//!
//! Every run prints exactly one machine-readable result line to stdout:
//!   tls-interop: outcome=<ok|fail> role=<client|server> suite=... group=...
//!                alpn=... sni=... certificate=... error=... alert=...
//! and exits 0 when the observed outcome matches `--expect` (and, when
//! given, `--expect-alert`/`--expect-error`), 1 otherwise.
//!
//! See scripts/interop/run-tls-interop.sh and docs/TLS_INTEROP_MATRIX.md.

const std = @import("std");
const tls = @import("tls_core");
const matrix = @import("tls_interop_matrix");

const algorithms = tls.algorithms;
const alerts = tls.alerts;
const es = tls.encrypted_stream;
const events = tls.events;
const identity_loader = tls.identity_loader;
const production_crypto = tls.production_crypto;
const sni_provider = tls.sni_provider;
const tls_backend = tls.tls13_backend;
const posix = std.posix;

/// The CertificateVerify scheme each private-key type signs with. The engine
/// derives the same pairing internally; stating it here lets a bundle declare
/// its `supported_schemes` without the harness guessing.
fn schemeForKeyKind(kind: sni_provider.KeyKind) tls.credentials.SignatureScheme {
    return switch (kind) {
        .ed25519 => .ed25519,
        .ecdsa_p256 => .ecdsa_secp256r1_sha256,
        .rsa => .rsa_pss_rsae_sha256,
    };
}

var verbose = false;

fn io() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

/// Plain sequential write(2) to fd 1 -- positional writes scribble over
/// interleaved stderr when a runner redirects both to the same log file.
fn writeStdout(bytes: []const u8) void {
    var written: usize = 0;
    while (written < bytes.len) {
        const n = std.c.write(1, bytes.ptr + written, bytes.len - written);
        if (n <= 0) return;
        written += @intCast(n);
    }
}

fn trace(comptime fmt: []const u8, args: anytype) void {
    if (!verbose) return;
    std.debug.print("tls-interop: " ++ fmt ++ "\n", args);
}

// -- Arguments --------------------------------------------------------------

const Expect = enum { ok, fail };
const PeerCloseExpectation = enum { none, clean, truncated };

const Args = struct {
    mode: enum { client, server },
    host: []const u8 = "127.0.0.1",
    port: u16 = 4433,
    cert: []const u8 = "",
    key: []const u8 = "",
    pin: []const u8 = "",
    insecure: bool = false,
    server_name: []const u8 = "",
    /// Client: require the server to select exactly this protocol. Distinct
    /// from the offered `--alpn` list -- a client can legitimately offer
    /// several and accept any, and only a row that pins one wants the
    /// stream-level requirement installed.
    expect_alpn: []const u8 = "",
    send: []const u8 = "",
    expect_contains: []const u8 = "",
    expect_min_bytes: usize = 0,
    expect_peer_close: PeerCloseExpectation = .none,
    expect: Expect = .ok,
    expect_alert: []const u8 = "",
    expect_error: []const u8 = "",
    expect_hrr: bool = false,
    empty_initial_key_share: bool = false,
    connections: usize = 1,
    timeout_ms: u64 = 15_000,
    transcript: []const u8 = "",
    config: matrix.Config = .{},
    /// Server: additional identities offered through the production
    /// SNI/signature-algorithm credential provider (#338). With one or more
    /// of these, `--cert`/`--key` are not used and the *engine* picks which
    /// credential to present -- which is the behaviour a certificate-selection
    /// row is actually testing. Without them the server holds a single fixed
    /// identity, as before.
    identities: [max_identities]Identity = undefined,
    identity_count: usize = 0,
    /// Server: require the engine to have selected a credential signing with
    /// exactly this scheme. Empty leaves selection unchecked.
    expect_signature: []const u8 = "",
    /// #357: send exactly one post-handshake `KeyUpdate` once the connection
    /// is open, before this side's application payload. `update_requested`
    /// additionally obliges the peer to roll its own sending keys, which is
    /// how a row exercises the *receiving* path against a real peer.
    key_update: ?tls.key_update.Request = null,
    /// #357: require this side to have advanced its receiving keys at least
    /// this many times by the end of the exchange -- i.e. to have processed
    /// that many `KeyUpdate` messages from the peer.
    expect_key_updates: u64 = 0,

    const Identity = struct {
        pattern: []const u8,
        cert_path: []const u8,
        key_path: []const u8,
    };
};

/// Bounded by what a conformance row plausibly needs: one identity per
/// signature scheme the engine supports, plus room for extra host patterns.
const max_identities = 8;

const usage =
    \\usage: tls_interop_tool server --port N --cert CERT --key KEY [options]
    \\       tls_interop_tool client --host HOST --port N [--pin CERT | --insecure] [options]
    \\       tls_interop_tool list-capabilities
    \\
    \\`list-capabilities` prints `kind<TAB>name` lines for every cipher suite,
    \\group, and signature scheme the engine natively negotiates. The runner
    \\script builds its whole matrix from that output rather than keeping its
    \\own copy of the lists, so a new engine capability becomes a new matrix
    \\row (or an immediate preflight failure if no peer spelling exists yet).
    \\
    \\negotiation (shared vocabulary with h3_interop_tool):
    \\
++ matrix.flag_usage ++
    \\  --require-sni         server: reject a ClientHello without SNI
    \\  --allow-absent-alpn   accept a peer that offers no ALPN extension
    \\
    \\connection:
    \\  --host HOST --port N --server-name NAME
    \\  --cert PATH --key PATH        server identity (PEM or DER)
    \\  --pin PATH | --insecure       client trust
    \\  --connections N --timeout-ms N
    \\  --empty-initial-key-share     client: force a HelloRetryRequest
    \\
    \\expectations (these drive the exit code):
    \\  --expect ok|fail --expect-alert NAME --expect-error NAME
    \\  --expect-alpn NAME --expect-hrr
    \\  --send STR --expect-contains STR --expect-min-bytes N
    \\  --expect-peer-close clean|truncated
    \\  --key-update not-requested|requested   send one post-handshake KeyUpdate
    \\  --expect-key-updates N                 require N received KeyUpdates
    \\  --transcript PATH             secret-free transcript + failure fixture
    \\  --verbose
    \\
;

/// `null` means the `list-capabilities` sub-command was requested: it takes no
/// flags and never opens a socket, so it is signalled here rather than as a
/// third `Args.mode` that every role switch below would have to carry an
/// unreachable arm for.
fn parseArgs(allocator: std.mem.Allocator, init_args: std.process.Args) !?Args {
    var it = init_args.iterate();
    _ = it.next(); // argv[0]
    const mode_str = it.next() orelse return error.MissingMode;
    if (std.mem.eql(u8, mode_str, "list-capabilities")) return null;
    var args = Args{
        .mode = if (std.mem.eql(u8, mode_str, "server"))
            .server
        else if (std.mem.eql(u8, mode_str, "client"))
            .client
        else
            return error.UnknownMode,
    };

    while (it.next()) |arg| {
        if (std.mem.eql(u8, arg, "--verbose")) {
            verbose = true;
        } else if (std.mem.eql(u8, arg, "--insecure")) {
            args.insecure = true;
        } else if (std.mem.eql(u8, arg, "--require-sni")) {
            args.config.require_sni = true;
        } else if (std.mem.eql(u8, arg, "--allow-absent-alpn")) {
            args.config.allow_absent_alpn = true;
        } else if (std.mem.eql(u8, arg, "--empty-initial-key-share")) {
            args.empty_initial_key_share = true;
        } else if (std.mem.eql(u8, arg, "--expect-hrr")) {
            args.expect_hrr = true;
        } else if (std.mem.eql(u8, arg, "--cipher-suite")) {
            try args.config.addCipherSuite(try allocator.dupe(u8, it.next() orelse return error.MissingValue));
        } else if (std.mem.eql(u8, arg, "--group")) {
            try args.config.addNamedGroup(try allocator.dupe(u8, it.next() orelse return error.MissingValue));
        } else if (std.mem.eql(u8, arg, "--signature")) {
            try args.config.addSignatureScheme(try allocator.dupe(u8, it.next() orelse return error.MissingValue));
        } else if (std.mem.eql(u8, arg, "--alpn")) {
            try args.config.addAlpn(try allocator.dupe(u8, it.next() orelse return error.MissingValue));
        } else if (std.mem.eql(u8, arg, "--host")) {
            args.host = try allocator.dupe(u8, it.next() orelse return error.MissingValue);
        } else if (std.mem.eql(u8, arg, "--port")) {
            args.port = try std.fmt.parseInt(u16, it.next() orelse return error.MissingValue, 10);
        } else if (std.mem.eql(u8, arg, "--cert")) {
            args.cert = try allocator.dupe(u8, it.next() orelse return error.MissingValue);
        } else if (std.mem.eql(u8, arg, "--key")) {
            args.key = try allocator.dupe(u8, it.next() orelse return error.MissingValue);
        } else if (std.mem.eql(u8, arg, "--pin")) {
            args.pin = try allocator.dupe(u8, it.next() orelse return error.MissingValue);
        } else if (std.mem.eql(u8, arg, "--server-name")) {
            args.server_name = try allocator.dupe(u8, it.next() orelse return error.MissingValue);
        } else if (std.mem.eql(u8, arg, "--expect-alpn")) {
            args.expect_alpn = try allocator.dupe(u8, it.next() orelse return error.MissingValue);
        } else if (std.mem.eql(u8, arg, "--send")) {
            args.send = try allocator.dupe(u8, it.next() orelse return error.MissingValue);
        } else if (std.mem.eql(u8, arg, "--expect-contains")) {
            args.expect_contains = try allocator.dupe(u8, it.next() orelse return error.MissingValue);
        } else if (std.mem.eql(u8, arg, "--expect-min-bytes")) {
            args.expect_min_bytes = try std.fmt.parseInt(usize, it.next() orelse return error.MissingValue, 10);
        } else if (std.mem.eql(u8, arg, "--expect-peer-close")) {
            const raw = it.next() orelse return error.MissingValue;
            args.expect_peer_close = if (std.mem.eql(u8, raw, "clean"))
                .clean
            else if (std.mem.eql(u8, raw, "truncated"))
                .truncated
            else
                return error.UnknownPeerCloseExpectation;
        } else if (std.mem.eql(u8, arg, "--expect")) {
            const raw = it.next() orelse return error.MissingValue;
            args.expect = if (std.mem.eql(u8, raw, "ok"))
                .ok
            else if (std.mem.eql(u8, raw, "fail"))
                .fail
            else
                return error.UnknownExpectation;
        } else if (std.mem.eql(u8, arg, "--expect-alert")) {
            args.expect_alert = try allocator.dupe(u8, it.next() orelse return error.MissingValue);
        } else if (std.mem.eql(u8, arg, "--expect-error")) {
            args.expect_error = try allocator.dupe(u8, it.next() orelse return error.MissingValue);
        } else if (std.mem.eql(u8, arg, "--connections")) {
            args.connections = try std.fmt.parseInt(usize, it.next() orelse return error.MissingValue, 10);
        } else if (std.mem.eql(u8, arg, "--timeout-ms")) {
            args.timeout_ms = try std.fmt.parseInt(u64, it.next() orelse return error.MissingValue, 10);
        } else if (std.mem.eql(u8, arg, "--transcript")) {
            args.transcript = try allocator.dupe(u8, it.next() orelse return error.MissingValue);
        } else if (std.mem.eql(u8, arg, "--identity")) {
            if (args.identity_count == max_identities) return error.TooManyIdentities;
            const spec = try allocator.dupe(u8, it.next() orelse return error.MissingValue);
            // PATTERN:CERT:KEY -- split from the left so a pattern can never
            // swallow a path containing a colon.
            var parts = std.mem.splitScalar(u8, spec, ':');
            args.identities[args.identity_count] = .{
                .pattern = parts.next() orelse return error.MalformedIdentity,
                .cert_path = parts.next() orelse return error.MalformedIdentity,
                .key_path = parts.rest(),
            };
            if (args.identities[args.identity_count].key_path.len == 0) return error.MalformedIdentity;
            args.identity_count += 1;
        } else if (std.mem.eql(u8, arg, "--expect-signature")) {
            args.expect_signature = try allocator.dupe(u8, it.next() orelse return error.MissingValue);
        } else if (std.mem.eql(u8, arg, "--key-update")) {
            const raw = it.next() orelse return error.MissingValue;
            args.key_update = if (std.mem.eql(u8, raw, "not-requested"))
                .update_not_requested
            else if (std.mem.eql(u8, raw, "requested"))
                .update_requested
            else
                return error.UnknownKeyUpdateRequest;
        } else if (std.mem.eql(u8, arg, "--expect-key-updates")) {
            args.expect_key_updates = try std.fmt.parseInt(u64, it.next() orelse return error.MissingValue, 10);
        } else {
            std.debug.print("tls-interop: unknown argument {s}\n", .{arg});
            return error.UnknownArgument;
        }
    }

    if (args.send.len == 0) {
        args.send = switch (args.mode) {
            .client => "GET / HTTP/1.0\r\nHost: tardigrade.test\r\nConnection: close\r\n\r\n",
            .server => "HTTP/1.0 200 ok\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\ntardigrade-tls-interop\n",
        };
    }
    return args;
}

// -- Sockets ----------------------------------------------------------------

fn setNonBlocking(fd: posix.fd_t) !void {
    const status_flags = std.c.fcntl(fd, std.c.F.GETFL, @as(c_int, 0));
    if (status_flags < 0) return error.FcntlFailed;
    const nonblock = @as(c_int, @bitCast(posix.O{ .NONBLOCK = true }));
    if (std.c.fcntl(fd, std.c.F.SETFL, status_flags | nonblock) < 0) return error.FcntlFailed;
}

fn parseIp4(host: []const u8, port: u16) !std.c.sockaddr.in {
    var octets: [4]u8 = undefined;
    var it = std.mem.splitScalar(u8, host, '.');
    for (&octets) |*octet| {
        octet.* = try std.fmt.parseInt(u8, it.next() orelse return error.InvalidAddress, 10);
    }
    if (it.next() != null) return error.InvalidAddress;
    return .{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, port),
        .addr = @bitCast(octets),
    };
}

fn listenTcp(port: u16) !posix.fd_t {
    const fd = std.c.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
    if (fd < 0) return error.SocketFailed;
    errdefer _ = std.c.close(fd);
    var one: c_int = 1;
    _ = std.c.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, &one, @sizeOf(c_int));
    var addr = std.c.sockaddr.in{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, port),
        .addr = 0, // INADDR_ANY
    };
    if (std.c.bind(fd, @ptrCast(&addr), @sizeOf(std.c.sockaddr.in)) != 0) return error.BindFailed;
    if (std.c.listen(fd, 8) != 0) return error.ListenFailed;
    return fd;
}

fn acceptTcp(listener: posix.fd_t, deadline_ms: i64) !posix.fd_t {
    while (nowMs() < deadline_ms) {
        var fds = [_]posix.pollfd{.{ .fd = listener, .events = posix.POLL.IN, .revents = 0 }};
        _ = posix.poll(&fds, 100) catch 0;
        if (fds[0].revents & posix.POLL.IN == 0) continue;
        const fd = std.c.accept(listener, null, null);
        if (fd < 0) continue;
        try setNonBlocking(fd);
        return fd;
    }
    return error.AcceptTimeout;
}

fn connectTcp(host: []const u8, port: u16, deadline_ms: i64) !posix.fd_t {
    const addr = try parseIp4(host, port);
    // The external peer is spawned concurrently by the runner, so a refused
    // connect is an ordinary startup race rather than a failure: retry until
    // the deadline before giving up.
    while (nowMs() < deadline_ms) {
        const fd = std.c.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
        if (fd < 0) return error.SocketFailed;
        if (std.c.connect(fd, @ptrCast(&addr), @sizeOf(std.c.sockaddr.in)) == 0) {
            try setNonBlocking(fd);
            return fd;
        }
        _ = std.c.close(fd);
        sleepMs(50);
    }
    return error.ConnectTimeout;
}

fn nowMs() i64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(i64, @intCast(ts.sec)) * 1000 + @divTrunc(@as(i64, @intCast(ts.nsec)), 1_000_000);
}

fn sleepMs(ms: u64) void {
    var fds = [_]posix.pollfd{};
    _ = posix.poll(&fds, @intCast(ms)) catch {};
}

// -- Carrier with secret-free transcript capture ----------------------------

/// Maximum record-layer frames one run records. Bounded so a multi-connection
/// or long-lived row cannot grow the transcript without limit; every frame a
/// conformance row cares about is at the front of the handshake.
const max_transcript_frames = 64;
/// Maximum plaintext handshake bytes retained as a reduced failure fixture.
/// Bounds a pathological peer's ClientHello and comfortably fits a real one.
const max_fixture_bytes = 4096;

const Direction = enum { tx, rx };

const Frame = struct {
    direction: Direction,
    content_type: u8,
    len: u16,
};

/// Record-layer observations taken at the carrier, where only the 5-byte TLS
/// record header is readable without keys.
///
/// **Redaction contract.** Payload bytes are retained for exactly two content
/// types, both unencrypted by construction in TLS 1.3 and carrying no secret
/// material:
///
///   * `handshake` (22) -- ClientHello, ServerHello, and HelloRetryRequest.
///     Their contents (offered suites/groups/signature schemes, extensions,
///     public key shares, public randoms) are exactly what reproducing a
///     negotiation bug needs, and are visible to any on-path observer anyway.
///     Once the epoch turns encrypted the peer's handshake messages arrive
///     as content type 23 and fall into the length-only branch below.
///   * `alert` (21) -- two bytes of level and description, which is the
///     failure class a negative row asserts on. An encrypted alert likewise
///     arrives as content type 23 and is only counted, never captured.
///
/// Everything else is recorded as direction, type, and length only. Traffic
/// secrets, resumption secrets, ticket bytes, and private keys never reach
/// this struct: it sits below the record-protection boundary and sees exactly
/// what the socket sees.
const Transcript = struct {
    frames: [max_transcript_frames]Frame = undefined,
    frame_count: usize = 0,
    dropped_frames: usize = 0,
    fixture: [max_fixture_bytes]u8 = undefined,
    fixture_len: usize = 0,
    fixture_truncated: bool = false,
    /// Partial record header/body accounting, per direction, so a record
    /// split across several carrier calls is still framed correctly.
    pending: [2]Pending = .{ .{}, .{} },

    const Pending = struct {
        header: [5]u8 = undefined,
        header_len: usize = 0,
        remaining: usize = 0,
        capture: bool = false,
    };

    fn observe(self: *Transcript, direction: Direction, bytes: []const u8) void {
        const state = &self.pending[@intFromEnum(direction)];
        var offset: usize = 0;
        while (offset < bytes.len) {
            if (state.header_len < 5) {
                const want = @min(5 - state.header_len, bytes.len - offset);
                @memcpy(state.header[state.header_len..][0..want], bytes[offset..][0..want]);
                state.header_len += want;
                offset += want;
                if (state.header_len < 5) return;
                const content_type = state.header[0];
                const length = std.mem.readInt(u16, state.header[3..5], .big);
                state.remaining = length;
                // See the redaction contract above: only plaintext-epoch
                // handshake and alert payloads are ever retained.
                state.capture = (content_type == 22 or content_type == 21);
                self.pushFrame(.{ .direction = direction, .content_type = content_type, .len = length });
                if (state.capture) self.appendFixtureBytes(&state.header);
                continue;
            }
            const take = @min(state.remaining, bytes.len - offset);
            if (state.capture) self.appendFixtureBytes(bytes[offset..][0..take]);
            state.remaining -= take;
            offset += take;
            if (state.remaining == 0) {
                state.header_len = 0;
                state.capture = false;
            }
        }
    }

    fn pushFrame(self: *Transcript, frame: Frame) void {
        if (self.frame_count == max_transcript_frames) {
            self.dropped_frames += 1;
            return;
        }
        self.frames[self.frame_count] = frame;
        self.frame_count += 1;
    }

    fn appendFixtureBytes(self: *Transcript, bytes: []const u8) void {
        const room = max_fixture_bytes - self.fixture_len;
        if (room == 0) {
            self.fixture_truncated = true;
            return;
        }
        const take = @min(room, bytes.len);
        @memcpy(self.fixture[self.fixture_len..][0..take], bytes[0..take]);
        self.fixture_len += take;
        if (take < bytes.len) self.fixture_truncated = true;
    }
};

const FdCarrier = struct {
    fd: posix.fd_t,
    transcript: *Transcript,

    fn carrier(self: *FdCarrier) es.Carrier {
        // `owns_handle` lets the stream half-close (shutdown(WR)) right after
        // it flushes close_notify or a fatal alert. External peers such as
        // `openssl s_server` wait for that FIN before exiting, and the fd
        // itself is still closed by `runOne`.
        return .{ .ptr = self, .readFn = read, .writeFn = write, .closeFn = close, .owns_handle = true };
    }

    fn read(ptr: *anyopaque, out: []u8) es.Error!usize {
        const self: *FdCarrier = @ptrCast(@alignCast(ptr));
        const n = std.c.read(self.fd, out.ptr, out.len);
        if (n < 0) {
            if (posix.errno(n) == .AGAIN) return error.WouldBlock;
            return error.SocketReadFailed;
        }
        const count: usize = @intCast(n);
        if (count > 0) self.transcript.observe(.rx, out[0..count]);
        return count;
    }

    fn write(ptr: *anyopaque, bytes: []const u8) es.Error!usize {
        const self: *FdCarrier = @ptrCast(@alignCast(ptr));
        const n = std.c.write(self.fd, bytes.ptr, bytes.len);
        if (n < 0) {
            if (posix.errno(n) == .AGAIN) return error.WouldBlock;
            return error.SocketWriteFailed;
        }
        const count: usize = @intCast(n);
        if (count > 0) self.transcript.observe(.tx, bytes[0..count]);
        return count;
    }

    fn close(ptr: *anyopaque) void {
        const self: *FdCarrier = @ptrCast(@alignCast(ptr));
        _ = std.c.shutdown(self.fd, posix.SHUT.WR);
    }
};

// -- Run outcome ------------------------------------------------------------

const Outcome = struct {
    ok: bool = false,
    handshake_complete: bool = false,
    cipher_suite: ?algorithms.CipherSuite = null,
    named_group: ?algorithms.NamedGroup = null,
    alpn: []const u8 = "",
    server_name: []const u8 = "",
    certificate: events.CertificateState = .not_checked,
    /// Server: the scheme the credential the *engine* selected signs with.
    /// This is the observable that makes certificate selection testable --
    /// without it a row can only confirm that the identity the harness
    /// preselected happened to work.
    signature_scheme: ?algorithms.SignatureScheme = null,
    hello_retry_request: bool = false,
    failure: ?anyerror = null,
    /// The fatal alert this side emitted, mapped from its own failure.
    emitted_alert: ?alerts.AlertDescription = null,
    /// The fatal alert the peer sent us, as observed by the record stream.
    peer_alert: ?alerts.AlertDescription = null,
    received_len: usize = 0,
    /// #357: how many times each direction's application traffic secret
    /// advanced. `read` counts KeyUpdates this side processed from the peer,
    /// `write` counts the ones it sent.
    key_updates_read: u64 = 0,
    key_updates_written: u64 = 0,
    /// True once the row's own `--key-update` message has been queued, so the
    /// send is attempted exactly once however many times the loop spins.
    key_update_sent: bool = false,
    /// A peer `close_notify` observed by the record stream. Abrupt EOF without
    /// `close_notify` is reported separately as `error.TruncatedStream`.
    peer_closed: bool = false,
};

/// The alert that characterises this run's failure, whichever side produced
/// it. A negative row asserts on this one value: for a rejection we make it is
/// what we put on the wire, and for a rejection the peer makes it is what the
/// peer put on the wire. Peer alerts win because when both are present ours is
/// only the local consequence of theirs.
fn conformanceAlert(outcome: Outcome) ?alerts.AlertDescription {
    return outcome.peer_alert orelse outcome.emitted_alert;
}

// -- The handshake run ------------------------------------------------------

const Runner = struct {
    allocator: std.mem.Allocator,
    args: Args,
    identity: ?identity_loader.LoadedIdentity = null,
    pinned: []const u8 = "",
    /// Server, multi-identity mode: the production SNI/signature-algorithm
    /// credential provider, holding every `--identity` for the process's
    /// lifetime. Present exactly when `args.identity_count > 0`.
    sni: ?*SniIdentities = null,

    /// Owns the loaded identities and the reloadable provider behind them.
    /// Heap-allocated so the provider's vtable pointer stays stable while the
    /// engine holds it.
    const SniIdentities = struct {
        allocator: std.mem.Allocator,
        loaded: [max_identities]identity_loader.LoadedIdentity = undefined,
        loaded_count: usize = 0,
        chains: [max_identities][1][]const u8 = undefined,
        patterns: [max_identities][1][]const u8 = undefined,
        schemes: [max_identities][1]tls.credentials.SignatureScheme = undefined,
        entropy_source: production_crypto.OsEntropy = .{},
        provider_state: sni_provider.ReloadableProvider = undefined,

        fn create(allocator: std.mem.Allocator, args: Args) !*SniIdentities {
            const self = try allocator.create(SniIdentities);
            errdefer allocator.destroy(self);
            self.* = .{ .allocator = allocator };
            self.provider_state = sni_provider.ReloadableProvider.init(allocator);
            errdefer self.provider_state.deinit();

            var configs: [max_identities]sni_provider.CredentialBundleConfig = undefined;
            for (args.identities[0..args.identity_count], 0..) |identity, i| {
                self.loaded[i] = try identity_loader.loadIdentity(
                    allocator,
                    identity.cert_path,
                    identity.key_path,
                    self.entropy_source.entropy(),
                );
                self.loaded_count = i + 1;
                self.chains[i] = .{self.loaded[i].cert_chain[0]};
                self.patterns[i] = .{identity.pattern};
                const key_kind: sni_provider.KeyKind = switch (self.loaded[i].identity.key) {
                    .ed25519 => .ed25519,
                    .ecdsa_p256 => .ecdsa_p256,
                    .rsa => .rsa,
                };
                self.schemes[i] = .{schemeForKeyKind(key_kind)};
                configs[i] = .{
                    .chain = self.chains[i][0..],
                    .patterns = self.patterns[i][0..],
                    .signer = sni_provider.SignAdapter.fromIdentity(
                        self.loaded[i].identity,
                        self.entropy_source.entropy(),
                    ),
                    .key_kind = key_kind,
                    .supported_schemes = self.schemes[i][0..],
                    // The first identity is the default: it answers a
                    // ClientHello whose SNI matches no pattern, which is what
                    // makes "unknown SNI falls back" observable rather than a
                    // handshake failure.
                    .is_default = i == 0,
                };
            }

            try self.provider_state.reload(configs[0..args.identity_count], .{
                // A row that omits SNI is exercising the default-credential
                // path, not an error path; `--require-sni` is the policy knob
                // for demanding one.
                .absent_sni_policy = .use_default,
                .unknown_sni_policy = .use_default,
            });
            return self;
        }

        fn destroy(self: *SniIdentities) void {
            const allocator = self.allocator;
            self.provider_state.deinit();
            for (self.loaded[0..self.loaded_count]) |*loaded| loaded.deinit();
            allocator.destroy(self);
        }
    };

    fn init(allocator: std.mem.Allocator, args: Args) !Runner {
        var self = Runner{ .allocator = allocator, .args = args };
        if (args.mode == .server) {
            if (args.identity_count > 0) {
                // Multi-identity: the engine selects, not the harness.
                self.sni = try SniIdentities.create(allocator, args);
            } else {
                if (args.cert.len == 0 or args.key.len == 0) return error.MissingIdentity;
                var entropy_source = production_crypto.OsEntropy{};
                self.identity = try identity_loader.loadIdentity(allocator, args.cert, args.key, entropy_source.entropy());
            }
        } else {
            if (args.pin.len == 0 and !args.insecure) return error.MissingClientTrust;
            if (args.pin.len > 0) {
                const raw = try identity_loader.readSmallFile(allocator, args.pin);
                self.pinned = try identity_loader.derFromPemOrDer(allocator, raw, "CERTIFICATE");
            }
        }
        return self;
    }

    fn deinit(self: *Runner) void {
        if (self.identity) |*loaded| loaded.deinit();
        if (self.sni) |sni| sni.destroy();
    }

    fn runOne(self: *Runner, fd: posix.fd_t, transcript: *Transcript) Outcome {
        defer _ = std.c.close(fd);

        // A real OS-backed provider: this tool completes real handshakes with
        // real peers, so ephemeral key shares and randoms must not be
        // predictable the way a deterministic test provider's would be.
        var entropy_source = production_crypto.OsEntropy{};
        var provider_state = production_crypto.Provider.init(entropy_source.entropy());
        const crypto_provider = provider_state.cryptoProvider();

        const handshake_entropy = production_crypto.freshHandshakeEntropy() catch |err| {
            return .{ .failure = err };
        };

        const default_alpns = [_]algorithms.ProtocolName{ algorithms.alpn.h2, algorithms.alpn.http_1_1 };
        const policy = self.args.config.policy(.record, &default_alpns);

        var backend = switch (self.args.mode) {
            // Multi-identity rows go through the same `CredentialProvider`
            // seam the production SNI listener uses, so the engine performs
            // the selection. A single-identity row keeps the fixed-identity
            // constructor.
            .server => if (self.sni) |sni| tls_backend.Tls13Backend.initServerWithProviderConfigured(
                handshake_entropy,
                crypto_provider,
                sni.provider_state.provider(),
                tls_backend.recordConfig(policy),
            ) else tls_backend.Tls13Backend.initServerConfigured(
                handshake_entropy,
                crypto_provider,
                self.identity.?.identity,
                tls_backend.recordConfig(policy),
            ),
            .client => tls_backend.Tls13Backend.initClientConfigured(
                handshake_entropy,
                crypto_provider,
                if (self.pinned.len > 0)
                    tls_backend.Trust{ .pinned_certificate = self.pinned }
                else
                    tls_backend.Trust.insecure_no_verification,
                tls_backend.recordConfig(policy),
                .{
                    .server_name = if (self.args.server_name.len > 0) self.args.server_name else null,
                    .initial_key_share_mode = if (self.args.empty_initial_key_share) .empty else .normal,
                },
            ),
        };

        var carrier_state = FdCarrier{ .fd = fd, .transcript = transcript };
        var stream = es.PureZigRecordStream.initWithCarrierAndBackend(
            self.allocator,
            switch (self.args.mode) {
                .client => .client,
                .server => .server,
            },
            crypto_provider,
            // The stream's construction-time suite only seeds the record
            // bridge; the negotiated suite replaces it once ServerHello lands.
            // Every matrix row is still checked against the suite its policy
            // actually selected -- see `evaluate`.
            policy.cipher_suites[0],
            carrier_state.carrier(),
            backend.backend(),
        ) catch |err| return .{ .failure = err };
        defer stream.deinit();

        if (self.args.insecure) stream.allow_unverified_certificate = true;
        if (self.args.expect_alpn.len > 0) {
            stream.setExpectedAlpn(self.args.expect_alpn) catch |err| return .{ .failure = err };
        }

        var outcome = Outcome{};
        const deadline = nowMs() + @as(i64, @intCast(self.args.timeout_ms));
        // How much of `--send` the stream has actually accepted. A short write
        // is normal on a nonblocking stream, so "sent" must mean the whole
        // payload is queued -- not that `write` was called once.
        var sent_len: usize = 0;
        var received = std.ArrayList(u8).empty;
        defer received.deinit(self.allocator);

        // True once both halves of the exchange are done: everything this side
        // owes the peer has been queued, and everything the row required from
        // the peer has arrived. Once it holds, a peer that closes the
        // connection is finishing normally, not failing -- so a close observed
        // afterwards must not overwrite the result.
        var delivered = false;
        const expect_peer_close = self.args.expect_peer_close != .none;

        while (nowMs() < deadline) {
            _ = stream.drive() catch |err| {
                if (delivered and !expect_peer_close) break;
                outcome.failure = err;
                outcome.ok = false;
                break;
            };

            if (delivered and self.args.expect_peer_close == .clean and stream.readiness().peer_closed) break;

            if (stream.applicationDataOpen()) {
                outcome.handshake_complete = true;

                // #357: roll our sending keys before the row's payload goes
                // out, so every application byte below crosses under the new
                // generation. `WouldBlock` here only means the outbound queue
                // has no room for the record yet; the next spin retries.
                if (self.args.key_update) |request| {
                    if (!outcome.key_update_sent) {
                        stream.requestKeyUpdate(request) catch |err| switch (err) {
                            error.WouldBlock => {},
                            else => {
                                if (delivered and !expect_peer_close) break;
                                outcome.failure = err;
                                outcome.ok = false;
                                break;
                            },
                        };
                        outcome.key_update_sent = stream.keyUpdateGenerations().write > 0;
                    }
                }

                var buf: [4096]u8 = undefined;
                const n = stream.stream().read(&buf) catch |err| switch (err) {
                    error.WouldBlock => 0,
                    else => {
                        if (delivered and !expect_peer_close) break;
                        outcome.failure = err;
                        outcome.ok = false;
                        break;
                    },
                };
                if (n > 0) received.appendSlice(self.allocator, buf[0..n]) catch {};

                // A client asks first; a server answers what it was asked.
                // Either way, application data crossing in both directions is
                // what proves the negotiated keys agree end to end.
                const may_send = switch (self.args.mode) {
                    .client => true,
                    .server => received.items.len > 0,
                };
                if (may_send and sent_len < self.args.send.len) {
                    const wrote = stream.stream().write(self.args.send[sent_len..]) catch |err| switch (err) {
                        error.WouldBlock => 0,
                        else => {
                            if (delivered and !expect_peer_close) break;
                            outcome.failure = err;
                            outcome.ok = false;
                            break;
                        },
                    };
                    sent_len += wrote;
                }

                const generations = stream.keyUpdateGenerations();
                delivered = sent_len == self.args.send.len and
                    self.matched(received.items) and
                    (self.args.key_update == null or generations.write > 0) and
                    generations.read >= self.args.expect_key_updates;
                if (delivered) {
                    outcome.ok = true;
                    // Keep driving until our reply has actually left the
                    // outbound queue. Breaking with bytes still buffered would
                    // close the connection before the peer ever saw them,
                    // failing the row on the peer's side instead of ours.
                    if (stream.bufferSnapshot().current.outbound_ciphertext == 0 and !expect_peer_close) break;
                }
            }

            if (stream.failed) |err| {
                if (delivered and !expect_peer_close) break;
                outcome.failure = err;
                outcome.ok = false;
                break;
            }
            waitForCarrier(fd, &stream, deadline);
        }

        outcome.received_len = received.items.len;
        const final_generations = stream.keyUpdateGenerations();
        outcome.key_updates_read = final_generations.read;
        outcome.key_updates_written = final_generations.write;
        outcome.hello_retry_request = backend.core.retry_state != .none;
        outcome.certificate = stream.certificateState();
        outcome.peer_alert = stream.peerAlert();
        outcome.peer_closed = stream.readiness().peer_closed;
        if (outcome.handshake_complete) {
            outcome.cipher_suite = backend.negotiated_cipher_suite;
            outcome.named_group = backend.negotiated_named_group;
            outcome.signature_scheme = backend.negotiated_signature_scheme;
            if (stream.negotiatedAlpn()) |alpn| outcome.alpn = self.allocator.dupe(u8, alpn) catch "";
            if (backend.server_name_present) {
                outcome.server_name = self.allocator.dupe(u8, backend.server_name[0..backend.server_name_len]) catch "";
            }
        }
        // A stream-level failure only counts against the row if the exchange
        // had not already completed. Peers routinely tear the connection down
        // the instant they have what they asked for, and that teardown is not
        // a conformance failure.
        if (!delivered) {
            if (outcome.failure == null) outcome.failure = stream.failed;
            if (outcome.failure != null) outcome.ok = false;
        }
        if (outcome.failure) |err| outcome.emitted_alert = emittedAlertFor(err);
        return outcome;
    }

    /// True once everything the row requires has been received. An empty
    /// `--expect-contains` means "any application data at all", which is still
    /// a real proof: bytes only arrive after both Finished messages verified
    /// and the traffic keys agreed.
    fn matched(self: *const Runner, received: []const u8) bool {
        if (received.len < self.args.expect_min_bytes) return false;
        if (self.args.expect_contains.len == 0) return received.len > 0;
        return std.mem.indexOf(u8, received, self.args.expect_contains) != null;
    }
};

fn waitForCarrier(fd: posix.fd_t, stream: *es.PureZigRecordStream, deadline: i64) void {
    const readiness = stream.readiness();
    var wanted: i16 = 0;
    if (readiness.wants_read) wanted |= posix.POLL.IN;
    if (readiness.wants_write) wanted |= posix.POLL.OUT;
    if (wanted == 0) wanted = posix.POLL.IN;
    var fds = [_]posix.pollfd{.{ .fd = fd, .events = wanted, .revents = 0 }};
    const remaining = deadline - nowMs();
    if (remaining <= 0) return;
    _ = posix.poll(&fds, @intCast(@min(remaining, 50))) catch {};
}

/// The alert this side puts on the wire for its own terminal failure. Mirrors
/// `tls_core.alerts.fromHandshakeError` for the handshake errors that reach
/// the tool as an untyped `anyerror` from the stream, so a negative row can
/// assert the standards-defined class without reaching into stream internals.
fn emittedAlertFor(err: anyerror) ?alerts.AlertDescription {
    const handshake_error: events.HandshakeError = switch (err) {
        error.MalformedHandshake => error.MalformedHandshake,
        error.IllegalParameter => error.IllegalParameter,
        error.UnexpectedHandshakeMessage => error.UnexpectedHandshakeMessage,
        error.MissingExtension => error.MissingExtension,
        error.UnsupportedExtension => error.UnsupportedExtension,
        error.CertificateInvalid => error.CertificateInvalid,
        error.UnsupportedCertificate => error.UnsupportedCertificate,
        error.SecretExportFailed => error.SecretExportFailed,
        error.InvalidHandshakeState => error.InvalidHandshakeState,
        error.TicketTooLarge => error.TicketTooLarge,
        error.AlpnMismatch => error.AlpnMismatch,
        error.NoApplicableCredential => error.NoApplicableCredential,
        error.CredentialProviderFailed => error.CredentialProviderFailed,
        error.ClientCertificateRequired => error.ClientCertificateRequired,
        error.DecryptError => error.DecryptError,
        error.NoMutualParameters => error.NoMutualParameters,
        error.UnsupportedProtocolVersion => error.UnsupportedProtocolVersion,
        // Carrier, buffering, and record-layer failures have no TLS alert of
        // their own; the stream tears down without inventing one.
        else => return null,
    };
    return alerts.fromHandshakeError(handshake_error);
}

// -- Reporting --------------------------------------------------------------

const Report = struct {
    buf: []u8,
    len: usize = 0,

    fn print(self: *Report, comptime fmt: []const u8, args: anytype) void {
        const chunk = std.fmt.bufPrint(self.buf[self.len..], fmt, args) catch return;
        self.len += chunk.len;
    }

    fn written(self: *const Report) []const u8 {
        return self.buf[0..self.len];
    }
};

fn reportLine(buf: []u8, args: Args, outcome: Outcome) []const u8 {
    var report = Report{ .buf = buf };
    report.print("tls-interop: outcome={s} role={s}", .{
        if (outcome.ok) "ok" else "fail",
        @tagName(args.mode),
    });
    if (outcome.cipher_suite) |suite| report.print(" suite={s}", .{matrix.cipherSuiteName(suite)});
    if (outcome.named_group) |group| report.print(" group={s}", .{matrix.namedGroupName(group)});
    if (outcome.signature_scheme) |scheme| report.print(" signature={s}", .{matrix.signatureSchemeName(scheme)});
    if (outcome.alpn.len > 0) report.print(" alpn={s}", .{outcome.alpn});
    if (outcome.server_name.len > 0) report.print(" sni={s}", .{outcome.server_name});
    report.print(" certificate={s} hrr={}", .{ @tagName(outcome.certificate), outcome.hello_retry_request });
    if (outcome.failure) |err| report.print(" error={s}", .{@errorName(err)});
    if (conformanceAlert(outcome)) |desc| {
        report.print(" alert={s} alert_origin={s}", .{
            @tagName(desc),
            if (outcome.peer_alert != null) "peer" else "local",
        });
    }
    report.print(" app_bytes={d}", .{outcome.received_len});
    if (outcome.key_updates_written > 0 or outcome.key_updates_read > 0) {
        report.print(" key_updates_sent={d} key_updates_received={d}", .{
            outcome.key_updates_written,
            outcome.key_updates_read,
        });
    }
    if (outcome.peer_closed) report.print(" peer_close=clean", .{});
    report.print("\n", .{});
    return report.written();
}

fn writeTranscript(path: []const u8, args: Args, outcome: Outcome, transcript: *const Transcript) !void {
    var buf: [64 * 1024]u8 = undefined;
    var report = Report{ .buf = &buf };

    report.print("# Tardigrade shared-TLS-engine interop transcript (#338)\n", .{});
    report.print("# Secret-free by construction: only plaintext-epoch handshake and alert\n", .{});
    report.print("# records are captured verbatim. Traffic secrets, resumption secrets,\n", .{});
    report.print("# ticket bytes, and private keys are never observable at this layer.\n", .{});
    report.print("transport: record\n", .{});
    report.print("role: {s}\n", .{@tagName(args.mode)});
    report.print("offered.cipher_suites:", .{});
    for (args.config.cipher_suites.slice(matrix.cipher_suites)) |suite| report.print(" {s}", .{matrix.cipherSuiteName(suite)});
    report.print("\noffered.groups:", .{});
    for (args.config.named_groups.slice(matrix.named_groups)) |group| report.print(" {s}", .{matrix.namedGroupName(group)});
    report.print("\noffered.signature_schemes:", .{});
    for (args.config.signature_schemes.slice(matrix.signature_schemes)) |scheme| report.print(" {s}", .{matrix.signatureSchemeName(scheme)});
    report.print("\noutcome: {s}\n", .{if (outcome.ok) "ok" else "fail"});
    report.print("handshake_complete: {}\n", .{outcome.handshake_complete});
    if (outcome.cipher_suite) |suite| report.print("negotiated.cipher_suite: {s}\n", .{matrix.cipherSuiteName(suite)});
    if (outcome.named_group) |group| report.print("negotiated.group: {s}\n", .{matrix.namedGroupName(group)});
    if (outcome.signature_scheme) |scheme| report.print("selected.signature_scheme: {s}\n", .{matrix.signatureSchemeName(scheme)});
    if (outcome.alpn.len > 0) report.print("negotiated.alpn: {s}\n", .{outcome.alpn});
    if (outcome.server_name.len > 0) report.print("negotiated.sni: {s}\n", .{outcome.server_name});
    report.print("certificate: {s}\n", .{@tagName(outcome.certificate)});
    report.print("hello_retry_request: {}\n", .{outcome.hello_retry_request});
    report.print("application_bytes_received: {d}\n", .{outcome.received_len});
    report.print("peer_close: {s}\n", .{if (outcome.peer_closed) "clean" else "none"});
    report.print("key_updates.sent: {d}\n", .{outcome.key_updates_written});
    report.print("key_updates.received: {d}\n", .{outcome.key_updates_read});
    if (outcome.failure) |err| report.print("failure: {s}\n", .{@errorName(err)});
    if (outcome.emitted_alert) |desc| report.print("alert.local: {s}\n", .{@tagName(desc)});
    if (outcome.peer_alert) |desc| report.print("alert.peer: {s}\n", .{@tagName(desc)});

    report.print("\n# record framing (direction, content type, length)\n", .{});
    for (transcript.frames[0..transcript.frame_count]) |frame| {
        report.print("frame: {s} type={s}({d}) len={d}\n", .{
            @tagName(frame.direction),
            contentTypeName(frame.content_type),
            frame.content_type,
            frame.len,
        });
    }
    if (transcript.dropped_frames > 0) report.print("frames_dropped: {d}\n", .{transcript.dropped_frames});

    report.print("\n# reduced failure fixture: the plaintext-epoch handshake and alert\n", .{});
    report.print("# records exactly as they crossed the socket, hex-encoded. Replaying\n", .{});
    report.print("# these bytes reproduces the negotiation without the peer present.\n", .{});
    report.print("fixture.bytes: {d}{s}\n", .{
        transcript.fixture_len,
        if (transcript.fixture_truncated) " (truncated)" else "",
    });
    report.print("fixture.hex: ", .{});
    for (transcript.fixture[0..transcript.fixture_len]) |byte| report.print("{x:0>2}", .{byte});
    report.print("\n", .{});

    var file = try std.Io.Dir.cwd().createFile(io(), path, .{ .truncate = true, .read = false });
    defer file.close(io());
    try file.writeStreamingAll(io(), report.written());
}

fn contentTypeName(content_type: u8) []const u8 {
    return switch (content_type) {
        20 => "change_cipher_spec",
        21 => "alert",
        22 => "handshake",
        23 => "application_data",
        else => "unknown",
    };
}

/// Compare the run against the row's expectations and return the process exit
/// code: 0 when everything the row asserted held, 1 otherwise. Every mismatch
/// explains itself on stderr -- an interop failure that shows up only as a
/// bare non-zero exit is not reproducible.
fn evaluate(args: Args, outcome: Outcome) u8 {
    var failed = false;

    switch (args.expect) {
        .ok => if (!outcome.ok) {
            std.debug.print("tls-interop: expected success but the exchange did not complete (error={?s})\n", .{
                if (outcome.failure) |err| @errorName(err) else null,
            });
            failed = true;
        },
        .fail => if (outcome.ok) {
            std.debug.print("tls-interop: expected failure but the exchange completed\n", .{});
            failed = true;
        },
    }

    if (args.expect_alert.len > 0) {
        const observed = conformanceAlert(outcome);
        if (observed == null or !std.mem.eql(u8, @tagName(observed.?), args.expect_alert)) {
            std.debug.print("tls-interop: expected alert {s} but observed {?s}\n", .{
                args.expect_alert,
                if (observed) |desc| @tagName(desc) else null,
            });
            failed = true;
        }
    }

    if (args.expect_error.len > 0) {
        const observed = if (outcome.failure) |err| @errorName(err) else null;
        if (observed == null or !std.mem.eql(u8, observed.?, args.expect_error)) {
            std.debug.print("tls-interop: expected error {s} but observed {?s}\n", .{ args.expect_error, observed });
            failed = true;
        }
    }

    if (args.expect_hrr and !outcome.hello_retry_request) {
        std.debug.print("tls-interop: expected a HelloRetryRequest but none was observed\n", .{});
        failed = true;
    }

    // #357. Both halves are asserted, because either alone is satisfiable
    // without the mechanism working: a KeyUpdate we sent but the peer ignored
    // would still leave our own write generation at 1, and a row that only
    // counted received updates could pass on a peer that rolled its keys for
    // reasons of its own.
    if (args.key_update != null and outcome.key_updates_written == 0) {
        std.debug.print("tls-interop: expected to send a KeyUpdate but the sending keys never advanced\n", .{});
        failed = true;
    }
    if (outcome.key_updates_read < args.expect_key_updates) {
        std.debug.print("tls-interop: expected at least {d} KeyUpdate(s) from the peer but observed {d}\n", .{
            args.expect_key_updates,
            outcome.key_updates_read,
        });
        failed = true;
    }

    if (outcome.received_len < args.expect_min_bytes) {
        std.debug.print("tls-interop: expected at least {d} application byte(s) but observed {d}\n", .{
            args.expect_min_bytes,
            outcome.received_len,
        });
        failed = true;
    }

    switch (args.expect_peer_close) {
        .none => {},
        .clean => if (!outcome.peer_closed or outcome.failure != null) {
            std.debug.print("tls-interop: expected clean peer close_notify but observed peer_closed={} error={?s}\n", .{
                outcome.peer_closed,
                if (outcome.failure) |err| @errorName(err) else null,
            });
            failed = true;
        },
        .truncated => if (outcome.failure == null or outcome.failure.? != error.TruncatedStream) {
            std.debug.print("tls-interop: expected truncated peer close but observed error={?s}\n", .{
                if (outcome.failure) |err| @errorName(err) else null,
            });
            failed = true;
        },
    }

    // Which credential the *engine* selected, for rows that offer several.
    // Checked separately from the negotiated tuple because selection is a
    // local decision about our own identity, not something negotiated with
    // the peer.
    if (args.expect_signature.len > 0) {
        const observed = if (outcome.signature_scheme) |scheme| matrix.signatureSchemeName(scheme) else null;
        if (observed == null or !std.mem.eql(u8, observed.?, args.expect_signature)) {
            std.debug.print("tls-interop: expected the engine to select a {s} credential but it selected {?s}\n", .{
                args.expect_signature,
                observed,
            });
            failed = true;
        }
    }

    // The negotiated-tuple expectations come from the shared matrix
    // validator, not a copy local to this transport -- see
    // `Config.validateNegotiated`.
    if (outcome.handshake_complete) {
        var ignored: u8 = 0;
        const held = args.config.validateNegotiated(.{
            .cipher_suite = outcome.cipher_suite,
            .named_group = outcome.named_group,
            .alpn = outcome.alpn,
        }, if (args.expect_alpn.len > 0) args.expect_alpn else null, &ignored, reportMismatch);
        if (!held) failed = true;
    }

    return if (failed) 1 else 0;
}

/// One `kind<TAB>name` line per native capability, on stdout, for the runner
/// script to read.
fn writeCapabilityLine(_: *u8, kind: []const u8, name: []const u8) void {
    var buf: [128]u8 = undefined;
    writeStdout(std.fmt.bufPrint(&buf, "{s}\t{s}\n", .{ kind, name }) catch return);
}

fn reportMismatch(_: *u8, mismatch: matrix.Mismatch) void {
    std.debug.print("tls-interop: expected {s} {s} but negotiated {s}\n", .{
        mismatch.dimension,
        mismatch.expected,
        mismatch.observed,
    });
}

// -- Entry point ------------------------------------------------------------

pub fn main(init: std.process.Init.Minimal) !void {
    // Short-lived tool: arena everything, reclaimed at exit.
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const parsed = parseArgs(allocator, init.args) catch |err| {
        std.debug.print("tls-interop: bad arguments ({s})\n{s}", .{ @errorName(err), usage });
        std.process.exit(2);
    };
    if (parsed == null) {
        var ignored: u8 = 0;
        matrix.listCapabilities(&ignored, writeCapabilityLine);
        std.process.exit(0);
    }
    const args = parsed.?;

    // Bind before any other setup. Loading an RSA identity runs Miller-Rabin
    // primality checks that take well over a second, and a runner that starts
    // the external peer on a timer would otherwise get ECONNREFUSED against a
    // socket this process has not opened yet. The `listening` line below is
    // the readiness signal a runner should wait for instead of sleeping.
    var listener: ?posix.fd_t = null;
    defer if (listener) |fd| {
        _ = std.c.close(fd);
    };
    if (args.mode == .server) {
        listener = listenTcp(args.port) catch |err| {
            std.debug.print("tls-interop: cannot listen on port {d} ({s})\n", .{ args.port, @errorName(err) });
            std.process.exit(2);
        };
    }

    var runner = Runner.init(allocator, args) catch |err| {
        std.debug.print("tls-interop: setup failed ({s})\n{s}", .{ @errorName(err), usage });
        std.process.exit(2);
    };
    defer runner.deinit();

    if (args.mode == .server) {
        var ready: [64]u8 = undefined;
        writeStdout(std.fmt.bufPrint(&ready, "tls-interop: listening port={d}\n", .{args.port}) catch "");
    }

    const deadline = nowMs() + @as(i64, @intCast(args.timeout_ms));
    var worst: u8 = 0;
    var connection: usize = 0;
    while (connection < args.connections) : (connection += 1) {
        var transcript = Transcript{};
        const fd = switch (args.mode) {
            .server => acceptTcp(listener.?, deadline) catch |err| {
                std.debug.print("tls-interop: accept failed ({s})\n", .{@errorName(err)});
                std.process.exit(1);
            },
            .client => connectTcp(args.host, args.port, deadline) catch |err| {
                std.debug.print("tls-interop: connect failed ({s})\n", .{@errorName(err)});
                std.process.exit(1);
            },
        };

        const outcome = runner.runOne(fd, &transcript);

        var line: [1024]u8 = undefined;
        writeStdout(reportLine(&line, args, outcome));

        if (args.transcript.len > 0) {
            // One transcript per run; multi-connection rows suffix the
            // connection index so every attempt is retained.
            var path_buf: [512]u8 = undefined;
            const path = if (args.connections == 1)
                args.transcript
            else
                std.fmt.bufPrint(&path_buf, "{s}.{d}", .{ args.transcript, connection }) catch args.transcript;
            writeTranscript(path, args, outcome, &transcript) catch |err| {
                std.debug.print("tls-interop: could not write transcript {s} ({s})\n", .{ path, @errorName(err) });
            };
        }

        worst = @max(worst, evaluate(args, outcome));
    }

    std.process.exit(worst);
}

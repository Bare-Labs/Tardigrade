//! Resumption/ticket cryptographic-machinery workloads for issue #378:
//! session-state codec size sweeps, stateless ticket seal/open/resolve
//! through `tls_core.ticket_protection.Protector`, resolver-miss paths, and
//! keyring/nonce-lease overhead. Whole resumed-handshake latency stays out
//! of scope here per the issue's ownership boundaries (#326/#369).
//!
//! Not covered: a standalone "AEAD open with a pre-parsed envelope" step.
//! `ticket_protection` does not expose the AAD-construction helper
//! (`buildAad`) that step would need publicly, and issue #378 itself
//! guards that bullet with "where the API permits it" — reimplementing
//! private framing logic here would risk silently drifting from the real
//! implementation. `runResolve` below covers the combined parse+open+decode
//! cost end to end.

const std = @import("std");
const crypto = @import("crypto");
const tls_core = @import("tls_core");
const harness = @import("harness.zig");

const provider = crypto.provider;
const pure_zig = crypto.pure_zig;
const session = tls_core.session;
const ticket_protection = tls_core.ticket_protection;

const Measurement = harness.Measurement;
const Scale = harness.Scale;

/// See `primitives.TestProvider`'s doc comment: constructed and initialized
/// on its own already-addressed stack frame, never returned by value.
const TestProvider = struct {
    entropy: pure_zig.DeterministicEntropy,
    instance: pure_zig.Provider,

    fn init(self: *TestProvider, seed: u64) void {
        self.entropy = pure_zig.DeterministicEntropy.init(seed);
        self.instance = pure_zig.Provider.init(self.entropy.entropy());
    }

    fn cryptoProvider(self: *const TestProvider) provider.CryptoProvider {
        return self.instance.cryptoProvider();
    }
};

fn keyIdFor(byte: u8) ticket_protection.KeyId {
    return [_]u8{byte} ** ticket_protection.key_id_len;
}

fn ticketCapabilities() provider.Capabilities {
    var caps = provider.Capabilities{};
    caps.aeads.insert(.aes_128_gcm);
    caps.aeads.insert(.aes_256_gcm);
    caps.aeads.insert(.chacha20_poly1305);
    return caps;
}

const StateSize = enum { small, medium, large };

fn buildServerState(allocator: std.mem.Allocator, comptime size: StateSize) !session.ServerRecoverableState {
    var common: session.ResumableSessionCommon = .{};
    switch (size) {
        .small => try common.init(allocator, session.Limits.default, .{
            .cipher_suite = .tls_aes_128_gcm_sha256,
            .resumption_psk = &([_]u8{0xab} ** 32),
            .auth_binding = session.AuthBinding.fromLeafCertificateDer("leaf-der-small"),
            .issued_at_unix_ms = 1_000,
            .lifetime_seconds = 3_600,
        }),
        .medium => try common.init(allocator, session.Limits.default, .{
            .cipher_suite = .tls_aes_128_gcm_sha256,
            .resumption_psk = &([_]u8{0xab} ** 32),
            .server_name = "medium.example.test",
            .application_protocol = "h3",
            .auth_binding = session.AuthBinding.fromLeafCertificateDer("leaf-der-medium"),
            .issued_at_unix_ms = 1_000,
            .lifetime_seconds = 3_600,
            .transport_compat = .{ .format_id = 1, .format_version = 1, .bytes = &([_]u8{0x5a} ** 256) },
        }),
        .large => try common.init(allocator, session.Limits.default, .{
            .cipher_suite = .tls_aes_256_gcm_sha384,
            .resumption_psk = &([_]u8{0xab} ** 48),
            .server_name = "large.example.test",
            .application_protocol = "h3",
            .auth_binding = session.AuthBinding.fromLeafCertificateDer("leaf-der-large"),
            .issued_at_unix_ms = 1_000,
            .lifetime_seconds = 3_600,
            .transport_compat = .{ .format_id = 1, .format_version = 1, .bytes = &([_]u8{0x5b} ** 900) },
            .application_compat = .{ .format_id = 2, .format_version = 1, .bytes = &([_]u8{0x5c} ** 900) },
        }),
    }
    var state: session.ServerRecoverableState = .{};
    state.init(&common, 0x1122_3344);
    return state;
}

pub fn run(allocator: std.mem.Allocator, out: *harness.Reporter, scale: Scale) !void {
    try runCodecSize(allocator, out, scale, .small);
    try runCodecSize(allocator, out, scale, .medium);
    try runCodecSize(allocator, out, scale, .large);

    inline for (.{ provider.Aead.aes_128_gcm, provider.Aead.aes_256_gcm, provider.Aead.chacha20_poly1305 }) |aead| {
        try runSeal(allocator, out, scale, aead);
        try runEnvelopeParseOnly(allocator, out, scale, aead);
        try runResolve(allocator, out, scale, aead);
    }
    try runResolverMissMalformed(allocator, out, scale);
    try runResolverMissUnknownKey(allocator, out, scale);
    try runResolverMissInvalidTag(allocator, out, scale);

    try runSnapshotBuild(allocator, out, scale);
    try runInstallRotation(allocator, out, scale, false);
    try runInstallRotation(allocator, out, scale, true);
    try runAcquireRelease(allocator, out, scale);
    try runNonceReservationContended(out, scale);
}

// ---------------------------------------------------------------------------
// Session-state codec
// ---------------------------------------------------------------------------

fn runCodecSize(allocator: std.mem.Allocator, out: *harness.Reporter, scale: Scale, comptime size: StateSize) !void {
    var state = try buildServerState(allocator, size);
    defer state.deinit();

    {
        const Context = struct {
            state: *const session.ServerRecoverableState,
            buf: [4096]u8 = undefined,

            fn step(self: *@This()) !void {
                const encoded = try session.encodeServer(self.state, session.Limits.default, &self.buf);
                std.mem.doNotOptimizeAway(encoded.len);
            }
        };
        var ctx = Context{ .state = &state };
        const iterations = scale.iterations(3000);
        const ns = try harness.timeLoop(Context, &ctx, iterations, Context.step);
        const encoded_len = try session.serverEncodedLenWithLimits(&state, session.Limits.default);
        try out.append(.{ .suite = "ticket", .name = "state_encode", .algorithm = @tagName(size), .input_bytes = encoded_len, .iterations = iterations, .ns_total = ns });
    }

    var encode_buf: [4096]u8 = undefined;
    const encoded = try session.encodeServer(&state, session.Limits.default, &encode_buf);
    {
        const Context = struct {
            allocator: std.mem.Allocator,
            encoded: []const u8,

            fn step(self: *@This()) !void {
                var decoded = try session.decode(self.allocator, session.Limits.default, self.encoded);
                decoded.deinit();
            }
        };
        var counting = harness.CountingAllocator.init(allocator);
        var ctx = Context{ .allocator = counting.allocator(), .encoded = encoded };
        const iterations = scale.iterations(3000);
        const ns = try harness.timeLoop(Context, &ctx, iterations, Context.step);
        try out.append(.{
            .suite = "ticket",
            .name = "state_decode",
            .algorithm = @tagName(size),
            .input_bytes = encoded.len,
            .iterations = iterations,
            .ns_total = ns,
            .allocations_per_op = @as(f64, @floatFromInt(counting.allocations)) / @as(f64, @floatFromInt(iterations)),
            .bytes_allocated_per_op = @as(f64, @floatFromInt(counting.bytes_allocated)) / @as(f64, @floatFromInt(iterations)),
        });
    }
}

// ---------------------------------------------------------------------------
// Stateless ticket seal / parse / resolve
// ---------------------------------------------------------------------------

fn runSeal(allocator: std.mem.Allocator, out: *harness.Reporter, scale: Scale, comptime aead: provider.Aead) !void {
    var tp: TestProvider = undefined;
    tp.init(0x378_60);
    const cp = tp.cryptoProvider();

    var keyring = ticket_protection.ReloadableKeyRing.init(allocator);
    defer keyring.deinit();
    const key_bytes = [_]u8{0x11} ** aead.keyLength();
    const config = ticket_protection.KeyConfig{
        .id = keyIdFor(0xA1),
        .aead = aead,
        .key_bytes = &key_bytes,
        .not_before_unix_ms = 0,
        .encrypt_until_unix_ms = 1_000_000_000,
        .decrypt_until_unix_ms = 2_000_000_000,
        .nonce_lease = .{ .prefix = .{ 0xA1, 0, 0, 0 }, .start = 0, .end_exclusive = 1_000_000 },
    };
    try keyring.install(try keyring.buildSnapshot(&.{config}, ticketCapabilities()));

    var state = try buildServerState(allocator, .medium);
    defer state.deinit();

    const Context = struct {
        protector: ticket_protection.Protector,
        allocator: std.mem.Allocator,
        state: *const session.ServerRecoverableState,
        out_buf: [4096]u8 = undefined,

        fn step(self: *@This()) !void {
            const sealed = try self.protector.seal(self.allocator, self.state, 1500, &self.out_buf);
            std.mem.doNotOptimizeAway(sealed.len);
        }
    };
    var counting = harness.CountingAllocator.init(allocator);
    var ctx = Context{
        .protector = .{ .provider = cp, .keyring = &keyring, .limits = session.Limits.default },
        .allocator = counting.allocator(),
        .state = &state,
    };
    const iterations = scale.iterations(1000);
    const ns = try harness.timeLoop(Context, &ctx, iterations, Context.step);
    try out.append(.{
        .suite = "ticket",
        .name = "seal",
        .algorithm = @tagName(aead),
        .iterations = iterations,
        .ns_total = ns,
        .allocations_per_op = @as(f64, @floatFromInt(counting.allocations)) / @as(f64, @floatFromInt(iterations)),
        .bytes_allocated_per_op = @as(f64, @floatFromInt(counting.bytes_allocated)) / @as(f64, @floatFromInt(iterations)),
    });
}

fn runEnvelopeParseOnly(allocator: std.mem.Allocator, out: *harness.Reporter, scale: Scale, comptime aead: provider.Aead) !void {
    var tp: TestProvider = undefined;
    tp.init(0x378_61);
    const cp = tp.cryptoProvider();

    var keyring = ticket_protection.ReloadableKeyRing.init(allocator);
    defer keyring.deinit();
    const key_bytes = [_]u8{0x44} ** aead.keyLength();
    const config = ticket_protection.KeyConfig{
        .id = keyIdFor(0xF1),
        .aead = aead,
        .key_bytes = &key_bytes,
        .not_before_unix_ms = 0,
        .encrypt_until_unix_ms = 1_000_000_000,
        .decrypt_until_unix_ms = 2_000_000_000,
        .nonce_lease = .{ .prefix = .{ 0xF1, 0, 0, 0 }, .start = 0, .end_exclusive = 2 },
    };
    try keyring.install(try keyring.buildSnapshot(&.{config}, ticketCapabilities()));

    var state = try buildServerState(allocator, .medium);
    defer state.deinit();
    var protector = ticket_protection.Protector{ .provider = cp, .keyring = &keyring, .limits = session.Limits.default };
    var sealed_buf: [4096]u8 = undefined;
    const identity = try protector.seal(allocator, &state, 1500, &sealed_buf);

    const Context = struct {
        identity: []const u8,

        fn step(self: *@This()) !void {
            const parsed = try ticket_protection.parseEnvelope(self.identity, session.Limits.default);
            std.mem.doNotOptimizeAway(parsed.ciphertext.len);
        }
    };
    var ctx = Context{ .identity = identity };
    const iterations = scale.iterations(5000);
    const ns = try harness.timeLoop(Context, &ctx, iterations, Context.step);
    try out.append(.{ .suite = "ticket", .name = "envelope_parse_only", .algorithm = @tagName(aead), .input_bytes = identity.len, .iterations = iterations, .ns_total = ns });
}

fn runResolve(allocator: std.mem.Allocator, out: *harness.Reporter, scale: Scale, comptime aead: provider.Aead) !void {
    var tp: TestProvider = undefined;
    tp.init(0x378_62);
    const cp = tp.cryptoProvider();

    var keyring = ticket_protection.ReloadableKeyRing.init(allocator);
    defer keyring.deinit();
    const key_bytes = [_]u8{0x55} ** aead.keyLength();
    const config = ticket_protection.KeyConfig{
        .id = keyIdFor(0xF2),
        .aead = aead,
        .key_bytes = &key_bytes,
        .not_before_unix_ms = 0,
        .encrypt_until_unix_ms = 1_000_000_000,
        .decrypt_until_unix_ms = 2_000_000_000,
        .nonce_lease = .{ .prefix = .{ 0xF2, 0, 0, 0 }, .start = 0, .end_exclusive = 2 },
    };
    try keyring.install(try keyring.buildSnapshot(&.{config}, ticketCapabilities()));

    var state = try buildServerState(allocator, .medium);
    defer state.deinit();
    var seal_protector = ticket_protection.Protector{ .provider = cp, .keyring = &keyring, .limits = session.Limits.default };
    var sealed_buf: [4096]u8 = undefined;
    const identity = try seal_protector.seal(allocator, &state, 1500, &sealed_buf);
    var identity_buf: [4096]u8 = undefined;
    @memcpy(identity_buf[0..identity.len], identity);

    const Context = struct {
        protector: ticket_protection.Protector,
        allocator: std.mem.Allocator,
        identity: [4096]u8,
        identity_len: usize,

        fn step(self: *@This()) !void {
            var recovered: session.ServerRecoverableState = .{};
            defer recovered.deinit();
            const ok = try self.protector.resolve(self.allocator, self.identity[0..self.identity_len], 1500, &recovered);
            if (!ok) return error.ExpectedResolveSuccess;
        }
    };
    var counting = harness.CountingAllocator.init(allocator);
    var ctx = Context{
        .protector = .{ .provider = cp, .keyring = &keyring, .limits = session.Limits.default },
        .allocator = counting.allocator(),
        .identity = identity_buf,
        .identity_len = identity.len,
    };
    const iterations = scale.iterations(1000);
    const ns = try harness.timeLoop(Context, &ctx, iterations, Context.step);
    try out.append(.{
        .suite = "ticket",
        .name = "resolve",
        .algorithm = @tagName(aead),
        .input_bytes = identity.len,
        .iterations = iterations,
        .ns_total = ns,
        .allocations_per_op = @as(f64, @floatFromInt(counting.allocations)) / @as(f64, @floatFromInt(iterations)),
        .bytes_allocated_per_op = @as(f64, @floatFromInt(counting.bytes_allocated)) / @as(f64, @floatFromInt(iterations)),
        .note = "full resolve: envelope parse + AEAD open + state decode",
    });
}

fn runResolverMissMalformed(allocator: std.mem.Allocator, out: *harness.Reporter, scale: Scale) !void {
    var tp: TestProvider = undefined;
    tp.init(0x378_63);
    const cp = tp.cryptoProvider();
    var keyring = ticket_protection.ReloadableKeyRing.init(allocator);
    defer keyring.deinit();
    const key_bytes = [_]u8{0x66} ** provider.Aead.aes_128_gcm.keyLength();
    const config = ticket_protection.KeyConfig{
        .id = keyIdFor(0xF3),
        .aead = .aes_128_gcm,
        .key_bytes = &key_bytes,
        .not_before_unix_ms = 0,
        .encrypt_until_unix_ms = 1_000_000_000,
        .decrypt_until_unix_ms = 2_000_000_000,
        .nonce_lease = null,
    };
    try keyring.install(try keyring.buildSnapshot(&.{config}, ticketCapabilities()));

    const Context = struct {
        protector: ticket_protection.Protector,
        allocator: std.mem.Allocator,

        fn step(self: *@This()) !void {
            var recovered: session.ServerRecoverableState = .{};
            defer recovered.deinit();
            const ok = try self.protector.resolve(self.allocator, "not-a-valid-ticket-envelope-at-all", 1500, &recovered);
            if (ok) return error.ExpectedResolveFailure;
        }
    };
    var ctx = Context{ .protector = .{ .provider = cp, .keyring = &keyring, .limits = session.Limits.default }, .allocator = allocator };
    const iterations = scale.iterations(5000);
    const ns = try harness.timeLoop(Context, &ctx, iterations, Context.step);
    try out.append(.{ .suite = "ticket", .name = "resolver_miss_malformed", .algorithm = "n/a", .iterations = iterations, .ns_total = ns, .note = "structurally invalid identity; rejected before any AEAD work" });
}

fn runResolverMissUnknownKey(allocator: std.mem.Allocator, out: *harness.Reporter, scale: Scale) !void {
    var tp: TestProvider = undefined;
    tp.init(0x378_64);
    const cp = tp.cryptoProvider();

    var keyring_a = ticket_protection.ReloadableKeyRing.init(allocator);
    defer keyring_a.deinit();
    const key_bytes_a = [_]u8{0x77} ** provider.Aead.aes_128_gcm.keyLength();
    const config_a = ticket_protection.KeyConfig{
        .id = keyIdFor(0xF4),
        .aead = .aes_128_gcm,
        .key_bytes = &key_bytes_a,
        .not_before_unix_ms = 0,
        .encrypt_until_unix_ms = 1_000_000_000,
        .decrypt_until_unix_ms = 2_000_000_000,
        .nonce_lease = .{ .prefix = .{ 0xF4, 0, 0, 0 }, .start = 0, .end_exclusive = 2 },
    };
    try keyring_a.install(try keyring_a.buildSnapshot(&.{config_a}, ticketCapabilities()));

    var state = try buildServerState(allocator, .medium);
    defer state.deinit();
    var seal_protector = ticket_protection.Protector{ .provider = cp, .keyring = &keyring_a, .limits = session.Limits.default };
    var sealed_buf: [4096]u8 = undefined;
    const identity = try seal_protector.seal(allocator, &state, 1500, &sealed_buf);
    var identity_buf: [4096]u8 = undefined;
    @memcpy(identity_buf[0..identity.len], identity);

    var keyring_b = ticket_protection.ReloadableKeyRing.init(allocator);
    defer keyring_b.deinit();
    const key_bytes_b = [_]u8{0x88} ** provider.Aead.aes_128_gcm.keyLength();
    const config_b = ticket_protection.KeyConfig{
        .id = keyIdFor(0xF5),
        .aead = .aes_128_gcm,
        .key_bytes = &key_bytes_b,
        .not_before_unix_ms = 0,
        .encrypt_until_unix_ms = 1_000_000_000,
        .decrypt_until_unix_ms = 2_000_000_000,
        .nonce_lease = null,
    };
    try keyring_b.install(try keyring_b.buildSnapshot(&.{config_b}, ticketCapabilities()));

    const Context = struct {
        protector: ticket_protection.Protector,
        allocator: std.mem.Allocator,
        identity: [4096]u8,
        identity_len: usize,

        fn step(self: *@This()) !void {
            var recovered: session.ServerRecoverableState = .{};
            defer recovered.deinit();
            const ok = try self.protector.resolve(self.allocator, self.identity[0..self.identity_len], 1500, &recovered);
            if (ok) return error.ExpectedResolveFailure;
        }
    };
    var ctx = Context{
        .protector = .{ .provider = cp, .keyring = &keyring_b, .limits = session.Limits.default },
        .allocator = allocator,
        .identity = identity_buf,
        .identity_len = identity.len,
    };
    const iterations = scale.iterations(3000);
    const ns = try harness.timeLoop(Context, &ctx, iterations, Context.step);
    try out.append(.{ .suite = "ticket", .name = "resolver_miss_unknown_key", .algorithm = "aes_128_gcm", .input_bytes = identity.len, .iterations = iterations, .ns_total = ns, .note = "well-formed envelope; key id absent from the resolving keyring" });
}

fn runResolverMissInvalidTag(allocator: std.mem.Allocator, out: *harness.Reporter, scale: Scale) !void {
    var tp: TestProvider = undefined;
    tp.init(0x378_65);
    const cp = tp.cryptoProvider();
    var keyring = ticket_protection.ReloadableKeyRing.init(allocator);
    defer keyring.deinit();
    const key_bytes = [_]u8{0x99} ** provider.Aead.aes_128_gcm.keyLength();
    const config = ticket_protection.KeyConfig{
        .id = keyIdFor(0xF6),
        .aead = .aes_128_gcm,
        .key_bytes = &key_bytes,
        .not_before_unix_ms = 0,
        .encrypt_until_unix_ms = 1_000_000_000,
        .decrypt_until_unix_ms = 2_000_000_000,
        .nonce_lease = .{ .prefix = .{ 0xF6, 0, 0, 0 }, .start = 0, .end_exclusive = 2 },
    };
    try keyring.install(try keyring.buildSnapshot(&.{config}, ticketCapabilities()));

    var state = try buildServerState(allocator, .medium);
    defer state.deinit();
    var seal_protector = ticket_protection.Protector{ .provider = cp, .keyring = &keyring, .limits = session.Limits.default };
    var sealed_buf: [4096]u8 = undefined;
    const identity = try seal_protector.seal(allocator, &state, 1500, &sealed_buf);
    var tampered: [4096]u8 = undefined;
    @memcpy(tampered[0..identity.len], identity);
    tampered[identity.len - 1] ^= 0x01;

    const Context = struct {
        protector: ticket_protection.Protector,
        allocator: std.mem.Allocator,
        identity: [4096]u8,
        identity_len: usize,

        fn step(self: *@This()) !void {
            var recovered: session.ServerRecoverableState = .{};
            defer recovered.deinit();
            const ok = try self.protector.resolve(self.allocator, self.identity[0..self.identity_len], 1500, &recovered);
            if (ok) return error.ExpectedResolveFailure;
        }
    };
    var ctx = Context{
        .protector = .{ .provider = cp, .keyring = &keyring, .limits = session.Limits.default },
        .allocator = allocator,
        .identity = tampered,
        .identity_len = identity.len,
    };
    const iterations = scale.iterations(3000);
    const ns = try harness.timeLoop(Context, &ctx, iterations, Context.step);
    try out.append(.{ .suite = "ticket", .name = "resolver_miss_invalid_tag", .algorithm = "aes_128_gcm", .input_bytes = identity.len, .iterations = iterations, .ns_total = ns, .note = "tampered AEAD tag byte; every call rejects" });
}

// ---------------------------------------------------------------------------
// Keyring / nonce leases
// ---------------------------------------------------------------------------

fn runSnapshotBuild(allocator: std.mem.Allocator, out: *harness.Reporter, scale: Scale) !void {
    inline for (.{ 1, 2, 4, 8, ticket_protection.max_keys }) |count| {
        var key_bytes: [count][32]u8 = undefined;
        var configs: [count]ticket_protection.KeyConfig = undefined;
        for (0..count) |i| {
            key_bytes[i] = [_]u8{@as(u8, @truncate(i + 1))} ** 32;
            configs[i] = .{
                .id = keyIdFor(@as(u8, @truncate(0xE0 + i))),
                .aead = .aes_256_gcm,
                .key_bytes = &key_bytes[i],
                .not_before_unix_ms = 0,
                .encrypt_until_unix_ms = 1_000_000_000,
                .decrypt_until_unix_ms = 2_000_000_000,
                .nonce_lease = null,
            };
        }
        var keyring = ticket_protection.ReloadableKeyRing.init(allocator);
        defer keyring.deinit();

        const Context = struct {
            keyring: *ticket_protection.ReloadableKeyRing,
            configs: []const ticket_protection.KeyConfig,

            fn step(self: *@This()) !void {
                const snapshot = try self.keyring.buildSnapshot(self.configs, ticketCapabilities());
                snapshot.release();
            }
        };
        var ctx = Context{ .keyring = &keyring, .configs = &configs };
        const iterations = scale.iterations(1000);
        const ns = try harness.timeLoop(Context, &ctx, iterations, Context.step);
        try out.append(.{ .suite = "ticket", .name = "snapshot_build", .algorithm = "ReloadableKeyRing", .input_bytes = count, .iterations = iterations, .ns_total = ns, .note = "input_bytes is the key count" });
    }
}

fn runInstallRotation(allocator: std.mem.Allocator, out: *harness.Reporter, scale: Scale, comptime hold_inflight: bool) !void {
    var keyring = ticket_protection.ReloadableKeyRing.init(allocator);
    defer keyring.deinit();
    const key_bytes = [_]u8{0x22} ** provider.Aead.aes_128_gcm.keyLength();
    const config = ticket_protection.KeyConfig{
        .id = keyIdFor(0xD0),
        .aead = .aes_128_gcm,
        .key_bytes = &key_bytes,
        .not_before_unix_ms = 0,
        .encrypt_until_unix_ms = 1_000_000_000,
        .decrypt_until_unix_ms = 2_000_000_000,
        .nonce_lease = null,
    };
    try keyring.install(try keyring.buildSnapshot(&.{config}, ticketCapabilities()));

    const Context = struct {
        keyring: *ticket_protection.ReloadableKeyRing,
        config: ticket_protection.KeyConfig,

        fn step(self: *@This()) !void {
            var held: ?*ticket_protection.Snapshot = null;
            if (hold_inflight) held = self.keyring.acquireCurrent();
            const snapshot = try self.keyring.buildSnapshot(&.{self.config}, ticketCapabilities());
            try self.keyring.install(snapshot);
            if (held) |s| s.release();
        }
    };
    var ctx = Context{ .keyring = &keyring, .config = config };
    const iterations = scale.iterations(500);
    const ns = try harness.timeLoop(Context, &ctx, iterations, Context.step);
    try out.append(.{
        .suite = "ticket",
        .name = if (hold_inflight) "install_with_inflight_reader" else "install_no_inflight_reader",
        .algorithm = "ReloadableKeyRing",
        .iterations = iterations,
        .ns_total = ns,
        .note = "single-key snapshot rebuild+install per iteration, retiring the previous generation (repeated bounded rotation)",
    });
}

fn runAcquireRelease(allocator: std.mem.Allocator, out: *harness.Reporter, scale: Scale) !void {
    var keyring = ticket_protection.ReloadableKeyRing.init(allocator);
    defer keyring.deinit();
    const key_bytes = [_]u8{0x33} ** provider.Aead.aes_128_gcm.keyLength();
    const config = ticket_protection.KeyConfig{
        .id = keyIdFor(0xE9),
        .aead = .aes_128_gcm,
        .key_bytes = &key_bytes,
        .not_before_unix_ms = 0,
        .encrypt_until_unix_ms = 1_000_000_000,
        .decrypt_until_unix_ms = 2_000_000_000,
        .nonce_lease = null,
    };
    try keyring.install(try keyring.buildSnapshot(&.{config}, ticketCapabilities()));

    const Context = struct {
        keyring: *ticket_protection.ReloadableKeyRing,

        fn step(self: *@This()) !void {
            const snapshot = self.keyring.acquireCurrent() orelse return error.NoActiveSnapshot;
            snapshot.release();
        }
    };
    var ctx = Context{ .keyring = &keyring };
    const iterations = scale.iterations(5000);
    const ns = try harness.timeLoop(Context, &ctx, iterations, Context.step);
    try out.append(.{ .suite = "ticket", .name = "acquire_active_snapshot", .algorithm = "ReloadableKeyRing", .iterations = iterations, .ns_total = ns });
}

fn runNonceReservationContended(out: *harness.Reporter, scale: Scale) !void {
    var tp: TestProvider = undefined;
    tp.init(0x378_70);
    const cp = tp.cryptoProvider();

    // Uses the OS-backed page allocator, not the harness's CountingAllocator:
    // this workload's point is to exercise the atomic nonce-lease CAS under
    // real concurrent writers, and a lock-free thread-safe allocator keeps
    // that contention isolated to the lease itself rather than a shared
    // counter inside the allocator.
    const thread_allocator = std.heap.page_allocator;
    var keyring = ticket_protection.ReloadableKeyRing.init(thread_allocator);
    defer keyring.deinit();

    const thread_count = 4;
    const per_thread_iterations = scale.iterations(500);
    const key_bytes = [_]u8{0x11} ** provider.Aead.aes_128_gcm.keyLength();
    const config = ticket_protection.KeyConfig{
        .id = keyIdFor(0xC1),
        .aead = .aes_128_gcm,
        .key_bytes = &key_bytes,
        .not_before_unix_ms = 0,
        .encrypt_until_unix_ms = 1_000_000_000,
        .decrypt_until_unix_ms = 2_000_000_000,
        .nonce_lease = .{ .prefix = .{ 0xC1, 0, 0, 0 }, .start = 0, .end_exclusive = @as(u64, thread_count * per_thread_iterations) + 1 },
    };
    try keyring.install(try keyring.buildSnapshot(&.{config}, ticketCapabilities()));

    var state = try buildServerState(thread_allocator, .small);
    defer state.deinit();
    var protector = ticket_protection.Protector{ .provider = cp, .keyring = &keyring, .limits = session.Limits.default };

    // A worker that hits a `Protector.seal` error (nonce-lease exhaustion,
    // an unexpected keyring rejection, ...) must not be able to make this
    // workload silently report success on partial work: nonce uniqueness is
    // a security invariant issue #378 says benchmarks must not weaken, so a
    // seal failure here has to fail the benchmark, not just end one thread
    // early while the parent reports the full requested iteration count
    // regardless.
    const Shared = struct {
        completed: std.atomic.Value(usize) = .init(0),
        failed: std.atomic.Value(bool) = .init(false),
    };

    const Worker = struct {
        fn run(shared: *Shared, protector_ptr: *ticket_protection.Protector, state_ptr: *const session.ServerRecoverableState, iterations: usize) void {
            var out_buf: [4096]u8 = undefined;
            var i: usize = 0;
            while (i < iterations) : (i += 1) {
                _ = protector_ptr.seal(std.heap.page_allocator, state_ptr, 1500, &out_buf) catch {
                    shared.failed.store(true, .release);
                    return;
                };
                _ = shared.completed.fetchAdd(1, .monotonic);
            }
        }
    };

    var shared = Shared{};
    var threads: [thread_count]std.Thread = undefined;
    const start = harness.monotonicNs();
    for (&threads) |*t| {
        t.* = try std.Thread.spawn(.{}, Worker.run, .{ &shared, &protector, &state, per_thread_iterations });
    }
    for (&threads) |*t| t.join();
    const ns: u64 = @intCast(harness.monotonicNs() - start);

    const expected = thread_count * per_thread_iterations;
    const completed = shared.completed.load(.acquire);
    if (shared.failed.load(.acquire) or completed != expected) {
        return error.NonceReservationWorkerFailed;
    }

    try out.append(.{
        .suite = "ticket",
        .name = "nonce_reservation_contended",
        .algorithm = "aes_128_gcm",
        .iterations = completed,
        .ns_total = ns,
        .note = "4 threads sharing one nonce lease, each doing end-to-end Protector.seal",
    });
}

//! TLS record cryptographic component workloads for issue #378: traffic
//! key/IV derivation, record AEAD seal/open, and the authentication-failure
//! path, through `tls_core.record_protection` — the same module the native
//! TLS record layer uses. Whole-stream/HTTP throughput stays out of scope
//! here per the issue's ownership boundaries (#325).

const std = @import("std");
const crypto = @import("crypto");
const tls_core = @import("tls_core");
const harness = @import("harness.zig");

const provider = crypto.provider;
const pure_zig = crypto.pure_zig;
const algorithms = tls_core.algorithms;
const record_protection = tls_core.record_protection;
const record_codec = tls_core.record_codec;

const Measurement = harness.Measurement;
const Scale = harness.Scale;

const cipher_suites = [_]algorithms.CipherSuite{
    .tls_aes_128_gcm_sha256,
    .tls_aes_256_gcm_sha384,
    .tls_chacha20_poly1305_sha256,
};
const record_sizes = [_]usize{ 64, 1350, 16384 };

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

fn trafficSecret(comptime hash: provider.Hash, fill: u8) [hash.digestLength()]u8 {
    return [_]u8{fill} ** hash.digestLength();
}

pub fn run(out: *harness.Reporter, scale: Scale) !void {
    for (cipher_suites) |suite| {
        try runTrafficKeyDerivation(out, scale, suite);
        for (record_sizes) |size| {
            try runSeal(out, scale, suite, size);
            try runOpen(out, scale, suite, size);
        }
        try runAuthFailure(out, scale, suite);
    }
}

fn runTrafficKeyDerivation(out: *harness.Reporter, scale: Scale, suite: algorithms.CipherSuite) !void {
    var tp: TestProvider = undefined;
    tp.init(0x378_50);
    const cp = tp.cryptoProvider();
    const profile = record_protection.suiteProfile(suite);

    const Context = struct {
        cp: provider.CryptoProvider,
        suite: algorithms.CipherSuite,
        hash: provider.Hash,
        secret_sha256: [32]u8,
        secret_sha384: [48]u8,

        fn step(self: *@This()) !void {
            const secret: []const u8 = switch (self.hash) {
                .sha256 => &self.secret_sha256,
                .sha384 => &self.secret_sha384,
            };
            var keys = try record_protection.TrafficKeys.derive(self.cp, self.suite, secret);
            keys.deinit();
        }
    };
    var ctx = Context{
        .cp = cp,
        .suite = suite,
        .hash = profile.hash,
        .secret_sha256 = trafficSecret(.sha256, 0x11),
        .secret_sha384 = trafficSecret(.sha384, 0x11),
    };
    const iterations = scale.iterations(3000);
    const ns = try harness.timeLoop(Context, &ctx, iterations, Context.step);
    try out.append(.{ .suite = "record", .name = "traffic_key_iv_derivation", .algorithm = @tagName(suite), .iterations = iterations, .ns_total = ns });
}

fn runSeal(out: *harness.Reporter, scale: Scale, suite: algorithms.CipherSuite, size: usize) !void {
    var tp: TestProvider = undefined;
    tp.init(0x378_51);
    const cp = tp.cryptoProvider();
    const profile = record_protection.suiteProfile(suite);
    const secret_sha256 = trafficSecret(.sha256, 0x22);
    const secret_sha384 = trafficSecret(.sha384, 0x22);
    const secret: []const u8 = switch (profile.hash) {
        .sha256 => &secret_sha256,
        .sha384 => &secret_sha384,
    };
    const keys = try record_protection.TrafficKeys.derive(cp, suite, secret);

    const Context = struct {
        write: record_protection.WriteState,
        plaintext: [16384]u8 = [_]u8{0x33} ** 16384,
        out_buf: [16384 + 256]u8 = undefined,
        size: usize,

        fn step(self: *@This()) !void {
            const sealed = try self.write.seal(.application_data, self.plaintext[0..self.size], 0, &self.out_buf);
            std.mem.doNotOptimizeAway(sealed.len);
        }
    };
    var ctx = Context{ .write = record_protection.WriteState.init(cp, keys), .size = size };
    defer ctx.write.deinit();
    const iterations = scale.iterations(if (size >= 16384) 500 else 3000);
    const ns = try harness.timeLoop(Context, &ctx, iterations, Context.step);
    try out.append(.{ .suite = "record", .name = "seal", .algorithm = @tagName(suite), .input_bytes = size, .iterations = iterations, .ns_total = ns });
}

fn runOpen(out: *harness.Reporter, scale: Scale, suite: algorithms.CipherSuite, size: usize) !void {
    var tp: TestProvider = undefined;
    tp.init(0x378_52);
    const cp = tp.cryptoProvider();
    const profile = record_protection.suiteProfile(suite);
    const secret_sha256 = trafficSecret(.sha256, 0x44);
    const secret_sha384 = trafficSecret(.sha384, 0x44);
    const secret: []const u8 = switch (profile.hash) {
        .sha256 => &secret_sha256,
        .sha384 => &secret_sha384,
    };

    const write_keys = try record_protection.TrafficKeys.derive(cp, suite, secret);
    var write = record_protection.WriteState.init(cp, write_keys);
    var sealed_buf: [16384 + 256]u8 = undefined;
    var plaintext: [16384]u8 = [_]u8{0x55} ** 16384;
    const sealed = try write.seal(.application_data, plaintext[0..size], 0, &sealed_buf);
    write.deinit();

    const header = record_codec.parseHeader(sealed[0..record_codec.header_len], .ciphertext, .strict) catch unreachable;
    var payload_buf: [16384 + 256]u8 = undefined;
    const payload_len = sealed.len - record_codec.header_len;
    @memcpy(payload_buf[0..payload_len], sealed[record_codec.header_len..]);

    // Reads through one long-lived `ReadState`, resetting `sequence` to 0
    // before each call (the same direct-field-reset pattern
    // `record_protection.zig`'s own tests use) rather than re-deriving
    // traffic keys every iteration, so this isolates AEAD-open cost from
    // key-derivation cost (measured separately by `runTrafficKeyDerivation`).
    const read_keys = try record_protection.TrafficKeys.derive(cp, suite, secret);
    const Context = struct {
        read: record_protection.ReadState,
        content_type: record_codec.ContentType,
        legacy_version: u16,
        payload: [16384 + 256]u8,
        payload_len: usize,
        out_buf: [16384 + 256]u8 = undefined,

        fn step(self: *@This()) !void {
            self.read.sequence = 0;
            self.read.exhausted = false;
            const record: record_codec.TLSCiphertext = .{
                .content_type = self.content_type,
                .legacy_version = self.legacy_version,
                .payload = self.payload[0..self.payload_len],
            };
            const inner = try self.read.open(record, &self.out_buf);
            std.mem.doNotOptimizeAway(inner.content.len);
        }
    };
    var ctx = Context{
        .read = record_protection.ReadState.init(cp, read_keys),
        .content_type = header.content_type,
        .legacy_version = header.legacy_version,
        .payload = payload_buf,
        .payload_len = payload_len,
    };
    defer ctx.read.deinit();
    const iterations = scale.iterations(if (size >= 16384) 500 else 3000);
    const ns = try harness.timeLoop(Context, &ctx, iterations, Context.step);
    try out.append(.{ .suite = "record", .name = "open", .algorithm = @tagName(suite), .input_bytes = size, .iterations = iterations, .ns_total = ns });
}

fn runAuthFailure(out: *harness.Reporter, scale: Scale, suite: algorithms.CipherSuite) !void {
    var tp: TestProvider = undefined;
    tp.init(0x378_53);
    const cp = tp.cryptoProvider();
    const profile = record_protection.suiteProfile(suite);
    const secret_sha256 = trafficSecret(.sha256, 0x66);
    const secret_sha384 = trafficSecret(.sha384, 0x66);
    const secret: []const u8 = switch (profile.hash) {
        .sha256 => &secret_sha256,
        .sha384 => &secret_sha384,
    };
    const size = 1350;

    const write_keys = try record_protection.TrafficKeys.derive(cp, suite, secret);
    var write = record_protection.WriteState.init(cp, write_keys);
    var sealed_buf: [size + 256]u8 = undefined;
    var plaintext: [size]u8 = [_]u8{0x77} ** size;
    const sealed = try write.seal(.application_data, &plaintext, 0, &sealed_buf);
    write.deinit();
    var tampered: [sealed_buf.len]u8 = undefined;
    @memcpy(tampered[0..sealed.len], sealed);
    tampered[sealed.len - 1] ^= 0x01; // tamper the AEAD tag's last byte.

    const header = record_codec.parseHeader(tampered[0..record_codec.header_len], .ciphertext, .strict) catch unreachable;

    const read_keys = try record_protection.TrafficKeys.derive(cp, suite, secret);
    const Context = struct {
        read: record_protection.ReadState,
        payload: [size + 256]u8,
        payload_len: usize,
        content_type: record_codec.ContentType,
        legacy_version: u16,
        out_buf: [size + 256]u8 = undefined,

        fn step(self: *@This()) !void {
            self.read.sequence = 0;
            self.read.exhausted = false;
            const record: record_codec.TLSCiphertext = .{
                .content_type = self.content_type,
                .legacy_version = self.legacy_version,
                .payload = self.payload[0..self.payload_len],
            };
            const result = self.read.open(record, &self.out_buf);
            if (result) |_| return error.ExpectedAuthenticationFailure else |err| {
                if (err != error.AuthenticationFailed) return err;
            }
        }
    };
    var payload_buf: [size + 256]u8 = undefined;
    const payload_len = tampered.len - record_codec.header_len;
    @memcpy(payload_buf[0..payload_len], tampered[record_codec.header_len..]);
    var ctx = Context{
        .read = record_protection.ReadState.init(cp, read_keys),
        .payload = payload_buf,
        .payload_len = payload_len,
        .content_type = header.content_type,
        .legacy_version = header.legacy_version,
    };
    defer ctx.read.deinit();
    const iterations = scale.iterations(3000);
    const ns = try harness.timeLoop(Context, &ctx, iterations, Context.step);
    try out.append(.{ .suite = "record", .name = "open_auth_failure", .algorithm = @tagName(suite), .input_bytes = size, .iterations = iterations, .ns_total = ns, .note = "tampered ciphertext tag; every call rejects" });
}

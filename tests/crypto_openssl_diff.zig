//! Out-of-process OpenSSL differential crypto checks (#377).
//!
//! This target intentionally uses the `openssl` CLI as an oracle instead of
//! linking libcrypto into the Zig test binary. It covers deterministic TLS 1.3
//! and QUIC HKDF label construction plus Finished MAC derivation where the
//! current OpenSSL command surface is stable.

const std = @import("std");
const compat = @import("zig_compat");
const diff_options = @import("crypto_openssl_diff_options");
const crypto_pkg = @import("crypto");
const quic = @import("quic");
const tls_core = @import("tls_core");

const testing = std.testing;
const provider = crypto_pkg.provider;
const profile = crypto_pkg.profile;
const pure_zig = crypto_pkg.pure_zig;
const X25519 = std.crypto.dh.X25519;
const Ed25519 = std.crypto.sign.Ed25519;
const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const P256Scalar = std.crypto.ecc.P256.scalar.Scalar;

const evp_oracle_max_input = 4096;
const evp_oracle_stdout_limit = 2 * evp_oracle_max_input + 128;
const evp_oracle_stderr_limit = 1024;

const OpenSslError = error{
    MissingOpenSslKdfOracle,
    OpenSslOracleFailed,
    EvpOracleFailed,
    DifferentialMismatch,
};

const CoverageKind = enum {
    hkdf_extract,
    hkdf_expand_label,
    tls_record_keys,
    tls_key_schedule,
    quic_initial,
    transcript_hash,
    finished_hmac,
    aead,
    key_exchange,
    signature_sign,
    signature_verify,
    psk_binder,
};

const CoverageClass = enum {
    positive,
    negative,
};

const DifferentialCase = struct {
    kind: CoverageKind,
    algorithm: ?profile.Algorithm,
    class: CoverageClass,
    rationale: []const u8,
    run: *const fn (std.mem.Allocator) anyerror!void,
};

const Waiver = struct {
    kind: CoverageKind,
    algorithm: profile.Algorithm,
    class: CoverageClass,
    reason: []const u8,
    tracking_issue: []const u8,
};

const differential_cases = [_]DifferentialCase{
    .{ .kind = .hkdf_extract, .algorithm = .{ .hkdf = .sha256 }, .class = .positive, .rationale = "provider HKDF-Extract compared to OpenSSL EXTRACT_ONLY", .run = runHkdfExtractSha256 },
    .{ .kind = .hkdf_extract, .algorithm = .{ .hkdf = .sha384 }, .class = .positive, .rationale = "provider HKDF-Extract compared to OpenSSL EXTRACT_ONLY", .run = runHkdfExtractSha384 },
    .{ .kind = .hkdf_expand_label, .algorithm = .{ .hkdf = .sha256 }, .class = .positive, .rationale = "provider TLS HKDF-Expand-Label compared to OpenSSL EXPAND_ONLY", .run = runHkdfExpandSha256 },
    .{ .kind = .hkdf_expand_label, .algorithm = .{ .hkdf = .sha384 }, .class = .positive, .rationale = "provider TLS HKDF-Expand-Label compared to OpenSSL EXPAND_ONLY", .run = runHkdfExpandSha384 },
    .{ .kind = .tls_record_keys, .algorithm = .{ .aead = .aes_128_gcm }, .class = .positive, .rationale = "TrafficKeys.derive compared to independent OpenSSL key/iv labels", .run = runTlsRecordAes128 },
    .{ .kind = .tls_record_keys, .algorithm = .{ .aead = .aes_256_gcm }, .class = .positive, .rationale = "TrafficKeys.derive compared to independent OpenSSL key/iv labels", .run = runTlsRecordAes256 },
    .{ .kind = .tls_record_keys, .algorithm = .{ .aead = .chacha20_poly1305 }, .class = .positive, .rationale = "TrafficKeys.derive compared to independent OpenSSL key/iv labels", .run = runTlsRecordChacha20 },
    .{ .kind = .tls_key_schedule, .algorithm = .{ .hkdf = .sha256 }, .class = .positive, .rationale = "KeySchedule init/application traffic secrets compared to OpenSSL HKDF labels", .run = runTlsKeySchedule },
    .{ .kind = .quic_initial, .algorithm = .{ .aead = .aes_128_gcm }, .class = .positive, .rationale = "deriveInitialSecretsV1 compared to independent OpenSSL RFC 9001 extract/labels", .run = runQuicInitial },
    .{ .kind = .transcript_hash, .algorithm = .{ .hash = .sha256 }, .class = .positive, .rationale = "Transcript update/HRR replacement compared to OpenSSL SHA-256", .run = runTranscriptAndFinished },
    .{ .kind = .transcript_hash, .algorithm = .{ .hash = .sha256 }, .class = .negative, .rationale = "mutated handshake byte rebuilds Transcript and OpenSSL transcript hash", .run = runTranscriptAndFinished },
    .{ .kind = .finished_hmac, .algorithm = .{ .hkdf = .sha256 }, .class = .positive, .rationale = "KeySchedule Finished key and HMAC compared to independent OpenSSL HKDF/HMAC", .run = runTranscriptAndFinished },
    .{ .kind = .finished_hmac, .algorithm = .{ .hkdf = .sha256 }, .class = .negative, .rationale = "mutated transcript changes Zig and OpenSSL Finished verify_data", .run = runTranscriptAndFinished },
    .{ .kind = .aead, .algorithm = .{ .aead = .aes_128_gcm }, .class = .positive, .rationale = "provider AES-128-GCM seal/open compared to detached-tag EVP oracle", .run = runAeadAes128Positive },
    .{ .kind = .aead, .algorithm = .{ .aead = .aes_128_gcm }, .class = .negative, .rationale = "provider AES-128-GCM invalid tag/ciphertext/AAD/key handling compared to EVP oracle", .run = runAeadAes128Negative },
    .{ .kind = .aead, .algorithm = .{ .aead = .aes_256_gcm }, .class = .positive, .rationale = "provider AES-256-GCM seal/open compared to detached-tag EVP oracle", .run = runAeadAes256Positive },
    .{ .kind = .aead, .algorithm = .{ .aead = .aes_256_gcm }, .class = .negative, .rationale = "provider AES-256-GCM invalid tag/ciphertext/AAD/key handling compared to EVP oracle", .run = runAeadAes256Negative },
    .{ .kind = .aead, .algorithm = .{ .aead = .chacha20_poly1305 }, .class = .positive, .rationale = "provider ChaCha20-Poly1305 seal/open compared to detached-tag EVP oracle", .run = runAeadChacha20Positive },
    .{ .kind = .aead, .algorithm = .{ .aead = .chacha20_poly1305 }, .class = .negative, .rationale = "provider ChaCha20-Poly1305 invalid tag/ciphertext/AAD/key handling compared to EVP oracle", .run = runAeadChacha20Negative },
    .{ .kind = .key_exchange, .algorithm = .{ .group = .x25519 }, .class = .positive, .rationale = "provider raw X25519 shared secret compared to EVP oracle", .run = runX25519Positive },
    .{ .kind = .key_exchange, .algorithm = .{ .group = .x25519 }, .class = .negative, .rationale = "provider X25519 malformed and low-order peer handling compared to EVP oracle status", .run = runX25519Negative },
    .{ .kind = .signature_sign, .algorithm = .{ .signature = .ed25519 }, .class = .positive, .rationale = "provider raw Ed25519 signing compared to EVP oracle", .run = runEd25519SignPositive },
    .{ .kind = .signature_sign, .algorithm = .{ .signature = .ecdsa_secp256r1_sha256 }, .class = .positive, .rationale = "pure-Zig ECDSA-P256 signatures cross-verify with the OpenSSL EVP oracle", .run = runEcdsaP256SignPositive },
    .{ .kind = .signature_verify, .algorithm = .{ .signature = .ed25519 }, .class = .positive, .rationale = "provider raw Ed25519 verification compared to EVP oracle", .run = runEd25519VerifyPositive },
    .{ .kind = .signature_verify, .algorithm = .{ .signature = .ed25519 }, .class = .negative, .rationale = "provider raw Ed25519 invalid signature/message/key handling compared to EVP oracle", .run = runEd25519VerifyNegative },
    .{ .kind = .signature_verify, .algorithm = .{ .signature = .ecdsa_secp256r1_sha256 }, .class = .positive, .rationale = "provider SEC1 ECDSA-P256-SHA256 verification compared to EVP oracle", .run = runEcdsaP256VerifyPositive },
    .{ .kind = .signature_verify, .algorithm = .{ .signature = .ecdsa_secp256r1_sha256 }, .class = .negative, .rationale = "provider SEC1 ECDSA-P256-SHA256 malformed and invalid verification compared to EVP oracle", .run = runEcdsaP256VerifyNegative },
};

const waivers = [_]Waiver{
    .{ .kind = .psk_binder, .algorithm = .{ .hkdf = .sha256 }, .class = .negative, .reason = "Pure-Zig PSK binder generation/verification is not implemented yet.", .tracking_issue = "#362" },
    .{ .kind = .psk_binder, .algorithm = .{ .hkdf = .sha384 }, .class = .negative, .reason = "Pure-Zig PSK binder generation/verification is not implemented yet.", .tracking_issue = "#362" },
};

fn hexBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var bytes: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, hex) catch unreachable;
    return bytes;
}

fn algorithmEql(a: profile.Algorithm, b: profile.Algorithm) bool {
    return switch (a) {
        .hash => |value| b == .hash and b.hash == value,
        .hkdf => |value| b == .hkdf and b.hkdf == value,
        .aead => |value| b == .aead and b.aead == value,
        .quic_header_protection => |value| b == .quic_header_protection and b.quic_header_protection == value,
        .group => |value| b == .group and b.group == value,
        .signature => |value| b == .signature and b.signature == value,
        .certificate_helper => |value| b == .certificate_helper and b.certificate_helper == value,
        .entropy => |value| b == .entropy and b.entropy == value,
    };
}

fn hasCoverage(kind: CoverageKind, algorithm: profile.Algorithm, class: CoverageClass) bool {
    for (differential_cases) |case| {
        const case_algorithm = case.algorithm orelse continue;
        if (case.kind == kind and case.class == class and algorithmEql(case_algorithm, algorithm)) return true;
    }
    return false;
}

fn hasWaiver(kind: CoverageKind, algorithm: profile.Algorithm, class: CoverageClass) bool {
    for (waivers) |waiver| {
        if (waiver.kind == kind and waiver.class == class and algorithmEql(waiver.algorithm, algorithm)) return true;
    }
    return false;
}

fn expectCoverageOrWaiver(kind: CoverageKind, algorithm: profile.Algorithm, class: CoverageClass) !void {
    if (hasCoverage(kind, algorithm, class) or hasWaiver(kind, algorithm, class)) return;
    std.debug.print("missing OpenSSL differential coverage or waiver: kind={s} class={s} algorithm={any}\n", .{ @tagName(kind), @tagName(class), algorithm });
    return error.MissingDifferentialCoverage;
}

fn cryptoProvider() provider.CryptoProvider {
    const Holder = struct {
        var entropy = pure_zig.DeterministicEntropy.init(0x377);
        var provider_instance = pure_zig.Provider.init(entropy.entropy());
    };
    return Holder.provider_instance.cryptoProvider();
}

fn expectStage(stage: []const u8, expected: []const u8, actual: []const u8) OpenSslError!void {
    if (!std.mem.eql(u8, expected, actual)) {
        std.debug.print("OpenSSL differential mismatch at stage: {s}\n", .{stage});
        return error.DifferentialMismatch;
    }
}

fn hexAlloc(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const alphabet = "0123456789abcdef";
    const out = try allocator.alloc(u8, bytes.len * 2);
    for (bytes, 0..) |byte, index| {
        out[index * 2] = alphabet[byte >> 4];
        out[index * 2 + 1] = alphabet[byte & 0x0f];
    }
    return out;
}

fn hexDecodeAlloc(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    if ((hex.len & 1) != 0) return error.InvalidInput;
    const out = try allocator.alloc(u8, hex.len / 2);
    errdefer allocator.free(out);
    _ = std.fmt.hexToBytes(out, hex) catch return error.InvalidInput;
    return out;
}

const EvpStatus = enum {
    ok,
    auth_fail,
    malformed,
    oracle_error,
};

const EvpOracleResult = struct {
    status: EvpStatus,
    fields: [2]?[]u8 = .{ null, null },

    fn deinit(self: *EvpOracleResult, allocator: std.mem.Allocator) void {
        for (&self.fields) |*field| {
            if (field.*) |bytes| allocator.free(bytes);
            field.* = null;
        }
    }
};

fn evpStatus(raw: []const u8) ?EvpStatus {
    if (std.mem.eql(u8, raw, "ok")) return .ok;
    if (std.mem.eql(u8, raw, "auth_fail")) return .auth_fail;
    if (std.mem.eql(u8, raw, "malformed")) return .malformed;
    if (std.mem.eql(u8, raw, "oracle_error")) return .oracle_error;
    return null;
}

fn runBoundedChildRaw(allocator: std.mem.Allocator, argv: []const []const u8, stdout_limit: std.Io.Limit, stderr_limit: std.Io.Limit) ![]u8 {
    const result = try std.process.run(allocator, compat.io(), .{
        .argv = argv,
        .stdout_limit = stdout_limit,
        .stderr_limit = stderr_limit,
    });
    defer allocator.free(result.stderr);

    switch (result.term) {
        .exited => |code| if (code == 0) return result.stdout,
        else => {},
    }

    if (result.stderr.len > 0) std.debug.print("EVP oracle process failed; stderr: {s}\n", .{result.stderr});
    allocator.free(result.stdout);
    return error.EvpOracleFailed;
}

fn runEvpOracleRaw(allocator: std.mem.Allocator, args: []const []const u8) ![]u8 {
    var argv = try allocator.alloc([]const u8, args.len + 1);
    defer allocator.free(argv);
    argv[0] = diff_options.evp_oracle_path;
    for (args, 0..) |arg, i| argv[i + 1] = arg;
    return runBoundedChildRaw(allocator, argv, .limited(evp_oracle_stdout_limit), .limited(evp_oracle_stderr_limit));
}

fn runEvpOracle(allocator: std.mem.Allocator, args: []const []const u8) !EvpOracleResult {
    const stdout = try runEvpOracleRaw(allocator, args);
    defer allocator.free(stdout);
    const trimmed = std.mem.trim(u8, stdout, " \t\r\n");
    var tokens = std.mem.tokenizeScalar(u8, trimmed, ' ');
    const status_token = tokens.next() orelse return error.EvpOracleFailed;
    var parsed = EvpOracleResult{ .status = evpStatus(status_token) orelse return error.EvpOracleFailed };
    errdefer parsed.deinit(allocator);
    var index: usize = 0;
    while (tokens.next()) |token| {
        if (index >= parsed.fields.len) return error.EvpOracleFailed;
        parsed.fields[index] = try hexDecodeAlloc(allocator, token);
        index += 1;
    }
    return parsed;
}

fn expectEvpStatus(result: *const EvpOracleResult, expected: EvpStatus) !void {
    if (result.status != expected) {
        std.debug.print("unexpected EVP oracle status: expected={s} actual={s}\n", .{ @tagName(expected), @tagName(result.status) });
        return error.DifferentialMismatch;
    }
}

fn expectProviderOpenError(actual: anyerror!void, expected: anyerror) !void {
    actual catch |err| {
        try testing.expectEqual(expected, err);
        return;
    };
    return error.DifferentialMismatch;
}

fn evpAeadName(aead: provider.Aead) []const u8 {
    return switch (aead) {
        .aes_128_gcm => "aes-128-gcm",
        .aes_256_gcm => "aes-256-gcm",
        .chacha20_poly1305 => "chacha20-poly1305",
    };
}

fn runEvpAeadSeal(allocator: std.mem.Allocator, aead: provider.Aead, key: []const u8, nonce: []const u8, aad: []const u8, plaintext: []const u8) !EvpOracleResult {
    const key_hex = try hexAlloc(allocator, key);
    defer allocator.free(key_hex);
    const nonce_hex = try hexAlloc(allocator, nonce);
    defer allocator.free(nonce_hex);
    const aad_hex = try hexAlloc(allocator, aad);
    defer allocator.free(aad_hex);
    const plaintext_hex = try hexAlloc(allocator, plaintext);
    defer allocator.free(plaintext_hex);
    return runEvpOracle(allocator, &.{ "aead-seal", evpAeadName(aead), key_hex, nonce_hex, aad_hex, plaintext_hex });
}

fn runEvpAeadOpen(allocator: std.mem.Allocator, aead: provider.Aead, key: []const u8, nonce: []const u8, aad: []const u8, ciphertext: []const u8, tag: []const u8) !EvpOracleResult {
    const key_hex = try hexAlloc(allocator, key);
    defer allocator.free(key_hex);
    const nonce_hex = try hexAlloc(allocator, nonce);
    defer allocator.free(nonce_hex);
    const aad_hex = try hexAlloc(allocator, aad);
    defer allocator.free(aad_hex);
    const ciphertext_hex = try hexAlloc(allocator, ciphertext);
    defer allocator.free(ciphertext_hex);
    const tag_hex = try hexAlloc(allocator, tag);
    defer allocator.free(tag_hex);
    return runEvpOracle(allocator, &.{ "aead-open", evpAeadName(aead), key_hex, nonce_hex, aad_hex, ciphertext_hex, tag_hex });
}

fn runAeadPositive(allocator: std.mem.Allocator, aead: provider.Aead) !void {
    const cp = cryptoProvider();
    var key_storage = [_]u8{0x31} ** provider.max_aead_key_len;
    const key = key_storage[0..aead.keyLength()];
    const nonce = hexBytes("000102030405060708090a0b");
    const aad = "tls-record-header";
    const plaintext = "primitive detached tag fixture";

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [provider.aead_tag_len]u8 = undefined;
    try cp.aeadSeal(aead, key, &nonce, aad, plaintext, &ciphertext, &tag);

    var sealed = try runEvpAeadSeal(allocator, aead, key, &nonce, aad, plaintext);
    defer sealed.deinit(allocator);
    try expectEvpStatus(&sealed, .ok);
    try testing.expectEqualSlices(u8, &ciphertext, sealed.fields[0].?);
    try testing.expectEqualSlices(u8, &tag, sealed.fields[1].?);

    var opened = try runEvpAeadOpen(allocator, aead, key, &nonce, aad, &ciphertext, &tag);
    defer opened.deinit(allocator);
    try expectEvpStatus(&opened, .ok);
    try testing.expectEqualSlices(u8, plaintext, opened.fields[0].?);
}

fn runAeadNegative(allocator: std.mem.Allocator, aead: provider.Aead) !void {
    const cp = cryptoProvider();
    var key_storage = [_]u8{0x41} ** provider.max_aead_key_len;
    const key = key_storage[0..aead.keyLength()];
    const nonce = hexBytes("101112131415161718191a1b");
    const aad = "aad";
    const plaintext = "negative aead fixture";
    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [provider.aead_tag_len]u8 = undefined;
    try cp.aeadSeal(aead, key, &nonce, aad, plaintext, &ciphertext, &tag);

    var recovered: [plaintext.len]u8 = undefined;
    var bad_tag = tag;
    bad_tag[0] ^= 0x80;
    try expectProviderOpenError(cp.aeadOpen(aead, key, &nonce, aad, &ciphertext, &bad_tag, &recovered), error.AuthenticationFailed);
    var bad_tag_result = try runEvpAeadOpen(allocator, aead, key, &nonce, aad, &ciphertext, &bad_tag);
    defer bad_tag_result.deinit(allocator);
    try expectEvpStatus(&bad_tag_result, .auth_fail);

    var bad_ciphertext = ciphertext;
    bad_ciphertext[0] ^= 0x01;
    try expectProviderOpenError(cp.aeadOpen(aead, key, &nonce, aad, &bad_ciphertext, &tag, &recovered), error.AuthenticationFailed);
    var bad_cipher_result = try runEvpAeadOpen(allocator, aead, key, &nonce, aad, &bad_ciphertext, &tag);
    defer bad_cipher_result.deinit(allocator);
    try expectEvpStatus(&bad_cipher_result, .auth_fail);

    try expectProviderOpenError(cp.aeadOpen(aead, key, &nonce, "wrong", &ciphertext, &tag, &recovered), error.AuthenticationFailed);
    var bad_aad_result = try runEvpAeadOpen(allocator, aead, key, &nonce, "wrong", &ciphertext, &tag);
    defer bad_aad_result.deinit(allocator);
    try expectEvpStatus(&bad_aad_result, .auth_fail);

    var wrong_key_storage = key_storage;
    wrong_key_storage[aead.keyLength() - 1] ^= 0x55;
    const wrong_key = wrong_key_storage[0..aead.keyLength()];
    try expectProviderOpenError(cp.aeadOpen(aead, wrong_key, &nonce, aad, &ciphertext, &tag, &recovered), error.AuthenticationFailed);
    var wrong_key_result = try runEvpAeadOpen(allocator, aead, wrong_key, &nonce, aad, &ciphertext, &tag);
    defer wrong_key_result.deinit(allocator);
    try expectEvpStatus(&wrong_key_result, .auth_fail);

    const short_key = key[0 .. key.len - 1];
    try testing.expectError(error.InvalidInput, cp.aeadSeal(aead, short_key, &nonce, aad, plaintext, &ciphertext, &tag));
    var malformed = try runEvpAeadSeal(allocator, aead, short_key, &nonce, aad, plaintext);
    defer malformed.deinit(allocator);
    try expectEvpStatus(&malformed, .malformed);

    const too_large = try allocator.alloc(u8, 4097);
    defer allocator.free(too_large);
    @memset(too_large, 0xaa);
    var bounded = try runEvpAeadSeal(allocator, aead, key, &nonce, aad, too_large);
    defer bounded.deinit(allocator);
    try expectEvpStatus(&bounded, .malformed);
}

fn runAeadAes128Positive(allocator: std.mem.Allocator) !void {
    try runAeadPositive(allocator, .aes_128_gcm);
}
fn runAeadAes128Negative(allocator: std.mem.Allocator) !void {
    try runAeadNegative(allocator, .aes_128_gcm);
}
fn runAeadAes256Positive(allocator: std.mem.Allocator) !void {
    try runAeadPositive(allocator, .aes_256_gcm);
}
fn runAeadAes256Negative(allocator: std.mem.Allocator) !void {
    try runAeadNegative(allocator, .aes_256_gcm);
}
fn runAeadChacha20Positive(allocator: std.mem.Allocator) !void {
    try runAeadPositive(allocator, .chacha20_poly1305);
}
fn runAeadChacha20Negative(allocator: std.mem.Allocator) !void {
    try runAeadNegative(allocator, .chacha20_poly1305);
}

fn runEvpX25519(allocator: std.mem.Allocator, private_scalar: []const u8, peer_public: []const u8) !EvpOracleResult {
    const private_hex = try hexAlloc(allocator, private_scalar);
    defer allocator.free(private_hex);
    const public_hex = try hexAlloc(allocator, peer_public);
    defer allocator.free(public_hex);
    return runEvpOracle(allocator, &.{ "x25519", private_hex, public_hex });
}

fn runX25519Positive(allocator: std.mem.Allocator) !void {
    const cp = cryptoProvider();
    const alice_private = hexBytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    const bob_public = hexBytes("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    const expected_shared = hexBytes("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    var shared: [X25519.shared_length]u8 = undefined;
    try cp.deriveSharedSecret(.x25519, &alice_private, &bob_public, &shared);
    try expectStage("x25519 shared secret / RFC 7748", &expected_shared, &shared);

    var oracle = try runEvpX25519(allocator, &alice_private, &bob_public);
    defer oracle.deinit(allocator);
    try expectEvpStatus(&oracle, .ok);
    try testing.expectEqualSlices(u8, &shared, oracle.fields[0].?);
}

fn runX25519Negative(allocator: std.mem.Allocator) !void {
    const cp = cryptoProvider();
    const alice_private = hexBytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    const zero_point = [_]u8{0} ** X25519.public_length;
    var shared: [X25519.shared_length]u8 = undefined;
    try testing.expectError(error.InvalidInput, cp.deriveSharedSecret(.x25519, &alice_private, &zero_point, &shared));
    var low_order = try runEvpX25519(allocator, &alice_private, &zero_point);
    defer low_order.deinit(allocator);
    try expectEvpStatus(&low_order, .auth_fail);

    try testing.expectError(error.InvalidInput, cp.deriveSharedSecret(.x25519, alice_private[0..31], &zero_point, &shared));
    var malformed = try runEvpX25519(allocator, alice_private[0..31], &zero_point);
    defer malformed.deinit(allocator);
    try expectEvpStatus(&malformed, .malformed);
}

fn runEvpEd25519Sign(allocator: std.mem.Allocator, seed: []const u8, message: []const u8) !EvpOracleResult {
    const seed_hex = try hexAlloc(allocator, seed);
    defer allocator.free(seed_hex);
    const message_hex = try hexAlloc(allocator, message);
    defer allocator.free(message_hex);
    return runEvpOracle(allocator, &.{ "ed25519-sign", seed_hex, message_hex });
}

fn runEvpEd25519Verify(allocator: std.mem.Allocator, public_key: []const u8, message: []const u8, signature: []const u8) !EvpOracleResult {
    const public_hex = try hexAlloc(allocator, public_key);
    defer allocator.free(public_hex);
    const message_hex = try hexAlloc(allocator, message);
    defer allocator.free(message_hex);
    const signature_hex = try hexAlloc(allocator, signature);
    defer allocator.free(signature_hex);
    return runEvpOracle(allocator, &.{ "ed25519-verify", public_hex, message_hex, signature_hex });
}

fn runEd25519SignPositive(allocator: std.mem.Allocator) !void {
    const cp = cryptoProvider();
    const seed = hexBytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    const expected_public = hexBytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    const message = "";
    var key = try pure_zig.SoftwareSigningKey.fromSeed(seed);
    defer key.deinit();
    const actual_public = key.publicKey();
    try expectStage("ed25519 public key / RFC 8032", &expected_public, &actual_public);
    var signature: [Ed25519.Signature.encoded_length]u8 = undefined;
    const len = try key.signingKey().sign(message, cp.entropy, &signature);
    try testing.expectEqual(@as(usize, Ed25519.Signature.encoded_length), len);

    var oracle = try runEvpEd25519Sign(allocator, &seed, message);
    defer oracle.deinit(allocator);
    try expectEvpStatus(&oracle, .ok);
    try testing.expectEqualSlices(u8, &signature, oracle.fields[0].?);
}

fn runEd25519VerifyPositive(allocator: std.mem.Allocator) !void {
    const cp = cryptoProvider();
    const public_key = hexBytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    const signature = hexBytes("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
    try cp.verify(.ed25519, &public_key, "", &signature);
    var oracle = try runEvpEd25519Verify(allocator, &public_key, "", &signature);
    defer oracle.deinit(allocator);
    try expectEvpStatus(&oracle, .ok);
}

fn runEd25519VerifyNegative(allocator: std.mem.Allocator) !void {
    const cp = cryptoProvider();
    const seed = hexBytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    const public_key = hexBytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    const signature = hexBytes("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");

    var bad_signature = signature;
    bad_signature[0] ^= 0x80;
    try testing.expectError(error.AuthenticationFailed, cp.verify(.ed25519, &public_key, "", &bad_signature));
    var bad_sig_oracle = try runEvpEd25519Verify(allocator, &public_key, "", &bad_signature);
    defer bad_sig_oracle.deinit(allocator);
    try expectEvpStatus(&bad_sig_oracle, .auth_fail);

    try testing.expectError(error.AuthenticationFailed, cp.verify(.ed25519, &public_key, "mutated", &signature));
    var bad_msg_oracle = try runEvpEd25519Verify(allocator, &public_key, "mutated", &signature);
    defer bad_msg_oracle.deinit(allocator);
    try expectEvpStatus(&bad_msg_oracle, .auth_fail);

    var wrong_key = public_key;
    wrong_key[0] ^= 0x01;
    try testing.expectError(error.AuthenticationFailed, cp.verify(.ed25519, &wrong_key, "", &signature));
    var wrong_key_oracle = try runEvpEd25519Verify(allocator, &wrong_key, "", &signature);
    defer wrong_key_oracle.deinit(allocator);
    try expectEvpStatus(&wrong_key_oracle, .auth_fail);

    try testing.expectError(error.InvalidInput, cp.verify(.ed25519, public_key[0..31], "", &signature));
    var malformed = try runEvpEd25519Verify(allocator, public_key[0..31], "", &signature);
    defer malformed.deinit(allocator);
    try expectEvpStatus(&malformed, .malformed);

    const seed_hex = try hexAlloc(allocator, &seed);
    defer allocator.free(seed_hex);
    const raw = try runEvpOracleRaw(allocator, &.{ "ed25519-sign", seed_hex[0..62], "" });
    defer allocator.free(raw);
    try testing.expect(!std.mem.containsAtLeast(u8, raw, 1, seed_hex));
}

fn runEvpEcdsaP256Verify(allocator: std.mem.Allocator, public_key: []const u8, message: []const u8, signature: []const u8) !EvpOracleResult {
    const public_hex = try hexAlloc(allocator, public_key);
    defer allocator.free(public_hex);
    const message_hex = try hexAlloc(allocator, message);
    defer allocator.free(message_hex);
    const signature_hex = try hexAlloc(allocator, signature);
    defer allocator.free(signature_hex);
    return runEvpOracle(allocator, &.{ "ecdsa-p256-verify", public_hex, message_hex, signature_hex });
}

fn runEvpEcdsaP256Sign(allocator: std.mem.Allocator, private_scalar: []const u8, message: []const u8) !EvpOracleResult {
    const private_hex = try hexAlloc(allocator, private_scalar);
    defer allocator.free(private_hex);
    const message_hex = try hexAlloc(allocator, message);
    defer allocator.free(message_hex);
    return runEvpOracle(allocator, &.{ "ecdsa-p256-sign", private_hex, message_hex });
}

fn readDerLen(bytes: []const u8, pos: *usize) !usize {
    if (pos.* >= bytes.len) return error.InvalidDer;
    const first = bytes[pos.*];
    pos.* += 1;
    if (first < 0x80) return first;
    const len_len = first & 0x7f;
    if (len_len == 0 or len_len > 2 or pos.* + len_len > bytes.len) return error.InvalidDer;
    if (bytes[pos.*] == 0) return error.InvalidDer;
    var len: usize = 0;
    for (0..len_len) |_| {
        len = (len << 8) | bytes[pos.*];
        pos.* += 1;
    }
    if (len < 0x80) return error.InvalidDer;
    return len;
}

fn readDerInteger32(der: []const u8, pos: *usize) ![32]u8 {
    if (pos.* >= der.len or der[pos.*] != 0x02) return error.InvalidDer;
    pos.* += 1;
    const len = try readDerLen(der, pos);
    if (len == 0 or len > 33 or pos.* + len > der.len) return error.InvalidDer;
    const int_bytes = der[pos.*..][0..len];
    pos.* += len;

    if (int_bytes[0] & 0x80 != 0) return error.InvalidDer;
    if (len > 1 and int_bytes[0] == 0 and int_bytes[1] & 0x80 == 0) return error.InvalidDer;

    const unsigned = if (len == 33) blk: {
        if (int_bytes[0] != 0) return error.InvalidDer;
        break :blk int_bytes[1..];
    } else int_bytes;
    var out = [_]u8{0} ** 32;
    @memcpy(out[32 - unsigned.len ..], unsigned);
    var non_zero: u8 = 0;
    for (out) |byte| non_zero |= byte;
    if (non_zero == 0) return error.InvalidDer;
    _ = P256Scalar.fromBytes(out, .big) catch return error.InvalidDer;
    return out;
}

fn expectCanonicalEcdsaP256Der(der: []const u8) !void {
    var pos: usize = 0;
    if (der.len == 0 or der[pos] != 0x30) return error.InvalidDer;
    pos += 1;
    const seq_len = try readDerLen(der, &pos);
    if (seq_len != der.len - pos) return error.InvalidDer;
    _ = try readDerInteger32(der, &pos);
    _ = try readDerInteger32(der, &pos);
    if (pos != der.len) return error.InvalidDer;
}

fn expectEcdsaP256Rejects(allocator: std.mem.Allocator, cp: provider.CryptoProvider, public_key: []const u8, message: []const u8, signature: []const u8, expected_native: anyerror, expected_oracle: EvpStatus) !void {
    try testing.expectError(expected_native, cp.verify(.ecdsa_secp256r1_sha256, public_key, message, signature));
    var oracle = try runEvpEcdsaP256Verify(allocator, public_key, message, signature);
    defer oracle.deinit(allocator);
    try expectEvpStatus(&oracle, expected_oracle);
}

fn expectEcdsaP256AcceptsBoth(allocator: std.mem.Allocator, cp: provider.CryptoProvider, public_key: []const u8, message: []const u8, signature: []const u8) !void {
    try cp.verify(.ecdsa_secp256r1_sha256, public_key, message, signature);
    var oracle = try runEvpEcdsaP256Verify(allocator, public_key, message, signature);
    defer oracle.deinit(allocator);
    try expectEvpStatus(&oracle, .ok);
}

fn runEcdsaP256SignPositive(allocator: std.mem.Allocator) !void {
    const cp = cryptoProvider();
    const private_scalar = hexBytes("519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacb259e1aa2c4ad49d");
    const message = "ecdsa p256 signing differential fixture";

    var native_key = try pure_zig.SoftwareEcdsaP256SigningKey.fromScalarBytes(&private_scalar);
    defer native_key.deinit();
    const public_key = native_key.publicKeySec1();
    const signer = native_key.signingKey();
    try testing.expectEqual(provider.SignatureScheme.ecdsa_secp256r1_sha256, signer.scheme());

    var native_entropy = pure_zig.DeterministicEntropy.init(0x433);
    var native_signature: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
    const native_len = try signer.sign(message, native_entropy.entropy(), &native_signature);
    const native_der = native_signature[0..native_len];
    try expectCanonicalEcdsaP256Der(native_der);

    var oracle_sign = try runEvpEcdsaP256Sign(allocator, &private_scalar, message);
    defer oracle_sign.deinit(allocator);
    try expectEvpStatus(&oracle_sign, .ok);
    const oracle_der = oracle_sign.fields[0].?;
    const oracle_public = oracle_sign.fields[1].?;
    try testing.expectEqualSlices(u8, &public_key, oracle_public);
    try expectCanonicalEcdsaP256Der(oracle_der);

    try expectEcdsaP256AcceptsBoth(allocator, cp, &public_key, message, native_der);
    try expectEcdsaP256AcceptsBoth(allocator, cp, &public_key, message, oracle_der);

    try expectEcdsaP256Rejects(allocator, cp, &public_key, "mutated message", native_der, error.AuthenticationFailed, .auth_fail);
    try expectEcdsaP256Rejects(allocator, cp, &public_key, "mutated message", oracle_der, error.AuthenticationFailed, .auth_fail);

    var wrong_key_owner = try pure_zig.SoftwareEcdsaP256SigningKey.fromSeed([_]u8{0x77} ** 32);
    defer wrong_key_owner.deinit();
    const wrong_key = wrong_key_owner.publicKeySec1();
    try expectEcdsaP256Rejects(allocator, cp, &wrong_key, message, native_der, error.AuthenticationFailed, .auth_fail);
    try expectEcdsaP256Rejects(allocator, cp, &wrong_key, message, oracle_der, error.AuthenticationFailed, .auth_fail);

    var modified_sig = try allocator.dupe(u8, native_der);
    defer allocator.free(modified_sig);
    modified_sig[modified_sig.len - 1] ^= 0x01;
    try expectEcdsaP256Rejects(allocator, cp, &public_key, message, modified_sig, error.AuthenticationFailed, .auth_fail);

    const malformed_der = [_]u8{0x30};
    try expectEcdsaP256Rejects(allocator, cp, &public_key, message, &malformed_der, error.AuthenticationFailed, .malformed);

    const zero_r_der = hexBytes("3006020100020101");
    try expectEcdsaP256Rejects(allocator, cp, &public_key, message, &zero_r_der, error.AuthenticationFailed, .auth_fail);

    const zero_s_der = hexBytes("3006020101020100");
    try expectEcdsaP256Rejects(allocator, cp, &public_key, message, &zero_s_der, error.AuthenticationFailed, .auth_fail);

    const order_r_der = hexBytes("3026022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551020101");
    try testing.expectError(error.InvalidDer, expectCanonicalEcdsaP256Der(&order_r_der));
    try expectEcdsaP256Rejects(allocator, cp, &public_key, message, &order_r_der, error.AuthenticationFailed, .auth_fail);

    const order_s_der = hexBytes("3026020101022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    try testing.expectError(error.InvalidDer, expectCanonicalEcdsaP256Der(&order_s_der));
    try expectEcdsaP256Rejects(allocator, cp, &public_key, message, &order_s_der, error.AuthenticationFailed, .auth_fail);

    const non_canonical_der = hexBytes("300702020001020101");
    try testing.expectError(error.InvalidDer, expectCanonicalEcdsaP256Der(&non_canonical_der));
    try expectEcdsaP256Rejects(allocator, cp, &public_key, message, &non_canonical_der, error.AuthenticationFailed, .malformed);

    const non_minimal_len_der = hexBytes("308106020101020101");
    try testing.expectError(error.InvalidDer, expectCanonicalEcdsaP256Der(&non_minimal_len_der));
    try expectEcdsaP256Rejects(allocator, cp, &public_key, message, &non_minimal_len_der, error.AuthenticationFailed, .malformed);

    const malformed_key = [_]u8{0x04};
    try expectEcdsaP256Rejects(allocator, cp, &malformed_key, message, native_der, error.InvalidInput, .malformed);
}

fn runEcdsaP256VerifyPositive(allocator: std.mem.Allocator) !void {
    const cp = cryptoProvider();
    const public_key = hexBytes("042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e");
    const message = hexBytes("313233343030");
    const signature = hexBytes("304502202ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18022100b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db");
    try cp.verify(.ecdsa_secp256r1_sha256, &public_key, &message, &signature);
    var oracle = try runEvpEcdsaP256Verify(allocator, &public_key, &message, &signature);
    defer oracle.deinit(allocator);
    try expectEvpStatus(&oracle, .ok);
}

fn runEcdsaP256VerifyNegative(allocator: std.mem.Allocator) !void {
    const cp = cryptoProvider();
    const public_key = hexBytes("042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e");
    const message = hexBytes("313233343030");
    const signature = hexBytes("304502202ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18022100b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db");

    try testing.expectError(error.AuthenticationFailed, cp.verify(.ecdsa_secp256r1_sha256, &public_key, "wrong", &signature));
    var bad_message = try runEvpEcdsaP256Verify(allocator, &public_key, "wrong", &signature);
    defer bad_message.deinit(allocator);
    try expectEvpStatus(&bad_message, .auth_fail);

    var bad_sig = signature;
    bad_sig[bad_sig.len - 1] ^= 0x01;
    try testing.expectError(error.AuthenticationFailed, cp.verify(.ecdsa_secp256r1_sha256, &public_key, &message, &bad_sig));
    var bad_sig_oracle = try runEvpEcdsaP256Verify(allocator, &public_key, &message, &bad_sig);
    defer bad_sig_oracle.deinit(allocator);
    try expectEvpStatus(&bad_sig_oracle, .auth_fail);

    var wrong_key_owner = try pure_zig.SoftwareEcdsaP256SigningKey.fromSeed([_]u8{0x77} ** 32);
    defer wrong_key_owner.deinit();
    const wrong_key = wrong_key_owner.publicKeySec1();
    try testing.expectError(error.AuthenticationFailed, cp.verify(.ecdsa_secp256r1_sha256, &wrong_key, &message, &signature));
    var wrong_key_oracle = try runEvpEcdsaP256Verify(allocator, &wrong_key, &message, &signature);
    defer wrong_key_oracle.deinit(allocator);
    try expectEvpStatus(&wrong_key_oracle, .auth_fail);

    const malformed_key = [_]u8{0x04};
    try testing.expectError(error.InvalidInput, cp.verify(.ecdsa_secp256r1_sha256, &malformed_key, &message, &signature));
    var malformed_key_oracle = try runEvpEcdsaP256Verify(allocator, &malformed_key, &message, &signature);
    defer malformed_key_oracle.deinit(allocator);
    try expectEvpStatus(&malformed_key_oracle, .malformed);

    const malformed_sig = [_]u8{0x30};
    try testing.expectError(error.AuthenticationFailed, cp.verify(.ecdsa_secp256r1_sha256, &public_key, &message, &malformed_sig));
    var malformed_sig_oracle = try runEvpEcdsaP256Verify(allocator, &public_key, &message, &malformed_sig);
    defer malformed_sig_oracle.deinit(allocator);
    try expectEvpStatus(&malformed_sig_oracle, .malformed);
}

fn tlsHkdfLabel(allocator: std.mem.Allocator, out_len: usize, label: []const u8, context: []const u8) ![]u8 {
    const prefix = "tls13 ";
    const full_label_len = prefix.len + label.len;
    if (out_len > std.math.maxInt(u16) or full_label_len > std.math.maxInt(u8) or context.len > std.math.maxInt(u8)) {
        return error.InvalidInput;
    }

    const encoded = try allocator.alloc(u8, 2 + 1 + full_label_len + 1 + context.len);
    encoded[0] = @intCast((out_len >> 8) & 0xff);
    encoded[1] = @intCast(out_len & 0xff);
    encoded[2] = @intCast(full_label_len);
    @memcpy(encoded[3..][0..prefix.len], prefix);
    @memcpy(encoded[3 + prefix.len ..][0..label.len], label);
    const context_len_offset = 3 + full_label_len;
    encoded[context_len_offset] = @intCast(context.len);
    @memcpy(encoded[context_len_offset + 1 ..][0..context.len], context);
    return encoded;
}

fn runOpenSslProbe(allocator: std.mem.Allocator, argv: []const []const u8) !bool {
    const result = std.process.run(allocator, compat.io(), .{
        .argv = argv,
        .stdout_limit = .limited(64 * 1024),
        .stderr_limit = .limited(64 * 1024),
    }) catch return false;
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    return switch (result.term) {
        .exited => |code| code == 0,
        else => false,
    };
}

fn runOpenSslOutputProbe(allocator: std.mem.Allocator, argv: []const []const u8, expected: []const u8) !bool {
    const result = std.process.run(allocator, compat.io(), .{
        .argv = argv,
        .stdout_limit = .limited(64 * 1024),
        .stderr_limit = .limited(64 * 1024),
    }) catch return false;
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    switch (result.term) {
        .exited => |code| if (code != 0) return false,
        else => return false,
    }
    return std.mem.eql(u8, expected, result.stdout);
}

fn opensslMatchesHkdfOracle(allocator: std.mem.Allocator, path: []const u8) !bool {
    if (!try runOpenSslProbe(allocator, &.{ path, "kdf", "-help" })) return false;
    return runOpenSslOutputProbe(
        allocator,
        &.{
            path,
            "kdf",
            "-keylen",
            "42",
            "-binary",
            "-kdfopt",
            "digest:SHA256",
            "-kdfopt",
            "mode:EXPAND_ONLY",
            "-kdfopt",
            "hexkey:077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
            "-kdfopt",
            "hexinfo:002a0d746c73313320646572697665640af0f1f2f3f4f5f6f7f8f9",
            "HKDF",
        },
        &hexBytes("e29ebe58889156b196d8f9c31e3a4658a71eabdc113c50e4bf9d7a97ed3af464e6286979f53caa6fba0c"),
    );
}

const OpenSslBinary = struct {
    path: []const u8,
    owned: bool = false,

    fn deinit(self: OpenSslBinary, allocator: std.mem.Allocator) void {
        if (self.owned) allocator.free(self.path);
    }
};

fn opensslBinary(allocator: std.mem.Allocator) !OpenSslBinary {
    if (compat.getEnvVarOwned(allocator, "OPENSSL_BIN")) |path| {
        if (try opensslMatchesHkdfOracle(allocator, path)) return .{ .path = path, .owned = true };
        allocator.free(path);
    } else |_| {}

    const candidates = [_][]const u8{
        "/opt/homebrew/opt/openssl@3/bin/openssl",
        "/usr/local/opt/openssl@3/bin/openssl",
        "/opt/homebrew/bin/openssl",
        "/usr/local/bin/openssl",
        "openssl",
    };
    for (candidates) |candidate| {
        if (try opensslMatchesHkdfOracle(allocator, candidate)) {
            return .{ .path = candidate };
        }
    }
    return error.MissingOpenSslKdfOracle;
}

fn runOpenSsl(allocator: std.mem.Allocator, stage: []const u8, argv: []const []const u8) ![]u8 {
    const result = try std.process.run(allocator, compat.io(), .{
        .argv = argv,
        .stdout_limit = .limited(1024 * 1024),
        .stderr_limit = .limited(1024 * 1024),
    });
    defer allocator.free(result.stderr);

    switch (result.term) {
        .exited => |code| if (code == 0) return result.stdout,
        else => {},
    }

    std.debug.print("OpenSSL oracle failed at stage: {s}; stderr: {s}\n", .{ stage, result.stderr });
    allocator.free(result.stdout);
    return error.OpenSslOracleFailed;
}

fn opensslHkdfExtract(
    allocator: std.mem.Allocator,
    stage: []const u8,
    hash: provider.Hash,
    salt: []const u8,
    ikm: []const u8,
) ![]u8 {
    const salt_hex = try hexAlloc(allocator, salt);
    defer allocator.free(salt_hex);
    const ikm_hex = try hexAlloc(allocator, ikm);
    defer allocator.free(ikm_hex);
    const salt_opt = try std.fmt.allocPrint(allocator, "hexsalt:{s}", .{salt_hex});
    defer allocator.free(salt_opt);
    const key_opt = try std.fmt.allocPrint(allocator, "hexkey:{s}", .{ikm_hex});
    defer allocator.free(key_opt);
    const key_len = try std.fmt.allocPrint(allocator, "{d}", .{hash.digestLength()});
    defer allocator.free(key_len);
    const digest = switch (hash) {
        .sha256 => "digest:SHA256",
        .sha384 => "digest:SHA384",
    };
    const openssl = try opensslBinary(allocator);
    defer openssl.deinit(allocator);

    return runOpenSsl(allocator, stage, &.{
        openssl.path,
        "kdf",
        "-keylen",
        key_len,
        "-binary",
        "-kdfopt",
        digest,
        "-kdfopt",
        "mode:EXTRACT_ONLY",
        "-kdfopt",
        salt_opt,
        "-kdfopt",
        key_opt,
        "HKDF",
    });
}

fn opensslHkdfExpandLabel(
    allocator: std.mem.Allocator,
    stage: []const u8,
    hash: provider.Hash,
    secret: []const u8,
    label: []const u8,
    context: []const u8,
    out_len: usize,
) ![]u8 {
    const secret_hex = try hexAlloc(allocator, secret);
    defer allocator.free(secret_hex);
    const info = try tlsHkdfLabel(allocator, out_len, label, context);
    defer allocator.free(info);
    const info_hex = try hexAlloc(allocator, info);
    defer allocator.free(info_hex);
    const key_opt = try std.fmt.allocPrint(allocator, "hexkey:{s}", .{secret_hex});
    defer allocator.free(key_opt);
    const info_opt = try std.fmt.allocPrint(allocator, "hexinfo:{s}", .{info_hex});
    defer allocator.free(info_opt);
    const key_len = try std.fmt.allocPrint(allocator, "{d}", .{out_len});
    defer allocator.free(key_len);
    const digest = switch (hash) {
        .sha256 => "digest:SHA256",
        .sha384 => "digest:SHA384",
    };
    const openssl = try opensslBinary(allocator);
    defer openssl.deinit(allocator);

    return runOpenSsl(allocator, stage, &.{
        openssl.path,
        "kdf",
        "-keylen",
        key_len,
        "-binary",
        "-kdfopt",
        digest,
        "-kdfopt",
        "mode:EXPAND_ONLY",
        "-kdfopt",
        key_opt,
        "-kdfopt",
        info_opt,
        "HKDF",
    });
}

fn opensslSha256File(allocator: std.mem.Allocator, stage: []const u8, path: []const u8) ![]u8 {
    const openssl = try opensslBinary(allocator);
    defer openssl.deinit(allocator);
    return runOpenSsl(allocator, stage, &.{ openssl.path, "dgst", "-sha256", "-binary", path });
}

fn expectOpenSslSha256File(allocator: std.mem.Allocator, stage: []const u8, expected: []const u8, path: []const u8) !void {
    const actual = try opensslSha256File(allocator, stage, path);
    defer allocator.free(actual);
    try expectStage(stage, expected, actual);
}

fn opensslHmacSha256File(
    allocator: std.mem.Allocator,
    stage: []const u8,
    key: []const u8,
    path: []const u8,
) ![]u8 {
    const key_hex = try hexAlloc(allocator, key);
    defer allocator.free(key_hex);
    const key_opt = try std.fmt.allocPrint(allocator, "hexkey:{s}", .{key_hex});
    defer allocator.free(key_opt);
    const openssl = try opensslBinary(allocator);
    defer openssl.deinit(allocator);
    return runOpenSsl(allocator, stage, &.{
        openssl.path,
        "dgst",
        "-sha256",
        "-mac",
        "HMAC",
        "-macopt",
        key_opt,
        "-binary",
        path,
    });
}

const TlsRecordOracleParams = struct {
    hash: provider.Hash,
    key_len: usize,
    iv_len: usize,
};

fn tlsRecordOracleParams(suite: tls_core.algorithms.CipherSuite) TlsRecordOracleParams {
    return switch (suite) {
        .tls_aes_128_gcm_sha256 => .{ .hash = .sha256, .key_len = 16, .iv_len = 12 },
        .tls_aes_256_gcm_sha384 => .{ .hash = .sha384, .key_len = 32, .iv_len = 12 },
        .tls_chacha20_poly1305_sha256 => .{ .hash = .sha256, .key_len = 32, .iv_len = 12 },
    };
}

fn expectTlsTrafficKeys(
    allocator: std.mem.Allocator,
    stage: []const u8,
    cp: provider.CryptoProvider,
    suite: tls_core.algorithms.CipherSuite,
    traffic_secret: []const u8,
) !void {
    const record_protection = tls_core.record_protection;
    const params = tlsRecordOracleParams(suite);
    var keys = try record_protection.TrafficKeys.derive(cp, suite, traffic_secret);
    defer keys.deinit();

    try testing.expectEqual(params.key_len, keys.key.slice().len);
    try testing.expectEqual(params.iv_len, keys.iv.slice().len);

    const openssl_key = try opensslHkdfExpandLabel(allocator, stage, params.hash, traffic_secret, "key", "", params.key_len);
    defer allocator.free(openssl_key);
    try expectStage(stage, keys.key.slice(), openssl_key);

    const iv_stage = try std.fmt.allocPrint(allocator, "{s} iv", .{stage});
    defer allocator.free(iv_stage);
    const openssl_iv = try opensslHkdfExpandLabel(allocator, iv_stage, params.hash, traffic_secret, "iv", "", params.iv_len);
    defer allocator.free(openssl_iv);
    try expectStage(iv_stage, keys.iv.slice(), openssl_iv);
}

fn runHkdfAndTlsRecordDerivations(allocator: std.mem.Allocator) !void {
    const cp = cryptoProvider();

    const ikm = hexBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    const salt = hexBytes("000102030405060708090a0b0c");
    var prk: [provider.Hash.sha256.digestLength()]u8 = undefined;
    try cp.hkdfExtract(.sha256, &salt, &ikm, &prk);
    const openssl_prk = try opensslHkdfExtract(allocator, "hkdf extract sha256 / RFC 5869 A.1", .sha256, &salt, &ikm);
    defer allocator.free(openssl_prk);
    try expectStage("hkdf extract sha256 / RFC 5869 A.1", &prk, openssl_prk);

    const context = hexBytes("f0f1f2f3f4f5f6f7f8f9");
    var pure_sha256: [42]u8 = undefined;
    try cp.hkdfExpandLabel(.sha256, &prk, "derived", &context, &pure_sha256);
    const openssl_sha256 = try opensslHkdfExpandLabel(allocator, "hkdf expand-label sha256 / TLS derived", .sha256, &prk, "derived", &context, pure_sha256.len);
    defer allocator.free(openssl_sha256);
    try expectStage("hkdf expand-label sha256 / TLS derived", &pure_sha256, openssl_sha256);

    const secret384 = [_]u8{0x42} ** provider.Hash.sha384.digestLength();
    var prk384: [provider.Hash.sha384.digestLength()]u8 = undefined;
    try cp.hkdfExtract(.sha384, &secret384, &ikm, &prk384);
    const openssl_prk384 = try opensslHkdfExtract(allocator, "hkdf extract sha384 / fixed fixture", .sha384, &secret384, &ikm);
    defer allocator.free(openssl_prk384);
    try expectStage("hkdf extract sha384 / fixed fixture", &prk384, openssl_prk384);

    var pure_sha384: [48]u8 = undefined;
    try cp.hkdfExpandLabel(.sha384, &secret384, "c hs traffic", "", &pure_sha384);
    const openssl_sha384 = try opensslHkdfExpandLabel(allocator, "hkdf expand-label sha384 / client handshake traffic", .sha384, &secret384, "c hs traffic", "", pure_sha384.len);
    defer allocator.free(openssl_sha384);
    try expectStage("hkdf expand-label sha384 / client handshake traffic", &pure_sha384, openssl_sha384);

    const tls_record_secret = hexBytes("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
    try expectTlsTrafficKeys(allocator, "tls record aes128 key", cp, .tls_aes_128_gcm_sha256, &tls_record_secret);
    try expectTlsTrafficKeys(allocator, "tls record aes256 key", cp, .tls_aes_256_gcm_sha384, &secret384);

    const chacha_secret = [_]u8{0x33} ** provider.Hash.sha256.digestLength();
    try expectTlsTrafficKeys(allocator, "tls record chacha20 key", cp, .tls_chacha20_poly1305_sha256, &chacha_secret);
}

fn runHkdfExtractSha256(allocator: std.mem.Allocator) !void {
    const cp = cryptoProvider();
    const ikm = hexBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    const salt = hexBytes("000102030405060708090a0b0c");
    var prk: [provider.Hash.sha256.digestLength()]u8 = undefined;
    try cp.hkdfExtract(.sha256, &salt, &ikm, &prk);
    const openssl_prk = try opensslHkdfExtract(allocator, "hkdf extract sha256 / RFC 5869 A.1", .sha256, &salt, &ikm);
    defer allocator.free(openssl_prk);
    try expectStage("hkdf extract sha256 / RFC 5869 A.1", &prk, openssl_prk);
}

fn runHkdfExtractSha384(allocator: std.mem.Allocator) !void {
    const cp = cryptoProvider();
    const ikm = hexBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    const secret384 = [_]u8{0x42} ** provider.Hash.sha384.digestLength();
    var prk384: [provider.Hash.sha384.digestLength()]u8 = undefined;
    try cp.hkdfExtract(.sha384, &secret384, &ikm, &prk384);
    const openssl_prk384 = try opensslHkdfExtract(allocator, "hkdf extract sha384 / fixed fixture", .sha384, &secret384, &ikm);
    defer allocator.free(openssl_prk384);
    try expectStage("hkdf extract sha384 / fixed fixture", &prk384, openssl_prk384);
}

fn runHkdfExpandSha256(allocator: std.mem.Allocator) !void {
    const cp = cryptoProvider();
    const ikm = hexBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    const salt = hexBytes("000102030405060708090a0b0c");
    var prk: [provider.Hash.sha256.digestLength()]u8 = undefined;
    try cp.hkdfExtract(.sha256, &salt, &ikm, &prk);
    const context = hexBytes("f0f1f2f3f4f5f6f7f8f9");
    var pure_sha256: [42]u8 = undefined;
    try cp.hkdfExpandLabel(.sha256, &prk, "derived", &context, &pure_sha256);
    const openssl_sha256 = try opensslHkdfExpandLabel(allocator, "hkdf expand-label sha256 / TLS derived", .sha256, &prk, "derived", &context, pure_sha256.len);
    defer allocator.free(openssl_sha256);
    try expectStage("hkdf expand-label sha256 / TLS derived", &pure_sha256, openssl_sha256);
}

fn runHkdfExpandSha384(allocator: std.mem.Allocator) !void {
    const cp = cryptoProvider();
    const secret384 = [_]u8{0x42} ** provider.Hash.sha384.digestLength();
    var pure_sha384: [48]u8 = undefined;
    try cp.hkdfExpandLabel(.sha384, &secret384, "c hs traffic", "", &pure_sha384);
    const openssl_sha384 = try opensslHkdfExpandLabel(allocator, "hkdf expand-label sha384 / client handshake traffic", .sha384, &secret384, "c hs traffic", "", pure_sha384.len);
    defer allocator.free(openssl_sha384);
    try expectStage("hkdf expand-label sha384 / client handshake traffic", &pure_sha384, openssl_sha384);
}

fn runTlsRecordAes128(allocator: std.mem.Allocator) !void {
    const cp = cryptoProvider();
    const tls_record_secret = hexBytes("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
    try expectTlsTrafficKeys(allocator, "tls record aes128 key", cp, .tls_aes_128_gcm_sha256, &tls_record_secret);
}

fn runTlsRecordAes256(allocator: std.mem.Allocator) !void {
    const cp = cryptoProvider();
    const secret384 = [_]u8{0x42} ** provider.Hash.sha384.digestLength();
    try expectTlsTrafficKeys(allocator, "tls record aes256 key", cp, .tls_aes_256_gcm_sha384, &secret384);
}

fn runTlsRecordChacha20(allocator: std.mem.Allocator) !void {
    const cp = cryptoProvider();
    const chacha_secret = [_]u8{0x33} ** provider.Hash.sha256.digestLength();
    try expectTlsTrafficKeys(allocator, "tls record chacha20 key", cp, .tls_chacha20_poly1305_sha256, &chacha_secret);
}

fn runTlsKeySchedule(allocator: std.mem.Allocator) !void {
    const KeySchedule = tls_core.key_schedule.KeySchedule;
    const cp = cryptoProvider();
    const shared = hexBytes("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
    const hello_hash = hexBytes("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");
    var schedule = try KeySchedule.init(cp, &shared, hello_hash);
    defer schedule.wipe();

    const zero = [_]u8{0} ** provider.Hash.sha256.digestLength();
    const empty_hash = hexBytes("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    const early_secret = try opensslHkdfExtract(allocator, "tls13 early secret", .sha256, "", &zero);
    defer allocator.free(early_secret);
    const derived_from_early = try opensslHkdfExpandLabel(allocator, "tls13 derived early secret", .sha256, early_secret, "derived", &empty_hash, provider.Hash.sha256.digestLength());
    defer allocator.free(derived_from_early);
    const handshake_secret = try opensslHkdfExtract(allocator, "tls13 handshake secret", .sha256, derived_from_early, &shared);
    defer allocator.free(handshake_secret);
    try expectStage("tls13 handshake secret", &schedule.handshake_secret, handshake_secret);

    const client_hs = try opensslHkdfExpandLabel(allocator, "tls13 client handshake traffic secret", .sha256, handshake_secret, "c hs traffic", &hello_hash, provider.Hash.sha256.digestLength());
    defer allocator.free(client_hs);
    try expectStage("tls13 client handshake traffic secret", &schedule.client_handshake_traffic, client_hs);

    const server_hs = try opensslHkdfExpandLabel(allocator, "tls13 server handshake traffic secret", .sha256, handshake_secret, "s hs traffic", &hello_hash, provider.Hash.sha256.digestLength());
    defer allocator.free(server_hs);
    try expectStage("tls13 server handshake traffic secret", &schedule.server_handshake_traffic, server_hs);

    const derived_from_handshake = try opensslHkdfExpandLabel(allocator, "tls13 derived handshake secret", .sha256, handshake_secret, "derived", &empty_hash, provider.Hash.sha256.digestLength());
    defer allocator.free(derived_from_handshake);
    const master_secret = try opensslHkdfExtract(allocator, "tls13 master secret", .sha256, derived_from_handshake, &zero);
    defer allocator.free(master_secret);
    try expectStage("tls13 master secret", &schedule.master_secret, master_secret);

    const finished_hash = hexBytes("9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13");
    var app = try schedule.applicationSecrets(finished_hash);
    defer app.wipe();
    const client_app = try opensslHkdfExpandLabel(allocator, "tls13 client application traffic secret", .sha256, master_secret, "c ap traffic", &finished_hash, provider.Hash.sha256.digestLength());
    defer allocator.free(client_app);
    try expectStage("tls13 client application traffic secret", &app.client, client_app);
    const server_app = try opensslHkdfExpandLabel(allocator, "tls13 server application traffic secret", .sha256, master_secret, "s ap traffic", &finished_hash, provider.Hash.sha256.digestLength());
    defer allocator.free(server_app);
    try expectStage("tls13 server application traffic secret", &app.server, server_app);
}

test "OpenSSL HKDF oracle matches provider and TLS record derivations" {
    const allocator = testing.allocator;
    const cp = cryptoProvider();

    const ikm = hexBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    const salt = hexBytes("000102030405060708090a0b0c");
    var prk: [provider.Hash.sha256.digestLength()]u8 = undefined;
    try cp.hkdfExtract(.sha256, &salt, &ikm, &prk);
    const openssl_prk = try opensslHkdfExtract(allocator, "hkdf extract sha256 / RFC 5869 A.1", .sha256, &salt, &ikm);
    defer allocator.free(openssl_prk);
    try expectStage("hkdf extract sha256 / RFC 5869 A.1", &prk, openssl_prk);

    const context = hexBytes("f0f1f2f3f4f5f6f7f8f9");
    var pure_sha256: [42]u8 = undefined;
    try cp.hkdfExpandLabel(.sha256, &prk, "derived", &context, &pure_sha256);
    const openssl_sha256 = try opensslHkdfExpandLabel(allocator, "hkdf expand-label sha256 / TLS derived", .sha256, &prk, "derived", &context, pure_sha256.len);
    defer allocator.free(openssl_sha256);
    try expectStage("hkdf expand-label sha256 / TLS derived", &pure_sha256, openssl_sha256);

    const secret384 = [_]u8{0x42} ** provider.Hash.sha384.digestLength();
    var prk384: [provider.Hash.sha384.digestLength()]u8 = undefined;
    try cp.hkdfExtract(.sha384, &secret384, &ikm, &prk384);
    const openssl_prk384 = try opensslHkdfExtract(allocator, "hkdf extract sha384 / fixed fixture", .sha384, &secret384, &ikm);
    defer allocator.free(openssl_prk384);
    try expectStage("hkdf extract sha384 / fixed fixture", &prk384, openssl_prk384);

    var pure_sha384: [48]u8 = undefined;
    try cp.hkdfExpandLabel(.sha384, &secret384, "c hs traffic", "", &pure_sha384);
    const openssl_sha384 = try opensslHkdfExpandLabel(allocator, "hkdf expand-label sha384 / client handshake traffic", .sha384, &secret384, "c hs traffic", "", pure_sha384.len);
    defer allocator.free(openssl_sha384);
    try expectStage("hkdf expand-label sha384 / client handshake traffic", &pure_sha384, openssl_sha384);

    const tls_record_secret = hexBytes("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
    try expectTlsTrafficKeys(allocator, "tls record aes128 key", cp, .tls_aes_128_gcm_sha256, &tls_record_secret);
    try expectTlsTrafficKeys(allocator, "tls record aes256 key", cp, .tls_aes_256_gcm_sha384, &secret384);

    const chacha_secret = [_]u8{0x33} ** provider.Hash.sha256.digestLength();
    try expectTlsTrafficKeys(allocator, "tls record chacha20 key", cp, .tls_chacha20_poly1305_sha256, &chacha_secret);
}

fn runQuicInitial(allocator: std.mem.Allocator) !void {
    const dcid = hexBytes("8394c8f03e515708");
    const zig_initial = try quic.tls_adapter.deriveInitialSecretsV1(&dcid);
    const rfc9001_initial_salt = hexBytes("38762cf7f55934b34d179ae6a4c80cadccbb7f0a");
    const quic_secret_len = 32;
    const quic_key_len = 16;
    const quic_iv_len = 12;
    const quic_hp_len = 16;

    const openssl_initial = try opensslHkdfExtract(allocator, "quic v1 initial secret", .sha256, &rfc9001_initial_salt, &dcid);
    defer allocator.free(openssl_initial);
    try expectStage("quic v1 initial secret", &zig_initial.initial_secret, openssl_initial);

    const openssl_client_secret = try opensslHkdfExpandLabel(allocator, "quic client initial secret", .sha256, openssl_initial, "client in", "", quic_secret_len);
    defer allocator.free(openssl_client_secret);
    try expectStage("quic client initial secret", &zig_initial.client.secret, openssl_client_secret);

    const openssl_server_secret = try opensslHkdfExpandLabel(allocator, "quic server initial secret", .sha256, openssl_initial, "server in", "", quic_secret_len);
    defer allocator.free(openssl_server_secret);
    try expectStage("quic server initial secret", &zig_initial.server.secret, openssl_server_secret);

    const openssl_client_key = try opensslHkdfExpandLabel(allocator, "quic client initial key", .sha256, openssl_client_secret, "quic key", "", quic_key_len);
    defer allocator.free(openssl_client_key);
    try expectStage("quic client initial key", &zig_initial.client.key, openssl_client_key);

    const openssl_client_iv = try opensslHkdfExpandLabel(allocator, "quic client initial iv", .sha256, openssl_client_secret, "quic iv", "", quic_iv_len);
    defer allocator.free(openssl_client_iv);
    try expectStage("quic client initial iv", &zig_initial.client.iv, openssl_client_iv);

    const openssl_client_hp = try opensslHkdfExpandLabel(allocator, "quic client initial hp", .sha256, openssl_client_secret, "quic hp", "", quic_hp_len);
    defer allocator.free(openssl_client_hp);
    try expectStage("quic client initial hp", &zig_initial.client.hp, openssl_client_hp);

    const openssl_server_key = try opensslHkdfExpandLabel(allocator, "quic server initial key", .sha256, openssl_server_secret, "quic key", "", quic_key_len);
    defer allocator.free(openssl_server_key);
    try expectStage("quic server initial key", &zig_initial.server.key, openssl_server_key);

    const openssl_server_iv = try opensslHkdfExpandLabel(allocator, "quic server initial iv", .sha256, openssl_server_secret, "quic iv", "", quic_iv_len);
    defer allocator.free(openssl_server_iv);
    try expectStage("quic server initial iv", &zig_initial.server.iv, openssl_server_iv);

    const openssl_server_hp = try opensslHkdfExpandLabel(allocator, "quic server initial hp", .sha256, openssl_server_secret, "quic hp", "", quic_hp_len);
    defer allocator.free(openssl_server_hp);
    try expectStage("quic server initial hp", &zig_initial.server.hp, openssl_server_hp);
}

test "OpenSSL HKDF oracle matches QUIC production initial derivation" {
    try runQuicInitial(testing.allocator);
}

fn fillSyntheticHrr(
    out: []u8,
    ch1_hash: *const [tls_core.transcript.digest_len]u8,
    hello_retry_request: []const u8,
    client_hello_2: []const u8,
) void {
    out[0] = 0xfe;
    std.mem.writeInt(u24, out[1..4], tls_core.transcript.digest_len, .big);
    @memcpy(out[4..][0..tls_core.transcript.digest_len], ch1_hash);
    var offset: usize = 4 + tls_core.transcript.digest_len;
    @memcpy(out[offset..][0..hello_retry_request.len], hello_retry_request);
    offset += hello_retry_request.len;
    @memcpy(out[offset..][0..client_hello_2.len], client_hello_2);
}

fn runTranscriptAndFinished(allocator: std.mem.Allocator) !void {
    const io = testing.io;
    const KeySchedule = tls_core.key_schedule.KeySchedule;
    const cp = cryptoProvider();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const client_hello_1 = hexBytes("01000003aabbcc");
    try tmp.dir.writeFile(io, .{ .sub_path = "client_hello_1.bin", .data = &client_hello_1 });
    const client_hello_path = try tmp.dir.realPathFileAlloc(io, "client_hello_1.bin", allocator);
    defer allocator.free(client_hello_path);

    var transcript = tls_core.transcript.Transcript{};
    transcript.update(&client_hello_1);
    const zig_ch1_hash = transcript.peek();
    try expectOpenSslSha256File(allocator, "tls transcript ClientHello1 hash", &zig_ch1_hash, client_hello_path);

    const hello_retry_request = hexBytes("02000002cf21");
    var client_hello_2 = hexBytes("01000002ddee");
    transcript.replace(zig_ch1_hash);
    transcript.update(&hello_retry_request);
    transcript.update(&client_hello_2);
    const zig_hrr_hash = transcript.peek();

    var synthetic_and_hrr: [4 + tls_core.transcript.digest_len + hello_retry_request.len + client_hello_2.len]u8 = undefined;
    fillSyntheticHrr(&synthetic_and_hrr, &zig_ch1_hash, &hello_retry_request, &client_hello_2);
    try tmp.dir.writeFile(io, .{ .sub_path = "synthetic_hrr.bin", .data = &synthetic_and_hrr });
    const synthetic_hrr_path = try tmp.dir.realPathFileAlloc(io, "synthetic_hrr.bin", allocator);
    defer allocator.free(synthetic_hrr_path);
    try expectOpenSslSha256File(allocator, "tls transcript HRR hash", &zig_hrr_hash, synthetic_hrr_path);

    const traffic_secret = hexBytes("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38");
    try tmp.dir.writeFile(io, .{ .sub_path = "finished_hash.bin", .data = &zig_hrr_hash });
    const finished_hash_path = try tmp.dir.realPathFileAlloc(io, "finished_hash.bin", allocator);
    defer allocator.free(finished_hash_path);

    var zig_finished_key = try KeySchedule.finishedKey(cp, &traffic_secret);
    defer std.crypto.secureZero(u8, &zig_finished_key);
    const openssl_finished_key = try opensslHkdfExpandLabel(allocator, "tls13 server Finished key", .sha256, &traffic_secret, "finished", "", provider.Hash.sha256.digestLength());
    defer allocator.free(openssl_finished_key);
    try expectStage("tls13 server Finished key", &zig_finished_key, openssl_finished_key);

    const openssl_verify_data = try opensslHmacSha256File(allocator, "tls13 server Finished verify_data", openssl_finished_key, finished_hash_path);
    defer allocator.free(openssl_verify_data);
    var zig_verify_data = try KeySchedule.verifyData(cp, &traffic_secret, zig_hrr_hash);
    defer std.crypto.secureZero(u8, &zig_verify_data);
    try expectStage("tls13 server Finished verify_data", &zig_verify_data, openssl_verify_data);

    client_hello_2[client_hello_2.len - 1] ^= 0x01;
    var mutated_transcript = tls_core.transcript.Transcript{};
    mutated_transcript.update(&client_hello_1);
    const mutated_ch1_hash = mutated_transcript.peek();
    try expectStage("tls transcript mutated ClientHello1 stable hash", &zig_ch1_hash, &mutated_ch1_hash);
    mutated_transcript.replace(mutated_ch1_hash);
    mutated_transcript.update(&hello_retry_request);
    mutated_transcript.update(&client_hello_2);
    const zig_mutated_hrr_hash = mutated_transcript.peek();

    fillSyntheticHrr(&synthetic_and_hrr, &zig_ch1_hash, &hello_retry_request, &client_hello_2);
    try tmp.dir.writeFile(io, .{ .sub_path = "synthetic_hrr_mutated.bin", .data = &synthetic_and_hrr });
    const synthetic_hrr_mutated_path = try tmp.dir.realPathFileAlloc(io, "synthetic_hrr_mutated.bin", allocator);
    defer allocator.free(synthetic_hrr_mutated_path);
    try expectOpenSslSha256File(allocator, "tls transcript HRR mutated hash", &zig_mutated_hrr_hash, synthetic_hrr_mutated_path);

    try tmp.dir.writeFile(io, .{ .sub_path = "finished_hash_mutated.bin", .data = &zig_mutated_hrr_hash });
    const finished_hash_mutated_path = try tmp.dir.realPathFileAlloc(io, "finished_hash_mutated.bin", allocator);
    defer allocator.free(finished_hash_mutated_path);
    const openssl_mutated_verify_data = try opensslHmacSha256File(allocator, "tls13 server Finished mutated verify_data", openssl_finished_key, finished_hash_mutated_path);
    defer allocator.free(openssl_mutated_verify_data);
    var zig_mutated_verify_data = try KeySchedule.verifyData(cp, &traffic_secret, zig_mutated_hrr_hash);
    defer std.crypto.secureZero(u8, &zig_mutated_verify_data);
    try expectStage("tls13 server Finished mutated verify_data", &zig_mutated_verify_data, openssl_mutated_verify_data);
    var stable_verify_data = try KeySchedule.verifyData(cp, &traffic_secret, zig_hrr_hash);
    defer std.crypto.secureZero(u8, &stable_verify_data);
    try testing.expect(!std.mem.eql(u8, &stable_verify_data, &zig_mutated_verify_data));
}

test "OpenSSL digest and HMAC oracles match transcript and Finished values" {
    try runTranscriptAndFinished(testing.allocator);
}

test "EVP oracle harness accepts maximum AEAD seal response" {
    const allocator = testing.allocator;
    const key = [_]u8{0x5a} ** 16;
    const nonce = hexBytes("202122232425262728292a2b");
    const aad = "max-aead-boundary";
    const plaintext = try allocator.alloc(u8, evp_oracle_max_input);
    defer allocator.free(plaintext);
    @memset(plaintext, 0x7b);

    var sealed = try runEvpAeadSeal(allocator, .aes_128_gcm, &key, &nonce, aad, plaintext);
    defer sealed.deinit(allocator);
    try expectEvpStatus(&sealed, .ok);
    try testing.expectEqual(@as(usize, evp_oracle_max_input), sealed.fields[0].?.len);
    try testing.expectEqual(@as(usize, provider.aead_tag_len), sealed.fields[1].?.len);
}

test "EVP oracle harness classifies child process termination and output caps" {
    const allocator = testing.allocator;

    try testing.expectError(
        error.EvpOracleFailed,
        runBoundedChildRaw(allocator, &.{ "/bin/sh", "-c", "exit 7" }, .limited(evp_oracle_stdout_limit), .limited(evp_oracle_stderr_limit)),
    );
    try testing.expectError(
        error.EvpOracleFailed,
        runBoundedChildRaw(allocator, &.{ "/bin/sh", "-c", "kill -TERM $$" }, .limited(evp_oracle_stdout_limit), .limited(evp_oracle_stderr_limit)),
    );
    try testing.expectError(
        error.StreamTooLong,
        runBoundedChildRaw(allocator, &.{ "/bin/sh", "-c", "printf 123456" }, .limited(4), .limited(evp_oracle_stderr_limit)),
    );
    try testing.expectError(
        error.StreamTooLong,
        runBoundedChildRaw(allocator, &.{ "/bin/sh", "-c", "printf 123456 >&2" }, .limited(evp_oracle_stdout_limit), .limited(4)),
    );
}

test "OpenSSL differential coverage registry has explicit coverage or waivers" {
    for (differential_cases) |case| {
        try testing.expect(case.rationale.len > 0);
        errdefer std.debug.print("failed OpenSSL differential case: kind={s} class={s} rationale={s}\n", .{ @tagName(case.kind), @tagName(case.class), case.rationale });
        try case.run(testing.allocator);
    }
    for (waivers) |waiver| {
        try testing.expect(waiver.reason.len > 0);
        try testing.expect(waiver.tracking_issue.len > 0);
        try testing.expect(!std.mem.eql(u8, waiver.tracking_issue, "#377"));
    }

    try expectCoverageOrWaiver(.hkdf_extract, .{ .hkdf = .sha256 }, .positive);
    try expectCoverageOrWaiver(.hkdf_extract, .{ .hkdf = .sha384 }, .positive);
    try expectCoverageOrWaiver(.hkdf_expand_label, .{ .hkdf = .sha256 }, .positive);
    try expectCoverageOrWaiver(.hkdf_expand_label, .{ .hkdf = .sha384 }, .positive);

    try expectCoverageOrWaiver(.tls_record_keys, .{ .aead = .aes_128_gcm }, .positive);
    try expectCoverageOrWaiver(.tls_record_keys, .{ .aead = .aes_256_gcm }, .positive);
    try expectCoverageOrWaiver(.tls_record_keys, .{ .aead = .chacha20_poly1305 }, .positive);
    try expectCoverageOrWaiver(.tls_key_schedule, .{ .hkdf = .sha256 }, .positive);
    try expectCoverageOrWaiver(.quic_initial, .{ .aead = .aes_128_gcm }, .positive);
    try expectCoverageOrWaiver(.transcript_hash, .{ .hash = .sha256 }, .positive);
    try expectCoverageOrWaiver(.transcript_hash, .{ .hash = .sha256 }, .negative);
    try expectCoverageOrWaiver(.finished_hmac, .{ .hkdf = .sha256 }, .positive);
    try expectCoverageOrWaiver(.finished_hmac, .{ .hkdf = .sha256 }, .negative);

    try expectCoverageOrWaiver(.aead, .{ .aead = .aes_128_gcm }, .positive);
    try expectCoverageOrWaiver(.aead, .{ .aead = .aes_128_gcm }, .negative);
    try expectCoverageOrWaiver(.aead, .{ .aead = .aes_256_gcm }, .positive);
    try expectCoverageOrWaiver(.aead, .{ .aead = .aes_256_gcm }, .negative);
    try expectCoverageOrWaiver(.aead, .{ .aead = .chacha20_poly1305 }, .positive);
    try expectCoverageOrWaiver(.aead, .{ .aead = .chacha20_poly1305 }, .negative);
    try expectCoverageOrWaiver(.key_exchange, .{ .group = .x25519 }, .positive);
    try expectCoverageOrWaiver(.key_exchange, .{ .group = .x25519 }, .negative);
    try expectCoverageOrWaiver(.signature_sign, .{ .signature = .ed25519 }, .positive);
    try expectCoverageOrWaiver(.signature_sign, .{ .signature = .ecdsa_secp256r1_sha256 }, .positive);
    try expectCoverageOrWaiver(.signature_verify, .{ .signature = .ed25519 }, .positive);
    try expectCoverageOrWaiver(.signature_verify, .{ .signature = .ed25519 }, .negative);
    try expectCoverageOrWaiver(.signature_verify, .{ .signature = .ecdsa_secp256r1_sha256 }, .positive);
    try expectCoverageOrWaiver(.signature_verify, .{ .signature = .ecdsa_secp256r1_sha256 }, .negative);
    try expectCoverageOrWaiver(.psk_binder, .{ .hkdf = .sha256 }, .negative);
    try expectCoverageOrWaiver(.psk_binder, .{ .hkdf = .sha384 }, .negative);
}

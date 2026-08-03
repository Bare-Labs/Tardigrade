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
const key_schedule = tls_core.key_schedule;
const pre_shared_key = tls_core.pre_shared_key;
const session = tls_core.session;
const ticket_protection = tls_core.ticket_protection;
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
    resumption_master_secret,
    resumption_psk,
    protected_ticket,
    key_exchange,
    signature_sign,
    signature_verify,
    rsa_pss_verify,
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
    .{ .kind = .resumption_master_secret, .algorithm = .{ .hkdf = .sha256 }, .class = .positive, .rationale = "KeySchedule.deriveResumptionMasterSecret SHA-256 compared to OpenSSL HKDF-Expand-Label", .run = runResumptionSha256 },
    .{ .kind = .resumption_master_secret, .algorithm = .{ .hkdf = .sha256 }, .class = .negative, .rationale = "SHA-256 resumption master secret mutation and length checks", .run = runResumptionSha256 },
    .{ .kind = .resumption_master_secret, .algorithm = .{ .hkdf = .sha384 }, .class = .positive, .rationale = "KeySchedule.deriveResumptionMasterSecret SHA-384 compared to OpenSSL HKDF-Expand-Label", .run = runResumptionSha384 },
    .{ .kind = .resumption_master_secret, .algorithm = .{ .hkdf = .sha384 }, .class = .negative, .rationale = "SHA-384 resumption master secret mutation and length checks", .run = runResumptionSha384 },
    .{ .kind = .resumption_psk, .algorithm = .{ .hkdf = .sha256 }, .class = .positive, .rationale = "KeySchedule.resumptionPsk SHA-256 compared to OpenSSL HKDF-Expand-Label for multiple ticket nonces", .run = runResumptionSha256 },
    .{ .kind = .resumption_psk, .algorithm = .{ .hkdf = .sha256 }, .class = .negative, .rationale = "SHA-256 per-ticket PSK nonce mutation and length checks", .run = runResumptionSha256 },
    .{ .kind = .resumption_psk, .algorithm = .{ .hkdf = .sha384 }, .class = .positive, .rationale = "KeySchedule.resumptionPsk SHA-384 compared to OpenSSL HKDF-Expand-Label for multiple ticket nonces", .run = runResumptionSha384 },
    .{ .kind = .resumption_psk, .algorithm = .{ .hkdf = .sha384 }, .class = .negative, .rationale = "SHA-384 per-ticket PSK nonce mutation and length checks", .run = runResumptionSha384 },
    .{ .kind = .psk_binder, .algorithm = .{ .hkdf = .sha256 }, .class = .positive, .rationale = "SHA-256 pre_shared_key write/parse/derive/verify fixture compared to independent OpenSSL HKDF/HMAC", .run = runPskBinderSha256 },
    .{ .kind = .psk_binder, .algorithm = .{ .hkdf = .sha256 }, .class = .negative, .rationale = "SHA-256 binder transcript, PSK, identity, binder, and length mutation checks", .run = runPskBinderSha256 },
    .{ .kind = .psk_binder, .algorithm = .{ .hkdf = .sha384 }, .class = .positive, .rationale = "SHA-384 pre_shared_key write/parse/derive/verify fixture compared to independent OpenSSL HKDF/HMAC", .run = runPskBinderSha384 },
    .{ .kind = .psk_binder, .algorithm = .{ .hkdf = .sha384 }, .class = .negative, .rationale = "SHA-384 binder transcript, PSK, identity, binder, and length mutation checks", .run = runPskBinderSha384 },
    .{ .kind = .protected_ticket, .algorithm = .{ .aead = .aes_128_gcm }, .class = .positive, .rationale = "AES-128-GCM ticket envelope matches native provider, EVP oracle, and Protector.seal/resolve", .run = runProtectedTicketAes128 },
    .{ .kind = .protected_ticket, .algorithm = .{ .aead = .aes_128_gcm }, .class = .negative, .rationale = "AES-128-GCM ticket resolver normalizes ciphertext/tag/header/key mutations to misses", .run = runProtectedTicketAes128 },
    .{ .kind = .protected_ticket, .algorithm = .{ .aead = .aes_256_gcm }, .class = .positive, .rationale = "AES-256-GCM ticket envelope matches native provider, EVP oracle, and Protector.seal/resolve", .run = runProtectedTicketAes256 },
    .{ .kind = .protected_ticket, .algorithm = .{ .aead = .aes_256_gcm }, .class = .negative, .rationale = "AES-256-GCM ticket resolver normalizes ciphertext/tag/header/key mutations to misses", .run = runProtectedTicketAes256 },
    .{ .kind = .protected_ticket, .algorithm = .{ .aead = .chacha20_poly1305 }, .class = .positive, .rationale = "ChaCha20-Poly1305 ticket envelope matches native provider, EVP oracle, and Protector.seal/resolve", .run = runProtectedTicketChacha20 },
    .{ .kind = .protected_ticket, .algorithm = .{ .aead = .chacha20_poly1305 }, .class = .negative, .rationale = "ChaCha20-Poly1305 ticket resolver normalizes ciphertext/tag/header/key mutations to misses", .run = runProtectedTicketChacha20 },
    .{ .kind = .key_exchange, .algorithm = .{ .group = .x25519 }, .class = .positive, .rationale = "provider raw X25519 shared secret compared to EVP oracle", .run = runX25519Positive },
    .{ .kind = .key_exchange, .algorithm = .{ .group = .x25519 }, .class = .negative, .rationale = "provider X25519 malformed and low-order peer handling compared to EVP oracle status", .run = runX25519Negative },
    .{ .kind = .key_exchange, .algorithm = .{ .group = .secp256r1 }, .class = .positive, .rationale = "provider raw P-256 ECDH shared secret compared to EVP oracle", .run = runP256EcdhPositive },
    .{ .kind = .key_exchange, .algorithm = .{ .group = .secp256r1 }, .class = .negative, .rationale = "provider P-256 ECDH malformed scalar and peer handling compared to EVP oracle status", .run = runP256EcdhNegative },
    .{ .kind = .signature_sign, .algorithm = .{ .signature = .ed25519 }, .class = .positive, .rationale = "provider raw Ed25519 signing compared to EVP oracle", .run = runEd25519SignPositive },
    .{ .kind = .signature_sign, .algorithm = .{ .signature = .ecdsa_secp256r1_sha256 }, .class = .positive, .rationale = "pure-Zig ECDSA-P256 signatures cross-verify with the OpenSSL EVP oracle", .run = runEcdsaP256SignPositive },
    .{ .kind = .signature_sign, .algorithm = .{ .signature = .rsa_pss_rsae_sha256 }, .class = .positive, .rationale = "pure-Zig RSA-PSS-RSAE-SHA256 private-key signatures cross-verify with an independent OpenSSL EVP verifier (#565)", .run = runRsaPssSignPositive },
    .{ .kind = .signature_verify, .algorithm = .{ .signature = .ed25519 }, .class = .positive, .rationale = "provider raw Ed25519 verification compared to EVP oracle", .run = runEd25519VerifyPositive },
    .{ .kind = .signature_verify, .algorithm = .{ .signature = .ed25519 }, .class = .negative, .rationale = "provider raw Ed25519 invalid signature/message/key handling compared to EVP oracle", .run = runEd25519VerifyNegative },
    .{ .kind = .signature_verify, .algorithm = .{ .signature = .ecdsa_secp256r1_sha256 }, .class = .positive, .rationale = "provider SEC1 ECDSA-P256-SHA256 verification compared to EVP oracle", .run = runEcdsaP256VerifyPositive },
    .{ .kind = .signature_verify, .algorithm = .{ .signature = .ecdsa_secp256r1_sha256 }, .class = .negative, .rationale = "provider SEC1 ECDSA-P256-SHA256 malformed and invalid verification compared to EVP oracle", .run = runEcdsaP256VerifyNegative },
};

const waivers = [_]Waiver{
    .{ .kind = .rsa_pss_verify, .algorithm = .{ .signature = .rsa_pss_rsae_sha256 }, .class = .positive, .reason = "RSA-PSS verification is already covered by the OpenSSL-derived strict corpus in tests/crypto_vectors.zig (rsa-pss-sha256-openssl-2048/3072/4096), completed by #413/#428; duplicating it here would add no new oracle boundary.", .tracking_issue = "#413/#428" },
    .{ .kind = .rsa_pss_verify, .algorithm = .{ .signature = .rsa_pss_rsae_sha256 }, .class = .negative, .reason = "RSA-PSS signature/message/key corruption and malformed-input behavior is already exercised by tests/crypto_vectors.zig's rsa-pss-sha256-signature-corruption and invalid-input checks, completed by #413/#428.", .tracking_issue = "#413/#428" },
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

fn runEvpP256Ecdh(allocator: std.mem.Allocator, private_scalar: []const u8, peer_public: []const u8) !EvpOracleResult {
    const private_hex = try hexAlloc(allocator, private_scalar);
    defer allocator.free(private_hex);
    const public_hex = try hexAlloc(allocator, peer_public);
    defer allocator.free(public_hex);
    return runEvpOracle(allocator, &.{ "p256-ecdh", private_hex, public_hex });
}

fn runP256EcdhPositive(allocator: std.mem.Allocator) !void {
    const cp = cryptoProvider();
    const scalar_one = [_]u8{0} ** 31 ++ [_]u8{1};
    const scalar_two_public = hexBytes("047cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc4766997807775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1");
    const expected_shared = hexBytes("7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978");
    var shared: [provider.max_shared_secret_len]u8 = undefined;
    try cp.deriveSharedSecret(.secp256r1, &scalar_one, &scalar_two_public, &shared);
    try expectStage("p256 ecdh shared secret / SEC 2", &expected_shared, &shared);

    var oracle = try runEvpP256Ecdh(allocator, &scalar_one, &scalar_two_public);
    defer oracle.deinit(allocator);
    try expectEvpStatus(&oracle, .ok);
    try testing.expectEqualSlices(u8, &shared, oracle.fields[0].?);
}

fn runP256EcdhNegative(allocator: std.mem.Allocator) !void {
    const cp = cryptoProvider();
    const scalar_one = [_]u8{0} ** 31 ++ [_]u8{1};
    const scalar_zero = [_]u8{0} ** 32;
    const scalar_out_of_range = [_]u8{0xff} ** 32;
    const scalar_two_public = hexBytes("047cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc4766997807775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1");
    var shared: [provider.max_shared_secret_len]u8 = undefined;

    try testing.expectError(error.InvalidInput, cp.deriveSharedSecret(.secp256r1, &scalar_zero, &scalar_two_public, &shared));
    var zero_scalar = try runEvpP256Ecdh(allocator, &scalar_zero, &scalar_two_public);
    defer zero_scalar.deinit(allocator);
    try expectEvpStatus(&zero_scalar, .malformed);

    try testing.expectError(error.InvalidInput, cp.deriveSharedSecret(.secp256r1, &scalar_out_of_range, &scalar_two_public, &shared));
    var out_of_range_scalar = try runEvpP256Ecdh(allocator, &scalar_out_of_range, &scalar_two_public);
    defer out_of_range_scalar.deinit(allocator);
    try expectEvpStatus(&out_of_range_scalar, .malformed);

    var malformed_peer = scalar_two_public;
    malformed_peer[0] = 0x02;
    try testing.expectError(error.InvalidInput, cp.deriveSharedSecret(.secp256r1, &scalar_one, &malformed_peer, &shared));
    var wrong_prefix = try runEvpP256Ecdh(allocator, &scalar_one, &malformed_peer);
    defer wrong_prefix.deinit(allocator);
    try expectEvpStatus(&wrong_prefix, .malformed);

    var off_curve = scalar_two_public;
    off_curve[64] ^= 0x01;
    try testing.expectError(error.InvalidInput, cp.deriveSharedSecret(.secp256r1, &scalar_one, &off_curve, &shared));
    var off_curve_result = try runEvpP256Ecdh(allocator, &scalar_one, &off_curve);
    defer off_curve_result.deinit(allocator);
    try expectEvpStatus(&off_curve_result, .malformed);
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

fn runEvpRsaPssVerify(allocator: std.mem.Allocator, public_key: []const u8, message: []const u8, signature: []const u8) !EvpOracleResult {
    const public_hex = try hexAlloc(allocator, public_key);
    defer allocator.free(public_hex);
    const message_hex = try hexAlloc(allocator, message);
    defer allocator.free(message_hex);
    const signature_hex = try hexAlloc(allocator, signature);
    defer allocator.free(signature_hex);
    return runEvpOracle(allocator, &.{ "rsa-pss-verify", public_hex, message_hex, signature_hex });
}

fn expectRsaPssAcceptsBoth(allocator: std.mem.Allocator, cp: provider.CryptoProvider, public_key: []const u8, message: []const u8, signature: []const u8) !void {
    try cp.verify(.rsa_pss_rsae_sha256, public_key, message, signature);
    var oracle = try runEvpRsaPssVerify(allocator, public_key, message, signature);
    defer oracle.deinit(allocator);
    try expectEvpStatus(&oracle, .ok);
}

fn expectRsaPssRejects(allocator: std.mem.Allocator, cp: provider.CryptoProvider, public_key: []const u8, message: []const u8, signature: []const u8, expected_native: anyerror, expected_oracle: EvpStatus) !void {
    try testing.expectError(expected_native, cp.verify(.rsa_pss_rsae_sha256, public_key, message, signature));
    var oracle = try runEvpRsaPssVerify(allocator, public_key, message, signature);
    defer oracle.deinit(allocator);
    try expectEvpStatus(&oracle, expected_oracle);
}

/// #565: cross-verifies native RSA-PSS-RSAE-SHA256 *signing* against an
/// independent OpenSSL verifier — the counterpart to `.rsa_pss_verify`'s
/// waivers above, which cover verification only. `rsa-pss-verify` (added to
/// `tests/evp_oracle.c` for this) checks the strict profile both this
/// project's decoder and RFC 8017 require: SHA-256 digest/MGF1, a 32-byte
/// salt, RSASSA-PSS padding. The oracle never signs here — signing stays
/// entirely inside the pure-Zig private-key owner (`rsa.zig`'s
/// `signPssSha256`, behind `provider.SigningKey`), so this test proves that
/// exact code path against an independent EVP verifier rather than merely
/// against its own decoder.
fn runRsaPssSignPositive(allocator: std.mem.Allocator) !void {
    const rsa = crypto_pkg.rsa;
    const cp = cryptoProvider();
    var native_key = try pure_zig.SoftwareRsaSigningKey.fromDer(rsa.testdata.private_key_pkcs1_der);
    defer native_key.deinit();
    const signer = native_key.signingKey();
    try testing.expectEqual(provider.SignatureScheme.rsa_pss_rsae_sha256, signer.scheme());

    const message = "rsa-pss signing differential fixture";
    var native_entropy = pure_zig.DeterministicEntropy.init(0x5091);
    var native_signature: [rsa.max_modulus_bytes]u8 = undefined;
    const native_len = try signer.sign(message, native_entropy.entropy(), &native_signature);
    try testing.expectEqual(@as(usize, 256), native_len);
    const native_sig = native_signature[0..native_len];
    const public_key = rsa.testdata.public_key_der;

    try expectRsaPssAcceptsBoth(allocator, cp, public_key, message, native_sig);

    try expectRsaPssRejects(allocator, cp, public_key, "mutated message", native_sig, error.AuthenticationFailed, .auth_fail);

    var modified_sig = try allocator.dupe(u8, native_sig);
    defer allocator.free(modified_sig);
    modified_sig[modified_sig.len - 1] ^= 0x01;
    try expectRsaPssRejects(allocator, cp, public_key, message, modified_sig, error.AuthenticationFailed, .auth_fail);

    const malformed_key = [_]u8{0x30};
    try expectRsaPssRejects(allocator, cp, &malformed_key, message, native_sig, error.InvalidInput, .malformed);

    // Flip a byte deep in the modulus to model an unrelated key: still a
    // structurally valid RSAPublicKey shape, wrong value.
    var wrong_public: [rsa.testdata.public_key_der.len]u8 = undefined;
    @memcpy(&wrong_public, rsa.testdata.public_key_der);
    wrong_public[20] ^= 0xff;
    try expectRsaPssRejects(allocator, cp, &wrong_public, message, native_sig, error.AuthenticationFailed, .auth_fail);
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
    return opensslDigestFile(allocator, stage, .sha256, path);
}

fn opensslDigestFile(allocator: std.mem.Allocator, stage: []const u8, hash: provider.Hash, path: []const u8) ![]u8 {
    const openssl = try opensslBinary(allocator);
    defer openssl.deinit(allocator);
    const digest = switch (hash) {
        .sha256 => "-sha256",
        .sha384 => "-sha384",
    };
    return runOpenSsl(allocator, stage, &.{ openssl.path, "dgst", digest, "-binary", path });
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
    return opensslHmacFile(allocator, stage, .sha256, key, path);
}

fn opensslHmacFile(
    allocator: std.mem.Allocator,
    stage: []const u8,
    hash: provider.Hash,
    key: []const u8,
    path: []const u8,
) ![]u8 {
    const key_hex = try hexAlloc(allocator, key);
    defer allocator.free(key_hex);
    const key_opt = try std.fmt.allocPrint(allocator, "hexkey:{s}", .{key_hex});
    defer allocator.free(key_opt);
    const openssl = try opensslBinary(allocator);
    defer openssl.deinit(allocator);
    const digest = switch (hash) {
        .sha256 => "-sha256",
        .sha384 => "-sha384",
    };
    return runOpenSsl(allocator, stage, &.{
        openssl.path,
        "dgst",
        digest,
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
    var schedule: KeySchedule = undefined;
    try KeySchedule.init(cp, .sha256, &shared, &hello_hash, &schedule);
    defer schedule.wipe();

    const zero = [_]u8{0} ** provider.Hash.sha256.digestLength();
    const empty_hash = hexBytes("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    const early_secret = try opensslHkdfExtract(allocator, "tls13 early secret", .sha256, "", &zero);
    defer allocator.free(early_secret);
    const derived_from_early = try opensslHkdfExpandLabel(allocator, "tls13 derived early secret", .sha256, early_secret, "derived", &empty_hash, provider.Hash.sha256.digestLength());
    defer allocator.free(derived_from_early);
    const handshake_secret = try opensslHkdfExtract(allocator, "tls13 handshake secret", .sha256, derived_from_early, &shared);
    defer allocator.free(handshake_secret);
    try expectStage("tls13 handshake secret", schedule.handshake_secret[0..32], handshake_secret);

    const client_hs = try opensslHkdfExpandLabel(allocator, "tls13 client handshake traffic secret", .sha256, handshake_secret, "c hs traffic", &hello_hash, provider.Hash.sha256.digestLength());
    defer allocator.free(client_hs);
    try expectStage("tls13 client handshake traffic secret", schedule.client_handshake_traffic[0..32], client_hs);

    const server_hs = try opensslHkdfExpandLabel(allocator, "tls13 server handshake traffic secret", .sha256, handshake_secret, "s hs traffic", &hello_hash, provider.Hash.sha256.digestLength());
    defer allocator.free(server_hs);
    try expectStage("tls13 server handshake traffic secret", schedule.server_handshake_traffic[0..32], server_hs);

    const derived_from_handshake = try opensslHkdfExpandLabel(allocator, "tls13 derived handshake secret", .sha256, handshake_secret, "derived", &empty_hash, provider.Hash.sha256.digestLength());
    defer allocator.free(derived_from_handshake);
    const master_secret = try opensslHkdfExtract(allocator, "tls13 master secret", .sha256, derived_from_handshake, &zero);
    defer allocator.free(master_secret);
    try expectStage("tls13 master secret", schedule.master_secret[0..32], master_secret);

    const finished_hash = hexBytes("9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13");
    var app: KeySchedule.ApplicationSecrets = undefined;
    try schedule.applicationSecrets(&finished_hash, &app);
    defer app.wipe();
    const client_app = try opensslHkdfExpandLabel(allocator, "tls13 client application traffic secret", .sha256, master_secret, "c ap traffic", &finished_hash, provider.Hash.sha256.digestLength());
    defer allocator.free(client_app);
    try expectStage("tls13 client application traffic secret", app.clientSecret(), client_app);
    const server_app = try opensslHkdfExpandLabel(allocator, "tls13 server application traffic secret", .sha256, master_secret, "s ap traffic", &finished_hash, provider.Hash.sha256.digestLength());
    defer allocator.free(server_app);
    try expectStage("tls13 server application traffic secret", app.serverSecret(), server_app);
}

fn fillPattern(out: []u8, seed: u8) void {
    for (out, 0..) |*byte, index| byte.* = seed +% @as(u8, @truncate(index * 17 + 3));
}

fn hashBytes(hash: provider.Hash, bytes: []const u8, out: []u8) !void {
    if (out.len != hash.digestLength()) return error.InvalidInput;
    switch (hash) {
        .sha256 => std.crypto.hash.sha2.Sha256.hash(bytes, out[0..32], .{}),
        .sha384 => std.crypto.hash.sha2.Sha384.hash(bytes, out[0..48], .{}),
    }
}

fn runResumptionForHash(allocator: std.mem.Allocator, hash: provider.Hash) !void {
    const cp = cryptoProvider();
    const digest_len = hash.digestLength();
    var master_secret_storage: [provider.max_digest_len]u8 = undefined;
    var transcript_hash_storage: [provider.max_digest_len]u8 = undefined;
    const master_secret = master_secret_storage[0..digest_len];
    const transcript_hash = transcript_hash_storage[0..digest_len];
    fillPattern(master_secret, 0x21);
    fillPattern(transcript_hash, 0x75);

    var rms_storage: [provider.max_digest_len]u8 = undefined;
    const rms = rms_storage[0..digest_len];
    try key_schedule.KeySchedule.deriveResumptionMasterSecret(cp, hash, master_secret, transcript_hash, rms);
    const expected_rms = try opensslHkdfExpandLabel(allocator, "resumption master secret", hash, master_secret, "res master", transcript_hash, digest_len);
    defer allocator.free(expected_rms);
    try expectStage("resumption master secret", rms, expected_rms);

    var mutated_transcript = transcript_hash_storage;
    mutated_transcript[0] ^= 0x01;
    var mutated_rms_storage: [provider.max_digest_len]u8 = undefined;
    const mutated_rms = mutated_rms_storage[0..digest_len];
    try key_schedule.KeySchedule.deriveResumptionMasterSecret(cp, hash, master_secret, mutated_transcript[0..digest_len], mutated_rms);
    try testing.expect(!std.mem.eql(u8, rms, mutated_rms));

    const nonces = [_][]const u8{ "", "\x01", "\x02distinct nonce" };
    for (nonces, 0..) |nonce, index| {
        var psk_storage: [provider.max_digest_len]u8 = undefined;
        const psk = psk_storage[0..digest_len];
        try key_schedule.KeySchedule.resumptionPsk(cp, hash, rms, nonce, psk);
        const stage = try std.fmt.allocPrint(allocator, "resumption psk nonce {d}", .{index});
        defer allocator.free(stage);
        const expected_psk = try opensslHkdfExpandLabel(allocator, stage, hash, rms, "resumption", nonce, digest_len);
        defer allocator.free(expected_psk);
        try expectStage(stage, psk, expected_psk);
    }

    var psk_a_storage: [provider.max_digest_len]u8 = undefined;
    var psk_b_storage: [provider.max_digest_len]u8 = undefined;
    const psk_a = psk_a_storage[0..digest_len];
    const psk_b = psk_b_storage[0..digest_len];
    try key_schedule.KeySchedule.resumptionPsk(cp, hash, rms, "\x01", psk_a);
    var rms_mutated_storage = rms_storage;
    rms_mutated_storage[0] ^= 0x01;
    try key_schedule.KeySchedule.resumptionPsk(cp, hash, rms_mutated_storage[0..digest_len], "\x01", psk_b);
    try testing.expect(!std.mem.eql(u8, psk_a, psk_b));

    var nonce_mut = [_]u8{0x01};
    nonce_mut[0] ^= 0x80;
    try key_schedule.KeySchedule.resumptionPsk(cp, hash, rms, &nonce_mut, psk_b);
    try testing.expect(!std.mem.eql(u8, psk_a, psk_b));

    var short_out: [provider.max_digest_len]u8 = undefined;
    try testing.expectError(error.InvalidSecretLength, key_schedule.KeySchedule.deriveResumptionMasterSecret(cp, hash, master_secret[0 .. digest_len - 1], transcript_hash, rms));
    try testing.expectError(error.InvalidSecretLength, key_schedule.KeySchedule.deriveResumptionMasterSecret(cp, hash, master_secret, transcript_hash[0 .. digest_len - 1], rms));
    try testing.expectError(error.InvalidSecretLength, key_schedule.KeySchedule.deriveResumptionMasterSecret(cp, hash, master_secret, transcript_hash, short_out[0 .. digest_len - 1]));
    try testing.expectError(error.InvalidSecretLength, key_schedule.KeySchedule.resumptionPsk(cp, hash, rms[0 .. digest_len - 1], "\x01", psk_a));
    try testing.expectError(error.InvalidSecretLength, key_schedule.KeySchedule.resumptionPsk(cp, hash, rms, "\x01", short_out[0 .. digest_len - 1]));
}

fn runResumptionSha256(allocator: std.mem.Allocator) !void {
    try runResumptionForHash(allocator, .sha256);
}

fn runResumptionSha384(allocator: std.mem.Allocator) !void {
    try runResumptionForHash(allocator, .sha384);
}

const BinderFixture = struct {
    full: []const u8,
    truncated: []const u8,
    ext_data: []const u8,
    slot: pre_shared_key.BinderSlot,
};

const expected_binder_truncated_sha256 = hexBytes("010000700303111111111111111111111111111111111111111111111111111111111111111100000213010100004500290041001c00167469636b65742d6964656e746974792d73686132353610203040");
const expected_binder_truncated_sha384 = hexBytes("010000800303111111111111111111111111111111111111111111111111111111111111111100000213010100005500290051001c00167469636b65742d6964656e746974792d73686133383410203040");
const expected_binder_hash_sha256 = hexBytes("9136468c5ddea96b88cdfc816087bc23b820b42646335d609c82b99320a4364e");
const expected_binder_hash_sha384 = hexBytes("e6f3b0ea1616e04d028eff2e3ed727e088b711cf985a60c0b02ea999522183becd01cd0f8a1392e7e2603f93cf2ce949");
const expected_binder_sha256 = hexBytes("5d93fb0a6d879504d8ada12cb6484fc3dbe9e0ae6f46e3c3131fa4941d0ac057");
const expected_binder_sha384 = hexBytes("d1b2ab1ddf233db1f82ae5748987b65180564038960391930320455f7cbfba5177d71099a59448c51bddb44cad526e10");

fn expectedBinderTruncated(hash: provider.Hash) []const u8 {
    return switch (hash) {
        .sha256 => &expected_binder_truncated_sha256,
        .sha384 => &expected_binder_truncated_sha384,
    };
}

fn expectedBinderTranscriptHash(hash: provider.Hash) []const u8 {
    return switch (hash) {
        .sha256 => &expected_binder_hash_sha256,
        .sha384 => &expected_binder_hash_sha384,
    };
}

fn expectedBinderBytes(hash: provider.Hash) []const u8 {
    return switch (hash) {
        .sha256 => &expected_binder_sha256,
        .sha384 => &expected_binder_sha384,
    };
}

fn buildBinderFixture(hash: provider.Hash, identity: []const u8, binder: []const u8, out: []u8) !BinderFixture {
    var w = tls_core.messages.Writer{ .buf = out };
    try w.u8_(@intFromEnum(tls_core.messages.MessageType.client_hello));
    const message_len_idx = try w.reserve(3);
    try w.u16_(0x0303);
    try w.bytes(&([_]u8{0x11} ** 32));
    try w.u8_(0);
    try w.u16_(2);
    try w.u16_(@intFromEnum(tls_core.algorithms.CipherSuite.tls_aes_128_gcm_sha256));
    try w.u8_(1);
    try w.u8_(0);
    const extensions_len_idx = try w.reserve(2);
    const ext_start = w.len;
    const offer = try pre_shared_key.writeOffer(&w, &.{
        .{ .identity = identity, .obfuscated_ticket_age = 0x10203040, .digest_len = hash.digestLength() },
    });
    w.patch(2, extensions_len_idx);
    w.patch(3, message_len_idx);
    try testing.expectEqual(@as(usize, 1), offer.count);
    try testing.expectEqual(offer.slots[0].len, binder.len);
    @memcpy(out[offer.slots[0].offset..][0..binder.len], binder);

    const ext_total = w.written()[ext_start..];
    var r = tls_core.messages.Reader{ .bytes = ext_total };
    try testing.expectEqual(pre_shared_key.ext_pre_shared_key, try r.u16_());
    const ext_len = try r.u16_();
    const ext_data = try r.slice(ext_len);
    try r.expectEnd();
    const parsed = try pre_shared_key.OfferedPsks.parse(ext_data);
    try testing.expectEqual(offer.truncated_len, ext_start + 4 + parsed.binder_vector_offset);

    return .{
        .full = w.written(),
        .truncated = w.written()[0..offer.truncated_len],
        .ext_data = ext_data,
        .slot = offer.slots[0],
    };
}

fn opensslBinder(allocator: std.mem.Allocator, hash: provider.Hash, psk: []const u8, transcript_hash: []const u8) ![]u8 {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "binder-transcript-hash.bin", .data = transcript_hash });
    const path = try tmp.dir.realPathFileAlloc(testing.io, "binder-transcript-hash.bin", allocator);
    defer allocator.free(path);

    const zero = [_]u8{0} ** provider.max_digest_len;
    const early_secret = try opensslHkdfExtract(allocator, "psk binder early secret", hash, "", psk);
    defer allocator.free(early_secret);
    const empty_hash = try opensslDigestFile(allocator, "psk binder empty hash", hash, "/dev/null");
    defer allocator.free(empty_hash);
    const binder_key = try opensslHkdfExpandLabel(allocator, "psk binder res binder key", hash, early_secret, "res binder", empty_hash, hash.digestLength());
    defer allocator.free(binder_key);
    const finished_key = try opensslHkdfExpandLabel(allocator, "psk binder finished key", hash, binder_key, "finished", "", hash.digestLength());
    defer allocator.free(finished_key);
    _ = zero;
    return opensslHmacFile(allocator, "psk binder hmac", hash, finished_key, path);
}

fn runPskBinderForHash(allocator: std.mem.Allocator, hash: provider.Hash) !void {
    const digest_len = hash.digestLength();
    var psk_storage: [provider.max_digest_len]u8 = undefined;
    const psk = psk_storage[0..digest_len];
    fillPattern(psk, if (hash == .sha256) 0x31 else 0x49);
    const identity = if (hash == .sha256) "ticket-identity-sha256" else "ticket-identity-sha384";

    var zero_binder_storage = [_]u8{0} ** provider.max_digest_len;
    var ch_buf: [512]u8 = undefined;
    var fixture = try buildBinderFixture(hash, identity, zero_binder_storage[0..digest_len], &ch_buf);
    try expectStage("psk binder exact truncated ClientHello", expectedBinderTruncated(hash), fixture.truncated);

    var transcript_hash_storage: [provider.max_digest_len]u8 = undefined;
    const transcript_hash = transcript_hash_storage[0..digest_len];
    try hashBytes(hash, fixture.truncated, transcript_hash);
    try expectStage("psk binder exact transcript hash", expectedBinderTranscriptHash(hash), transcript_hash);
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "truncated-client-hello.bin", .data = fixture.truncated });
    const truncated_path = try tmp.dir.realPathFileAlloc(testing.io, "truncated-client-hello.bin", allocator);
    defer allocator.free(truncated_path);
    const openssl_transcript_hash = try opensslDigestFile(allocator, "psk binder truncated ClientHello hash", hash, truncated_path);
    defer allocator.free(openssl_transcript_hash);
    try expectStage("psk binder truncated ClientHello hash", transcript_hash, openssl_transcript_hash);

    const expected_binder = try opensslBinder(allocator, hash, psk, transcript_hash);
    defer allocator.free(expected_binder);
    try expectStage("psk binder exact binder bytes", expectedBinderBytes(hash), expected_binder);
    var from_transcript: [provider.max_digest_len]u8 = undefined;
    try pre_shared_key.deriveBinderFromTranscriptHash(hash, psk, transcript_hash, from_transcript[0..digest_len]);
    try expectStage("psk binder from transcript hash", expected_binder, from_transcript[0..digest_len]);
    var from_client_hello: [provider.max_digest_len]u8 = undefined;
    try pre_shared_key.deriveBinder(hash, psk, fixture.truncated, from_client_hello[0..digest_len]);
    try expectStage("psk binder from ClientHello", expected_binder, from_client_hello[0..digest_len]);

    fixture = try buildBinderFixture(hash, identity, expected_binder, &ch_buf);
    const parsed = try pre_shared_key.OfferedPsks.parse(fixture.ext_data);
    try testing.expectEqual(@as(usize, 1), parsed.count);
    try testing.expectEqual(parsed.binder_vector_offset + 2 + 1, fixture.slot.offset - (fixture.full.len - fixture.ext_data.len));
    var pairs = parsed.pairs();
    const pair = (try pairs.next()).?;
    try testing.expectEqualSlices(u8, identity, pair.identity.identity);
    try testing.expectEqualSlices(u8, expected_binder, pair.binder);
    try testing.expect(try pre_shared_key.verifyBinder(hash, psk, fixture.truncated, pair.binder));
    try testing.expect(try pre_shared_key.verifyBinderFromTranscriptHash(hash, psk, transcript_hash, pair.binder));
    try testing.expect((try pairs.next()) == null);

    var mutated_truncated = try allocator.dupe(u8, fixture.truncated);
    defer allocator.free(mutated_truncated);
    mutated_truncated[mutated_truncated.len - 1] ^= 0x01;
    try testing.expect(!try pre_shared_key.verifyBinder(hash, psk, mutated_truncated, pair.binder));

    var mutated_psk = psk_storage;
    mutated_psk[0] ^= 0x01;
    try testing.expect(!try pre_shared_key.verifyBinder(hash, mutated_psk[0..digest_len], fixture.truncated, pair.binder));

    var identity_mutated_buf: [512]u8 = undefined;
    const identity_mutated = try buildBinderFixture(hash, "mutated-ticket-identity", expected_binder, &identity_mutated_buf);
    try testing.expect(!try pre_shared_key.verifyBinder(hash, psk, identity_mutated.truncated, expected_binder));

    var bad_binder = try allocator.dupe(u8, expected_binder);
    defer allocator.free(bad_binder);
    bad_binder[0] ^= 0x80;
    try testing.expect(!try pre_shared_key.verifyBinder(hash, psk, fixture.truncated, bad_binder));
    try testing.expect(!try pre_shared_key.verifyBinder(hash, psk, fixture.truncated, bad_binder[0 .. bad_binder.len - 1]));

    var short: [provider.max_digest_len]u8 = undefined;
    try testing.expectError(error.InvalidSecretLength, pre_shared_key.deriveBinderFromTranscriptHash(hash, psk[0 .. digest_len - 1], transcript_hash, short[0..digest_len]));
    try testing.expectError(error.InvalidSecretLength, pre_shared_key.deriveBinderFromTranscriptHash(hash, psk, transcript_hash[0 .. digest_len - 1], short[0..digest_len]));
    try testing.expectError(error.InvalidSecretLength, pre_shared_key.deriveBinderFromTranscriptHash(hash, psk, transcript_hash, short[0 .. digest_len - 1]));
}

fn runPskBinderSha256(allocator: std.mem.Allocator) !void {
    try runPskBinderForHash(allocator, .sha256);
}

fn runPskBinderSha384(allocator: std.mem.Allocator) !void {
    try runPskBinderForHash(allocator, .sha384);
}

const ticket_aad_prefix = "tardigrade/tls-ticket/v1\x00";

fn makeTicketState(allocator: std.mem.Allocator, hash: provider.Hash) !session.ServerRecoverableState {
    const suite: tls_core.algorithms.CipherSuite = if (hash == .sha384) .tls_aes_256_gcm_sha384 else .tls_aes_128_gcm_sha256;
    var psk_storage: [provider.max_digest_len]u8 = undefined;
    const psk = psk_storage[0..hash.digestLength()];
    fillPattern(psk, if (hash == .sha384) 0x91 else 0x61);
    var common: session.ResumableSessionCommon = .{};
    defer common.deinit();
    try common.init(allocator, session.Limits.default, .{
        .cipher_suite = suite,
        .resumption_psk = psk,
        .server_name = "ticket.example",
        .application_protocol = "h3",
        .auth_binding = session.AuthBinding.fromLeafCertificateDer("ticket-fixture-leaf"),
        .issued_at_unix_ms = 1_000_000,
        .lifetime_seconds = 3600,
        .early_data = .{ .early_data_capable = 4096 },
        .transport_compat = .{ .format_id = 7, .format_version = 1, .bytes = "transport" },
        .application_compat = .{ .format_id = 9, .format_version = 2, .bytes = "application" },
    });
    var state: session.ServerRecoverableState = .{};
    state.init(&common, 0xa1b2c3d4);
    return state;
}

fn ticketKeyForAead(aead: provider.Aead) [provider.max_aead_key_len]u8 {
    var out: [provider.max_aead_key_len]u8 = undefined;
    fillPattern(out[0..aead.keyLength()], switch (aead) {
        .aes_128_gcm => 0x10,
        .aes_256_gcm => 0x20,
        .chacha20_poly1305 => 0x30,
    });
    return out;
}

fn buildTicketAad(header: []const u8, out: *[ticket_aad_prefix.len + ticket_protection.fixed_header_len]u8) void {
    @memcpy(out[0..ticket_aad_prefix.len], ticket_aad_prefix);
    @memcpy(out[ticket_aad_prefix.len..], header);
}

const expected_ticket_ciphertext_aes128 = hexBytes("c8a6da034a177480f14d9c792c1bce52d79b45d6ce6e9979a1ed932a0c19524c3e91a65ebc88ed4a707cb4fbed0243b33a9074c0a5113a09544c80b729f2bd1f982ce05146259033b7b7a60904bc295262fe725dabb59a77080ef7989961e00db923beeae0d126a966a4ce2bcd194ccdfb8a766fb9730d7225ca23dc42ae48ba73e816e95f68518478011d37e8a021bbc1d19101366bf0fddf9578def815624e0b7cec115fe2327339d9118d31d7fe9d01c366bb8b8ba08a8d");
const expected_ticket_ciphertext_aes256 = hexBytes("d44e63bba33981f43100d675d38184cfa2e23552c289cb8766278a3a9fd668f4722267bea776dc38304546ac8bcacb535cafa708fda436df0731009cc4c524277621ca9b26ffa25140e3c99f8c2536c63d9e04567c951de491165eead7e305edcf8d26ca7f6f0f826714c2dc50e733e6f8fb8074249d51fb16d38412945c7ddb62c7961ab592004c5dde614644695f102f063c535447b80fa1c50ed352fd2c9218ebcbd3595546e4e4c6dc28d7fec4cfcce89d5c5ffb64b556c0d92fb2cc5d73dd41c28c2bde82963c");
const expected_ticket_ciphertext_chacha20 = hexBytes("8e8db3658013fde33ef8a9ac26a49921417cac8b71e56e89d36bd4c4e90f742a289a4e7f72c09b70917b1f30cf25bdc313bfb3757cf9986ffd944344b6bf3f0f130338c820ead63b7ac2fe8e7de99e2775c099a5f169706cce41fc6f66677055294309168b1e30e82ed04f8ce47f1353840a20a69edcff463cb15506f7e7020ef725d37009aed9e533eb9048982f53a15638d7de4aaa1eaef0249cc846634d9c497866c7ac02dbbf95ae1aca51382a742c389cee2a3ae88997");
const expected_ticket_tag_aes128 = hexBytes("ba11b6e8aa17eb5ff5e035df9c1d1fe0");
const expected_ticket_tag_aes256 = hexBytes("132365a4fe41ecf4f36a1f6e4c667e3c");
const expected_ticket_tag_chacha20 = hexBytes("026dc5c35bf97bf642a3d5cf580a2a0a");
const expected_ticket_envelope_aes128 = hexBytes("5444544b0101000000112233445566778899aabbccddeeffa0a1a2a30000000000000377c8a6da034a177480f14d9c792c1bce52d79b45d6ce6e9979a1ed932a0c19524c3e91a65ebc88ed4a707cb4fbed0243b33a9074c0a5113a09544c80b729f2bd1f982ce05146259033b7b7a60904bc295262fe725dabb59a77080ef7989961e00db923beeae0d126a966a4ce2bcd194ccdfb8a766fb9730d7225ca23dc42ae48ba73e816e95f68518478011d37e8a021bbc1d19101366bf0fddf9578def815624e0b7cec115fe2327339d9118d31d7fe9d01c366bb8b8ba08a8dba11b6e8aa17eb5ff5e035df9c1d1fe0");
const expected_ticket_envelope_aes256 = hexBytes("5444544b0102000000112233445566778899aabbccddeeffa0a1a2a30000000000000377d44e63bba33981f43100d675d38184cfa2e23552c289cb8766278a3a9fd668f4722267bea776dc38304546ac8bcacb535cafa708fda436df0731009cc4c524277621ca9b26ffa25140e3c99f8c2536c63d9e04567c951de491165eead7e305edcf8d26ca7f6f0f826714c2dc50e733e6f8fb8074249d51fb16d38412945c7ddb62c7961ab592004c5dde614644695f102f063c535447b80fa1c50ed352fd2c9218ebcbd3595546e4e4c6dc28d7fec4cfcce89d5c5ffb64b556c0d92fb2cc5d73dd41c28c2bde82963c132365a4fe41ecf4f36a1f6e4c667e3c");
const expected_ticket_envelope_chacha20 = hexBytes("5444544b0103000000112233445566778899aabbccddeeffa0a1a2a300000000000003778e8db3658013fde33ef8a9ac26a49921417cac8b71e56e89d36bd4c4e90f742a289a4e7f72c09b70917b1f30cf25bdc313bfb3757cf9986ffd944344b6bf3f0f130338c820ead63b7ac2fe8e7de99e2775c099a5f169706cce41fc6f66677055294309168b1e30e82ed04f8ce47f1353840a20a69edcff463cb15506f7e7020ef725d37009aed9e533eb9048982f53a15638d7de4aaa1eaef0249cc846634d9c497866c7ac02dbbf95ae1aca51382a742c389cee2a3ae88997026dc5c35bf97bf642a3d5cf580a2a0a");

fn expectedTicketCiphertext(aead: provider.Aead) []const u8 {
    return switch (aead) {
        .aes_128_gcm => &expected_ticket_ciphertext_aes128,
        .aes_256_gcm => &expected_ticket_ciphertext_aes256,
        .chacha20_poly1305 => &expected_ticket_ciphertext_chacha20,
    };
}

fn expectedTicketTag(aead: provider.Aead) []const u8 {
    return switch (aead) {
        .aes_128_gcm => &expected_ticket_tag_aes128,
        .aes_256_gcm => &expected_ticket_tag_aes256,
        .chacha20_poly1305 => &expected_ticket_tag_chacha20,
    };
}

fn expectedTicketEnvelope(aead: provider.Aead) []const u8 {
    return switch (aead) {
        .aes_128_gcm => &expected_ticket_envelope_aes128,
        .aes_256_gcm => &expected_ticket_envelope_aes256,
        .chacha20_poly1305 => &expected_ticket_envelope_chacha20,
    };
}

fn expectTicketResolveMiss(protector: *ticket_protection.Protector, allocator: std.mem.Allocator, identity: []const u8) !void {
    var out: session.ServerRecoverableState = .{};
    defer out.deinit();
    try testing.expect(!try protector.resolve(allocator, identity, 1_500_000, &out));
    try testing.expectEqual(@as(usize, 0), out.common.resumption_psk.slice().len);
}

fn expectRawAeadAuthFailureParity(
    allocator: std.mem.Allocator,
    cp: provider.CryptoProvider,
    aead: provider.Aead,
    key: []const u8,
    nonce: []const u8,
    aad: []const u8,
    ciphertext: []const u8,
    tag: []const u8,
) !void {
    const plaintext = try allocator.alloc(u8, ciphertext.len);
    defer allocator.free(plaintext);
    try testing.expectError(error.AuthenticationFailed, cp.aeadOpen(aead, key, nonce, aad, ciphertext, tag, plaintext));
    var oracle = try runEvpAeadOpen(allocator, aead, key, nonce, aad, ciphertext, tag);
    defer oracle.deinit(allocator);
    try expectEvpStatus(&oracle, .auth_fail);
}

const CapabilityDenyProvider = struct {
    base: provider.CryptoProvider,
    denied_aead: provider.Aead,

    fn cryptoProvider(self: *CapabilityDenyProvider) provider.CryptoProvider {
        return .{ .context = self, .vtable = &vtable, .entropy = self.base.entropy };
    }

    fn fromContext(ctx: *anyopaque) *CapabilityDenyProvider {
        return @ptrCast(@alignCast(ctx));
    }

    fn capabilities(ctx: *anyopaque) provider.Capabilities {
        const me = fromContext(ctx);
        var caps = me.base.capabilities();
        caps.aeads.remove(me.denied_aead);
        return caps;
    }

    fn hkdfExtract(ctx: *anyopaque, hash: provider.Hash, salt: []const u8, ikm: []const u8, out: []u8) provider.HkdfError!void {
        return fromContext(ctx).base.hkdfExtract(hash, salt, ikm, out);
    }

    fn hkdfExpandLabel(ctx: *anyopaque, hash: provider.Hash, secret: []const u8, label: []const u8, hash_context: []const u8, out: []u8) provider.HkdfError!void {
        return fromContext(ctx).base.hkdfExpandLabel(hash, secret, label, hash_context, out);
    }

    fn aeadSeal(ctx: *anyopaque, aead: provider.Aead, key: []const u8, nonce: []const u8, associated_data: []const u8, plaintext: []const u8, ciphertext: []u8, tag: []u8) provider.SealError!void {
        return fromContext(ctx).base.aeadSeal(aead, key, nonce, associated_data, plaintext, ciphertext, tag);
    }

    fn aeadOpen(ctx: *anyopaque, aead: provider.Aead, key: []const u8, nonce: []const u8, associated_data: []const u8, ciphertext: []const u8, tag: []const u8, plaintext: []u8) provider.OpenError!void {
        return fromContext(ctx).base.aeadOpen(aead, key, nonce, associated_data, ciphertext, tag, plaintext);
    }

    fn quicHeaderProtectionMask(ctx: *anyopaque, hp: provider.QuicHeaderProtection, key: []const u8, sample: []const u8, mask: []u8) provider.QuicHeaderProtectionError!void {
        return fromContext(ctx).base.quicHeaderProtectionMask(hp, key, sample, mask);
    }

    fn generateKeyShare(ctx: *anyopaque, group: provider.Group, public_out: []u8, private_out: []u8) provider.KeyShareError!void {
        return fromContext(ctx).base.generateKeyShare(group, public_out, private_out);
    }

    fn deriveSharedSecret(ctx: *anyopaque, group: provider.Group, private_scalar: []const u8, peer_public: []const u8, out: []u8) provider.DeriveError!void {
        return fromContext(ctx).base.deriveSharedSecret(group, private_scalar, peer_public, out);
    }

    fn verify(ctx: *anyopaque, scheme: provider.SignatureScheme, public_key: []const u8, message: []const u8, signature: []const u8) provider.VerifyError!void {
        return fromContext(ctx).base.verify(scheme, public_key, message, signature);
    }

    const vtable = provider.CryptoProvider.VTable{
        .capabilities = capabilities,
        .hkdfExtract = hkdfExtract,
        .hkdfExpandLabel = hkdfExpandLabel,
        .aeadSeal = aeadSeal,
        .aeadOpen = aeadOpen,
        .quicHeaderProtectionMask = quicHeaderProtectionMask,
        .generateKeyShare = generateKeyShare,
        .deriveSharedSecret = deriveSharedSecret,
        .verify = verify,
    };
};

fn runProtectedTicketForAead(allocator: std.mem.Allocator, aead: provider.Aead) !void {
    const cp = cryptoProvider();
    const hash: provider.Hash = if (aead == .aes_256_gcm) .sha384 else .sha256;
    var state = try makeTicketState(allocator, hash);
    defer state.deinit();

    const key_id = hexBytes("00112233445566778899aabbccddeeff");
    var nonce = hexBytes("a0a1a2a30000000000000377");
    const key_storage = ticketKeyForAead(aead);
    const key = key_storage[0..aead.keyLength()];
    var plaintext_buf: [1024]u8 = undefined;
    const plaintext = try session.encodeServer(&state, session.Limits.default, &plaintext_buf);

    var header: [ticket_protection.fixed_header_len]u8 = undefined;
    @memcpy(header[0..4], &ticket_protection.magic);
    header[4] = ticket_protection.format_version;
    header[5] = ticket_protection.encodeAeadId(aead);
    std.mem.writeInt(u16, header[6..8], 0, .big);
    @memcpy(header[8..24], &key_id);
    @memcpy(header[24..36], &nonce);
    var aad: [ticket_aad_prefix.len + ticket_protection.fixed_header_len]u8 = undefined;
    buildTicketAad(&header, &aad);

    const native_ciphertext = try allocator.alloc(u8, plaintext.len);
    defer allocator.free(native_ciphertext);
    var native_tag: [provider.aead_tag_len]u8 = undefined;
    try cp.aeadSeal(aead, key, &nonce, &aad, plaintext, native_ciphertext, &native_tag);
    var oracle = try runEvpAeadSeal(allocator, aead, key, &nonce, &aad, plaintext);
    defer oracle.deinit(allocator);
    try expectEvpStatus(&oracle, .ok);
    try expectStage("protected ticket provider ciphertext", native_ciphertext, oracle.fields[0].?);
    try expectStage("protected ticket provider tag", &native_tag, oracle.fields[1].?);
    try expectStage("protected ticket pinned ciphertext", expectedTicketCiphertext(aead), native_ciphertext);
    try expectStage("protected ticket pinned tag", expectedTicketTag(aead), &native_tag);

    var expected_envelope = try allocator.alloc(u8, ticket_protection.fixed_header_len + plaintext.len + provider.aead_tag_len);
    defer allocator.free(expected_envelope);
    @memcpy(expected_envelope[0..ticket_protection.fixed_header_len], &header);
    @memcpy(expected_envelope[ticket_protection.fixed_header_len..][0..plaintext.len], native_ciphertext);
    @memcpy(expected_envelope[ticket_protection.fixed_header_len + plaintext.len ..], &native_tag);
    try expectStage("protected ticket pinned envelope", expectedTicketEnvelope(aead), expected_envelope);

    const parsed = try ticket_protection.parseEnvelope(expected_envelope, session.Limits.default);
    try testing.expectEqual(aead, parsed.aead);
    try testing.expectEqualSlices(u8, &ticket_protection.magic, expected_envelope[0..4]);
    try testing.expectEqual(@as(u8, 1), expected_envelope[4]);
    try testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, expected_envelope[6..8], .big));
    try testing.expectEqual(@as(u8, 1), ticket_protection.encodeAeadId(.aes_128_gcm));
    try testing.expectEqual(@as(u8, 2), ticket_protection.encodeAeadId(.aes_256_gcm));
    try testing.expectEqual(@as(u8, 3), ticket_protection.encodeAeadId(.chacha20_poly1305));
    try testing.expectEqualSlices(u8, &key_id, &parsed.key_id);
    try testing.expectEqualSlices(u8, &nonce, &parsed.nonce);

    var keyring = ticket_protection.ReloadableKeyRing.init(allocator);
    defer keyring.deinit();
    const config = ticket_protection.KeyConfig{
        .id = key_id,
        .aead = aead,
        .key_bytes = key,
        .not_before_unix_ms = 0,
        .encrypt_until_unix_ms = 2_000_000,
        .decrypt_until_unix_ms = 10_000_000,
        .nonce_lease = .{ .prefix = nonce[0..4].*, .start = 0x377, .end_exclusive = 0x378 },
    };
    const snapshot = try keyring.buildSnapshot(&.{config}, cp.capabilities());
    try keyring.install(snapshot);
    var protector = ticket_protection.Protector{ .provider = cp, .keyring = &keyring, .limits = session.Limits.default };
    try testing.expectEqual(expected_envelope.len, try protector.protectedLen(&state));
    var sealed_buf: [2048]u8 = undefined;
    const sealed = try protector.seal(allocator, &state, 1_500_000, &sealed_buf);
    try expectStage("protected ticket complete envelope", expected_envelope, sealed);

    var recovered: session.ServerRecoverableState = .{};
    defer recovered.deinit();
    try testing.expect(try protector.resolve(allocator, sealed, 1_500_000, &recovered));
    var recovered_plaintext_buf: [1024]u8 = undefined;
    const recovered_plaintext = try session.encodeServer(&recovered, session.Limits.default, &recovered_plaintext_buf);
    try expectStage("protected ticket recovered canonical state", plaintext, recovered_plaintext);

    var bad_tag = try allocator.dupe(u8, sealed);
    defer allocator.free(bad_tag);
    bad_tag[bad_tag.len - 1] ^= 0x01;
    try expectRawAeadAuthFailureParity(allocator, cp, aead, key, &nonce, &aad, parsed.ciphertext, bad_tag[bad_tag.len - provider.aead_tag_len ..]);
    try expectTicketResolveMiss(&protector, allocator, bad_tag);

    var bad_ciphertext = try allocator.dupe(u8, sealed);
    defer allocator.free(bad_ciphertext);
    bad_ciphertext[ticket_protection.fixed_header_len] ^= 0x01;
    try expectRawAeadAuthFailureParity(allocator, cp, aead, key, &nonce, &aad, bad_ciphertext[ticket_protection.fixed_header_len .. bad_ciphertext.len - provider.aead_tag_len], parsed.tag);
    try expectTicketResolveMiss(&protector, allocator, bad_ciphertext);

    var bad_header = try allocator.dupe(u8, sealed);
    defer allocator.free(bad_header);
    bad_header[24] ^= 0x01;
    try expectTicketResolveMiss(&protector, allocator, bad_header);

    var wrong_aead = try allocator.dupe(u8, sealed);
    defer allocator.free(wrong_aead);
    wrong_aead[5] = if (aead == .aes_128_gcm) ticket_protection.encodeAeadId(.aes_256_gcm) else ticket_protection.encodeAeadId(.aes_128_gcm);
    try expectTicketResolveMiss(&protector, allocator, wrong_aead);

    var bad_aad = aad;
    bad_aad[bad_aad.len - 1] ^= 0x01;
    try expectRawAeadAuthFailureParity(allocator, cp, aead, key, &nonce, &bad_aad, parsed.ciphertext, parsed.tag);

    var truncated_ciphertext = try allocator.alloc(u8, sealed.len - 1);
    defer allocator.free(truncated_ciphertext);
    @memcpy(truncated_ciphertext[0..ticket_protection.fixed_header_len], sealed[0..ticket_protection.fixed_header_len]);
    @memcpy(truncated_ciphertext[ticket_protection.fixed_header_len..][0 .. plaintext.len - 1], sealed[ticket_protection.fixed_header_len..][0 .. plaintext.len - 1]);
    @memcpy(truncated_ciphertext[ticket_protection.fixed_header_len + plaintext.len - 1 ..], sealed[ticket_protection.fixed_header_len + plaintext.len ..]);
    try expectTicketResolveMiss(&protector, allocator, truncated_ciphertext);
    try expectTicketResolveMiss(&protector, allocator, sealed[0 .. sealed.len - 1]);

    var wrong_keyring = ticket_protection.ReloadableKeyRing.init(allocator);
    defer wrong_keyring.deinit();
    var wrong_key_storage = key_storage;
    wrong_key_storage[0] ^= 0x44;
    var wrong_config = config;
    wrong_config.key_bytes = wrong_key_storage[0..aead.keyLength()];
    wrong_config.nonce_lease = null;
    const wrong_snapshot = try wrong_keyring.buildSnapshot(&.{wrong_config}, cp.capabilities());
    try wrong_keyring.install(wrong_snapshot);
    var wrong_protector = ticket_protection.Protector{ .provider = cp, .keyring = &wrong_keyring, .limits = session.Limits.default };
    try expectTicketResolveMiss(&wrong_protector, allocator, sealed);

    var deny = CapabilityDenyProvider{ .base = cp, .denied_aead = aead };
    var unsupported_protector = ticket_protection.Protector{ .provider = deny.cryptoProvider(), .keyring = &keyring, .limits = session.Limits.default };
    var unsupported_out: session.ServerRecoverableState = .{};
    defer unsupported_out.deinit();
    try testing.expectError(error.UnsupportedCapability, unsupported_protector.resolve(allocator, sealed, 1_500_000, &unsupported_out));

    var opened = try runEvpAeadOpen(allocator, aead, key, &nonce, &aad, parsed.ciphertext, parsed.tag);
    defer opened.deinit(allocator);
    try expectEvpStatus(&opened, .ok);
    try expectStage("protected ticket oracle open plaintext", plaintext, opened.fields[0].?);
}

fn runProtectedTicketAes128(allocator: std.mem.Allocator) !void {
    try runProtectedTicketForAead(allocator, .aes_128_gcm);
}

fn runProtectedTicketAes256(allocator: std.mem.Allocator) !void {
    try runProtectedTicketForAead(allocator, .aes_256_gcm);
}

fn runProtectedTicketChacha20(allocator: std.mem.Allocator) !void {
    try runProtectedTicketForAead(allocator, .chacha20_poly1305);
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
    var zig_initial = try quic.tls_adapter.deriveInitialSecretsV1(&dcid);
    defer zig_initial.deinit();
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
    try expectStage("quic client initial secret", zig_initial.client.secret.slice(), openssl_client_secret);

    const openssl_server_secret = try opensslHkdfExpandLabel(allocator, "quic server initial secret", .sha256, openssl_initial, "server in", "", quic_secret_len);
    defer allocator.free(openssl_server_secret);
    try expectStage("quic server initial secret", zig_initial.server.secret.slice(), openssl_server_secret);

    const openssl_client_key = try opensslHkdfExpandLabel(allocator, "quic client initial key", .sha256, openssl_client_secret, "quic key", "", quic_key_len);
    defer allocator.free(openssl_client_key);
    try expectStage("quic client initial key", zig_initial.client.key.slice(), openssl_client_key);

    const openssl_client_iv = try opensslHkdfExpandLabel(allocator, "quic client initial iv", .sha256, openssl_client_secret, "quic iv", "", quic_iv_len);
    defer allocator.free(openssl_client_iv);
    try expectStage("quic client initial iv", zig_initial.client.iv.slice(), openssl_client_iv);

    const openssl_client_hp = try opensslHkdfExpandLabel(allocator, "quic client initial hp", .sha256, openssl_client_secret, "quic hp", "", quic_hp_len);
    defer allocator.free(openssl_client_hp);
    try expectStage("quic client initial hp", zig_initial.client.hp.slice(), openssl_client_hp);

    const openssl_server_key = try opensslHkdfExpandLabel(allocator, "quic server initial key", .sha256, openssl_server_secret, "quic key", "", quic_key_len);
    defer allocator.free(openssl_server_key);
    try expectStage("quic server initial key", zig_initial.server.key.slice(), openssl_server_key);

    const openssl_server_iv = try opensslHkdfExpandLabel(allocator, "quic server initial iv", .sha256, openssl_server_secret, "quic iv", "", quic_iv_len);
    defer allocator.free(openssl_server_iv);
    try expectStage("quic server initial iv", zig_initial.server.iv.slice(), openssl_server_iv);

    const openssl_server_hp = try opensslHkdfExpandLabel(allocator, "quic server initial hp", .sha256, openssl_server_secret, "quic hp", "", quic_hp_len);
    defer allocator.free(openssl_server_hp);
    try expectStage("quic server initial hp", zig_initial.server.hp.slice(), openssl_server_hp);
}

test "OpenSSL HKDF oracle matches QUIC production initial derivation" {
    try runQuicInitial(testing.allocator);
}

const sha256_digest_len = provider.Hash.sha256.digestLength();

fn fillSyntheticHrr(
    out: []u8,
    ch1_hash: *const [sha256_digest_len]u8,
    hello_retry_request: []const u8,
    client_hello_2: []const u8,
) void {
    out[0] = 0xfe;
    std.mem.writeInt(u24, out[1..4], sha256_digest_len, .big);
    @memcpy(out[4..][0..sha256_digest_len], ch1_hash);
    var offset: usize = 4 + sha256_digest_len;
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
    transcript.selectFamily(.sha256);
    try transcript.update(&client_hello_1);
    const zig_ch1_digest = transcript.peek();
    const zig_ch1_hash = zig_ch1_digest.bytes[0..sha256_digest_len].*;
    try expectOpenSslSha256File(allocator, "tls transcript ClientHello1 hash", zig_ch1_digest.slice(), client_hello_path);

    const hello_retry_request = hexBytes("02000002cf21");
    var client_hello_2 = hexBytes("01000002ddee");
    transcript.replace(zig_ch1_digest);
    try transcript.update(&hello_retry_request);
    try transcript.update(&client_hello_2);
    const zig_hrr_digest = transcript.peek();
    const zig_hrr_hash = zig_hrr_digest.bytes[0..sha256_digest_len].*;

    var synthetic_and_hrr: [4 + sha256_digest_len + hello_retry_request.len + client_hello_2.len]u8 = undefined;
    fillSyntheticHrr(&synthetic_and_hrr, &zig_ch1_hash, &hello_retry_request, &client_hello_2);
    try tmp.dir.writeFile(io, .{ .sub_path = "synthetic_hrr.bin", .data = &synthetic_and_hrr });
    const synthetic_hrr_path = try tmp.dir.realPathFileAlloc(io, "synthetic_hrr.bin", allocator);
    defer allocator.free(synthetic_hrr_path);
    try expectOpenSslSha256File(allocator, "tls transcript HRR hash", zig_hrr_digest.slice(), synthetic_hrr_path);

    const traffic_secret = hexBytes("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38");
    try tmp.dir.writeFile(io, .{ .sub_path = "finished_hash.bin", .data = &zig_hrr_hash });
    const finished_hash_path = try tmp.dir.realPathFileAlloc(io, "finished_hash.bin", allocator);
    defer allocator.free(finished_hash_path);

    var zig_finished_key: [sha256_digest_len]u8 = undefined;
    try KeySchedule.finishedKey(cp, .sha256, &traffic_secret, &zig_finished_key);
    defer std.crypto.secureZero(u8, &zig_finished_key);
    const openssl_finished_key = try opensslHkdfExpandLabel(allocator, "tls13 server Finished key", .sha256, &traffic_secret, "finished", "", provider.Hash.sha256.digestLength());
    defer allocator.free(openssl_finished_key);
    try expectStage("tls13 server Finished key", &zig_finished_key, openssl_finished_key);

    const openssl_verify_data = try opensslHmacSha256File(allocator, "tls13 server Finished verify_data", openssl_finished_key, finished_hash_path);
    defer allocator.free(openssl_verify_data);
    var zig_verify_data: [sha256_digest_len]u8 = undefined;
    try KeySchedule.verifyData(cp, .sha256, &traffic_secret, &zig_hrr_hash, &zig_verify_data);
    defer std.crypto.secureZero(u8, &zig_verify_data);
    try expectStage("tls13 server Finished verify_data", &zig_verify_data, openssl_verify_data);

    client_hello_2[client_hello_2.len - 1] ^= 0x01;
    var mutated_transcript = tls_core.transcript.Transcript{};
    mutated_transcript.selectFamily(.sha256);
    try mutated_transcript.update(&client_hello_1);
    const mutated_ch1_digest = mutated_transcript.peek();
    const mutated_ch1_hash = mutated_ch1_digest.bytes[0..sha256_digest_len].*;
    try expectStage("tls transcript mutated ClientHello1 stable hash", &zig_ch1_hash, &mutated_ch1_hash);
    mutated_transcript.replace(mutated_ch1_digest);
    try mutated_transcript.update(&hello_retry_request);
    try mutated_transcript.update(&client_hello_2);
    const zig_mutated_hrr_digest = mutated_transcript.peek();
    const zig_mutated_hrr_hash = zig_mutated_hrr_digest.bytes[0..sha256_digest_len].*;

    fillSyntheticHrr(&synthetic_and_hrr, &zig_ch1_hash, &hello_retry_request, &client_hello_2);
    try tmp.dir.writeFile(io, .{ .sub_path = "synthetic_hrr_mutated.bin", .data = &synthetic_and_hrr });
    const synthetic_hrr_mutated_path = try tmp.dir.realPathFileAlloc(io, "synthetic_hrr_mutated.bin", allocator);
    defer allocator.free(synthetic_hrr_mutated_path);
    try expectOpenSslSha256File(allocator, "tls transcript HRR mutated hash", zig_mutated_hrr_digest.slice(), synthetic_hrr_mutated_path);

    try tmp.dir.writeFile(io, .{ .sub_path = "finished_hash_mutated.bin", .data = &zig_mutated_hrr_hash });
    const finished_hash_mutated_path = try tmp.dir.realPathFileAlloc(io, "finished_hash_mutated.bin", allocator);
    defer allocator.free(finished_hash_mutated_path);
    const openssl_mutated_verify_data = try opensslHmacSha256File(allocator, "tls13 server Finished mutated verify_data", openssl_finished_key, finished_hash_mutated_path);
    defer allocator.free(openssl_mutated_verify_data);
    var zig_mutated_verify_data: [sha256_digest_len]u8 = undefined;
    try KeySchedule.verifyData(cp, .sha256, &traffic_secret, &zig_mutated_hrr_hash, &zig_mutated_verify_data);
    defer std.crypto.secureZero(u8, &zig_mutated_verify_data);
    try expectStage("tls13 server Finished mutated verify_data", &zig_mutated_verify_data, openssl_mutated_verify_data);
    var stable_verify_data: [sha256_digest_len]u8 = undefined;
    try KeySchedule.verifyData(cp, .sha256, &traffic_secret, &zig_hrr_hash, &stable_verify_data);
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
    try expectCoverageOrWaiver(.resumption_master_secret, .{ .hkdf = .sha256 }, .positive);
    try expectCoverageOrWaiver(.resumption_master_secret, .{ .hkdf = .sha256 }, .negative);
    try expectCoverageOrWaiver(.resumption_master_secret, .{ .hkdf = .sha384 }, .positive);
    try expectCoverageOrWaiver(.resumption_master_secret, .{ .hkdf = .sha384 }, .negative);
    try expectCoverageOrWaiver(.resumption_psk, .{ .hkdf = .sha256 }, .positive);
    try expectCoverageOrWaiver(.resumption_psk, .{ .hkdf = .sha256 }, .negative);
    try expectCoverageOrWaiver(.resumption_psk, .{ .hkdf = .sha384 }, .positive);
    try expectCoverageOrWaiver(.resumption_psk, .{ .hkdf = .sha384 }, .negative);
    try expectCoverageOrWaiver(.psk_binder, .{ .hkdf = .sha256 }, .positive);
    try expectCoverageOrWaiver(.psk_binder, .{ .hkdf = .sha256 }, .negative);
    try expectCoverageOrWaiver(.psk_binder, .{ .hkdf = .sha384 }, .positive);
    try expectCoverageOrWaiver(.psk_binder, .{ .hkdf = .sha384 }, .negative);
    try expectCoverageOrWaiver(.protected_ticket, .{ .aead = .aes_128_gcm }, .positive);
    try expectCoverageOrWaiver(.protected_ticket, .{ .aead = .aes_128_gcm }, .negative);
    try expectCoverageOrWaiver(.protected_ticket, .{ .aead = .aes_256_gcm }, .positive);
    try expectCoverageOrWaiver(.protected_ticket, .{ .aead = .aes_256_gcm }, .negative);
    try expectCoverageOrWaiver(.protected_ticket, .{ .aead = .chacha20_poly1305 }, .positive);
    try expectCoverageOrWaiver(.protected_ticket, .{ .aead = .chacha20_poly1305 }, .negative);
    try expectCoverageOrWaiver(.key_exchange, .{ .group = .x25519 }, .positive);
    try expectCoverageOrWaiver(.key_exchange, .{ .group = .x25519 }, .negative);
    try expectCoverageOrWaiver(.key_exchange, .{ .group = .secp256r1 }, .positive);
    try expectCoverageOrWaiver(.key_exchange, .{ .group = .secp256r1 }, .negative);
    try expectCoverageOrWaiver(.signature_sign, .{ .signature = .ed25519 }, .positive);
    try expectCoverageOrWaiver(.signature_sign, .{ .signature = .ecdsa_secp256r1_sha256 }, .positive);
    try expectCoverageOrWaiver(.signature_sign, .{ .signature = .rsa_pss_rsae_sha256 }, .positive);
    try expectCoverageOrWaiver(.signature_verify, .{ .signature = .ed25519 }, .positive);
    try expectCoverageOrWaiver(.signature_verify, .{ .signature = .ed25519 }, .negative);
    try expectCoverageOrWaiver(.signature_verify, .{ .signature = .ecdsa_secp256r1_sha256 }, .positive);
    try expectCoverageOrWaiver(.signature_verify, .{ .signature = .ecdsa_secp256r1_sha256 }, .negative);
    try expectCoverageOrWaiver(.rsa_pss_verify, .{ .signature = .rsa_pss_rsae_sha256 }, .positive);
    try expectCoverageOrWaiver(.rsa_pss_verify, .{ .signature = .rsa_pss_rsae_sha256 }, .negative);
}

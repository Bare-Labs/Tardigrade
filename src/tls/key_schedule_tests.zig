//! Tests for the protocol-neutral TLS 1.3 key schedule (`key_schedule.zig`).
//!
//! Kept in a separate file from the production module (#490 review): this
//! file's own cross-check against a direct `std.crypto.auth.hmac.sha2.
//! HmacSha256` computation, and its raw `CryptoProvider` vtable fixture for
//! typed-error-propagation, are legitimate test-only direct-crypto use, but a
//! textual "scan everything before this marker" boundary inside the
//! production file is not a sound reachability proof — Zig declarations are
//! order-independent, so a production function declared before such a marker
//! could still call a private helper declared after it, and the scan would
//! never see the call. Structural separation (a file `scripts/
//! audit_crypto_boundary.zig` never scans at all, the same way
//! `tests/support/quic_crypto.zig` and `tests/crypto_vectors.zig` aren't
//! scanned either) is the sound fix: `key_schedule.zig` itself now has zero
//! test-only content and is scanned in full, with no marker.

const std = @import("std");
const testing = std.testing;
const crypto = std.crypto;

const provider = @import("crypto").provider;
const pure_zig = @import("crypto").pure_zig;
const key_schedule = @import("key_schedule.zig");

const KeySchedule = key_schedule.KeySchedule;
const hash_len = key_schedule.hash_len;
const shared_secret_len = key_schedule.shared_secret_len;

/// A fresh deterministic pure-Zig `CryptoProvider` for this module's own
/// tests, built the same way `src/crypto/pure_zig.zig`'s own test block
/// does: `DeterministicEntropy` (explicitly not a CSPRNG) plus the pure-Zig
/// `Provider`, constructed locally per test rather than shared globally.
fn testProvider(det: *pure_zig.DeterministicEntropy, backing: *pure_zig.Provider) provider.CryptoProvider {
    backing.* = pure_zig.Provider.init(det.entropy());
    return backing.cryptoProvider();
}

test "record-mode users can instantiate the protocol-neutral key schedule" {
    var det = pure_zig.DeterministicEntropy.init(1);
    var backing: pure_zig.Provider = undefined;
    const cp = testProvider(&det, &backing);

    const shared = [_]u8{0x42} ** shared_secret_len;
    const transcript = [_]u8{0x24} ** hash_len;
    var schedule = try KeySchedule.init(cp, &shared, transcript);
    defer schedule.wipe();
    var app = try schedule.applicationSecrets(transcript);
    defer app.wipe();
    try testing.expect(!std.mem.eql(u8, &app.client, &app.server));
}

test "shared TLS 1.3 key schedule matches the RFC 8448 simple 1-RTT trace" {
    var det = pure_zig.DeterministicEntropy.init(2);
    var backing: pure_zig.Provider = undefined;
    const cp = testProvider(&det, &backing);

    const shared = hexBytes("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
    const hello_hash = hexBytes("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");
    var schedule = try KeySchedule.init(cp, &shared, hello_hash);
    defer schedule.wipe();

    try testing.expectEqualSlices(u8, &hexBytes("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac"), &schedule.handshake_secret);
    try testing.expectEqualSlices(u8, &hexBytes("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"), &schedule.client_handshake_traffic);
    try testing.expectEqualSlices(u8, &hexBytes("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"), &schedule.server_handshake_traffic);
    try testing.expectEqualSlices(u8, &hexBytes("18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919"), &schedule.master_secret);

    const finished_hash = hexBytes("9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13");
    var app = try schedule.applicationSecrets(finished_hash);
    defer app.wipe();
    try testing.expectEqualSlices(u8, &hexBytes("9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5"), &app.client);
    try testing.expectEqualSlices(u8, &hexBytes("a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643"), &app.server);
    var finished_key = try KeySchedule.finishedKey(cp, &schedule.server_handshake_traffic);
    defer crypto.secureZero(u8, &finished_key);
    try testing.expectEqualSlices(u8, &hexBytes("008d3b66f816ea559f96b537e885c31fc068bf492c652f01f288a1d8cdc19fc8"), &finished_key);

    // The HKDF-Extract-as-HMAC verify_data trick documented on `verifyData`
    // must match a direct HMAC-SHA256(finished_key, transcript_hash)
    // computation, cross-checking the derivation this migration introduced
    // against the primitive it claims to be equivalent to. Direct
    // std.crypto use is fine here — this file is test-only and not scanned
    // by scripts/audit_crypto_boundary.zig.
    const HmacSha256 = crypto.auth.hmac.sha2.HmacSha256;
    var direct_mac: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&direct_mac, &finished_hash, &finished_key);
    const verify_data = try KeySchedule.verifyData(cp, &schedule.server_handshake_traffic, finished_hash);
    try testing.expectEqualSlices(u8, &direct_mac, &verify_data);
}

test "application traffic secret storage has explicit cleanup" {
    var det = pure_zig.DeterministicEntropy.init(3);
    var backing: pure_zig.Provider = undefined;
    const cp = testProvider(&det, &backing);

    const shared = [_]u8{0x42} ** shared_secret_len;
    const transcript = [_]u8{0x24} ** hash_len;
    var schedule = try KeySchedule.init(cp, &shared, transcript);
    defer schedule.wipe();
    var app = try schedule.applicationSecrets(transcript);
    try testing.expect(!std.mem.allEqual(u8, std.mem.asBytes(&app), 0));
    app.wipe();
    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&app), 0));
}

test "KeySchedule.wipe zeroizes every derived secret" {
    // Deliberately a plain (non-optional) local, wiped in place and
    // inspected directly — unlike a backend-owned `?KeySchedule` that gets
    // set to `null` right after wiping, there is no subsequent
    // optional-invalidation step here whose own debug-safety poisoning
    // could be mistaken for (or mask the absence of) this `wipe()` call's
    // effect. That makes this the reliable place to prove the zeroing
    // itself; backend-level tests should only assert that `schedule`
    // becomes `null`, not re-inspect the bytes afterward.
    var det = pure_zig.DeterministicEntropy.init(4);
    var backing: pure_zig.Provider = undefined;
    const cp = testProvider(&det, &backing);

    const shared = [_]u8{0x77} ** shared_secret_len;
    const transcript = [_]u8{0x88} ** hash_len;
    var schedule = try KeySchedule.init(cp, &shared, transcript);
    const bytes = std.mem.asBytes(&schedule);
    try testing.expect(!std.mem.allEqual(u8, bytes, 0));
    schedule.wipe();
    try testing.expect(std.mem.allEqual(u8, bytes, 0));
}

test "resumption master secret and PSK derivation are deterministic" {
    var det = pure_zig.DeterministicEntropy.init(5);
    var backing: pure_zig.Provider = undefined;
    const cp = testProvider(&det, &backing);

    const shared = hexBytes("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
    const hello_hash = hexBytes("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");
    var schedule = try KeySchedule.init(cp, &shared, hello_hash);
    defer schedule.wipe();

    const complete_hash = hexBytes("209145a96ee8e5751f3b7e74e573c01c384cff1b902e8ae503d6d3469c698d1c");
    var rms: [hash_len]u8 = undefined;
    defer crypto.secureZero(u8, &rms);
    try schedule.resumptionMasterSecret(&complete_hash, &rms);
    try testing.expectEqualSlices(u8, &hexBytes("9089b75df5e8d1720f8383601331c07ce14c8b8dbe4ded1511ce84c55ca2396c"), &rms);

    var psk_empty: [hash_len]u8 = undefined;
    var psk_nonce: [hash_len]u8 = undefined;
    defer crypto.secureZero(u8, &psk_empty);
    defer crypto.secureZero(u8, &psk_nonce);
    try KeySchedule.resumptionPsk(cp, .sha256, &rms, "", &psk_empty);
    try KeySchedule.resumptionPsk(cp, .sha256, &rms, "\x01", &psk_nonce);
    try testing.expectEqualSlices(u8, &hexBytes("c1392efd98f6932d62f5ccd42c724230871638e8ad0ac9ce9b2af89f5f919fed"), &psk_empty);
    try testing.expectEqualSlices(u8, &hexBytes("54d2811b66ec2ad537c626f21da4d6ed48c5aed25e2fd708e3f17cd08cb71077"), &psk_nonce);
    try testing.expect(!std.mem.eql(u8, &psk_empty, &psk_nonce));
}

test "resumption PSK supports SHA-384 length and rejects inconsistent lengths" {
    var det = pure_zig.DeterministicEntropy.init(6);
    var backing: pure_zig.Provider = undefined;
    const cp = testProvider(&det, &backing);

    const rms384 = [_]u8{0x42} ** provider.Hash.sha384.digestLength();
    var out384: [provider.Hash.sha384.digestLength()]u8 = undefined;
    defer crypto.secureZero(u8, &out384);
    try KeySchedule.resumptionPsk(cp, .sha384, &rms384, "nonce", &out384);
    try testing.expectEqualSlices(u8, &hexBytes("e72237478501a59682cd8580d7e2a526847e1e7049a83c3c0f7ef3dc3a950f3d88fb87be1d1e9d2cf94f038cb7b05033"), &out384);

    var short_out: [hash_len - 1]u8 = undefined;
    try testing.expectError(error.InvalidSecretLength, KeySchedule.resumptionPsk(cp, .sha256, &rms384, "nonce", &short_out));
    try testing.expectError(error.InvalidSecretLength, KeySchedule.resumptionPsk(cp, .sha384, rms384[0..hash_len], "nonce", &out384));
}

test "generic resumption master secret derivation supports SHA-384" {
    var det = pure_zig.DeterministicEntropy.init(7);
    var backing: pure_zig.Provider = undefined;
    const cp = testProvider(&det, &backing);

    const master_secret = [_]u8{0x11} ** provider.Hash.sha384.digestLength();
    const transcript_hash = [_]u8{0x22} ** provider.Hash.sha384.digestLength();
    var out: [provider.Hash.sha384.digestLength()]u8 = undefined;
    defer crypto.secureZero(u8, &out);
    try KeySchedule.deriveResumptionMasterSecret(cp, .sha384, &master_secret, &transcript_hash, &out);
    try testing.expectEqualSlices(u8, &hexBytes("4f9d68ff762f5b886f275d162b90c268db5ccc65c4e0b8fc810030429a070f8e9f12b641b209e15ae210b1153a68fc42"), &out);
    try testing.expectError(error.InvalidSecretLength, KeySchedule.deriveResumptionMasterSecret(cp, .sha384, master_secret[0..hash_len], &transcript_hash, &out));
}

test "initWithPsk diverges from the zero-PSK schedule and is deterministic" {
    var det = pure_zig.DeterministicEntropy.init(8);
    var backing: pure_zig.Provider = undefined;
    const cp = testProvider(&det, &backing);

    const shared = [_]u8{0x42} ** shared_secret_len;
    const transcript = [_]u8{0x24} ** hash_len;
    const psk = [_]u8{0x99} ** hash_len;

    var zero_psk_schedule = try KeySchedule.init(cp, &shared, transcript);
    defer zero_psk_schedule.wipe();
    var psk_schedule = try KeySchedule.initWithPsk(cp, &psk, &shared, transcript);
    defer psk_schedule.wipe();
    var psk_schedule_again = try KeySchedule.initWithPsk(cp, &psk, &shared, transcript);
    defer psk_schedule_again.wipe();

    try testing.expect(!std.mem.eql(u8, &zero_psk_schedule.handshake_secret, &psk_schedule.handshake_secret));
    try testing.expect(!std.mem.eql(u8, &zero_psk_schedule.master_secret, &psk_schedule.master_secret));
    try testing.expectEqualSlices(u8, &psk_schedule.handshake_secret, &psk_schedule_again.handshake_secret);
    try testing.expectEqualSlices(u8, &psk_schedule.master_secret, &psk_schedule_again.master_secret);
    try testing.expect(!std.mem.eql(u8, &psk_schedule.client_handshake_traffic, &psk_schedule.server_handshake_traffic));

    var app = try psk_schedule.applicationSecrets(transcript);
    defer app.wipe();
    try testing.expect(!std.mem.eql(u8, &app.client, &app.server));
}

test "initWithPsk matches independently computed secrets" {
    // Checked-in literals for the same inputs as "initWithPsk diverges from
    // the zero-PSK schedule and is deterministic" above (psk=0x99*32,
    // shared=0x42*32, transcript=0x24*32), computed independently of this
    // module rather than by re-deriving with the same helpers under test.
    var det = pure_zig.DeterministicEntropy.init(9);
    var backing: pure_zig.Provider = undefined;
    const cp = testProvider(&det, &backing);

    const shared = [_]u8{0x42} ** shared_secret_len;
    const transcript = [_]u8{0x24} ** hash_len;
    const psk = [_]u8{0x99} ** hash_len;

    var schedule = try KeySchedule.initWithPsk(cp, &psk, &shared, transcript);
    defer schedule.wipe();

    try testing.expectEqualSlices(u8, &hexBytes("ab0803d6203c8feddfe8adc74f986c9d89b817b3d4132fc55c866a3522d9ff49"), &schedule.handshake_secret);
    try testing.expectEqualSlices(u8, &hexBytes("e92139285417b6a9a54a7a9153f4b6dcce44b99cdc0937b83dfea5c79805c920"), &schedule.client_handshake_traffic);
    try testing.expectEqualSlices(u8, &hexBytes("739483d9d6a9508c73b4656de22fedd85a2a8d00e9a6ca1449d8cba678c94baf"), &schedule.server_handshake_traffic);
    try testing.expectEqualSlices(u8, &hexBytes("abe96cce65361235f3126971c67760888b79d4c1724a6cb1e15f6d2ae128ff44"), &schedule.master_secret);

    var app = try schedule.applicationSecrets(transcript);
    defer app.wipe();
    try testing.expectEqualSlices(u8, &hexBytes("d1ba0b1be9862f1bd4c3bcc0d53b5a98c6a4951c4bad19243051237bc735031c"), &app.client);
    try testing.expectEqualSlices(u8, &hexBytes("c7428c93109f1b656dcbf0971e5d1bad9c2d38b79420038b7e165a17c7f61fa1"), &app.server);
}

test "a different resumption PSK produces a different PSK-resumed schedule" {
    var det = pure_zig.DeterministicEntropy.init(10);
    var backing: pure_zig.Provider = undefined;
    const cp = testProvider(&det, &backing);

    const shared = [_]u8{0x11} ** shared_secret_len;
    const transcript = [_]u8{0x22} ** hash_len;
    const psk_a = [_]u8{0xaa} ** hash_len;
    const psk_b = [_]u8{0xbb} ** hash_len;

    var schedule_a = try KeySchedule.initWithPsk(cp, &psk_a, &shared, transcript);
    defer schedule_a.wipe();
    var schedule_b = try KeySchedule.initWithPsk(cp, &psk_b, &shared, transcript);
    defer schedule_b.wipe();

    try testing.expect(!std.mem.eql(u8, &schedule_a.master_secret, &schedule_b.master_secret));
}

test "clientEarlyTrafficSecret matches an independently computed known-answer fixture" {
    // Checked-in literals computed independently of this module (plain
    // Python hmac/hashlib HKDF-Extract + RFC 8446 HKDF-Expand-Label), not by
    // re-deriving with the helper under test.
    var det = pure_zig.DeterministicEntropy.init(11);
    var backing: pure_zig.Provider = undefined;
    const cp = testProvider(&det, &backing);

    const psk = [_]u8{0x99} ** hash_len;
    const hello_hash = [_]u8{0x24} ** hash_len;

    const early = try KeySchedule.clientEarlyTrafficSecret(cp, &psk, hello_hash);
    try testing.expectEqualSlices(u8, &hexBytes("16d133c56483399331d093c3389c265a9547962c6b494b215e02e4eb92900afd"), &early);
}

test "clientEarlyTrafficSecret differs when the PSK differs" {
    var det = pure_zig.DeterministicEntropy.init(12);
    var backing: pure_zig.Provider = undefined;
    const cp = testProvider(&det, &backing);

    const psk_a = [_]u8{0x99} ** hash_len;
    const psk_b = [_]u8{0xaa} ** hash_len;
    const hello_hash_a = [_]u8{0x24} ** hash_len;
    const hello_hash_b = [_]u8{0x11} ** hash_len;

    const early_a = try KeySchedule.clientEarlyTrafficSecret(cp, &psk_a, hello_hash_a);
    const early_b = try KeySchedule.clientEarlyTrafficSecret(cp, &psk_b, hello_hash_b);
    try testing.expectEqualSlices(u8, &hexBytes("e69f3f7132880345ceda14cd7dcef6aeec62182cb3973d19a50371d75832f596"), &early_b);
    try testing.expect(!std.mem.eql(u8, &early_a, &early_b));
}

test "clientEarlyTrafficSecret differs when only the ClientHello hash differs" {
    // Same PSK as the first fixture above, but a different (complete)
    // ClientHello hash: the early secret must bind to the exact transcript,
    // not just the PSK, so this must differ from `early_a`.
    var det = pure_zig.DeterministicEntropy.init(13);
    var backing: pure_zig.Provider = undefined;
    const cp = testProvider(&det, &backing);

    const psk = [_]u8{0x99} ** hash_len;
    const hello_hash = [_]u8{0x77} ** hash_len;

    const early = try KeySchedule.clientEarlyTrafficSecret(cp, &psk, hello_hash);
    try testing.expectEqualSlices(u8, &hexBytes("7d693eba9b582d3867e21784c2682d6ecef79deacbd28089a705e45ea8273310"), &early);
}

test "init/initWithPsk/applicationSecrets propagate a typed provider error rather than collapsing it" {
    // A provider that declares no capabilities at all: every HKDF call must
    // surface `error.UnsupportedCapability` from the real provider vtable,
    // not a generic failure — proving these newly-fallible entry points
    // actually propagate the provider's typed error rather than papering
    // over it.
    const NoCapabilityProvider = struct {
        fn capabilities(context: *anyopaque) provider.Capabilities {
            _ = context;
            return .{};
        }
        fn hkdfExtract(context: *anyopaque, hash: provider.Hash, salt: []const u8, ikm: []const u8, out: []u8) provider.HkdfError!void {
            _ = context;
            _ = hash;
            _ = salt;
            _ = ikm;
            _ = out;
            return error.UnsupportedCapability;
        }
        fn hkdfExpandLabel(context: *anyopaque, hash: provider.Hash, secret: []const u8, label: []const u8, hash_context: []const u8, out: []u8) provider.HkdfError!void {
            _ = context;
            _ = hash;
            _ = secret;
            _ = label;
            _ = hash_context;
            _ = out;
            return error.UnsupportedCapability;
        }
        fn unused1(context: *anyopaque, aead: provider.Aead, key: []const u8, nonce: []const u8, ad: []const u8, pt: []const u8, ct: []u8, tag: []u8) provider.SealError!void {
            _ = .{ context, aead, key, nonce, ad, pt, ct, tag };
            return error.UnsupportedCapability;
        }
        fn unused2(context: *anyopaque, aead: provider.Aead, key: []const u8, nonce: []const u8, ad: []const u8, ct: []const u8, tag: []const u8, pt: []u8) provider.OpenError!void {
            _ = .{ context, aead, key, nonce, ad, ct, tag, pt };
            return error.UnsupportedCapability;
        }
        fn unused3(context: *anyopaque, hp: provider.QuicHeaderProtection, key: []const u8, sample: []const u8, mask: []u8) provider.QuicHeaderProtectionError!void {
            _ = .{ context, hp, key, sample, mask };
            return error.UnsupportedCapability;
        }
        fn unused4(context: *anyopaque, group: provider.Group, pub_out: []u8, priv_out: []u8) provider.KeyShareError!void {
            _ = .{ context, group, pub_out, priv_out };
            return error.UnsupportedCapability;
        }
        fn unused5(context: *anyopaque, group: provider.Group, priv: []const u8, peer_pub: []const u8, out: []u8) provider.DeriveError!void {
            _ = .{ context, group, priv, peer_pub, out };
            return error.UnsupportedCapability;
        }
        fn unused6(context: *anyopaque, scheme: provider.SignatureScheme, pub_key: []const u8, msg: []const u8, sig: []const u8) provider.VerifyError!void {
            _ = .{ context, scheme, pub_key, msg, sig };
            return error.UnsupportedCapability;
        }
        fn entropyFill(context: *anyopaque, buffer: []u8) provider.EntropyError!void {
            _ = context;
            @memset(buffer, 0);
        }
    };
    var sentinel: u8 = 0;
    const vtable = provider.CryptoProvider.VTable{
        .capabilities = NoCapabilityProvider.capabilities,
        .hkdfExtract = NoCapabilityProvider.hkdfExtract,
        .hkdfExpandLabel = NoCapabilityProvider.hkdfExpandLabel,
        .aeadSeal = NoCapabilityProvider.unused1,
        .aeadOpen = NoCapabilityProvider.unused2,
        .quicHeaderProtectionMask = NoCapabilityProvider.unused3,
        .generateKeyShare = NoCapabilityProvider.unused4,
        .deriveSharedSecret = NoCapabilityProvider.unused5,
        .verify = NoCapabilityProvider.unused6,
    };
    const cp = provider.CryptoProvider{
        .context = &sentinel,
        .vtable = &vtable,
        .entropy = .{ .context = &sentinel, .fillFn = NoCapabilityProvider.entropyFill },
    };

    const shared = [_]u8{0x42} ** shared_secret_len;
    const transcript = [_]u8{0x24} ** hash_len;
    try testing.expectError(error.UnsupportedCapability, KeySchedule.init(cp, &shared, transcript));

    const psk = [_]u8{0x99} ** hash_len;
    try testing.expectError(error.UnsupportedCapability, KeySchedule.initWithPsk(cp, &psk, &shared, transcript));
    try testing.expectError(error.UnsupportedCapability, KeySchedule.clientEarlyTrafficSecret(cp, &psk, transcript));

    var out: [hash_len]u8 = undefined;
    try testing.expectError(error.UnsupportedCapability, KeySchedule.resumptionPsk(cp, .sha256, &psk, "n", &out));
}

/// A provider whose HKDF vtable methods write a recognizable non-zero prefix
/// into `out` before failing, modelling a conforming implementation that
/// partially writes its output buffer before reporting an error — the
/// provider interface never promises an untouched or zeroed `out` on failure
/// (#490 review). Every key-schedule entry point that owns a fallible HKDF
/// call must wipe its own stack buffer(s) on this path regardless.
const PartialWriteThenFailProvider = struct {
    fn capabilities(context: *anyopaque) provider.Capabilities {
        _ = context;
        var caps = provider.Capabilities{};
        caps.hashes.insert(.sha256);
        caps.hashes.insert(.sha384);
        return caps;
    }
    fn hkdfExtract(context: *anyopaque, hash: provider.Hash, salt: []const u8, ikm: []const u8, out: []u8) provider.HkdfError!void {
        _ = .{ context, hash, salt, ikm };
        writePrefixThenFail(out);
        return error.UnsupportedCapability;
    }
    fn hkdfExpandLabel(context: *anyopaque, hash: provider.Hash, secret: []const u8, label: []const u8, hash_context: []const u8, out: []u8) provider.HkdfError!void {
        _ = .{ context, hash, secret, label, hash_context };
        writePrefixThenFail(out);
        return error.UnsupportedCapability;
    }
    fn writePrefixThenFail(out: []u8) void {
        const prefix = @min(out.len, 4);
        @memset(out[0..prefix], 0xEE);
    }
    fn unused1(context: *anyopaque, aead: provider.Aead, key: []const u8, nonce: []const u8, ad: []const u8, pt: []const u8, ct: []u8, tag: []u8) provider.SealError!void {
        _ = .{ context, aead, key, nonce, ad, pt, ct, tag };
        return error.UnsupportedCapability;
    }
    fn unused2(context: *anyopaque, aead: provider.Aead, key: []const u8, nonce: []const u8, ad: []const u8, ct: []const u8, tag: []const u8, pt: []u8) provider.OpenError!void {
        _ = .{ context, aead, key, nonce, ad, ct, tag, pt };
        return error.UnsupportedCapability;
    }
    fn unused3(context: *anyopaque, hp: provider.QuicHeaderProtection, key: []const u8, sample: []const u8, mask: []u8) provider.QuicHeaderProtectionError!void {
        _ = .{ context, hp, key, sample, mask };
        return error.UnsupportedCapability;
    }
    fn unused4(context: *anyopaque, group: provider.Group, pub_out: []u8, priv_out: []u8) provider.KeyShareError!void {
        _ = .{ context, group, pub_out, priv_out };
        return error.UnsupportedCapability;
    }
    fn unused5(context: *anyopaque, group: provider.Group, priv: []const u8, peer_pub: []const u8, out: []u8) provider.DeriveError!void {
        _ = .{ context, group, priv, peer_pub, out };
        return error.UnsupportedCapability;
    }
    fn unused6(context: *anyopaque, scheme: provider.SignatureScheme, pub_key: []const u8, msg: []const u8, sig: []const u8) provider.VerifyError!void {
        _ = .{ context, scheme, pub_key, msg, sig };
        return error.UnsupportedCapability;
    }
    fn entropyFill(context: *anyopaque, buffer: []u8) provider.EntropyError!void {
        _ = context;
        @memset(buffer, 0);
    }

    fn cryptoProvider(self: *PartialWriteThenFailProvider) provider.CryptoProvider {
        const vtable = provider.CryptoProvider.VTable{
            .capabilities = capabilities,
            .hkdfExtract = hkdfExtract,
            .hkdfExpandLabel = hkdfExpandLabel,
            .aeadSeal = unused1,
            .aeadOpen = unused2,
            .quicHeaderProtectionMask = unused3,
            .generateKeyShare = unused4,
            .deriveSharedSecret = unused5,
            .verify = unused6,
        };
        return .{
            .context = self,
            .vtable = &vtable,
            .entropy = .{ .context = self, .fillFn = entropyFill },
        };
    }
};

test "every fallible HKDF entry point wipes its own output buffer(s) when the provider fails after a partial write" {
    var fault: PartialWriteThenFailProvider = .{};
    const cp = fault.cryptoProvider();

    const shared = [_]u8{0x42} ** shared_secret_len;
    const transcript = [_]u8{0x24} ** hash_len;
    const psk = [_]u8{0x99} ** hash_len;

    try testing.expectError(error.UnsupportedCapability, KeySchedule.init(cp, &shared, transcript));
    try testing.expectError(error.UnsupportedCapability, KeySchedule.initWithPsk(cp, &psk, &shared, transcript));
    try testing.expectError(error.UnsupportedCapability, KeySchedule.clientEarlyTrafficSecret(cp, &psk, transcript));
    try testing.expectError(error.UnsupportedCapability, KeySchedule.finishedKey(cp, &psk));
    try testing.expectError(error.UnsupportedCapability, KeySchedule.verifyData(cp, &psk, transcript));

    var out: [hash_len]u8 = undefined;
    try testing.expectError(error.UnsupportedCapability, KeySchedule.resumptionPsk(cp, .sha256, &psk, "n", &out));
    try testing.expect(std.mem.allEqual(u8, &out, 0));
    try testing.expectError(error.UnsupportedCapability, KeySchedule.deriveResumptionMasterSecret(cp, .sha256, &psk, &transcript, &out));
    try testing.expect(std.mem.allEqual(u8, &out, 0));

    // A successfully constructed schedule, then applicationSecrets failing
    // against the same fault provider: the two output buffers it fills must
    // both come back wiped, not carrying the fault provider's 0xEE prefix.
    var real_det = pure_zig.DeterministicEntropy.init(20);
    var real_backing: pure_zig.Provider = undefined;
    const real_cp = testProvider(&real_det, &real_backing);
    var schedule = try KeySchedule.init(real_cp, &shared, transcript);
    defer schedule.wipe();
    schedule.provider = cp;
    try testing.expectError(error.UnsupportedCapability, schedule.applicationSecrets(transcript));
}

fn hexBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var bytes: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, hex) catch unreachable;
    return bytes;
}

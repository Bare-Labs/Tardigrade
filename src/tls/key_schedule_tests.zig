//! Tests for the protocol-neutral TLS 1.3 key schedule (`key_schedule.zig`).
//!
//! Kept in a separate file from the production module (#490 review): this
//! file's own cross-check against a direct `std.crypto.auth.hmac.sha2.
//! HmacSha256`/`HmacSha384` computation, and its raw `CryptoProvider` vtable
//! fixture for typed-error-propagation, are legitimate test-only direct-crypto
//! use, but a textual "scan everything before this marker" boundary inside the
//! production file is not a sound reachability proof — Zig declarations are
//! order-independent, so a production function declared before such a marker
//! could still call a private helper declared after it, and the scan would
//! never see the call. Structural separation (a file `scripts/
//! audit_crypto_boundary.zig` never scans at all, the same way
//! `tests/support/quic_crypto.zig` and `tests/crypto_vectors.zig` aren't
//! scanned either) is the sound fix: `key_schedule.zig` itself now has zero
//! test-only content and is scanned in full, with no marker.
//!
//! SHA-384 fixtures below (independent of the SHA-256 RFC 8448 trace) were
//! computed with plain Python `hmac`/`hashlib` implementing RFC 8446's
//! HKDF-Expand-Label directly — not by re-deriving with the helpers under
//! test — matching this codebase's existing differential-fixture convention
//! (see `record_protection.zig`'s AES-256-GCM/ChaCha20 known-answer tests).

const std = @import("std");
const testing = std.testing;
const crypto = std.crypto;

const provider = @import("crypto").provider;
const pure_zig = @import("crypto").pure_zig;
// Through the named `tls_core` module, not a raw `@import("key_schedule.zig")`
// file-relative import: this file is compiled as part of its own dedicated
// test-only module (`key_schedule_test_root_mod` in build.zig, rooted at
// `key_schedule_test_root.zig`), and Zig does not allow the same on-disk
// file to belong to two different modules — a raw file import here would
// otherwise re-claim `key_schedule.zig`, which already belongs to the
// production `tls_core` module via `src/tls/root.zig`.
const key_schedule = @import("tls_core").key_schedule;

const KeySchedule = key_schedule.KeySchedule;
const shared_secret_len = key_schedule.shared_secret_len;
/// SHA-256's digest length, used throughout the SHA-256 fixtures below. Not
/// re-exported by `key_schedule.zig` itself (#564): the production module no
/// longer names a single fixed digest length, since it is hash-agile.
const hash_len = 32;
const hash_len_384 = 48;

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
    var schedule: KeySchedule = undefined;
    try KeySchedule.init(cp, .sha256, &shared, &transcript, &schedule);
    defer schedule.wipe();
    var app: KeySchedule.ApplicationSecrets = undefined;
    try schedule.applicationSecrets(&transcript, &app);
    defer app.wipe();
    try testing.expect(!std.mem.eql(u8, app.clientSecret(), app.serverSecret()));
}

test "shared TLS 1.3 key schedule matches the RFC 8448 simple 1-RTT trace" {
    var det = pure_zig.DeterministicEntropy.init(2);
    var backing: pure_zig.Provider = undefined;
    const cp = testProvider(&det, &backing);

    const shared = hexBytes("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
    const hello_hash = hexBytes("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");
    var schedule: KeySchedule = undefined;
    try KeySchedule.init(cp, .sha256, &shared, &hello_hash, &schedule);
    defer schedule.wipe();

    try testing.expectEqualSlices(u8, &hexBytes("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac"), schedule.handshake_secret[0..hash_len]);
    try testing.expectEqualSlices(u8, &hexBytes("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"), schedule.client_handshake_traffic[0..hash_len]);
    try testing.expectEqualSlices(u8, &hexBytes("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"), schedule.server_handshake_traffic[0..hash_len]);
    try testing.expectEqualSlices(u8, &hexBytes("18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919"), schedule.master_secret[0..hash_len]);

    const finished_hash = hexBytes("9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13");
    var app: KeySchedule.ApplicationSecrets = undefined;
    try schedule.applicationSecrets(&finished_hash, &app);
    defer app.wipe();
    try testing.expectEqualSlices(u8, &hexBytes("9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5"), app.clientSecret());
    try testing.expectEqualSlices(u8, &hexBytes("a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643"), app.serverSecret());

    var finished_key: [hash_len]u8 = undefined;
    defer crypto.secureZero(u8, &finished_key);
    try KeySchedule.finishedKey(cp, .sha256, schedule.server_handshake_traffic[0..hash_len], &finished_key);
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
    var verify_data: [hash_len]u8 = undefined;
    try KeySchedule.verifyData(cp, .sha256, schedule.server_handshake_traffic[0..hash_len], &finished_hash, &verify_data);
    try testing.expectEqualSlices(u8, &direct_mac, &verify_data);
}

test "SHA-384 key schedule matches an independently computed known-answer fixture" {
    // Checked-in literals computed independently of this module (plain
    // Python hmac/hashlib implementing RFC 8446 HKDF-Expand-Label directly),
    // for shared=0x42*32, transcript=0x24*48 — the SHA-384 analogue of the
    // zero-PSK fixtures above.
    var det = pure_zig.DeterministicEntropy.init(14);
    var backing: pure_zig.Provider = undefined;
    const cp = testProvider(&det, &backing);

    const shared = [_]u8{0x42} ** shared_secret_len;
    const transcript = [_]u8{0x24} ** hash_len_384;
    var schedule: KeySchedule = undefined;
    try KeySchedule.init(cp, .sha384, &shared, &transcript, &schedule);
    defer schedule.wipe();
    try testing.expectEqual(provider.Hash.sha384, schedule.hash);
    try testing.expectEqual(@as(usize, hash_len_384), schedule.digestLen());

    try testing.expectEqualSlices(u8, &hexBytes("d6dc3f5d0217df1301fb9479d8aadd88e542306d6cdcf197913593658a5f2c50f526964fbaf5e4587be563272eda583d"), schedule.handshake_secret[0..hash_len_384]);
    try testing.expectEqualSlices(u8, &hexBytes("8df0e42bc34170cf567790494d4fbb5b61538895bdaa2cf8a0ad2db0b588b46d52853504d8713db39e4c28f396cab7b0"), schedule.master_secret[0..hash_len_384]);
    try testing.expectEqualSlices(u8, &hexBytes("3ce66a169e12ab6927d5832cba1abaabb6c5237b1f129ff8e18e355c2e8f6f56e53ab195579da5131217e94aa57f18ac"), schedule.client_handshake_traffic[0..hash_len_384]);
    try testing.expectEqualSlices(u8, &hexBytes("062cc3bc2f786fd4d738bcf21d14ab173386513f5a98e99656b46865b373062768ff77f69b58467715667f56c7fd3353"), schedule.server_handshake_traffic[0..hash_len_384]);

    var app: KeySchedule.ApplicationSecrets = undefined;
    try schedule.applicationSecrets(&transcript, &app);
    defer app.wipe();
    try testing.expectEqual(@as(usize, hash_len_384), app.len);
    try testing.expectEqualSlices(u8, &hexBytes("8d2c41fc2f30630d9924bae6ff52df22d94939379fcd7de4b31f6bf7ceb0ec40c46c744a69ab217dc5c6e797ebebc291"), app.clientSecret());
    try testing.expectEqualSlices(u8, &hexBytes("776852783850e21c01a86b5d5a861a7851f98a14189e6c58bfa941c9d99815317304e2deb0d74185ee97aa415ea74eb0"), app.serverSecret());

    var finished_key: [hash_len_384]u8 = undefined;
    defer crypto.secureZero(u8, &finished_key);
    try KeySchedule.finishedKey(cp, .sha384, schedule.server_handshake_traffic[0..hash_len_384], &finished_key);
    try testing.expectEqualSlices(u8, &hexBytes("0618d45ecd47b39463530464a6a91a50394c343442f3ec4491a8d0ecbcfb79ba24163c3a3a035676253e5c08ebe7b22e"), &finished_key);

    const HmacSha384 = crypto.auth.hmac.sha2.HmacSha384;
    var direct_mac: [HmacSha384.mac_length]u8 = undefined;
    HmacSha384.create(&direct_mac, &transcript, &finished_key);
    var verify_data: [hash_len_384]u8 = undefined;
    try KeySchedule.verifyData(cp, .sha384, schedule.server_handshake_traffic[0..hash_len_384], &transcript, &verify_data);
    try testing.expectEqualSlices(u8, &hexBytes("c9df95efc74c3e4ad63513ef86662693b2c52ceb0365773697c35d99a0ae7895a103993cad47021f0f55d0148d375daf"), &verify_data);
    try testing.expectEqualSlices(u8, &direct_mac, &verify_data);
}

test "SHA-384 initWithPsk matches an independently computed known-answer fixture" {
    var det = pure_zig.DeterministicEntropy.init(15);
    var backing: pure_zig.Provider = undefined;
    const cp = testProvider(&det, &backing);

    const shared = [_]u8{0x42} ** shared_secret_len;
    const transcript = [_]u8{0x24} ** hash_len_384;
    const psk = [_]u8{0x99} ** hash_len_384;

    var schedule: KeySchedule = undefined;
    try KeySchedule.initWithPsk(cp, .sha384, &psk, &shared, &transcript, &schedule);
    defer schedule.wipe();

    try testing.expectEqualSlices(u8, &hexBytes("219ee43b44c170016081d9116317eab9b749cd4a6f3c7f0ba4f33594ba2889c3636f74b6ca205763519447a4fbb2bbd6"), schedule.handshake_secret[0..hash_len_384]);
    try testing.expectEqualSlices(u8, &hexBytes("c29de3d70cc9b39002b526cd3da32b39898e2b3a92fb167edfe18eb8df87da96a2ba26ba178b9062d6f2c85ea5d35bb6"), schedule.master_secret[0..hash_len_384]);
    try testing.expectEqualSlices(u8, &hexBytes("f69664bafa4dff4ba0d22cb285225af79da35d46b7f2c5315fdb3479ebedfb612912473b798499cd6f69c61a201cabec"), schedule.client_handshake_traffic[0..hash_len_384]);
    try testing.expectEqualSlices(u8, &hexBytes("f64f8f854a4fed3eb56a6f2587881b36c7b03ec941e611fee8a400fe3259a922110da51cde297e420f65a8fb47bee8c0"), schedule.server_handshake_traffic[0..hash_len_384]);
}

test "SHA-384 clientEarlyTrafficSecret matches an independently computed known-answer fixture" {
    var det = pure_zig.DeterministicEntropy.init(16);
    var backing: pure_zig.Provider = undefined;
    const cp = testProvider(&det, &backing);

    const psk = [_]u8{0x99} ** hash_len_384;
    const hello_hash = [_]u8{0x24} ** hash_len_384;
    var out: [hash_len_384]u8 = undefined;
    defer crypto.secureZero(u8, &out);
    try KeySchedule.clientEarlyTrafficSecret(cp, .sha384, &psk, &hello_hash, &out);
    try testing.expectEqualSlices(u8, &hexBytes("c40401d9bf363b9677cc95cb7de19c7ce0bb56eac777b92d7b89235ef7c9c68947bba378116f1abcaf1e9bcb7211807c"), &out);
}

test "SHA-384 KeySchedule.init and applicationSecrets reject SHA-256-sized inputs" {
    var det = pure_zig.DeterministicEntropy.init(17);
    var backing: pure_zig.Provider = undefined;
    const cp = testProvider(&det, &backing);

    const shared = [_]u8{0x42} ** shared_secret_len;
    const wrong_transcript = [_]u8{0x24} ** hash_len;
    var scratch: KeySchedule = undefined;
    try testing.expectError(error.InvalidSecretLength, KeySchedule.init(cp, .sha384, &shared, &wrong_transcript, &scratch));

    const transcript384 = [_]u8{0x24} ** hash_len_384;
    var schedule: KeySchedule = undefined;
    try KeySchedule.init(cp, .sha384, &shared, &transcript384, &schedule);
    defer schedule.wipe();
    var scratch_app: KeySchedule.ApplicationSecrets = undefined;
    try testing.expectError(error.InvalidSecretLength, schedule.applicationSecrets(&wrong_transcript, &scratch_app));

    const wrong_psk = [_]u8{0x99} ** hash_len;
    try testing.expectError(error.InvalidSecretLength, KeySchedule.initWithPsk(cp, .sha384, &wrong_psk, &shared, &transcript384, &scratch));
}

test "application traffic secret storage has explicit cleanup" {
    var det = pure_zig.DeterministicEntropy.init(3);
    var backing: pure_zig.Provider = undefined;
    const cp = testProvider(&det, &backing);

    const shared = [_]u8{0x42} ** shared_secret_len;
    const transcript = [_]u8{0x24} ** hash_len;
    var schedule: KeySchedule = undefined;
    try KeySchedule.init(cp, .sha256, &shared, &transcript, &schedule);
    defer schedule.wipe();
    var app: KeySchedule.ApplicationSecrets = undefined;
    try schedule.applicationSecrets(&transcript, &app);
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
    var schedule: KeySchedule = undefined;
    try KeySchedule.init(cp, .sha256, &shared, &transcript, &schedule);
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
    var schedule: KeySchedule = undefined;
    try KeySchedule.init(cp, .sha256, &shared, &hello_hash, &schedule);
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

    var zero_psk_schedule: KeySchedule = undefined;
    try KeySchedule.init(cp, .sha256, &shared, &transcript, &zero_psk_schedule);
    defer zero_psk_schedule.wipe();
    var psk_schedule: KeySchedule = undefined;
    try KeySchedule.initWithPsk(cp, .sha256, &psk, &shared, &transcript, &psk_schedule);
    defer psk_schedule.wipe();
    var psk_schedule_again: KeySchedule = undefined;
    try KeySchedule.initWithPsk(cp, .sha256, &psk, &shared, &transcript, &psk_schedule_again);
    defer psk_schedule_again.wipe();

    try testing.expect(!std.mem.eql(u8, &zero_psk_schedule.handshake_secret, &psk_schedule.handshake_secret));
    try testing.expect(!std.mem.eql(u8, &zero_psk_schedule.master_secret, &psk_schedule.master_secret));
    try testing.expectEqualSlices(u8, &psk_schedule.handshake_secret, &psk_schedule_again.handshake_secret);
    try testing.expectEqualSlices(u8, &psk_schedule.master_secret, &psk_schedule_again.master_secret);
    try testing.expect(!std.mem.eql(u8, &psk_schedule.client_handshake_traffic, &psk_schedule.server_handshake_traffic));

    var app: KeySchedule.ApplicationSecrets = undefined;
    try psk_schedule.applicationSecrets(&transcript, &app);
    defer app.wipe();
    try testing.expect(!std.mem.eql(u8, app.clientSecret(), app.serverSecret()));
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

    var schedule: KeySchedule = undefined;
    try KeySchedule.initWithPsk(cp, .sha256, &psk, &shared, &transcript, &schedule);
    defer schedule.wipe();

    try testing.expectEqualSlices(u8, &hexBytes("ab0803d6203c8feddfe8adc74f986c9d89b817b3d4132fc55c866a3522d9ff49"), schedule.handshake_secret[0..hash_len]);
    try testing.expectEqualSlices(u8, &hexBytes("e92139285417b6a9a54a7a9153f4b6dcce44b99cdc0937b83dfea5c79805c920"), schedule.client_handshake_traffic[0..hash_len]);
    try testing.expectEqualSlices(u8, &hexBytes("739483d9d6a9508c73b4656de22fedd85a2a8d00e9a6ca1449d8cba678c94baf"), schedule.server_handshake_traffic[0..hash_len]);
    try testing.expectEqualSlices(u8, &hexBytes("abe96cce65361235f3126971c67760888b79d4c1724a6cb1e15f6d2ae128ff44"), schedule.master_secret[0..hash_len]);

    var app: KeySchedule.ApplicationSecrets = undefined;
    try schedule.applicationSecrets(&transcript, &app);
    defer app.wipe();
    try testing.expectEqualSlices(u8, &hexBytes("d1ba0b1be9862f1bd4c3bcc0d53b5a98c6a4951c4bad19243051237bc735031c"), app.clientSecret());
    try testing.expectEqualSlices(u8, &hexBytes("c7428c93109f1b656dcbf0971e5d1bad9c2d38b79420038b7e165a17c7f61fa1"), app.serverSecret());
}

test "a different resumption PSK produces a different PSK-resumed schedule" {
    var det = pure_zig.DeterministicEntropy.init(10);
    var backing: pure_zig.Provider = undefined;
    const cp = testProvider(&det, &backing);

    const shared = [_]u8{0x11} ** shared_secret_len;
    const transcript = [_]u8{0x22} ** hash_len;
    const psk_a = [_]u8{0xaa} ** hash_len;
    const psk_b = [_]u8{0xbb} ** hash_len;

    var schedule_a: KeySchedule = undefined;
    try KeySchedule.initWithPsk(cp, .sha256, &psk_a, &shared, &transcript, &schedule_a);
    defer schedule_a.wipe();
    var schedule_b: KeySchedule = undefined;
    try KeySchedule.initWithPsk(cp, .sha256, &psk_b, &shared, &transcript, &schedule_b);
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

    var early: [hash_len]u8 = undefined;
    try KeySchedule.clientEarlyTrafficSecret(cp, .sha256, &psk, &hello_hash, &early);
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

    var early_a: [hash_len]u8 = undefined;
    var early_b: [hash_len]u8 = undefined;
    try KeySchedule.clientEarlyTrafficSecret(cp, .sha256, &psk_a, &hello_hash_a, &early_a);
    try KeySchedule.clientEarlyTrafficSecret(cp, .sha256, &psk_b, &hello_hash_b, &early_b);
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

    var early: [hash_len]u8 = undefined;
    try KeySchedule.clientEarlyTrafficSecret(cp, .sha256, &psk, &hello_hash, &early);
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
    var scratch: KeySchedule = undefined;
    try testing.expectError(error.UnsupportedCapability, KeySchedule.init(cp, .sha256, &shared, &transcript, &scratch));

    const psk = [_]u8{0x99} ** hash_len;
    try testing.expectError(error.UnsupportedCapability, KeySchedule.initWithPsk(cp, .sha256, &psk, &shared, &transcript, &scratch));
    var early: [hash_len]u8 = undefined;
    try testing.expectError(error.UnsupportedCapability, KeySchedule.clientEarlyTrafficSecret(cp, .sha256, &psk, &transcript, &early));

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

    var scratch: KeySchedule = undefined;
    try testing.expectError(error.UnsupportedCapability, KeySchedule.init(cp, .sha256, &shared, &transcript, &scratch));
    try testing.expectError(error.UnsupportedCapability, KeySchedule.initWithPsk(cp, .sha256, &psk, &shared, &transcript, &scratch));

    // clientEarlyTrafficSecret and verifyData both fail at an earlier
    // *internal* HKDF call (into a local secret, not the caller's `out`)
    // before ever writing to `out` itself, so there is nothing to wipe
    // there — only `expectError` applies. finishedKey passes `out` directly
    // to its one HKDF call, so its own `errdefer` wipe is checked below.
    var early: [hash_len]u8 = undefined;
    try testing.expectError(error.UnsupportedCapability, KeySchedule.clientEarlyTrafficSecret(cp, .sha256, &psk, &transcript, &early));

    var fkey: [hash_len]u8 = undefined;
    try testing.expectError(error.UnsupportedCapability, KeySchedule.finishedKey(cp, .sha256, &psk, &fkey));
    try testing.expect(std.mem.allEqual(u8, &fkey, 0));

    var vdata: [hash_len]u8 = undefined;
    try testing.expectError(error.UnsupportedCapability, KeySchedule.verifyData(cp, .sha256, &psk, &transcript, &vdata));

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
    var schedule: KeySchedule = undefined;
    try KeySchedule.init(real_cp, .sha256, &shared, &transcript, &schedule);
    defer schedule.wipe();
    schedule.provider = cp;
    var app_scratch: KeySchedule.ApplicationSecrets = undefined;
    try testing.expectError(error.UnsupportedCapability, schedule.applicationSecrets(&transcript, &app_scratch));
}

fn hexBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var bytes: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, hex) catch unreachable;
    return bytes;
}

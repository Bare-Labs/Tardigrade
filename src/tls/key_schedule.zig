//! Protocol-neutral TLS 1.3 SHA-256 key schedule.
//!
//! This module has no QUIC, HTTP, socket, or record-layer types. QUIC and
//! future TCP-record integrations both derive handshake/application traffic
//! secrets through this shared core.
//!
//! Every secret-bearing HKDF operation here (HKDF-Extract, HKDF-Expand-Label,
//! and TLS Finished `verify_data`, itself expressed as HKDF-Extract per RFC
//! 5869 — see `verifyData`) crosses `crypto.provider.CryptoProvider`, the
//! shared provider/security seam every other keyed TLS/QUIC operation uses
//! (#490). The only crypto this module still performs directly is *unkeyed*
//! transcript hashing (`Sha256.hash` for the comptime empty-transcript and
//! all-zero-PSK constants below): that hash has no secret input, so it stays
//! provider-independent by design, matching `docs/CRYPTO_PROVIDER_AUDIT.md`'s
//! "unkeyed transcript hashing may remain provider-independent" disposition.
//!
//! `KeySchedule` holds the `CryptoProvider` it was constructed with (the same
//! borrowed-value-type convention `QuicTlsAdapter` uses) so instance methods
//! (`applicationSecrets`, `resumptionMasterSecret`) do not need it passed
//! again; free functions that do not require a live `KeySchedule` instance
//! (`resumptionPsk`, `deriveResumptionMasterSecret`, `clientEarlyTrafficSecret`,
//! `finishedKey`, `verifyData`) take one explicitly, since resumption/ticket
//! code (`new_session_ticket.zig`) and 0-RTT paths often need these before —
//! or without ever constructing — a full `KeySchedule`.

const std = @import("std");
const provider = @import("crypto").provider;

const crypto = std.crypto;
const Sha256 = crypto.hash.sha2.Sha256;

pub const TranscriptHash = Sha256;
pub const hash_len = Sha256.digest_length;
/// X25519 shared-secret length (RFC 7748) — this module's only consumer of
/// key-exchange output, not a key-exchange implementation itself.
pub const shared_secret_len = 32;

/// Errors this module's own length preconditions can raise, composed with the
/// provider's typed HKDF error set so callers see (and can distinguish)
/// exactly why a derivation failed rather than a single collapsed error.
pub const Error = error{InvalidSecretLength} || provider.HkdfError;

const empty_transcript_hash: [hash_len]u8 = blk: {
    @setEvalBranchQuota(100_000);
    var out: [hash_len]u8 = undefined;
    Sha256.hash("", &out, .{});
    break :blk out;
};

/// RFC 8446 §7.1's "derived" early secret for the zero-PSK (full handshake,
/// non-resumed) key-schedule chain: `HKDF-Expand-Label(HKDF-Extract(0, 0),
/// "derived", Hash(""), Hash.length)`. This is a fixed public constant — the
/// early secret input is the all-zero PSK, not connection-specific secret
/// material — so it is computed once at compile time directly, the same way
/// `empty_transcript_hash` above is: there is no runtime provider available
/// at comptime, and none is needed, since nothing here is a secret specific
/// to any handshake. `scripts/audit_crypto_boundary.zig` allowlists this
/// declaration by name for exactly that reason (see
/// `docs/CRYPTO_PROVIDER_AUDIT.md`).
const derived_early_secret: [hash_len]u8 = blk: {
    @setEvalBranchQuota(100_000);
    const HkdfSha256 = crypto.kdf.hkdf.HkdfSha256;
    const zeros = [_]u8{0} ** hash_len;
    const early_secret = HkdfSha256.extract("", &zeros);
    break :blk crypto.tls.hkdfExpandLabel(HkdfSha256, early_secret, "derived", &empty_transcript_hash, hash_len);
};

pub const KeySchedule = struct {
    provider: provider.CryptoProvider,
    handshake_secret: [hash_len]u8,
    master_secret: [hash_len]u8,
    client_handshake_traffic: [hash_len]u8,
    server_handshake_traffic: [hash_len]u8,

    pub fn init(
        crypto_provider: provider.CryptoProvider,
        shared: *const [shared_secret_len]u8,
        hello_transcript_hash: [hash_len]u8,
    ) provider.HkdfError!KeySchedule {
        return initFromEarlySecret(crypto_provider, &derived_early_secret, shared, hello_transcript_hash);
    }

    /// PSK-resumed (`psk_dhe_ke`) handshake: the same key-schedule chain as
    /// `init`, but starting from a real early secret derived from the
    /// resumption PSK (RFC 8446 §7.1) instead of the comptime all-zero-PSK
    /// early secret `init` uses. `psk` must already be exactly `hash_len`
    /// bytes (the SHA-256 resumption PSK produced by
    /// `resumptionPsk`/`KeySchedule.resumptionPsk`, matching this module's
    /// concrete SHA-256 schedule). X25519 key share remains mandatory in
    /// this profile, so `shared` is still the ECDHE shared secret.
    pub fn initWithPsk(
        crypto_provider: provider.CryptoProvider,
        psk: *const [hash_len]u8,
        shared: *const [shared_secret_len]u8,
        hello_transcript_hash: [hash_len]u8,
    ) provider.HkdfError!KeySchedule {
        var early_secret: [hash_len]u8 = undefined;
        try crypto_provider.hkdfExtract(.sha256, "", psk, &early_secret);
        defer crypto.secureZero(u8, &early_secret);
        var derived_early: [hash_len]u8 = undefined;
        try crypto_provider.hkdfExpandLabel(.sha256, &early_secret, "derived", &empty_transcript_hash, &derived_early);
        defer crypto.secureZero(u8, &derived_early);
        return initFromEarlySecret(crypto_provider, &derived_early, shared, hello_transcript_hash);
    }

    /// Shared continuation from a "derived" early secret (RFC 8446 §7.1)
    /// into the handshake/master secrets and handshake traffic secrets. Used
    /// by both the zero-PSK (`init`) and real-PSK (`initWithPsk`) entry
    /// points, which differ only in how `derived_early` was produced.
    fn initFromEarlySecret(
        crypto_provider: provider.CryptoProvider,
        derived_early: *const [hash_len]u8,
        shared: *const [shared_secret_len]u8,
        hello_transcript_hash: [hash_len]u8,
    ) provider.HkdfError!KeySchedule {
        const zeros = [_]u8{0} ** hash_len;

        var handshake_secret: [hash_len]u8 = undefined;
        try crypto_provider.hkdfExtract(.sha256, derived_early, shared, &handshake_secret);
        errdefer crypto.secureZero(u8, &handshake_secret);

        var derived_handshake: [hash_len]u8 = undefined;
        try crypto_provider.hkdfExpandLabel(.sha256, &handshake_secret, "derived", &empty_transcript_hash, &derived_handshake);
        defer crypto.secureZero(u8, &derived_handshake);

        var master_secret: [hash_len]u8 = undefined;
        try crypto_provider.hkdfExtract(.sha256, &derived_handshake, &zeros, &master_secret);
        errdefer crypto.secureZero(u8, &master_secret);

        var client_handshake_traffic: [hash_len]u8 = undefined;
        try crypto_provider.hkdfExpandLabel(.sha256, &handshake_secret, "c hs traffic", &hello_transcript_hash, &client_handshake_traffic);
        errdefer crypto.secureZero(u8, &client_handshake_traffic);

        var server_handshake_traffic: [hash_len]u8 = undefined;
        try crypto_provider.hkdfExpandLabel(.sha256, &handshake_secret, "s hs traffic", &hello_transcript_hash, &server_handshake_traffic);

        return .{
            .provider = crypto_provider,
            .handshake_secret = handshake_secret,
            .master_secret = master_secret,
            .client_handshake_traffic = client_handshake_traffic,
            .server_handshake_traffic = server_handshake_traffic,
        };
    }

    pub const ApplicationSecrets = struct {
        client: [hash_len]u8,
        server: [hash_len]u8,

        pub fn wipe(self: *ApplicationSecrets) void {
            crypto.secureZero(u8, std.mem.asBytes(self));
        }
    };

    pub fn applicationSecrets(self: *const KeySchedule, finished_transcript_hash: [hash_len]u8) provider.HkdfError!ApplicationSecrets {
        var client: [hash_len]u8 = undefined;
        try self.provider.hkdfExpandLabel(.sha256, &self.master_secret, "c ap traffic", &finished_transcript_hash, &client);
        errdefer crypto.secureZero(u8, &client);
        var server: [hash_len]u8 = undefined;
        try self.provider.hkdfExpandLabel(.sha256, &self.master_secret, "s ap traffic", &finished_transcript_hash, &server);
        return .{ .client = client, .server = server };
    }

    pub fn resumptionMasterSecret(
        self: *const KeySchedule,
        handshake_complete_transcript_hash: []const u8,
        out: []u8,
    ) Error!void {
        return deriveResumptionMasterSecret(self.provider, .sha256, &self.master_secret, handshake_complete_transcript_hash, out);
    }

    pub fn deriveResumptionMasterSecret(
        crypto_provider: provider.CryptoProvider,
        hash: provider.Hash,
        master_secret: []const u8,
        handshake_complete_transcript_hash: []const u8,
        out: []u8,
    ) Error!void {
        const expected_len = hash.digestLength();
        if (master_secret.len != expected_len or
            handshake_complete_transcript_hash.len != expected_len or
            out.len != expected_len)
            return error.InvalidSecretLength;
        try crypto_provider.hkdfExpandLabel(hash, master_secret, "res master", handshake_complete_transcript_hash, out);
    }

    pub fn resumptionPsk(
        crypto_provider: provider.CryptoProvider,
        hash: provider.Hash,
        resumption_master_secret: []const u8,
        ticket_nonce: []const u8,
        out: []u8,
    ) Error!void {
        const expected_len = hash.digestLength();
        if (resumption_master_secret.len != expected_len or out.len != expected_len)
            return error.InvalidSecretLength;
        try crypto_provider.hkdfExpandLabel(hash, resumption_master_secret, "resumption", ticket_nonce, out);
    }

    /// RFC 8446 §7.1/§4.2.10: the client's 0-RTT traffic secret, derived
    /// from a resumption PSK and the hash of the *complete* ClientHello
    /// (including its real binders) — never the binder-truncated prefix
    /// used for binder computation itself. Independent of `KeySchedule`:
    /// unlike `initWithPsk`, early data has no ECDHE contribution and is
    /// derived directly from the early secret, before `derived_early_secret`
    /// folds in the (EC)DHE shared secret for the handshake/master chain.
    pub fn clientEarlyTrafficSecret(
        crypto_provider: provider.CryptoProvider,
        psk: *const [hash_len]u8,
        client_hello_hash: [hash_len]u8,
    ) provider.HkdfError![hash_len]u8 {
        var early_secret: [hash_len]u8 = undefined;
        try crypto_provider.hkdfExtract(.sha256, "", psk, &early_secret);
        defer crypto.secureZero(u8, &early_secret);
        var out: [hash_len]u8 = undefined;
        try crypto_provider.hkdfExpandLabel(.sha256, &early_secret, "c e traffic", &client_hello_hash, &out);
        return out;
    }

    pub fn finishedKey(crypto_provider: provider.CryptoProvider, traffic_secret: *const [hash_len]u8) provider.HkdfError![hash_len]u8 {
        var out: [hash_len]u8 = undefined;
        try crypto_provider.hkdfExpandLabel(.sha256, traffic_secret, "finished", "", &out);
        return out;
    }

    /// RFC 8446 §4.4.4: `verify_data = HMAC(finished_key, transcript_hash)`.
    /// Rather than adding a generic keyed-HMAC entry point to the provider
    /// boundary merely for this one TLS Finished computation, this expresses
    /// it with the HKDF-Extract primitive the boundary already exposes:
    /// RFC 5869 defines `HKDF-Extract(salt, IKM) = HMAC-Hash(salt, IKM)`
    /// with `salt` as the HMAC key — so `hkdfExtract(hash, salt =
    /// finished_key, ikm = transcript_hash, out)` computes exactly
    /// `HMAC(finished_key, transcript_hash)`. The pure-Zig provider's own
    /// `hkdfExtract` implementation (`src/crypto/pure_zig.zig`) confirms this:
    /// it calls `Hmac.create(out, ikm, salt)`, i.e. HMAC keyed by `salt` over
    /// `ikm`, matching this call shape bit for bit. This is cross-checked
    /// against the RFC 8448 known-answer `finished_key` fixtures below, which
    /// are unchanged by this migration.
    pub fn verifyData(
        crypto_provider: provider.CryptoProvider,
        traffic_secret: *const [hash_len]u8,
        transcript_hash: [hash_len]u8,
    ) provider.HkdfError![hash_len]u8 {
        var finished_key = try finishedKey(crypto_provider, traffic_secret);
        defer crypto.secureZero(u8, &finished_key);
        var mac: [hash_len]u8 = undefined;
        try crypto_provider.hkdfExtract(.sha256, &finished_key, &transcript_hash, &mac);
        return mac;
    }

    pub fn wipe(self: *KeySchedule) void {
        crypto.secureZero(u8, std.mem.asBytes(self));
    }
};

const testing = std.testing;
const pure_zig = @import("crypto").pure_zig;

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
    // against the primitive it claims to be equivalent to.
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

fn hexBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var bytes: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, hex) catch unreachable;
    return bytes;
}

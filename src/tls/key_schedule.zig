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
//!
//! This is a production-only file: it has no test block of its own. Tests
//! live in `key_schedule_tests.zig`, a separate file that `scripts/
//! audit_crypto_boundary.zig` never scans (#490 review) — this file's own
//! forbidden-pattern scan therefore covers every declaration, no marker or
//! test-boundary heuristic required. Every remaining fallible provider call
//! below arms its output buffer's `errdefer`/`defer` cleanup *before* the
//! call, not after: `CryptoProvider.hkdfExtract`/`.hkdfExpandLabel` do not
//! promise `out` remains untouched on error, so a conforming provider may
//! write a partial output and then fail. Cleanup calls `provider.secureZero`
//! — the canonical shared zeroization seam — never `std.crypto.secureZero`
//! directly.

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
/// to any handshake. `scripts/audit_crypto_boundary.zig` allowlists the two
/// lines below by exact text for exactly that reason (see
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
        defer provider.secureZero(&early_secret);
        try crypto_provider.hkdfExtract(.sha256, "", psk, &early_secret);

        var derived_early: [hash_len]u8 = undefined;
        defer provider.secureZero(&derived_early);
        try crypto_provider.hkdfExpandLabel(.sha256, &early_secret, "derived", &empty_transcript_hash, &derived_early);

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

        // handshake_secret, master_secret, client_handshake_traffic, and
        // server_handshake_traffic are all retained in the returned
        // KeySchedule on success, so each gets an errdefer (wipe only on
        // failure) rather than an unconditional defer.
        var handshake_secret: [hash_len]u8 = undefined;
        errdefer provider.secureZero(&handshake_secret);
        try crypto_provider.hkdfExtract(.sha256, derived_early, shared, &handshake_secret);

        // derived_handshake is purely transient — never retained — so it
        // always gets wiped, success or failure.
        var derived_handshake: [hash_len]u8 = undefined;
        defer provider.secureZero(&derived_handshake);
        try crypto_provider.hkdfExpandLabel(.sha256, &handshake_secret, "derived", &empty_transcript_hash, &derived_handshake);

        var master_secret: [hash_len]u8 = undefined;
        errdefer provider.secureZero(&master_secret);
        try crypto_provider.hkdfExtract(.sha256, &derived_handshake, &zeros, &master_secret);

        var client_handshake_traffic: [hash_len]u8 = undefined;
        errdefer provider.secureZero(&client_handshake_traffic);
        try crypto_provider.hkdfExpandLabel(.sha256, &handshake_secret, "c hs traffic", &hello_transcript_hash, &client_handshake_traffic);

        var server_handshake_traffic: [hash_len]u8 = undefined;
        errdefer provider.secureZero(&server_handshake_traffic);
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
            provider.secureZero(std.mem.asBytes(self));
        }
    };

    pub fn applicationSecrets(self: *const KeySchedule, finished_transcript_hash: [hash_len]u8) provider.HkdfError!ApplicationSecrets {
        var client: [hash_len]u8 = undefined;
        errdefer provider.secureZero(&client);
        try self.provider.hkdfExpandLabel(.sha256, &self.master_secret, "c ap traffic", &finished_transcript_hash, &client);

        var server: [hash_len]u8 = undefined;
        errdefer provider.secureZero(&server);
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
        // `out` is caller-owned but this function is the one deriving secret
        // bytes into it, so a partial write on failure is this function's
        // responsibility to clean up, same as an owned local buffer.
        errdefer provider.secureZero(out);
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
        errdefer provider.secureZero(out);
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
        defer provider.secureZero(&early_secret);
        try crypto_provider.hkdfExtract(.sha256, "", psk, &early_secret);

        var out: [hash_len]u8 = undefined;
        errdefer provider.secureZero(&out);
        try crypto_provider.hkdfExpandLabel(.sha256, &early_secret, "c e traffic", &client_hello_hash, &out);

        return out;
    }

    pub fn finishedKey(crypto_provider: provider.CryptoProvider, traffic_secret: *const [hash_len]u8) provider.HkdfError![hash_len]u8 {
        var out: [hash_len]u8 = undefined;
        errdefer provider.secureZero(&out);
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
    /// `ikm`, matching this call shape bit for bit. `key_schedule_tests.zig`
    /// cross-checks this against a direct HMAC-SHA256 computation.
    pub fn verifyData(
        crypto_provider: provider.CryptoProvider,
        traffic_secret: *const [hash_len]u8,
        transcript_hash: [hash_len]u8,
    ) provider.HkdfError![hash_len]u8 {
        var finished_key = try finishedKey(crypto_provider, traffic_secret);
        defer provider.secureZero(&finished_key);

        var mac: [hash_len]u8 = undefined;
        errdefer provider.secureZero(&mac);
        try crypto_provider.hkdfExtract(.sha256, &finished_key, &transcript_hash, &mac);

        return mac;
    }

    pub fn wipe(self: *KeySchedule) void {
        provider.secureZero(std.mem.asBytes(self));
    }
};

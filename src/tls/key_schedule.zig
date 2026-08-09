//! Protocol-neutral TLS 1.3 key schedule, hash-agile across SHA-256 and
//! SHA-384 (#564): every secret length and HKDF call follows the hash the
//! caller names, which must always be `algorithms.transcriptHash(suite)` for
//! the negotiated cipher suite — this module does not select or persist a
//! hash of its own, so it can never disagree with the negotiated suite.
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
//! transcript hashing (`Sha256.hash`/`Sha384.hash` for the comptime/runtime
//! empty-transcript-hash constants below): that hash has no secret input, so
//! it stays provider-independent by design, matching
//! `docs/CRYPTO_PROVIDER_AUDIT.md`'s "unkeyed transcript hashing may remain
//! provider-independent" disposition.
//!
//! `KeySchedule` holds the `CryptoProvider` and the negotiated `Hash` it was
//! constructed with (the same borrowed-value-type convention `QuicTlsAdapter`
//! uses) so instance methods (`applicationSecrets`, `resumptionMasterSecret`)
//! do not need either passed again; free functions that do not require a
//! live `KeySchedule` instance (`resumptionPsk`, `deriveResumptionMasterSecret`,
//! `clientEarlyTrafficSecret`, `finishedKey`, `verifyData`) take an explicit
//! `hash: provider.Hash`, since resumption/ticket code (`new_session_ticket.zig`)
//! and 0-RTT paths often need these before — or without ever constructing —
//! a full `KeySchedule`, and a resumed ticket's own stored hash need not
//! match whatever `KeySchedule` (if any) is live for the current connection.
//!
//! Every secret this module returns is bounded to `max_digest_len` (48
//! bytes, SHA-384's output) with an explicit logical length rather than a
//! hash-family-sized array — the caller-visible shape does not change with
//! the negotiated suite, only how many of those bytes are meaningful.
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
const Sha384 = crypto.hash.sha2.Sha384;

/// Largest secret this module produces or consumes (SHA-384's 48-byte
/// digest/PRK length) — every bounded buffer below is sized to this, with
/// callers slicing to the negotiated hash's actual `digestLength()`.
pub const max_digest_len = provider.max_digest_len;
/// X25519 shared-secret length (RFC 7748) — this module's only consumer of
/// key-exchange output, not a key-exchange implementation itself.
pub const shared_secret_len = 32;

/// Errors this module's own length preconditions can raise, composed with the
/// provider's typed HKDF error set so callers see (and can distinguish)
/// exactly why a derivation failed rather than a single collapsed error.
pub const Error = error{InvalidSecretLength} || provider.HkdfError;

/// SHA-256's digest length — used only by the one documented comptime
/// exception below (`derived_early_secret_sha256`); every other declaration
/// in this file sizes its buffers to `max_digest_len` and slices to the
/// negotiated hash's `digestLength()` instead of naming a fixed hash.
const hash_len = Sha256.digest_length;

const empty_transcript_hash: [hash_len]u8 = blk: {
    @setEvalBranchQuota(100_000);
    var out: [hash_len]u8 = undefined;
    Sha256.hash("", &out, .{});
    break :blk out;
};

/// RFC 8446 §7.1's "derived" early secret for the zero-PSK (full handshake,
/// non-resumed) key-schedule chain under SHA-256:
/// `HKDF-Expand-Label(HKDF-Extract(0, 0), "derived", Hash(""), Hash.length)`.
/// This is a fixed public constant — the early secret input is the all-zero
/// PSK, not connection-specific secret material — so it is computed once at
/// compile time directly, the same way `empty_transcript_hash` above is:
/// there is no runtime provider available at comptime, and none is needed,
/// since nothing here is a secret specific to any handshake.
/// `scripts/audit_crypto_boundary.zig` allowlists the two lines below by
/// exact text for exactly that reason (see `docs/CRYPTO_PROVIDER_AUDIT.md`).
/// SHA-384's equivalent constant is not worth a second comptime block +
/// audit exemption for a value computed at most once per full handshake:
/// `zeroPskDerivedEarlySecret` below derives it through the provider at
/// runtime instead, for every hash family other than this one fast path.
const derived_early_secret_sha256: [hash_len]u8 = blk: {
    @setEvalBranchQuota(100_000);
    const HkdfSha256 = crypto.kdf.hkdf.HkdfSha256;
    const zeros = [_]u8{0} ** hash_len;
    const early_secret = HkdfSha256.extract("", &zeros);
    break :blk crypto.tls.hkdfExpandLabel(HkdfSha256, early_secret, "derived", &empty_transcript_hash, hash_len);
};

/// Unkeyed `Hash("")` for `hash`, zero-padded to `max_digest_len` — never
/// exposes uninitialized suffix bytes. Unkeyed transcript hashing stays
/// provider-independent by design (see the module doc comment).
fn emptyTranscriptHashFor(hash: provider.Hash) [max_digest_len]u8 {
    var out: [max_digest_len]u8 = [_]u8{0} ** max_digest_len;
    switch (hash) {
        .sha256 => @memcpy(out[0..hash_len], &empty_transcript_hash),
        .sha384 => Sha384.hash("", out[0..Sha384.digest_length], .{}),
    }
    return out;
}

/// The "derived" early secret for the zero-PSK key-schedule chain, under
/// whichever hash the negotiated suite selected, written into `out`
/// (zeroed first so bytes beyond the active hash's digest length are never
/// left uninitialized). SHA-256 copies the precomputed public constant;
/// every other hash derives it fresh through the provider (two HKDF calls,
/// once per full handshake — not worth a second comptime/audit exemption).
/// Out-parameter style (#564 review), like every other retained-or-caller-
/// owned secret in this file: writing directly into caller storage means
/// there is never a separate successful-path local left unwiped after a
/// by-value return.
fn zeroPskDerivedEarlySecret(crypto_provider: provider.CryptoProvider, hash: provider.Hash, out: *[max_digest_len]u8) provider.HkdfError!void {
    out.* = [_]u8{0} ** max_digest_len;
    switch (hash) {
        .sha256 => @memcpy(out[0..hash_len], &derived_early_secret_sha256),
        .sha384 => {
            const n = Sha384.digest_length;
            const zeros = [_]u8{0} ** n;
            var early_secret: [n]u8 = undefined;
            defer provider.secureZero(&early_secret);
            try crypto_provider.hkdfExtract(.sha384, "", &zeros, &early_secret);
            const empty_hash = emptyTranscriptHashFor(.sha384);
            try crypto_provider.hkdfExpandLabel(.sha384, &early_secret, "derived", empty_hash[0..n], out[0..n]);
        },
    }
}

pub const KeySchedule = struct {
    provider: provider.CryptoProvider,
    hash: provider.Hash,
    handshake_secret: [max_digest_len]u8 = [_]u8{0} ** max_digest_len,
    master_secret: [max_digest_len]u8 = [_]u8{0} ** max_digest_len,
    client_handshake_traffic: [max_digest_len]u8 = [_]u8{0} ** max_digest_len,
    server_handshake_traffic: [max_digest_len]u8 = [_]u8{0} ** max_digest_len,

    /// This connection's negotiated transcript/HKDF digest length —
    /// `self.hash.digestLength()`, exposed so callers never need to
    /// re-derive it from the cipher suite once a schedule already exists.
    pub fn digestLen(self: *const KeySchedule) usize {
        return self.hash.digestLength();
    }

    pub fn init(
        crypto_provider: provider.CryptoProvider,
        hash: provider.Hash,
        shared: []const u8,
        hello_transcript_hash: []const u8,
        out: *KeySchedule,
    ) Error!void {
        const n = hash.digestLength();
        if (hello_transcript_hash.len != n) return error.InvalidSecretLength;
        var derived_early: [max_digest_len]u8 = undefined;
        defer provider.secureZero(&derived_early);
        try zeroPskDerivedEarlySecret(crypto_provider, hash, &derived_early);
        try initFromEarlySecret(crypto_provider, hash, derived_early[0..n], shared, hello_transcript_hash, out);
    }

    /// PSK-resumed (`psk_dhe_ke`) handshake: the same key-schedule chain as
    /// `init`, but starting from a real early secret derived from the
    /// resumption PSK (RFC 8446 §7.1) instead of the all-zero-PSK early
    /// secret `init` uses. `psk` must already be exactly `hash.digestLength()`
    /// bytes (the resumption PSK produced by `resumptionPsk`, under the same
    /// hash this ticket's own suite negotiated). X25519 key share remains
    /// mandatory in this profile, so `shared` is still the ECDHE shared
    /// secret.
    pub fn initWithPsk(
        crypto_provider: provider.CryptoProvider,
        hash: provider.Hash,
        psk: []const u8,
        shared: []const u8,
        hello_transcript_hash: []const u8,
        out: *KeySchedule,
    ) Error!void {
        const n = hash.digestLength();
        if (psk.len != n) return error.InvalidSecretLength;

        var early_secret: [max_digest_len]u8 = [_]u8{0} ** max_digest_len;
        defer provider.secureZero(&early_secret);
        try crypto_provider.hkdfExtract(hash, "", psk, early_secret[0..n]);

        var derived_early: [max_digest_len]u8 = [_]u8{0} ** max_digest_len;
        defer provider.secureZero(&derived_early);
        const empty_hash = emptyTranscriptHashFor(hash);
        try crypto_provider.hkdfExpandLabel(hash, early_secret[0..n], "derived", empty_hash[0..n], derived_early[0..n]);

        try initFromEarlySecret(crypto_provider, hash, derived_early[0..n], shared, hello_transcript_hash, out);
    }

    /// Shared continuation from a "derived" early secret (RFC 8446 §7.1)
    /// into the handshake/master secrets and handshake traffic secrets. Used
    /// by both the zero-PSK (`init`) and real-PSK (`initWithPsk`) entry
    /// points, which differ only in how `derived_early` was produced.
    fn initFromEarlySecret(
        crypto_provider: provider.CryptoProvider,
        hash: provider.Hash,
        derived_early: []const u8,
        shared: []const u8,
        hello_transcript_hash: []const u8,
        out: *KeySchedule,
    ) Error!void {
        const n = hash.digestLength();
        if (shared.len != shared_secret_len or derived_early.len != n or hello_transcript_hash.len != n)
            return error.InvalidSecretLength;
        const zeros = [_]u8{0} ** max_digest_len;

        // #564 review: every retained secret is derived directly into
        // `out.*` — never a separate local later copied in by a by-value
        // `return .{...}` — so there is no successful-path stack copy left
        // unwiped once this returns. `out.*` is reset to its (zeroed)
        // default field values first so a single `errdefer out.wipe()`,
        // armed from that point on, covers every failure below uniformly,
        // partial writes included.
        out.* = .{ .provider = crypto_provider, .hash = hash };
        errdefer out.wipe();

        try crypto_provider.hkdfExtract(hash, derived_early, shared, out.handshake_secret[0..n]);

        // derived_handshake is purely transient — never retained — so it
        // always gets wiped, success or failure.
        var derived_handshake: [max_digest_len]u8 = [_]u8{0} ** max_digest_len;
        defer provider.secureZero(&derived_handshake);
        const empty_hash = emptyTranscriptHashFor(hash);
        try crypto_provider.hkdfExpandLabel(hash, out.handshake_secret[0..n], "derived", empty_hash[0..n], derived_handshake[0..n]);

        try crypto_provider.hkdfExtract(hash, derived_handshake[0..n], zeros[0..n], out.master_secret[0..n]);

        try crypto_provider.hkdfExpandLabel(hash, out.handshake_secret[0..n], "c hs traffic", hello_transcript_hash, out.client_handshake_traffic[0..n]);

        try crypto_provider.hkdfExpandLabel(hash, out.handshake_secret[0..n], "s hs traffic", hello_transcript_hash, out.server_handshake_traffic[0..n]);
    }

    pub const ApplicationSecrets = struct {
        client: [max_digest_len]u8 = [_]u8{0} ** max_digest_len,
        server: [max_digest_len]u8 = [_]u8{0} ** max_digest_len,
        len: usize = 0,

        pub fn clientSecret(self: *const ApplicationSecrets) []const u8 {
            return self.client[0..self.len];
        }

        pub fn serverSecret(self: *const ApplicationSecrets) []const u8 {
            return self.server[0..self.len];
        }

        pub fn wipe(self: *ApplicationSecrets) void {
            provider.secureZero(std.mem.asBytes(self));
        }
    };

    /// Out-parameter style (#564 review): both secrets are derived directly
    /// into `out.*`, never a pair of locals copied in by a by-value return.
    pub fn applicationSecrets(self: *const KeySchedule, finished_transcript_hash: []const u8, out: *ApplicationSecrets) Error!void {
        const n = self.digestLen();
        if (finished_transcript_hash.len != n) return error.InvalidSecretLength;

        out.* = .{ .len = n };
        errdefer out.wipe();
        try self.provider.hkdfExpandLabel(self.hash, self.master_secret[0..n], "c ap traffic", finished_transcript_hash, out.client[0..n]);
        try self.provider.hkdfExpandLabel(self.hash, self.master_secret[0..n], "s ap traffic", finished_transcript_hash, out.server[0..n]);
    }

    pub fn resumptionMasterSecret(
        self: *const KeySchedule,
        handshake_complete_transcript_hash: []const u8,
        out: []u8,
    ) Error!void {
        const n = self.digestLen();
        return deriveResumptionMasterSecret(self.provider, self.hash, self.master_secret[0..n], handshake_complete_transcript_hash, out);
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
    /// derived directly from the early secret, before the "derived" early
    /// secret folds in the (EC)DHE shared secret for the handshake/master
    /// chain. `out` must be exactly `hash.digestLength()` bytes.
    pub fn clientEarlyTrafficSecret(
        crypto_provider: provider.CryptoProvider,
        hash: provider.Hash,
        psk: []const u8,
        client_hello_hash: []const u8,
        out: []u8,
    ) Error!void {
        const n = hash.digestLength();
        if (psk.len != n or client_hello_hash.len != n or out.len != n) return error.InvalidSecretLength;

        var early_secret: [max_digest_len]u8 = [_]u8{0} ** max_digest_len;
        defer provider.secureZero(&early_secret);
        try crypto_provider.hkdfExtract(hash, "", psk, early_secret[0..n]);

        errdefer provider.secureZero(out);
        try crypto_provider.hkdfExpandLabel(hash, early_secret[0..n], "c e traffic", client_hello_hash, out);
    }

    /// RFC 8446 §7.2: `application_traffic_secret_N+1 =
    /// HKDF-Expand-Label(application_traffic_secret_N, "traffic upd", "",
    /// Hash.length)` — the one-way step a post-handshake `KeyUpdate` (#357)
    /// takes to replace one direction's application traffic secret.
    ///
    /// Independent of `KeySchedule` because it is: the chain is seeded by the
    /// application traffic secret and never touches the master secret again,
    /// so a record layer holding only the current secret can advance without
    /// retaining the handshake's key schedule. It is also direction-agnostic
    /// — each direction advances its own secret on its own schedule.
    ///
    /// `traffic_secret` and `out` must both be exactly `hash.digestLength()`
    /// bytes and must not alias: `traffic_secret` is the HKDF PRK, re-read for
    /// every output block, so writing the new secret over it in place would
    /// feed later blocks a mutated key. Callers advancing a secret in place
    /// derive into a scratch buffer and then replace.
    pub fn nextTrafficSecret(
        crypto_provider: provider.CryptoProvider,
        hash: provider.Hash,
        traffic_secret: []const u8,
        out: []u8,
    ) Error!void {
        const n = hash.digestLength();
        if (traffic_secret.len != n or out.len != n) return error.InvalidSecretLength;
        errdefer provider.secureZero(out);
        try crypto_provider.hkdfExpandLabel(hash, traffic_secret, "traffic upd", "", out);
    }

    pub fn finishedKey(crypto_provider: provider.CryptoProvider, hash: provider.Hash, traffic_secret: []const u8, out: []u8) Error!void {
        const n = hash.digestLength();
        if (traffic_secret.len != n or out.len != n) return error.InvalidSecretLength;
        errdefer provider.secureZero(out);
        try crypto_provider.hkdfExpandLabel(hash, traffic_secret, "finished", "", out);
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
    /// cross-checks this against a direct HMAC computation for both hashes.
    /// `out` must be exactly `hash.digestLength()` bytes.
    pub fn verifyData(
        crypto_provider: provider.CryptoProvider,
        hash: provider.Hash,
        traffic_secret: []const u8,
        transcript_hash: []const u8,
        out: []u8,
    ) Error!void {
        const n = hash.digestLength();
        if (traffic_secret.len != n or transcript_hash.len != n or out.len != n) return error.InvalidSecretLength;

        var finished_key: [max_digest_len]u8 = [_]u8{0} ** max_digest_len;
        defer provider.secureZero(&finished_key);
        try finishedKey(crypto_provider, hash, traffic_secret, finished_key[0..n]);

        errdefer provider.secureZero(out);
        try crypto_provider.hkdfExtract(hash, finished_key[0..n], transcript_hash, out);
    }

    pub fn wipe(self: *KeySchedule) void {
        provider.secureZero(std.mem.asBytes(self));
    }
};

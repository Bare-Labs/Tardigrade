//! QUIC server address-validation and anti-amplification (#250, RFC 9000 §8 &
//! RFC 9001 §5.8): the safety mechanisms that let a server handle
//! unauthenticated UDP before a peer's address is validated without becoming an
//! amplification vector.
//!
//! - `AntiAmplification` enforces the 3x send budget per unvalidated path.
//! - `RetryTokens` issues and verifies integrity-protected address-validation
//!   tokens (timestamp/expiry, address binding, key rotation, tamper rejection).
//! - `PathManager` (#251) owns the per-connection path table keyed by the
//!   (local, remote) address tuple: PATH_CHALLENGE/PATH_RESPONSE validation,
//!   NAT-rebinding vs. migration classification, the configurable migration
//!   policy from `config.zig`, and the RFC 9000 §9.4 congestion-reset rule.
//! - `Metrics` exposes the operator counters #250/#251 require.
//!
//! Packet framing and DCID parsing stay in `packet.zig` (#243); CID issuance
//! and routing live in `cid.zig`; interop/fuzz in #247.

const std = @import("std");
const config = @import("config.zig");
const packet = @import("packet.zig");
const pmtu = @import("pmtu.zig");
const udp = @import("udp.zig");
const secrets = @import("crypto_secrets");

const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;

// ---------------------------------------------------------------------------
// Anti-amplification (RFC 9000 §8.1)
// ---------------------------------------------------------------------------

/// A server may send at most this multiple of the bytes it has received from an
/// unvalidated peer address.
pub const anti_amplification_factor = 3;

/// Per-path ledger of bytes received from and sent to a peer whose address has
/// not yet been validated. Once the address is validated the limit is lifted.
/// The connection layer records every received datagram and every send (including
/// handshake/certificate bytes and retransmissions) against this ledger.
pub const AntiAmplification = struct {
    received: u64 = 0,
    sent: u64 = 0,
    validated: bool = false,

    pub fn recordReceived(self: *AntiAmplification, bytes: u64) void {
        self.received +|= bytes;
    }

    pub fn recordSent(self: *AntiAmplification, bytes: u64) void {
        self.sent +|= bytes;
    }

    /// Mark the peer address validated (a Retry/handshake token was verified or
    /// the handshake completed). Lifts the send budget.
    pub fn markValidated(self: *AntiAmplification) void {
        self.validated = true;
    }

    /// Total bytes this side is currently permitted to have sent.
    pub fn budget(self: *const AntiAmplification) u64 {
        if (self.validated) return std.math.maxInt(u64);
        return self.received *| anti_amplification_factor;
    }

    /// Bytes that may still be sent before the budget is exhausted.
    pub fn remaining(self: *const AntiAmplification) u64 {
        if (self.validated) return std.math.maxInt(u64);
        return self.budget() -| self.sent;
    }

    /// Whether a datagram of `bytes` may be sent now without exceeding the
    /// budget. A blocked send must be deferred, not dropped or spun on.
    pub fn canSend(self: *const AntiAmplification, bytes: u64) bool {
        if (self.validated) return true;
        return (self.sent +| bytes) <= self.budget();
    }
};

// ---------------------------------------------------------------------------
// Retry / address-validation tokens (RFC 9000 §8.1.1–§8.1.4)
// ---------------------------------------------------------------------------

pub const token_key_len = Aes128Gcm.key_length;
pub const token_nonce_len = Aes128Gcm.nonce_length;
pub const token_tag_len = Aes128Gcm.tag_length;
pub const max_token_keys = 8;

/// What a token authenticates. Retry tokens are bound to a specific connection
/// attempt (original DCID + QUIC version); the enum leaves room for the future
/// NEW_TOKEN address-validation flow (RFC 9000 §8.1.3) without a format break.
pub const TokenKind = enum(u8) {
    retry = 1,
    address_validation = 2,
};

/// Fixed-size prefix of the token plaintext: `kind(1) + version(4) +
/// issued_at(8) + odcid_len(1)`. The connection ID, Retry SCID, address, and
/// port follow.
const token_header_len = 1 + 4 + 8 + 1;
/// Variable address suffix: `family(1) + addr_len(1) + addr(4|16) +
/// scope_id(4, IPv6 only) + port(2)`.
const token_addr_min_len = 1 + 1 + 4 + 2; // IPv4
const token_addr_max_len = 1 + 1 + 16 + 4 + 2; // IPv6, with scope id
/// `retry_scid_len(1)` plus the CID bytes it prefixes.
const token_retry_scid_min_len = 1;
const token_retry_scid_max_len = 1 + udp.MaxConnectionIdLen;
const token_min_plaintext_len = token_header_len + 0 + token_retry_scid_min_len + token_addr_min_len;
const token_max_plaintext_len = token_header_len + udp.MaxConnectionIdLen + token_retry_scid_max_len + token_addr_max_len;

/// Largest possible encoded token (`key_id + nonce + plaintext + tag`).
pub const max_token_len = 1 + token_nonce_len + token_max_plaintext_len + token_tag_len;

pub const TokenError = error{
    /// Token is too short/long or otherwise not well-formed.
    MalformedToken,
    /// Token names a key id the server does not hold (e.g. rotated out).
    UnknownTokenKey,
    /// AEAD authentication failed — the token was forged or tampered with.
    TokenAuthenticationFailed,
    /// Token authenticated but was issued to a different peer address.
    TokenAddressMismatch,
    /// Token authenticated but is expired or impossibly future-dated.
    TokenExpired,
    /// Token authenticated but is not the expected kind (e.g. NEW_TOKEN where a
    /// Retry token was required).
    UnexpectedTokenKind,
};

/// A rotating ring of AEAD keys used to protect address-validation tokens.
/// Installing a key makes it current; older keys remain valid for verification
/// until explicitly retired, so tokens issued before a rotation still validate.
pub const RetryTokenKeyRing = struct {
    /// `FixedSecret` keeps each slot's byte storage live for the ring's
    /// entire lifetime — installed/retired is tracked by `.len` (0 vs
    /// `token_key_len`), never by wrapping the array in an outer
    /// `?[N]u8`. An optional wrapper would make the payload logically
    /// inactive the moment a key is retired, and safety-checked builds are
    /// free to poison-fill an inactive optional payload — observably so on
    /// Linux x64 — which would make it impossible to assert the bytes were
    /// actually zeroed rather than merely tagged absent.
    keys: [max_token_keys]secrets.FixedSecret(token_key_len) = [_]secrets.FixedSecret(token_key_len){secrets.FixedSecret(token_key_len){}} ** max_token_keys,
    current: u8 = 0,

    pub fn install(self: *RetryTokenKeyRing, key_id: u8, key: *const [token_key_len]u8) void {
        std.debug.assert(key_id < max_token_keys);
        self.keys[key_id].replace(key) catch unreachable;
        self.current = key_id;
    }

    pub fn retire(self: *RetryTokenKeyRing, key_id: u8) void {
        if (key_id >= max_token_keys) return;
        self.keys[key_id].deinit();
    }

    pub fn deinit(self: *RetryTokenKeyRing) void {
        for (&self.keys) |*slot| slot.deinit();
        self.current = 0;
    }

    fn get(self: *const RetryTokenKeyRing, key_id: u8) ?*const [token_key_len]u8 {
        if (key_id >= max_token_keys) return null;
        if (self.keys[key_id].len == 0) return null;
        return &self.keys[key_id].bytes;
    }
};

/// Context recovered from a validated Retry token. The connection layer needs
/// the original destination connection ID and Retry source connection ID to
/// validate the Retry flow and populate/verify the
/// `original_destination_connection_id` / `retry_source_connection_id`
/// transport parameters (RFC 9000 §7.3), plus the QUIC version.
pub const RetryContext = struct {
    original_dcid: udp.ConnectionId,
    retry_scid: udp.ConnectionId,
    quic_version: u32,
};

/// Issues and verifies Retry address-validation tokens. Tokens are AEAD-sealed
/// with a key from the ring and bind the original destination connection ID,
/// the QUIC version, the peer address, and an issue timestamp.
pub const RetryTokens = struct {
    keys: RetryTokenKeyRing = .{},
    /// Maximum token age, in microseconds, before verification rejects it.
    lifetime_us: u64 = 10 * std.time.us_per_s,
    /// Tolerance for a token whose issue time is slightly ahead of the
    /// validator's clock. Tokens further in the future are rejected.
    allowed_clock_skew_us: u64 = 0,

    /// Seal a Retry token binding `original_dcid` + `retry_scid` +
    /// `quic_version` + `address`, stamped at `issued_at_us`. `nonce` must be
    /// unique per token under the current key (the caller supplies it so the
    /// module stays deterministic and free of ambient randomness).
    pub fn issueRetry(
        self: *const RetryTokens,
        original_dcid: []const u8,
        retry_scid: []const u8,
        quic_version: u32,
        address: udp.Address,
        issued_at_us: u64,
        nonce: [token_nonce_len]u8,
        out: []u8,
    ) error{ OutputTooSmall, NoTokenKey, ConnectionIdTooLong }![]u8 {
        if (original_dcid.len > udp.MaxConnectionIdLen) return error.ConnectionIdTooLong;
        if (retry_scid.len > udp.MaxConnectionIdLen) return error.ConnectionIdTooLong;
        const key = self.keys.get(self.keys.current) orelse return error.NoTokenKey;

        var plaintext: [token_max_plaintext_len]u8 = undefined;
        const plaintext_len = encodeTokenPlaintext(.retry, quic_version, original_dcid, retry_scid, address, issued_at_us, &plaintext);
        const total = 1 + token_nonce_len + plaintext_len + token_tag_len;
        if (out.len < total) return error.OutputTooSmall;

        out[0] = self.keys.current;
        @memcpy(out[1..][0..token_nonce_len], &nonce);
        const cipher = out[1 + token_nonce_len ..][0..plaintext_len];
        var tag: [token_tag_len]u8 = undefined;
        Aes128Gcm.encrypt(cipher, &tag, plaintext[0..plaintext_len], &.{}, nonce, key.*);
        @memcpy(out[1 + token_nonce_len + plaintext_len ..][0..token_tag_len], &tag);
        return out[0..total];
    }

    /// Verify a Retry token was issued by this server to `address`, is a Retry
    /// token, and is neither expired nor impossibly future-dated. Returns the
    /// bound original DCID and QUIC version for the connection layer.
    pub fn validateRetry(self: *const RetryTokens, token: []const u8, address: udp.Address, now_us: u64) TokenError!RetryContext {
        if (token.len < 1 + token_nonce_len + token_min_plaintext_len + token_tag_len) return error.MalformedToken;
        if (token.len > max_token_len) return error.MalformedToken;
        const plaintext_len = token.len - 1 - token_nonce_len - token_tag_len;

        const key = self.keys.get(token[0]) orelse return error.UnknownTokenKey;
        var nonce: [token_nonce_len]u8 = undefined;
        @memcpy(&nonce, token[1..][0..token_nonce_len]);
        const cipher = token[1 + token_nonce_len ..][0..plaintext_len];
        var tag: [token_tag_len]u8 = undefined;
        @memcpy(&tag, token[1 + token_nonce_len + plaintext_len ..][0..token_tag_len]);

        var plaintext: [token_max_plaintext_len]u8 = undefined;
        Aes128Gcm.decrypt(plaintext[0..plaintext_len], cipher, tag, &.{}, nonce, key.*) catch return error.TokenAuthenticationFailed;

        const decoded = decodeTokenPlaintext(plaintext[0..plaintext_len]) catch return error.MalformedToken;
        if (decoded.kind != .retry) return error.UnexpectedTokenKind;
        if (!addressEql(decoded.address, address)) return error.TokenAddressMismatch;
        // Reject tokens dated further in the future than the allowed skew, so a
        // backwards clock jump cannot make a stale token look freshly issued.
        if (decoded.issued_at_us > now_us +| self.allowed_clock_skew_us) return error.TokenExpired;
        if ((now_us -| decoded.issued_at_us) > self.lifetime_us) return error.TokenExpired;
        return .{
            .original_dcid = decoded.original_dcid,
            .retry_scid = decoded.retry_scid,
            .quic_version = decoded.quic_version,
        };
    }
};

const DecodedToken = struct {
    kind: TokenKind,
    quic_version: u32,
    issued_at_us: u64,
    original_dcid: udp.ConnectionId,
    retry_scid: udp.ConnectionId,
    address: udp.Address,
};

fn encodeTokenPlaintext(
    kind: TokenKind,
    quic_version: u32,
    original_dcid: []const u8,
    retry_scid: []const u8,
    address: udp.Address,
    issued_at_us: u64,
    out: *[token_max_plaintext_len]u8,
) usize {
    var pos: usize = 0;
    out[pos] = @intFromEnum(kind);
    pos += 1;
    std.mem.writeInt(u32, out[pos..][0..4], quic_version, .big);
    pos += 4;
    std.mem.writeInt(u64, out[pos..][0..8], issued_at_us, .big);
    pos += 8;
    out[pos] = @intCast(original_dcid.len);
    pos += 1;
    @memcpy(out[pos..][0..original_dcid.len], original_dcid);
    pos += original_dcid.len;
    out[pos] = @intCast(retry_scid.len);
    pos += 1;
    @memcpy(out[pos..][0..retry_scid.len], retry_scid);
    pos += retry_scid.len;

    out[pos] = @intFromEnum(address.family);
    pos += 1;
    const addr = address.slice();
    out[pos] = @intCast(addr.len);
    pos += 1;
    @memcpy(out[pos..][0..addr.len], addr);
    pos += addr.len;
    // Encode scope_id for IPv6 so scoped (link-local) addresses round-trip.
    if (address.family == .ip6) {
        std.mem.writeInt(u32, out[pos..][0..4], address.scope_id, .big);
        pos += 4;
    }
    std.mem.writeInt(u16, out[pos..][0..2], address.port, .big);
    pos += 2;
    return pos;
}

fn decodeTokenPlaintext(bytes: []const u8) error{MalformedToken}!DecodedToken {
    var pos: usize = 0;
    if (bytes.len < token_header_len) return error.MalformedToken;
    const kind = std.enums.fromInt(TokenKind, bytes[pos]) orelse return error.MalformedToken;
    pos += 1;
    const quic_version = std.mem.readInt(u32, bytes[pos..][0..4], .big);
    pos += 4;
    const issued_at_us = std.mem.readInt(u64, bytes[pos..][0..8], .big);
    pos += 8;
    const odcid_len = bytes[pos];
    pos += 1;
    if (odcid_len > udp.MaxConnectionIdLen) return error.MalformedToken;
    if (bytes.len - pos < odcid_len) return error.MalformedToken;
    var original_dcid = udp.ConnectionId{ .len = odcid_len };
    @memcpy(original_dcid.bytes[0..odcid_len], bytes[pos..][0..odcid_len]);
    pos += odcid_len;

    if (bytes.len - pos < 1) return error.MalformedToken;
    const retry_scid_len = bytes[pos];
    pos += 1;
    if (retry_scid_len > udp.MaxConnectionIdLen) return error.MalformedToken;
    if (bytes.len - pos < retry_scid_len) return error.MalformedToken;
    var retry_scid = udp.ConnectionId{ .len = retry_scid_len };
    @memcpy(retry_scid.bytes[0..retry_scid_len], bytes[pos..][0..retry_scid_len]);
    pos += retry_scid_len;

    if (bytes.len - pos < 2) return error.MalformedToken;
    const family = std.enums.fromInt(udp.AddressFamily, bytes[pos]) orelse return error.MalformedToken;
    pos += 1;
    const addr_len = bytes[pos];
    pos += 1;
    const expected_addr_len: usize = switch (family) {
        .ip4 => 4,
        .ip6 => 16,
    };
    if (addr_len != expected_addr_len) return error.MalformedToken;
    if (bytes.len - pos < expected_addr_len) return error.MalformedToken;
    var address = udp.Address{ .family = family, .port = 0 };
    @memcpy(address.bytes[0..expected_addr_len], bytes[pos..][0..expected_addr_len]);
    pos += expected_addr_len;
    if (family == .ip6) {
        if (bytes.len - pos < 4) return error.MalformedToken;
        address.scope_id = std.mem.readInt(u32, bytes[pos..][0..4], .big);
        pos += 4;
    }
    if (bytes.len - pos != 2) return error.MalformedToken;
    address.port = std.mem.readInt(u16, bytes[pos..][0..2], .big);

    return .{
        .kind = kind,
        .quic_version = quic_version,
        .issued_at_us = issued_at_us,
        .original_dcid = original_dcid,
        .retry_scid = retry_scid,
        .address = address,
    };
}

fn addressEql(a: udp.Address, b: udp.Address) bool {
    if (a.family != b.family or a.port != b.port) return false;
    if (!std.mem.eql(u8, a.slice(), b.slice())) return false;
    // scope_id distinguishes link-local IPv6 paths and now round-trips in tokens.
    return a.scope_id == b.scope_id;
}

// ---------------------------------------------------------------------------
// Operator metrics (issue #250)
// ---------------------------------------------------------------------------

/// Counters that let an operator distinguish normal Retry usage from invalid
/// tokens, budget-blocked sends, and unknown-CID / stateless-reset traffic.
pub const Metrics = struct {
    retry_packets_sent: u64 = 0,
    invalid_tokens: u64 = 0,
    amplification_blocked_sends: u64 = 0,
    stateless_resets_sent: u64 = 0,
    unknown_connection_id_packets: u64 = 0,
    // Path lifecycle (#251): the acceptance criteria require distinguishing
    // rebinding, migration, validation failure, and blocked attempts.
    path_challenges_sent: u64 = 0,
    path_validations_succeeded: u64 = 0,
    /// Validations that failed terminally: the challenge expired unanswered.
    path_validations_failed: u64 = 0,
    /// PATH_RESPONSE frames that validated nothing — wrong payload, wrong
    /// path, or no outstanding challenge. Kept separate from
    /// `path_validations_failed` because the probe may still succeed; a spike
    /// here without failures suggests reordering or off-path spoofing.
    path_response_mismatches: u64 = 0,
    nat_rebindings: u64 = 0,
    migrations: u64 = 0,
    migrations_blocked: u64 = 0,
    /// A host migration validated but could not promote because the peer had
    /// no unused CID to migrate to (RFC 9000 §9.5). Kept separate from
    /// `migrations_blocked` (policy denial before any probe) because this
    /// path already spent a validation round trip.
    migrations_blocked_no_peer_cid: u64 = 0,

    pub fn recordRetrySent(self: *Metrics) void {
        self.retry_packets_sent += 1;
    }

    pub fn recordInvalidToken(self: *Metrics) void {
        self.invalid_tokens += 1;
    }

    pub fn recordAmplificationBlocked(self: *Metrics) void {
        self.amplification_blocked_sends += 1;
    }

    pub fn recordStatelessReset(self: *Metrics) void {
        self.stateless_resets_sent += 1;
    }

    pub fn recordUnknownConnectionId(self: *Metrics) void {
        self.unknown_connection_id_packets += 1;
    }

    /// Fold a token-validation result into the counters (invalid tokens are
    /// counted; a success is a no-op). Accepts any `TokenError!T` result.
    pub fn recordTokenValidation(self: *Metrics, result: anytype) void {
        if (result) |_| {} else |_| self.recordInvalidToken();
    }
};

// ---------------------------------------------------------------------------
// Path state, PATH_CHALLENGE / PATH_RESPONSE validation, and migration policy
// (#251, RFC 9000 §8.2 / §9)
// ---------------------------------------------------------------------------

pub const path_challenge_len = 8;
/// Most concurrently tracked paths per connection: the active path plus a
/// small number of probes. A peer hopping addresses faster than probes
/// resolve recycles the oldest failed/unvalidated slot.
pub const max_paths = 4;
/// How long a PATH_CHALLENGE may stay unanswered before the validation fails
/// deterministically. Connection integration can override per RTT (3×PTO);
/// the default keeps standalone use safe.
pub const default_validation_timeout_us: u64 = 1_000_000;

/// A network path keyed by the (local, remote) address tuple.
pub const PathKey = struct {
    local: udp.Address,
    remote: udp.Address,

    pub fn eql(self: PathKey, other: PathKey) bool {
        return self.local.eql(other.local) and self.remote.eql(other.remote);
    }
};

pub const PathState = enum {
    /// Traffic seen, no validation started (policy denied or not yet probed).
    unvalidated,
    /// PATH_CHALLENGE outstanding.
    validating,
    /// PATH_RESPONSE echoed the challenge, but the path has not yet been
    /// promoted to active (RFC 9000 §9.5: host migration must claim a fresh
    /// peer CID first). Distinct from `.validated` so a later authenticated
    /// datagram on this exact path cannot be mistaken for "previously active,
    /// safe to trust indefinitely" and does not discard the completed
    /// validation by re-probing.
    validated_pending_promotion,
    /// The path is (or was) promoted to active. RFC 9000 §9.3 permits
    /// skipping validation for a previously validated address only when it
    /// has been seen *recently*; this implementation tracks no recency, so a
    /// non-active `.validated` path is re-probed like `.unvalidated`/`.failed`
    /// rather than trusted forever.
    validated,
    /// The challenge expired unanswered.
    failed,
};

/// How a new remote tuple is classified against the active path.
pub const AddressChange = enum {
    /// Same host, different port: almost always a NAT rebinding (RFC 9308 §4.1).
    nat_rebinding,
    /// Different host: a real migration with likely-new path characteristics.
    migration,
};

pub const Path = struct {
    key: PathKey,
    state: PathState = .unvalidated,
    change: AddressChange,
    challenge: [path_challenge_len]u8 = undefined,
    challenge_deadline_us: u64 = 0,
    anti_amplification: AntiAmplification = .{},
    /// DPLPMTUD state for *this* path (#256-B). Path-scoped rather than
    /// connection-scoped because that is what the question means: a size
    /// discovered on one path says nothing about another. A new or recycled
    /// slot therefore starts from the RFC 9000 §14 floor by construction —
    /// there is no inherit-the-old-value path to get wrong.
    plpmtu: pmtu.Controller = .{},
};

/// The action the connection takes for a datagram from a given tuple.
pub const PathDecision = union(enum) {
    /// Datagram arrived on the active path: nothing to do.
    on_active_path,
    /// A new/unvalidated tuple is being probed: send PATH_CHALLENGE with this
    /// payload on that path (RFC 9000 §9.3: packets from the new address are
    /// processed, but the path is validated before it becomes the active one).
    probe: PathProbe,
    /// Probe already in flight for this tuple; nothing new to send.
    probing,
    /// The tuple already validated (via `validatePathResponse`) but has not
    /// been promoted yet — e.g. a host migration blocked earlier on a fresh
    /// peer CID. No new challenge is needed; the completed validation stays
    /// intact and the caller may retry `promoteValidated`.
    validated_pending_promotion,
    /// Migration policy forbids this address change: the caller drops state
    /// changes for this tuple (packets themselves stay processed on the
    /// active path per RFC 9000 §9.1 server behavior for disabled migration).
    blocked: BlockedPath,
};

pub const PathProbe = struct {
    data: [path_challenge_len]u8,
    change: AddressChange,
};

pub const BlockedPath = struct {
    change: AddressChange,
    first_observation: bool,
};

/// A candidate path whose PATH_RESPONSE validated, returned by
/// `validatePathResponse` before any active-path mutation.
pub const ValidatedCandidate = struct {
    path: PathKey,
    change: AddressChange,
};

pub const FailedValidation = struct {
    path: PathKey,
    change: AddressChange,
};

/// Result of a successful path validation switch.
pub const MigrationOutcome = struct {
    change: AddressChange,
    /// RFC 9000 §9.4 policy, documented here once: RTT and congestion state
    /// reset (`recovery.RecoveryController.resetForPathMigration`) when the
    /// peer's *host* changed — new path, unknown characteristics. A NAT
    /// rebinding that only changed the port keeps the estimator, since the
    /// underlying path is almost certainly the same.
    reset_congestion: bool,
};

pub const PathManager = struct {
    policy: config.MigrationPolicy,
    validation_timeout_us: u64 = default_validation_timeout_us,
    paths: [max_paths]?Path = [_]?Path{null} ** max_paths,
    /// Index of the active (validated, in-use) path.
    active: usize = 0,
    metrics: Metrics = .{},

    /// Start with the handshake path as the active routing path. Its
    /// anti-amplification ledger is only marked validated when
    /// `initial_address_validated` is true (RFC 9000 §8.1): a non-Retry
    /// server's initial path stays amplification-limited until the handshake
    /// completes; Retry-validated server paths and every client initial path
    /// begin validated.
    pub fn init(policy: config.MigrationPolicy, handshake_path: PathKey, initial_address_validated: bool) PathManager {
        var manager = PathManager{ .policy = policy };
        manager.paths[0] = .{
            .key = handshake_path,
            .state = .validated,
            .change = .migration,
        };
        if (initial_address_validated) manager.paths[0].?.anti_amplification.markValidated();
        return manager;
    }

    pub fn activePath(self: *const PathManager) *const Path {
        return &self.paths[self.active].?;
    }

    /// The active path's DPLPMTUD state, for a caller that drives probing and
    /// consumes probe/loss feedback (#256-B). Mutable by design and reached
    /// only through the active slot: promoting a different path swaps which
    /// controller this returns, which is exactly the per-path reset the
    /// discovery model requires.
    pub fn activePlpmtu(self: *PathManager) *pmtu.Controller {
        return &self.paths[self.active].?.plpmtu;
    }

    /// Lift the active path's anti-amplification limit once its address is
    /// validated some other way (e.g. a non-Retry server's handshake
    /// completed). Prefer this over reaching into a connection-wide ledger.
    pub fn markActiveValidated(self: *PathManager) void {
        self.paths[self.active].?.anti_amplification.markValidated();
    }

    /// Lift a *specific tracked path's* anti-amplification limit — e.g. a
    /// non-Retry server's Handshake-level receipt proves that exact path's
    /// address (RFC 9001 §4.9.1), which may not be the active path if it
    /// arrived on a not-yet-promoted candidate. A no-op if `path` is not
    /// tracked. Prefer this over `markActiveValidated()` whenever the
    /// authenticated packet's actual path is known, so traffic on one path
    /// can never lift a different path's limit.
    pub fn markValidatedOnPath(self: *PathManager, path: PathKey) void {
        const index = self.find(path) orelse return;
        self.paths[index].?.anti_amplification.markValidated();
    }

    /// Record bytes sent on `path` against that path's own ledger. A no-op if
    /// `path` is not tracked.
    pub fn recordSentOnPath(self: *PathManager, path: PathKey, bytes: u64) void {
        const index = self.find(path) orelse return;
        self.paths[index].?.anti_amplification.recordSent(bytes);
    }

    /// Whether `bytes` may be sent on `path` right now without exceeding that
    /// path's own anti-amplification budget. An untracked path has no budget.
    pub fn canSendOnPath(self: *const PathManager, path: PathKey, bytes: u64) bool {
        const index = self.find(path) orelse return false;
        return self.paths[index].?.anti_amplification.canSend(bytes);
    }

    /// Bytes still permitted to send on `path` before its anti-amplification
    /// budget is exhausted, zero for an untracked path. Lets a caller size a
    /// packet (e.g. how much PATH_CHALLENGE padding fits) without a separate
    /// `canSendOnPath` probe for every candidate length.
    pub fn remainingOnPath(self: *const PathManager, path: PathKey) u64 {
        const index = self.find(path) orelse return 0;
        return self.paths[index].?.anti_amplification.remaining();
    }

    /// The current lifecycle state of `path`, or null if untracked. Lets a
    /// caller confirm a queued egress action (e.g. a pending PATH_CHALLENGE)
    /// still corresponds to a live validation attempt before sending it.
    pub fn stateOf(self: *const PathManager, path: PathKey) ?PathState {
        const index = self.find(path) orelse return null;
        return self.paths[index].?.state;
    }

    /// The key of a validated-but-not-yet-promoted candidate, if any. Lets a
    /// caller retry `promoteValidated` opportunistically (e.g. once a fresh
    /// peer CID becomes available after a NEW_CONNECTION_ID) without
    /// re-deriving path state itself.
    pub fn pendingPromotionCandidate(self: *const PathManager) ?PathKey {
        for (self.paths) |slot| {
            const path = slot orelse continue;
            if (path.state == .validated_pending_promotion) return path.key;
        }
        return null;
    }

    /// Earliest deadline among paths with an outstanding PATH_CHALLENGE, or
    /// null when nothing is validating. Callers fold this into their own
    /// timer wheel (e.g. `Connection.nextTimeoutUs()`) so `expireValidations`
    /// runs promptly instead of only on the next unrelated timeout.
    pub fn nextValidationDeadlineUs(self: *const PathManager) ?u64 {
        var earliest: ?u64 = null;
        for (self.paths) |slot| {
            const path = slot orelse continue;
            if (path.state != .validating) continue;
            if (earliest == null or path.challenge_deadline_us < earliest.?) earliest = path.challenge_deadline_us;
        }
        return earliest;
    }

    /// Classify a datagram's tuple, credit `authenticated_bytes` against that
    /// path's own anti-amplification ledger, and drive path state — all as
    /// one operation, so the very first datagram on a brand-new candidate
    /// path is accounted atomically with the path's creation. There is no
    /// separate "record received bytes" step a caller could invoke before
    /// the path exists: classification and accounting happen together here,
    /// satisfying the required ingress order (authenticate, then credit and
    /// classify) without forcing a two-call sequence that only works once the
    /// path has already been seen.
    ///
    /// The caller must only pass datagrams whose packet protection already
    /// succeeded (RFC 9000 §8.2.1) — an unauthenticated datagram must never
    /// create a path slot or buy candidate-path send budget.
    /// `challenge_entropy` supplies the unpredictable PATH_CHALLENGE payload
    /// when a probe starts.
    pub fn onDatagram(
        self: *PathManager,
        key: PathKey,
        authenticated_bytes: u64,
        challenge_entropy: [path_challenge_len]u8,
        now_us: u64,
    ) PathDecision {
        if (key.eql(self.paths[self.active].?.key)) {
            self.paths[self.active].?.anti_amplification.recordReceived(authenticated_bytes);
            return .on_active_path;
        }

        const change = self.classifyAgainstActive(key);

        const allowed = switch (self.policy) {
            .disabled => false,
            .nat_rebinding_only => change == .nat_rebinding,
            .full => true,
        };
        if (!allowed) {
            self.metrics.migrations_blocked += 1;
            // Migration policy blocks *promotion/migration* of this tuple —
            // it must not also block answering a PATH_CHALLENGE the peer
            // sends from it (RFC 9000 §8.2.2 owes a PATH_RESPONSE regardless
            // of migration policy). Track a bounded `.unvalidated` record
            // and credit its own anti-amplification ledger so a caller can
            // still afford to send that response on this exact path, without
            // ever starting a challenge or becoming eligible for promotion
            // (both require `.validating` first, which this path never
            // reaches while blocked).
            if (self.find(key)) |index| {
                self.paths[index].?.anti_amplification.recordReceived(authenticated_bytes);
                return .{ .blocked = .{ .change = change, .first_observation = false } };
            } else {
                const slot = self.claimSlot();
                self.paths[slot] = .{ .key = key, .state = .unvalidated, .change = change };
                self.paths[slot].?.anti_amplification.recordReceived(authenticated_bytes);
                return .{ .blocked = .{ .change = change, .first_observation = true } };
            }
        }

        if (self.find(key)) |index| {
            const path = &self.paths[index].?;
            // A previously-active path being re-probed starts a genuinely
            // fresh validation attempt: its old anti-amplification
            // validation must not carry over, or canSendOnPath() would stay
            // unlimited throughout the new attempt even though this code
            // deliberately chose not to skip validation (RFC 9000 §9.3.1).
            // A path still mid-validation or awaiting promotion keeps its
            // ledger untouched — it either hasn't validated yet or just did.
            // Same reasoning for the path's measured MTU (#256-B): a tuple
            // being re-validated after having been away is not demonstrably
            // the same path it was, and an inherited size that no longer
            // traverses it is a black hole waiting to happen. Discovery
            // restarts from the guaranteed floor.
            if (path.state == .validated) {
                path.anti_amplification = .{};
                path.plpmtu.reset();
            }
            path.anti_amplification.recordReceived(authenticated_bytes);
            switch (path.state) {
                .validating => return .probing,
                // Already validated but not yet promoted (e.g. blocked
                // earlier on a fresh peer CID): keep the completed validation
                // intact instead of discarding it for a fresh challenge.
                .validated_pending_promotion => return .validated_pending_promotion,
                // A previously-active/validated-but-now-non-active path has
                // no tracked recency (RFC 9000 §9.3 permits skipping
                // validation only for a *recently* seen address), and its
                // stored `change` may be stale relative to the current active
                // path. Treat it the same as unvalidated/failed: start a
                // fresh, conservative probe rather than trusting it — and
                // silently reusing a stale `change` — indefinitely.
                .failed, .unvalidated, .validated => {},
            }
            path.state = .validating;
            path.change = change;
            path.challenge = challenge_entropy;
            path.challenge_deadline_us = now_us + self.validation_timeout_us;
            self.metrics.path_challenges_sent += 1;
            return .{ .probe = .{ .data = challenge_entropy, .change = change } };
        }

        const slot = self.claimSlot();
        self.paths[slot] = .{
            .key = key,
            .state = .validating,
            .change = change,
            .challenge = challenge_entropy,
            .challenge_deadline_us = now_us + self.validation_timeout_us,
        };
        self.paths[slot].?.anti_amplification.recordReceived(authenticated_bytes);
        self.metrics.path_challenges_sent += 1;
        return .{ .probe = .{ .data = challenge_entropy, .change = change } };
    }

    /// PATH_CHALLENGE handling is stateless: echo the payload in a
    /// PATH_RESPONSE on the same path (RFC 9000 §8.2.2).
    pub fn onPathChallenge(data: [path_challenge_len]u8) [path_challenge_len]u8 {
        return data;
    }

    /// Validate a PATH_RESPONSE received from `key` without promoting it to
    /// the active path. On a match the candidate becomes
    /// `.validated_pending_promotion` — distinct from `.validated`, which
    /// means "is or was the active path" — so `onDatagram` cannot mistake it
    /// for a previously-active path and re-probe it out from under a pending
    /// promotion. Its anti-amplification limit is lifted immediately (RFC
    /// 9000 §8.2.3: a successful PATH_RESPONSE permits sending beyond the 3x
    /// limit even before migration/promotion happens), so a host migration
    /// blocked later on a fresh peer CID is not also stuck amplification
    /// limited. The returned (and stored) `change` is recomputed against the
    /// active path *right now*, not the value captured when the challenge
    /// started — another candidate can promote while this one's challenge was
    /// outstanding, which changes what "migration" vs. "rebinding" means for
    /// it. `promotionChange` covers the same staleness for a promotion
    /// delayed *after* this call returns. The caller decides when (or
    /// whether) to call `promoteValidated` — host migration must claim a
    /// fresh peer CID first (RFC 9000 §9.5), so validation and promotion
    /// cannot be one atomic step. A response with no matching outstanding
    /// challenge — wrong payload, wrong path, or expired — is ignored (null)
    /// and counted in `path_response_mismatches`: responses do not validate
    /// paths they were not sent on (RFC 9000 §8.2.3), but the probe itself
    /// keeps waiting (only expiry fails it terminally).
    pub fn validatePathResponse(
        self: *PathManager,
        key: PathKey,
        data: [path_challenge_len]u8,
        now_us: u64,
    ) ?ValidatedCandidate {
        const index = self.find(key) orelse {
            self.metrics.path_response_mismatches += 1;
            return null;
        };
        const candidate = &self.paths[index].?;
        if (candidate.state != .validating) {
            self.metrics.path_response_mismatches += 1;
            return null;
        }
        if (now_us > candidate.challenge_deadline_us) {
            self.failValidation(candidate);
            return null;
        }
        if (!secrets.constantTimeEqual(&candidate.challenge, &data)) {
            self.metrics.path_response_mismatches += 1;
            return null;
        }

        candidate.state = .validated_pending_promotion;
        candidate.anti_amplification.markValidated();
        candidate.change = self.classifyAgainstActive(key);
        self.metrics.path_validations_succeeded += 1;
        return .{ .path = key, .change = candidate.change };
    }

    /// The current NAT-rebinding-vs-migration classification of a
    /// `.validated_pending_promotion` candidate, recomputed against
    /// `activePath()` right now rather than returning the (possibly stale)
    /// classification stored from when the candidate was first probed or last
    /// validated. `PathManager` allows several pending candidates at once; if
    /// a different one is promoted first, an older candidate's relationship
    /// to the *new* active path can differ from its stored `change` (e.g. two
    /// candidates on the same host: once one promotes, the other is only a
    /// port rebind relative to it). Call this immediately before deciding
    /// whether a fresh peer CID is required and before promoting. Returns
    /// null if `key` is not a pending-promotion candidate.
    pub fn promotionChange(self: *const PathManager, key: PathKey) ?AddressChange {
        const index = self.find(key) orelse return null;
        if (self.paths[index].?.state != .validated_pending_promotion) return null;
        return self.classifyAgainstActive(key);
    }

    /// Classify `key` as a NAT rebinding or a host migration relative to the
    /// *current* active path. The one implementation shared by `onDatagram`,
    /// `validatePathResponse`, and `promotionChange`, so "recompute against
    /// the active path right now" always means the same thing.
    fn classifyAgainstActive(self: *const PathManager, key: PathKey) AddressChange {
        return if (key.remote.sameHost(self.activePath().key.remote))
            .nat_rebinding
        else
            .migration;
    }

    /// Promote a path already marked `.validated_pending_promotion` by
    /// `validatePathResponse` to the active path, transitioning it to
    /// `.validated`. The returned outcome uses `promotionChange`'s current
    /// classification, not the stored (possibly stale) one, since another
    /// candidate may have promoted in the meantime. Returns null if `key` is
    /// not a pending-promotion candidate. For a host migration the caller
    /// must claim a fresh peer CID before calling this (RFC 9000 §9.5); if
    /// none is available, call `recordMigrationBlockedNoPeerCid` instead and
    /// leave the candidate `.validated_pending_promotion` so a later retry
    /// can promote it without a new challenge round trip.
    pub fn promoteValidated(self: *PathManager, key: PathKey) ?MigrationOutcome {
        const change = self.promotionChange(key) orelse return null;
        const index = self.find(key).?;
        const candidate = &self.paths[index].?;

        candidate.state = .validated;
        candidate.change = change;
        self.active = index;
        switch (change) {
            .nat_rebinding => self.metrics.nat_rebindings += 1,
            .migration => self.metrics.migrations += 1,
        }
        return .{
            .change = change,
            .reset_congestion = change == .migration,
        };
    }

    /// Count a host migration that validated but could not promote because no
    /// fresh peer CID was available. The previous active path stays active.
    pub fn recordMigrationBlockedNoPeerCid(self: *PathManager) void {
        self.metrics.migrations_blocked_no_peer_cid += 1;
    }

    /// Fail every probe whose challenge deadline has passed. Returns how many
    /// validations failed; callers run this off their timer wheel.
    pub fn expireValidations(self: *PathManager, now_us: u64) usize {
        var failures: [max_paths]FailedValidation = undefined;
        return self.expireValidationsInto(now_us, &failures).len;
    }

    /// Fail every probe whose challenge deadline has passed and return the
    /// bounded path/change records that fit in `out`.
    pub fn expireValidationsInto(self: *PathManager, now_us: u64, out: []FailedValidation) []const FailedValidation {
        var failed: usize = 0;
        for (&self.paths) |*slot| {
            const path = &(slot.* orelse continue);
            if (path.state != .validating) continue;
            if (now_us <= path.challenge_deadline_us) continue;
            if (failed < out.len) {
                out[failed] = .{ .path = path.key, .change = path.change };
                failed += 1;
            }
            self.failValidation(path);
        }
        return out[0..failed];
    }

    fn failValidation(self: *PathManager, path: *Path) void {
        path.state = .failed;
        self.metrics.path_validations_failed += 1;
    }

    fn find(self: *const PathManager, key: PathKey) ?usize {
        for (self.paths, 0..) |slot, index| {
            const path = slot orelse continue;
            if (path.key.eql(key)) return index;
        }
        return null;
    }

    /// A free slot, or the oldest non-active failed/unvalidated slot when the
    /// table is full — probe storms recycle probes, never the active path.
    fn claimSlot(self: *PathManager) usize {
        for (self.paths, 0..) |slot, index| {
            if (slot == null) return index;
        }
        for (self.paths, 0..) |slot, index| {
            if (index == self.active) continue;
            if (slot.?.state == .failed or slot.?.state == .unvalidated) return index;
        }
        // All slots are live probes: recycle the first non-active one.
        for (self.paths, 0..) |_, index| {
            if (index != self.active) return index;
        }
        unreachable; // max_paths >= 2 guarantees a non-active slot
    }
};

const testing = std.testing;

fn loopbackV4(port: u16) udp.Address {
    return udp.Address.ip4(.{ 127, 0, 0, 1 }, port);
}

test "anti-amplification caps sends at 3x received until validated" {
    var limiter = AntiAmplification{};
    limiter.recordReceived(1200);
    try testing.expectEqual(@as(u64, 3600), limiter.budget());
    try testing.expectEqual(@as(u64, 3600), limiter.remaining());

    try testing.expect(limiter.canSend(3600));
    try testing.expect(!limiter.canSend(3601));

    limiter.recordSent(3000);
    try testing.expectEqual(@as(u64, 600), limiter.remaining());
    try testing.expect(limiter.canSend(600));
    try testing.expect(!limiter.canSend(601));

    // Validation lifts the budget entirely.
    limiter.markValidated();
    try testing.expect(limiter.canSend(std.math.maxInt(u64)));
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), limiter.remaining());
}

test "anti-amplification accounting saturates instead of overflowing" {
    var limiter = AntiAmplification{};
    limiter.recordReceived(std.math.maxInt(u64));
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), limiter.budget());
    try testing.expect(limiter.canSend(std.math.maxInt(u64)));
}

const test_odcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
const test_retry_scid = [_]u8{ 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18 };
const test_version: u32 = 0x0000_0001;

test "retry token round-trips and recovers the original DCID, Retry SCID, and version" {
    var tokens = RetryTokens{ .lifetime_us = 10_000_000 };
    tokens.keys.install(0, &([_]u8{0xa5} ** token_key_len));

    var buf: [max_token_len]u8 = undefined;
    const token = try tokens.issueRetry(&test_odcid, &test_retry_scid, test_version, loopbackV4(4433), 1_000_000, [_]u8{0x11} ** token_nonce_len, &buf);

    const ctx = try tokens.validateRetry(token, loopbackV4(4433), 1_500_000);
    try testing.expectEqualSlices(u8, &test_odcid, ctx.original_dcid.slice());
    try testing.expectEqualSlices(u8, &test_retry_scid, ctx.retry_scid.slice());
    try testing.expectEqual(test_version, ctx.quic_version);

    // A different port or host is a different path.
    try testing.expectError(error.TokenAddressMismatch, tokens.validateRetry(token, loopbackV4(4434), 1_500_000));
    try testing.expectError(error.TokenAddressMismatch, tokens.validateRetry(token, udp.Address.ip4(.{ 10, 0, 0, 1 }, 4433), 1_500_000));
}

test "retry token binds scoped IPv6 addresses including the scope id" {
    var tokens = RetryTokens{ .lifetime_us = 10_000_000 };
    tokens.keys.install(0, &([_]u8{0xa5} ** token_key_len));

    const scoped = udp.Address.ip6([_]u8{0xfe} ++ [_]u8{0x80} ++ [_]u8{0} ** 13 ++ [_]u8{0x01}, 4433, 7);
    var buf: [max_token_len]u8 = undefined;
    const token = try tokens.issueRetry(&test_odcid, &test_retry_scid, test_version, scoped, 1_000_000, [_]u8{0x66} ** token_nonce_len, &buf);

    // Same address including scope id validates; a different scope id does not.
    _ = try tokens.validateRetry(token, scoped, 1_500_000);
    const other_scope = udp.Address.ip6(scoped.bytes, 4433, 9);
    try testing.expectError(error.TokenAddressMismatch, tokens.validateRetry(token, other_scope, 1_500_000));
}

test "retry token expires after its lifetime" {
    var tokens = RetryTokens{ .lifetime_us = 5_000_000 };
    tokens.keys.install(1, &([_]u8{0x5a} ** token_key_len));

    var buf: [max_token_len]u8 = undefined;
    const token = try tokens.issueRetry(&test_odcid, &test_retry_scid, test_version, loopbackV4(443), 2_000_000, [_]u8{0x22} ** token_nonce_len, &buf);

    _ = try tokens.validateRetry(token, loopbackV4(443), 7_000_000); // exactly at the limit
    try testing.expectError(error.TokenExpired, tokens.validateRetry(token, loopbackV4(443), 7_000_001));
}

test "retry token dated in the future is rejected" {
    var tokens = RetryTokens{ .lifetime_us = 5_000_000, .allowed_clock_skew_us = 1_000 };
    tokens.keys.install(0, &([_]u8{0x7a} ** token_key_len));

    var buf: [max_token_len]u8 = undefined;
    const token = try tokens.issueRetry(&test_odcid, &test_retry_scid, test_version, loopbackV4(443), 5_000_000, [_]u8{0x77} ** token_nonce_len, &buf);

    // Within the allowed skew: accepted (age saturates to zero).
    _ = try tokens.validateRetry(token, loopbackV4(443), 4_999_500);
    // Further in the future than the skew: rejected instead of treated as fresh.
    try testing.expectError(error.TokenExpired, tokens.validateRetry(token, loopbackV4(443), 4_000_000));
}

test "retry token rejects tampering and unknown keys" {
    var tokens = RetryTokens{ .lifetime_us = 10_000_000 };
    tokens.keys.install(0, &([_]u8{0x01} ** token_key_len));

    var buf: [max_token_len]u8 = undefined;
    const token = try tokens.issueRetry(&test_odcid, &test_retry_scid, test_version, loopbackV4(4433), 1_000_000, [_]u8{0x33} ** token_nonce_len, &buf);

    // Flip a ciphertext byte: AEAD authentication must fail.
    var tampered: [max_token_len]u8 = undefined;
    @memcpy(tampered[0..token.len], token);
    tampered[1 + token_nonce_len] ^= 0x80;
    try testing.expectError(error.TokenAuthenticationFailed, tokens.validateRetry(tampered[0..token.len], loopbackV4(4433), 1_000_000));

    // Name a key id the ring never held.
    var wrong_key: [max_token_len]u8 = undefined;
    @memcpy(wrong_key[0..token.len], token);
    wrong_key[0] = 7;
    try testing.expectError(error.UnknownTokenKey, tokens.validateRetry(wrong_key[0..token.len], loopbackV4(4433), 1_000_000));

    // Truncated token is malformed.
    try testing.expectError(error.MalformedToken, tokens.validateRetry(token[0..10], loopbackV4(4433), 1_000_000));
}

test "retry token survives key rotation while a key is retained" {
    var tokens = RetryTokens{ .lifetime_us = 10_000_000 };
    tokens.keys.install(0, &([_]u8{0x01} ** token_key_len));

    var buf: [max_token_len]u8 = undefined;
    const token = try tokens.issueRetry(&test_odcid, &test_retry_scid, test_version, loopbackV4(4433), 1_000_000, [_]u8{0x44} ** token_nonce_len, &buf);

    // Rotate to a new current key; the old key still validates prior tokens.
    tokens.keys.install(1, &([_]u8{0x02} ** token_key_len));
    _ = try tokens.validateRetry(token, loopbackV4(4433), 1_000_000);

    // Retiring the issuing key invalidates its tokens.
    tokens.keys.retire(0);
    try testing.expectError(error.UnknownTokenKey, tokens.validateRetry(token, loopbackV4(4433), 1_000_000));
}

test "retry token key ring deinit clears installed keys down to the byte level" {
    var ring = RetryTokenKeyRing{};
    ring.install(0, &([_]u8{0x9c} ** token_key_len));
    ring.install(1, &([_]u8{0x8d} ** token_key_len));
    try testing.expect(ring.get(0) != null);
    try testing.expect(ring.get(1) != null);

    // Capture raw pointers into the always-live key storage before deinit:
    // asserting only `get(id) == null` afterward would also pass an
    // implementation that never actually touched the key bytes, only the
    // occupancy length. `.bytes` stays addressable regardless of `.len`, so
    // this read is well-defined even after the slot is cleared.
    const key0_ptr: *const [token_key_len]u8 = &ring.keys[0].bytes;
    const key1_ptr: *const [token_key_len]u8 = &ring.keys[1].bytes;

    ring.deinit();
    try testing.expect(ring.get(0) == null);
    try testing.expect(ring.get(1) == null);
    for (key0_ptr) |byte| try testing.expectEqual(@as(u8, 0), byte);
    for (key1_ptr) |byte| try testing.expectEqual(@as(u8, 0), byte);
}

test "retry token key ring retire wipes the retired key, not just its slot tag" {
    var ring = RetryTokenKeyRing{};
    defer ring.deinit();
    ring.install(0, &([_]u8{0x9c} ** token_key_len));
    const key0_ptr: *const [token_key_len]u8 = &ring.keys[0].bytes;
    var saw_nonzero = false;
    for (key0_ptr) |byte| {
        if (byte != 0) saw_nonzero = true;
    }
    try testing.expect(saw_nonzero);

    ring.retire(0);
    try testing.expect(ring.get(0) == null);
    for (key0_ptr) |byte| try testing.expectEqual(@as(u8, 0), byte);
}

test "retry token key ring install wipes a replaced key before the new one takes over" {
    var ring = RetryTokenKeyRing{};
    defer ring.deinit();
    ring.install(0, &([_]u8{0xaa} ** token_key_len));
    const key0_ptr: *const [token_key_len]u8 = &ring.keys[0].bytes;

    ring.install(0, &([_]u8{0xbb} ** token_key_len));
    // The old 0xaa key must not survive anywhere in the slot's storage —
    // only the new key's bytes.
    for (key0_ptr) |byte| try testing.expectEqual(@as(u8, 0xbb), byte);
}

test "retry token deterministic boundary matrix rejects malformed public input" {
    var tokens = RetryTokens{ .lifetime_us = 1_000_000 };
    tokens.keys.install(0, &([_]u8{0x31} ** token_key_len));

    try testing.expectError(error.MalformedToken, tokens.validateRetry(&([_]u8{0xaa} ** (1 + token_nonce_len + token_min_plaintext_len + token_tag_len - 1)), loopbackV4(4433), 0));
    try testing.expectError(error.MalformedToken, tokens.validateRetry(&([_]u8{0xaa} ** (max_token_len + 1)), loopbackV4(4433), 0));

    var buf: [max_token_len]u8 = undefined;
    const token = try tokens.issueRetry(&test_odcid, &test_retry_scid, test_version, loopbackV4(4433), 100, [_]u8{0x9a} ** token_nonce_len, &buf);

    var mutated: [max_token_len]u8 = undefined;
    @memcpy(mutated[0..token.len], token);
    mutated[0] = max_token_keys;
    try testing.expectError(error.UnknownTokenKey, tokens.validateRetry(mutated[0..token.len], loopbackV4(4433), 100));

    @memcpy(mutated[0..token.len], token);
    mutated[1] ^= 0x01;
    try testing.expectError(error.TokenAuthenticationFailed, tokens.validateRetry(mutated[0..token.len], loopbackV4(4433), 100));

    @memcpy(mutated[0..token.len], token);
    mutated[1 + token_nonce_len] ^= 0x01;
    try testing.expectError(error.TokenAuthenticationFailed, tokens.validateRetry(mutated[0..token.len], loopbackV4(4433), 100));

    @memcpy(mutated[0..token.len], token);
    mutated[token.len - 1] ^= 0x01;
    try testing.expectError(error.TokenAuthenticationFailed, tokens.validateRetry(mutated[0..token.len], loopbackV4(4433), 100));

    try testing.expectError(error.TokenAuthenticationFailed, tokens.validateRetry(token[0 .. token.len - token_tag_len], loopbackV4(4433), 100));
    try testing.expectError(error.TokenAuthenticationFailed, tokens.validateRetry(token[0 .. token.len - 1], loopbackV4(4433), 100));
}

test "retry token validates exact time boundaries and u64 saturation" {
    var tokens = RetryTokens{ .lifetime_us = 5_000, .allowed_clock_skew_us = 100 };
    tokens.keys.install(0, &([_]u8{0x41} ** token_key_len));

    var buf: [max_token_len]u8 = undefined;
    var token = try tokens.issueRetry(&test_odcid, &test_retry_scid, test_version, loopbackV4(4433), 10_000, [_]u8{0x42} ** token_nonce_len, &buf);
    _ = try tokens.validateRetry(token, loopbackV4(4433), 10_000);
    _ = try tokens.validateRetry(token, loopbackV4(4433), 15_000);
    try testing.expectError(error.TokenExpired, tokens.validateRetry(token, loopbackV4(4433), 15_001));

    token = try tokens.issueRetry(&test_odcid, &test_retry_scid, test_version, loopbackV4(4433), 20_000, [_]u8{0x43} ** token_nonce_len, &buf);
    _ = try tokens.validateRetry(token, loopbackV4(4433), 19_900);
    try testing.expectError(error.TokenExpired, tokens.validateRetry(token, loopbackV4(4433), 19_899));

    token = try tokens.issueRetry(&test_odcid, &test_retry_scid, test_version, loopbackV4(4433), std.math.maxInt(u64), [_]u8{0x44} ** token_nonce_len, &buf);
    _ = try tokens.validateRetry(token, loopbackV4(4433), std.math.maxInt(u64));
    try testing.expectError(error.TokenExpired, tokens.validateRetry(token, loopbackV4(4433), std.math.maxInt(u64) - 101));
}

test "retry token authenticated malformed plaintext maps to public rejection classes" {
    var tokens = RetryTokens{ .lifetime_us = 1_000_000 };
    tokens.keys.install(0, &([_]u8{0x51} ** token_key_len));
    const nonce = [_]u8{0x52} ** token_nonce_len;
    const address = loopbackV4(4433);
    var plaintext: [token_max_plaintext_len]u8 = undefined;
    var token: [max_token_len]u8 = undefined;

    const wrong_kind_len = encodeTokenPlaintext(.address_validation, test_version, &test_odcid, &test_retry_scid, address, 1_000, &plaintext);
    const wrong_kind = try sealTokenPlaintextForTest(&tokens, 0, nonce, plaintext[0..wrong_kind_len], &token);
    try testing.expectError(error.UnexpectedTokenKind, tokens.validateRetry(wrong_kind, address, 1_000));

    var len = minimalRetryPlaintextForTest(&plaintext, address, 1_000);
    plaintext[13] = udp.MaxConnectionIdLen + 1;
    const bad_odcid = try sealTokenPlaintextForTest(&tokens, 0, nonce, plaintext[0..len], &token);
    try testing.expectError(error.MalformedToken, tokens.validateRetry(bad_odcid, address, 1_000));

    len = minimalRetryPlaintextForTest(&plaintext, address, 1_000);
    plaintext[14] = udp.MaxConnectionIdLen + 1;
    const bad_retry_scid = try sealTokenPlaintextForTest(&tokens, 0, nonce, plaintext[0..len], &token);
    try testing.expectError(error.MalformedToken, tokens.validateRetry(bad_retry_scid, address, 1_000));

    len = minimalRetryPlaintextForTest(&plaintext, address, 1_000);
    plaintext[15] = 0xff;
    const bad_family = try sealTokenPlaintextForTest(&tokens, 0, nonce, plaintext[0..len], &token);
    try testing.expectError(error.MalformedToken, tokens.validateRetry(bad_family, address, 1_000));

    len = minimalRetryPlaintextForTest(&plaintext, address, 1_000);
    plaintext[16] = 16;
    const bad_addr_len = try sealTokenPlaintextForTest(&tokens, 0, nonce, plaintext[0..len], &token);
    try testing.expectError(error.MalformedToken, tokens.validateRetry(bad_addr_len, address, 1_000));
}

test "fuzz: Retry token issue validate and mutation boundary is deterministic" {
    try testing.fuzz({}, fuzzRetryTokenIssueValidate, .{ .corpus = &.{
        "\x00",
        "\x01\x02\x03\x04",
        "\xff\x00\x7f\x40",
        "\x14\x00\x14\x01",
    } });
}

fn minimalRetryPlaintextForTest(out: *[token_max_plaintext_len]u8, address: udp.Address, issued_at_us: u64) usize {
    return encodeTokenPlaintext(.retry, test_version, &.{}, &.{}, address, issued_at_us, out);
}

fn sealTokenPlaintextForTest(
    tokens: *const RetryTokens,
    key_id: u8,
    nonce: [token_nonce_len]u8,
    plaintext: []const u8,
    out: []u8,
) ![]const u8 {
    const key = tokens.keys.get(key_id) orelse return error.TestUnexpectedResult;
    const total = 1 + token_nonce_len + plaintext.len + token_tag_len;
    if (out.len < total) return error.TestUnexpectedResult;
    out[0] = key_id;
    @memcpy(out[1..][0..token_nonce_len], &nonce);
    const cipher = out[1 + token_nonce_len ..][0..plaintext.len];
    var tag: [token_tag_len]u8 = undefined;
    Aes128Gcm.encrypt(cipher, &tag, plaintext, &.{}, nonce, key.*);
    @memcpy(out[1 + token_nonce_len + plaintext.len ..][0..token_tag_len], &tag);
    return out[0..total];
}

fn fuzzRetryTokenIssueValidate(_: void, smith: *testing.Smith) !void {
    var tokens = RetryTokens{
        .lifetime_us = 1 + @as(u64, smith.value(u16)),
        .allowed_clock_skew_us = @as(u64, smith.value(u8)),
    };
    tokens.keys.install(0, &([_]u8{0x61} ** token_key_len));
    tokens.keys.install(1, &([_]u8{0x62} ** token_key_len));

    var odcid_storage: [udp.MaxConnectionIdLen]u8 = undefined;
    var retry_scid_storage: [udp.MaxConnectionIdLen]u8 = undefined;
    @memset(&odcid_storage, 0);
    @memset(&retry_scid_storage, 0);
    _ = smith.slice(&odcid_storage);
    _ = smith.slice(&retry_scid_storage);
    const odcid_len = @as(usize, smith.value(u8)) % (udp.MaxConnectionIdLen + 1);
    const retry_scid_len = @as(usize, smith.value(u8)) % (udp.MaxConnectionIdLen + 1);
    const odcid = odcid_storage[0..odcid_len];
    const retry_scid = retry_scid_storage[0..retry_scid_len];

    var nonce: [token_nonce_len]u8 = undefined;
    @memset(&nonce, 0);
    _ = smith.slice(&nonce);
    const issued_at = @as(u64, smith.value(u32));
    const address = fuzzAddress(smith);
    const version = smith.value(u32);

    var buf: [max_token_len]u8 = undefined;
    const token = try tokens.issueRetry(odcid, retry_scid, version, address, issued_at, nonce, &buf);
    const ctx = try tokens.validateRetry(token, address, issued_at);
    try testing.expectEqualSlices(u8, odcid, ctx.original_dcid.slice());
    try testing.expectEqualSlices(u8, retry_scid, ctx.retry_scid.slice());
    try testing.expectEqual(version, ctx.quic_version);

    tokens.keys.install(2, &([_]u8{0x63} ** token_key_len));
    _ = try tokens.validateRetry(token, address, issued_at);

    var mutated: [max_token_len]u8 = undefined;
    @memcpy(mutated[0..token.len], token);
    switch (smith.value(u3)) {
        0 => {
            mutated[0] = max_token_keys;
            try testing.expectError(error.UnknownTokenKey, tokens.validateRetry(mutated[0..token.len], address, issued_at));
        },
        1 => {
            mutated[1] ^= 0x01;
            try testing.expectError(error.TokenAuthenticationFailed, tokens.validateRetry(mutated[0..token.len], address, issued_at));
        },
        2 => {
            mutated[1 + token_nonce_len] ^= 0x01;
            try testing.expectError(error.TokenAuthenticationFailed, tokens.validateRetry(mutated[0..token.len], address, issued_at));
        },
        3 => {
            mutated[token.len - 1] ^= 0x01;
            try testing.expectError(error.TokenAuthenticationFailed, tokens.validateRetry(mutated[0..token.len], address, issued_at));
        },
        4 => {
            try testing.expectError(error.TokenAddressMismatch, tokens.validateRetry(token, mutateAddressPort(address), issued_at));
        },
        5 => {
            try testing.expectError(error.TokenExpired, tokens.validateRetry(token, address, issued_at + tokens.lifetime_us + 1));
        },
        else => {
            tokens.keys.retire(token[0]);
            try testing.expectError(error.UnknownTokenKey, tokens.validateRetry(token, address, issued_at));
        },
    }
}

fn fuzzAddress(smith: *testing.Smith) udp.Address {
    if (smith.value(u1) == 0) {
        return udp.Address.ip4(.{ smith.value(u8), smith.value(u8), smith.value(u8), smith.value(u8) }, smith.value(u16));
    }
    var bytes: [16]u8 = undefined;
    @memset(&bytes, 0);
    _ = smith.slice(&bytes);
    return udp.Address.ip6(bytes, smith.value(u16), smith.value(u32));
}

fn mutateAddressPort(address: udp.Address) udp.Address {
    return switch (address.family) {
        .ip4 => udp.Address.ip4(address.bytes[0..4].*, address.port +% 1),
        .ip6 => udp.Address.ip6(address.bytes, address.port +% 1, address.scope_id),
    };
}

test "retry integrity tag matches the RFC 9001 Appendix A.4 vector" {
    var odcid: [8]u8 = undefined;
    _ = try std.fmt.hexToBytes(&odcid, "8394c8f03e515708");
    var retry_body: [20]u8 = undefined;
    _ = try std.fmt.hexToBytes(&retry_body, "ff000000010008f067a5502a4262b5746f6b656e");

    const tag = try packet.computeRetryIntegrityTag(&odcid, &retry_body);
    var expected: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "04a265ba2eff4d829058fb3f0f2496ba");
    try testing.expectEqualSlices(u8, &expected, &tag);

    // The full Retry packet (body + tag) verifies; a tampered tag does not.
    var retry_packet: [36]u8 = undefined;
    @memcpy(retry_packet[0..20], &retry_body);
    @memcpy(retry_packet[20..], &tag);
    try testing.expect(packet.verifyRetryIntegrity(&retry_packet, &odcid));

    retry_packet[35] ^= 0x01;
    try testing.expect(!packet.verifyRetryIntegrity(&retry_packet, &odcid));
    // Wrong original DCID must also fail.
    @memcpy(retry_packet[20..], &tag);
    try testing.expect(!packet.verifyRetryIntegrity(&retry_packet, "wrongdcid"));
}

test "metrics distinguish invalid tokens from normal retry usage" {
    var tokens = RetryTokens{ .lifetime_us = 1_000_000 };
    tokens.keys.install(0, &([_]u8{0x09} ** token_key_len));
    var metrics = Metrics{};

    var buf: [max_token_len]u8 = undefined;
    const token = try tokens.issueRetry(&test_odcid, &test_retry_scid, test_version, loopbackV4(4433), 1_000_000, [_]u8{0x55} ** token_nonce_len, &buf);
    metrics.recordRetrySent();

    metrics.recordTokenValidation(tokens.validateRetry(token, loopbackV4(4433), 1_500_000)); // valid
    metrics.recordTokenValidation(tokens.validateRetry(token, loopbackV4(4433), 9_000_000)); // expired
    metrics.recordTokenValidation(tokens.validateRetry(token, loopbackV4(9999), 1_500_000)); // wrong address

    try testing.expectEqual(@as(u64, 1), metrics.retry_packets_sent);
    try testing.expectEqual(@as(u64, 2), metrics.invalid_tokens);
}

// ---------------------------------------------------------------------------
// Path validation / migration tests (#251)
// ---------------------------------------------------------------------------

fn testKey(remote_port: u16) PathKey {
    return .{ .local = loopbackV4(4433), .remote = udp.Address.ip4(.{ 192, 0, 2, 10 }, remote_port) };
}

fn testKeyOtherHost(remote_port: u16) PathKey {
    return .{ .local = loopbackV4(4433), .remote = udp.Address.ip4(.{ 198, 51, 100, 7 }, remote_port) };
}

const test_challenge = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };

test "datagrams on the active path require no action" {
    var manager = PathManager.init(.full, testKey(50_000), true);
    try testing.expectEqual(PathDecision.on_active_path, manager.onDatagram(testKey(50_000), 1_200, test_challenge, 0));
    try testing.expectEqual(PathState.validated, manager.activePath().state);
}

test "an unvalidated initial path keeps its amplification budget until markActiveValidated" {
    var manager = PathManager.init(.full, testKey(50_000), false);
    try testing.expect(!manager.activePath().anti_amplification.validated);
    try testing.expectEqual(PathState.validated, manager.activePath().state);
    _ = manager.onDatagram(testKey(50_000), 1_000, test_challenge, 0);
    try testing.expect(!manager.canSendOnPath(testKey(50_000), 3_001));
    manager.markActiveValidated();
    try testing.expect(manager.canSendOnPath(testKey(50_000), std.math.maxInt(u64)));
}

test "markValidatedOnPath lifts only the named path's limit, never a different tracked path's" {
    var manager = PathManager.init(.full, testKey(50_000), false);
    const candidate = testKeyOtherHost(50_001);
    _ = manager.onDatagram(candidate, 100, test_challenge, 0);

    // Marking the candidate validated must not touch the still-unvalidated
    // active path.
    manager.markValidatedOnPath(candidate);
    try testing.expect(manager.canSendOnPath(candidate, std.math.maxInt(u64)));
    try testing.expect(!manager.canSendOnPath(testKey(50_000), 3_001));

    // An untracked path is a no-op, not a crash.
    manager.markValidatedOnPath(testKeyOtherHost(9));
}

test "the first authenticated datagram on a new candidate path credits its own budget atomically" {
    var manager = PathManager.init(.full, testKey(50_000), true);
    const candidate = testKeyOtherHost(50_000);
    // No path exists yet, so there is no pre-authentication budget at all —
    // the candidate cannot have been credited before it was even classified.
    try testing.expect(!manager.canSendOnPath(candidate, 1));

    // A single onDatagram call both creates the path and credits it: there is
    // no separate step where a caller could try (and silently fail) to
    // record bytes on a path that does not exist yet.
    _ = manager.onDatagram(candidate, 1_200, test_challenge, 0);
    try testing.expect(manager.canSendOnPath(candidate, 3_600));
    try testing.expect(!manager.canSendOnPath(candidate, 3_601));
}

test "path validation succeeds deterministically and switches the active path" {
    var manager = PathManager.init(.full, testKey(50_000), true);
    const rebound = testKey(50_001); // same host, new port: NAT rebinding

    const decision = manager.onDatagram(rebound, 1_200, test_challenge, 1_000);
    try testing.expectEqualSlices(u8, &test_challenge, &decision.probe.data);
    try testing.expectEqual(@as(u64, 1), manager.metrics.path_challenges_sent);

    // Peer echoes the challenge (PATH_RESPONSE semantics are a pure echo).
    const echoed = PathManager.onPathChallenge(test_challenge);
    const validated = manager.validatePathResponse(rebound, echoed, 2_000).?;
    try testing.expectEqual(AddressChange.nat_rebinding, validated.change);
    // Validation alone does not promote the candidate.
    try testing.expect(manager.activePath().key.eql(testKey(50_000)));

    const outcome = manager.promoteValidated(rebound).?;
    try testing.expectEqual(AddressChange.nat_rebinding, outcome.change);
    // Port-only rebinding: same underlying path, keep congestion/RTT state.
    try testing.expect(!outcome.reset_congestion);
    try testing.expect(manager.activePath().key.eql(rebound));
    try testing.expectEqual(@as(u64, 1), manager.metrics.nat_rebindings);
    try testing.expectEqual(@as(u64, 1), manager.metrics.path_validations_succeeded);
}

test "a real migration validates and requires congestion/RTT reset" {
    var manager = PathManager.init(.full, testKey(50_000), true);
    const migrated = testKeyOtherHost(50_000); // new host: real migration

    _ = manager.onDatagram(migrated, 1_200, test_challenge, 0);
    const validated = manager.validatePathResponse(migrated, test_challenge, 100).?;
    try testing.expectEqual(AddressChange.migration, validated.change);
    const outcome = manager.promoteValidated(migrated).?;
    try testing.expectEqual(AddressChange.migration, outcome.change);
    try testing.expect(outcome.reset_congestion);
    try testing.expectEqual(@as(u64, 1), manager.metrics.migrations);

    // The documented reset actually reinitializes recovery state.
    const recovery = @import("recovery.zig");
    var controller = recovery.RecoveryController{};
    controller.rtt.update(50_000, 0);
    controller.congestion.congestion_window = 3;
    const old_path_packet = recovery.SentPacket{
        .space = .application,
        .packet_number = 5,
        .time_sent_us = 10,
        .size = 999,
    };
    controller.congestion.onPacketSent(old_path_packet.size);
    controller.resetForPathMigration();
    try testing.expect(!controller.rtt.hasSample());
    try testing.expectEqual(recovery.CongestionController.initialWindow(recovery.initial_max_datagram_size), controller.congestion.congestion_window);
    // Packets in flight on the old path stay in the single send ledger...
    try testing.expectEqual(@as(usize, 999), controller.congestion.bytes_in_flight);
    // ...and drain through the normal ack path without corrupting accounting.
    controller.congestion.onPacketAcked(old_path_packet);
    try testing.expectEqual(@as(usize, 0), controller.congestion.bytes_in_flight);
}

test "a wrong PATH_RESPONSE payload does not validate the path" {
    var manager = PathManager.init(.full, testKey(50_000), true);
    const rebound = testKey(50_001);
    _ = manager.onDatagram(rebound, 1_200, test_challenge, 0);

    const wrong = [_]u8{0xff} ** path_challenge_len;
    try testing.expectEqual(@as(?ValidatedCandidate, null), manager.validatePathResponse(rebound, wrong, 100));
    // A response on a different tuple does not validate the probed one either.
    try testing.expectEqual(@as(?ValidatedCandidate, null), manager.validatePathResponse(testKeyOtherHost(1), test_challenge, 100));
    // Still probing; the active path is unchanged. Both bogus responses are
    // counted as mismatches, not as terminal validation failures — the probe
    // can still succeed.
    try testing.expect(manager.activePath().key.eql(testKey(50_000)));
    try testing.expectEqual(@as(u64, 0), manager.metrics.path_validations_succeeded);
    try testing.expectEqual(@as(u64, 0), manager.metrics.path_validations_failed);
    try testing.expectEqual(@as(u64, 2), manager.metrics.path_response_mismatches);
    try testing.expect(manager.validatePathResponse(rebound, test_challenge, 200) != null);
}

test "path validation fails deterministically when the challenge expires" {
    var manager = PathManager.init(.full, testKey(50_000), true);
    manager.validation_timeout_us = 1_000;
    const rebound = testKey(50_001);
    _ = manager.onDatagram(rebound, 1_200, test_challenge, 0);
    try testing.expectEqual(@as(?u64, 1_000), manager.nextValidationDeadlineUs());

    // Not yet expired: nothing fails.
    try testing.expectEqual(@as(usize, 0), manager.expireValidations(1_000));
    // Past the deadline: the probe fails and is counted.
    try testing.expectEqual(@as(usize, 1), manager.expireValidations(1_001));
    try testing.expectEqual(@as(u64, 1), manager.metrics.path_validations_failed);
    try testing.expectEqual(@as(?u64, null), manager.nextValidationDeadlineUs());
    // A late response for the failed probe is ignored.
    try testing.expectEqual(@as(?ValidatedCandidate, null), manager.validatePathResponse(rebound, test_challenge, 1_002));
    // New traffic from the tuple restarts a probe.
    const retry = manager.onDatagram(rebound, 1_200, test_challenge, 2_000);
    try testing.expectEqualSlices(u8, &test_challenge, &retry.probe.data);
}

test "migration policy gates rebinding and migration separately" {
    // disabled: even a port-only rebinding is blocked.
    var disabled = PathManager.init(.disabled, testKey(50_000), true);
    const disabled_blocked = disabled.onDatagram(testKey(50_001), 1_200, test_challenge, 0).blocked;
    try testing.expectEqual(AddressChange.nat_rebinding, disabled_blocked.change);
    try testing.expect(disabled_blocked.first_observation);
    const disabled_repeat = disabled.onDatagram(testKey(50_001), 1_200, test_challenge, 0).blocked;
    try testing.expectEqual(AddressChange.nat_rebinding, disabled_repeat.change);
    try testing.expect(!disabled_repeat.first_observation);
    try testing.expectEqual(@as(u64, 2), disabled.metrics.migrations_blocked);

    // nat_rebinding_only: port change probes, host change is blocked.
    var rebind_only = PathManager.init(.nat_rebinding_only, testKey(50_000), true);
    const probe = rebind_only.onDatagram(testKey(50_001), 1_200, test_challenge, 0);
    try testing.expectEqualSlices(u8, &test_challenge, &probe.probe.data);
    const migration_blocked = rebind_only.onDatagram(testKeyOtherHost(50_000), 1_200, test_challenge, 0).blocked;
    try testing.expectEqual(AddressChange.migration, migration_blocked.change);
    try testing.expect(migration_blocked.first_observation);
    try testing.expectEqual(@as(u64, 1), rebind_only.metrics.migrations_blocked);

    // full: both probe.
    var full = PathManager.init(.full, testKey(50_000), true);
    const rebinding_probe = full.onDatagram(testKey(50_001), 1_200, test_challenge, 0);
    try testing.expectEqualSlices(u8, &test_challenge, &rebinding_probe.probe.data);
    const migration_probe = full.onDatagram(testKeyOtherHost(50_000), 1_200, test_challenge, 0);
    try testing.expectEqualSlices(u8, &test_challenge, &migration_probe.probe.data);
}

test "duplicate datagrams on a probing path do not restart the challenge" {
    var manager = PathManager.init(.full, testKey(50_000), true);
    const rebound = testKey(50_001);
    _ = manager.onDatagram(rebound, 1_200, test_challenge, 0);
    const again = manager.onDatagram(rebound, 1_200, [_]u8{0xee} ** path_challenge_len, 10);
    try testing.expectEqual(PathDecision.probing, again);
    try testing.expectEqual(@as(u64, 1), manager.metrics.path_challenges_sent);
    // The original challenge still validates.
    try testing.expect(manager.validatePathResponse(rebound, test_challenge, 20) != null);
}

test "host migration validates without promoting until the caller secures a fresh peer CID" {
    var manager = PathManager.init(.full, testKey(50_000), true);
    const migrated = testKeyOtherHost(50_000);
    _ = manager.onDatagram(migrated, 1_200, test_challenge, 0);

    const validated = manager.validatePathResponse(migrated, test_challenge, 100).?;
    try testing.expectEqual(AddressChange.migration, validated.change);
    // No fresh peer CID: the caller does not promote, just counts the block.
    manager.recordMigrationBlockedNoPeerCid();
    try testing.expectEqual(@as(u64, 1), manager.metrics.migrations_blocked_no_peer_cid);
    try testing.expectEqual(@as(u64, 0), manager.metrics.migrations);
    try testing.expect(manager.activePath().key.eql(testKey(50_000)));

    // The peer later issues a fresh CID: the already-validated candidate
    // promotes without a new challenge round trip.
    const outcome = manager.promoteValidated(migrated).?;
    try testing.expect(outcome.reset_congestion);
    try testing.expect(manager.activePath().key.eql(migrated));
    try testing.expectEqual(@as(u64, 1), manager.metrics.migrations);
}

test "a validated candidate blocked on a peer CID survives further datagrams instead of re-probing" {
    var manager = PathManager.init(.full, testKey(50_000), true);
    const migrated = testKeyOtherHost(50_000);
    _ = manager.onDatagram(migrated, 1_200, test_challenge, 0);
    _ = manager.validatePathResponse(migrated, test_challenge, 100).?;
    manager.recordMigrationBlockedNoPeerCid();
    try testing.expectEqual(@as(u64, 1), manager.metrics.migrations_blocked_no_peer_cid);
    try testing.expectEqual(@as(u64, 1), manager.metrics.path_challenges_sent);

    // Another authenticated datagram arrives on the same still-validated
    // candidate path (for example, carrying the NEW_CONNECTION_ID that will
    // unblock it). It must not discard the completed validation and start a
    // fresh challenge round trip.
    const decision = manager.onDatagram(migrated, 300, test_challenge, 200);
    try testing.expectEqual(PathDecision.validated_pending_promotion, decision);
    try testing.expectEqual(@as(u64, 1), manager.metrics.path_challenges_sent);

    // The still-validated candidate promotes without ever re-probing.
    const outcome = manager.promoteValidated(migrated).?;
    try testing.expect(outcome.reset_congestion);
    try testing.expect(manager.activePath().key.eql(migrated));
}

test "validatePathResponse lifts the candidate's anti-amplification limit immediately, not only on promotion" {
    var manager = PathManager.init(.full, testKey(50_000), true);
    const migrated = testKeyOtherHost(50_000);
    // A small receive credits only a small (3x) send budget.
    _ = manager.onDatagram(migrated, 100, test_challenge, 0);
    try testing.expect(manager.canSendOnPath(migrated, 300));
    try testing.expect(!manager.canSendOnPath(migrated, 301));

    _ = manager.validatePathResponse(migrated, test_challenge, 10).?;
    // Validated but deliberately not promoted (e.g. still waiting on a fresh
    // peer CID): RFC 9000 §8.2.3 already permits unlimited sends on this path.
    try testing.expect(manager.canSendOnPath(migrated, std.math.maxInt(u64)));
    // The old path is still active — validation alone does not promote.
    try testing.expect(manager.activePath().key.eql(testKey(50_000)));
}

test "a pending candidate's promotion classification is recomputed against the current active path" {
    var manager = PathManager.init(.full, testKey(50_000), true); // A active
    const b = testKeyOtherHost(50_001);
    const c = testKeyOtherHost(50_002); // same host as B, different port

    // B validates while A is active: classified as a host migration.
    _ = manager.onDatagram(b, 1_200, test_challenge, 0);
    const validated_b = manager.validatePathResponse(b, test_challenge, 10).?;
    try testing.expectEqual(AddressChange.migration, validated_b.change);
    // No fresh peer CID for B yet: it stays pending.
    manager.recordMigrationBlockedNoPeerCid();

    // C also validates while A is still active (also a migration relative to
    // A), and gets a fresh peer CID first, so it promotes.
    _ = manager.onDatagram(c, 1_200, test_challenge, 20);
    _ = manager.validatePathResponse(c, test_challenge, 30).?;
    const outcome_c = manager.promoteValidated(c).?;
    try testing.expectEqual(AddressChange.migration, outcome_c.change);
    try testing.expect(manager.activePath().key.eql(c));

    // B is still pending, and a fresh peer CID becomes available for it too.
    // B and C share a host: relative to the now-active C, B is only a NAT
    // rebinding, even though it was originally probed and validated as a
    // migration relative to A.
    try testing.expectEqual(AddressChange.nat_rebinding, manager.promotionChange(b).?);
    const outcome_b = manager.promoteValidated(b).?;
    try testing.expectEqual(AddressChange.nat_rebinding, outcome_b.change);
    try testing.expect(!outcome_b.reset_congestion);
    try testing.expect(manager.activePath().key.eql(b));
    try testing.expectEqual(@as(u64, 1), manager.metrics.nat_rebindings);
    try testing.expectEqual(@as(u64, 1), manager.metrics.migrations);
}

test "validatePathResponse returns the current classification, not the one captured when the challenge started" {
    var manager = PathManager.init(.full, testKey(50_000), true); // A active
    const b = testKeyOtherHost(50_001);
    const c = testKeyOtherHost(50_002); // same host as B, different port

    // B and C both start validating while A is active: both would classify
    // as migrations relative to A.
    _ = manager.onDatagram(b, 1_200, test_challenge, 0);
    _ = manager.onDatagram(c, 1_200, test_challenge, 0);

    // C's PATH_RESPONSE arrives first and promotes it before B's does.
    _ = manager.validatePathResponse(c, test_challenge, 10).?;
    _ = manager.promoteValidated(c).?;
    try testing.expect(manager.activePath().key.eql(c));

    // B's PATH_RESPONSE arrives only now, after C is already active. B
    // shares C's host, so it must be reported as a NAT rebinding relative to
    // the *current* active path — not the `.migration` its challenge started
    // as — the instant validation succeeds, not only via a later
    // `promotionChange` query.
    const validated_b = manager.validatePathResponse(b, test_challenge, 20).?;
    try testing.expectEqual(AddressChange.nat_rebinding, validated_b.change);

    const outcome_b = manager.promoteValidated(b).?;
    try testing.expectEqual(AddressChange.nat_rebinding, outcome_b.change);
    try testing.expect(!outcome_b.reset_congestion);
}

test "re-probing a previously-active validated path resets its stale anti-amplification ledger" {
    const a = testKey(50_000);
    const b = testKeyOtherHost(50_001);
    var manager = PathManager.init(.full, a, true);

    // B validates and promotes; A becomes a non-active `.validated` path
    // whose ledger was marked validated (unlimited) during its own tenure as
    // the active path.
    _ = manager.onDatagram(b, 1_200, test_challenge, 0);
    _ = manager.validatePathResponse(b, test_challenge, 10).?;
    _ = manager.promoteValidated(b).?;
    try testing.expect(manager.activePath().key.eql(b));

    // Traffic returns to A: it is re-probed (a previously-active path has no
    // tracked recency), and its old "unlimited" ledger must not survive into
    // the new validation attempt — the budget reflects only the fresh
    // datagram's 100 bytes.
    const decision = manager.onDatagram(a, 100, test_challenge, 20);
    try testing.expect(decision == .probe);
    try testing.expect(manager.canSendOnPath(a, 300));
    try testing.expect(!manager.canSendOnPath(a, 301));

    // Once A re-validates, its ledger is unlimited again.
    _ = manager.validatePathResponse(a, test_challenge, 30).?;
    try testing.expect(manager.canSendOnPath(a, std.math.maxInt(u64)));
}

test "a previously-active validated path is re-probed, not trusted indefinitely" {
    const a = testKey(50_000);
    const b = testKey(50_001); // same host, new port: NAT rebinding
    var manager = PathManager.init(.full, a, true);

    // B validates and is promoted; A is now a non-active `.validated` path.
    _ = manager.onDatagram(b, 1_200, test_challenge, 0);
    _ = manager.validatePathResponse(b, test_challenge, 10).?;
    _ = manager.promoteValidated(b).?;
    try testing.expect(manager.activePath().key.eql(b));

    // Traffic later arrives back on A. A previously-active `.validated` path
    // must not be mistaken for a pending-first-promotion candidate: it is
    // re-probed like any unvalidated/failed path (RFC 9000 §9.3 permits
    // skipping validation only for a *recently* seen address, which this
    // implementation does not track).
    const decision = manager.onDatagram(a, 1_200, test_challenge, 20);
    try testing.expect(decision == .probe);

    // The fresh probe recomputes `change` relative to the *current* active
    // path (B), so a stale `.migration` value from A's original
    // initialization cannot make a plain port rebind look like a host
    // migration once it re-validates.
    const echoed = PathManager.onPathChallenge(decision.probe.data);
    const validated = manager.validatePathResponse(a, echoed, 30).?;
    try testing.expectEqual(AddressChange.nat_rebinding, validated.change);
    const outcome = manager.promoteValidated(a).?;
    try testing.expectEqual(AddressChange.nat_rebinding, outcome.change);
    try testing.expect(!outcome.reset_congestion);
}

test "promoteValidated is null for a path that never validated" {
    var manager = PathManager.init(.full, testKey(50_000), true);
    try testing.expectEqual(@as(?MigrationOutcome, null), manager.promoteValidated(testKey(50_001)));
    _ = manager.onDatagram(testKey(50_001), 1_200, test_challenge, 0);
    // Still only .validating, not .validated_pending_promotion: promotion
    // must not skip validation.
    try testing.expectEqual(@as(?MigrationOutcome, null), manager.promoteValidated(testKey(50_001)));
}

test "per-path anti-amplification accounting does not leak between paths" {
    var manager = PathManager.init(.full, testKey(50_000), false);
    _ = manager.onDatagram(testKey(50_000), 1_200, test_challenge, 0);
    const candidate = testKeyOtherHost(50_000);
    _ = manager.onDatagram(candidate, 100, test_challenge, 0);

    // The active (still unvalidated) path's budget reflects only its own bytes.
    try testing.expect(manager.canSendOnPath(testKey(50_000), 3_600));
    try testing.expect(!manager.canSendOnPath(testKey(50_000), 3_601));
    // The candidate path has its own, much smaller budget.
    try testing.expect(manager.canSendOnPath(candidate, 300));
    try testing.expect(!manager.canSendOnPath(candidate, 301));
    manager.recordSentOnPath(candidate, 300);
    try testing.expect(!manager.canSendOnPath(candidate, 1));
    // An untracked path has no budget at all.
    try testing.expect(!manager.canSendOnPath(testKeyOtherHost(1), 1));
}

test "probe storms recycle probe slots but never the active path" {
    var manager = PathManager.init(.full, testKey(50_000), true);
    // More new tuples than slots: the oldest probes are recycled.
    var port: u16 = 50_001;
    while (port < 50_001 + 2 * max_paths) : (port += 1) {
        _ = manager.onDatagram(testKey(port), 1_200, test_challenge, 0);
    }
    // The active path survived the storm and still routes.
    try testing.expect(manager.activePath().key.eql(testKey(50_000)));
    try testing.expectEqual(PathState.validated, manager.activePath().state);
    try testing.expectEqual(PathDecision.on_active_path, manager.onDatagram(testKey(50_000), 1_200, test_challenge, 0));
}

test "a policy-blocked tuple still gets its own anti-amplification ledger, never a challenge" {
    var manager = PathManager.init(.disabled, testKey(50_000), true);
    const blocked = testKeyOtherHost(50_001);

    const decision = manager.onDatagram(blocked, 100, test_challenge, 0);
    try testing.expectEqual(AddressChange.migration, decision.blocked.change);
    try testing.expect(decision.blocked.first_observation);
    try testing.expectEqual(@as(u64, 1), manager.metrics.migrations_blocked);
    try testing.expectEqual(@as(u64, 0), manager.metrics.path_challenges_sent);

    // A budget exists (isolated from the active path) even though the
    // tuple may never migrate or promote: enough to answer a PATH_CHALLENGE
    // received from it, per RFC 9000 §8.2.2.
    try testing.expectEqual(@as(u64, 300), manager.remainingOnPath(blocked));
    try testing.expectEqual(PathState.unvalidated, manager.stateOf(blocked).?);

    // More traffic from the same blocked tuple keeps crediting the same
    // ledger rather than creating a second entry or a challenge.
    _ = manager.onDatagram(blocked, 50, test_challenge, 0);
    try testing.expectEqual(@as(u64, 450), manager.remainingOnPath(blocked));
    try testing.expectEqual(@as(u64, 2), manager.metrics.migrations_blocked);
    try testing.expectEqual(@as(u64, 0), manager.metrics.path_challenges_sent);

    // Never eligible for promotion while blocked: validatePathResponse
    // requires `.validating`, which a blocked tuple never reaches.
    try testing.expectEqual(@as(?ValidatedCandidate, null), manager.validatePathResponse(blocked, test_challenge, 10));
    try testing.expect(manager.activePath().key.eql(testKey(50_000)));
}

test "remainingOnPath mirrors canSendOnPath and is zero for an untracked path" {
    var manager = PathManager.init(.full, testKey(50_000), false);
    _ = manager.onDatagram(testKey(50_000), 1_200, test_challenge, 0);
    try testing.expectEqual(@as(u64, 3_600), manager.remainingOnPath(testKey(50_000)));
    manager.paths[manager.active].?.anti_amplification.recordSent(1_000);
    try testing.expectEqual(@as(u64, 2_600), manager.remainingOnPath(testKey(50_000)));
    try testing.expectEqual(@as(u64, 0), manager.remainingOnPath(testKeyOtherHost(1)));
}

test "stateOf reports lifecycle state and null for an untracked path" {
    var manager = PathManager.init(.full, testKey(50_000), true);
    try testing.expectEqual(@as(?PathState, PathState.validated), manager.stateOf(testKey(50_000)));
    try testing.expectEqual(@as(?PathState, null), manager.stateOf(testKeyOtherHost(1)));

    const candidate = testKeyOtherHost(50_001);
    _ = manager.onDatagram(candidate, 1_200, test_challenge, 0);
    try testing.expectEqual(@as(?PathState, PathState.validating), manager.stateOf(candidate));
}

test "pendingPromotionCandidate finds a validated-but-unpromoted path and clears once promoted" {
    var manager = PathManager.init(.full, testKey(50_000), true);
    try testing.expectEqual(@as(?PathKey, null), manager.pendingPromotionCandidate());

    const candidate = testKeyOtherHost(50_001);
    _ = manager.onDatagram(candidate, 1_200, test_challenge, 0);
    try testing.expectEqual(@as(?PathKey, null), manager.pendingPromotionCandidate());

    _ = manager.validatePathResponse(candidate, test_challenge, 10).?;
    try testing.expect(manager.pendingPromotionCandidate().?.eql(candidate));

    _ = manager.promoteValidated(candidate).?;
    try testing.expectEqual(@as(?PathKey, null), manager.pendingPromotionCandidate());
}

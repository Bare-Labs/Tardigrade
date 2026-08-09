//! TLS record epoch bridge.
//!
//! The shared TLS engine emits protocol events: handshake bytes, traffic
//! secrets, epoch discard, and completion. This module is the record-mode glue
//! between those events and `record_protection`: it owns independent read/write
//! traffic states for handshake and application epochs, keeps the initial
//! ClientHello/ServerHello plaintext path explicit, and rejects out-of-order key
//! transitions deterministically.

const std = @import("std");
const crypto = @import("crypto");
const algorithms = @import("algorithms.zig");
const engine = @import("engine.zig");
const events = @import("events.zig");
const key_schedule = @import("key_schedule.zig");
const record_codec = @import("record_codec.zig");
const record_protection = @import("record_protection.zig");
const tls_state = @import("state.zig");
const transport = @import("transport.zig");

const provider = crypto.provider;
const secrets = crypto.secrets;

pub const Error = record_codec.Error || record_protection.Error || key_schedule.Error || error{
    UnsupportedRecordEpoch,
    DuplicateTrafficSecret,
    MissingReadKeys,
    MissingWriteKeys,
    MissingApplicationKeys,
    HandshakeNotComplete,
    InvalidEpochTransition,
    UnexpectedRecordContent,
    EpochAlreadyDiscarded,
    EpochDiscardTooEarly,
    /// A `KeyUpdate` arrived for a direction whose application traffic secret
    /// is not (or no longer) retained, so the `"traffic upd"` chain cannot be
    /// advanced. Distinct from `MissingApplicationKeys`: the derived record
    /// keys may well still exist — it is the *secret* they came from that is
    /// gone, which is exactly the state an orderly discard leaves behind.
    MissingTrafficSecret,
};

/// One direction's retained application traffic secret, kept alongside the
/// derived record keys purely so `KeyUpdate` can walk RFC 8446 §7.2's
/// `"traffic upd"` chain (#357). Handshake- and 0-RTT-epoch secrets are never
/// retained: neither epoch can be updated, so keeping their secrets past key
/// derivation would extend their lifetime for no protocol reason.
const TrafficSecret = secrets.FixedSecret(provider.max_digest_len);

pub const OpenedRecord = struct {
    epoch: events.EncryptionEpoch,
    inner: record_codec.InnerPlaintext,
};

const DirectionPhase = enum {
    initial,
    handshake,
    application,
    complete,
};

pub const Bridge = struct {
    crypto_provider: provider.CryptoProvider,
    cipher_suite: algorithms.CipherSuite,
    read_handshake: ?record_protection.ReadState = null,
    write_handshake: ?record_protection.WriteState = null,
    read_zero_rtt: ?record_protection.ReadState = null,
    write_zero_rtt: ?record_protection.WriteState = null,
    read_application: ?record_protection.ReadState = null,
    write_application: ?record_protection.WriteState = null,
    /// Retained application traffic secrets, the input to the next `KeyUpdate`
    /// (#357). Kept per direction because each direction advances its own
    /// chain independently and at its own time.
    read_application_secret: TrafficSecret = .{},
    write_application_secret: TrafficSecret = .{},
    /// How many times each direction has advanced past the handshake's
    /// original application traffic secret (0 = `application_traffic_secret_0`).
    /// Observable state, not a limit: it lets a caller — and this module's
    /// tests — tell "the keys changed" from "the same keys were reinstalled".
    read_key_generation: u64 = 0,
    write_key_generation: u64 = 0,
    read_phase: DirectionPhase = .initial,
    write_phase: DirectionPhase = .initial,
    initial_discarded: bool = false,
    handshake_discarded: bool = false,
    application_discarded: bool = false,
    handshake_complete: bool = false,
    /// Set by every session-teardown path and never cleared. Teardown is
    /// terminal: a torn-down bridge must not be able to acquire key material
    /// again, and the per-epoch discard flags alone cannot express that.
    ///
    /// There are two teardown paths, and *both* reset `handshake_complete`
    /// to false — which was the only gate the 0-RTT install path had. Without
    /// this flag either one left a bridge able to reinstall both 0-RTT
    /// directions and resume sealing and opening records on that epoch
    /// (#493-B review):
    ///
    ///   * `deinit`, the unconditional wipe for an abandoned or failed
    ///     handshake; and
    ///   * `discardEpoch(.application)`, the *orderly* teardown of a
    ///     completed session.
    ///
    /// Starting a new session is `Bridge.init`, which yields a fresh value
    /// with this cleared.
    torn_down: bool = false,

    pub fn init(crypto_provider: provider.CryptoProvider, cipher_suite: algorithms.CipherSuite) Bridge {
        return .{ .crypto_provider = crypto_provider, .cipher_suite = cipher_suite };
    }

    /// Unconditionally wipes all traffic secret material, regardless of
    /// whether the handshake reached a state where `discardEpoch` would
    /// have accepted an orderly discard. Teardown on an abandoned or
    /// failed handshake must still zero any installed keys, so this does
    /// not route through the ordering checks in `discardEpoch`.
    pub fn deinit(self: *Bridge) void {
        clearRead(&self.read_handshake);
        clearWrite(&self.write_handshake);
        clearRead(&self.read_zero_rtt);
        clearWrite(&self.write_zero_rtt);
        clearRead(&self.read_application);
        clearWrite(&self.write_application);
        self.read_application_secret.deinit();
        self.write_application_secret.deinit();
        self.initial_discarded = true;
        self.handshake_discarded = true;
        self.application_discarded = true;
        self.handshake_complete = false;
        self.torn_down = true;
    }

    pub fn applyEvent(self: *Bridge, event: events.Event, out: []u8) Error!?[]const u8 {
        switch (event) {
            .handshake_bytes => |bytes| return try self.sealHandshake(bytes.epoch, bytes.data, out),
            // #564: the negotiated suite arrives before any handshake-epoch
            // traffic secret (the contract `EventSink.emitNegotiatedParameters`
            // documents), so updating `cipher_suite` here — rather than only
            // ever accepting the constructor's fixed value — is what lets
            // `installTrafficSecret` derive the right `TrafficKeys` for
            // whichever suite this connection actually negotiated.
            .negotiated_parameters, .early_data_parameters => |params| self.cipher_suite = algorithms.fromInt(algorithms.CipherSuite, params.cipher_suite) orelse
                return error.UnsupportedRecordEpoch,
            .traffic_secret => |traffic_secret| try self.installTrafficSecret(traffic_secret.epoch, traffic_secret.direction, traffic_secret.data),
            // Ordering is the protocol here (`events.KeyUpdate`): this arrives
            // after the peer's `KeyUpdate` was opened (`.read`) or after our
            // own was sealed by the `handshake_bytes` arm above (`.write`), so
            // applying it in event order is what puts the boundary in the
            // right place.
            .key_update => |update| try self.updateTrafficSecret(update.direction),
            .discard_epoch => |epoch| try self.discardEpoch(epoch),
            .handshake_complete => try self.markHandshakeComplete(),
            .alpn,
            .certificate,
            => {},
        }
        return null;
    }

    pub fn installTrafficSecret(
        self: *Bridge,
        epoch: events.EncryptionEpoch,
        direction: events.SecretDirection,
        traffic_secret: []const u8,
    ) Error!void {
        // Teardown is terminal for every epoch, including the ones whose
        // ordinary gates `deinit` happens to leave open.
        if (self.torn_down) return error.InvalidEpochTransition;
        switch (epoch) {
            .handshake => switch (direction) {
                .read => {
                    if (self.read_phase != .initial or self.handshake_discarded) return error.InvalidEpochTransition;
                    try self.installRead(&self.read_handshake, traffic_secret);
                    self.read_phase = .handshake;
                },
                .write => {
                    if (self.write_phase != .initial or self.handshake_discarded) return error.InvalidEpochTransition;
                    try self.installWrite(&self.write_handshake, traffic_secret);
                    self.write_phase = .handshake;
                },
            },
            .application => switch (direction) {
                .read => {
                    if (self.read_phase != .handshake or self.handshake_discarded or self.application_discarded) return error.InvalidEpochTransition;
                    try self.installRead(&self.read_application, traffic_secret);
                    // Retained only after the keys derived successfully, so a
                    // failed install never leaves a secret behind that a later
                    // `KeyUpdate` could advance off of.
                    self.read_application_secret.replace(traffic_secret) catch return error.InvalidTrafficSecretLength;
                    self.read_phase = .application;
                },
                .write => {
                    if (self.write_phase != .handshake or self.handshake_discarded or self.application_discarded) return error.InvalidEpochTransition;
                    try self.installWrite(&self.write_application, traffic_secret);
                    self.write_application_secret.replace(traffic_secret) catch return error.InvalidTrafficSecretLength;
                    self.write_phase = .application;
                },
            },
            .zero_rtt => switch (direction) {
                .read => {
                    if (self.handshake_complete) return error.InvalidEpochTransition;
                    try self.installRead(&self.read_zero_rtt, traffic_secret);
                },
                .write => {
                    if (self.handshake_complete) return error.InvalidEpochTransition;
                    try self.installWrite(&self.write_zero_rtt, traffic_secret);
                },
            },
            .initial => return error.UnsupportedRecordEpoch,
        }
    }

    /// Discards `epoch`'s key material as a validated one-way state
    /// transition: each epoch may be discarded at most once, and the
    /// handshake and initial epochs may only be discarded once the
    /// handshake has actually progressed past them, so a premature or
    /// duplicate discard fails closed instead of silently no-op'ing.
    pub fn discardEpoch(self: *Bridge, epoch: events.EncryptionEpoch) Error!void {
        switch (epoch) {
            .initial => {
                if (self.initial_discarded) return error.EpochAlreadyDiscarded;
                if (self.read_phase == .initial or self.write_phase == .initial) return error.EpochDiscardTooEarly;
                self.initial_discarded = true;
            },
            .handshake => {
                if (self.handshake_discarded) return error.EpochAlreadyDiscarded;
                if (self.read_phase != .application or self.write_phase != .application) return error.EpochDiscardTooEarly;
                clearRead(&self.read_handshake);
                clearWrite(&self.write_handshake);
                self.handshake_discarded = true;
            },
            .application => {
                if (self.application_discarded) return error.EpochAlreadyDiscarded;
                // Orderly application-epoch discard represents session
                // teardown after a completed handshake, not abandonment --
                // that path is `deinit`, which wipes unconditionally
                // regardless of how far the handshake got.
                if (!self.handshake_complete or self.read_phase != .complete or self.write_phase != .complete) {
                    return error.EpochDiscardTooEarly;
                }
                clearRead(&self.read_application);
                clearWrite(&self.write_application);
                self.read_application_secret.deinit();
                self.write_application_secret.deinit();
                self.application_discarded = true;
                self.read_phase = .initial;
                self.write_phase = .initial;
                self.handshake_complete = false;
                // Orderly teardown is still teardown: clearing
                // `handshake_complete` above would otherwise reopen the
                // 0-RTT install gate, letting a finished session acquire
                // fresh early-data keys and resume record traffic.
                self.torn_down = true;
            },
            .zero_rtt => {
                clearRead(&self.read_zero_rtt);
                clearWrite(&self.write_zero_rtt);
            },
        }
    }

    pub fn markHandshakeComplete(self: *Bridge) Error!void {
        if (self.handshake_complete) return error.InvalidEpochTransition;
        if (!self.initial_discarded or !self.handshake_discarded) return error.InvalidEpochTransition;
        if (self.read_phase != .application or self.write_phase != .application) return error.InvalidEpochTransition;
        if (self.read_application == null or self.write_application == null) return error.MissingApplicationKeys;
        clearRead(&self.read_zero_rtt);
        clearWrite(&self.write_zero_rtt);
        self.handshake_complete = true;
        self.read_phase = .complete;
        self.write_phase = .complete;
    }

    /// Advances `direction`'s application traffic secret one step along RFC
    /// 8446 §7.2's chain and rebuilds that direction's record keys from it
    /// (#357).
    ///
    /// The transition is all-or-nothing. The new secret and the new keys are
    /// both derived into scratch *before* anything installed is touched, so a
    /// provider failure anywhere leaves the direction still protecting traffic
    /// under the generation it had — a half-updated direction would be
    /// undecryptable in both generations at once.
    ///
    /// On success the previous keys are zeroized (`WriteState.deinit`/
    /// `ReadState.deinit` wipe their `TrafficKeys`), the previous secret is
    /// overwritten in place by `FixedSecret.replace`, and the record sequence
    /// restarts at zero — RFC 8446 §5.3's requirement, since the nonce is the
    /// static IV XOR the sequence and a fresh key must not reuse a nonce that
    /// key never used, but also must start counting again rather than carry
    /// the old count forward.
    ///
    /// Only the application epoch can be updated, and only on a live,
    /// completed, not-torn-down session: `KeyUpdate` is defined solely as a
    /// post-handshake message, so a pre-handshake or post-teardown call is a
    /// state error rather than a no-op.
    pub fn updateTrafficSecret(self: *Bridge, direction: events.SecretDirection) Error!void {
        if (self.torn_down or self.application_discarded) return error.InvalidEpochTransition;
        if (!self.handshake_complete) return error.HandshakeNotComplete;

        const hash = record_protection.suiteProfile(self.cipher_suite).hash;
        var next: [provider.max_digest_len]u8 = undefined;
        defer provider.secureZero(&next);
        const digest_len = hash.digestLength();

        switch (direction) {
            .read => {
                const state = self.readApplication() orelse return error.MissingReadKeys;
                const current = self.read_application_secret.slice();
                if (current.len == 0) return error.MissingTrafficSecret;
                try key_schedule.KeySchedule.nextTrafficSecret(self.crypto_provider, hash, current, next[0..digest_len]);
                var keys = try record_protection.TrafficKeys.derive(self.crypto_provider, self.cipher_suite, next[0..digest_len]);
                errdefer keys.deinit();
                self.read_application_secret.replace(next[0..digest_len]) catch return error.InvalidTrafficSecretLength;
                state.deinit();
                state.* = record_protection.ReadState.init(self.crypto_provider, keys);
                self.read_key_generation += 1;
            },
            .write => {
                const state = self.writeApplication() orelse return error.MissingWriteKeys;
                const current = self.write_application_secret.slice();
                if (current.len == 0) return error.MissingTrafficSecret;
                try key_schedule.KeySchedule.nextTrafficSecret(self.crypto_provider, hash, current, next[0..digest_len]);
                var keys = try record_protection.TrafficKeys.derive(self.crypto_provider, self.cipher_suite, next[0..digest_len]);
                errdefer keys.deinit();
                self.write_application_secret.replace(next[0..digest_len]) catch return error.InvalidTrafficSecretLength;
                state.deinit();
                state.* = record_protection.WriteState.init(self.crypto_provider, keys);
                self.write_key_generation += 1;
            },
        }
    }

    /// Records sealed under the current write generation — i.e. the write
    /// state's next sequence number, which a `KeyUpdate` reset to zero. This
    /// is the input `key_update.UsageLimits.reached` is written against, kept
    /// as an accessor rather than a mirrored counter so proactive-update
    /// policy can never disagree with the sequence feeding the record nonce.
    pub fn applicationRecordsSealed(self: *const Bridge) u64 {
        const state = self.write_application orelse return 0;
        return state.sequence;
    }

    pub fn sealHandshake(self: *Bridge, epoch: events.EncryptionEpoch, bytes: []const u8, out: []u8) Error![]const u8 {
        if (bytes.len <= record_codec.max_plaintext_fragment_len) {
            return self.sealProtected(epoch, .handshake, bytes, out);
        }
        return switch (epoch) {
            .initial => blk: {
                if (self.initial_discarded) return error.UnsupportedRecordEpoch;
                const needed = try plaintextHandshakeRecordLen(bytes.len);
                if (out.len < needed) return error.RecordBufferOverflow;
                var in_pos: usize = 0;
                var out_pos: usize = 0;
                while (in_pos < bytes.len) {
                    const take = @min(record_codec.max_plaintext_fragment_len, bytes.len - in_pos);
                    const record = try record_codec.encodePlaintextRecord(.handshake, bytes[in_pos..][0..take], out[out_pos..]);
                    in_pos += take;
                    out_pos += record.len;
                }
                break :blk out[0..out_pos];
            },
            .handshake => blk: {
                const write = self.writeHandshake() orelse return error.MissingWriteKeys;
                break :blk try sealHandshakeFragments(write, bytes, out);
            },
            .application => blk: {
                if (!self.handshake_complete) return error.HandshakeNotComplete;
                const write = self.writeApplication() orelse return error.MissingWriteKeys;
                break :blk try sealHandshakeFragments(write, bytes, out);
            },
            .zero_rtt => blk: {
                if (self.handshake_complete) return error.UnsupportedRecordEpoch;
                const write = self.writeZeroRtt() orelse return error.MissingWriteKeys;
                break :blk try sealHandshakeFragments(write, bytes, out);
            },
        };
    }

    pub fn sealedHandshakeLen(self: *Bridge, epoch: events.EncryptionEpoch, bytes_len: usize) Error!usize {
        return switch (epoch) {
            .initial => if (self.initial_discarded)
                error.UnsupportedRecordEpoch
            else
                try plaintextHandshakeRecordLen(bytes_len),
            .handshake => blk: {
                const write = self.writeHandshake() orelse return error.MissingWriteKeys;
                break :blk try protectedHandshakeRecordLen(write, bytes_len);
            },
            .application => blk: {
                if (!self.handshake_complete) return error.HandshakeNotComplete;
                const write = self.writeApplication() orelse return error.MissingWriteKeys;
                break :blk try protectedHandshakeRecordLen(write, bytes_len);
            },
            .zero_rtt => blk: {
                if (self.handshake_complete) return error.UnsupportedRecordEpoch;
                const write = self.writeZeroRtt() orelse return error.MissingWriteKeys;
                break :blk try protectedHandshakeRecordLen(write, bytes_len);
            },
        };
    }

    pub fn sealProtected(
        self: *Bridge,
        epoch: events.EncryptionEpoch,
        content_type: record_codec.ContentType,
        bytes: []const u8,
        out: []u8,
    ) Error![]const u8 {
        return switch (epoch) {
            .initial => if (self.initial_discarded)
                error.UnsupportedRecordEpoch
            else if (content_type == .handshake)
                record_codec.encodePlaintextRecord(.handshake, bytes, out)
            else
                error.UnsupportedRecordEpoch,
            .handshake => blk: {
                const write = self.writeHandshake() orelse return error.MissingWriteKeys;
                break :blk try write.seal(content_type, bytes, 0, out);
            },
            .application => blk: {
                if (!self.handshake_complete and content_type != .alert) return error.HandshakeNotComplete;
                const write = self.writeApplication() orelse return error.MissingWriteKeys;
                break :blk try write.seal(content_type, bytes, 0, out);
            },
            .zero_rtt => blk: {
                if (self.handshake_complete or
                    !(content_type == .application_data or content_type == .handshake))
                    return error.UnsupportedRecordEpoch;
                const write = self.writeZeroRtt() orelse return error.MissingWriteKeys;
                break :blk try write.seal(content_type, bytes, 0, out);
            },
        };
    }

    pub fn sealApplicationData(self: *Bridge, bytes: []const u8, out: []u8) Error![]const u8 {
        return self.sealProtected(.application, .application_data, bytes, out);
    }

    pub fn openHandshake(
        self: *Bridge,
        epoch: events.EncryptionEpoch,
        record: record_codec.Record,
        out: []u8,
    ) Error!OpenedRecord {
        const opened = try self.openProtected(epoch, record, out);
        if (opened.inner.content_type != .handshake) return error.UnexpectedRecordContent;
        return opened;
    }

    pub fn openProtected(
        self: *Bridge,
        epoch: events.EncryptionEpoch,
        record: record_codec.Record,
        out: []u8,
    ) Error!OpenedRecord {
        const inner = switch (epoch) {
            .initial => blk: {
                if (self.initial_discarded) return error.UnsupportedRecordEpoch;
                if (record.content_type != .handshake) return error.UnexpectedRecordContent;
                break :blk record_codec.InnerPlaintext{
                    .content_type = record.content_type,
                    .content = record.payload,
                    .padding_len = 0,
                };
            },
            .handshake => blk: {
                const read = self.readHandshake() orelse return error.MissingReadKeys;
                break :blk try read.open(record, out);
            },
            .application => blk: {
                if (!self.handshake_complete) return error.HandshakeNotComplete;
                const read = self.readApplication() orelse return error.MissingReadKeys;
                break :blk try read.open(record, out);
            },
            .zero_rtt => blk: {
                if (self.handshake_complete) return error.UnsupportedRecordEpoch;
                const read = self.readZeroRtt() orelse return error.MissingReadKeys;
                break :blk try read.open(record, out);
            },
        };
        return .{ .epoch = epoch, .inner = inner };
    }

    pub fn openApplicationData(self: *Bridge, record: record_codec.Record, out: []u8) Error!OpenedRecord {
        const opened = try self.openProtected(.application, record, out);
        if (opened.inner.content_type != .application_data) return error.UnexpectedRecordContent;
        return opened;
    }

    pub fn hasReadKeys(self: *const Bridge, epoch: events.EncryptionEpoch) bool {
        return switch (epoch) {
            .handshake => self.read_handshake != null,
            .zero_rtt => self.read_zero_rtt != null,
            .application => self.read_application != null,
            .initial => false,
        };
    }

    pub fn hasWriteKeys(self: *const Bridge, epoch: events.EncryptionEpoch) bool {
        return switch (epoch) {
            .handshake => self.write_handshake != null,
            .zero_rtt => self.write_zero_rtt != null,
            .application => self.write_application != null,
            .initial => false,
        };
    }

    fn installRead(self: *Bridge, slot: *?record_protection.ReadState, traffic_secret: []const u8) Error!void {
        if (slot.* != null) return error.DuplicateTrafficSecret;
        slot.* = record_protection.ReadState.init(
            self.crypto_provider,
            try record_protection.TrafficKeys.derive(self.crypto_provider, self.cipher_suite, traffic_secret),
        );
    }

    fn installWrite(self: *Bridge, slot: *?record_protection.WriteState, traffic_secret: []const u8) Error!void {
        if (slot.* != null) return error.DuplicateTrafficSecret;
        slot.* = record_protection.WriteState.init(
            self.crypto_provider,
            try record_protection.TrafficKeys.derive(self.crypto_provider, self.cipher_suite, traffic_secret),
        );
    }

    fn readHandshake(self: *Bridge) ?*record_protection.ReadState {
        if (self.read_handshake) |*state| return state;
        return null;
    }

    fn writeHandshake(self: *Bridge) ?*record_protection.WriteState {
        if (self.write_handshake) |*state| return state;
        return null;
    }

    fn readZeroRtt(self: *Bridge) ?*record_protection.ReadState {
        if (self.read_zero_rtt) |*state| return state;
        return null;
    }

    fn writeZeroRtt(self: *Bridge) ?*record_protection.WriteState {
        if (self.write_zero_rtt) |*state| return state;
        return null;
    }

    fn readApplication(self: *Bridge) ?*record_protection.ReadState {
        if (self.read_application) |*state| return state;
        return null;
    }

    fn writeApplication(self: *Bridge) ?*record_protection.WriteState {
        if (self.write_application) |*state| return state;
        return null;
    }
};

fn clearRead(slot: *?record_protection.ReadState) void {
    if (slot.*) |*state| state.deinit();
    slot.* = null;
}

fn clearWrite(slot: *?record_protection.WriteState) void {
    if (slot.*) |*state| state.deinit();
    slot.* = null;
}

/// Number of `max_plaintext_fragment_len`-sized chunks `bytes_len` splits
/// into (0 for an empty input). Uses `std.math.divCeil`'s
/// `@divFloor(numerator - 1, denominator) + 1` form rather than the
/// `(bytes_len + chunk_size - 1) / chunk_size` idiom, so a synthetic
/// near-`usize`-max `bytes_len` -- impossible to represent with a real
/// allocation, but exactly the "arithmetic/offset overflow-adjacent
/// synthetic limits" #493 requires coverage for -- never overflows this
/// step's own `+ chunk_size - 1` addition; the `Error!` return still exists
/// because callers (`plaintextHandshakeRecordLen`/
/// `protectedHandshakeRecordLen`) add `bytes_len` back on top of the chunk
/// overhead, and that addition can overflow even though this one can't.
fn chunkCount(bytes_len: usize) Error!usize {
    if (bytes_len == 0) return 0;
    return std.math.divCeil(usize, bytes_len, record_codec.max_plaintext_fragment_len) catch error.RecordTooLarge;
}

fn plaintextHandshakeRecordLen(bytes_len: usize) Error!usize {
    const chunks = try chunkCount(bytes_len);
    const overhead = std.math.mul(usize, chunks, record_codec.header_len) catch return error.RecordTooLarge;
    return std.math.add(usize, bytes_len, overhead) catch error.RecordTooLarge;
}

fn protectedHandshakeRecordLen(write: *const record_protection.WriteState, bytes_len: usize) Error!usize {
    const chunks = try chunkCount(bytes_len);
    const per_chunk_overhead = record_codec.header_len + 1 + write.keys.profile.aead.tagLength();
    const overhead = std.math.mul(usize, chunks, per_chunk_overhead) catch return error.RecordTooLarge;
    return std.math.add(usize, bytes_len, overhead) catch error.RecordTooLarge;
}

fn sealHandshakeFragments(
    write: *record_protection.WriteState,
    bytes: []const u8,
    out: []u8,
) Error![]const u8 {
    if (write.exhausted) return error.SequenceExhausted;
    const chunks = try chunkCount(bytes.len);
    if (chunks > 0 and chunks - 1 > std.math.maxInt(u64) - write.sequence) return error.SequenceExhausted;
    const needed = try protectedHandshakeRecordLen(write, bytes.len);
    if (out.len < needed) return error.RecordBufferOverflow;

    var in_pos: usize = 0;
    var out_pos: usize = 0;
    while (in_pos < bytes.len) {
        const take = @min(record_codec.max_plaintext_fragment_len, bytes.len - in_pos);
        const record = try write.seal(.handshake, bytes[in_pos..][0..take], 0, out[out_pos..]);
        in_pos += take;
        out_pos += record.len;
    }
    return out[0..out_pos];
}

fn parseSingleRecord(mode: record_codec.RecordMode, bytes: []const u8) Error!record_codec.Record {
    if (bytes.len < record_codec.header_len) return error.TruncatedRecord;
    const header = try record_codec.parseHeader(bytes[0..record_codec.header_len], mode, .strict);
    const record_len = record_codec.header_len + header.payload_len;
    if (bytes.len != record_len) return error.TruncatedRecord;
    return .{
        .content_type = header.content_type,
        .legacy_version = header.legacy_version,
        .payload = bytes[record_codec.header_len..record_len],
    };
}

fn testProvider() provider.CryptoProvider {
    const pure_zig = crypto.pure_zig;
    const State = struct {
        var entropy = pure_zig.DeterministicEntropy.init(0x352);
        var provider_state = pure_zig.Provider.init(entropy.entropy());
    };
    return State.provider_state.cryptoProvider();
}

fn secret(comptime fill: u8) [32]u8 {
    return [_]u8{fill} ** 32;
}

fn expectAes128TrafficKeys(traffic_secret: [32]u8, keys: record_protection.TrafficKeys) !void {
    const std_crypto = std.crypto;
    const HkdfSha256 = std_crypto.kdf.hkdf.HkdfSha256;
    const expected_key = std_crypto.tls.hkdfExpandLabel(HkdfSha256, traffic_secret, "key", "", 16);
    const expected_iv = std_crypto.tls.hkdfExpandLabel(HkdfSha256, traffic_secret, "iv", "", provider.aead_nonce_len);
    try testing.expectEqualSlices(u8, &expected_key, keys.key.slice());
    try testing.expectEqualSlices(u8, &expected_iv, keys.iv.slice());
}

const testing = std.testing;

test "chunkCount stays overflow-safe at a synthetic near-usize-max bytes_len" {
    try testing.expectEqual(@as(usize, 0), try chunkCount(0));
    try testing.expectEqual(@as(usize, 1), try chunkCount(1));
    try testing.expectEqual(@as(usize, 1), try chunkCount(record_codec.max_plaintext_fragment_len));
    try testing.expectEqual(@as(usize, 2), try chunkCount(record_codec.max_plaintext_fragment_len + 1));
    // `divCeil`'s `@divFloor(numerator - 1, denominator) + 1` form (unlike
    // the naive `(numerator + denominator - 1) / denominator` idiom this
    // replaced) cannot itself overflow for a positive numerator/denominator,
    // so a synthetic near-`usize`-max `bytes_len` still succeeds here with a
    // huge-but-exact chunk count; the overflow this hardening actually
    // guards against surfaces one step later, in
    // `plaintextHandshakeRecordLen`/`protectedHandshakeRecordLen`'s
    // `bytes_len + chunks * overhead` addition (see the next test).
    try testing.expectEqual(
        try std.math.divCeil(usize, std.math.maxInt(usize), record_codec.max_plaintext_fragment_len),
        try chunkCount(std.math.maxInt(usize)),
    );
}

test "plaintextHandshakeRecordLen rejects synthetic overflow-adjacent bytes_len" {
    try testing.expectEqual(@as(usize, 0), try plaintextHandshakeRecordLen(0));
    try testing.expectEqual(
        record_codec.max_plaintext_fragment_len + record_codec.header_len,
        try plaintextHandshakeRecordLen(record_codec.max_plaintext_fragment_len),
    );
    try testing.expectError(error.RecordTooLarge, plaintextHandshakeRecordLen(std.math.maxInt(usize)));
}

test "record epoch bridge drives event loopback across plaintext, handshake, application, and post-handshake records" {
    const cp = testProvider();
    var client = Bridge.init(cp, .tls_aes_128_gcm_sha256);
    defer client.deinit();
    var server = Bridge.init(cp, .tls_aes_128_gcm_sha256);
    defer server.deinit();

    const client_hs = secret(0x11);
    const server_hs = secret(0x22);
    const client_app = secret(0x33);
    const server_app = secret(0x44);

    var protected: [record_codec.max_ciphertext_record_len]u8 = undefined;
    var plaintext: [record_codec.max_ciphertext_fragment_len]u8 = undefined;

    const client_hello = (try client.applyEvent(.{ .handshake_bytes = .{ .epoch = .initial, .data = "client hello" } }, &protected)).?;
    const client_hello_record = try parseSingleRecord(.plaintext, client_hello);
    const opened_client_hello = try server.openHandshake(.initial, client_hello_record, &plaintext);
    try testing.expectEqual(events.EncryptionEpoch.initial, opened_client_hello.epoch);
    try testing.expectEqualStrings("client hello", opened_client_hello.inner.content);

    try testing.expectEqual(@as(?[]const u8, null), try client.applyEvent(.{ .traffic_secret = .{ .epoch = .handshake, .direction = .write, .data = &client_hs } }, &protected));
    try testing.expectEqual(@as(?[]const u8, null), try client.applyEvent(.{ .traffic_secret = .{ .epoch = .handshake, .direction = .read, .data = &server_hs } }, &protected));
    try testing.expectEqual(@as(?[]const u8, null), try server.applyEvent(.{ .traffic_secret = .{ .epoch = .handshake, .direction = .read, .data = &client_hs } }, &protected));
    try testing.expectEqual(@as(?[]const u8, null), try server.applyEvent(.{ .traffic_secret = .{ .epoch = .handshake, .direction = .write, .data = &server_hs } }, &protected));
    try expectAes128TrafficKeys(client_hs, client.write_handshake.?.keys);
    try testing.expectEqual(@as(u64, 0), client.write_handshake.?.sequence);

    // Both directions now have handshake traffic keys installed, so the
    // initial epoch's plaintext keys (there were none to begin with, but
    // the epoch itself) are no longer needed on either side.
    _ = try client.applyEvent(.{ .discard_epoch = .initial }, &protected);
    _ = try server.applyEvent(.{ .discard_epoch = .initial }, &protected);
    try testing.expectError(error.UnsupportedRecordEpoch, client.sealHandshake(.initial, "too late", &protected));
    try testing.expectError(error.UnsupportedRecordEpoch, server.openHandshake(.initial, client_hello_record, &plaintext));

    const encrypted_finished = (try client.applyEvent(.{ .handshake_bytes = .{ .epoch = .handshake, .data = "client finished" } }, &protected)).?;
    const encrypted_finished_record = try parseSingleRecord(.ciphertext, encrypted_finished);
    const opened_finished = try server.openHandshake(.handshake, encrypted_finished_record, &plaintext);
    try testing.expectEqualStrings("client finished", opened_finished.inner.content);
    try testing.expectEqual(@as(u64, 1), client.write_handshake.?.sequence);
    try testing.expectEqual(@as(u64, 1), server.read_handshake.?.sequence);

    try testing.expectEqual(@as(?[]const u8, null), try client.applyEvent(.{ .traffic_secret = .{ .epoch = .application, .direction = .write, .data = &client_app } }, &protected));
    try testing.expectEqual(@as(?[]const u8, null), try client.applyEvent(.{ .traffic_secret = .{ .epoch = .application, .direction = .read, .data = &server_app } }, &protected));
    try testing.expectEqual(@as(?[]const u8, null), try server.applyEvent(.{ .traffic_secret = .{ .epoch = .application, .direction = .read, .data = &client_app } }, &protected));
    try testing.expectEqual(@as(?[]const u8, null), try server.applyEvent(.{ .traffic_secret = .{ .epoch = .application, .direction = .write, .data = &server_app } }, &protected));
    _ = try client.applyEvent(.{ .discard_epoch = .handshake }, &protected);
    _ = try server.applyEvent(.{ .discard_epoch = .handshake }, &protected);
    try testing.expectEqual(@as(?[]const u8, null), try client.applyEvent(.handshake_complete, &protected));
    try testing.expectEqual(@as(?[]const u8, null), try server.applyEvent(.handshake_complete, &protected));

    const application_record = try client.sealApplicationData("GET / HTTP/3", &protected);
    const parsed_application = try parseSingleRecord(.ciphertext, application_record);
    const opened_application = try server.openApplicationData(parsed_application, &plaintext);
    try testing.expectEqual(events.EncryptionEpoch.application, opened_application.epoch);
    try testing.expectEqualStrings("GET / HTTP/3", opened_application.inner.content);
    try testing.expectEqual(@as(u64, 1), client.write_application.?.sequence);
    try testing.expectEqual(@as(u64, 1), server.read_application.?.sequence);

    const post_handshake = (try server.applyEvent(.{ .handshake_bytes = .{ .epoch = .application, .data = "new session ticket" } }, &protected)).?;
    const parsed_post_handshake = try parseSingleRecord(.ciphertext, post_handshake);
    const opened_post_handshake = try client.openHandshake(.application, parsed_post_handshake, &plaintext);
    try testing.expectEqualStrings("new session ticket", opened_post_handshake.inner.content);
    try testing.expectEqual(@as(u64, 1), server.write_application.?.sequence);
    try testing.expectEqual(@as(u64, 1), client.read_application.?.sequence);
}

test "record epoch bridge fragments large post-handshake messages into multiple records" {
    const cp = testProvider();
    var server = Bridge.init(cp, .tls_aes_128_gcm_sha256);
    defer server.deinit();
    var client = Bridge.init(cp, .tls_aes_128_gcm_sha256);
    defer client.deinit();

    const hs = secret(0x71);
    const app = secret(0x72);
    try server.installTrafficSecret(.handshake, .read, &hs);
    try server.installTrafficSecret(.handshake, .write, &hs);
    try server.installTrafficSecret(.application, .read, &app);
    try server.installTrafficSecret(.application, .write, &app);
    try server.discardEpoch(.initial);
    try server.discardEpoch(.handshake);
    try server.markHandshakeComplete();

    try client.installTrafficSecret(.handshake, .read, &hs);
    try client.installTrafficSecret(.handshake, .write, &hs);
    try client.installTrafficSecret(.application, .read, &app);
    try client.installTrafficSecret(.application, .write, &app);
    try client.discardEpoch(.initial);
    try client.discardEpoch(.handshake);
    try client.markHandshakeComplete();

    const payload = [_]u8{0xa5} ** (record_codec.max_plaintext_fragment_len + 33);
    var protected: [record_codec.max_ciphertext_record_len * 3]u8 = undefined;
    const records = try server.sealHandshake(.application, &payload, &protected);

    var parser = record_codec.Parser.init(.ciphertext);
    var sink = record_codec.RecordSink(4, record_codec.max_ciphertext_fragment_len * 4){};
    try parser.feed(records, &sink);
    try testing.expectEqual(@as(usize, 2), sink.len);

    var opened_buf: [record_codec.max_ciphertext_fragment_len]u8 = undefined;
    var reassembled: [payload.len]u8 = undefined;
    var offset: usize = 0;
    for (sink.items[0..sink.len]) |record| {
        const opened = try client.openHandshake(.application, record, &opened_buf);
        @memcpy(reassembled[offset..][0..opened.inner.content.len], opened.inner.content);
        offset += opened.inner.content.len;
    }
    try testing.expectEqual(payload.len, offset);
    try testing.expectEqualSlices(u8, &payload, &reassembled);
}

test "sealedHandshakeLen rejects a synthetic overflow-adjacent bytes_len at every installed epoch" {
    const cp = testProvider();
    var server = Bridge.init(cp, .tls_aes_128_gcm_sha256);
    defer server.deinit();

    const hs = secret(0x73);
    const app = secret(0x74);
    try server.installTrafficSecret(.handshake, .write, &hs);
    try testing.expectError(error.RecordTooLarge, server.sealedHandshakeLen(.handshake, std.math.maxInt(usize)));

    try server.installTrafficSecret(.handshake, .read, &hs);
    try server.installTrafficSecret(.application, .read, &app);
    try server.installTrafficSecret(.application, .write, &app);
    try server.discardEpoch(.initial);
    try server.discardEpoch(.handshake);
    try server.markHandshakeComplete();
    try testing.expectError(error.RecordTooLarge, server.sealedHandshakeLen(.application, std.math.maxInt(usize)));

    // A small, real length still computes correctly alongside the rejected
    // synthetic one, proving the checked helpers didn't just start
    // rejecting everything.
    try testing.expectEqual(
        @as(usize, 4 + record_codec.header_len + 1 + 16),
        try server.sealedHandshakeLen(.application, 4),
    );
}

test "record epoch bridge rejects early, duplicate, missing, and unsupported transitions" {
    const cp = testProvider();
    var bridge = Bridge.init(cp, .tls_aes_128_gcm_sha256);
    defer bridge.deinit();

    var protected: [record_codec.max_ciphertext_record_len]u8 = undefined;
    const hs = secret(0x51);
    const app = secret(0x52);

    try testing.expectError(error.MissingWriteKeys, bridge.sealHandshake(.handshake, "finished", &protected));
    try testing.expectError(error.HandshakeNotComplete, bridge.sealApplicationData("data", &protected));
    try testing.expectError(error.UnsupportedRecordEpoch, bridge.installTrafficSecret(.initial, .write, &hs));
    try testing.expectError(error.InvalidEpochTransition, bridge.installTrafficSecret(.application, .write, &app));
    try testing.expectError(error.EpochDiscardTooEarly, bridge.discardEpoch(.initial));
    try bridge.discardEpoch(.zero_rtt);

    try bridge.installTrafficSecret(.handshake, .write, &hs);
    try testing.expectError(error.InvalidEpochTransition, bridge.installTrafficSecret(.handshake, .write, &hs));
    try testing.expectError(error.InvalidEpochTransition, bridge.markHandshakeComplete());
    try testing.expectError(error.EpochDiscardTooEarly, bridge.discardEpoch(.handshake));

    try bridge.installTrafficSecret(.application, .write, &app);
    try testing.expectError(error.InvalidEpochTransition, bridge.markHandshakeComplete());
}

test "record epoch bridge opens zero-rtt application data and wipes keys at handshake completion" {
    const cp = testProvider();
    var client = Bridge.init(cp, .tls_aes_128_gcm_sha256);
    defer client.deinit();
    var server = Bridge.init(cp, .tls_aes_128_gcm_sha256);
    defer server.deinit();

    const early = secret(0x61);
    const hs = secret(0x62);
    const app = secret(0x63);
    try client.installTrafficSecret(.zero_rtt, .write, &early);
    try server.installTrafficSecret(.zero_rtt, .read, &early);

    var protected: [record_codec.max_ciphertext_record_len]u8 = undefined;
    var plaintext: [record_codec.max_ciphertext_fragment_len]u8 = undefined;
    const early_record_bytes = try client.sealProtected(.zero_rtt, .application_data, "GET / HTTP/1.1\r\n\r\n", &protected);
    const early_record = try parseSingleRecord(.ciphertext, early_record_bytes);
    const opened_early = try server.openProtected(.zero_rtt, early_record, &plaintext);
    try testing.expectEqual(events.EncryptionEpoch.zero_rtt, opened_early.epoch);
    try testing.expectEqualStrings("GET / HTTP/1.1\r\n\r\n", opened_early.inner.content);

    try server.installTrafficSecret(.handshake, .read, &hs);
    try server.installTrafficSecret(.handshake, .write, &hs);
    try server.installTrafficSecret(.application, .read, &app);
    try server.installTrafficSecret(.application, .write, &app);
    try server.discardEpoch(.initial);
    try server.discardEpoch(.handshake);
    try server.markHandshakeComplete();

    try testing.expect(!server.hasReadKeys(.zero_rtt));
    try testing.expect(!server.hasWriteKeys(.zero_rtt));
    try testing.expectError(error.UnsupportedRecordEpoch, server.openProtected(.zero_rtt, early_record, &plaintext));
}

test "#510 record epoch bridge protects EndOfEarlyData with zero-rtt keys" {
    const cp = testProvider();
    var client = Bridge.init(cp, .tls_aes_128_gcm_sha256);
    defer client.deinit();
    var server = Bridge.init(cp, .tls_aes_128_gcm_sha256);
    defer server.deinit();

    const early = secret(0x64);
    const hs = secret(0x65);
    try client.installTrafficSecret(.zero_rtt, .write, &early);
    try server.installTrafficSecret(.zero_rtt, .read, &early);
    try server.installTrafficSecret(.handshake, .read, &hs);

    var protected: [record_codec.max_ciphertext_record_len]u8 = undefined;
    var plaintext: [record_codec.max_ciphertext_fragment_len]u8 = undefined;
    const eom = [_]u8{ 5, 0, 0, 0 };
    const record_bytes = try client.sealHandshake(.zero_rtt, &eom, &protected);
    const record = try parseSingleRecord(.ciphertext, record_bytes);

    try testing.expectError(error.AuthenticationFailed, server.openHandshake(.handshake, record, &plaintext));
    const opened = try server.openHandshake(.zero_rtt, record, &plaintext);
    try testing.expectEqual(events.EncryptionEpoch.zero_rtt, opened.epoch);
    try testing.expectEqualSlices(u8, &eom, opened.inner.content);
}

test "record epoch bridge discards prior epoch keys and fails closed after discard" {
    const cp = testProvider();
    var bridge = Bridge.init(cp, .tls_aes_128_gcm_sha256);
    defer bridge.deinit();

    const hs_read = secret(0x61);
    const hs_write = secret(0x62);
    const app_read = secret(0x63);
    const app_write = secret(0x64);
    try bridge.installTrafficSecret(.handshake, .read, &hs_read);
    try bridge.installTrafficSecret(.handshake, .write, &hs_write);
    try testing.expect(bridge.hasReadKeys(.handshake));
    try testing.expect(bridge.hasWriteKeys(.handshake));

    // The handshake epoch cannot be discarded until both directions have
    // moved on to application keys.
    try testing.expectError(error.EpochDiscardTooEarly, bridge.discardEpoch(.handshake));

    try bridge.installTrafficSecret(.application, .read, &app_read);
    try bridge.installTrafficSecret(.application, .write, &app_write);

    try bridge.discardEpoch(.handshake);
    try testing.expect(!bridge.hasReadKeys(.handshake));
    try testing.expect(!bridge.hasWriteKeys(.handshake));
    try testing.expectError(error.EpochAlreadyDiscarded, bridge.discardEpoch(.handshake));

    var protected: [record_codec.max_ciphertext_record_len]u8 = undefined;
    try testing.expectError(error.MissingWriteKeys, bridge.sealHandshake(.handshake, "late finished", &protected));
    try testing.expectError(error.InvalidEpochTransition, bridge.installTrafficSecret(.handshake, .write, &hs_write));
    try testing.expectError(error.InvalidEpochTransition, bridge.installTrafficSecret(.application, .write, &hs_write));
}

test "record epoch bridge treats the initial epoch as a validated one-way transition" {
    const cp = testProvider();
    var bridge = Bridge.init(cp, .tls_aes_128_gcm_sha256);
    defer bridge.deinit();

    const hs = secret(0x65);
    try testing.expectError(error.EpochDiscardTooEarly, bridge.discardEpoch(.initial));

    try bridge.installTrafficSecret(.handshake, .read, &hs);
    try bridge.installTrafficSecret(.handshake, .write, &hs);
    try bridge.discardEpoch(.initial);
    try testing.expectError(error.EpochAlreadyDiscarded, bridge.discardEpoch(.initial));

    var protected: [record_codec.max_ciphertext_record_len]u8 = undefined;
    var plaintext: [record_codec.max_ciphertext_fragment_len]u8 = undefined;
    try testing.expectError(error.UnsupportedRecordEpoch, bridge.sealHandshake(.initial, "too late", &protected));
    try testing.expectError(error.UnsupportedRecordEpoch, bridge.openHandshake(.initial, .{
        .content_type = .handshake,
        .legacy_version = 0x0303,
        .payload = "late client hello",
    }, &plaintext));
}

test "record epoch bridge requires both the initial and handshake epochs to be discarded before completion" {
    const cp = testProvider();
    var bridge = Bridge.init(cp, .tls_aes_128_gcm_sha256);
    defer bridge.deinit();

    const hs = secret(0x66);
    const app = secret(0x67);
    try bridge.installTrafficSecret(.handshake, .read, &hs);
    try bridge.installTrafficSecret(.handshake, .write, &hs);
    try bridge.installTrafficSecret(.application, .read, &app);
    try bridge.installTrafficSecret(.application, .write, &app);

    // Neither the initial nor the handshake epoch has been discarded yet.
    try testing.expectError(error.InvalidEpochTransition, bridge.markHandshakeComplete());

    try bridge.discardEpoch(.initial);
    // Completion must still prove prior handshake keys were released, not
    // just that the initial epoch was: the handshake epoch's read/write
    // states are still live here.
    try testing.expect(bridge.hasReadKeys(.handshake));
    try testing.expect(bridge.hasWriteKeys(.handshake));
    try testing.expectError(error.InvalidEpochTransition, bridge.markHandshakeComplete());

    try bridge.discardEpoch(.handshake);
    try bridge.markHandshakeComplete();
}

test "record epoch bridge rejects early application discard before and after handshake completion" {
    const cp = testProvider();
    var bridge = Bridge.init(cp, .tls_aes_128_gcm_sha256);
    defer bridge.deinit();

    // A fresh bridge: no keys of any kind installed yet.
    try testing.expectError(error.EpochDiscardTooEarly, bridge.discardEpoch(.application));

    const hs = secret(0x69);
    const app = secret(0x6a);
    try bridge.installTrafficSecret(.handshake, .read, &hs);
    try bridge.installTrafficSecret(.handshake, .write, &hs);
    try bridge.installTrafficSecret(.application, .read, &app);
    try bridge.installTrafficSecret(.application, .write, &app);

    // Application keys are installed, but the handshake has not completed
    // (initial/handshake discard and markHandshakeComplete were never
    // called) -- discarding now would tear down live session state under
    // the guise of orderly teardown.
    try testing.expectError(error.EpochDiscardTooEarly, bridge.discardEpoch(.application));
    try testing.expect(bridge.hasReadKeys(.application));
    try testing.expect(bridge.hasWriteKeys(.application));

    try bridge.discardEpoch(.initial);
    try bridge.discardEpoch(.handshake);
    try bridge.markHandshakeComplete();

    try bridge.discardEpoch(.application);
    try testing.expect(!bridge.hasReadKeys(.application));
    try testing.expect(!bridge.hasWriteKeys(.application));
    try testing.expectError(error.EpochAlreadyDiscarded, bridge.discardEpoch(.application));
}

test "record epoch bridge deinit wipes secrets even when no epoch was ever discarded" {
    const cp = testProvider();
    var bridge = Bridge.init(cp, .tls_aes_128_gcm_sha256);

    const hs = secret(0x68);
    try bridge.installTrafficSecret(.handshake, .read, &hs);
    try bridge.installTrafficSecret(.handshake, .write, &hs);
    try testing.expect(bridge.hasReadKeys(.handshake));
    try testing.expect(bridge.hasWriteKeys(.handshake));

    bridge.deinit();
    try testing.expect(!bridge.hasReadKeys(.handshake));
    try testing.expect(!bridge.hasWriteKeys(.handshake));
}

test "record epoch bridge rejects wrong content at otherwise valid epochs" {
    const cp = testProvider();
    var client = Bridge.init(cp, .tls_aes_128_gcm_sha256);
    defer client.deinit();
    var server = Bridge.init(cp, .tls_aes_128_gcm_sha256);
    defer server.deinit();

    const client_app = secret(0x71);
    const server_app = secret(0x72);
    const client_hs = secret(0x73);
    const server_hs = secret(0x74);
    try client.installTrafficSecret(.handshake, .write, &client_hs);
    try client.installTrafficSecret(.handshake, .read, &server_hs);
    try server.installTrafficSecret(.handshake, .read, &client_hs);
    try server.installTrafficSecret(.handshake, .write, &server_hs);
    try client.installTrafficSecret(.application, .write, &client_app);
    try client.installTrafficSecret(.application, .read, &server_app);
    try server.installTrafficSecret(.application, .read, &client_app);
    try server.installTrafficSecret(.application, .write, &server_app);
    try client.discardEpoch(.initial);
    try server.discardEpoch(.initial);
    try client.discardEpoch(.handshake);
    try server.discardEpoch(.handshake);
    try client.markHandshakeComplete();
    try server.markHandshakeComplete();

    var protected: [record_codec.max_ciphertext_record_len]u8 = undefined;
    var plaintext: [record_codec.max_ciphertext_fragment_len]u8 = undefined;
    const record = try client.sealApplicationData("not handshake", &protected);
    const parsed = try parseSingleRecord(.ciphertext, record);
    try testing.expectError(error.UnexpectedRecordContent, server.openHandshake(.application, parsed, &plaintext));
}

test "record epoch bridge shuttles protocol-neutral driver events through records" {
    const DriverError = Error || error{ InvalidHandshakeState, TransportBufferOverflow };
    const T = transport.Contract(void, events.EncryptionEpoch, DriverError);
    const D = engine.Driver(T);

    const ScriptedBackend = struct {
        const Self = @This();

        role: tls_state.Role,
        client_hs: [32]u8 = secret(0x81),
        server_hs: [32]u8 = secret(0x82),
        client_app: [32]u8 = secret(0x83),
        server_app: [32]u8 = secret(0x84),

        fn backend(self: *Self) T.Backend {
            return .{ .ptr = self, .startFn = start, .receiveFn = receive };
        }

        fn start(ptr: *anyopaque, role: tls_state.Role, _: void, sink: *T.EventSink) DriverError!void {
            const self: *Self = @ptrCast(@alignCast(ptr));
            if (self.role != role) return error.InvalidEpochTransition;
            if (role == .client) try sink.emitHandshakeBytes(.initial, "client hello");
        }

        fn receive(ptr: *anyopaque, epoch: events.EncryptionEpoch, bytes: []const u8, sink: *T.EventSink) DriverError!void {
            const self: *Self = @ptrCast(@alignCast(ptr));
            switch (self.role) {
                .server => {
                    if (epoch == .initial and std.mem.eql(u8, bytes, "client hello")) {
                        try sink.emitHandshakeBytes(.initial, "server hello");
                        try sink.emitSecret(.handshake, .read, &self.client_hs);
                        try sink.emitSecret(.handshake, .write, &self.server_hs);
                        try sink.emitDiscardEpoch(.initial);
                        try sink.emitHandshakeBytes(.handshake, "server finished");
                    } else if (epoch == .handshake and std.mem.eql(u8, bytes, "client finished")) {
                        try sink.emitSecret(.application, .read, &self.client_app);
                        try sink.emitSecret(.application, .write, &self.server_app);
                        try sink.emitDiscardEpoch(.handshake);
                        try sink.emitHandshakeComplete();
                        try sink.emitHandshakeBytes(.application, "new session ticket");
                    } else {
                        return error.UnexpectedRecordContent;
                    }
                },
                .client => {
                    if (epoch == .initial and std.mem.eql(u8, bytes, "server hello")) {
                        try sink.emitSecret(.handshake, .write, &self.client_hs);
                        try sink.emitSecret(.handshake, .read, &self.server_hs);
                        try sink.emitDiscardEpoch(.initial);
                    } else if (epoch == .handshake and std.mem.eql(u8, bytes, "server finished")) {
                        try sink.emitSecret(.application, .write, &self.client_app);
                        try sink.emitSecret(.application, .read, &self.server_app);
                        // The client's own Finished message must be sealed with
                        // the handshake write key before that key is discarded.
                        try sink.emitHandshakeBytes(.handshake, "client finished");
                        try sink.emitDiscardEpoch(.handshake);
                        try sink.emitHandshakeComplete();
                    } else if (epoch == .application and std.mem.eql(u8, bytes, "new session ticket")) {
                        try sink.emitAlpn("h3");
                    } else {
                        return error.UnexpectedRecordContent;
                    }
                },
            }
        }
    };

    const Harness = struct {
        fn pump(
            sender_driver: *D,
            sender_bridge: *Bridge,
            receiver_driver: *D,
            receiver_bridge: *Bridge,
            sink: *T.EventSink,
        ) DriverError!void {
            var opened: [record_codec.max_ciphertext_fragment_len]u8 = undefined;

            // Sealing must happen in the sink's own order (an event later in
            // the same sink may discard the key a handshake-bytes event was
            // just sealed with). Delivering to the peer must not happen
            // inline: the peer's cascading response can require this side's
            // own later same-sink events -- notably `handshake_complete` --
            // to already be applied (a receiver cannot open a post-handshake
            // application-epoch message from a cascaded delivery before its
            // own handshake_complete has been applied). So seal in-line, in
            // order, but queue delivery/recursion for a second pass once the
            // whole sink is drained.
            const max_queued = 4;
            const QueuedMessage = struct {
                epoch: events.EncryptionEpoch,
                mode: record_codec.RecordMode,
                buf: [1024]u8 = undefined,
                len: usize,
            };
            var queued: [max_queued]QueuedMessage = undefined;
            var queued_len: usize = 0;

            for (sink.items[0..sink.len]) |event| {
                switch (event) {
                    .handshake_bytes => |handshake| {
                        std.debug.assert(queued_len < max_queued);
                        const slot = &queued[queued_len];
                        queued_len += 1;
                        slot.* = .{ .epoch = handshake.epoch, .mode = if (handshake.epoch == .initial) .plaintext else .ciphertext, .len = 0 };
                        const bytes = (try sender_bridge.applyEvent(.{ .handshake_bytes = .{ .epoch = handshake.epoch, .data = handshake.data } }, &slot.buf)).?;
                        slot.len = bytes.len;
                    },
                    .traffic_secret => |traffic_secret| {
                        var scratch: [1]u8 = undefined;
                        _ = try sender_bridge.applyEvent(.{ .traffic_secret = .{
                            .epoch = traffic_secret.epoch,
                            .direction = traffic_secret.direction,
                            .data = traffic_secret.data,
                        } }, &scratch);
                    },
                    .discard_epoch => |epoch| {
                        var scratch: [1]u8 = undefined;
                        _ = try sender_bridge.applyEvent(.{ .discard_epoch = epoch }, &scratch);
                    },
                    .handshake_complete => {
                        var scratch: [1]u8 = undefined;
                        _ = try sender_bridge.applyEvent(.handshake_complete, &scratch);
                        sender_driver.complete();
                    },
                    .negotiated_parameters => |params| {
                        var scratch: [1]u8 = undefined;
                        _ = try sender_bridge.applyEvent(.{ .negotiated_parameters = params }, &scratch);
                    },
                    .early_data_parameters => |params| {
                        var scratch: [1]u8 = undefined;
                        _ = try sender_bridge.applyEvent(.{ .early_data_parameters = params }, &scratch);
                    },
                    .key_update => |update| {
                        var scratch: [1]u8 = undefined;
                        _ = try sender_bridge.applyEvent(.{ .key_update = update }, &scratch);
                    },
                    .peer_transport_parameters,
                    .alpn,
                    .certificate,
                    // Whether/when to synthesize one is transport policy
                    // (#354); this harness only proves the contract can carry
                    // it, not that record mode acts on it yet.
                    .fatal_alert,
                    => {},
                }
            }

            for (queued[0..queued_len]) |msg| {
                const record = try parseSingleRecord(msg.mode, msg.buf[0..msg.len]);
                const message = try receiver_bridge.openHandshake(msg.epoch, record, &opened);
                const next = try receiver_driver.receive(message.epoch, message.inner.content);
                try pump(receiver_driver, receiver_bridge, sender_driver, sender_bridge, next);
            }
        }
    };

    const cp = testProvider();
    var client_backend = ScriptedBackend{ .role = .client };
    var server_backend = ScriptedBackend{ .role = .server };
    var client_driver = D.init(.client, client_backend.backend());
    var server_driver = D.init(.server, server_backend.backend());
    var client_bridge = Bridge.init(cp, .tls_aes_128_gcm_sha256);
    defer client_bridge.deinit();
    var server_bridge = Bridge.init(cp, .tls_aes_128_gcm_sha256);
    defer server_bridge.deinit();

    const initial = try client_driver.start({});
    try Harness.pump(&client_driver, &client_bridge, &server_driver, &server_bridge, initial);

    try testing.expect(client_driver.isComplete());
    try testing.expect(server_driver.isComplete());
    // The handshake epoch was discarded as part of completing (finding 5),
    // so its keys -- and the sequence counters that went with them -- are
    // gone on both sides.
    try testing.expect(!client_bridge.hasWriteKeys(.handshake));
    try testing.expect(!server_bridge.hasReadKeys(.handshake));
    try testing.expectEqual(@as(u64, 1), server_bridge.write_application.?.sequence);
    try testing.expectEqual(@as(u64, 1), client_bridge.read_application.?.sequence);
}

// -----------------------------------------------------------------------
// #493 epoch/key-lifecycle fuzz target. See docs/CRYPTO_FUZZ_CONTRACT.md's
// "#493" section for the shared rules this follows (fresh provider and
// bridge per case, fixed buffers, explicit operation bounds, typed-error
// classification, sanitized diagnostics).
// -----------------------------------------------------------------------

const fuzz_epoch_max_operations = 48;
const fuzz_epoch_content_len = 24;

const all_epochs = [_]events.EncryptionEpoch{ .initial, .zero_rtt, .handshake, .application };
const all_suites = [_]algorithms.CipherSuite{
    .tls_aes_128_gcm_sha256,
    .tls_aes_256_gcm_sha384,
    .tls_chacha20_poly1305_sha256,
};

fn epochIndex(epoch: events.EncryptionEpoch) usize {
    return switch (epoch) {
        .initial => 0,
        .zero_rtt => 1,
        .handshake => 2,
        .application => 3,
    };
}

/// The traffic secret this target always uses for `epoch`, so a read slot and
/// a write slot installed for the same epoch under the same suite hold
/// byte-identical key material. That makes "does this record authenticate?"
/// a function of the model's tracked suite and sequence alone, rather than of
/// key bytes the model would otherwise have to reproduce.
fn fuzzEpochSecret(epoch: events.EncryptionEpoch, len: usize, out: []u8) []const u8 {
    const tag: u8 = 0x40 +% @as(u8, @intCast(epochIndex(epoch)));
    for (out[0..len], 0..) |*byte, i| byte.* = tag ^ @as(u8, @truncate(i));
    return out[0..len];
}

/// The externally observable state of a `Bridge`: direction phases, the
/// discard/completion flags, the negotiated suite, and -- for each of the six
/// key slots -- whether a key is installed and, if so, its sequence counter.
/// Folding presence and sequence into one optional means a comparison catches
/// both a key that should have been wiped and a sequence that advanced when
/// it should not have.
const BridgeSnapshot = struct {
    cipher_suite: algorithms.CipherSuite,
    read_phase: DirectionPhase,
    write_phase: DirectionPhase,
    read_handshake: ?u64,
    write_handshake: ?u64,
    read_zero_rtt: ?u64,
    write_zero_rtt: ?u64,
    read_application: ?u64,
    write_application: ?u64,
    initial_discarded: bool,
    handshake_discarded: bool,
    application_discarded: bool,
    handshake_complete: bool,
    torn_down: bool,
};

fn bridgeSnapshot(bridge: *const Bridge) !BridgeSnapshot {
    const snapshot = BridgeSnapshot{
        .cipher_suite = bridge.cipher_suite,
        .read_phase = bridge.read_phase,
        .write_phase = bridge.write_phase,
        .read_handshake = if (bridge.read_handshake) |state| state.sequence else null,
        .write_handshake = if (bridge.write_handshake) |state| state.sequence else null,
        .read_zero_rtt = if (bridge.read_zero_rtt) |state| state.sequence else null,
        .write_zero_rtt = if (bridge.write_zero_rtt) |state| state.sequence else null,
        .read_application = if (bridge.read_application) |state| state.sequence else null,
        .write_application = if (bridge.write_application) |state| state.sequence else null,
        .initial_discarded = bridge.initial_discarded,
        .handshake_discarded = bridge.handshake_discarded,
        .application_discarded = bridge.application_discarded,
        .handshake_complete = bridge.handshake_complete,
        .torn_down = bridge.torn_down,
    };
    // The public key-presence predicates must agree with the private slots
    // they report on, at every point in the program.
    try testing.expectEqual(snapshot.read_handshake != null, bridge.hasReadKeys(.handshake));
    try testing.expectEqual(snapshot.write_handshake != null, bridge.hasWriteKeys(.handshake));
    try testing.expectEqual(snapshot.read_zero_rtt != null, bridge.hasReadKeys(.zero_rtt));
    try testing.expectEqual(snapshot.write_zero_rtt != null, bridge.hasWriteKeys(.zero_rtt));
    try testing.expectEqual(snapshot.read_application != null, bridge.hasReadKeys(.application));
    try testing.expectEqual(snapshot.write_application != null, bridge.hasWriteKeys(.application));
    // The initial epoch never has record-protection keys of its own.
    try testing.expect(!bridge.hasReadKeys(.initial));
    try testing.expect(!bridge.hasWriteKeys(.initial));
    return snapshot;
}

fn expectSnapshotEqual(expected: BridgeSnapshot, actual: BridgeSnapshot) !void {
    try testing.expectEqual(expected.cipher_suite, actual.cipher_suite);
    try testing.expectEqual(expected.read_phase, actual.read_phase);
    try testing.expectEqual(expected.write_phase, actual.write_phase);
    try testing.expectEqual(expected.read_handshake, actual.read_handshake);
    try testing.expectEqual(expected.write_handshake, actual.write_handshake);
    try testing.expectEqual(expected.read_zero_rtt, actual.read_zero_rtt);
    try testing.expectEqual(expected.write_zero_rtt, actual.write_zero_rtt);
    try testing.expectEqual(expected.read_application, actual.read_application);
    try testing.expectEqual(expected.write_application, actual.write_application);
    try testing.expectEqual(expected.initial_discarded, actual.initial_discarded);
    try testing.expectEqual(expected.handshake_discarded, actual.handshake_discarded);
    try testing.expectEqual(expected.application_discarded, actual.application_discarded);
    try testing.expectEqual(expected.handshake_complete, actual.handshake_complete);
    try testing.expectEqual(expected.torn_down, actual.torn_down);
}

/// A compact reference model of the epoch lifecycle, written directly from
/// the documented transition rules rather than from the `Bridge` code, so a
/// rule the implementation silently relaxes shows up as a disagreement.
///
/// Per slot it tracks the suite the key was installed under (which decides
/// whether a sealed record can authenticate against it) and the sequence
/// counter, in addition to mere presence.
const EpochModel = struct {
    cipher_suite: algorithms.CipherSuite,
    read_phase: DirectionPhase = .initial,
    write_phase: DirectionPhase = .initial,
    read_suite: [4]?algorithms.CipherSuite = .{null} ** 4,
    write_suite: [4]?algorithms.CipherSuite = .{null} ** 4,
    read_sequence: [4]u64 = .{0} ** 4,
    write_sequence: [4]u64 = .{0} ** 4,
    initial_discarded: bool = false,
    handshake_discarded: bool = false,
    application_discarded: bool = false,
    handshake_complete: bool = false,
    /// Stated here as an independent rule of the lifecycle -- "a session that
    /// has been torn down, by either path, never acquires key material
    /// again" -- rather than being re-derived from whichever gates the
    /// `Bridge` happens to implement. Deriving it from the per-epoch discard
    /// and completion flags is exactly how this model twice came to bless a
    /// 0-RTT resurrection instead of detecting it (#493-B review): first for
    /// `deinit`, then for orderly `discardEpoch(.application)`. Both reset
    /// `handshake_complete`, which was the 0-RTT install path's only gate,
    /// and a model that mirrors that expression agrees with the bug.
    torn_down: bool = false,

    fn snapshot(self: *const EpochModel) BridgeSnapshot {
        return .{
            .cipher_suite = self.cipher_suite,
            .read_phase = self.read_phase,
            .write_phase = self.write_phase,
            .read_handshake = self.slotSequence(.read, .handshake),
            .write_handshake = self.slotSequence(.write, .handshake),
            .read_zero_rtt = self.slotSequence(.read, .zero_rtt),
            .write_zero_rtt = self.slotSequence(.write, .zero_rtt),
            .read_application = self.slotSequence(.read, .application),
            .write_application = self.slotSequence(.write, .application),
            .initial_discarded = self.initial_discarded,
            .handshake_discarded = self.handshake_discarded,
            .application_discarded = self.application_discarded,
            .handshake_complete = self.handshake_complete,
            .torn_down = self.torn_down,
        };
    }

    fn slotSequence(self: *const EpochModel, direction: events.SecretDirection, epoch: events.EncryptionEpoch) ?u64 {
        const idx = epochIndex(epoch);
        const suite = if (direction == .read) self.read_suite[idx] else self.write_suite[idx];
        if (suite == null) return null;
        return if (direction == .read) self.read_sequence[idx] else self.write_sequence[idx];
    }

    fn clearSlots(self: *EpochModel, epoch: events.EncryptionEpoch) void {
        const idx = epochIndex(epoch);
        self.read_suite[idx] = null;
        self.write_suite[idx] = null;
        self.read_sequence[idx] = 0;
        self.write_sequence[idx] = 0;
    }

    fn secretLen(self: *const EpochModel) usize {
        return record_protection.suiteProfile(self.cipher_suite).hash.digestLength();
    }

    fn predictInstall(
        self: *const EpochModel,
        epoch: events.EncryptionEpoch,
        direction: events.SecretDirection,
        secret_len: usize,
    ) ?Error {
        // Terminal teardown outranks every per-epoch rule below. Stated
        // independently, so a bridge that reopens *any* epoch after `deinit`
        // is a disagreement rather than a match.
        if (self.torn_down) return error.InvalidEpochTransition;
        switch (epoch) {
            // The initial epoch is plaintext-only; it has no traffic secret.
            .initial => return error.UnsupportedRecordEpoch,
            .handshake => {
                const phase = if (direction == .read) self.read_phase else self.write_phase;
                if (phase != .initial or self.handshake_discarded) return error.InvalidEpochTransition;
            },
            .application => {
                const phase = if (direction == .read) self.read_phase else self.write_phase;
                if (phase != .handshake or self.handshake_discarded or self.application_discarded) {
                    return error.InvalidEpochTransition;
                }
            },
            .zero_rtt => {
                if (self.handshake_complete) return error.InvalidEpochTransition;
            },
        }
        const idx = epochIndex(epoch);
        const slot = if (direction == .read) self.read_suite[idx] else self.write_suite[idx];
        // Duplicate detection happens before key derivation, so a duplicate
        // install is reported as such even when its length is also wrong.
        if (slot != null) return error.DuplicateTrafficSecret;
        if (secret_len != self.secretLen()) return error.InvalidTrafficSecretLength;
        return null;
    }

    fn applyInstall(self: *EpochModel, epoch: events.EncryptionEpoch, direction: events.SecretDirection) void {
        const idx = epochIndex(epoch);
        if (direction == .read) {
            self.read_suite[idx] = self.cipher_suite;
            self.read_sequence[idx] = 0;
        } else {
            self.write_suite[idx] = self.cipher_suite;
            self.write_sequence[idx] = 0;
        }
        switch (epoch) {
            .handshake => if (direction == .read) {
                self.read_phase = .handshake;
            } else {
                self.write_phase = .handshake;
            },
            .application => if (direction == .read) {
                self.read_phase = .application;
            } else {
                self.write_phase = .application;
            },
            // 0-RTT keys live alongside the phase progression rather than
            // advancing it.
            .zero_rtt, .initial => {},
        }
    }

    fn predictDiscard(self: *const EpochModel, epoch: events.EncryptionEpoch) ?Error {
        return switch (epoch) {
            .initial => if (self.initial_discarded)
                error.EpochAlreadyDiscarded
            else if (self.read_phase == .initial or self.write_phase == .initial)
                error.EpochDiscardTooEarly
            else
                null,
            .handshake => if (self.handshake_discarded)
                error.EpochAlreadyDiscarded
            else if (self.read_phase != .application or self.write_phase != .application)
                error.EpochDiscardTooEarly
            else
                null,
            .application => if (self.application_discarded)
                error.EpochAlreadyDiscarded
            else if (!self.handshake_complete or self.read_phase != .complete or self.write_phase != .complete)
                error.EpochDiscardTooEarly
            else
                null,
            // 0-RTT discard is idempotent by contract: it is emitted whenever
            // early data ends, including when no early keys ever existed.
            .zero_rtt => null,
        };
    }

    fn applyDiscard(self: *EpochModel, epoch: events.EncryptionEpoch) void {
        switch (epoch) {
            .initial => self.initial_discarded = true,
            .handshake => {
                self.clearSlots(.handshake);
                self.handshake_discarded = true;
            },
            .application => {
                self.clearSlots(.application);
                self.application_discarded = true;
                self.read_phase = .initial;
                self.write_phase = .initial;
                self.handshake_complete = false;
                // Orderly session teardown, so the same terminal rule
                // applies as for `deinit` -- stated here, not inherited from
                // the flags this branch happens to reset.
                self.torn_down = true;
            },
            // 0-RTT discard is epoch-scoped, not session teardown: it is
            // emitted whenever early data ends, including mid-handshake and
            // when no early keys ever existed, so it must not be terminal.
            .zero_rtt => self.clearSlots(.zero_rtt),
        }
    }

    fn predictComplete(self: *const EpochModel) ?Error {
        if (self.handshake_complete) return error.InvalidEpochTransition;
        if (!self.initial_discarded or !self.handshake_discarded) return error.InvalidEpochTransition;
        if (self.read_phase != .application or self.write_phase != .application) return error.InvalidEpochTransition;
        const idx = epochIndex(.application);
        if (self.read_suite[idx] == null or self.write_suite[idx] == null) return error.MissingApplicationKeys;
        return null;
    }

    fn applyComplete(self: *EpochModel) void {
        self.clearSlots(.zero_rtt);
        self.handshake_complete = true;
        self.read_phase = .complete;
        self.write_phase = .complete;
    }

    fn applyTeardown(self: *EpochModel) void {
        self.clearSlots(.zero_rtt);
        self.clearSlots(.handshake);
        self.clearSlots(.application);
        self.initial_discarded = true;
        self.handshake_discarded = true;
        self.application_discarded = true;
        self.handshake_complete = false;
        self.torn_down = true;
        // `deinit` deliberately does not rewind the direction phases: it is
        // teardown, not a transition back to a usable earlier state.
    }

    /// The gate `sealProtected` applies before it reaches a write state, for
    /// a `handshake` content type.
    fn predictSealGate(self: *const EpochModel, epoch: events.EncryptionEpoch) ?Error {
        const idx = epochIndex(epoch);
        return switch (epoch) {
            .initial => if (self.initial_discarded) error.UnsupportedRecordEpoch else null,
            .handshake => if (self.write_suite[idx] == null) error.MissingWriteKeys else null,
            .application => if (!self.handshake_complete)
                error.HandshakeNotComplete
            else if (self.write_suite[idx] == null)
                error.MissingWriteKeys
            else
                null,
            .zero_rtt => if (self.handshake_complete)
                error.UnsupportedRecordEpoch
            else if (self.write_suite[idx] == null)
                error.MissingWriteKeys
            else
                null,
        };
    }

    /// Everything `openProtected` rejects before the AEAD runs: the bridge's
    /// own epoch gate, and then -- for a protected epoch -- `ReadState.open`'s
    /// header preflight in its documented order. A plaintext initial-epoch
    /// record replayed at a protected epoch is refused as `InvalidRecordType`
    /// by that preflight, never treated as a candidate ciphertext.
    fn predictOpenGate(self: *const EpochModel, epoch: events.EncryptionEpoch, record: record_codec.Record) ?Error {
        const idx = epochIndex(epoch);
        switch (epoch) {
            .initial => {
                if (self.initial_discarded) return error.UnsupportedRecordEpoch;
                if (record.content_type != .handshake) return error.UnexpectedRecordContent;
                return null;
            },
            .handshake => if (self.read_suite[idx] == null) return error.MissingReadKeys,
            .application => {
                if (!self.handshake_complete) return error.HandshakeNotComplete;
                if (self.read_suite[idx] == null) return error.MissingReadKeys;
            },
            .zero_rtt => {
                if (self.handshake_complete) return error.UnsupportedRecordEpoch;
                if (self.read_suite[idx] == null) return error.MissingReadKeys;
            },
        }
        if (record.content_type != .application_data) return error.InvalidRecordType;
        if (record.legacy_version != record_codec.legacy_record_version) return error.InvalidRecordVersion;
        if (record.payload.len > record_codec.max_ciphertext_fragment_len) return error.RecordTooLarge;
        const tag_len = record_protection.suiteProfile(self.read_suite[idx].?).aead.tagLength();
        if (record.payload.len < tag_len) return error.MalformedInnerPlaintext;
        return null;
    }
};

/// The most recently sealed record, and everything the model needs to decide
/// whether re-opening it can authenticate.
const LastRecord = struct {
    bytes: [record_codec.max_ciphertext_record_len]u8 = undefined,
    len: usize = 0,
    /// `null` until this case has sealed anything: the synthetic placeholder
    /// record can never authenticate at any epoch.
    epoch: ?events.EncryptionEpoch = null,
    suite: algorithms.CipherSuite = .tls_aes_128_gcm_sha256,
    sequence: u64 = 0,
    content: [fuzz_epoch_content_len]u8 = undefined,
};

test "fuzz: TLS record: epoch operation sequences preserve one-way key lifecycle" {
    try testing.fuzz({}, fuzzEpochOperationsInput, .{
        .corpus = &.{
            "",
            &[_]u8{0},
            // The #408 transition classes, as operation-selector prefixes:
            // early discard, duplicate discard, missing direction,
            // application install before handshake, partial completion,
            // abandoned handshake, full progression, and teardown at each
            // boundary. The generator's own bounds keep every one of these
            // inside `fuzz_epoch_max_operations`.
            &[_]u8{ 1, 0, 1, 2, 1, 3 },
            &[_]u8{ 0, 2, 0, 0, 0, 2, 1, 0 },
            &[_]u8{ 0, 3, 0, 0, 0, 3, 1, 0, 2 },
            &[_]u8{ 0, 2, 0, 0, 0, 2, 1, 0, 1, 2, 0, 3, 0, 0, 0, 3, 1, 0, 1, 2, 2 },
            &[_]u8{ 6, 0, 2, 0, 0, 6, 1, 0 },
            &[_]u8{ 4, 0, 4, 2, 4, 3, 5, 0, 5, 2, 5, 3 },
            &[_]u8{ 3, 0, 3, 1, 3, 2, 3, 3 },
            &([_]u8{0} ** 64),
            &([_]u8{0xff} ** 64),
            &([_]u8{ 0, 1, 2, 3, 4, 5, 6 } ** 8),
        },
    });
}

fn fuzzEpochOperationsInput(_: void, smith: *std.testing.Smith) !void {
    const pure_zig = crypto.pure_zig;
    // Fresh provider per case, per the #493 shared rules -- not this module's
    // process-wide `testProvider()` singleton.
    var entropy = pure_zig.DeterministicEntropy.init(0x493c);
    var provider_state = pure_zig.Provider.init(entropy.entropy());
    const cp = provider_state.cryptoProvider();

    const initial_suite = all_suites[smith.index(all_suites.len)];
    var bridge = Bridge.init(cp, initial_suite);
    defer bridge.deinit();
    var model = EpochModel{ .cipher_suite = initial_suite };
    try expectSnapshotEqual(model.snapshot(), try bridgeSnapshot(&bridge));

    var last = LastRecord{};
    var out_buf: [record_codec.max_ciphertext_record_len]u8 = undefined;
    var opened_buf: [record_codec.max_ciphertext_fragment_len]u8 = undefined;
    var secret_buf: [provider.max_digest_len + 1]u8 = undefined;
    var scratch: [1]u8 = undefined;

    const operations = smith.index(fuzz_epoch_max_operations + 1);
    for (0..operations) |_| {
        switch (smith.index(7)) {
            // Install a traffic secret. The length comes from a matrix around
            // the current suite's digest length, so a wrong-length install is
            // a first-class operation rather than an afterthought.
            0 => {
                const epoch = all_epochs[smith.index(all_epochs.len)];
                const direction: events.SecretDirection = if (smith.index(2) == 0) .read else .write;
                const exact = model.secretLen();
                const secret_len = switch (smith.index(4)) {
                    0 => exact - 1,
                    1 => exact + 1,
                    else => exact,
                };
                const traffic_secret = fuzzEpochSecret(epoch, secret_len, &secret_buf);

                const predicted = model.predictInstall(epoch, direction, secret_len);
                const result = bridge.applyEvent(.{ .traffic_secret = .{
                    .epoch = epoch,
                    .direction = direction,
                    .data = traffic_secret,
                } }, &scratch);
                if (predicted) |expected| {
                    try testing.expectError(expected, result);
                } else {
                    try testing.expectEqual(@as(?[]const u8, null), try result);
                    model.applyInstall(epoch, direction);
                }
            },
            // Discard an epoch.
            1 => {
                const epoch = all_epochs[smith.index(all_epochs.len)];
                const predicted = model.predictDiscard(epoch);
                const result = bridge.applyEvent(.{ .discard_epoch = epoch }, &scratch);
                if (predicted) |expected| {
                    try testing.expectError(expected, result);
                } else {
                    try testing.expectEqual(@as(?[]const u8, null), try result);
                    model.applyDiscard(epoch);
                }
            },
            // Mark the handshake complete.
            2 => {
                const predicted = model.predictComplete();
                const result = bridge.applyEvent(.handshake_complete, &scratch);
                if (predicted) |expected| {
                    try testing.expectError(expected, result);
                } else {
                    try testing.expectEqual(@as(?[]const u8, null), try result);
                    model.applyComplete();
                }
            },
            // Update the negotiated suite, including unknown code points,
            // which must be refused without disturbing the current suite.
            3 => {
                const known = smith.index(4) != 0;
                var raw: [2]u8 = undefined;
                smith.bytes(&raw);
                const chosen = all_suites[smith.index(all_suites.len)];
                var wire = std.mem.readInt(u16, &raw, .big);
                if (known) {
                    wire = @intFromEnum(chosen);
                } else if (algorithms.fromInt(algorithms.CipherSuite, wire) != null) {
                    wire = 0x1300;
                }
                const params = events.NegotiatedParameters{
                    .cipher_suite = wire,
                    .transcript_hash = if (smith.index(2) == 0) .sha256 else .sha384,
                };
                const event: events.Event = if (smith.index(2) == 0)
                    .{ .negotiated_parameters = params }
                else
                    .{ .early_data_parameters = params };
                const result = bridge.applyEvent(event, &scratch);
                if (algorithms.fromInt(algorithms.CipherSuite, wire)) |suite| {
                    try testing.expectEqual(@as(?[]const u8, null), try result);
                    model.cipher_suite = suite;
                } else {
                    try testing.expectError(error.UnsupportedRecordEpoch, result);
                }
            },
            // Seal a handshake record at a chosen epoch.
            4 => {
                const epoch = all_epochs[smith.index(all_epochs.len)];
                var content: [fuzz_epoch_content_len]u8 = undefined;
                smith.bytes(&content);
                const predicted = model.predictSealGate(epoch);
                const result = bridge.sealProtected(epoch, .handshake, &content, &out_buf);
                if (predicted) |expected| {
                    try testing.expectError(expected, result);
                } else {
                    const record = try result;
                    const idx = epochIndex(epoch);
                    last.len = record.len;
                    @memcpy(last.bytes[0..record.len], record);
                    last.epoch = epoch;
                    last.content = content;
                    if (epoch != .initial) {
                        last.suite = model.write_suite[idx].?;
                        last.sequence = model.write_sequence[idx];
                        model.write_sequence[idx] += 1;
                    }
                }
            },
            // Open the most recently sealed record at a chosen epoch. The
            // model predicts not just the gate but whether the record can
            // authenticate at all, so a bridge that opened a record under the
            // wrong epoch's keys would be caught here.
            5 => {
                const epoch = all_epochs[smith.index(all_epochs.len)];
                const record = if (last.epoch) |sealed_at|
                    try parseSingleRecord(
                        if (sealed_at == .initial) .plaintext else .ciphertext,
                        last.bytes[0..last.len],
                    )
                else
                    record_codec.Record{
                        .content_type = .application_data,
                        .legacy_version = record_codec.legacy_record_version,
                        .payload = &[_]u8{0} ** 32,
                    };
                const idx = epochIndex(epoch);
                const result = bridge.openProtected(epoch, record, &opened_buf);
                if (model.predictOpenGate(epoch, record)) |expected| {
                    try testing.expectError(expected, result);
                } else if (last.epoch != null and last.epoch.? == epoch and
                    (epoch == .initial or (model.read_suite[idx].? == last.suite and
                        model.read_sequence[idx] == last.sequence)))
                {
                    const opened = try result;
                    try testing.expectEqual(epoch, opened.epoch);
                    try testing.expectEqual(record_codec.ContentType.handshake, opened.inner.content_type);
                    try testing.expectEqualSlices(u8, &last.content, opened.inner.content);
                    if (epoch != .initial) model.read_sequence[idx] += 1;
                } else {
                    // Wrong epoch, wrong suite, or a read sequence that has
                    // moved on: the record must fail closed, and -- asserted
                    // by the snapshot comparison below -- must not consume a
                    // read sequence number, or a later legitimate record
                    // would become unopenable.
                    try testing.expectError(error.AuthenticationFailed, result);
                }
            },
            // Teardown at an arbitrary point in the program, followed by
            // continued operation: every later step must see wiped keys and
            // terminal discard flags.
            else => {
                bridge.deinit();
                model.applyTeardown();
            },
        }

        try expectSnapshotEqual(model.snapshot(), try bridgeSnapshot(&bridge));
    }

    // Final teardown always clears every key slot regardless of how far the
    // program progressed, including from an abandoned handshake.
    bridge.deinit();
    model.applyTeardown();
    try expectSnapshotEqual(model.snapshot(), try bridgeSnapshot(&bridge));
}

// A single scripted full progression, pinned deterministically so CI's seed
// replay always exercises the accepting path of every transition rule the
// fuzz target's model encodes -- the generated programs reach the deepest
// states (completion, orderly application discard, post-teardown operation)
// only when their random operation order happens to line up.
test "the epoch lifecycle model agrees with a scripted full progression through teardown" {
    const cp = testProvider();
    var bridge = Bridge.init(cp, .tls_aes_128_gcm_sha256);
    defer bridge.deinit();
    var model = EpochModel{ .cipher_suite = .tls_aes_128_gcm_sha256 };
    var secret_buf: [provider.max_digest_len + 1]u8 = undefined;
    var scratch: [1]u8 = undefined;

    const Step = struct {
        fn install(
            b: *Bridge,
            m: *EpochModel,
            buf: []u8,
            sc: []u8,
            epoch: events.EncryptionEpoch,
            direction: events.SecretDirection,
            len: usize,
        ) !void {
            const data = fuzzEpochSecret(epoch, len, buf);
            const predicted = m.predictInstall(epoch, direction, len);
            const result = b.applyEvent(.{ .traffic_secret = .{ .epoch = epoch, .direction = direction, .data = data } }, sc);
            if (predicted) |expected| {
                try testing.expectError(expected, result);
            } else {
                _ = try result;
                m.applyInstall(epoch, direction);
            }
            try expectSnapshotEqual(m.snapshot(), try bridgeSnapshot(b));
        }

        fn discard(b: *Bridge, m: *EpochModel, sc: []u8, epoch: events.EncryptionEpoch) !void {
            const predicted = m.predictDiscard(epoch);
            const result = b.applyEvent(.{ .discard_epoch = epoch }, sc);
            if (predicted) |expected| {
                try testing.expectError(expected, result);
            } else {
                _ = try result;
                m.applyDiscard(epoch);
            }
            try expectSnapshotEqual(m.snapshot(), try bridgeSnapshot(b));
        }

        fn complete(b: *Bridge, m: *EpochModel, sc: []u8) !void {
            const predicted = m.predictComplete();
            const result = b.applyEvent(.handshake_complete, sc);
            if (predicted) |expected| {
                try testing.expectError(expected, result);
            } else {
                _ = try result;
                m.applyComplete();
            }
            try expectSnapshotEqual(m.snapshot(), try bridgeSnapshot(b));
        }
    };

    const hash_len = record_protection.suiteProfile(.tls_aes_128_gcm_sha256).hash.digestLength();

    // Early/duplicate/wrong-length/missing-direction rejections.
    try Step.discard(&bridge, &model, &scratch, .initial);
    try Step.complete(&bridge, &model, &scratch);
    try Step.install(&bridge, &model, &secret_buf, &scratch, .initial, .write, hash_len);
    try Step.install(&bridge, &model, &secret_buf, &scratch, .application, .write, hash_len);
    try Step.install(&bridge, &model, &secret_buf, &scratch, .handshake, .write, hash_len - 1);

    // 0-RTT keys, then the full progression.
    try Step.install(&bridge, &model, &secret_buf, &scratch, .zero_rtt, .write, hash_len);
    try Step.install(&bridge, &model, &secret_buf, &scratch, .zero_rtt, .write, hash_len);
    try Step.install(&bridge, &model, &secret_buf, &scratch, .handshake, .read, hash_len);
    try Step.install(&bridge, &model, &secret_buf, &scratch, .handshake, .write, hash_len);
    try Step.discard(&bridge, &model, &scratch, .handshake);
    try Step.discard(&bridge, &model, &scratch, .initial);
    try Step.discard(&bridge, &model, &scratch, .initial);
    try Step.install(&bridge, &model, &secret_buf, &scratch, .application, .read, hash_len);
    try Step.complete(&bridge, &model, &scratch);
    try Step.install(&bridge, &model, &secret_buf, &scratch, .application, .write, hash_len);
    try Step.discard(&bridge, &model, &scratch, .handshake);
    try Step.complete(&bridge, &model, &scratch);
    // Completion wipes any surviving 0-RTT keys.
    try testing.expect(!bridge.hasWriteKeys(.zero_rtt));

    // Orderly application discard, then teardown after a completed session.
    try Step.discard(&bridge, &model, &scratch, .application);
    try Step.discard(&bridge, &model, &scratch, .application);

    // The window *between* orderly application discard and `deinit`: that
    // discard is session teardown too, and it resets `handshake_complete`,
    // so it is the second place the 0-RTT install gate could reopen
    // (#493-B review). Exercised here, before any `deinit`, so removing
    // either the production or the model's terminal rule for this branch is
    // mutation-detectable independently of the `deinit` path below.
    try Step.install(&bridge, &model, &secret_buf, &scratch, .zero_rtt, .read, hash_len);
    try Step.install(&bridge, &model, &secret_buf, &scratch, .zero_rtt, .write, hash_len);
    try testing.expect(!bridge.hasReadKeys(.zero_rtt));
    try testing.expect(!bridge.hasWriteKeys(.zero_rtt));

    bridge.deinit();
    model.applyTeardown();
    try expectSnapshotEqual(model.snapshot(), try bridgeSnapshot(&bridge));

    // Post-teardown operations stay terminal: nothing can revive the bridge.
    // 0-RTT is checked in *both* directions specifically because it is the
    // epoch whose ordinary gate (`handshake_complete`) `deinit` reopens, so
    // it is the one that could actually come back (#493-B review). Keeping
    // it here means mutation validation covers the oracle too: a model that
    // regressed to mirroring the implementation's gates would stop
    // predicting these rejections.
    try Step.install(&bridge, &model, &secret_buf, &scratch, .zero_rtt, .read, hash_len);
    try Step.install(&bridge, &model, &secret_buf, &scratch, .zero_rtt, .write, hash_len);
    try Step.install(&bridge, &model, &secret_buf, &scratch, .handshake, .read, hash_len);
    try Step.install(&bridge, &model, &secret_buf, &scratch, .application, .write, hash_len);
    try Step.discard(&bridge, &model, &scratch, .handshake);
    try Step.complete(&bridge, &model, &scratch);
}

test "record epoch bridge cannot reinstall zero-rtt keys after orderly application discard" {
    const cp = testProvider();
    var bridge = Bridge.init(cp, .tls_aes_128_gcm_sha256);
    defer bridge.deinit();

    const hs = secret(0xa1);
    const app = secret(0xa2);
    const early = secret(0xa3);

    try bridge.installTrafficSecret(.handshake, .read, &hs);
    try bridge.installTrafficSecret(.handshake, .write, &hs);
    try bridge.installTrafficSecret(.application, .read, &app);
    try bridge.installTrafficSecret(.application, .write, &app);
    try bridge.discardEpoch(.initial);
    try bridge.discardEpoch(.handshake);
    try bridge.markHandshakeComplete();

    // Orderly teardown of a completed session -- `discardEpoch`'s own
    // documentation calls this session teardown. It resets
    // `handshake_complete`, which was the 0-RTT install path's only gate, so
    // before the terminal rule covered this branch a finished session could
    // acquire fresh early-data keys here and resume record traffic. This is
    // the window *before* any `deinit` call.
    try bridge.discardEpoch(.application);

    try testing.expectError(
        error.InvalidEpochTransition,
        bridge.installTrafficSecret(.zero_rtt, .read, &early),
    );
    try testing.expectError(
        error.InvalidEpochTransition,
        bridge.installTrafficSecret(.zero_rtt, .write, &early),
    );
    try testing.expect(!bridge.hasReadKeys(.zero_rtt));
    try testing.expect(!bridge.hasWriteKeys(.zero_rtt));

    // No key material is obtainable, so the epoch stays unusable rather than
    // merely un-keyed -- and so do the epochs whose own keys this discard
    // wiped.
    var protected: [record_codec.max_ciphertext_record_len]u8 = undefined;
    try testing.expectError(
        error.MissingWriteKeys,
        bridge.sealProtected(.zero_rtt, .application_data, "post-teardown", &protected),
    );
    try testing.expectError(
        error.HandshakeNotComplete,
        bridge.sealApplicationData("post-teardown", &protected),
    );
    try testing.expectError(
        error.InvalidEpochTransition,
        bridge.installTrafficSecret(.handshake, .read, &hs),
    );
    try testing.expectError(
        error.InvalidEpochTransition,
        bridge.installTrafficSecret(.application, .write, &app),
    );

    // A 0-RTT *discard* stays legal and non-terminal by contract, so it must
    // not have been swept up by the terminal rule.
    try bridge.discardEpoch(.zero_rtt);
}

test "record epoch bridge cannot reinstall zero-rtt keys after teardown" {
    const cp = testProvider();
    var bridge = Bridge.init(cp, .tls_aes_128_gcm_sha256);
    const early = secret(0x91);

    // Teardown from a fresh bridge is the worst case for the 0-RTT gate:
    // `deinit` clears `handshake_complete`, which was the only condition
    // `installTrafficSecret(.zero_rtt, ...)` checked, so before the
    // `torn_down` guard both directions could be reinstalled here and the
    // epoch used to seal and open records again.
    bridge.deinit();

    try testing.expectError(
        error.InvalidEpochTransition,
        bridge.installTrafficSecret(.zero_rtt, .read, &early),
    );
    try testing.expectError(
        error.InvalidEpochTransition,
        bridge.installTrafficSecret(.zero_rtt, .write, &early),
    );
    try testing.expect(!bridge.hasReadKeys(.zero_rtt));
    try testing.expect(!bridge.hasWriteKeys(.zero_rtt));

    // With no key material obtainable, the epoch stays unusable rather than
    // merely un-keyed.
    var protected: [record_codec.max_ciphertext_record_len]u8 = undefined;
    var plaintext: [record_codec.max_ciphertext_fragment_len]u8 = undefined;
    try testing.expectError(
        error.MissingWriteKeys,
        bridge.sealProtected(.zero_rtt, .application_data, "resurrected", &protected),
    );
    try testing.expectError(error.MissingReadKeys, bridge.openProtected(.zero_rtt, .{
        .content_type = .application_data,
        .legacy_version = record_codec.legacy_record_version,
        .payload = &[_]u8{0} ** 32,
    }, &plaintext));

    // The same guard covers every other epoch, at every stage of teardown.
    const hs = secret(0x92);
    try testing.expectError(
        error.InvalidEpochTransition,
        bridge.installTrafficSecret(.handshake, .read, &hs),
    );
    try testing.expectError(
        error.InvalidEpochTransition,
        bridge.installTrafficSecret(.application, .write, &hs),
    );
    // Teardown after a *completed* session is the other reachable shape.
    var completed = Bridge.init(cp, .tls_aes_128_gcm_sha256);
    const app = secret(0x93);
    try completed.installTrafficSecret(.handshake, .read, &hs);
    try completed.installTrafficSecret(.handshake, .write, &hs);
    try completed.installTrafficSecret(.application, .read, &app);
    try completed.installTrafficSecret(.application, .write, &app);
    try completed.discardEpoch(.initial);
    try completed.discardEpoch(.handshake);
    try completed.markHandshakeComplete();
    completed.deinit();
    try testing.expectError(
        error.InvalidEpochTransition,
        completed.installTrafficSecret(.zero_rtt, .write, &early),
    );

    // `Bridge.init` is the way to start a new session, and it is unaffected.
    var fresh = Bridge.init(cp, .tls_aes_128_gcm_sha256);
    defer fresh.deinit();
    try fresh.installTrafficSecret(.zero_rtt, .write, &early);
    try testing.expect(fresh.hasWriteKeys(.zero_rtt));
}

// ── KeyUpdate: application traffic secret advancement (#357) ────────────────

/// A bridge pair carried to a completed handshake with the given application
/// secrets, so a `KeyUpdate` test starts from the only state `KeyUpdate` is
/// ever legal in. `a`'s write secret is `b`'s read secret and vice versa,
/// which is what makes an update on one side observable on the other.
fn establishedPair(
    a: *Bridge,
    b: *Bridge,
    a_to_b: []const u8,
    b_to_a: []const u8,
) !void {
    const hs_a_to_b = secret(0x01);
    const hs_b_to_a = secret(0x02);
    for ([_]struct { bridge: *Bridge, write: []const u8, read: []const u8 }{
        .{ .bridge = a, .write = &hs_a_to_b, .read = &hs_b_to_a },
        .{ .bridge = b, .write = &hs_b_to_a, .read = &hs_a_to_b },
    }) |side| {
        try side.bridge.installTrafficSecret(.handshake, .write, side.write);
        try side.bridge.installTrafficSecret(.handshake, .read, side.read);
    }
    try a.installTrafficSecret(.application, .write, a_to_b);
    try a.installTrafficSecret(.application, .read, b_to_a);
    try b.installTrafficSecret(.application, .write, b_to_a);
    try b.installTrafficSecret(.application, .read, a_to_b);
    for ([_]*Bridge{ a, b }) |bridge| {
        try bridge.discardEpoch(.initial);
        try bridge.discardEpoch(.handshake);
        try bridge.markHandshakeComplete();
    }
}

/// RFC 8446 §7.2's `"traffic upd"` step, computed independently of the module
/// under test so a test cannot pass by agreeing with a wrong implementation.
fn expectedNextSecret(current: [32]u8) [32]u8 {
    const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
    return std.crypto.tls.hkdfExpandLabel(HkdfSha256, current, "traffic upd", "", 32);
}

fn sealOne(bridge: *Bridge, plaintext: []const u8, out: []u8) ![]const u8 {
    return bridge.sealApplicationData(plaintext, out);
}

test "key update advances one direction along the RFC 8446 traffic-upd chain" {
    const cp = testProvider();
    var client = Bridge.init(cp, .tls_aes_128_gcm_sha256);
    defer client.deinit();
    var server = Bridge.init(cp, .tls_aes_128_gcm_sha256);
    defer server.deinit();
    const c2s = secret(0x33);
    const s2c = secret(0x44);
    try establishedPair(&client, &server, &c2s, &s2c);

    // The client updates its *sending* keys; the server updates the matching
    // *receiving* keys. Every other direction is untouched -- a one-way
    // update must not disturb the reverse direction's chain.
    try client.updateTrafficSecret(.write);
    try server.updateTrafficSecret(.read);

    const expected = expectedNextSecret(c2s);
    try testing.expectEqualSlices(u8, &expected, client.write_application_secret.slice());
    try testing.expectEqualSlices(u8, &expected, server.read_application_secret.slice());
    try expectAes128TrafficKeys(expected, client.write_application.?.keys);
    try expectAes128TrafficKeys(expected, server.read_application.?.keys);

    // The reverse direction stayed on generation 0.
    try testing.expectEqualSlices(u8, &s2c, server.write_application_secret.slice());
    try testing.expectEqualSlices(u8, &s2c, client.read_application_secret.slice());
    try testing.expectEqual(@as(u64, 1), client.write_key_generation);
    try testing.expectEqual(@as(u64, 1), server.read_key_generation);
    try testing.expectEqual(@as(u64, 0), client.read_key_generation);
    try testing.expectEqual(@as(u64, 0), server.write_key_generation);

    // Traffic still flows, under the new keys, in both directions.
    var protected: [record_codec.max_ciphertext_record_len]u8 = undefined;
    var plaintext: [record_codec.max_ciphertext_fragment_len]u8 = undefined;
    const forward = try parseSingleRecord(.ciphertext, try sealOne(&client, "after update", &protected));
    try testing.expectEqualStrings("after update", (try server.openApplicationData(forward, &plaintext)).inner.content);
    const back = try parseSingleRecord(.ciphertext, try sealOne(&server, "still fine", &protected));
    try testing.expectEqualStrings("still fine", (try client.openApplicationData(back, &plaintext)).inner.content);
}

test "key update restarts the record sequence and retires the previous keys" {
    const cp = testProvider();
    var client = Bridge.init(cp, .tls_aes_128_gcm_sha256);
    defer client.deinit();
    var server = Bridge.init(cp, .tls_aes_128_gcm_sha256);
    defer server.deinit();
    const c2s = secret(0x51);
    const s2c = secret(0x52);
    try establishedPair(&client, &server, &c2s, &s2c);

    var protected: [record_codec.max_ciphertext_record_len]u8 = undefined;
    var plaintext: [record_codec.max_ciphertext_fragment_len]u8 = undefined;

    // Move both sides off sequence zero so the reset is observable as a
    // change rather than as a value that happened to already hold.
    for (0..3) |_| {
        const record = try parseSingleRecord(.ciphertext, try sealOne(&client, "pre", &protected));
        _ = try server.openApplicationData(record, &plaintext);
    }
    try testing.expectEqual(@as(u64, 3), client.write_application.?.sequence);
    try testing.expectEqual(@as(u64, 3), server.read_application.?.sequence);

    // A record sealed under the old keys, captured *before* the transition.
    var stale_buf: [record_codec.max_ciphertext_record_len]u8 = undefined;
    const stale_bytes = try sealOne(&client, "old generation", &stale_buf);
    var stale_copy: [record_codec.max_ciphertext_record_len]u8 = undefined;
    @memcpy(stale_copy[0..stale_bytes.len], stale_bytes);
    const stale = try parseSingleRecord(.ciphertext, stale_copy[0..stale_bytes.len]);

    try client.updateTrafficSecret(.write);
    try server.updateTrafficSecret(.read);

    // RFC 8446 §5.3: the new key starts counting from zero again.
    try testing.expectEqual(@as(u64, 0), client.write_application.?.sequence);
    try testing.expectEqual(@as(u64, 0), server.read_application.?.sequence);

    // The old keys are gone on the receiving side: a record sealed under the
    // previous generation no longer authenticates.
    try testing.expectError(error.AuthenticationFailed, server.openApplicationData(stale, &plaintext));

    // ...and sequence semantics resume normally from the new zero.
    const fresh = try parseSingleRecord(.ciphertext, try sealOne(&client, "new generation", &protected));
    try testing.expectEqualStrings("new generation", (try server.openApplicationData(fresh, &plaintext)).inner.content);
    try testing.expectEqual(@as(u64, 1), client.write_application.?.sequence);
    try testing.expectEqual(@as(u64, 1), server.read_application.?.sequence);
}

test "repeated key updates keep both directions walking the same chain" {
    const cp = testProvider();
    var client = Bridge.init(cp, .tls_aes_128_gcm_sha256);
    defer client.deinit();
    var server = Bridge.init(cp, .tls_aes_128_gcm_sha256);
    defer server.deinit();
    const c2s = secret(0x61);
    const s2c = secret(0x62);
    try establishedPair(&client, &server, &c2s, &s2c);

    var protected: [record_codec.max_ciphertext_record_len]u8 = undefined;
    var plaintext: [record_codec.max_ciphertext_fragment_len]u8 = undefined;
    var expected_c2s = c2s;
    var expected_s2c = s2c;

    // Simultaneous updates: each round advances both directions, which is the
    // state two endpoints reach when their updates cross on the wire.
    for (1..9) |round| {
        try client.updateTrafficSecret(.write);
        try server.updateTrafficSecret(.read);
        try server.updateTrafficSecret(.write);
        try client.updateTrafficSecret(.read);
        expected_c2s = expectedNextSecret(expected_c2s);
        expected_s2c = expectedNextSecret(expected_s2c);

        try testing.expectEqualSlices(u8, &expected_c2s, client.write_application_secret.slice());
        try testing.expectEqualSlices(u8, &expected_c2s, server.read_application_secret.slice());
        try testing.expectEqualSlices(u8, &expected_s2c, server.write_application_secret.slice());
        try testing.expectEqualSlices(u8, &expected_s2c, client.read_application_secret.slice());
        try testing.expectEqual(round, client.write_key_generation);
        try testing.expectEqual(round, client.read_key_generation);

        const forward = try parseSingleRecord(.ciphertext, try sealOne(&client, "c2s", &protected));
        try testing.expectEqualStrings("c2s", (try server.openApplicationData(forward, &plaintext)).inner.content);
        const back = try parseSingleRecord(.ciphertext, try sealOne(&server, "s2c", &protected));
        try testing.expectEqualStrings("s2c", (try client.openApplicationData(back, &plaintext)).inner.content);
    }
}

test "a direction that skipped an update cannot read the peer's next generation" {
    // The chain is one-way and per-direction: falling one step behind is not
    // recoverable by the record layer, which is exactly why the transition
    // point has to be exact rather than approximately right.
    const cp = testProvider();
    var client = Bridge.init(cp, .tls_aes_128_gcm_sha256);
    defer client.deinit();
    var server = Bridge.init(cp, .tls_aes_128_gcm_sha256);
    defer server.deinit();
    const c2s = secret(0x71);
    const s2c = secret(0x72);
    try establishedPair(&client, &server, &c2s, &s2c);

    try client.updateTrafficSecret(.write);
    var protected: [record_codec.max_ciphertext_record_len]u8 = undefined;
    var plaintext: [record_codec.max_ciphertext_fragment_len]u8 = undefined;
    const record = try parseSingleRecord(.ciphertext, try sealOne(&client, "generation 1", &protected));
    try testing.expectError(error.AuthenticationFailed, server.openApplicationData(record, &plaintext));
}

test "key update replaces key material without leaving the previous generation in the bridge" {
    const cp = testProvider();
    var client = Bridge.init(cp, .tls_aes_128_gcm_sha256);
    defer client.deinit();
    var server = Bridge.init(cp, .tls_aes_128_gcm_sha256);
    defer server.deinit();
    const c2s = secret(0x81);
    const s2c = secret(0x82);
    try establishedPair(&client, &server, &c2s, &s2c);

    var old_secret: [32]u8 = undefined;
    @memcpy(&old_secret, client.write_application_secret.slice());
    var old_key: [16]u8 = undefined;
    @memcpy(&old_key, client.write_application.?.keys.key.slice());
    var old_iv: [provider.aead_nonce_len]u8 = undefined;
    @memcpy(&old_iv, client.write_application.?.keys.iv.slice());

    try client.updateTrafficSecret(.write);

    // Every byte string the previous generation consisted of must be absent
    // from the bridge's entire footprint -- not merely absent from the slot it
    // used to occupy, which a "keep the old keys for late records" change
    // would still satisfy while leaving retired material live.
    const footprint = std.mem.asBytes(&client);
    try testing.expect(std.mem.indexOf(u8, footprint, &old_secret) == null);
    try testing.expect(std.mem.indexOf(u8, footprint, &old_key) == null);
    try testing.expect(std.mem.indexOf(u8, footprint, &old_iv) == null);
    // The new generation is present, so the search above is a real search.
    try testing.expect(std.mem.indexOf(u8, footprint, &expectedNextSecret(c2s)) != null);

    // Teardown after an update still wipes whatever generation is current.
    var current_secret: [32]u8 = undefined;
    @memcpy(&current_secret, client.write_application_secret.slice());
    client.deinit();
    try testing.expect(std.mem.indexOf(u8, footprint, &current_secret) == null);
    try testing.expect(client.write_application == null);
    try testing.expectEqual(@as(usize, 0), client.write_application_secret.slice().len);
}

test "key update is rejected outside a live, completed application epoch" {
    const cp = testProvider();

    // Before the handshake completes there is no application epoch to update.
    var early = Bridge.init(cp, .tls_aes_128_gcm_sha256);
    defer early.deinit();
    try testing.expectError(error.HandshakeNotComplete, early.updateTrafficSecret(.write));
    try testing.expectError(error.HandshakeNotComplete, early.updateTrafficSecret(.read));
    const hs = secret(0x91);
    try early.installTrafficSecret(.handshake, .write, &hs);
    try early.installTrafficSecret(.handshake, .read, &hs);
    try testing.expectError(error.HandshakeNotComplete, early.updateTrafficSecret(.write));
    const app = secret(0x92);
    try early.installTrafficSecret(.application, .write, &app);
    try early.installTrafficSecret(.application, .read, &app);
    // Application keys exist, but `handshake_complete` has not been marked --
    // `KeyUpdate` is post-handshake by definition, so key presence alone is
    // not enough.
    try testing.expectError(error.HandshakeNotComplete, early.updateTrafficSecret(.write));

    // After teardown the session is over in both directions.
    var torn = Bridge.init(cp, .tls_aes_128_gcm_sha256);
    var peer = Bridge.init(cp, .tls_aes_128_gcm_sha256);
    defer peer.deinit();
    const c2s = secret(0x93);
    const s2c = secret(0x94);
    try establishedPair(&torn, &peer, &c2s, &s2c);
    try torn.updateTrafficSecret(.write);
    torn.deinit();
    try testing.expectError(error.InvalidEpochTransition, torn.updateTrafficSecret(.write));
    try testing.expectError(error.InvalidEpochTransition, torn.updateTrafficSecret(.read));

    // Orderly application-epoch discard is teardown too, and drops the
    // retained secrets along with the keys.
    var closed = Bridge.init(cp, .tls_aes_128_gcm_sha256);
    defer closed.deinit();
    var closed_peer = Bridge.init(cp, .tls_aes_128_gcm_sha256);
    defer closed_peer.deinit();
    try establishedPair(&closed, &closed_peer, &c2s, &s2c);
    try closed.discardEpoch(.application);
    try testing.expectEqual(@as(usize, 0), closed.write_application_secret.slice().len);
    try testing.expectError(error.InvalidEpochTransition, closed.updateTrafficSecret(.write));
}

test "applicationRecordsSealed tracks the current generation's sequence for usage limits" {
    const cp = testProvider();
    var client = Bridge.init(cp, .tls_aes_128_gcm_sha256);
    defer client.deinit();
    var server = Bridge.init(cp, .tls_aes_128_gcm_sha256);
    defer server.deinit();
    const c2s = secret(0xa1);
    const s2c = secret(0xa2);

    // No application keys yet: nothing has been sealed.
    try testing.expectEqual(@as(u64, 0), client.applicationRecordsSealed());
    try establishedPair(&client, &server, &c2s, &s2c);
    try testing.expectEqual(@as(u64, 0), client.applicationRecordsSealed());

    var protected: [record_codec.max_ciphertext_record_len]u8 = undefined;
    for (0..5) |_| _ = try sealOne(&client, "x", &protected);
    try testing.expectEqual(@as(u64, 5), client.applicationRecordsSealed());
    // The counter is the write sequence itself, so an update resets it with
    // the sequence rather than tracking a lifetime total.
    try client.updateTrafficSecret(.write);
    try testing.expectEqual(@as(u64, 0), client.applicationRecordsSealed());
}

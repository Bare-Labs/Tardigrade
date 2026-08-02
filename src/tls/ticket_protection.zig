//! Provider-neutral stateless TLS ticket protection (#363).
//!
//! The public ticket identity is a small authenticated envelope around the
//! canonical `session.ServerRecoverableState` encoding. Runtime loading,
//! rotation scheduling, metrics export, and TLS PSK binder policy stay outside
//! this module.

const std = @import("std");
const crypto = @import("crypto");
const pre_shared_key = @import("pre_shared_key.zig");
const session = @import("session.zig");

const provider = crypto.provider;
const secrets = crypto.secrets;

pub const magic = [4]u8{ 'T', 'D', 'T', 'K' };
pub const format_version: u8 = 1;
pub const key_id_len = 16;
pub const fixed_header_len = 36;
pub const tag_len = provider.aead_tag_len;
pub const envelope_overhead = fixed_header_len + tag_len;
pub const max_keys = 16;

const aad_prefix = "tardigrade/tls-ticket/v1\x00";
const key_fingerprint_domain = "tardigrade/tls-ticket/key-fingerprint/v1\x00";

pub const KeyId = [key_id_len]u8;
const TicketKeySecret = secrets.FixedSecret(provider.max_aead_key_len);
const KeyFingerprint = [32]u8;
const KeyDeinitProbe = struct {
    observed: usize = 0,

    fn record(self: *KeyDeinitProbe, key: *const TicketKeySecret, logical_len: usize) void {
        for (key.bytes[0..logical_len]) |byte| {
            if (byte != 0) @panic("ticket key was not zeroized before cleanup observation");
        }
        self.observed += 1;
    }
};
var test_key_deinit_probe: ?*KeyDeinitProbe = null;

pub const ParseError = error{
    MalformedEnvelope,
    UnsupportedVersion,
    UnsupportedAeadId,
    EnvelopeTooLarge,
};

pub const SnapshotError = error{
    TooManyKeys,
    DuplicateKeyId,
    InvalidKeyLength,
    UnsupportedCapability,
    InvalidValidityWindow,
    InvalidNonceLease,
    OverlappingNonceLease,
    AmbiguousEncryptionWindow,
    StaleSnapshotGeneration,
    GenerationOverflow,
    OutOfMemory,
};

pub const SealError = error{
    NoActiveEncryptionKey,
    AmbiguousActiveEncryptionKey,
    TicketOutlivesKey,
    NonceLeaseExhausted,
    SerializedStateTooLarge,
    TicketTooLarge,
    OutputTooSmall,
    UnsupportedCapability,
    InvalidInternalState,
    OutOfMemory,
};

pub const ResolveError = error{
    OutOfMemory,
    UnsupportedCapability,
    InvalidInternalState,
};

pub const SealRejectReason = enum {
    no_active_encryption_key,
    ambiguous_active_encryption_key,
    ticket_outlives_key,
    nonce_lease_exhausted,
    serialized_state_too_large,
    ticket_too_large,
    output_too_small,
    unsupported_capability,
    invalid_internal_state,
    out_of_memory,
};

pub const ResolveRejectReason = enum {
    malformed_envelope,
    unsupported_version,
    unsupported_aead,
    envelope_too_large,
    unknown_key,
    future_key,
    retired_key,
    unsupported_capability,
    authentication_failed,
    invalid_plaintext,
    not_yet_valid,
    expired,
    invalid_internal_state,
    out_of_memory,
};

pub const SnapshotRejectReason = enum {
    too_many_keys,
    duplicate_key_id,
    invalid_key_length,
    unsupported_capability,
    invalid_validity_window,
    invalid_nonce_lease,
    overlapping_nonce_lease,
    ambiguous_encryption_window,
    stale_generation,
    generation_overflow,
    out_of_memory,
};

pub const Event = union(enum) {
    seal_succeeded,
    seal_rejected: SealRejectReason,
    resolve_succeeded,
    resolve_rejected: ResolveRejectReason,
    snapshot_installed: u64,
    snapshot_rejected: SnapshotRejectReason,
    key_retired: u64,
    nonce_lease_exhausted,
};

pub const Observer = struct {
    ctx: *anyopaque,
    recordFn: *const fn (*anyopaque, Event) void,

    pub fn record(self: Observer, event: Event) void {
        self.recordFn(self.ctx, event);
    }
};

pub const NonceLeaseConfig = struct {
    prefix: [4]u8,
    start: u64,
    end_exclusive: u64,
};

pub const KeyConfig = struct {
    id: KeyId,
    aead: provider.Aead,
    key_bytes: []const u8,
    not_before_unix_ms: i64,
    encrypt_until_unix_ms: i64,
    decrypt_until_unix_ms: i64,
    nonce_lease: ?NonceLeaseConfig = null,
};

pub const ParsedEnvelope = struct {
    aead: provider.Aead,
    key_id: KeyId,
    nonce: [provider.aead_nonce_len]u8,
    header: []const u8,
    ciphertext: []const u8,
    tag: []const u8,
};

pub fn encodeAeadId(aead: provider.Aead) u8 {
    return switch (aead) {
        .aes_128_gcm => 1,
        .aes_256_gcm => 2,
        .chacha20_poly1305 => 3,
    };
}

pub fn decodeAeadId(id: u8) ParseError!provider.Aead {
    return switch (id) {
        1 => .aes_128_gcm,
        2 => .aes_256_gcm,
        3 => .chacha20_poly1305,
        else => error.UnsupportedAeadId,
    };
}

pub fn parseEnvelope(identity: []const u8, limits: session.Limits) ParseError!ParsedEnvelope {
    limits.validate() catch return error.EnvelopeTooLarge;
    if (identity.len > limits.max_ticket_len or identity.len > session.absolute_ticket_wire_max)
        return error.EnvelopeTooLarge;
    if (identity.len < fixed_header_len + 1 + tag_len) return error.MalformedEnvelope;
    if (!std.mem.eql(u8, identity[0..4], &magic)) return error.MalformedEnvelope;
    if (identity[4] != format_version) return error.UnsupportedVersion;
    const aead = try decodeAeadId(identity[5]);
    if (std.mem.readInt(u16, identity[6..8], .big) != 0) return error.MalformedEnvelope;

    var key_id: KeyId = undefined;
    @memcpy(&key_id, identity[8..24]);
    var nonce: [provider.aead_nonce_len]u8 = undefined;
    @memcpy(&nonce, identity[24..36]);

    return .{
        .aead = aead,
        .key_id = key_id,
        .nonce = nonce,
        .header = identity[0..fixed_header_len],
        .ciphertext = identity[fixed_header_len .. identity.len - tag_len],
        .tag = identity[identity.len - tag_len ..],
    };
}

const NonceLease = struct {
    prefix: [4]u8,
    next_counter: std.atomic.Value(u64),
    end_exclusive: u64,

    fn init(config: NonceLeaseConfig) SnapshotError!NonceLease {
        if (config.start >= config.end_exclusive) return error.InvalidNonceLease;
        return .{
            .prefix = config.prefix,
            .next_counter = std.atomic.Value(u64).init(config.start),
            .end_exclusive = config.end_exclusive,
        };
    }

    fn reserve(self: *NonceLease) SealError![provider.aead_nonce_len]u8 {
        while (true) {
            const current = self.next_counter.load(.acquire);
            if (current >= self.end_exclusive) return error.NonceLeaseExhausted;
            if (current == std.math.maxInt(u64)) return error.NonceLeaseExhausted;
            if (self.next_counter.cmpxchgWeak(current, current + 1, .acq_rel, .acquire) == null) {
                var nonce: [provider.aead_nonce_len]u8 = undefined;
                @memcpy(nonce[0..4], &self.prefix);
                std.mem.writeInt(u64, nonce[4..12], current, .big);
                return nonce;
            }
            std.atomic.spinLoopHint();
        }
    }

    fn currentEnd(self: *const NonceLease) u64 {
        return self.end_exclusive;
    }
};

const KeyRecord = struct {
    id: KeyId,
    aead: provider.Aead,
    key: TicketKeySecret,
    not_before_unix_ms: i64,
    encrypt_until_unix_ms: i64,
    decrypt_until_unix_ms: i64,
    nonce_lease: ?NonceLease,

    fn build(config: KeyConfig, caps: provider.Capabilities) SnapshotError!KeyRecord {
        if (!caps.supportsAead(config.aead)) return error.UnsupportedCapability;
        if (config.key_bytes.len != config.aead.keyLength()) return error.InvalidKeyLength;
        if (!(config.not_before_unix_ms < config.encrypt_until_unix_ms and
            config.encrypt_until_unix_ms <= config.decrypt_until_unix_ms))
            return error.InvalidValidityWindow;

        var key = TicketKeySecret.init(config.key_bytes) catch return error.InvalidKeyLength;
        errdefer key.deinit();

        const lease = if (config.nonce_lease) |lease_config|
            try NonceLease.init(lease_config)
        else
            null;

        return .{
            .id = config.id,
            .aead = config.aead,
            .key = key,
            .not_before_unix_ms = config.not_before_unix_ms,
            .encrypt_until_unix_ms = config.encrypt_until_unix_ms,
            .decrypt_until_unix_ms = config.decrypt_until_unix_ms,
            .nonce_lease = lease,
        };
    }

    fn deinit(self: *KeyRecord) void {
        const key_len = self.key.len;
        self.key.deinit();
        if (test_key_deinit_probe) |probe| probe.record(&self.key, key_len);
    }

    fn canEncryptAt(self: *const KeyRecord, now_unix_ms: i64) bool {
        return self.nonce_lease != null and
            now_unix_ms >= self.not_before_unix_ms and
            now_unix_ms < self.encrypt_until_unix_ms;
    }

    fn decryptWindowAt(self: *const KeyRecord, now_unix_ms: i64) enum { future, active, retained, retired } {
        if (now_unix_ms < self.not_before_unix_ms) return .future;
        if (now_unix_ms < self.encrypt_until_unix_ms) return .active;
        if (now_unix_ms < self.decrypt_until_unix_ms) return .retained;
        return .retired;
    }

    pub fn format(
        _: KeyRecord,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        _: anytype,
    ) !void {
        @compileError("ticket key records must not be formatted or logged");
    }
};

pub const Snapshot = struct {
    allocator: std.mem.Allocator,
    generation: u64,
    keys: []KeyRecord,
    ref_count: std.atomic.Value(usize) = std.atomic.Value(usize).init(1),
    deinit_count: ?*std.atomic.Value(usize) = null,

    pub fn build(
        allocator: std.mem.Allocator,
        configs: []const KeyConfig,
        generation: u64,
        caps: provider.Capabilities,
    ) SnapshotError!*Snapshot {
        if (configs.len == 0 or configs.len > max_keys) return error.TooManyKeys;

        var snapshot = allocator.create(Snapshot) catch return error.OutOfMemory;
        snapshot.* = .{
            .allocator = allocator,
            .generation = generation,
            .keys = &.{},
        };
        errdefer {
            snapshot.deinit();
            allocator.destroy(snapshot);
        }

        var keys = allocator.alloc(KeyRecord, configs.len) catch return error.OutOfMemory;
        var initialized: usize = 0;
        errdefer {
            for (keys[0..initialized]) |*key| key.deinit();
            allocator.free(keys);
        }

        for (configs, 0..) |config, i| {
            for (configs[0..i]) |prior| {
                if (std.mem.eql(u8, &prior.id, &config.id)) return error.DuplicateKeyId;
                if (prior.aead == config.aead and std.mem.eql(u8, prior.key_bytes, config.key_bytes))
                    return error.DuplicateKeyId;
            }
            keys[i] = try KeyRecord.build(config, caps);
            initialized += 1;
        }
        try validateEncryptionWindows(keys);

        snapshot.keys = keys;
        return snapshot;
    }

    pub fn retain(self: *Snapshot) void {
        _ = self.ref_count.fetchAdd(1, .acq_rel);
    }

    pub fn release(self: *Snapshot) void {
        const previous = self.ref_count.fetchSub(1, .acq_rel);
        std.debug.assert(previous > 0);
        if (previous == 1) {
            const allocator = self.allocator;
            self.deinit();
            allocator.destroy(self);
        }
    }

    fn deinit(self: *Snapshot) void {
        if (self.deinit_count) |counter| _ = counter.fetchAdd(1, .monotonic);
        for (self.keys) |*key| key.deinit();
        self.allocator.free(self.keys);
        self.keys = &.{};
    }

    fn activeEncryptionKey(self: *Snapshot, now_unix_ms: i64) SealError!*KeyRecord {
        var found: ?*KeyRecord = null;
        for (self.keys) |*key| {
            if (!key.canEncryptAt(now_unix_ms)) continue;
            if (found != null) return error.AmbiguousActiveEncryptionKey;
            found = key;
        }
        return found orelse error.NoActiveEncryptionKey;
    }

    fn findKey(self: *Snapshot, key_id: *const KeyId) ?*KeyRecord {
        for (self.keys) |*key| {
            if (std.mem.eql(u8, &key.id, key_id)) return key;
        }
        return null;
    }

    fn findKeyConst(self: *const Snapshot, key_id: *const KeyId) ?*const KeyRecord {
        for (self.keys) |*key| {
            if (std.mem.eql(u8, &key.id, key_id)) return key;
        }
        return null;
    }

    pub fn format(
        _: Snapshot,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        _: anytype,
    ) !void {
        @compileError("ticket key snapshots must not be formatted or logged");
    }
};

const LeaseHighWater = struct {
    key_id: KeyId,
    prefix: [4]u8,
    end_exclusive: u64,
    has_lease: bool,
    aead: provider.Aead,
    key_fingerprint: KeyFingerprint,

    /// Initialize `out` in place rather than returning a `LeaseHighWater` by
    /// value: a return-by-value constructor would copy the fingerprint
    /// through an unwiped stack temporary as part of copying the whole
    /// struct into its final (heap-allocated) home. The one remaining
    /// fingerprint temporary here is explicitly wiped once copied in.
    fn initInto(out: *LeaseHighWater, record: *const KeyRecord) void {
        out.key_id = record.id;
        out.prefix = if (record.nonce_lease) |*value| value.prefix else [_]u8{0} ** 4;
        out.end_exclusive = if (record.nonce_lease) |*value| value.currentEnd() else 0;
        out.has_lease = record.nonce_lease != null;
        out.aead = record.aead;
        var fingerprint = fingerprintKey(record.aead, record.key.slice());
        defer secrets.secureZero(&fingerprint);
        out.key_fingerprint = fingerprint;
    }

    fn deinit(self: *LeaseHighWater) void {
        secrets.secureZero(&self.key_fingerprint);
        self.* = undefined;
    }
};

/// Entries allocated while validating a replacement snapshot, held here
/// until the whole validation pass succeeds. `validateReplacementLocked`
/// allocates every ledger entry a replacement needs *before* `install()`
/// mutates `self.current`, so an allocation failure anywhere in validation
/// rejects the whole install — it can no longer commit a key while silently
/// omitting its ledger fingerprint/nonce high-water mark.
const PendingLedgerEntries = struct {
    entries: [max_keys]*LeaseHighWater = undefined,
    count: usize = 0,

    fn destroyAll(self: *PendingLedgerEntries, allocator: std.mem.Allocator) void {
        for (self.entries[0..self.count]) |entry| {
            entry.deinit();
            allocator.destroy(entry);
        }
        self.count = 0;
    }
};

pub const ReloadableKeyRing = struct {
    allocator: std.mem.Allocator,
    mutex: SpinMutex = .{},
    current: ?*Snapshot = null,
    next_generation: u64 = 1,
    // Entries are individually heap-allocated (rather than stored by value in
    // this list) so that growing the list never copies a `key_fingerprint`
    // through an intermediate allocation that gets freed unwiped: only the
    // pointers move, and the fingerprint bytes stay in one stable allocation
    // until `LeaseHighWater.deinit()` wipes it before the entry is destroyed.
    ledger: std.ArrayList(*LeaseHighWater) = .empty,
    observer: ?Observer = null,

    pub fn init(allocator: std.mem.Allocator) ReloadableKeyRing {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *ReloadableKeyRing) void {
        self.mutex.lock();
        const retired = self.current;
        self.current = null;
        const ledger = self.ledger;
        self.ledger = .empty;
        self.mutex.unlock();
        if (retired) |snapshot| snapshot.release();
        var mutable_ledger = ledger;
        for (mutable_ledger.items) |entry| {
            entry.deinit();
            self.allocator.destroy(entry);
        }
        mutable_ledger.deinit(self.allocator);
    }

    pub fn buildSnapshot(self: *ReloadableKeyRing, configs: []const KeyConfig, caps: provider.Capabilities) SnapshotError!*Snapshot {
        const replacement = Snapshot.build(self.allocator, configs, 0, caps) catch |err| {
            self.record(.{ .snapshot_rejected = snapshotReason(err) });
            return err;
        };
        return replacement;
    }

    /// Consumes `replacement` on every successful and rejected install path.
    pub fn install(self: *ReloadableKeyRing, replacement: *Snapshot) SnapshotError!void {
        self.mutex.lock();
        if (self.current) |current| {
            if (current == replacement) {
                if (replacement.generation == std.math.maxInt(u64)) {
                    self.mutex.unlock();
                    replacement.release();
                    self.record(.{ .snapshot_rejected = .generation_overflow });
                    return error.GenerationOverflow;
                }
                self.next_generation = @max(self.next_generation, replacement.generation + 1);
                self.mutex.unlock();
                replacement.release();
                return;
            }
            if (replacement.generation != 0 and replacement.generation <= current.generation) {
                self.mutex.unlock();
                replacement.release();
                self.record(.{ .snapshot_rejected = .stale_generation });
                return error.StaleSnapshotGeneration;
            }
        }
        if (replacement.generation == std.math.maxInt(u64)) {
            self.mutex.unlock();
            replacement.release();
            self.record(.{ .snapshot_rejected = .generation_overflow });
            return error.GenerationOverflow;
        }

        var pending: PendingLedgerEntries = .{};
        self.validateReplacementLocked(replacement, &pending) catch |err| {
            self.mutex.unlock();
            replacement.release();
            self.record(.{ .snapshot_rejected = snapshotReason(err) });
            return err;
        };
        if (replacement.generation == 0) {
            if (self.next_generation == std.math.maxInt(u64)) {
                self.mutex.unlock();
                pending.destroyAll(self.allocator);
                replacement.release();
                self.record(.{ .snapshot_rejected = .generation_overflow });
                return error.GenerationOverflow;
            }
            replacement.generation = self.next_generation;
            self.next_generation += 1;
        }

        const retired = self.current;
        const installed_generation = replacement.generation;
        const retired_key_count = if (retired) |snapshot| retiredKeyCount(snapshot, replacement) else 0;
        self.current = replacement;
        self.next_generation = @max(self.next_generation, replacement.generation + 1);
        // Every entry `updateLedgerLocked` needs was already allocated (and
        // validated) above, so publication from here on is infallible.
        self.updateLedgerLocked(replacement, &pending);
        self.mutex.unlock();

        self.record(.{ .snapshot_installed = installed_generation });
        if (retired) |snapshot| {
            for (0..retired_key_count) |_| self.record(.{ .key_retired = snapshot.generation });
            snapshot.release();
        }
    }

    pub fn validateInstallCandidate(self: *ReloadableKeyRing, replacement: *Snapshot) SnapshotError!void {
        self.mutex.lock();
        if (self.current) |current| {
            if (replacement.generation != 0 and replacement.generation <= current.generation) {
                self.mutex.unlock();
                self.record(.{ .snapshot_rejected = .stale_generation });
                return error.StaleSnapshotGeneration;
            }
        }
        if (replacement.generation == std.math.maxInt(u64)) {
            self.mutex.unlock();
            self.record(.{ .snapshot_rejected = .generation_overflow });
            return error.GenerationOverflow;
        }
        // This is a dry run — it never installs `replacement` — so any
        // ledger entries `validateReplacementLocked` allocates for it must
        // be destroyed here regardless of outcome; nothing else will ever
        // consume them.
        var pending: PendingLedgerEntries = .{};
        defer pending.destroyAll(self.allocator);
        self.validateReplacementLocked(replacement, &pending) catch |err| {
            self.mutex.unlock();
            self.record(.{ .snapshot_rejected = snapshotReason(err) });
            return err;
        };
        if (replacement.generation == 0 and self.next_generation == std.math.maxInt(u64)) {
            self.mutex.unlock();
            self.record(.{ .snapshot_rejected = .generation_overflow });
            return error.GenerationOverflow;
        }
        self.mutex.unlock();
    }

    pub fn acquireCurrent(self: *ReloadableKeyRing) ?*Snapshot {
        self.mutex.lock();
        defer self.mutex.unlock();
        const snapshot = self.current orelse return null;
        snapshot.retain();
        return snapshot;
    }

    fn validateReplacementLocked(self: *ReloadableKeyRing, replacement: *Snapshot, pending: *PendingLedgerEntries) SnapshotError!void {
        errdefer pending.destroyAll(self.allocator);
        for (replacement.keys, 0..) |*key, i| {
            for (replacement.keys[0..i]) |*prior| {
                if (prior.aead == key.aead and prior.key.eql(&key.key)) return error.DuplicateKeyId;
            }

            var key_fingerprint = fingerprintKey(key.aead, key.key.slice());
            defer secrets.secureZero(&key_fingerprint);
            if (self.findLedger(&key.id)) |entry| {
                if (entry.aead != key.aead or !secrets.constantTimeEqual(&entry.key_fingerprint, &key_fingerprint)) return error.DuplicateKeyId;
            } else {
                var duplicate = false;
                for (self.ledger.items) |entry| {
                    if (entry.aead == key.aead and secrets.constantTimeEqual(&entry.key_fingerprint, &key_fingerprint)) {
                        duplicate = true;
                        break;
                    }
                }
                if (duplicate) return error.DuplicateKeyId;
                // Allocate and initialize the entry now, before any state is
                // committed: if this fails, the whole install is rejected
                // rather than later silently omitting this key's ledger
                // fingerprint after `self.current` has already moved.
                const entry = self.allocator.create(LeaseHighWater) catch return error.OutOfMemory;
                LeaseHighWater.initInto(entry, key);
                pending.entries[pending.count] = entry;
                pending.count += 1;
            }

            if (key.nonce_lease) |*lease| {
                for (replacement.keys[0..i]) |*prior| {
                    if (!std.mem.eql(u8, &prior.id, &key.id)) continue;
                    if (prior.nonce_lease) |*prior_lease| {
                        if (std.mem.eql(u8, &prior_lease.prefix, &lease.prefix) and
                            rangesOverlap(prior_lease.next_counter.load(.acquire), prior_lease.currentEnd(), lease.next_counter.load(.acquire), lease.currentEnd()))
                            return error.OverlappingNonceLease;
                    }
                }
                if (self.findLedger(&key.id)) |entry| {
                    if (entry.has_lease) {
                        if (!std.mem.eql(u8, &entry.prefix, &lease.prefix)) return error.OverlappingNonceLease;
                        if (lease.next_counter.load(.acquire) < entry.end_exclusive) return error.OverlappingNonceLease;
                    }
                }
            }

            if (self.current) |current| {
                if (current.findKey(&key.id)) |old| {
                    if (old.aead != key.aead or !old.key.eql(&key.key)) return error.DuplicateKeyId;
                }
            }
        }
        self.ledger.ensureUnusedCapacity(self.allocator, pending.count) catch return error.OutOfMemory;
    }

    /// Publish `pending`'s entries into the ledger. Every entry this needs
    /// was already allocated and validated by `validateReplacementLocked`
    /// (which reserved ledger pointer-array capacity for exactly
    /// `pending.count` entries too), so this cannot fail — publication after
    /// `self.current` has moved must be infallible.
    fn updateLedgerLocked(self: *ReloadableKeyRing, snapshot: *Snapshot, pending: *PendingLedgerEntries) void {
        var pending_idx: usize = 0;
        for (snapshot.keys) |*key| {
            if (self.findLedgerIndex(&key.id)) |idx| {
                if (key.nonce_lease) |*lease| {
                    const entry = self.ledger.items[idx];
                    entry.has_lease = true;
                    entry.prefix = lease.prefix;
                    entry.end_exclusive = @max(entry.end_exclusive, lease.currentEnd());
                }
            } else {
                const entry = pending.entries[pending_idx];
                pending_idx += 1;
                self.ledger.appendAssumeCapacity(entry);
            }
        }
        // Ownership of every entry moved into `self.ledger` above.
        pending.count = 0;
    }

    fn findLedger(self: *const ReloadableKeyRing, key_id: *const KeyId) ?*const LeaseHighWater {
        if (self.findLedgerIndex(key_id)) |idx| return self.ledger.items[idx];
        return null;
    }

    fn findLedgerIndex(self: *const ReloadableKeyRing, key_id: *const KeyId) ?usize {
        for (self.ledger.items, 0..) |entry, i| {
            if (std.mem.eql(u8, &entry.key_id, key_id)) return i;
        }
        return null;
    }

    fn record(self: *ReloadableKeyRing, event: Event) void {
        if (self.observer) |observer| observer.record(event);
    }

    fn retiredKeyCount(retired: *const Snapshot, replacement: *const Snapshot) usize {
        var count: usize = 0;
        for (retired.keys) |*old_key| {
            if (replacement.findKeyConst(&old_key.id) == null) count += 1;
        }
        return count;
    }

    pub fn format(
        _: ReloadableKeyRing,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        _: anytype,
    ) !void {
        @compileError("ticket keyrings must not be formatted or logged");
    }
};

fn validateEncryptionWindows(keys: []const KeyRecord) SnapshotError!void {
    for (keys, 0..) |*a, i| {
        if (a.nonce_lease == null) continue;
        for (keys[i + 1 ..]) |*b| {
            if (b.nonce_lease == null) continue;
            if (a.not_before_unix_ms < b.encrypt_until_unix_ms and
                b.not_before_unix_ms < a.encrypt_until_unix_ms)
                return error.AmbiguousEncryptionWindow;
        }
    }
}

pub const Protector = struct {
    provider: provider.CryptoProvider,
    keyring: *ReloadableKeyRing,
    limits: session.Limits,
    observer: ?Observer = null,

    pub fn protectedLen(
        self: *const Protector,
        state: *const session.ServerRecoverableState,
    ) SealError!usize {
        self.limits.validate() catch return error.InvalidInternalState;
        const plaintext_len = session.serverEncodedLenWithLimits(state, self.limits) catch |err| switch (err) {
            error.StateTooLarge => return error.SerializedStateTooLarge,
            error.InvalidLimits => return error.InvalidInternalState,
            error.InvalidState => return error.InvalidInternalState,
            error.TooManyFields, error.FieldTooLarge => return error.SerializedStateTooLarge,
            error.BufferTooSmall => unreachable,
        };
        return checkedProtectedLen(plaintext_len, self.limits);
    }

    pub fn seal(
        self: *Protector,
        allocator: std.mem.Allocator,
        state: *const session.ServerRecoverableState,
        now_unix_ms: i64,
        out: []u8,
    ) SealError![]const u8 {
        const sealed = self.sealInner(allocator, state, now_unix_ms, out) catch |err| {
            if (err == error.NonceLeaseExhausted) self.record(.nonce_lease_exhausted);
            self.record(.{ .seal_rejected = sealReason(err) });
            return err;
        };
        self.record(.seal_succeeded);
        return sealed;
    }

    fn sealInner(
        self: *Protector,
        allocator: std.mem.Allocator,
        state: *const session.ServerRecoverableState,
        now_unix_ms: i64,
        out: []u8,
    ) SealError![]const u8 {
        const snapshot = self.keyring.acquireCurrent() orelse {
            return error.NoActiveEncryptionKey;
        };
        defer snapshot.release();

        const key = snapshot.activeEncryptionKey(now_unix_ms) catch |err| {
            return err;
        };

        if (!self.provider.capabilities().supportsAead(key.aead)) {
            return error.UnsupportedCapability;
        }

        if (!ticketExpiresWithinKey(state, key.decrypt_until_unix_ms)) {
            return error.TicketOutlivesKey;
        }

        const protected_len = try self.protectedLen(state);
        if (out.len < protected_len) {
            return error.OutputTooSmall;
        }

        const plaintext_len = protected_len - envelope_overhead;
        const plaintext = allocator.alloc(u8, plaintext_len) catch {
            return error.OutOfMemory;
        };
        defer {
            zeroAndFree(allocator, plaintext);
        }

        const encoded = session.encodeServer(state, self.limits, plaintext) catch |err| switch (err) {
            error.BufferTooSmall, error.InvalidLimits, error.TooManyFields, error.FieldTooLarge, error.InvalidState => return error.InvalidInternalState,
            error.StateTooLarge => return error.SerializedStateTooLarge,
        };
        std.debug.assert(encoded.len == plaintext_len);

        const lease = &(key.nonce_lease orelse {
            return error.NoActiveEncryptionKey;
        });
        const nonce = try lease.reserve();

        writeHeader(out[0..fixed_header_len], key.aead, &key.id, &nonce);
        var aad: [aad_prefix.len + fixed_header_len]u8 = undefined;
        buildAad(out[0..fixed_header_len], &aad);
        const ciphertext = out[fixed_header_len .. fixed_header_len + plaintext_len];
        const tag = out[fixed_header_len + plaintext_len .. protected_len];
        self.provider.aeadSeal(key.aead, key.key.slice(), &nonce, &aad, encoded, ciphertext, tag) catch |err| switch (err) {
            error.UnsupportedCapability => return error.UnsupportedCapability,
            error.InvalidInput => return error.InvalidInternalState,
        };

        return out[0..protected_len];
    }

    pub fn resolve(
        self: *Protector,
        allocator: std.mem.Allocator,
        identity: []const u8,
        now_unix_ms: i64,
        out: *session.ServerRecoverableState,
    ) ResolveError!bool {
        const outcome = self.resolveInner(allocator, identity, now_unix_ms, out) catch |err| {
            self.record(.{ .resolve_rejected = resolveErrorReason(err) });
            return err;
        };
        switch (outcome) {
            .accepted => {
                self.record(.resolve_succeeded);
                return true;
            },
            .rejected => |reason| {
                self.record(.{ .resolve_rejected = reason });
                return false;
            },
        }
    }

    const ResolveOutcome = union(enum) {
        accepted,
        rejected: ResolveRejectReason,
    };

    fn resolveInner(
        self: *Protector,
        allocator: std.mem.Allocator,
        identity: []const u8,
        now_unix_ms: i64,
        out: *session.ServerRecoverableState,
    ) ResolveError!ResolveOutcome {
        self.limits.validate() catch return error.InvalidInternalState;
        const parsed = parseEnvelope(identity, self.limits) catch |err| {
            return .{ .rejected = parseReason(err) };
        };

        const snapshot = self.keyring.acquireCurrent() orelse {
            return .{ .rejected = .unknown_key };
        };
        defer snapshot.release();

        const key = snapshot.findKey(&parsed.key_id) orelse {
            return .{ .rejected = .unknown_key };
        };
        if (key.aead != parsed.aead) {
            return .{ .rejected = .authentication_failed };
        }
        switch (key.decryptWindowAt(now_unix_ms)) {
            .future => {
                return .{ .rejected = .future_key };
            },
            .active, .retained => {},
            .retired => {
                return .{ .rejected = .retired_key };
            },
        }
        if (!self.provider.capabilities().supportsAead(key.aead)) return error.UnsupportedCapability;

        const plaintext = allocator.alloc(u8, parsed.ciphertext.len) catch return error.OutOfMemory;
        defer {
            zeroAndFree(allocator, plaintext);
        }

        var aad: [aad_prefix.len + fixed_header_len]u8 = undefined;
        buildAad(parsed.header, &aad);
        self.provider.aeadOpen(key.aead, key.key.slice(), &parsed.nonce, &aad, parsed.ciphertext, parsed.tag, plaintext) catch |err| switch (err) {
            error.AuthenticationFailed => {
                return .{ .rejected = .authentication_failed };
            },
            error.UnsupportedCapability => return error.UnsupportedCapability,
            error.InvalidInput => return error.InvalidInternalState,
        };

        var decoded = session.decode(allocator, self.limits, plaintext) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvalidLimits => return error.InvalidInternalState,
            else => {
                return .{ .rejected = .invalid_plaintext };
            },
        };
        defer decoded.deinit();

        var recovered = switch (decoded) {
            .server => |*server_state| server_state,
            .client => {
                return .{ .rejected = .invalid_plaintext };
            },
        };
        if (recovered.common.isNotYetValid(now_unix_ms)) {
            return .{ .rejected = .not_yet_valid };
        }
        if (recovered.common.isExpired(now_unix_ms)) {
            return .{ .rejected = .expired };
        }

        out.moveFrom(recovered);
        return .accepted;
    }

    fn record(self: *Protector, event: Event) void {
        if (self.observer) |observer| observer.record(event);
    }
};

pub const ServerPskResolverAdapter = struct {
    protector: *Protector,
    allocator: std.mem.Allocator,
    now_unix_ms: i64,

    pub fn resolver(self: *ServerPskResolverAdapter) pre_shared_key.ServerPskResolver {
        return .{
            .ctx = self,
            .nowUnixMsFn = nowUnixMs,
            .resolveFn = resolve,
        };
    }

    fn nowUnixMs(ctx: *anyopaque) i64 {
        const self: *ServerPskResolverAdapter = @ptrCast(@alignCast(ctx));
        return self.now_unix_ms;
    }

    fn resolve(ctx: *anyopaque, identity: []const u8) pre_shared_key.ResolveError!pre_shared_key.ServerPskResolveResult {
        const self: *ServerPskResolverAdapter = @ptrCast(@alignCast(ctx));
        var out: session.ServerRecoverableState = .{};
        const found = self.protector.resolve(self.allocator, identity, self.now_unix_ms, &out) catch return error.ResolverFailed;
        if (!found) return .miss;
        return .{ .hit = .{ .state = out, .lease = pre_shared_key.ServerPskLease.initNoop() } };
    }
};

fn checkedProtectedLen(plaintext_len: usize, limits: session.Limits) SealError!usize {
    if (plaintext_len > limits.max_serialized_len) return error.SerializedStateTooLarge;
    const protected_len = std.math.add(usize, fixed_header_len, plaintext_len) catch return error.TicketTooLarge;
    const total = std.math.add(usize, protected_len, tag_len) catch return error.TicketTooLarge;
    if (total > limits.max_ticket_len) return error.TicketTooLarge;
    if (total > session.absolute_ticket_wire_max) return error.TicketTooLarge;
    return total;
}

fn zeroAndFree(allocator: std.mem.Allocator, buffer: []u8) void {
    secrets.secureZeroAndFree(allocator, buffer);
}

fn ticketExpiresWithinKey(state: *const session.ServerRecoverableState, key_decrypt_until_unix_ms: i64) bool {
    const expires: i128 = @as(i128, state.common.issued_at_unix_ms) +
        @as(i128, state.common.lifetime_seconds) * 1000;
    return expires <= @as(i128, key_decrypt_until_unix_ms);
}

fn fingerprintKey(aead: provider.Aead, key: []const u8) KeyFingerprint {
    var out: KeyFingerprint = undefined;
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    defer secrets.secureZero(std.mem.asBytes(&hasher));
    hasher.update(key_fingerprint_domain);
    hasher.update(&[_]u8{encodeAeadId(aead)});
    var len_bytes: [2]u8 = undefined;
    std.mem.writeInt(u16, &len_bytes, @intCast(key.len), .big);
    hasher.update(&len_bytes);
    hasher.update(key);
    hasher.final(&out);
    return out;
}

fn writeHeader(out: []u8, aead: provider.Aead, key_id: *const KeyId, nonce: *const [provider.aead_nonce_len]u8) void {
    std.debug.assert(out.len == fixed_header_len);
    @memcpy(out[0..4], &magic);
    out[4] = format_version;
    out[5] = encodeAeadId(aead);
    std.mem.writeInt(u16, out[6..8], 0, .big);
    @memcpy(out[8..24], key_id);
    @memcpy(out[24..36], nonce);
}

fn buildAad(header: []const u8, out: *[aad_prefix.len + fixed_header_len]u8) void {
    std.debug.assert(header.len == fixed_header_len);
    @memcpy(out[0..aad_prefix.len], aad_prefix);
    @memcpy(out[aad_prefix.len..], header);
}

fn rangesOverlap(a_start: u64, a_end: u64, b_start: u64, b_end: u64) bool {
    return a_start < b_end and b_start < a_end;
}

fn parseReason(err: ParseError) ResolveRejectReason {
    return switch (err) {
        error.MalformedEnvelope => .malformed_envelope,
        error.UnsupportedVersion => .unsupported_version,
        error.UnsupportedAeadId => .unsupported_aead,
        error.EnvelopeTooLarge => .envelope_too_large,
    };
}

fn sealReason(err: SealError) SealRejectReason {
    return switch (err) {
        error.NoActiveEncryptionKey => .no_active_encryption_key,
        error.AmbiguousActiveEncryptionKey => .ambiguous_active_encryption_key,
        error.TicketOutlivesKey => .ticket_outlives_key,
        error.NonceLeaseExhausted => .nonce_lease_exhausted,
        error.SerializedStateTooLarge => .serialized_state_too_large,
        error.TicketTooLarge => .ticket_too_large,
        error.OutputTooSmall => .output_too_small,
        error.UnsupportedCapability => .unsupported_capability,
        error.InvalidInternalState => .invalid_internal_state,
        error.OutOfMemory => .out_of_memory,
    };
}

fn resolveErrorReason(err: ResolveError) ResolveRejectReason {
    return switch (err) {
        error.UnsupportedCapability => .unsupported_capability,
        error.InvalidInternalState => .invalid_internal_state,
        error.OutOfMemory => .out_of_memory,
    };
}

fn snapshotReason(err: SnapshotError) SnapshotRejectReason {
    return switch (err) {
        error.TooManyKeys => .too_many_keys,
        error.DuplicateKeyId => .duplicate_key_id,
        error.InvalidKeyLength => .invalid_key_length,
        error.UnsupportedCapability => .unsupported_capability,
        error.InvalidValidityWindow => .invalid_validity_window,
        error.InvalidNonceLease => .invalid_nonce_lease,
        error.OverlappingNonceLease => .overlapping_nonce_lease,
        error.AmbiguousEncryptionWindow => .ambiguous_encryption_window,
        error.StaleSnapshotGeneration => .stale_generation,
        error.GenerationOverflow => .generation_overflow,
        error.OutOfMemory => .out_of_memory,
    };
}

const SpinMutex = struct {
    state: std.atomic.Value(u8) = std.atomic.Value(u8).init(0),

    fn lock(self: *SpinMutex) void {
        while (self.state.cmpxchgStrong(0, 1, .acquire, .monotonic) != null) {
            std.atomic.spinLoopHint();
        }
    }

    fn unlock(self: *SpinMutex) void {
        self.state.store(0, .release);
    }
};

const testing = std.testing;

fn testCapabilities() provider.Capabilities {
    var caps = provider.Capabilities{};
    caps.aeads.insert(.aes_128_gcm);
    caps.aeads.insert(.aes_256_gcm);
    caps.aeads.insert(.chacha20_poly1305);
    return caps;
}

fn testProvider() provider.CryptoProvider {
    const pure_zig = crypto.pure_zig;
    const Static = struct {
        var entropy_buf = [_]u8{0x42} ** 256;
        var entropy = std.Random.DefaultPrng.init(1);
        var provider_state = pure_zig.Provider.init(.{
            .context = &entropy,
            .fillFn = fill,
        });

        fn fill(ctx: *anyopaque, out: []u8) provider.EntropyError!void {
            _ = &entropy_buf;
            const prng: *std.Random.DefaultPrng = @ptrCast(@alignCast(ctx));
            prng.random().bytes(out);
        }
    };
    return Static.provider_state.cryptoProvider();
}

fn keyId(byte: u8) KeyId {
    return [_]u8{byte} ** key_id_len;
}

fn sampleKeyConfig(id: KeyId, aead: provider.Aead, lease: ?NonceLeaseConfig) KeyConfig {
    return sampleKeyConfigWithByte(id, aead, lease, switch (aead) {
        .aes_128_gcm => 0x11,
        .aes_256_gcm, .chacha20_poly1305 => 0x22,
    });
}

fn sampleKeyConfigWithByte(id: KeyId, aead: provider.Aead, lease: ?NonceLeaseConfig, byte: u8) KeyConfig {
    return .{
        .id = id,
        .aead = aead,
        .key_bytes = testKeyBytes(aead, byte),
        .not_before_unix_ms = 1_000,
        .encrypt_until_unix_ms = 5_000,
        .decrypt_until_unix_ms = 20_000,
        .nonce_lease = lease,
    };
}

fn testKeyBytes(aead: provider.Aead, byte: u8) []const u8 {
    return switch (aead) {
        .aes_128_gcm => switch (byte) {
            0x10 => &([_]u8{0x10} ** 16),
            0x11 => &([_]u8{0x11} ** 16),
            0x13 => &([_]u8{0x13} ** 16),
            else => &([_]u8{0x22} ** 16),
        },
        .aes_256_gcm, .chacha20_poly1305 => switch (byte) {
            0x22 => &([_]u8{0x22} ** 32),
            else => &([_]u8{0x33} ** 32),
        },
    };
}

fn sampleServerState(allocator: std.mem.Allocator) !session.ServerRecoverableState {
    var common: session.ResumableSessionCommon = .{};
    try common.init(allocator, session.Limits.default, .{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .resumption_psk = &([_]u8{0xab} ** 32),
        .server_name = "Example.TEST",
        .application_protocol = "h3",
        .auth_binding = session.AuthBinding.fromLeafCertificateDer("leaf"),
        .issued_at_unix_ms = 1_000,
        .lifetime_seconds = 10,
        .early_data = .resume_only,
        .transport_compat = .{ .format_id = 1, .format_version = 1, .bytes = "transport" },
    });
    var state: session.ServerRecoverableState = .{};
    state.init(&common, 0x11223344);
    return state;
}

fn sentinelServerState(allocator: std.mem.Allocator) !session.ServerRecoverableState {
    var common: session.ResumableSessionCommon = .{};
    try common.init(allocator, session.Limits.default, .{
        .cipher_suite = .tls_chacha20_poly1305_sha256,
        .resumption_psk = &([_]u8{0xcd} ** 32),
        .server_name = "sentinel.example.test",
        .application_protocol = "http/1.1",
        .auth_binding = session.AuthBinding.fromLeafCertificateDer("sentinel-leaf"),
        .issued_at_unix_ms = 777,
        .lifetime_seconds = 123,
        .early_data = .{ .early_data_capable = 99 },
        .transport_compat = .{ .format_id = 7, .format_version = 2, .bytes = "sentinel-transport" },
        .application_compat = .{ .format_id = 8, .format_version = 3, .bytes = "sentinel-application" },
        .early_data_transport_compat = .{ .format_id = 9, .format_version = 4, .bytes = "sentinel-early-transport" },
        .early_data_application_compat = .{ .format_id = 10, .format_version = 5, .bytes = "sentinel-early-application" },
    });
    var state: session.ServerRecoverableState = .{};
    state.init(&common, 0x55667788);
    return state;
}

const TestObserver = struct {
    events: std.ArrayList(Event) = .empty,

    fn deinit(self: *TestObserver, allocator: std.mem.Allocator) void {
        self.events.deinit(allocator);
    }

    fn observer(self: *TestObserver) Observer {
        return .{ .ctx = self, .recordFn = record };
    }

    fn record(ctx: *anyopaque, event: Event) void {
        const self: *TestObserver = @ptrCast(@alignCast(ctx));
        self.events.append(testing.allocator, event) catch @panic("test observer allocation failed");
    }

    fn expectOnly(self: *const TestObserver, expected: Event) !void {
        try testing.expectEqual(@as(usize, 1), self.events.items.len);
        try testing.expectEqualDeep(expected, self.events.items[0]);
    }

    fn reset(self: *TestObserver) void {
        self.events.clearRetainingCapacity();
    }
};

const ReentrantDeinitObserver = struct {
    keyring: *ReloadableKeyRing,
    deinit_on_install: bool = true,
    deinit_on_rejection: bool = false,
    installed_events: usize = 0,
    retired_events: usize = 0,
    rejected_events: usize = 0,

    fn observer(self: *ReentrantDeinitObserver) Observer {
        return .{ .ctx = self, .recordFn = record };
    }

    fn record(ctx: *anyopaque, event: Event) void {
        const self: *ReentrantDeinitObserver = @ptrCast(@alignCast(ctx));
        switch (event) {
            .snapshot_installed => {
                self.installed_events += 1;
                if (self.deinit_on_install) {
                    self.deinit_on_install = false;
                    self.keyring.deinit();
                }
            },
            .key_retired => self.retired_events += 1,
            .snapshot_rejected => {
                self.rejected_events += 1;
                if (self.deinit_on_rejection) {
                    self.deinit_on_rejection = false;
                    self.keyring.deinit();
                }
            },
            else => {},
        }
    }
};

fn installSingleKey(
    keyring: *ReloadableKeyRing,
    id: KeyId,
    aead: provider.Aead,
    lease: NonceLeaseConfig,
    byte: u8,
) !void {
    const config = sampleKeyConfigWithByte(id, aead, lease, byte);
    try keyring.install(try keyring.buildSnapshot(&.{config}, testCapabilities()));
}

fn expectResolveFalseUnchanged(
    protector: *Protector,
    allocator: std.mem.Allocator,
    identity: []const u8,
    now_unix_ms: i64,
) !void {
    var out: session.ServerRecoverableState = .{};
    defer out.deinit();
    try testing.expect(!try protector.resolve(allocator, identity, now_unix_ms, &out));
    try testing.expectEqual(@as(u32, 0), out.ticket_age_add);
    try testing.expectEqual(@as(usize, 0), out.common.resumption_psk.len);
}

fn expectRoundTrip(
    protector: *Protector,
    allocator: std.mem.Allocator,
    state: *const session.ServerRecoverableState,
    ticket: []const u8,
    now_unix_ms: i64,
) !void {
    var recovered: session.ServerRecoverableState = .{};
    defer recovered.deinit();
    try testing.expect(try protector.resolve(allocator, ticket, now_unix_ms, &recovered));
    try testing.expectEqual(state.ticket_age_add, recovered.ticket_age_add);
    try testing.expectEqual(state.common.lifetime_seconds, recovered.common.lifetime_seconds);
    try testing.expectEqualSlices(u8, state.common.resumption_psk.slice(), recovered.common.resumption_psk.slice());
}

fn expectCompatEqual(expected: ?*const session.CompatSnapshot, actual: ?*const session.CompatSnapshot) !void {
    if (expected) |expected_snap| {
        try testing.expect(actual != null);
        try testing.expectEqual(expected_snap.format_id, actual.?.format_id);
        try testing.expectEqual(expected_snap.format_version, actual.?.format_version);
        try testing.expectEqualSlices(u8, expected_snap.slice(), actual.?.slice());
    } else {
        try testing.expect(actual == null);
    }
}

fn expectServerStateEqual(expected: *const session.ServerRecoverableState, actual: *const session.ServerRecoverableState) !void {
    try testing.expectEqual(expected.ticket_age_add, actual.ticket_age_add);
    try testing.expectEqual(expected.common.cipher_suite, actual.common.cipher_suite);
    try testing.expectEqual(expected.common.server_name == null, actual.common.server_name == null);
    if (expected.common.server_name) |expected_sni|
        try testing.expectEqualSlices(u8, expected_sni.slice(), actual.common.server_name.?.slice());
    try testing.expectEqual(expected.common.application_protocol == null, actual.common.application_protocol == null);
    if (expected.common.application_protocol) |expected_alpn|
        try testing.expectEqualSlices(u8, expected_alpn.slice(), actual.common.application_protocol.?.slice());
    try testing.expectEqualSlices(u8, &expected.common.auth_binding.bytes, &actual.common.auth_binding.bytes);
    try testing.expectEqual(expected.common.issued_at_unix_ms, actual.common.issued_at_unix_ms);
    try testing.expectEqual(expected.common.lifetime_seconds, actual.common.lifetime_seconds);
    try testing.expectEqualDeep(expected.common.early_data, actual.common.early_data);
    try testing.expectEqualSlices(u8, expected.common.resumption_psk.slice(), actual.common.resumption_psk.slice());
    try expectCompatEqual(if (expected.common.transport_compat) |*snap| snap else null, if (actual.common.transport_compat) |*snap| snap else null);
    try expectCompatEqual(if (expected.common.application_compat) |*snap| snap else null, if (actual.common.application_compat) |*snap| snap else null);
    try expectCompatEqual(if (expected.common.early_data_transport_compat) |*snap| snap else null, if (actual.common.early_data_transport_compat) |*snap| snap else null);
    try expectCompatEqual(if (expected.common.early_data_application_compat) |*snap| snap else null, if (actual.common.early_data_application_compat) |*snap| snap else null);
}

pub fn fuzzTicketIdentity(allocator: std.mem.Allocator, input: []const u8) !void {
    const limits = session.Limits.default;
    _ = parseEnvelope(input, limits) catch {};

    var keyring = ReloadableKeyRing.init(allocator);
    defer keyring.deinit();
    const configs = [_]KeyConfig{
        sampleKeyConfigWithByte(keyId(0xf1), .aes_128_gcm, null, 0x11),
        sampleKeyConfigWithByte(keyId(0xf2), .aes_256_gcm, null, 0x22),
        sampleKeyConfigWithByte(keyId(0xf3), .chacha20_poly1305, null, 0x33),
    };
    keyring.install(keyring.buildSnapshot(&configs, testCapabilities()) catch return) catch return;

    var protector = Protector{ .provider = testProvider(), .keyring = &keyring, .limits = limits };
    var out = try sentinelServerState(allocator);
    defer out.deinit();
    var expected: session.ServerRecoverableState = .{};
    try out.cloneInto(allocator, &expected);
    defer expected.deinit();

    const result = protector.resolve(allocator, input, 2_000, &out);
    if (result) |found| {
        if (!found) try expectServerStateEqual(&expected, &out);
    } else |_| {
        try expectServerStateEqual(&expected, &out);
    }
}

const snapshot_fuzz_control_len = 4;
const snapshot_fuzz_config_stride = 28;
const SnapshotFuzzOutcome = enum {
    build_success,
    too_many_keys,
    duplicate_key_id,
    invalid_key_length,
    unsupported_capability,
    invalid_validity_window,
    invalid_nonce_lease,
    ambiguous_encryption_window,
    stale_generation,
    generation_overflow,
    non_overlapping_nonce_lease,
    overlapping_nonce_lease,
};

pub fn fuzzSnapshotConfig(allocator: std.mem.Allocator, input: []const u8) !void {
    var key_storage: [max_keys + 1][provider.max_aead_key_len + 1]u8 = undefined;
    var configs: [max_keys + 1]KeyConfig = undefined;
    const configs_slice = decodeSnapshotFuzzConfigs(input, &key_storage, &configs);
    const caps = fuzzCapabilities(input);
    const generation = fuzzGeneration(input);
    const mode = fuzzMode(input);

    const snapshot = Snapshot.build(allocator, configs_slice, generation, caps) catch {
        try expectPartialBuildWipesCopiedKey(input);
        try expectBuildErrorLeavesPublicationUnchanged(allocator, configs_slice, generation, caps);
        return;
    };
    defer snapshot.release();

    try testing.expect(configs_slice.len >= 1 and configs_slice.len <= max_keys);
    try testing.expectEqual(configs_slice.len, snapshot.keys.len);
    for (snapshot.keys) |*key| {
        try testing.expect(caps.supportsAead(key.aead));
        try testing.expectEqual(key.aead.keyLength(), key.key.len);
        try testing.expect(key.not_before_unix_ms < key.encrypt_until_unix_ms);
        try testing.expect(key.encrypt_until_unix_ms <= key.decrypt_until_unix_ms);
        if (key.nonce_lease) |*lease| {
            try testing.expect(lease.next_counter.load(.acquire) < lease.currentEnd());
        }
    }

    if (mode == 3 and configs_slice.len > 0 and configs_slice[0].nonce_lease != null) {
        try exerciseReplacementInstall(allocator, configs_slice[0], generation, caps, false);
    } else {
        try exerciseCandidateDryRun(allocator, configs_slice, generation, caps);
    }
}

fn decodeSnapshotFuzzConfigs(
    input: []const u8,
    key_storage: *[max_keys + 1][provider.max_aead_key_len + 1]u8,
    configs: *[max_keys + 1]KeyConfig,
) []KeyConfig {
    const config_count = if (input.len == 0) 0 else @as(usize, input[0] % (max_keys + 2));
    const bounded_count = @min(config_count, configs.len);
    for (configs.*[0..bounded_count], 0..) |*config, i| {
        const base = snapshot_fuzz_control_len + i * snapshot_fuzz_config_stride;
        const aead = fuzzAead(byteAt(input, base));
        const exact_len = aead.keyLength();
        const len = switch (byteAt(input, base + 1) % 5) {
            0 => 0,
            1 => exact_len - 1,
            2 => exact_len,
            3 => exact_len + 1,
            else => @min(provider.max_aead_key_len + 1, exact_len + (byteAt(input, base + 2) % 3)),
        };
        for (key_storage.*[i][0..], 0..) |*byte, j| {
            byte.* = @truncate(byteAt(input, base + 3) +% @as(u8, @truncate(i * 17 + j)));
        }

        const time_case = byteAt(input, base + 4) % 8;
        const not_before, const encrypt_until, const decrypt_until = fuzzWindows(time_case);

        const lease = if ((byteAt(input, base + 5) & 0x01) == 0)
            null
        else
            fuzzLease(input, base + 6);

        config.* = .{
            .id = fuzzKeyId(input, base + 12, @intCast(i)),
            .aead = aead,
            .key_bytes = key_storage.*[i][0..len],
            .not_before_unix_ms = not_before,
            .encrypt_until_unix_ms = encrypt_until,
            .decrypt_until_unix_ms = decrypt_until,
            .nonce_lease = lease,
        };
    }

    if (config_count > 1) {
        switch (fuzzMode(input)) {
            0 => configs.*[1].id = configs.*[0].id,
            1 => configs.*[1].key_bytes = configs.*[0].key_bytes,
            2 => {
                configs.*[1].nonce_lease = configs.*[0].nonce_lease;
                configs.*[1].not_before_unix_ms = configs.*[0].not_before_unix_ms;
                configs.*[1].encrypt_until_unix_ms = configs.*[0].encrypt_until_unix_ms;
            },
            else => {},
        }
    }
    return configs.*[0..bounded_count];
}

fn exerciseCandidateDryRun(
    allocator: std.mem.Allocator,
    configs: []const KeyConfig,
    generation: u64,
    caps: provider.Capabilities,
) !void {
    var keyring = ReloadableKeyRing.init(allocator);
    defer keyring.deinit();
    const current = sampleKeyConfigWithByte(keyId(0xee), .aes_128_gcm, .{ .prefix = .{ 0xee, 0, 0, 0 }, .start = 0, .end_exclusive = 4 }, 0x11);
    try keyring.install(try keyring.buildSnapshot(&.{current}, testCapabilities()));
    const before = captureKeyringState(&keyring);

    const candidate = Snapshot.build(allocator, configs, generation, caps) catch return;
    keyring.validateInstallCandidate(candidate) catch {
        candidate.release();
        try expectKeyringStateEqual(before, &keyring);
        return;
    };
    candidate.release();
}

fn exerciseReplacementInstall(
    allocator: std.mem.Allocator,
    candidate_config: KeyConfig,
    generation: u64,
    caps: provider.Capabilities,
    comptime expect_overlap: bool,
) !void {
    if (!caps.supportsAead(candidate_config.aead)) return;
    if (candidate_config.key_bytes.len != candidate_config.aead.keyLength()) return;
    const candidate_lease = candidate_config.nonce_lease orelse return;
    if (candidate_lease.start >= candidate_lease.end_exclusive) return;
    if (!expect_overlap) {
        if (candidate_lease.start == 0) return;
        if (generation == 1 or generation == std.math.maxInt(u64)) return;
    }

    var keyring = ReloadableKeyRing.init(allocator);
    defer keyring.deinit();

    const baseline_end = if (expect_overlap)
        candidate_lease.end_exclusive
    else
        candidate_lease.start;
    var baseline = candidate_config;
    baseline.nonce_lease = .{
        .prefix = candidate_lease.prefix,
        .start = 0,
        .end_exclusive = baseline_end,
    };
    baseline.not_before_unix_ms = 0;
    baseline.encrypt_until_unix_ms = 1_000;
    baseline.decrypt_until_unix_ms = 20_000;
    try keyring.install(try keyring.buildSnapshot(&.{baseline}, caps));
    const before = captureKeyringState(&keyring);

    const candidate = try Snapshot.build(allocator, &.{candidate_config}, generation, caps);
    keyring.install(candidate) catch |err| {
        if (expect_overlap) try testing.expectEqual(error.OverlappingNonceLease, err);
        try expectKeyringStateEqual(before, &keyring);
        return;
    };
    if (expect_overlap) return error.TestUnexpectedResult;
    try testing.expect(keyring.current != before.current);
    try testing.expect(keyring.current != null);
    try testing.expectEqual(candidate_config.id, keyring.current.?.keys[0].id);
}

const KeyringState = struct {
    current: ?*Snapshot,
    current_generation: u64,
    next_generation: u64,
    ledger_len: usize,
    current_key_count: usize,
    ledger_count: usize,
    current_keys: [max_keys]KeyState = undefined,
    ledger_entries: [max_keys + 4]LedgerState = undefined,
};

const KeyState = struct {
    id: KeyId,
    aead: provider.Aead,
    not_before_unix_ms: i64,
    encrypt_until_unix_ms: i64,
    decrypt_until_unix_ms: i64,
    lease: LeaseState,
};

const LeaseState = struct {
    key_id: KeyId = [_]u8{0} ** key_id_len,
    prefix: [4]u8 = [_]u8{0} ** 4,
    next_counter: u64 = 0,
    end_exclusive: u64 = 0,
    has_lease: bool = false,
};

const LedgerState = struct {
    lease: LeaseState,
    aead: provider.Aead,
    key_fingerprint: KeyFingerprint,
};

fn captureKeyringState(keyring: *ReloadableKeyRing) KeyringState {
    var state = KeyringState{
        .current = keyring.current,
        .current_generation = if (keyring.current) |current| current.generation else 0,
        .next_generation = keyring.next_generation,
        .ledger_len = keyring.ledger.items.len,
        .current_key_count = 0,
        .ledger_count = 0,
    };
    if (keyring.current) |current| {
        std.debug.assert(current.keys.len <= state.current_keys.len);
        state.current_key_count = current.keys.len;
        for (current.keys, 0..) |*key, i| {
            state.current_keys[i] = .{
                .id = key.id,
                .aead = key.aead,
                .not_before_unix_ms = key.not_before_unix_ms,
                .encrypt_until_unix_ms = key.encrypt_until_unix_ms,
                .decrypt_until_unix_ms = key.decrypt_until_unix_ms,
                .lease = leaseStateFromKey(key),
            };
        }
    }
    std.debug.assert(keyring.ledger.items.len <= state.ledger_entries.len);
    state.ledger_count = keyring.ledger.items.len;
    for (keyring.ledger.items, 0..) |entry, i| {
        state.ledger_entries[i] = .{
            .lease = .{
                .key_id = entry.key_id,
                .prefix = entry.prefix,
                .next_counter = 0,
                .end_exclusive = entry.end_exclusive,
                .has_lease = entry.has_lease,
            },
            .aead = entry.aead,
            .key_fingerprint = entry.key_fingerprint,
        };
    }
    return state;
}

fn expectKeyringStateEqual(expected: KeyringState, keyring: *ReloadableKeyRing) !void {
    try testing.expectEqual(expected.current, keyring.current);
    try testing.expectEqual(expected.current_generation, if (keyring.current) |current| current.generation else 0);
    try testing.expectEqual(expected.next_generation, keyring.next_generation);
    try testing.expectEqual(expected.ledger_len, keyring.ledger.items.len);
    try testing.expectEqual(expected.current_key_count, if (keyring.current) |current| current.keys.len else 0);
    if (keyring.current) |current| {
        for (current.keys, 0..) |*key, i| {
            try expectKeyStateEqual(expected.current_keys[i], key);
        }
    }
    try testing.expectEqual(expected.ledger_count, keyring.ledger.items.len);
    for (keyring.ledger.items, 0..) |entry, i| {
        try expectLedgerStateEqual(expected.ledger_entries[i], entry);
    }
}

fn leaseStateFromKey(key: *const KeyRecord) LeaseState {
    if (key.nonce_lease) |*lease| {
        return .{
            .key_id = key.id,
            .prefix = lease.prefix,
            .next_counter = lease.next_counter.load(.acquire),
            .end_exclusive = lease.currentEnd(),
            .has_lease = true,
        };
    }
    return .{ .key_id = key.id };
}

fn expectKeyStateEqual(expected: KeyState, key: *const KeyRecord) !void {
    try testing.expectEqualSlices(u8, &expected.id, &key.id);
    try testing.expectEqual(expected.aead, key.aead);
    try testing.expectEqual(expected.not_before_unix_ms, key.not_before_unix_ms);
    try testing.expectEqual(expected.encrypt_until_unix_ms, key.encrypt_until_unix_ms);
    try testing.expectEqual(expected.decrypt_until_unix_ms, key.decrypt_until_unix_ms);
    try expectLeaseStateEqual(expected.lease, leaseStateFromKey(key));
}

fn expectLedgerStateEqual(expected: LedgerState, entry: *const LeaseHighWater) !void {
    try expectLeaseStateEqual(expected.lease, .{
        .key_id = entry.key_id,
        .prefix = entry.prefix,
        .next_counter = 0,
        .end_exclusive = entry.end_exclusive,
        .has_lease = entry.has_lease,
    });
    try testing.expectEqual(expected.aead, entry.aead);
    try testing.expectEqualSlices(u8, &expected.key_fingerprint, &entry.key_fingerprint);
}

fn expectLeaseStateEqual(expected: LeaseState, actual: LeaseState) !void {
    try testing.expectEqualSlices(u8, &expected.key_id, &actual.key_id);
    try testing.expectEqualSlices(u8, &expected.prefix, &actual.prefix);
    try testing.expectEqual(expected.next_counter, actual.next_counter);
    try testing.expectEqual(expected.end_exclusive, actual.end_exclusive);
    try testing.expectEqual(expected.has_lease, actual.has_lease);
}

fn expectBuildErrorLeavesPublicationUnchanged(
    allocator: std.mem.Allocator,
    configs: []const KeyConfig,
    _: u64,
    caps: provider.Capabilities,
) !void {
    var keyring = ReloadableKeyRing.init(allocator);
    defer keyring.deinit();
    const current = sampleKeyConfigWithByte(keyId(0xed), .aes_128_gcm, .{ .prefix = .{ 0xed, 0, 0, 0 }, .start = 0, .end_exclusive = 4 }, 0x11);
    try keyring.install(try keyring.buildSnapshot(&.{current}, testCapabilities()));
    const before = captureKeyringState(&keyring);

    const candidate = keyring.buildSnapshot(configs, caps) catch {
        try expectKeyringStateEqual(before, &keyring);
        return;
    };
    candidate.release();
    try expectKeyringStateEqual(before, &keyring);
}

fn expectPartialBuildWipesCopiedKey(input: []const u8) !void {
    var key_storage: [max_keys + 1][provider.max_aead_key_len + 1]u8 = undefined;
    var configs: [max_keys + 1]KeyConfig = undefined;
    const configs_slice = decodeSnapshotFuzzConfigs(input, &key_storage, &configs);
    const caps = fuzzCapabilities(input);
    const generation = fuzzGeneration(input);
    const expected_deinit_count = initializedPrefixBeforeBuildFailure(configs_slice, caps);
    if (expected_deinit_count == 0) return;

    var probe = KeyDeinitProbe{};
    test_key_deinit_probe = &probe;
    defer test_key_deinit_probe = null;

    const snapshot = Snapshot.build(testing.allocator, configs_slice, generation, caps) catch {
        try testing.expectEqual(expected_deinit_count, probe.observed);
        return;
    };
    snapshot.release();
}

fn initializedPrefixBeforeBuildFailure(configs: []const KeyConfig, caps: provider.Capabilities) usize {
    var initialized: usize = 0;
    for (configs, 0..) |config, i| {
        for (configs[0..i]) |prior| {
            if (std.mem.eql(u8, &prior.id, &config.id)) return initialized;
            if (prior.aead == config.aead and std.mem.eql(u8, prior.key_bytes, config.key_bytes)) return initialized;
        }
        if (!caps.supportsAead(config.aead)) return initialized;
        if (config.key_bytes.len != config.aead.keyLength()) return initialized;
        if (!(config.not_before_unix_ms < config.encrypt_until_unix_ms and
            config.encrypt_until_unix_ms <= config.decrypt_until_unix_ms)) return initialized;
        if (config.nonce_lease) |lease| {
            if (lease.start >= lease.end_exclusive) return initialized;
        }
        initialized += 1;
    }
    return 0;
}

fn byteAt(input: []const u8, idx: usize) u8 {
    return if (idx < input.len) input[idx] else 0;
}

fn fuzzAead(byte: u8) provider.Aead {
    return switch (byte % 3) {
        0 => .aes_128_gcm,
        1 => .aes_256_gcm,
        else => .chacha20_poly1305,
    };
}

fn fuzzKeyId(input: []const u8, offset: usize, fallback: u8) KeyId {
    var id = [_]u8{fallback} ** key_id_len;
    for (&id, 0..) |*byte, i| {
        byte.* = byteAt(input, offset + i);
    }
    return id;
}

fn fuzzWindows(case: u8) struct { i64, i64, i64 } {
    return switch (case) {
        0 => .{ 0, 1, 1 },
        1 => .{ 1_000, 5_000, 20_000 },
        2 => .{ 5_000, 5_000, 20_000 },
        3 => .{ 5_000, 4_999, 20_000 },
        4 => .{ 1_000, 20_000, 19_999 },
        5 => .{ std.math.minInt(i64), -1, 0 },
        6 => .{ std.math.maxInt(i64) - 2, std.math.maxInt(i64) - 1, std.math.maxInt(i64) },
        else => .{ 1_000, 5_000, 5_000 },
    };
}

fn fuzzLease(input: []const u8, offset: usize) NonceLeaseConfig {
    const start, const end = switch (byteAt(input, offset + 4) % 7) {
        0 => .{ @as(u64, 0), @as(u64, 1) },
        1 => .{ @as(u64, 0), @as(u64, 0) },
        2 => .{ @as(u64, 2), @as(u64, 1) },
        3 => .{ std.math.maxInt(u64) - 1, std.math.maxInt(u64) },
        4 => .{ std.math.maxInt(u64), std.math.maxInt(u64) },
        5 => .{ @as(u64, 65_534), @as(u64, 65_535) },
        else => .{ @as(u64, byteAt(input, offset + 5)), @as(u64, byteAt(input, offset + 5)) + 2 },
    };
    return .{
        .prefix = .{
            byteAt(input, offset),
            byteAt(input, offset + 1),
            byteAt(input, offset + 2),
            byteAt(input, offset + 3),
        },
        .start = start,
        .end_exclusive = end,
    };
}

fn fuzzCapabilities(input: []const u8) provider.Capabilities {
    if (input.len > 1 and (input[1] & 0x01) != 0) return testCapabilities();
    var caps = provider.Capabilities{};
    if (input.len > 1 and (input[1] & 0x02) != 0) caps.aeads.insert(.aes_128_gcm);
    if (input.len > 1 and (input[1] & 0x04) != 0) caps.aeads.insert(.aes_256_gcm);
    if (input.len > 1 and (input[1] & 0x08) != 0) caps.aeads.insert(.chacha20_poly1305);
    return caps;
}

fn fuzzMode(input: []const u8) u8 {
    return if (input.len > 2) input[2] % 4 else 3;
}

fn fuzzGeneration(input: []const u8) u64 {
    if (input.len < 4) return 0;
    return switch (input[3] % 5) {
        0 => 0,
        1 => 1,
        2 => std.math.maxInt(u64) - 1,
        3 => std.math.maxInt(u64),
        else => std.mem.readInt(u16, input[0..2], .big),
    };
}

fn expectKeyringStillPublishesCurrent(allocator: std.mem.Allocator) !void {
    var keyring = ReloadableKeyRing.init(allocator);
    defer keyring.deinit();
    const current = sampleKeyConfigWithByte(keyId(0xed), .aes_128_gcm, .{ .prefix = .{ 0xed, 0, 0, 0 }, .start = 0, .end_exclusive = 4 }, 0x11);
    try keyring.install(try keyring.buildSnapshot(&.{current}, testCapabilities()));
    const before_current = keyring.current.?;
    const before_generation = before_current.generation;
    try testing.expectError(error.TooManyKeys, keyring.buildSnapshot(&.{}, testCapabilities()));
    try testing.expectEqual(before_current, keyring.current.?);
    try testing.expectEqual(before_generation, keyring.current.?.generation);
}

const ConcurrentSealTask = struct {
    protector: *Protector,
    state: *const session.ServerRecoverableState,
    start: *std.atomic.Value(bool),
    successes: *std.atomic.Value(usize),
    failures: *std.atomic.Value(usize),
    nonces: *[32][provider.aead_nonce_len]u8,

    fn run(self: *ConcurrentSealTask) void {
        while (!self.start.load(.acquire)) std.atomic.spinLoopHint();
        var ticket_buf = [_]u8{0} ** 512;
        const ticket = self.protector.seal(testing.allocator, self.state, 2_000, &ticket_buf) catch {
            _ = self.failures.fetchAdd(1, .monotonic);
            return;
        };
        const slot = self.successes.fetchAdd(1, .monotonic);
        if (slot < self.nonces.len) @memcpy(&self.nonces[slot], ticket[24..36]);
    }
};

const ZeroCheckingAllocator = struct {
    child: std.mem.Allocator,
    free_count: usize = 0,

    fn init(child: std.mem.Allocator) ZeroCheckingAllocator {
        return .{ .child = child };
    }

    fn allocator(self: *ZeroCheckingAllocator) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *ZeroCheckingAllocator = @ptrCast(@alignCast(ctx));
        return self.child.rawAlloc(len, alignment, ret_addr);
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *ZeroCheckingAllocator = @ptrCast(@alignCast(ctx));
        return self.child.rawResize(memory, alignment, new_len, ret_addr);
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *ZeroCheckingAllocator = @ptrCast(@alignCast(ctx));
        return self.child.rawRemap(memory, alignment, new_len, ret_addr);
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *ZeroCheckingAllocator = @ptrCast(@alignCast(ctx));
        for (memory) |byte| {
            if (byte != 0) @panic("secret-bearing allocation was not zeroized before free");
        }
        self.free_count += 1;
        self.child.rawFree(memory, alignment, ret_addr);
    }

    const vtable = std.mem.Allocator.VTable{
        .alloc = alloc,
        .resize = resize,
        .remap = remap,
        .free = free,
    };
};

fn buildAuthenticatedEnvelope(
    out: []u8,
    aead: provider.Aead,
    key_id: KeyId,
    key: []const u8,
    nonce: [provider.aead_nonce_len]u8,
    plaintext: []const u8,
) ![]const u8 {
    const protected_len = envelope_overhead + plaintext.len;
    if (out.len < protected_len) return error.BufferTooSmall;
    writeHeader(out[0..fixed_header_len], aead, &key_id, &nonce);
    var aad: [aad_prefix.len + fixed_header_len]u8 = undefined;
    buildAad(out[0..fixed_header_len], &aad);
    const ciphertext = out[fixed_header_len .. fixed_header_len + plaintext.len];
    const tag = out[fixed_header_len + plaintext.len .. protected_len];
    try testProvider().aeadSeal(aead, key, &nonce, &aad, plaintext, ciphertext, tag);
    return out[0..protected_len];
}

fn buildProtectedTicketSeed(
    allocator: std.mem.Allocator,
    aead: provider.Aead,
    id: KeyId,
    key_byte: u8,
    nonce_prefix: [4]u8,
    out: []u8,
) ![]const u8 {
    var keyring = ReloadableKeyRing.init(allocator);
    defer keyring.deinit();
    try installSingleKey(&keyring, id, aead, .{ .prefix = nonce_prefix, .start = 0, .end_exclusive = 1 }, key_byte);

    var state = try sampleServerState(allocator);
    defer state.deinit();
    var protector = Protector{ .provider = testProvider(), .keyring = &keyring, .limits = session.Limits.default };
    return try protector.seal(allocator, &state, 2_000, out);
}

test "AEAD id mapping is stable and not enum ordinal dependent" {
    try testing.expectEqual(@as(u8, 1), encodeAeadId(.aes_128_gcm));
    try testing.expectEqual(@as(u8, 2), encodeAeadId(.aes_256_gcm));
    try testing.expectEqual(@as(u8, 3), encodeAeadId(.chacha20_poly1305));
    try testing.expectEqual(provider.Aead.aes_128_gcm, try decodeAeadId(1));
    try testing.expectEqual(provider.Aead.aes_256_gcm, try decodeAeadId(2));
    try testing.expectEqual(provider.Aead.chacha20_poly1305, try decodeAeadId(3));
    try testing.expectError(error.UnsupportedAeadId, decodeAeadId(0));
}

test "secret-bearing ticket protection types expose no ordinary formatting path" {
    try testing.expect(@hasDecl(KeyRecord, "format"));
    try testing.expect(@hasDecl(Snapshot, "format"));
    try testing.expect(@hasDecl(ReloadableKeyRing, "format"));
}

test "parseEnvelope validates public structure without allocation" {
    var identity = [_]u8{0} ** (fixed_header_len + 1 + tag_len);
    writeHeader(identity[0..fixed_header_len], .aes_128_gcm, &keyId(7), &([_]u8{0x33} ** provider.aead_nonce_len));
    identity[fixed_header_len] = 1;
    const parsed = try parseEnvelope(&identity, session.Limits.default);
    try testing.expectEqual(provider.Aead.aes_128_gcm, parsed.aead);
    try testing.expectEqual(@as(usize, 1), parsed.ciphertext.len);
    try testing.expectEqual(@as(usize, tag_len), parsed.tag.len);

    identity[0] = 'x';
    try testing.expectError(error.MalformedEnvelope, parseEnvelope(&identity, session.Limits.default));
    identity[0] = 'T';
    identity[4] = 2;
    try testing.expectError(error.UnsupportedVersion, parseEnvelope(&identity, session.Limits.default));
    identity[4] = format_version;
    identity[5] = 99;
    try testing.expectError(error.UnsupportedAeadId, parseEnvelope(&identity, session.Limits.default));
    identity[5] = encodeAeadId(.aes_128_gcm);
    identity[7] = 1;
    try testing.expectError(error.MalformedEnvelope, parseEnvelope(&identity, session.Limits.default));
}

test "fuzz: ticket identity parsing and miss resolution never panic or mutate output" {
    var aes128_seed_buf = [_]u8{0} ** 512;
    var aes256_seed_buf = [_]u8{0} ** 512;
    var chacha_seed_buf = [_]u8{0} ** 512;
    const aes128_seed = try buildProtectedTicketSeed(testing.allocator, .aes_128_gcm, keyId(0xf1), 0x11, .{ 0xf1, 0, 0, 0 }, &aes128_seed_buf);
    const aes256_seed = try buildProtectedTicketSeed(testing.allocator, .aes_256_gcm, keyId(0xf2), 0x22, .{ 0xf2, 0, 0, 0 }, &aes256_seed_buf);
    const chacha_seed = try buildProtectedTicketSeed(testing.allocator, .chacha20_poly1305, keyId(0xf3), 0x33, .{ 0xf3, 0, 0, 0 }, &chacha_seed_buf);

    var corpus = [_][]const u8{
        "",
        "TDTK",
        "TDTK\x01\x01\x00\x00",
        &([_]u8{0} ** (fixed_header_len + tag_len)),
        &([_]u8{ 0x54, 0x44, 0x54, 0x4b, 0x01, 0x01, 0x00, 0x00 } ++ [_]u8{0x00} ** (fixed_header_len + tag_len)),
        &([_]u8{0xff} ** 256),
        aes128_seed,
        aes256_seed,
        chacha_seed,
    };
    try testing.fuzz({}, fuzzTicketIdentityInput, .{ .corpus = &corpus });
}

fn fuzzTicketIdentityInput(_: void, smith: *testing.Smith) !void {
    var input_buf: [session.absolute_ticket_wire_max + 16]u8 = undefined;
    const len = smith.slice(&input_buf);
    try fuzzTicketIdentity(testing.allocator, input_buf[0..len]);
}

test "fuzz helper preserves output on resolver allocation errors" {
    var ticket_buf = [_]u8{0} ** 512;
    const ticket = try buildProtectedTicketSeed(testing.allocator, .aes_128_gcm, keyId(0xf1), 0x11, .{ 0xf1, 0, 0, 0 }, &ticket_buf);

    var keyring = ReloadableKeyRing.init(testing.allocator);
    defer keyring.deinit();
    const config = sampleKeyConfigWithByte(keyId(0xf1), .aes_128_gcm, null, 0x11);
    try keyring.install(try keyring.buildSnapshot(&.{config}, testCapabilities()));
    var protector = Protector{ .provider = testProvider(), .keyring = &keyring, .limits = session.Limits.default };

    var out = try sentinelServerState(testing.allocator);
    defer out.deinit();
    var expected: session.ServerRecoverableState = .{};
    try out.cloneInto(testing.allocator, &expected);
    defer expected.deinit();

    var plaintext_failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    try testing.expectError(error.OutOfMemory, protector.resolve(plaintext_failing.allocator(), ticket, 2_000, &out));
    try expectServerStateEqual(&expected, &out);

    var decode_failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 1 });
    try testing.expectError(error.OutOfMemory, protector.resolve(decode_failing.allocator(), ticket, 2_000, &out));
    try expectServerStateEqual(&expected, &out);
}

test "fuzz: ticket snapshot configs preserve bounded build invariants" {
    var empty_config_count = snapshotSeed(0, 0xff, 3, 0);
    var exact_one_aes128 = snapshotSeed(1, 0xff, 3, 0);
    writeSnapshotSeedRecord(&exact_one_aes128, 0, .{ .aead = 0, .key_seed = 0x10, .id_seed = 0x10 });
    var exact_one_aes256 = snapshotSeed(1, 0xff, 3, 0);
    writeSnapshotSeedRecord(&exact_one_aes256, 0, .{ .aead = 1, .key_seed = 0x20, .id_seed = 0x20 });
    var exact_one_chacha = snapshotSeed(1, 0xff, 3, 0);
    writeSnapshotSeedRecord(&exact_one_chacha, 0, .{ .aead = 2, .key_seed = 0x30, .id_seed = 0x30 });

    var duplicate_id = snapshotSeed(2, 0xff, 0, 0);
    writeSnapshotSeedRecord(&duplicate_id, 0, .{ .aead = 0, .key_seed = 0x40, .id_seed = 0x40 });
    writeSnapshotSeedRecord(&duplicate_id, 1, .{ .aead = 1, .key_seed = 0x50, .id_seed = 0x50 });

    var unsupported_capability = snapshotSeed(1, 0x02, 3, 0);
    writeSnapshotSeedRecord(&unsupported_capability, 0, .{ .aead = 2, .key_seed = 0x60, .id_seed = 0x60 });

    var invalid_window = snapshotSeed(1, 0xff, 3, 0);
    writeSnapshotSeedRecord(&invalid_window, 0, .{ .aead = 0, .key_seed = 0x70, .id_seed = 0x70, .time_case = 2 });

    var invalid_lease = snapshotSeed(1, 0xff, 3, 0);
    writeSnapshotSeedRecord(&invalid_lease, 0, .{
        .aead = 0,
        .key_seed = 0x80,
        .id_seed = 0x80,
        .lease_enabled = true,
        .lease_case = 1,
    });

    var partial_build_wipe = snapshotSeed(2, 0xff, 3, 0);
    writeSnapshotSeedRecord(&partial_build_wipe, 0, .{ .aead = 0, .key_seed = 0x90, .id_seed = 0x90 });
    writeSnapshotSeedRecord(&partial_build_wipe, 1, .{ .aead = 1, .key_seed = 0xa0, .id_seed = 0xa0, .key_len_mode = 1 });

    var exact_max_keys = snapshotSeed(max_keys, 0xff, 3, 0);
    for (0..max_keys) |i| {
        writeSnapshotSeedRecord(&exact_max_keys, i, .{ .aead = @truncate(i % 3), .key_seed = @intCast(0x20 + i), .id_seed = @intCast(0x40 + i), .lease_enabled = false });
    }
    var max_plus_one_keys = snapshotSeed(max_keys + 1, 0xff, 3, 0);

    var generation_overflow = snapshotSeed(1, 0xff, 3, 3);
    writeSnapshotSeedRecord(&generation_overflow, 0, .{ .aead = 0, .key_seed = 0xb0, .id_seed = 0xb0 });

    var stale_generation = snapshotSeed(1, 0xff, 3, 1);
    writeSnapshotSeedRecord(&stale_generation, 0, .{ .aead = 0, .key_seed = 0xb8, .id_seed = 0xb8 });

    var non_overlapping_replacement_lease = snapshotSeed(1, 0xff, 3, 0);
    writeSnapshotSeedRecord(&non_overlapping_replacement_lease, 0, .{
        .aead = 0,
        .key_seed = 0xbc,
        .id_seed = 0xbc,
        .lease_enabled = true,
        .lease_case = 6,
        .lease_value = 1,
    });

    var overlapping_replacement_lease = snapshotSeed(1, 0xff, 3, 0);
    writeSnapshotSeedRecord(&overlapping_replacement_lease, 0, .{
        .aead = 0,
        .key_seed = 0xc0,
        .id_seed = 0xc0,
        .lease_enabled = true,
        .lease_case = 6,
        .lease_value = 1,
    });

    try expectSnapshotSeedOutcome(&empty_config_count, .too_many_keys);
    try expectSnapshotSeedOutcome(&exact_one_aes128, .build_success);
    try expectSnapshotSeedOutcome(&exact_one_aes256, .build_success);
    try expectSnapshotSeedOutcome(&exact_one_chacha, .build_success);
    try expectSnapshotSeedOutcome(&duplicate_id, .duplicate_key_id);
    try expectSnapshotSeedOutcome(&unsupported_capability, .unsupported_capability);
    try expectSnapshotSeedOutcome(&invalid_window, .invalid_validity_window);
    try expectSnapshotSeedOutcome(&invalid_lease, .invalid_nonce_lease);
    try expectSnapshotSeedOutcome(&partial_build_wipe, .invalid_key_length);
    try expectSnapshotSeedOutcome(&exact_max_keys, .build_success);
    try expectSnapshotSeedOutcome(&max_plus_one_keys, .too_many_keys);
    try expectSnapshotSeedOutcome(&generation_overflow, .generation_overflow);
    try expectSnapshotSeedOutcome(&stale_generation, .stale_generation);
    try expectSnapshotSeedOutcome(&non_overlapping_replacement_lease, .non_overlapping_nonce_lease);
    try expectSnapshotSeedOutcome(&overlapping_replacement_lease, .overlapping_nonce_lease);

    try testing.fuzz({}, fuzzTicketSnapshotConfigInput, .{ .corpus = &.{
        &empty_config_count,
        &exact_one_aes128,
        &exact_one_aes256,
        &exact_one_chacha,
        &duplicate_id,
        &unsupported_capability,
        &invalid_window,
        &invalid_lease,
        &partial_build_wipe,
        &exact_max_keys,
        &max_plus_one_keys,
        &generation_overflow,
        &stale_generation,
        &non_overlapping_replacement_lease,
        &overlapping_replacement_lease,
    } });
}

fn fuzzTicketSnapshotConfigInput(_: void, smith: *testing.Smith) !void {
    var input_buf: [snapshot_fuzz_control_len + (max_keys + 1) * snapshot_fuzz_config_stride]u8 = undefined;
    const len = smith.slice(&input_buf);
    try fuzzSnapshotConfig(testing.allocator, input_buf[0..len]);
}

const SnapshotSeedRecord = struct {
    aead: u8,
    key_len_mode: u8 = 2,
    key_seed: u8,
    time_case: u8 = 1,
    lease_enabled: bool = false,
    lease_prefix: [4]u8 = .{ 0xaa, 0xbb, 0xcc, 0xdd },
    lease_case: u8 = 0,
    lease_value: u8 = 0,
    id_seed: u8,
};

fn snapshotSeed(count: u8, caps: u8, mode: u8, generation_mode: u8) [snapshot_fuzz_control_len + (max_keys + 1) * snapshot_fuzz_config_stride]u8 {
    var seed = [_]u8{0} ** (snapshot_fuzz_control_len + (max_keys + 1) * snapshot_fuzz_config_stride);
    seed[0] = count;
    seed[1] = caps;
    seed[2] = mode;
    seed[3] = generation_mode;
    return seed;
}

fn writeSnapshotSeedRecord(
    seed: *[snapshot_fuzz_control_len + (max_keys + 1) * snapshot_fuzz_config_stride]u8,
    index: usize,
    record: SnapshotSeedRecord,
) void {
    const base = snapshot_fuzz_control_len + index * snapshot_fuzz_config_stride;
    seed[base] = record.aead;
    seed[base + 1] = record.key_len_mode;
    seed[base + 3] = record.key_seed;
    seed[base + 4] = record.time_case;
    seed[base + 5] = if (record.lease_enabled) 1 else 0;
    seed[base + 6] = record.lease_prefix[0];
    seed[base + 7] = record.lease_prefix[1];
    seed[base + 8] = record.lease_prefix[2];
    seed[base + 9] = record.lease_prefix[3];
    seed[base + 10] = record.lease_case;
    seed[base + 11] = record.lease_value;
    @memset(seed[base + 12 .. base + 12 + key_id_len], record.id_seed);
}

fn expectSnapshotSeedOutcome(input: []const u8, outcome: SnapshotFuzzOutcome) !void {
    var key_storage: [max_keys + 1][provider.max_aead_key_len + 1]u8 = undefined;
    var configs: [max_keys + 1]KeyConfig = undefined;
    const configs_slice = decodeSnapshotFuzzConfigs(input, &key_storage, &configs);
    const caps = fuzzCapabilities(input);
    const generation = fuzzGeneration(input);

    if (outcome == .non_overlapping_nonce_lease) {
        try testing.expect(configs_slice.len > 0);
        try exerciseReplacementInstall(testing.allocator, configs_slice[0], generation, caps, false);
        return;
    }
    if (outcome == .overlapping_nonce_lease) {
        try testing.expect(configs_slice.len > 0);
        try exerciseReplacementInstall(testing.allocator, configs_slice[0], generation, caps, true);
        return;
    }
    if (outcome == .stale_generation) {
        const candidate = try Snapshot.build(testing.allocator, configs_slice, generation, caps);
        var keyring = ReloadableKeyRing.init(testing.allocator);
        defer keyring.deinit();
        const current = sampleKeyConfigWithByte(keyId(0xd1), .aes_128_gcm, .{ .prefix = .{ 0xd1, 0, 0, 0 }, .start = 0, .end_exclusive = 4 }, 0x11);
        try keyring.install(try keyring.buildSnapshot(&.{current}, testCapabilities()));
        const before = captureKeyringState(&keyring);
        try testing.expectError(error.StaleSnapshotGeneration, keyring.install(candidate));
        try expectKeyringStateEqual(before, &keyring);
        return;
    }
    if (outcome == .generation_overflow) {
        const candidate = try Snapshot.build(testing.allocator, configs_slice, generation, caps);
        var keyring = ReloadableKeyRing.init(testing.allocator);
        defer keyring.deinit();
        const before = captureKeyringState(&keyring);
        try testing.expectError(error.GenerationOverflow, keyring.install(candidate));
        try expectKeyringStateEqual(before, &keyring);
        return;
    }

    const result = Snapshot.build(testing.allocator, configs_slice, generation, caps);
    switch (outcome) {
        .build_success => {
            const snapshot = try result;
            snapshot.release();
        },
        .too_many_keys => try testing.expectError(error.TooManyKeys, result),
        .duplicate_key_id => try testing.expectError(error.DuplicateKeyId, result),
        .invalid_key_length => {
            try testing.expectError(error.InvalidKeyLength, result);
            try expectPartialBuildWipesCopiedKey(input);
        },
        .unsupported_capability => try testing.expectError(error.UnsupportedCapability, result),
        .invalid_validity_window => try testing.expectError(error.InvalidValidityWindow, result),
        .invalid_nonce_lease => try testing.expectError(error.InvalidNonceLease, result),
        .ambiguous_encryption_window => try testing.expectError(error.AmbiguousEncryptionWindow, result),
        .stale_generation, .generation_overflow, .non_overlapping_nonce_lease, .overlapping_nonce_lease => unreachable,
    }
}

test "protectedLen reserves envelope overhead exactly" {
    var state = try sampleServerState(testing.allocator);
    defer state.deinit();
    const encoded_len = try session.serverEncodedLenWithLimits(&state, session.Limits.default);
    var limits = session.Limits.default;
    limits.max_ticket_len = encoded_len + envelope_overhead;
    var keyring = ReloadableKeyRing.init(testing.allocator);
    defer keyring.deinit();
    var protector = Protector{ .provider = testProvider(), .keyring = &keyring, .limits = limits };
    try testing.expectEqual(encoded_len + envelope_overhead, try protector.protectedLen(&state));

    limits.max_ticket_len = encoded_len + envelope_overhead - 1;
    protector.limits = limits;
    try testing.expectError(error.TicketTooLarge, protector.protectedLen(&state));
}

test "seal and resolve round trip and authenticate header fields" {
    const allocator = testing.allocator;
    var keyring = ReloadableKeyRing.init(allocator);
    defer keyring.deinit();
    const config = sampleKeyConfig(keyId(1), .aes_128_gcm, .{ .prefix = .{ 1, 2, 3, 4 }, .start = 9, .end_exclusive = 11 });
    const snapshot = try keyring.buildSnapshot(&.{config}, testCapabilities());
    try keyring.install(snapshot);

    var state = try sampleServerState(allocator);
    defer state.deinit();
    var protector = Protector{ .provider = testProvider(), .keyring = &keyring, .limits = session.Limits.default };
    var ticket_buf = [_]u8{0} ** 512;
    const ticket = try protector.seal(allocator, &state, 2_000, &ticket_buf);
    try testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 9 }, ticket[24..36]);

    var recovered: session.ServerRecoverableState = .{};
    defer recovered.deinit();
    try testing.expect(try protector.resolve(allocator, ticket, 2_000, &recovered));
    try testing.expectEqual(state.ticket_age_add, recovered.ticket_age_add);
    try testing.expectEqual(state.common.lifetime_seconds, recovered.common.lifetime_seconds);
    try testing.expectEqualSlices(u8, state.common.resumption_psk.slice(), recovered.common.resumption_psk.slice());

    ticket_buf[8] ^= 1;
    var untouched: session.ServerRecoverableState = .{};
    defer untouched.deinit();
    try testing.expect(!try protector.resolve(allocator, ticket, 2_000, &untouched));
}

test "all supported AEADs seal and resolve" {
    const allocator = testing.allocator;
    const cases = [_]struct {
        aead: provider.Aead,
        key_byte: u8,
        prefix: [4]u8,
    }{
        .{ .aead = .aes_128_gcm, .key_byte = 0x11, .prefix = .{ 3, 1, 0, 0 } },
        .{ .aead = .aes_256_gcm, .key_byte = 0x22, .prefix = .{ 3, 2, 0, 0 } },
        .{ .aead = .chacha20_poly1305, .key_byte = 0x33, .prefix = .{ 3, 3, 0, 0 } },
    };

    for (cases, 0..) |case, i| {
        var keyring = ReloadableKeyRing.init(allocator);
        defer keyring.deinit();
        try installSingleKey(&keyring, keyId(@intCast(30 + i)), case.aead, .{ .prefix = case.prefix, .start = 0, .end_exclusive = 3 }, case.key_byte);

        var state = try sampleServerState(allocator);
        defer state.deinit();
        var protector = Protector{ .provider = testProvider(), .keyring = &keyring, .limits = session.Limits.default };
        var ticket_buf = [_]u8{0} ** 512;
        const ticket = try protector.seal(allocator, &state, 2_000, &ticket_buf);
        try testing.expectEqual(case.aead, (try parseEnvelope(ticket, session.Limits.default)).aead);
        try expectRoundTrip(&protector, allocator, &state, ticket, 2_000);
    }
}

test "deterministic envelope fixture stays stable" {
    const allocator = testing.allocator;
    var keyring = ReloadableKeyRing.init(allocator);
    defer keyring.deinit();
    try installSingleKey(&keyring, keyId(31), .aes_128_gcm, .{ .prefix = .{ 3, 1, 0, 1 }, .start = 7, .end_exclusive = 8 }, 0x11);

    var state = try sampleServerState(allocator);
    defer state.deinit();
    var protector = Protector{ .provider = testProvider(), .keyring = &keyring, .limits = session.Limits.default };
    var ticket_buf = [_]u8{0} ** 512;
    const ticket = try protector.seal(allocator, &state, 2_000, &ticket_buf);
    const expected = [_]u8{
        0x54, 0x44, 0x54, 0x4B, 0x01, 0x01, 0x00, 0x00, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F,
        0x1F, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F, 0x03, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x07, 0x66, 0x7F, 0x02, 0x37, 0x11, 0xE4, 0xF3, 0x9C, 0xF8, 0x63, 0x20, 0xB4,
        0xEA, 0x5C, 0xE7, 0xAC, 0xEF, 0xFC, 0xB6, 0x6D, 0x78, 0xA8, 0xDC, 0x56, 0x81, 0x50, 0x21, 0x6E,
        0x51, 0xB8, 0x54, 0xA5, 0x0D, 0x64, 0x75, 0x9A, 0x5A, 0x3A, 0x90, 0x88, 0x65, 0x6B, 0xEB, 0xAC,
        0x49, 0x78, 0x2F, 0x6A, 0xE1, 0xD9, 0x78, 0xF2, 0x70, 0x7D, 0xB7, 0x9C, 0x28, 0x45, 0xD5, 0x94,
        0xEB, 0x57, 0x24, 0x63, 0x18, 0xDB, 0x52, 0x48, 0xD1, 0x07, 0x0E, 0x53, 0x44, 0xE3, 0xA6, 0x74,
        0x11, 0xC9, 0xCF, 0x11, 0x31, 0x52, 0x06, 0xC8, 0x8D, 0x41, 0x37, 0xB6, 0xC0, 0x22, 0x72, 0x8D,
        0x80, 0x7D, 0xCE, 0x34, 0x30, 0x26, 0x12, 0x91, 0x0C, 0x23, 0x8F, 0xAA, 0xAB, 0x23, 0x8B, 0xEF,
        0x80, 0x65, 0x4F, 0xCD, 0x12, 0x20, 0x02, 0xB6, 0xF1, 0x3B, 0x75, 0xFC, 0x87, 0x7C, 0xF4, 0x4B,
        0xF7, 0x9E, 0x2E, 0x69, 0x68, 0x1B, 0xF5, 0x20, 0x0C, 0x57, 0xA2, 0xC5, 0x94, 0x17, 0x53, 0x1D,
        0x48, 0xE9, 0x2B, 0x3A, 0xE0, 0xE6, 0x3A, 0x2F, 0xAF, 0x1D, 0xB7, 0xD8, 0x8E, 0xAC, 0x6B, 0xE0,
        0x6B, 0x08, 0x15, 0xE1, 0xB6, 0xED, 0x57, 0x04, 0x8A, 0x76, 0xD9, 0x3D, 0xCE, 0xB2, 0x18, 0x05,
        0x37, 0x5C, 0x7B, 0x25,
    };
    try testing.expectEqualSlices(u8, &expected, ticket);
}

test "ticket identity tampering is unusable and leaves output untouched" {
    const allocator = testing.allocator;
    var keyring = ReloadableKeyRing.init(allocator);
    defer keyring.deinit();
    try installSingleKey(&keyring, keyId(32), .aes_128_gcm, .{ .prefix = .{ 3, 2, 0, 0 }, .start = 0, .end_exclusive = 12 }, 0x11);

    var state = try sampleServerState(allocator);
    defer state.deinit();
    var protector = Protector{ .provider = testProvider(), .keyring = &keyring, .limits = session.Limits.default };
    var ticket_buf = [_]u8{0} ** 512;
    const ticket = try protector.seal(allocator, &state, 2_000, &ticket_buf);

    const positions = [_]usize{ 0, 4, 5, 6, 8, 24, fixed_header_len, ticket.len - 1 };
    for (positions) |pos| {
        var mutated = ticket_buf;
        mutated[pos] ^= 0x01;
        try expectResolveFalseUnchanged(&protector, allocator, mutated[0..ticket.len], 2_000);
    }
}

test "decrypt windows are enforced at exact boundaries" {
    const allocator = testing.allocator;
    var keyring = ReloadableKeyRing.init(allocator);
    defer keyring.deinit();
    try installSingleKey(&keyring, keyId(33), .aes_128_gcm, .{ .prefix = .{ 3, 3, 0, 0 }, .start = 0, .end_exclusive = 3 }, 0x11);

    var state = try sampleServerState(allocator);
    defer state.deinit();
    var protector = Protector{ .provider = testProvider(), .keyring = &keyring, .limits = session.Limits.default };
    var ticket_buf = [_]u8{0} ** 512;
    const ticket = try protector.seal(allocator, &state, 2_000, &ticket_buf);

    try expectResolveFalseUnchanged(&protector, allocator, ticket, 999);
    try expectRoundTrip(&protector, allocator, &state, ticket, 1_000);
    try expectRoundTrip(&protector, allocator, &state, ticket, 4_999);
    try expectRoundTrip(&protector, allocator, &state, ticket, 5_000);
    try expectResolveFalseUnchanged(&protector, allocator, ticket, 20_000);
}

test "authenticated session state rejections are distinct from key-window misses" {
    const allocator = testing.allocator;
    var keyring = ReloadableKeyRing.init(allocator);
    defer keyring.deinit();
    try installSingleKey(&keyring, keyId(39), .aes_128_gcm, .{ .prefix = .{ 3, 9, 0, 0 }, .start = 0, .end_exclusive = 8 }, 0x11);

    var observer = TestObserver{};
    defer observer.deinit(allocator);
    var protector = Protector{ .provider = testProvider(), .keyring = &keyring, .limits = session.Limits.default, .observer = observer.observer() };
    var ticket_buf = [_]u8{0} ** 512;

    var future_state = try sampleServerState(allocator);
    defer future_state.deinit();
    future_state.common.issued_at_unix_ms = 3_000;
    const future_ticket = try protector.seal(allocator, &future_state, 2_000, &ticket_buf);
    observer.reset();
    try expectResolveFalseUnchanged(&protector, allocator, future_ticket, 2_000);
    try observer.expectOnly(.{ .resolve_rejected = .not_yet_valid });

    var expired_state = try sampleServerState(allocator);
    defer expired_state.deinit();
    expired_state.common.issued_at_unix_ms = 1_000;
    expired_state.common.lifetime_seconds = 1;
    const expired_ticket = try protector.seal(allocator, &expired_state, 1_500, &ticket_buf);
    observer.reset();
    try expectResolveFalseUnchanged(&protector, allocator, expired_ticket, 2_000);
    try observer.expectOnly(.{ .resolve_rejected = .expired });

    var invalid_buf = [_]u8{0} ** 128;
    const invalid_ticket = try buildAuthenticatedEnvelope(
        &invalid_buf,
        .aes_128_gcm,
        keyId(39),
        testKeyBytes(.aes_128_gcm, 0x11),
        [_]u8{ 3, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 99 },
        "not a session record",
    );
    observer.reset();
    try expectResolveFalseUnchanged(&protector, allocator, invalid_ticket, 2_000);
    try observer.expectOnly(.{ .resolve_rejected = .invalid_plaintext });
}

test "ticket identity size boundaries reject malformed envelopes" {
    const allocator = testing.allocator;
    var keyring = ReloadableKeyRing.init(allocator);
    defer keyring.deinit();
    try installSingleKey(&keyring, keyId(34), .aes_128_gcm, .{ .prefix = .{ 3, 4, 0, 0 }, .start = 0, .end_exclusive = 3 }, 0x11);

    var state = try sampleServerState(allocator);
    defer state.deinit();
    var protector = Protector{ .provider = testProvider(), .keyring = &keyring, .limits = session.Limits.default };
    var ticket_buf = [_]u8{0} ** 512;
    const ticket = try protector.seal(allocator, &state, 2_000, &ticket_buf);
    try expectResolveFalseUnchanged(&protector, allocator, ticket[0 .. ticket.len - 1], 2_000);

    var min_identity = [_]u8{0} ** (fixed_header_len + 1 + tag_len);
    writeHeader(min_identity[0..fixed_header_len], .aes_128_gcm, &keyId(34), &([_]u8{0} ** provider.aead_nonce_len));
    try expectResolveFalseUnchanged(&protector, allocator, &min_identity, 2_000);

    var trailing = [_]u8{0} ** 513;
    @memcpy(trailing[0..ticket.len], ticket);
    trailing[ticket.len] = 0;
    try expectResolveFalseUnchanged(&protector, allocator, trailing[0 .. ticket.len + 1], 2_000);

    var limits = session.Limits.default;
    limits.max_ticket_len = ticket.len - 1;
    try testing.expectError(error.EnvelopeTooLarge, parseEnvelope(ticket, limits));
}

test "concurrent sealing reserves unique nonces over one lease" {
    const allocator = testing.allocator;
    var keyring = ReloadableKeyRing.init(allocator);
    defer keyring.deinit();
    try installSingleKey(&keyring, keyId(35), .aes_128_gcm, .{ .prefix = .{ 3, 5, 0, 0 }, .start = 0, .end_exclusive = 32 }, 0x11);

    var state = try sampleServerState(allocator);
    defer state.deinit();
    var protector = Protector{ .provider = testProvider(), .keyring = &keyring, .limits = session.Limits.default };
    var start = std.atomic.Value(bool).init(false);
    var successes = std.atomic.Value(usize).init(0);
    var failures = std.atomic.Value(usize).init(0);
    var nonces: [32][provider.aead_nonce_len]u8 = undefined;
    var tasks: [40]ConcurrentSealTask = undefined;
    var threads: [40]std.Thread = undefined;

    for (&tasks, 0..) |*task, i| {
        task.* = .{ .protector = &protector, .state = &state, .start = &start, .successes = &successes, .failures = &failures, .nonces = &nonces };
        threads[i] = try std.Thread.spawn(.{}, ConcurrentSealTask.run, .{task});
    }
    start.store(true, .release);
    for (&threads) |thread| thread.join();

    try testing.expectEqual(@as(usize, 32), successes.load(.monotonic));
    try testing.expectEqual(@as(usize, 8), failures.load(.monotonic));
    for (nonces[0..], 0..) |nonce, i| {
        try testing.expectEqualSlices(u8, &[_]u8{ 3, 5, 0, 0 }, nonce[0..4]);
        for (nonces[0..i]) |prior| try testing.expect(!std.mem.eql(u8, &nonce, &prior));
    }
}

test "nonce lease exhaustion fails closed without wraparound" {
    const allocator = testing.allocator;
    var keyring = ReloadableKeyRing.init(allocator);
    defer keyring.deinit();
    const config = sampleKeyConfig(keyId(2), .aes_128_gcm, .{ .prefix = .{ 9, 8, 7, 6 }, .start = 0, .end_exclusive = 1 });
    const snapshot = try keyring.buildSnapshot(&.{config}, testCapabilities());
    try keyring.install(snapshot);

    var state = try sampleServerState(allocator);
    defer state.deinit();
    var protector = Protector{ .provider = testProvider(), .keyring = &keyring, .limits = session.Limits.default };
    var ticket_buf = [_]u8{0} ** 512;
    _ = try protector.seal(allocator, &state, 2_000, &ticket_buf);
    try testing.expectError(error.NonceLeaseExhausted, protector.seal(allocator, &state, 2_000, &ticket_buf));
}

test "replacement snapshot rejects overlapping nonce lease and accepts adjacent range" {
    const allocator = testing.allocator;
    var keyring = ReloadableKeyRing.init(allocator);
    defer keyring.deinit();
    const first = sampleKeyConfig(keyId(3), .aes_128_gcm, .{ .prefix = .{ 1, 1, 1, 1 }, .start = 0, .end_exclusive = 10 });
    try keyring.install(try keyring.buildSnapshot(&.{first}, testCapabilities()));

    const overlap = sampleKeyConfig(keyId(3), .aes_128_gcm, .{ .prefix = .{ 1, 1, 1, 1 }, .start = 9, .end_exclusive = 20 });
    try testing.expectError(error.OverlappingNonceLease, keyring.install(try keyring.buildSnapshot(&.{overlap}, testCapabilities())));

    const adjacent = sampleKeyConfig(keyId(3), .aes_128_gcm, .{ .prefix = .{ 1, 1, 1, 1 }, .start = 10, .end_exclusive = 20 });
    try keyring.install(try keyring.buildSnapshot(&.{adjacent}, testCapabilities()));

    const changed_prefix = sampleKeyConfig(keyId(3), .aes_128_gcm, .{ .prefix = .{ 2, 1, 1, 1 }, .start = 20, .end_exclusive = 30 });
    try testing.expectError(error.OverlappingNonceLease, keyring.install(try keyring.buildSnapshot(&.{changed_prefix}, testCapabilities())));
}

test "failed install leaves generation current and ledger unchanged" {
    const allocator = testing.allocator;
    var keyring = ReloadableKeyRing.init(allocator);
    defer keyring.deinit();
    const first = sampleKeyConfig(keyId(38), .aes_128_gcm, .{ .prefix = .{ 3, 8, 0, 0 }, .start = 0, .end_exclusive = 10 });
    try keyring.install(try keyring.buildSnapshot(&.{first}, testCapabilities()));

    const before_generation = keyring.next_generation;
    const before_current = keyring.current.?;
    const before_ledger_len = keyring.ledger.items.len;
    const overlap = sampleKeyConfig(keyId(38), .aes_128_gcm, .{ .prefix = .{ 3, 8, 0, 0 }, .start = 9, .end_exclusive = 20 });
    try testing.expectError(error.OverlappingNonceLease, keyring.install(try keyring.buildSnapshot(&.{overlap}, testCapabilities())));
    try testing.expectEqual(before_generation, keyring.next_generation);
    try testing.expectEqual(before_current, keyring.current.?);
    try testing.expectEqual(before_ledger_len, keyring.ledger.items.len);

    const adjacent = sampleKeyConfig(keyId(38), .aes_128_gcm, .{ .prefix = .{ 3, 8, 0, 0 }, .start = 10, .end_exclusive = 20 });
    try keyring.install(try keyring.buildSnapshot(&.{adjacent}, testCapabilities()));
    try testing.expectEqual(before_generation, keyring.current.?.generation);
    try testing.expectEqual(before_generation + 1, keyring.next_generation);
}

test "failed snapshot build leaves publication state unchanged" {
    const allocator = testing.allocator;
    var keyring = ReloadableKeyRing.init(allocator);
    var observer = TestObserver{};
    defer observer.deinit(allocator);
    keyring.observer = observer.observer();
    defer keyring.deinit();

    const first = sampleKeyConfig(keyId(21), .aes_128_gcm, .{ .prefix = .{ 2, 1, 0, 0 }, .start = 0, .end_exclusive = 10 });
    try keyring.install(try keyring.buildSnapshot(&.{first}, testCapabilities()));
    observer.reset();

    const before_generation = keyring.next_generation;
    const before_current = keyring.current.?;
    const before_ledger_len = keyring.ledger.items.len;
    try testing.expectError(error.TooManyKeys, keyring.buildSnapshot(&.{}, testCapabilities()));
    try testing.expectEqual(before_generation, keyring.next_generation);
    try testing.expectEqual(before_current, keyring.current.?);
    try testing.expectEqual(before_ledger_len, keyring.ledger.items.len);
    try observer.expectOnly(.{ .snapshot_rejected = .too_many_keys });

    observer.reset();
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    keyring.allocator = failing.allocator();
    try testing.expectError(error.OutOfMemory, keyring.buildSnapshot(&.{first}, testCapabilities()));
    keyring.allocator = allocator;
    try testing.expectEqual(before_generation, keyring.next_generation);
    try testing.expectEqual(before_current, keyring.current.?);
    try testing.expectEqual(before_ledger_len, keyring.ledger.items.len);
    try observer.expectOnly(.{ .snapshot_rejected = .out_of_memory });
}

test "install consumes acquired current snapshot reference" {
    const allocator = testing.allocator;
    var keyring = ReloadableKeyRing.init(allocator);
    const first = sampleKeyConfig(keyId(22), .aes_128_gcm, .{ .prefix = .{ 2, 2, 0, 0 }, .start = 0, .end_exclusive = 10 });
    try keyring.install(try keyring.buildSnapshot(&.{first}, testCapabilities()));

    var deinit_count = std.atomic.Value(usize).init(0);
    const current = keyring.acquireCurrent().?;
    current.deinit_count = &deinit_count;
    try keyring.install(current);

    keyring.deinit();
    try testing.expectEqual(@as(usize, 1), deinit_count.load(.monotonic));
}

test "install observer callbacks do not dereference snapshots after reentrant deinit" {
    const allocator = testing.allocator;
    var keyring = ReloadableKeyRing.init(allocator);
    const first = sampleKeyConfig(keyId(26), .aes_128_gcm, .{ .prefix = .{ 2, 6, 0, 0 }, .start = 0, .end_exclusive = 10 });
    try keyring.install(try keyring.buildSnapshot(&.{first}, testCapabilities()));

    var old_deinit_count = std.atomic.Value(usize).init(0);
    keyring.current.?.deinit_count = &old_deinit_count;
    var observer = ReentrantDeinitObserver{ .keyring = &keyring, .deinit_on_install = false };
    keyring.observer = observer.observer();

    const replacement_a = sampleKeyConfigWithByte(keyId(27), .aes_128_gcm, .{ .prefix = .{ 2, 7, 0, 0 }, .start = 0, .end_exclusive = 10 }, 0x13);
    try keyring.install(try keyring.buildSnapshot(&.{replacement_a}, testCapabilities()));
    try testing.expectEqual(@as(usize, 1), observer.retired_events);

    var replacement_deinit_count = std.atomic.Value(usize).init(0);
    keyring.current.?.deinit_count = &replacement_deinit_count;
    observer.deinit_on_install = true;
    const replacement_b = sampleKeyConfigWithByte(keyId(28), .aes_128_gcm, .{ .prefix = .{ 2, 8, 0, 0 }, .start = 0, .end_exclusive = 10 }, 0x22);
    try keyring.install(try keyring.buildSnapshot(&.{replacement_b}, testCapabilities()));

    try testing.expectEqual(@as(usize, 2), observer.installed_events);
    try testing.expectEqual(@as(usize, 2), observer.retired_events);
    try testing.expectEqual(@as(usize, 1), old_deinit_count.load(.monotonic));
    try testing.expectEqual(@as(usize, 1), replacement_deinit_count.load(.monotonic));
    keyring.deinit();
}

test "candidate validation rejection observer may reenter keyring" {
    const allocator = testing.allocator;
    var keyring = ReloadableKeyRing.init(allocator);
    const current = sampleKeyConfigWithByte(keyId(29), .aes_128_gcm, .{ .prefix = .{ 2, 9, 0, 0 }, .start = 0, .end_exclusive = 10 }, 0x11);
    try keyring.install(try keyring.buildSnapshot(&.{current}, testCapabilities()));

    var observer = ReentrantDeinitObserver{
        .keyring = &keyring,
        .deinit_on_install = false,
        .deinit_on_rejection = true,
    };
    keyring.observer = observer.observer();

    const stale = sampleKeyConfigWithByte(keyId(30), .aes_128_gcm, .{ .prefix = .{ 3, 0, 0, 0 }, .start = 0, .end_exclusive = 10 }, 0x22);
    const candidate = try Snapshot.build(allocator, &.{stale}, 1, testCapabilities());
    defer candidate.release();

    try testing.expectError(error.StaleSnapshotGeneration, keyring.validateInstallCandidate(candidate));
    try testing.expectEqual(@as(usize, 1), observer.rejected_events);
}

test "ambiguous encryption windows are rejected before publication" {
    const adjacent_a = sampleKeyConfigWithByte(keyId(10), .aes_128_gcm, .{ .prefix = .{ 1, 0, 0, 0 }, .start = 0, .end_exclusive = 10 }, 0x10);
    var adjacent_b = sampleKeyConfigWithByte(keyId(11), .aes_128_gcm, .{ .prefix = .{ 2, 0, 0, 0 }, .start = 0, .end_exclusive = 10 }, 0x11);
    adjacent_b.not_before_unix_ms = adjacent_a.encrypt_until_unix_ms;
    adjacent_b.encrypt_until_unix_ms = 8_000;
    var snap = try Snapshot.build(testing.allocator, &.{ adjacent_a, adjacent_b }, 1, testCapabilities());
    snap.release();

    var overlap = adjacent_b;
    overlap.not_before_unix_ms = adjacent_a.encrypt_until_unix_ms - 1;
    try testing.expectError(error.AmbiguousEncryptionWindow, Snapshot.build(testing.allocator, &.{ adjacent_a, overlap }, 2, testCapabilities()));

    var future_overlap = adjacent_b;
    future_overlap.not_before_unix_ms = 4_000;
    future_overlap.encrypt_until_unix_ms = 9_000;
    try testing.expectError(error.AmbiguousEncryptionWindow, Snapshot.build(testing.allocator, &.{ adjacent_a, future_overlap }, 3, testCapabilities()));
}

test "nonce ledger persists through decrypt-only and removed snapshots" {
    const allocator = testing.allocator;
    var keyring = ReloadableKeyRing.init(allocator);
    defer keyring.deinit();

    const active = sampleKeyConfig(keyId(12), .aes_128_gcm, .{ .prefix = .{ 5, 5, 5, 5 }, .start = 0, .end_exclusive = 10 });
    try keyring.install(try keyring.buildSnapshot(&.{active}, testCapabilities()));

    var decrypt_only = active;
    decrypt_only.nonce_lease = null;
    decrypt_only.encrypt_until_unix_ms = 1_500;
    decrypt_only.decrypt_until_unix_ms = 20_000;
    try keyring.install(try keyring.buildSnapshot(&.{decrypt_only}, testCapabilities()));

    const rollback = sampleKeyConfig(keyId(12), .aes_128_gcm, .{ .prefix = .{ 5, 5, 5, 5 }, .start = 0, .end_exclusive = 10 });
    try testing.expectError(error.OverlappingNonceLease, keyring.install(try keyring.buildSnapshot(&.{rollback}, testCapabilities())));

    const adjacent = sampleKeyConfig(keyId(12), .aes_128_gcm, .{ .prefix = .{ 5, 5, 5, 5 }, .start = 10, .end_exclusive = 20 });
    try keyring.install(try keyring.buildSnapshot(&.{adjacent}, testCapabilities()));

    const other = sampleKeyConfigWithByte(keyId(13), .aes_128_gcm, .{ .prefix = .{ 6, 6, 6, 6 }, .start = 0, .end_exclusive = 10 }, 0x13);
    try keyring.install(try keyring.buildSnapshot(&.{other}, testCapabilities()));

    const reintroduced = sampleKeyConfig(keyId(12), .aes_128_gcm, .{ .prefix = .{ 5, 5, 5, 5 }, .start = 0, .end_exclusive = 10 });
    try testing.expectError(error.OverlappingNonceLease, keyring.install(try keyring.buildSnapshot(&.{reintroduced}, testCapabilities())));
}

test "rotation: a resolve against a decrypt-only grace-window key still succeeds, and new seals use the new key (#369)" {
    const allocator = testing.allocator;
    var keyring = ReloadableKeyRing.init(allocator);
    defer keyring.deinit();

    const old_id = keyId(60);
    const new_id = keyId(61);
    const active_old = sampleKeyConfig(old_id, .aes_128_gcm, .{ .prefix = .{ 6, 0, 0, 0 }, .start = 0, .end_exclusive = 10 });
    try keyring.install(try keyring.buildSnapshot(&.{active_old}, testCapabilities()));

    var protector = Protector{ .provider = testProvider(), .keyring = &keyring, .limits = session.Limits.default };
    var state = try sampleServerState(allocator);
    defer state.deinit();
    var old_ticket_buf: [1024]u8 = undefined;
    const old_ticket = try protector.seal(allocator, &state, 1_000, &old_ticket_buf);
    const old_parsed = try parseEnvelope(old_ticket, session.Limits.default);
    try testing.expectEqualSlices(u8, &old_id, &old_parsed.key_id);

    // Rotate: retire `old_id` to decrypt-only (grace window) and bring up
    // `new_id` as the sole active encryption key, mirroring an operator
    // pushing a new key config without yet removing the old one.
    var decrypt_only_old = active_old;
    decrypt_only_old.nonce_lease = null;
    decrypt_only_old.encrypt_until_unix_ms = 1_500;
    decrypt_only_old.decrypt_until_unix_ms = 20_000;
    const active_new = sampleKeyConfigWithByte(new_id, .aes_128_gcm, .{ .prefix = .{ 6, 1, 0, 0 }, .start = 0, .end_exclusive = 10 }, 0x13);
    try keyring.install(try keyring.buildSnapshot(&.{ decrypt_only_old, active_new }, testCapabilities()));

    // The ticket sealed under `old_id` before rotation still decrypts
    // during the grace window.
    var recovered: session.ServerRecoverableState = .{};
    defer recovered.deinit();
    try testing.expect(try protector.resolve(allocator, old_ticket, 2_000, &recovered));

    // A ticket sealed after rotation is bound to the new key, not the
    // retired one.
    var new_ticket_buf: [1024]u8 = undefined;
    const new_ticket = try protector.seal(allocator, &state, 2_000, &new_ticket_buf);
    const new_parsed = try parseEnvelope(new_ticket, session.Limits.default);
    try testing.expectEqualSlices(u8, &new_id, &new_parsed.key_id);
}

test "rotation: a fully removed key rejects old tickets with unknown_key instead of crashing (#369)" {
    const allocator = testing.allocator;
    var keyring = ReloadableKeyRing.init(allocator);
    defer keyring.deinit();

    const old_id = keyId(70);
    const new_id = keyId(71);
    const active_old = sampleKeyConfig(old_id, .aes_128_gcm, .{ .prefix = .{ 7, 0, 0, 0 }, .start = 0, .end_exclusive = 10 });
    try keyring.install(try keyring.buildSnapshot(&.{active_old}, testCapabilities()));

    var protector = Protector{ .provider = testProvider(), .keyring = &keyring, .limits = session.Limits.default };
    var state = try sampleServerState(allocator);
    defer state.deinit();
    var old_ticket_buf: [1024]u8 = undefined;
    const old_ticket = try protector.seal(allocator, &state, 1_000, &old_ticket_buf);

    // Rotate: install a replacement snapshot that no longer contains
    // `old_id` at all (a full key removal, not a grace-window retirement).
    const active_new = sampleKeyConfigWithByte(new_id, .aes_128_gcm, .{ .prefix = .{ 7, 1, 0, 0 }, .start = 0, .end_exclusive = 10 }, 0x13);
    try keyring.install(try keyring.buildSnapshot(&.{active_new}, testCapabilities()));

    var observer = TestObserver{};
    defer observer.deinit(allocator);
    protector.observer = observer.observer();

    var recovered: session.ServerRecoverableState = .{};
    defer recovered.deinit();
    const accepted = try protector.resolve(allocator, old_ticket, 2_000, &recovered);
    try testing.expect(!accepted);
    try observer.expectOnly(.{ .resolve_rejected = .unknown_key });
}

test "nonce ledger rejects same key under a different id" {
    const allocator = testing.allocator;
    var keyring = ReloadableKeyRing.init(allocator);
    defer keyring.deinit();
    const first = sampleKeyConfig(keyId(14), .aes_128_gcm, .{ .prefix = .{ 7, 7, 7, 7 }, .start = 0, .end_exclusive = 10 });
    try keyring.install(try keyring.buildSnapshot(&.{first}, testCapabilities()));

    const changed_id = sampleKeyConfig(keyId(15), .aes_128_gcm, .{ .prefix = .{ 8, 8, 8, 8 }, .start = 0, .end_exclusive = 10 });
    try testing.expectError(error.DuplicateKeyId, keyring.install(try keyring.buildSnapshot(&.{changed_id}, testCapabilities())));
}

test "nonce ledger does not retain full retired key bytes after final snapshot release" {
    var backing = [_]u8{0xcc} ** 16384;
    var fba = std.heap.FixedBufferAllocator.init(&backing);
    const allocator = fba.allocator();
    var keyring = ReloadableKeyRing.init(allocator);
    defer keyring.deinit();

    const retired_key = [_]u8{0x55} ** 16;
    const active = KeyConfig{
        .id = keyId(17),
        .aead = .aes_128_gcm,
        .key_bytes = &retired_key,
        .not_before_unix_ms = 1_000,
        .encrypt_until_unix_ms = 5_000,
        .decrypt_until_unix_ms = 20_000,
        .nonce_lease = .{ .prefix = .{ 1, 7, 0, 0 }, .start = 0, .end_exclusive = 10 },
    };
    try keyring.install(try keyring.buildSnapshot(&.{active}, testCapabilities()));

    const retained = keyring.acquireCurrent().?;
    const replacement = sampleKeyConfigWithByte(keyId(18), .aes_128_gcm, .{ .prefix = .{ 1, 8, 0, 0 }, .start = 0, .end_exclusive = 10 }, 0x13);
    try keyring.install(try keyring.buildSnapshot(&.{replacement}, testCapabilities()));
    retained.release();

    try testing.expect(std.mem.indexOf(u8, &backing, &retired_key) == null);
    try testing.expectEqual(@as(usize, 2), keyring.ledger.items.len);
}

test "retained old snapshot delays final key wipe across replacement" {
    const allocator = testing.allocator;
    var keyring = ReloadableKeyRing.init(allocator);
    defer keyring.deinit();
    const first = sampleKeyConfig(keyId(29), .aes_128_gcm, .{ .prefix = .{ 2, 9, 0, 0 }, .start = 0, .end_exclusive = 10 });
    try keyring.install(try keyring.buildSnapshot(&.{first}, testCapabilities()));
    const retained = keyring.acquireCurrent().?;
    var deinit_count = std.atomic.Value(usize).init(0);
    retained.deinit_count = &deinit_count;

    const replacement = sampleKeyConfigWithByte(keyId(36), .aes_128_gcm, .{ .prefix = .{ 3, 6, 0, 0 }, .start = 0, .end_exclusive = 10 }, 0x13);
    try keyring.install(try keyring.buildSnapshot(&.{replacement}, testCapabilities()));
    try testing.expectEqual(@as(usize, 0), deinit_count.load(.monotonic));

    retained.release();
    try testing.expectEqual(@as(usize, 1), deinit_count.load(.monotonic));
}

test "nonce ledger supports more than fixed live-snapshot rotations" {
    const allocator = testing.allocator;
    var keyring = ReloadableKeyRing.init(allocator);
    defer keyring.deinit();

    var key_storage: [70][16]u8 = undefined;
    for (&key_storage, 0..) |*bytes, i| {
        @memset(bytes, @intCast(i + 1));
        const config = KeyConfig{
            .id = keyId(@intCast(i + 40)),
            .aead = .aes_128_gcm,
            .key_bytes = bytes,
            .not_before_unix_ms = 1_000,
            .encrypt_until_unix_ms = 5_000,
            .decrypt_until_unix_ms = 20_000,
            .nonce_lease = .{ .prefix = .{ 2, 0, 0, @intCast(i) }, .start = 0, .end_exclusive = 10 },
        };
        try keyring.install(try keyring.buildSnapshot(&.{config}, testCapabilities()));
    }
    try testing.expectEqual(@as(usize, 70), keyring.ledger.items.len);
}

test "ledger growth across many installs never leaves a stale fingerprint copy behind" {
    // Each `LeaseHighWater` is individually heap-allocated and the ledger
    // stores pointers to them, so growing the pointer array (which this
    // loop forces several times over) only ever moves pointers, never the
    // fingerprint bytes themselves. A regression to storing entries by
    // value in the growable list would leave old, unwiped fingerprint
    // copies behind at each prior backing allocation.
    var backing = [_]u8{0xcc} ** (64 * 1024);
    var fba = std.heap.FixedBufferAllocator.init(&backing);
    const allocator = fba.allocator();
    var keyring = ReloadableKeyRing.init(allocator);
    defer keyring.deinit();

    var key_storage: [40][16]u8 = undefined;
    for (&key_storage, 0..) |*bytes, i| {
        @memset(bytes, @intCast(i + 1));
        const config = KeyConfig{
            .id = keyId(@intCast(i + 100)),
            .aead = .aes_128_gcm,
            .key_bytes = bytes,
            .not_before_unix_ms = 1_000,
            .encrypt_until_unix_ms = 5_000,
            .decrypt_until_unix_ms = 20_000,
            .nonce_lease = .{ .prefix = .{ 9, 0, 0, @intCast(i) }, .start = 0, .end_exclusive = 10 },
        };
        try keyring.install(try keyring.buildSnapshot(&.{config}, testCapabilities()));
    }
    try testing.expectEqual(@as(usize, 40), keyring.ledger.items.len);

    for (keyring.ledger.items) |entry| {
        try testing.expectEqual(@as(usize, 1), std.mem.count(u8, &backing, &entry.key_fingerprint));
    }
}

test "ledger fingerprint check catches a mismatch at the first, middle, or last byte" {
    const allocator = testing.allocator;
    var keyring = ReloadableKeyRing.init(allocator);
    defer keyring.deinit();

    const retiring_id = keyId(200);
    var base_key = [_]u8{0xaa} ** 16;
    const base = KeyConfig{
        .id = retiring_id,
        .aead = .aes_128_gcm,
        .key_bytes = &base_key,
        .not_before_unix_ms = 1_000,
        .encrypt_until_unix_ms = 5_000,
        .decrypt_until_unix_ms = 20_000,
        .nonce_lease = .{ .prefix = .{ 9, 9, 0, 0 }, .start = 0, .end_exclusive = 10 },
    };
    try keyring.install(try keyring.buildSnapshot(&.{base}, testCapabilities()));

    // Rotate `retiring_id` out of the current snapshot entirely, so only
    // the ledger (not `current.findKey`) remembers its fingerprint.
    const other = sampleKeyConfig(keyId(201), .aes_128_gcm, .{ .prefix = .{ 9, 9, 1, 0 }, .start = 0, .end_exclusive = 10 });
    try keyring.install(try keyring.buildSnapshot(&.{other}, testCapabilities()));

    // Each variant replaces `current` outright (a single-key snapshot), so
    // only the ledger's memory of `retiring_id` — not `current.findKey` —
    // can be catching the mismatch.
    const mismatch_positions = [_]usize{ 0, 8, 15 };
    for (mismatch_positions) |pos| {
        var variant_key = base_key;
        variant_key[pos] ^= 0x01;
        const variant = KeyConfig{
            .id = retiring_id,
            .aead = .aes_128_gcm,
            .key_bytes = &variant_key,
            .not_before_unix_ms = 1_000,
            .encrypt_until_unix_ms = 5_000,
            .decrypt_until_unix_ms = 20_000,
            .nonce_lease = null,
        };
        try testing.expectError(
            error.DuplicateKeyId,
            keyring.install(try keyring.buildSnapshot(&.{variant}, testCapabilities())),
        );
    }

    // Reasserting the exact same key bytes under the retired id is not a
    // conflict — only the ledger fingerprint has to agree.
    const same = KeyConfig{
        .id = retiring_id,
        .aead = .aes_128_gcm,
        .key_bytes = &base_key,
        .not_before_unix_ms = 1_000,
        .encrypt_until_unix_ms = 5_000,
        .decrypt_until_unix_ms = 20_000,
        .nonce_lease = null,
    };
    try keyring.install(try keyring.buildSnapshot(&.{same}, testCapabilities()));
}

test "invalid issuance limits fail before reserving a nonce" {
    const allocator = testing.allocator;
    var keyring = ReloadableKeyRing.init(allocator);
    defer keyring.deinit();
    const config = sampleKeyConfig(keyId(19), .aes_128_gcm, .{ .prefix = .{ 1, 9, 0, 0 }, .start = 0, .end_exclusive = 3 });
    try keyring.install(try keyring.buildSnapshot(&.{config}, testCapabilities()));

    var state = try sampleServerState(allocator);
    defer state.deinit();
    var protector = Protector{ .provider = testProvider(), .keyring = &keyring, .limits = session.Limits.default };
    protector.limits.max_fields = 0;
    try testing.expectError(error.InvalidInternalState, protector.protectedLen(&state));
    var ticket_buf = [_]u8{0} ** 512;
    try testing.expectError(error.InvalidInternalState, protector.seal(allocator, &state, 2_000, &ticket_buf));

    protector.limits = session.Limits.default;
    const ticket = try protector.seal(allocator, &state, 2_000, &ticket_buf);
    try testing.expectEqualSlices(u8, &[_]u8{ 1, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, ticket[24..36]);
}

test "semantically invalid state is local corruption and leaves nonce available" {
    const allocator = testing.allocator;
    var keyring = ReloadableKeyRing.init(allocator);
    defer keyring.deinit();
    const config = sampleKeyConfig(keyId(23), .aes_128_gcm, .{ .prefix = .{ 2, 3, 0, 0 }, .start = 0, .end_exclusive = 3 });
    try keyring.install(try keyring.buildSnapshot(&.{config}, testCapabilities()));

    var state = try sampleServerState(allocator);
    defer state.deinit();
    state.common.lifetime_seconds = 0;
    var protector = Protector{ .provider = testProvider(), .keyring = &keyring, .limits = session.Limits.default };
    var ticket_buf = [_]u8{0} ** 512;

    try testing.expectError(error.InvalidInternalState, protector.protectedLen(&state));
    try testing.expectError(error.InvalidInternalState, protector.seal(allocator, &state, 2_000, &ticket_buf));

    state.common.lifetime_seconds = 10;
    const ticket = try protector.seal(allocator, &state, 2_000, &ticket_buf);
    try testing.expectEqualSlices(u8, &[_]u8{ 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, ticket[24..36]);
}

test "seal observer records one terminal event per typed result" {
    const allocator = testing.allocator;
    var keyring = ReloadableKeyRing.init(allocator);
    defer keyring.deinit();
    var observer = TestObserver{};
    defer observer.deinit(allocator);
    var protector = Protector{ .provider = testProvider(), .keyring = &keyring, .limits = session.Limits.default, .observer = observer.observer() };
    var state = try sampleServerState(allocator);
    defer state.deinit();
    var ticket_buf = [_]u8{0} ** 512;

    try testing.expectError(error.NoActiveEncryptionKey, protector.seal(allocator, &state, 2_000, &ticket_buf));
    try observer.expectOnly(.{ .seal_rejected = .no_active_encryption_key });
    observer.reset();

    const config = sampleKeyConfig(keyId(24), .aes_128_gcm, .{ .prefix = .{ 2, 4, 0, 0 }, .start = 0, .end_exclusive = 1 });
    try keyring.install(try keyring.buildSnapshot(&.{config}, testCapabilities()));
    state.common.lifetime_seconds = 0;
    try testing.expectError(error.InvalidInternalState, protector.seal(allocator, &state, 2_000, &ticket_buf));
    try observer.expectOnly(.{ .seal_rejected = .invalid_internal_state });
    observer.reset();

    state.common.lifetime_seconds = 10;
    try testing.expectError(error.OutputTooSmall, protector.seal(allocator, &state, 2_000, ticket_buf[0..8]));
    try observer.expectOnly(.{ .seal_rejected = .output_too_small });
    observer.reset();

    _ = try protector.seal(allocator, &state, 2_000, &ticket_buf);
    try observer.expectOnly(.seal_succeeded);
    observer.reset();

    try testing.expectError(error.NonceLeaseExhausted, protector.seal(allocator, &state, 2_000, &ticket_buf));
    try testing.expectEqual(@as(usize, 2), observer.events.items.len);
    try testing.expectEqualDeep(Event.nonce_lease_exhausted, observer.events.items[0]);
    try testing.expectEqualDeep(Event{ .seal_rejected = .nonce_lease_exhausted }, observer.events.items[1]);
}

test "resolve observer records one terminal event for false and error paths" {
    const allocator = testing.allocator;
    var keyring = ReloadableKeyRing.init(allocator);
    defer keyring.deinit();
    const config = sampleKeyConfig(keyId(25), .aes_128_gcm, .{ .prefix = .{ 2, 5, 0, 0 }, .start = 0, .end_exclusive = 3 });
    try keyring.install(try keyring.buildSnapshot(&.{config}, testCapabilities()));

    var observer = TestObserver{};
    defer observer.deinit(allocator);
    var protector = Protector{ .provider = testProvider(), .keyring = &keyring, .limits = session.Limits.default, .observer = observer.observer() };
    var out: session.ServerRecoverableState = .{};
    defer out.deinit();

    try testing.expect(!try protector.resolve(allocator, "not-a-ticket", 2_000, &out));
    try observer.expectOnly(.{ .resolve_rejected = .malformed_envelope });
    observer.reset();

    var state = try sampleServerState(allocator);
    defer state.deinit();
    var ticket_buf = [_]u8{0} ** 512;
    const ticket = try protector.seal(allocator, &state, 2_000, &ticket_buf);
    observer.reset();

    var invalid_limits = session.Limits.default;
    invalid_limits.max_fields = 0;
    protector.limits = invalid_limits;
    try testing.expectError(error.InvalidInternalState, protector.resolve(allocator, ticket, 2_000, &out));
    try observer.expectOnly(.{ .resolve_rejected = .invalid_internal_state });
    observer.reset();

    protector.limits = session.Limits.default;
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try testing.expectError(error.OutOfMemory, protector.resolve(failing.allocator(), ticket, 2_000, &out));
    try observer.expectOnly(.{ .resolve_rejected = .out_of_memory });
}

test "allocation failures leave nonce and recovered state unchanged" {
    const allocator = testing.allocator;
    var keyring = ReloadableKeyRing.init(allocator);
    defer keyring.deinit();
    try installSingleKey(&keyring, keyId(37), .aes_128_gcm, .{ .prefix = .{ 3, 7, 0, 0 }, .start = 0, .end_exclusive = 3 }, 0x11);

    var state = try sampleServerState(allocator);
    defer state.deinit();
    var protector = Protector{ .provider = testProvider(), .keyring = &keyring, .limits = session.Limits.default };
    var ticket_buf = [_]u8{0} ** 512;

    var seal_failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try testing.expectError(error.OutOfMemory, protector.seal(seal_failing.allocator(), &state, 2_000, &ticket_buf));
    const ticket = try protector.seal(allocator, &state, 2_000, &ticket_buf);
    try testing.expectEqualSlices(u8, &[_]u8{ 3, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, ticket[24..36]);

    var out: session.ServerRecoverableState = .{};
    defer out.deinit();
    var plaintext_failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try testing.expectError(error.OutOfMemory, protector.resolve(plaintext_failing.allocator(), ticket, 2_000, &out));
    try testing.expectEqual(@as(u32, 0), out.ticket_age_add);
    try testing.expectEqual(@as(usize, 0), out.common.resumption_psk.len);

    var decode_failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 1 });
    try testing.expectError(error.OutOfMemory, protector.resolve(decode_failing.allocator(), ticket, 2_000, &out));
    try testing.expectEqual(@as(u32, 0), out.ticket_age_add);
    try testing.expectEqual(@as(usize, 0), out.common.resumption_psk.len);
}

test "seal and invalid-plaintext resolve zeroize plaintext before free" {
    const allocator = testing.allocator;
    var keyring = ReloadableKeyRing.init(allocator);
    defer keyring.deinit();
    try installSingleKey(&keyring, keyId(40), .aes_128_gcm, .{ .prefix = .{ 4, 0, 0, 0 }, .start = 0, .end_exclusive = 3 }, 0x11);

    var state = try sampleServerState(allocator);
    defer state.deinit();
    var protector = Protector{ .provider = testProvider(), .keyring = &keyring, .limits = session.Limits.default };
    var ticket_buf = [_]u8{0} ** 512;
    var seal_zero = ZeroCheckingAllocator.init(allocator);
    _ = try protector.seal(seal_zero.allocator(), &state, 2_000, &ticket_buf);
    try testing.expectEqual(@as(usize, 1), seal_zero.free_count);

    var invalid_buf = [_]u8{0} ** 128;
    const invalid_ticket = try buildAuthenticatedEnvelope(
        &invalid_buf,
        .aes_128_gcm,
        keyId(40),
        testKeyBytes(.aes_128_gcm, 0x11),
        [_]u8{ 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 99 },
        "not a session record",
    );
    var out: session.ServerRecoverableState = .{};
    defer out.deinit();
    var resolve_zero = ZeroCheckingAllocator.init(allocator);
    try testing.expect(!try protector.resolve(resolve_zero.allocator(), invalid_ticket, 2_000, &out));
    try testing.expectEqual(@as(usize, 1), resolve_zero.free_count);
}

test "resolve treats invalid limits and decode allocation failure as local errors" {
    const allocator = testing.allocator;
    var keyring = ReloadableKeyRing.init(allocator);
    defer keyring.deinit();
    const config = sampleKeyConfig(keyId(16), .aes_128_gcm, .{ .prefix = .{ 9, 9, 9, 9 }, .start = 0, .end_exclusive = 3 });
    try keyring.install(try keyring.buildSnapshot(&.{config}, testCapabilities()));

    var state = try sampleServerState(allocator);
    defer state.deinit();
    var protector = Protector{ .provider = testProvider(), .keyring = &keyring, .limits = session.Limits.default };
    var ticket_buf = [_]u8{0} ** 512;
    const ticket = try protector.seal(allocator, &state, 2_000, &ticket_buf);

    var invalid_limits = session.Limits.default;
    invalid_limits.max_fields = 0;
    protector.limits = invalid_limits;
    var out: session.ServerRecoverableState = .{};
    defer out.deinit();
    try testing.expectError(error.InvalidInternalState, protector.resolve(allocator, ticket, 2_000, &out));

    protector.limits = session.Limits.default;
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 1 });
    try testing.expectError(error.OutOfMemory, protector.resolve(failing.allocator(), ticket, 2_000, &out));
    try testing.expectEqual(@as(u32, 0), out.ticket_age_add);
    try testing.expectEqual(@as(usize, 0), out.common.resumption_psk.len);
}

test "ServerPskResolver adapter uses one captured time for now and recovery" {
    const allocator = testing.allocator;
    var keyring = ReloadableKeyRing.init(allocator);
    defer keyring.deinit();
    const config = sampleKeyConfig(keyId(20), .aes_128_gcm, .{ .prefix = .{ 2, 0, 2, 0 }, .start = 0, .end_exclusive = 3 });
    try keyring.install(try keyring.buildSnapshot(&.{config}, testCapabilities()));

    var state = try sampleServerState(allocator);
    defer state.deinit();
    var protector = Protector{ .provider = testProvider(), .keyring = &keyring, .limits = session.Limits.default };
    var ticket_buf = [_]u8{0} ** 512;
    const ticket = try protector.seal(allocator, &state, 2_000, &ticket_buf);

    var adapter = ServerPskResolverAdapter{
        .protector = &protector,
        .allocator = allocator,
        .now_unix_ms = 2_000,
    };
    const resolver = adapter.resolver();
    try testing.expectEqual(@as(i64, 2_000), resolver.nowUnixMs());

    var out = try resolver.resolve(ticket);
    defer out.deinit();
    try testing.expect(out == .hit);
    try testing.expectEqual(state.ticket_age_add, out.hit.state.ticket_age_add);
    try testing.expectEqualSlices(u8, state.common.resumption_psk.slice(), out.hit.state.common.resumption_psk.slice());

    var miss = try resolver.resolve("not-a-ticket");
    defer miss.deinit();
    try testing.expect(miss == .miss);

    adapter.now_unix_ms = 20_000;
    var expired = try resolver.resolve(ticket);
    defer expired.deinit();
    try testing.expect(expired == .miss);
}

test "key windows and ticket lifetime are enforced" {
    const allocator = testing.allocator;
    var keyring = ReloadableKeyRing.init(allocator);
    defer keyring.deinit();
    const config = sampleKeyConfig(keyId(4), .aes_128_gcm, .{ .prefix = .{ 4, 4, 4, 4 }, .start = 0, .end_exclusive = 3 });
    try keyring.install(try keyring.buildSnapshot(&.{config}, testCapabilities()));
    var protector = Protector{ .provider = testProvider(), .keyring = &keyring, .limits = session.Limits.default };
    var state = try sampleServerState(allocator);
    defer state.deinit();
    var ticket_buf = [_]u8{0} ** 512;

    try testing.expectError(error.NoActiveEncryptionKey, protector.seal(allocator, &state, 999, &ticket_buf));
    _ = try protector.seal(allocator, &state, 4_999, &ticket_buf);
    try testing.expectError(error.NoActiveEncryptionKey, protector.seal(allocator, &state, 5_000, &ticket_buf));

    state.common.lifetime_seconds = 20;
    try testing.expectError(error.TicketOutlivesKey, protector.seal(allocator, &state, 2_000, &ticket_buf));
}

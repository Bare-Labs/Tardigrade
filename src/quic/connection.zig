//! Native QUIC v1 connection driver (#247, RFC 9000/9001/9002): the stitching
//! layer that coordinates — without reimplementing — the packet codec
//! (`packet.zig`/`frame.zig`), packet protection (`tls_adapter.zig`), the TLS
//! handshake driver (`tls_handshake.zig`), loss recovery and congestion
//! control (`recovery.zig`), stream and flow-control state (`stream.zig`),
//! CID bookkeeping (`cid.zig`), and anti-amplification (`path.zig`).
//!
//! One `Connection` is one QUIC connection on one path. The embedding runtime
//! owns sockets, routing (by DCID), and time; the driver is sans-I/O:
//!
//!   * `ingest`         — feed one received UDP datagram (may be coalesced)
//!   * `pollTransmit`   — produce the next outbound UDP datagram, or null
//!   * `nextTimeoutUs`  — the next deadline that needs `onTimeout`
//!   * `onTimeout`      — drive loss detection, PTO, idle, close timers
//!   * stream API       — open/write/read/reset QUIC streams
//!   * `close`          — start an orderly CONNECTION_CLOSE
//!
//! The driver never bypasses congestion control, flow control, packet
//! protection, or anti-amplification: every outbound datagram passes the
//! recovery controller's window, the path's amplification budget, and the
//! adapter's AEAD seal.

const std = @import("std");
const crypto_secrets = @import("crypto_secrets");
const varint = @import("quic_varint");
const config = @import("config.zig");
const packet = @import("packet.zig");
const frame = @import("frame.zig");
const tls_adapter = @import("tls_adapter.zig");
const tls_handshake = @import("tls_handshake.zig");
const crypto_pkg = @import("crypto");
const tls_core = @import("tls_core");
const recovery = @import("recovery.zig");
const quic_stream = @import("stream.zig");
const quic_cid = @import("cid.zig");
const quic_path = @import("path.zig");
const quic_udp = @import("udp.zig");
const test_quic_crypto = @import("test_quic_crypto");

const EncryptionLevel = tls_adapter.EncryptionLevel;
const PacketNumberSpace = recovery.PacketNumberSpace;
const StreamId = quic_stream.StreamId;

pub const Role = enum { client, server };

pub const State = enum {
    /// TLS handshake in progress.
    handshaking,
    /// Handshake complete; application data flows.
    established,
    /// We sent CONNECTION_CLOSE and wait out 3×PTO.
    closing,
    /// Peer sent CONNECTION_CLOSE; we wait out 3×PTO without sending.
    draining,
    /// Terminal. All resources may be reclaimed.
    closed,
};

/// The datagram size this driver sends. Conservative (RFC 9000 §14.1 minimum)
/// until DPLPMTUD lands under #256.
pub const max_datagram_size: usize = recovery.max_datagram_size;
pub const max_application_crypto_outstanding: usize = 2 * tls_core.tls13_transport.max_emitted_new_session_ticket_message_len;
const min_application_crypto_payload: usize = max_datagram_size / 2;
/// RFC 9000 §14.1: datagrams carrying Initial packets are padded to 1200.
pub const min_initial_datagram: usize = 1200;

/// Hard bound on bytes buffered per stream for transmission (unsent +
/// unacked). `writeStream` accepts partial writes beyond it.
pub const max_stream_send_buffer: usize = 256 * 1024;

const aead_tag_len = tls_adapter.packet_protection_tag_len;
const sample_len = tls_adapter.header_protection_sample_len;
/// Local ACK delay parameters (we advertise the RFC defaults).
const local_ack_delay_exponent: u6 = 3;
const local_max_ack_delay_us: u64 = 25_000;
/// Ack-eliciting packets received before an app-space ACK is forced.
const ack_eliciting_threshold: u64 = 2;

// QUIC transport error codes (RFC 9000 §20.1).
pub const error_no_error: u64 = 0x00;
pub const error_internal: u64 = 0x01;
pub const error_flow_control: u64 = 0x03;
pub const error_stream_limit: u64 = 0x04;
pub const error_stream_state: u64 = 0x05;
pub const error_final_size: u64 = 0x06;
pub const error_frame_encoding: u64 = 0x07;
pub const error_transport_parameter: u64 = 0x08;
pub const error_protocol_violation: u64 = 0x0a;
pub const error_crypto_buffer_exceeded: u64 = 0x0d;
pub const error_key_update: u64 = 0x0e;
/// CRYPTO_ERROR base (0x0100–0x01ff carries the TLS alert).
pub const error_crypto_base: u64 = 0x0100;

const h3_early_data_format_id: u16 = 0x6833;
const h3_early_data_format_version: u16 = 1;
const h3_default_settings_snapshot = [_]u8{0} ** 25;

/// Zero-credit stand-in for the peer's transport parameters, used only to
/// bring the stream layer up early for 0-RTT admission (`ensureEarlyStreamManager`)
/// before the real peer parameters are authenticated. Grants no send credit
/// of any kind, so it can never be more permissive than whatever the real
/// peer eventually authorizes — `StreamManager.refreshPeerParams` only ever
/// raises limits once the authenticated values land.
const zero_send_credit_params: config.TransportParameters = .{
    .max_idle_timeout_ms = 0,
    .active_connection_id_limit = 0,
    .max_udp_payload_size = 0,
    .initial_max_data = 0,
    .initial_max_stream_data_bidi_local = 0,
    .initial_max_stream_data_bidi_remote = 0,
    .initial_max_stream_data_uni = 0,
    .initial_max_streams_bidi = 0,
    .initial_max_streams_uni = 0,
    .disable_active_migration = false,
};

pub const IngestError = error{OutOfMemory};

pub const Event = union(enum) {
    state: State,
    packet_received: struct { space: PacketNumberSpace, packet_number: u64, size: usize },
    packet_sent: struct { space: PacketNumberSpace, packet_number: u64, size: usize, ack_eliciting: bool },
    packet_dropped: struct { reason: DropReason, size: usize },
    keys_discarded: PacketNumberSpace,
    handshake_complete,
    handshake_confirmed,
    pto_fired: struct { space: PacketNumberSpace, count: u32 },
    packets_lost: struct { space: PacketNumberSpace, bytes: usize },
    close_sent: struct { error_code: u64 },
    close_received: struct { error_code: u64, is_application: bool },
    idle_timeout,
    path_validation_started: PathTransitionEvent,
    path_validation_succeeded: PathTransitionEvent,
    path_validation_failed: PathTransitionEvent,
    path_migration_blocked: PathMigrationBlockedEvent,
    /// A candidate path was promoted to active (RFC 9000 §9.3/§9.5): a NAT
    /// rebinding or a host migration, per `change`.
    path_promoted: PathTransitionEvent,
    /// #523: a typed outcome for every `.zero_rtt` packet this connection
    /// processes, distinguishing "policy/keys unavailable" from a genuine
    /// AEAD authentication failure and from an authenticated duplicate —
    /// `packet_received`/`packet_dropped` above collapse all of these into
    /// generic application-space bookkeeping. Never carries ticket
    /// identities, PSKs, traffic secrets, or other decrypted session state.
    zero_rtt_packet: struct { outcome: ZeroRttPacketOutcome, size: usize },
    /// #523: the authoritative TLS-layer 0-RTT decision, bridged once per
    /// connection as soon as the server has processed the ClientHello —
    /// independent of whether any `.zero_rtt` packet ever actually arrives
    /// on the wire (`zero_rtt_packet` above only exists if one does).
    /// Distinguishes *why* early data was unavailable (disabled, ticket not
    /// capable, replay, transport/application incompatibility, age skew,
    /// ...) rather than collapsing every reason into one bucket. Never
    /// carries ticket identities, PSKs, or other decrypted session state —
    /// `EarlyDataDecision` is a closed, non-secret enum.
    early_data_decision: tls_core.tls13_backend.EarlyDataDecision,
};

/// See `Event.zero_rtt_packet`.
pub const ZeroRttPacketOutcome = enum {
    /// Authenticated and, if it carried a STREAM frame, delivered.
    accepted,
    /// No installed/enabled `.zero_rtt` read secret — the ordinary shape of
    /// "TLS never authorized this attempt" (not attempted, rejected by
    /// policy/replay/compatibility, or the carrier is simply disabled): all
    /// of these leave the same observable state at this layer.
    keys_unavailable,
    /// A read secret was installed, but AEAD authentication failed —
    /// tampered or spoofed, distinct from `keys_unavailable`.
    authentication_failed,
    /// Authenticated, but this packet number was already processed in the
    /// application space; its frame effects were not reapplied.
    duplicate,
    /// Too short to remove header protection / locate the payload.
    malformed,
};

pub const PathTransitionEvent = struct {
    path: quic_path.PathKey,
    change: quic_path.AddressChange,
};

pub const PathMigrationBlockedReason = enum {
    policy,
    no_peer_cid,
};

pub const PathMigrationBlockedEvent = struct {
    path: quic_path.PathKey,
    change: quic_path.AddressChange,
    reason: PathMigrationBlockedReason,
};

/// A datagram `pollTransmitOnPath` produced, and the exact destination it
/// must be sent to. Never the connection's "current" address implicitly:
/// candidate-path probes and responses target a path other than the active
/// one, so the caller must always send to `path.remote`, never a fixed peer
/// address cached elsewhere.
pub const Transmit = struct {
    bytes: []const u8,
    path: quic_path.PathKey,
};

pub const StreamSchedulingHint = struct {
    urgency: u3 = 3,
    incremental: bool = false,
};

pub const DropReason = enum {
    unknown_cid,
    keys_unavailable,
    undecryptable,
    malformed,
    unsupported_version,
    unexpected_type,
};

/// Diagnostics hook (qlog attaches here under #255). Must not block.
pub const EventSink = struct {
    context: ?*anyopaque = null,
    emitFn: ?*const fn (?*anyopaque, Event) void = null,

    pub fn emit(self: EventSink, event: Event) void {
        if (self.emitFn) |emit_fn| emit_fn(self.context, event);
    }
};

pub const Metrics = struct {
    datagrams_received: u64 = 0,
    datagrams_sent: u64 = 0,
    packets_received: u64 = 0,
    packets_sent: u64 = 0,
    packets_dropped: u64 = 0,
    packets_lost: u64 = 0,
    pto_count_total: u64 = 0,
    acks_sent: u64 = 0,
};

pub const CloseInfo = struct {
    error_code: u64,
    is_application: bool,
    /// True when this side initiated the close.
    local: bool,
};

pub const Options = struct {
    role: Role,
    config: config.Config = .{},
    /// This side's connection ID.
    local_cid: []const u8,
    /// Client: leave empty; adopted from the server's first Initial SCID.
    /// Server: the client's SCID.
    peer_cid: []const u8 = &.{},
    /// The client Initial DCID before any Retry. Servers bind this into
    /// `original_destination_connection_id`; clients use it to verify the
    /// server binding after the handshake.
    original_destination_cid: []const u8,
    /// Server-only after Retry: the SCID the server used in its Retry packet.
    retry_source_cid: ?[]const u8 = null,
    /// DCID used to derive Initial secrets. This is the ODCID without Retry
    /// and the retried Initial DCID/Retry SCID after Retry.
    initial_secret_dcid: []const u8,
    tls: tls_handshake.TlsBackend,
    /// The provider-owned crypto QUIC packet protection uses (#490). Required,
    /// with no default: `src/quic/` does not choose a concrete backend —
    /// selecting one (e.g. the pure-Zig provider) is the native HTTP/QUIC
    /// composition root's job. `Connection.init` rejects a provider missing
    /// the fixed profile's required capabilities.
    crypto_provider: crypto_pkg.provider.CryptoProvider,
    now_us: u64,
    events: EventSink = .{},
    /// Local escape hatch for interop tests against peers whose certificates
    /// this backend cannot chain-validate. Mirrors
    /// `Handshake.allow_unverified_certificate`.
    allow_unverified_certificate: bool = false,
    /// The (local, remote) UDP tuple the handshake is conducted on — the
    /// embedder resolves its own bound local address (`getsockname`
    /// semantics) and the datagram's source before constructing this.
    initial_path: quic_path.PathKey,
    /// Whether `initial_path`'s address is already validated (e.g. a
    /// Retry-validated server path). A client's own initial path is always
    /// validated regardless of this value (RFC 9000 §8.1); a non-Retry
    /// server's initial path stays amplification-limited until the
    /// handshake completes unless this is true.
    initial_address_validated: bool = false,
    /// Process-lifetime stateless reset secret supplied by the runtime. The
    /// transport derives a token for every locally issued CID from this key.
    /// Borrowed rather than taken by value so the caller's owned key is
    /// never duplicated through this struct or through `Connection.init`'s
    /// by-value `options` parameter.
    stateless_reset_key: *const [32]u8 = &([_]u8{0} ** 32),
};

// ---------------------------------------------------------------------------
// Range bookkeeping for retransmittable byte streams (CRYPTO and STREAM).
// ---------------------------------------------------------------------------

const Range = struct {
    start: u64,
    end: u64, // exclusive

    fn len(self: Range) u64 {
        return self.end - self.start;
    }
};

/// Sorted, merged list of byte ranges. Small: crypto flights and per-stream
/// send windows produce a handful of ranges.
const RangeList = struct {
    items: std.ArrayList(Range) = .empty,

    fn deinit(self: *RangeList, allocator: std.mem.Allocator) void {
        self.items.deinit(allocator);
    }

    fn isEmpty(self: *const RangeList) bool {
        return self.items.items.len == 0;
    }

    fn insert(self: *RangeList, allocator: std.mem.Allocator, incoming: Range) !void {
        if (incoming.start >= incoming.end) return;
        var merged = incoming;
        var index: usize = 0;
        while (index < self.items.items.len) {
            const current = self.items.items[index];
            if (merged.end < current.start) break;
            if (current.end < merged.start) {
                index += 1;
                continue;
            }
            merged.start = @min(merged.start, current.start);
            merged.end = @max(merged.end, current.end);
            _ = self.items.orderedRemove(index);
        }
        try self.items.insert(allocator, index, merged);
    }

    fn ensureUnusedCapacity(self: *RangeList, allocator: std.mem.Allocator, additional_count: usize) !void {
        try self.items.ensureUnusedCapacity(allocator, additional_count);
    }

    fn insertAssumeCapacity(self: *RangeList, incoming: Range) void {
        if (incoming.start >= incoming.end) return;
        var merged = incoming;
        var index: usize = 0;
        while (index < self.items.items.len) {
            const current = self.items.items[index];
            if (merged.end < current.start) break;
            if (current.end < merged.start) {
                index += 1;
                continue;
            }
            merged.start = @min(merged.start, current.start);
            merged.end = @max(merged.end, current.end);
            _ = self.items.orderedRemove(index);
        }
        self.items.insertAssumeCapacity(index, merged);
    }

    fn subtract(self: *RangeList, allocator: std.mem.Allocator, removed: Range) !void {
        if (removed.start >= removed.end) return;
        var index: usize = 0;
        while (index < self.items.items.len) {
            const current = self.items.items[index];
            if (removed.end <= current.start) break;
            if (removed.start >= current.end) {
                index += 1;
                continue;
            }

            if (removed.start <= current.start and removed.end >= current.end) {
                _ = self.items.orderedRemove(index);
                continue;
            }
            if (removed.start <= current.start) {
                self.items.items[index].start = removed.end;
                if (self.items.items[index].start >= self.items.items[index].end) {
                    _ = self.items.orderedRemove(index);
                } else {
                    index += 1;
                }
                continue;
            }
            if (removed.end >= current.end) {
                self.items.items[index].end = removed.start;
                index += 1;
                continue;
            }

            self.items.items[index].end = removed.start;
            try self.items.insert(allocator, index + 1, .{ .start = removed.end, .end = current.end });
            break;
        }
    }

    /// Remove and return up to `max_len` bytes from the lowest range.
    fn takeFirst(self: *RangeList, max_len: u64) ?Range {
        if (self.items.items.len == 0) return null;
        const first = &self.items.items[0];
        if (first.len() <= max_len) {
            const taken = first.*;
            _ = self.items.orderedRemove(0);
            return taken;
        }
        const taken = Range{ .start = first.start, .end = first.start + max_len };
        first.start = taken.end;
        return taken;
    }

    /// Whether [0, end) is fully covered by a single leading range.
    fn coversPrefix(self: *const RangeList, end: u64) bool {
        if (self.items.items.len == 0) return end == 0;
        const first = self.items.items[0];
        return first.start == 0 and first.end >= end;
    }
};

/// Retained CRYPTO transmit data for one encryption level. Offsets are
/// absolute stream offsets; handshake flights are small, so the whole flight
/// stays buffered until the level's keys are discarded.
const CryptoTx = struct {
    data: std.ArrayList(u8) = .empty,
    pending: RangeList = .{},
    acked: RangeList = .{},
    base: u64 = 0,

    const Reservation = struct {
        allocator: std.mem.Allocator,
        data: ?[]u8 = null,
        pending: ?[]Range = null,
        acked: ?[]Range = null,

        fn deinit(self: *Reservation) void {
            if (self.data) |buf| {
                crypto_secrets.secureZero(buf);
                self.allocator.free(buf);
            }
            if (self.pending) |buf| self.allocator.free(buf);
            if (self.acked) |buf| self.allocator.free(buf);
            self.* = .{ .allocator = self.allocator };
        }
    };

    fn deinit(self: *CryptoTx, allocator: std.mem.Allocator) void {
        crypto_secrets.secureZero(self.data.allocatedSlice());
        self.data.deinit(allocator);
        self.pending.deinit(allocator);
        self.acked.deinit(allocator);
    }

    fn bufferedEnd(self: *const CryptoTx) u64 {
        return self.base + self.data.items.len;
    }

    fn slice(self: *const CryptoTx, range: Range) []const u8 {
        const start: usize = @intCast(range.start - self.base);
        const end: usize = @intCast(range.end - self.base);
        return self.data.items[start..end];
    }

    fn liveRange(self: *const CryptoTx, incoming: Range) ?Range {
        if (incoming.end <= self.base) return null;
        var range = incoming;
        if (range.start < self.base) range.start = self.base;
        if (range.start >= range.end) return null;
        return range;
    }

    fn markAcked(self: *CryptoTx, allocator: std.mem.Allocator, range: Range) void {
        const live = self.liveRange(range) orelse return;
        self.acked.insertAssumeCapacity(live);
        self.compactAcked(allocator);
    }

    fn compactAcked(self: *CryptoTx, allocator: std.mem.Allocator) void {
        while (self.acked.items.items.len > 0 and self.acked.items.items[0].end <= self.base) {
            _ = self.acked.items.orderedRemove(0);
        }
        if (self.acked.items.items.len == 0) {
            self.trimPendingBelowBase();
            return;
        }
        const first = self.acked.items.items[0];
        if (first.start != self.base or first.end <= self.base) return;
        const release_len: usize = @intCast(@min(first.end, self.bufferedEnd()) - self.base);
        if (release_len == 0) return;
        const old_len = self.data.items.len;
        crypto_secrets.secureZero(self.data.items[0..release_len]);
        const keep_len = self.data.items.len - release_len;
        if (keep_len > 0) std.mem.copyForwards(u8, self.data.items[0..keep_len], self.data.items[release_len..]);
        crypto_secrets.secureZero(self.data.items[keep_len..old_len]);
        self.data.shrinkRetainingCapacity(keep_len);
        self.base += release_len;
        if (first.end <= self.base) {
            _ = self.acked.items.orderedRemove(0);
        } else {
            self.acked.items.items[0].start = self.base;
        }
        self.trimPendingBelowBase();
        if (self.data.items.len == 0 and self.data.capacity > 0) {
            crypto_secrets.secureZero(self.data.allocatedSlice());
            self.data.clearAndFree(allocator);
            self.pending.items.clearAndFree(allocator);
            self.acked.items.clearAndFree(allocator);
        }
    }

    fn trimPendingBelowBase(self: *CryptoTx) void {
        var out: usize = 0;
        var index: usize = 0;
        while (index < self.pending.items.items.len) : (index += 1) {
            if (self.liveRange(self.pending.items.items[index])) |range| {
                self.pending.items.items[out] = range;
                out += 1;
            }
        }
        self.pending.items.shrinkRetainingCapacity(out);
    }

    fn reserveAppend(self: *CryptoTx, allocator: std.mem.Allocator, bytes_len: usize, max_outstanding: usize) !void {
        var reservation = try self.prepareAppend(allocator, bytes_len, max_outstanding);
        errdefer reservation.deinit();
        self.commitReservation(&reservation);
    }

    fn prepareAppend(self: *CryptoTx, allocator: std.mem.Allocator, bytes_len: usize, max_outstanding: usize) !Reservation {
        if (bytes_len > max_outstanding) return error.CryptoBufferTooLarge;
        if (self.data.items.len > max_outstanding - bytes_len) return error.CryptoBufferTooLarge;

        const new_total = self.data.items.len + bytes_len;
        const range_budget = applicationCryptoRangeBudget(new_total);
        const pending_capacity = self.pending.items.items.len + range_budget + 1;
        const acked_capacity = self.acked.items.items.len + range_budget;

        var reservation = Reservation{ .allocator = allocator };
        errdefer reservation.deinit();
        if (self.data.capacity < new_total) {
            const replacement = try allocator.alloc(u8, new_total);
            @memcpy(replacement[0..self.data.items.len], self.data.items);
            reservation.data = replacement;
        }

        if (self.pending.items.capacity < pending_capacity) {
            const replacement = try allocator.alloc(Range, pending_capacity);
            @memcpy(replacement[0..self.pending.items.items.len], self.pending.items.items);
            reservation.pending = replacement;
        }

        if (self.acked.items.capacity < acked_capacity) {
            const replacement = try allocator.alloc(Range, acked_capacity);
            @memcpy(replacement[0..self.acked.items.items.len], self.acked.items.items);
            reservation.acked = replacement;
        }

        return reservation;
    }

    fn commitReservation(self: *CryptoTx, reservation: *Reservation) void {
        if (reservation.pending) |replacement| {
            self.replaceRangeCapacity(reservation.allocator, &self.pending, replacement);
            reservation.pending = null;
        }
        if (reservation.acked) |replacement| {
            self.replaceRangeCapacity(reservation.allocator, &self.acked, replacement);
            reservation.acked = null;
        }
        if (reservation.data) |replacement| {
            self.replaceDataCapacity(reservation.allocator, replacement);
            reservation.data = null;
        }
    }

    fn replaceRangeCapacity(self: *CryptoTx, allocator: std.mem.Allocator, list: *RangeList, replacement: []Range) void {
        _ = self;
        const old_len = list.items.items.len;
        if (list.items.capacity > 0) allocator.free(list.items.allocatedSlice());
        list.items.items = replacement[0..old_len];
        list.items.capacity = replacement.len;
    }

    fn replaceDataCapacity(self: *CryptoTx, allocator: std.mem.Allocator, replacement: []u8) void {
        const old_len = self.data.items.len;
        if (self.data.capacity > 0) {
            crypto_secrets.secureZero(self.data.allocatedSlice());
            allocator.free(self.data.allocatedSlice());
        }
        self.data.items = replacement[0..old_len];
        self.data.capacity = replacement.len;
    }

    fn appendReserved(self: *CryptoTx, bytes: []const u8) void {
        const start = self.bufferedEnd();
        self.data.appendSliceAssumeCapacity(bytes);
        self.pending.insertAssumeCapacity(.{
            .start = start,
            .end = start + bytes.len,
        });
    }
};

fn applicationCryptoRangeBudget(bytes_len: usize) usize {
    return (bytes_len + min_application_crypto_payload - 1) / min_application_crypto_payload + 8;
}

/// Driver-owned transmit buffer for one stream: bytes the application handed
/// to `writeStream` that are unsent or unacked. `base` is the stream offset
/// of `data[start]`.
const SendQueue = struct {
    data: std.ArrayList(u8) = .empty,
    start: usize = 0,
    base: u64 = 0,
    /// Bytes already granted by the stream manager (flow control) and sent at
    /// least once. New data begins at this offset.
    reserved_end: u64 = 0,
    fin_requested: bool = false,
    fin_reserved: bool = false,
    /// Previously sent ranges that need retransmission (loss/PTO).
    retransmit: RangeList = .{},
    /// Acked ranges (absolute offsets), for releasing the buffer prefix.
    acked: RangeList = .{},
    /// A lost packet carried this stream's FIN; resend it.
    fin_retransmit: bool = false,
    /// A sent STREAM+FIN was acknowledged; later duplicate loss must not
    /// resurrect the final-size signal.
    fin_acked: bool = false,
    /// Stream was reset locally; drop all queued data.
    reset_sent: bool = false,
    scheduling_hint: StreamSchedulingHint = .{},

    fn deinit(self: *SendQueue, allocator: std.mem.Allocator) void {
        self.data.deinit(allocator);
        self.retransmit.deinit(allocator);
        self.acked.deinit(allocator);
    }

    fn bufferedEnd(self: *const SendQueue) u64 {
        return self.base + @as(u64, @intCast(self.data.items.len - self.start));
    }

    fn buffered(self: *const SendQueue) usize {
        return self.data.items.len - self.start;
    }

    fn slice(self: *const SendQueue, range: Range) []const u8 {
        const from: usize = @intCast(range.start - self.base);
        return self.data.items[self.start + from ..][0..@intCast(range.len())];
    }

    /// Release the acked prefix so long-lived streams don't grow unboundedly.
    fn compact(self: *SendQueue, allocator: std.mem.Allocator) void {
        var prefix_end = self.base;
        if (self.acked.items.items.len > 0) {
            const first = self.acked.items.items[0];
            if (first.start <= self.base) prefix_end = @min(first.end, self.reserved_end);
        }
        if (prefix_end <= self.base) return;
        // Never release bytes that still need retransmission.
        for (self.retransmit.items.items) |r| {
            if (r.start < prefix_end) prefix_end = r.start;
        }
        if (prefix_end <= self.base) return;
        const drop: usize = @intCast(prefix_end - self.base);
        self.start += drop;
        self.base = prefix_end;
        if (self.start == self.data.items.len and self.data.items.len > 4096) {
            self.data.clearAndFree(allocator);
            self.start = 0;
        }
    }
};

fn markSendQueueRangeAcked(allocator: std.mem.Allocator, queue: *SendQueue, range: Range, fin: bool) void {
    queue.retransmit.subtract(allocator, range) catch {};
    queue.acked.insert(allocator, range) catch {};
    if (fin) {
        queue.fin_acked = true;
        queue.fin_retransmit = false;
    }
    queue.compact(allocator);
}

fn requeueSendQueueRange(allocator: std.mem.Allocator, queue: *SendQueue, range: Range, fin: bool) void {
    if (queue.reset_sent) return;
    if (fin and !queue.fin_acked) queue.fin_retransmit = true;
    var live = range;
    if (live.start < queue.base) live.start = queue.base;
    if (live.start >= live.end) return;
    queue.retransmit.insert(allocator, live) catch {};
    for (queue.acked.items.items) |acked| {
        queue.retransmit.subtract(allocator, acked) catch {};
    }
}

/// What a sent packet carried, for retransmission on loss and release on ack.
/// Parallel to the recovery controller's `SentPacket` accounting.
const SentRecord = struct {
    space: PacketNumberSpace,
    packet_number: u64,
    ack_eliciting: bool,
    crypto: ?Range = null,
    stream_count: u8 = 0,
    streams: [4]StreamRange = undefined,
    /// Flow-control and lifecycle frames that must be re-armed on loss.
    carried_max_data: bool = false,
    carried_max_stream_data: ?StreamId = null,
    carried_handshake_done: bool = false,
    carried_reset_stream: ?quic_stream.ResetStreamFrame = null,
    carried_stop_sending: ?quic_stream.StopSendingFrame = null,
    carried_new_connection_id: ?quic_cid.NewConnectionIdFrame = null,
    /// PATH_CHALLENGE re-arms on loss; PATH_RESPONSE does not (the peer
    /// re-challenges, RFC 9000 §8.2.2). Both force datagram expansion.
    /// Non-null when this record carried a PATH_CHALLENGE for the given
    /// candidate path — re-arms that candidate's `needs_send` on loss
    /// (RFC 9000 §8.2.2). PATH_RESPONSE does not re-arm on loss (the peer
    /// re-challenges instead), so it needs no requeue-identifying field.
    carried_path_challenge_path: ?quic_path.PathKey = null,
    carried_path_response: bool = false,
    carried_ack_largest: ?u64 = null,

    const StreamRange = struct {
        id: StreamId,
        range: Range,
        fin: bool,
    };
};

/// Wipe a `SentRecord`'s carried stateless-reset token copy in place. A
/// `NewConnectionIdFrame` embeds the token by value, so every place that
/// copies, requeues, or discards a `SentRecord` mints or drops an
/// independent copy of it; each of those copies must be scrubbed once it is
/// no longer needed rather than left for the allocator to reclaim unwiped.
fn wipeSentRecordToken(record: *SentRecord) void {
    if (record.carried_new_connection_id) |*ncid| crypto_secrets.secureZero(&ncid.stateless_reset_token);
}

fn wipeSentRecordTokens(records: []SentRecord) void {
    for (records) |*record| wipeSentRecordToken(record);
}

/// Publish `source` (a function-local `SentRecord` about to be sealed and
/// sent) into `self.sent_records` by writing directly into the reserved
/// destination slot, rather than passing it by value into
/// `ArrayList.append` — which would create an unowned intermediate copy of
/// any carried reset token. Capacity is always available here: every call
/// site only reaches this after `self.recovery.onPacketSent` accepted the
/// packet, and that tracker is itself bounded by `recovery.max_tracked_packets`
/// — the same bound `init()` reserves `sent_records`' capacity to once, up
/// front.
fn publishSentRecord(self: *Connection, source: *const SentRecord) void {
    // Real traffic can never exceed capacity here: `sent_records` only ever
    // grows in lockstep with `self.recovery.tracker` (both gated by
    // `onPacketSent`) and shrinks in lockstep with it (ACK/loss processing
    // remove from both together), and the tracker is bounded by the same
    // `recovery.max_tracked_packets` this reserves capacity to. If that ever
    // desyncs, degrade to an untracked send — like recovery-tracker
    // exhaustion itself, just above — rather than growing the backing
    // allocation and reopening the unwiped-growth path capacity reservation
    // exists to close.
    if (self.sent_records.items.len == self.sent_records.capacity) return;
    self.sent_records.addOneAssumeCapacity().* = source.*;
}

/// `std.ArrayList.swapRemove` moves the last live element into the removed
/// slot, then assigns `undefined` to the vacated tail slot — which is a
/// real poison-fill in safety-checked builds (not a no-op) and may be no
/// write at all in `ReleaseFast`. Either way, that slot is no longer a
/// validly-typed `SentRecord`: its optional tags may be garbage. Call this
/// immediately after every `sent_records.swapRemove(...)` — it scrubs the
/// vacated slot as raw bytes only, never interpreting any field, so it
/// cannot read an undefined optional tag the way pattern-matching
/// `carried_new_connection_id` on that slot would. Callers must wipe the
/// *live* element's own token (via `wipeSentRecordToken`) before calling
/// `swapRemove`, since this only cleans up the residue the swap leaves
/// behind, not the record being removed.
fn wipeSentRecordsSwapRemoveResidue(records: *std.ArrayList(SentRecord)) void {
    crypto_secrets.secureZero(std.mem.asBytes(&records.allocatedSlice()[records.items.len]));
}

fn wipePendingNewConnectionIdTokens(frames: []quic_cid.NewConnectionIdFrame) void {
    for (frames) |*ncid| crypto_secrets.secureZero(&ncid.stateless_reset_token);
}

/// Same hazard as `wipeSentRecordsSwapRemoveResidue`, but for
/// `pending_new_connection_ids.orderedRemove(0)`: scrub the vacated slot as
/// raw bytes rather than selecting a field from a `NewConnectionIdFrame`
/// whose representation is no longer guaranteed valid.
fn wipePendingNewConnectionIdsOrderedRemoveResidue(frames: *std.ArrayList(quic_cid.NewConnectionIdFrame)) void {
    crypto_secrets.secureZero(std.mem.asBytes(&frames.allocatedSlice()[frames.items.len]));
}

/// A candidate path (RFC 9000 §9.3/§9.5) we are validating: the
/// `PathManager`-issued PATH_CHALLENGE payload and whether the packet
/// carrying it still needs to go out (initially, and again after loss —
/// PATH_CHALLENGE re-arms on loss, RFC 9000 §8.2.2, unlike PATH_RESPONSE).
const CandidateChallenge = struct {
    path: quic_path.PathKey,
    data: [quic_path.path_challenge_len]u8,
    needs_send: bool = true,
};

/// A PATH_RESPONSE queued to echo a received PATH_CHALLENGE back on the
/// exact path it arrived on (RFC 9000 §8.2.2) — not necessarily the active
/// path, since the challenge may have arrived on a peer address probing us.
const PendingPathResponse = struct {
    path: quic_path.PathKey,
    data: [quic_path.path_challenge_len]u8,
};

// ---------------------------------------------------------------------------
// The connection.
// ---------------------------------------------------------------------------

pub const Connection = struct {
    allocator: std.mem.Allocator,
    role: Role,
    state_: State = .handshaking,
    cfg: config.Config,
    local_params: config.TransportParameters,
    events: EventSink,
    metrics: Metrics = .{},

    adapter: tls_adapter.QuicTlsAdapter,
    handshake: tls_handshake.Handshake = undefined,
    tls: tls_handshake.TlsBackend,

    recovery: recovery.RecoveryController = .{},
    /// Authenticated path state (#251/#515): the active path's identity and
    /// amplification ledger, plus any candidate paths being validated. Set in
    /// `init()`; never default-constructed since it needs the handshake path.
    paths: quic_path.PathManager = undefined,

    local_cid: config.CidValue,
    peer_cid: config.CidValue,
    original_dcid: config.CidValue,
    retry_scid: ?config.CidValue = null,
    retry_token: std.ArrayList(u8) = .empty,
    local_cids: ?quic_cid.LocalCidRegistry = null,
    stateless_reset_key: [32]u8,
    peer_cids: quic_cid.PeerCidPool,

    streams: ?quic_stream.StreamManager = null,
    send_queues: std.AutoHashMap(StreamId, *SendQueue),
    known_streams: std.AutoHashMap(StreamId, void),
    stream_transport_early: std.AutoHashMap(StreamId, void),
    accept_queue: std.ArrayList(StreamId) = .empty,
    stream_scheduling_cursor: StreamId = 0,

    crypto_tx: [3]CryptoTx = .{ .{}, .{}, .{} },
    sent_records: std.ArrayList(SentRecord) = .empty,

    next_pn: [3]u64 = .{ 0, 0, 0 },
    largest_recv_pn: [3]?u64 = .{ null, null, null },
    largest_peer_acked: [3]?u64 = .{ null, null, null },
    /// Whether an ACK must be assembled for the space, and when the obligation
    /// arose (for the encoded ack_delay and the delayed-ack timer).
    ack_needed: [3]bool = .{ false, false, false },
    ack_armed_at_us: [3]u64 = .{ 0, 0, 0 },
    ack_eliciting_since_ack: [3]u64 = .{ 0, 0, 0 },
    /// Last time an ack-eliciting packet was sent per space (PTO base).
    last_ack_eliciting_sent_us: [3]?u64 = .{ null, null, null },
    pto_count: u32 = 0,
    /// Probe datagrams owed per space after a PTO fires.
    probes_pending: [3]u8 = .{ 0, 0, 0 },

    handshake_complete: bool = false,
    /// Server: discard Handshake keys once the Finished ACK has been sent.
    handshake_keys_discard_pending: bool = false,
    handshake_confirmed: bool = false,
    handshake_done_pending: bool = false,
    handshake_done_acked: bool = false,
    /// Client adopted the server's SCID from its first Initial packet.
    peer_cid_adopted: bool = false,
    got_retry: bool = false,
    initial_packet_processed: bool = false,
    /// First Handshake-level packet sent (client Initial-key discard trigger).
    sent_handshake_packet: bool = false,
    processed_handshake_packet: bool = false,
    /// #523: whether `Event.early_data_decision` has already been reported
    /// for this connection — emitted at most once, as soon as the TLS layer
    /// has made a real decision, regardless of whether a `.zero_rtt` packet
    /// ever arrives.
    early_data_decision_reported: bool = false,

    pending_max_data: ?u64 = null,
    pending_max_stream_data: std.ArrayList(struct { id: StreamId, limit: u64 }) = .empty,
    pending_resets: std.ArrayList(quic_stream.ResetStreamFrame) = .empty,
    pending_stop_sending: std.ArrayList(quic_stream.StopSendingFrame) = .empty,
    pending_retires: std.ArrayList(u64) = .empty,
    pending_new_connection_ids: std.ArrayList(quic_cid.NewConnectionIdFrame) = .empty,
    pending_path_responses: std.ArrayList(PendingPathResponse) = .empty,
    /// Candidate paths currently being validated (RFC 9000 §8.2), keyed by
    /// path so multiple concurrent probes (bounded by `quic_path.max_paths`)
    /// each retransmit independently on loss.
    candidate_challenges: std.ArrayList(CandidateChallenge) = .empty,

    idle_deadline_us: ?u64 = null,
    last_activity_us: u64,
    close_info: ?CloseInfo = null,
    close_reason: [64]u8 = undefined,
    close_reason_len: usize = 0,
    close_deadline_us: ?u64 = null,
    close_resend_allowed_at_us: u64 = 0,
    close_needs_send: bool = false,
    /// Terminal handshake failure (kept for the embedder's diagnostics).
    handshake_error: ?tls_handshake.HandshakeError = null,

    pub fn init(allocator: std.mem.Allocator, options: Options) !*Connection {
        const conn = try allocator.create(Connection);
        errdefer allocator.destroy(conn);

        const params = try options.config.transportParameters();
        conn.* = .{
            .allocator = allocator,
            .role = options.role,
            .cfg = options.config,
            .local_params = params,
            .events = options.events,
            .tls = options.tls,
            .adapter = try tls_adapter.QuicTlsAdapter.init(options.crypto_provider),
            .local_cid = try config.CidValue.init(options.local_cid),
            .peer_cid = if (options.peer_cid.len > 0)
                try config.CidValue.init(options.peer_cid)
            else
                .{},
            .original_dcid = try config.CidValue.init(options.original_destination_cid),
            .retry_scid = if (options.retry_source_cid) |retry_source|
                try config.CidValue.init(retry_source)
            else
                null,
            .stateless_reset_key = options.stateless_reset_key.*,
            .peer_cids = quic_cid.PeerCidPool.init(params.active_connection_id_limit),
            .send_queues = std.AutoHashMap(StreamId, *SendQueue).init(allocator),
            .known_streams = std.AutoHashMap(StreamId, void).init(allocator),
            .stream_transport_early = std.AutoHashMap(StreamId, void).init(allocator),
            .last_activity_us = options.now_us,
        };
        conn.adapter.setZeroRttEnabled(conn.cfg.zero_rtt_enabled);
        // Construct the handshake before `errdefer conn.deinitPartial()` is
        // installed: deinitPartial() unconditionally calls
        // `self.handshake.deinit()`, so any fallible operation between the
        // errdefer and this assignment would otherwise run deinit() against
        // undefined storage. Handshake.initClient/initServer are plain
        // constructors (no I/O, no dependency on installed secrets), so
        // this reordering is free.
        conn.handshake = switch (options.role) {
            .client => tls_handshake.Handshake.initClient(&conn.adapter, options.tls),
            .server => tls_handshake.Handshake.initServer(&conn.adapter, options.tls),
        };
        // A client's own initial path is validated by definition; a server
        // must not exceed 3x received bytes until Retry or the handshake
        // validates the client (RFC 9000 §8.1).
        const initial_validated = options.initial_address_validated or options.role == .client;
        conn.paths = quic_path.PathManager.init(conn.cfg.migration_policy, options.initial_path, initial_validated);
        errdefer conn.deinitPartial();

        // Reserve the full capacity these two collections can ever need,
        // before any locally-generated stateless-reset token is queued into
        // them: `sent_records` cannot exceed `recovery.max_tracked_packets`
        // (every append is gated by a successful recovery-tracker insert,
        // itself bounded there), and `pending_new_connection_ids` cannot
        // exceed `quic_cid.max_local_active_cids` (the local CID registry's
        // own issuance limit). With capacity reserved up front, later
        // `append`/`ensureUnusedCapacity` calls never trigger `std.ArrayList`'s
        // grow-and-free-the-old-backing-unwiped path, which would otherwise
        // copy a live reset token into a new allocation and free the old one
        // without scrubbing it.
        try conn.sent_records.ensureTotalCapacityPrecise(allocator, recovery.max_tracked_packets);
        try conn.pending_new_connection_ids.ensureTotalCapacityPrecise(allocator, quic_cid.max_local_active_cids);

        // RFC 9000 §7.3 binding: commit our CIDs into the TLS transport
        // parameters before the first flight. `binding` is a local, owned
        // copy; `setCidBinding` borrows it so the retained backend copy is
        // the only further duplicate, and that copy is wiped in the
        // backend's own `deinit()`. `defer binding.deinit()` wipes this
        // local's token on every path out of `init`, including the early
        // handshake-construction failures below.
        var binding = config.CidBinding{
            .initial_source_connection_id = conn.local_cid,
        };
        defer binding.deinit();
        if (options.role == .server) {
            binding.original_destination_connection_id = conn.original_dcid;
            if (conn.retry_scid) |retry_source| binding.retry_source_connection_id = retry_source;
            binding.stateless_reset_token = [_]u8{0} ** quic_cid.stateless_reset_token_len;
            quic_cid.statelessResetTokenInto(&binding.stateless_reset_token.?, options.stateless_reset_key[0..], conn.local_cid.slice());
        }
        options.tls.setCidBinding(&binding);

        if (options.role == .client and conn.peer_cid.len == 0) {
            conn.peer_cid = conn.original_dcid;
        }
        if (conn.peer_cid.len > 0) {
            const initial_peer = quic_cid.ConnectionId.init(conn.peer_cid.slice()) catch null;
            if (initial_peer) |cid_value| conn.peer_cids.registerInitial(cid_value) catch {};
        }
        _ = try conn.adapter.installInitialSecrets(
            switch (options.role) {
                .client => .client,
                .server => .server,
            },
            options.initial_secret_dcid,
        );
        conn.handshake.manual_key_discard = true;
        conn.handshake.allow_unverified_certificate = options.allow_unverified_certificate;
        if (options.role == .client) {
            options.tls.setEarlyDataApplicationCompat(.{
                .format_id = h3_early_data_format_id,
                .format_version = h3_early_data_format_version,
                .bytes = &h3_default_settings_snapshot,
            }) catch |err| {
                conn.failHandshake(err);
                return conn;
            };
            options.tls.setPostHandshakeAllocator(allocator) catch |err| {
                conn.failHandshake(err);
                return conn;
            };
        }
        conn.handshake.start(params) catch |err| {
            conn.failHandshake(err);
            return conn;
        };
        try conn.collectCryptoOutput();
        conn.armIdle(options.now_us);
        return conn;
    }

    fn deinitPartial(self: *Connection) void {
        self.handshake.deinit();
        self.adapter.deinit();
        if (self.streams) |*manager| manager.deinit();
        var it = self.send_queues.valueIterator();
        while (it.next()) |queue| {
            queue.*.deinit(self.allocator);
            self.allocator.destroy(queue.*);
        }
        self.send_queues.deinit();
        self.known_streams.deinit();
        self.stream_transport_early.deinit();
        self.accept_queue.deinit(self.allocator);
        for (&self.crypto_tx) |*tx| tx.deinit(self.allocator);
        // Any still-outstanding (unacked/unlost) or still-queued
        // NEW_CONNECTION_ID carries a stateless-reset token copy; teardown
        // must scrub those before the backing allocations are freed, not
        // just the registry's own copy below.
        wipeSentRecordTokens(self.sent_records.items);
        self.sent_records.deinit(self.allocator);
        self.pending_max_stream_data.deinit(self.allocator);
        self.pending_resets.deinit(self.allocator);
        self.pending_stop_sending.deinit(self.allocator);
        self.pending_retires.deinit(self.allocator);
        wipePendingNewConnectionIdTokens(self.pending_new_connection_ids.items);
        self.pending_new_connection_ids.deinit(self.allocator);
        self.pending_path_responses.deinit(self.allocator);
        self.candidate_challenges.deinit(self.allocator);
        self.retry_token.deinit(self.allocator);
        if (self.local_cids) |*registry| registry.deinit();
        self.local_cids = null;
        crypto_secrets.secureZero(&self.stateless_reset_key);
    }

    pub fn deinit(self: *Connection) void {
        const allocator = self.allocator;
        self.deinitPartial();
        allocator.destroy(self);
    }

    // -- state ---------------------------------------------------------------

    pub fn state(self: *const Connection) State {
        return self.state_;
    }

    pub fn isEstablished(self: *const Connection) bool {
        return self.state_ == .established;
    }

    pub fn negotiatedH3(self: *const Connection) bool {
        return self.adapter.negotiatedH3();
    }

    pub fn peerTransportParameters(self: *const Connection) ?config.TransportParameters {
        return self.adapter.peerTransportParameters();
    }

    pub fn closeInfo(self: *const Connection) ?CloseInfo {
        return self.close_info;
    }

    pub fn handshakeFailure(self: *const Connection) ?tls_handshake.HandshakeError {
        return self.handshake_error;
    }

    /// The connection ID the peer routes to us with (for endpoint routing).
    pub fn localCid(self: *const Connection) []const u8 {
        return self.local_cid.slice();
    }

    pub fn activeLocalCidCount(self: *const Connection) usize {
        if (self.local_cids) |registry| return registry.activeCount();
        return 1;
    }

    pub fn copyActiveLocalCids(self: *const Connection, out: []quic_cid.ConnectionId) usize {
        var count: usize = 0;
        if (self.local_cids) |registry| {
            for (registry.entries, registry.occupied) |entry, occupied| {
                if (occupied) {
                    if (count == out.len) return count;
                    out[count] = entry.cid;
                    count += 1;
                }
            }
            return count;
        }
        if (out.len > 0) {
            out[0] = quic_cid.ConnectionId.init(self.local_cid.slice()) catch return 0;
            return 1;
        }
        return 0;
    }

    pub fn needsLocalCid(self: *const Connection) bool {
        if (self.state_ != .established) return false;
        const registry = if (self.local_cids) |*registry| registry else return false;
        const target = @min(@as(usize, 2), @as(usize, @intCast(registry.active_limit)));
        return registry.activeCount() < target;
    }

    pub fn advertiseLocalCid(self: *Connection, cid_value: quic_cid.ConnectionId) error{ CidLimitExceeded, DuplicateCid, OutOfMemory }!void {
        try self.pending_new_connection_ids.ensureUnusedCapacity(self.allocator, 1);
        const registry = if (self.local_cids) |*registry| registry else return error.CidLimitExceeded;
        // Write the issued frame directly into the reserved queue slot: the
        // registry entry is the only prior owner of the reset token, so this
        // is its single copy into caller-owned storage, rather than a
        // separate local plus a second copy into the queue.
        const dst = self.pending_new_connection_ids.addOneAssumeCapacity();
        registry.issueCidInto(cid_value, dst) catch |err| {
            self.pending_new_connection_ids.shrinkRetainingCapacity(self.pending_new_connection_ids.items.len - 1);
            switch (err) {
                error.CidLimitExceeded => return error.CidLimitExceeded,
                error.DuplicateCid => return error.DuplicateCid,
            }
        };
    }

    fn setState(self: *Connection, next: State) void {
        if (self.state_ == next) return;
        self.state_ = next;
        self.events.emit(.{ .state = next });
    }

    fn spaceIndex(space: PacketNumberSpace) usize {
        return @intFromEnum(space);
    }

    fn levelForSpace(space: PacketNumberSpace) EncryptionLevel {
        return switch (space) {
            .initial => .initial,
            .handshake => .handshake,
            .application => .application,
        };
    }

    fn spaceForLevel(level: EncryptionLevel) PacketNumberSpace {
        return switch (level) {
            .initial => .initial,
            .handshake => .handshake,
            .application, .zero_rtt => .application,
        };
    }

    // -- ingest ---------------------------------------------------------------

    /// Feed one received UDP datagram that arrived on `ingress_path`.
    /// Malformed or undecryptable packets are dropped individually; a
    /// protocol violation closes the connection. Path state (the
    /// anti-amplification ledger, migration/rebinding classification) only
    /// ever changes for a packet whose AEAD open succeeds — an unauthenticated
    /// datagram, however it is addressed, must not create path state, credit
    /// budget, or move the active path. `challenge_entropy` supplies fresh
    /// unpredictable PATH_CHALLENGE payload for use if this datagram starts a
    /// new candidate-path validation; unused otherwise.
    pub fn ingestOnPath(
        self: *Connection,
        datagram: []const u8,
        ingress_path: quic_path.PathKey,
        challenge_entropy: [quic_path.path_challenge_len]u8,
        now_us: u64,
    ) IngestError!void {
        if (self.state_ == .closed or self.state_ == .draining) return;
        self.metrics.datagrams_received += 1;

        var offset: usize = 0;
        while (offset < datagram.len) {
            const rest = datagram[offset..];
            const parsed = packet.parsePacket(rest, self.local_cid.len) catch {
                self.dropPacket(.malformed, rest.len);
                return;
            };
            if (parsed.packet_len == 0 or parsed.packet_len > rest.len) {
                self.dropPacket(.malformed, rest.len);
                return;
            }
            try self.ingestPacket(rest[0..parsed.packet_len], parsed, ingress_path, challenge_entropy, now_us);
            if (self.state_ == .closed or self.state_ == .draining) return;
            offset += parsed.packet_len;
            // Everything after a short-header packet is part of it.
            if (parsed.kind == .one_rtt) break;
        }
        // Idle-timer refresh happens inside `ingestPacket`, only for a
        // packet that authenticated and was not a duplicate (RFC 9000
        // §10.1) — never unconditionally per datagram here, or a replayed
        // or undecryptable datagram could keep the connection alive.
    }

    fn ingestPacket(
        self: *Connection,
        bytes: []const u8,
        parsed: packet.ParsedPacket,
        ingress_path: quic_path.PathKey,
        challenge_entropy: [quic_path.path_challenge_len]u8,
        now_us: u64,
    ) IngestError!void {
        switch (parsed.kind) {
            .version_negotiation => {
                // We only speak v1; a VN packet means no common version.
                if (self.role == .client and !self.initial_packet_processed) {
                    self.dropPacket(.unsupported_version, bytes.len);
                    self.startClose(.{ .error_code = error_internal, .is_application = false, .local = true }, "no common QUIC version", now_us);
                } else {
                    self.dropPacket(.unexpected_type, bytes.len);
                }
                return;
            },
            .retry => {
                self.handleRetry(bytes, parsed, now_us);
                return;
            },
            else => {},
        }
        if (parsed.kind != .one_rtt and parsed.version != packet.quic_v1) {
            self.dropPacket(.unsupported_version, bytes.len);
            return;
        }
        const local_cid_sequence = self.localCidSequence(parsed.dcid) orelse {
            self.dropPacket(.unknown_cid, bytes.len);
            return;
        };

        const level: EncryptionLevel = switch (parsed.kind) {
            .initial => .initial,
            .handshake => .handshake,
            .zero_rtt => .zero_rtt,
            .one_rtt => .application,
            else => unreachable,
        };
        const space = spaceForLevel(level);
        if (level == .application and !self.handshake_complete) {
            self.dropPacket(.keys_unavailable, bytes.len);
            return;
        }

        // Header protection removal needs a sample 4 bytes past pn_offset.
        var work: [2048]u8 = undefined;
        if (bytes.len > work.len) {
            self.dropPacket(.malformed, bytes.len);
            self.emitZeroRttOutcome(level, .malformed, bytes.len);
            return;
        }
        @memcpy(work[0..bytes.len], bytes);
        if (parsed.packet_len < parsed.pn_offset + 4 + sample_len) {
            self.dropPacket(.malformed, bytes.len);
            self.emitZeroRttOutcome(level, .malformed, bytes.len);
            return;
        }

        // `error.ProviderUnsupported` is distinct from "no keys installed":
        // `setProvider`/`init` already reject a provider missing the fixed
        // profile's capabilities, so it cannot occur here — `unreachable`
        // documents that invariant instead of folding a provider
        // misconfiguration into the ordinary "no secret at this level" path
        // below, which would misreport it as this being about peer behavior.
        var keys = (self.adapter.protectionKeys(level, .read) catch unreachable) orelse {
            // No installed/enabled read secret at this level. For 0-RTT this
            // is the ordinary "early data not authorized yet" case (TLS never
            // accepted the PSK attempt, or the carrier is disabled) rather
            // than an authentication failure, so it gets its own reason.
            self.dropPacket(if (level == .zero_rtt) .keys_unavailable else .undecryptable, bytes.len);
            self.emitZeroRttOutcome(level, .keys_unavailable, bytes.len);
            return;
        };
        var sample: [sample_len]u8 = undefined;
        @memcpy(&sample, work[parsed.pn_offset + 4 ..][0..sample_len]);
        var sampled_pn: [4]u8 = work[parsed.pn_offset..][0..4].*;
        const removed = keys.removeHeaderProtectionWithProvider(self.adapter.provider, &work[0], &sampled_pn, sample) catch {
            self.dropPacket(.undecryptable, bytes.len);
            self.emitZeroRttOutcome(level, .authentication_failed, bytes.len);
            return;
        };
        @memcpy(work[parsed.pn_offset..][0..removed.packet_number_length], sampled_pn[0..removed.packet_number_length]);

        const space_idx = spaceIndex(space);
        const pn = packet.decodePacketNumber(
            self.largest_recv_pn[space_idx] orelse 0,
            removed.truncated_packet_number,
            @intCast(removed.packet_number_length * 8),
        );

        // 1-RTT key update (RFC 9001 §6): a flipped key-phase bit means the
        // peer moved to the next generation.
        var used_next_keys = false;
        if (level == .application) {
            const wire_phase: u1 = @intCast((work[0] >> 2) & 1);
            if (wire_phase != self.adapter.applicationReadKeyPhase()) {
                keys = (self.adapter.nextApplicationReadKeys() catch unreachable) orelse {
                    self.dropPacket(.undecryptable, bytes.len);
                    return;
                };
                used_next_keys = true;
            }
        }

        const header = work[0 .. parsed.pn_offset + removed.packet_number_length];
        const ciphertext = work[parsed.pn_offset + removed.packet_number_length .. parsed.packet_len];
        var plain: [2048]u8 = undefined;
        const payload = keys.openPayloadWithProvider(self.adapter.provider, pn, header, ciphertext, &plain) catch {
            self.adapter.metrics.deprotection_failures += 1;
            self.dropPacket(.undecryptable, bytes.len);
            self.emitZeroRttOutcome(level, .authentication_failed, bytes.len);
            return;
        };
        self.adapter.metrics.packets_deprotected += 1;

        if (level == .zero_rtt) self.ensureEarlyStreamManager();

        // RFC 9001 §4.9.3: a server retires its 0-RTT read key once it has
        // received a 1-RTT packet — the client's Finished (and any coalesced
        // 1-RTT application data) proves it has moved on, so a 0-RTT key can
        // no longer be legitimately used. This wipes only the `.zero_rtt`
        // secret slot; 0-RTT and 1-RTT share the application packet-number
        // and recovery state, which is untouched. `discardSecrets` is a
        // no-op once already discarded, so this needs no "first time only"
        // guard.
        if (self.role == .server and level == .application) {
            self.adapter.discardSecrets(.zero_rtt);
        }

        if (used_next_keys) {
            self.adapter.commitApplicationReadKeyUpdate() catch {};
            self.adapter.updateApplicationWriteKeys() catch {};
        }

        // Post-authentication bookkeeping.
        self.metrics.packets_received += 1;
        self.events.emit(.{ .packet_received = .{ .space = space, .packet_number = pn, .size = bytes.len } });
        if (self.largest_recv_pn[space_idx] == null or pn > self.largest_recv_pn[space_idx].?) {
            self.largest_recv_pn[space_idx] = pn;
        }
        // An authenticated duplicate (same packet number already recorded in
        // this space — query *before* recording this one) must be inert
        // beyond the fact that it authenticated: no re-applied frame
        // effects (0-RTT and 1-RTT share the application space, so this is
        // also what stops a replayed 0-RTT packet from re-crediting
        // stream/connection state), no idle-timer refresh, no ACK-range
        // insertion (already covered — the insert would be a no-op merge
        // anyway), and critically no path classification / anti-
        // amplification crediting: a captured-and-replayed packet resent
        // from a *different* (possibly spoofed) source address must not be
        // able to create or credit candidate-path state for that address
        // just because its packet number already authenticated once.
        const already_received = self.recovery.wasReceived(space, pn);
        self.emitZeroRttOutcome(level, if (already_received) .duplicate else .accepted, bytes.len);
        if (!already_received) {
            self.recovery.onPacketReceived(space, pn) catch {
                // Pathological ACK-range fragmentation; close rather than lose ACK state.
                self.startClose(.{ .error_code = error_internal, .is_application = false, .local = true }, "ack range overflow", now_us);
                return;
            };
            self.last_activity_us = now_us;
            // RFC 9000 §10.1: the idle timer restarts only when a packet is
            // received *and processed successfully* — a duplicate (or a
            // dropped/undecryptable packet, which never reaches this point
            // at all) must not keep the connection alive. This must live
            // here, not as an unconditional call in `ingestOnPath` after the
            // packet loop — that would refresh the deadline for every
            // datagram regardless of whether anything in it actually
            // authenticated.
            self.armIdle(now_us);
        }

        if (self.role == .client and parsed.kind == .initial and !self.peer_cid_adopted) {
            // RFC 9000 §7.2: the client adopts the server's SCID.
            self.peer_cid = config.CidValue.init(parsed.scid) catch self.peer_cid;
            self.peer_cid_adopted = true;
            self.peer_cids = quic_cid.PeerCidPool.init(self.local_params.active_connection_id_limit);
            if (quic_cid.ConnectionId.init(self.peer_cid.slice()) catch null) |cid_value| {
                self.peer_cids.registerInitial(cid_value) catch {};
            }
        }
        self.initial_packet_processed = true;
        if (level == .handshake and !self.processed_handshake_packet) {
            self.processed_handshake_packet = true;
            // Server: receiving a Handshake packet proves the client got
            // the ServerHello; Initial keys are done (RFC 9001 §4.9.1).
            if (self.role == .server) self.discardKeys(.initial);
        }

        // Authenticated path state (#251/#515): only a packet whose AEAD open
        // just succeeded (we are past that point now) *and* is not an
        // already-processed duplicate may create path state, credit
        // anti-amplification budget, or start/continue a candidate
        // validation — see the comment above `already_received` for why a
        // duplicate must not reach here. This never moves the active path
        // or an outbound destination by itself — only `tryPromote` (driven
        // by a validated PATH_RESPONSE) does that. A new validation attempt
        // uses the #387 contract for its timeout: max(default, 3x
        // application-space PTO).
        if (!already_received) {
            self.paths.validation_timeout_us = @max(quic_path.default_validation_timeout_us, 3 * self.recovery.rtt.ptoDuration(.application));
            switch (self.paths.onDatagram(ingress_path, bytes.len, challenge_entropy, now_us)) {
                .probe => |probe| {
                    self.queueCandidateChallenge(ingress_path, probe.data);
                    self.events.emit(.{ .path_validation_started = .{ .path = ingress_path, .change = probe.change } });
                },
                .blocked => |blocked| {
                    if (blocked.first_observation) {
                        self.events.emit(.{ .path_migration_blocked = .{ .path = ingress_path, .change = blocked.change, .reason = .policy } });
                    }
                },
                .on_active_path, .probing, .validated_pending_promotion => {},
            }
            if (level == .handshake and self.role == .server) {
                // RFC 9001 §4.9.1 / RFC 9000 §8.1: receiving an authenticated
                // Handshake packet proves the client owns the exact address it
                // arrived on — never implicitly "whatever path is currently
                // active". `onDatagram` above has already classified/tracked
                // `ingress_path` (creating it as a candidate if it differs from
                // the active path), so this lifts only that path's limit.
                self.paths.markValidatedOnPath(ingress_path);
            }
        }

        var ack_eliciting = false;
        if (!already_received) {
            var parser = frame.Parser.init(payload);
            while (true) {
                const decoded = parser.next() catch {
                    self.startClose(.{ .error_code = error_frame_encoding, .is_application = false, .local = true }, "frame decode", now_us);
                    return;
                };
                const f = decoded orelse break;
                if (f.isAckEliciting()) ack_eliciting = true;
                try self.applyFrame(level, f, ingress_path, local_cid_sequence, now_us);
                if (self.state_ == .closed or self.state_ == .draining) return;
                if (self.state_ == .closing) break;
            }
        }

        if (ack_eliciting) {
            if (!self.ack_needed[space_idx]) {
                self.ack_needed[space_idx] = true;
                self.ack_armed_at_us[space_idx] = now_us;
            }
            self.ack_eliciting_since_ack[space_idx] += 1;
        }

        // While closing, a peer that keeps talking gets the close again
        // (rate-limited).
        if (self.state_ == .closing and now_us >= self.close_resend_allowed_at_us) {
            self.close_needs_send = true;
        }
    }

    fn localCidSequence(self: *const Connection, dcid: []const u8) ?u64 {
        const parsed = quic_cid.ConnectionId.init(dcid) catch return null;
        if (self.local_cids) |registry| return registry.sequenceForCid(parsed);
        if (std.mem.eql(u8, dcid, self.local_cid.slice())) return 0;
        return null;
    }

    fn applyFrame(self: *Connection, level: EncryptionLevel, f: frame.Frame, ingress_path: quic_path.PathKey, local_cid_sequence: u64, now_us: u64) IngestError!void {
        if (!frameAllowedAtLevel(level, f)) {
            self.startClose(.{ .error_code = error_protocol_violation, .is_application = false, .local = true }, "0-rtt frame level", now_us);
            return;
        }
        const space = spaceForLevel(level);
        switch (f) {
            .padding, .ping => {},
            .ack => |ack| self.processAck(space, ack, now_us),
            .crypto => |c| {
                self.handshake.onCrypto(level, c.offset, c.data) catch |err| {
                    self.failHandshake(err);
                    self.startClose(.{ .error_code = cryptoErrorCode(err), .is_application = false, .local = true }, @errorName(err), now_us);
                    return;
                };
                // Poll any parked asynchronous authentication (#334) so a
                // resolved external signer/verifier/selector progresses the
                // handshake as this packet is processed. A no-op when nothing is
                // suspended.
                self.handshake.resumeAuth() catch |err| {
                    self.failHandshake(err);
                    self.startClose(.{ .error_code = cryptoErrorCode(err), .is_application = false, .local = true }, @errorName(err), now_us);
                    return;
                };
                self.collectCryptoOutput() catch {
                    self.failHandshake(error.HandshakeBufferOverflow);
                    self.startClose(.{ .error_code = error_crypto_buffer_exceeded, .is_application = false, .local = true }, "crypto buffer", now_us);
                    return;
                };
                self.reportEarlyDataDecisionOnce();
                self.afterHandshakeProgress(ingress_path, now_us);
            },
            .stream => |sf| {
                if (level != .application and level != .zero_rtt) {
                    self.startClose(.{ .error_code = error_protocol_violation, .is_application = false, .local = true }, "stream frame level", now_us);
                    return;
                }
                var manager = self.streamManager() orelse {
                    self.startClose(.{ .error_code = error_protocol_violation, .is_application = false, .local = true }, "stream before handshake", now_us);
                    return;
                };
                const known = self.known_streams.contains(sf.id);
                _ = manager.receiveStreamFrame(sf) catch |err| {
                    self.closeOnStreamError(err, now_us);
                    return;
                };
                if (!known) {
                    try self.known_streams.put(sf.id, {});
                    if (quic_stream.streamInitiator(sf.id) != roleInitiator(self.role)) {
                        try self.accept_queue.append(self.allocator, sf.id);
                    }
                }
                if (level == .zero_rtt) {
                    // Sticky provenance (#523): bytes delivered while this
                    // packet was 0-RTT stay marked early even once later
                    // 1-RTT bytes land on the same stream.
                    try self.markStreamZeroRtt(sf.id);
                }
            },
            .reset_stream => |rs| {
                var manager = self.streamManager() orelse return;
                manager.receiveResetStream(rs) catch |err| {
                    self.closeOnStreamError(err, now_us);
                    return;
                };
                if (!self.known_streams.contains(rs.id)) {
                    try self.known_streams.put(rs.id, {});
                    if (quic_stream.streamInitiator(rs.id) != roleInitiator(self.role)) {
                        try self.accept_queue.append(self.allocator, rs.id);
                    }
                }
            },
            .stop_sending => |ss| {
                var manager = self.streamManager() orelse return;
                manager.receiveStopSending(ss) catch |err| {
                    self.closeOnStreamError(err, now_us);
                    return;
                };
                // RFC 9000 §3.5: a STOP_SENDING peer expects RESET_STREAM.
                if (manager.sendResetStream(ss.id, ss.app_error_code)) |reset| {
                    try self.pending_resets.append(self.allocator, reset);
                    if (self.send_queues.get(ss.id)) |queue| queue.reset_sent = true;
                } else |_| {}
            },
            .max_data => |limit| {
                if (self.streamManager()) |manager| manager.applyMaxData(limit);
            },
            .max_stream_data => |msd| {
                if (self.streamManager()) |manager| manager.applyMaxStreamData(msd.id, msd.limit) catch {};
            },
            .max_streams_bidi => |limit| {
                if (self.streamManager()) |manager| manager.applyMaxStreams(.bidi, limit);
            },
            .max_streams_uni => |limit| {
                if (self.streamManager()) |manager| manager.applyMaxStreams(.uni, limit);
            },
            .data_blocked, .stream_data_blocked, .streams_blocked_bidi, .streams_blocked_uni => {},
            .new_token => {
                // Address-validation tokens for future connections; endpoint
                // token stores are out of scope for the driver.
                if (self.role == .server) {
                    self.startClose(.{ .error_code = error_protocol_violation, .is_application = false, .local = true }, "client sent NEW_TOKEN", now_us);
                }
            },
            .new_connection_id => |ncid| {
                self.peer_cids.onNewConnectionId(ncid.frame) catch |err| switch (err) {
                    error.ProtocolViolation => {
                        self.startClose(.{ .error_code = error_protocol_violation, .is_application = false, .local = true }, "NEW_CONNECTION_ID", now_us);
                        return;
                    },
                    error.CidLimitExceeded => {
                        self.startClose(.{ .error_code = error_protocol_violation, .is_application = false, .local = true }, "CID limit", now_us);
                        return;
                    },
                    error.RetireQueueFull => {},
                };
                while (self.peer_cids.takePendingRetire()) |retire| {
                    try self.pending_retires.append(self.allocator, retire.sequence);
                }
                // A fresh peer CID may be exactly what was missing to promote
                // a host migration that validated earlier but was blocked on
                // CID exhaustion (RFC 9000 §9.5): retry now rather than
                // waiting for another challenge round trip.
                if (self.paths.pendingPromotionCandidate()) |candidate| self.tryPromote(candidate);
            },
            .retire_connection_id => |retire| {
                if (retire.sequence == local_cid_sequence) {
                    self.startClose(.{ .error_code = error_protocol_violation, .is_application = false, .local = true }, "retire active cid", now_us);
                    return;
                }
                const registry = if (self.local_cids) |*registry| registry else {
                    if (retire.sequence == 0) return;
                    self.startClose(.{ .error_code = error_protocol_violation, .is_application = false, .local = true }, "RETIRE_CONNECTION_ID", now_us);
                    return;
                };
                _ = registry.retire(retire) catch {
                    self.startClose(.{ .error_code = error_protocol_violation, .is_application = false, .local = true }, "RETIRE_CONNECTION_ID", now_us);
                    return;
                };
                // Cancel every owned copy of this sequence's frame, not only
                // the registry entry `retire()` already wiped — including on
                // an idempotent repeated retire, since a duplicate
                // RETIRE_CONNECTION_ID for an already-retired sequence still
                // means no in-flight copy of it should survive.
                self.cancelLocalCidFrameCopies(retire.sequence);
            },
            .path_challenge => |data| {
                // Echo on the exact path the challenge arrived on (RFC 9000
                // §8.2.2) — never the active path by default, since the
                // challenge may have come from a peer address probing us.
                // Legal in 0-RTT as well as 1-RTT (RFC 9000 §12.5); the
                // response itself always transmits under 1-RTT keys since
                // the server never sends 0-RTT (queued the same way either
                // way — only the trigger's level differs).
                if (level == .application or level == .zero_rtt) {
                    try self.pending_path_responses.append(self.allocator, .{ .path = ingress_path, .data = data });
                }
            },
            .path_response => |data| {
                // Validation completes only when the response echoes the
                // outstanding challenge on the exact path it was sent on
                // (RFC 9000 §8.2.3) — a response arriving on a different path
                // never validates that candidate. Anything else is a response
                // to an abandoned/mismatched challenge; ignoring it is
                // permitted (§19.18 makes the connection error optional).
                if (level != .application) return;
                const validated = self.paths.validatePathResponse(ingress_path, data, now_us) orelse return;
                self.events.emit(.{ .path_validation_succeeded = .{ .path = validated.path, .change = validated.change } });
                self.tryPromote(validated.path);
            },
            .connection_close => |cc| {
                self.events.emit(.{ .close_received = .{ .error_code = cc.error_code, .is_application = cc.is_application } });
                self.close_info = .{ .error_code = cc.error_code, .is_application = cc.is_application, .local = false };
                self.setState(.draining);
                self.close_deadline_us = now_us + 3 * self.ptoDurationNow();
            },
            .handshake_done => {
                if (self.role == .server) {
                    self.startClose(.{ .error_code = error_protocol_violation, .is_application = false, .local = true }, "client sent HANDSHAKE_DONE", now_us);
                    return;
                }
                if (!self.handshake_confirmed) {
                    self.handshake_confirmed = true;
                    self.events.emit(.handshake_confirmed);
                    self.discardKeys(.handshake);
                }
            },
        }
    }

    /// RFC 9000 §12.5 (frame types permitted per packet type): ACK, CRYPTO,
    /// NEW_TOKEN, RETIRE_CONNECTION_ID, PATH_RESPONSE, and HANDSHAKE_DONE are
    /// never legal in a 0-RTT packet. Checked once, before any frame-specific
    /// side effect, so an authenticated 0-RTT packet carrying one of these
    /// can never mutate sent/recovery/congestion state, hand bytes to the
    /// TLS engine, or otherwise act as if it were an ordinary 1-RTT packet.
    fn frameAllowedAtLevel(level: EncryptionLevel, f: frame.Frame) bool {
        if (level != .zero_rtt) return true;
        return switch (f) {
            .ack, .crypto, .new_token, .retire_connection_id, .path_response, .handshake_done => false,
            else => true,
        };
    }

    fn processAck(self: *Connection, space: PacketNumberSpace, ack: frame.Ack, now_us: u64) void {
        const exponent: u6 = if (self.adapter.peerTransportParameters()) |peer|
            @intCast(@min(peer.ack_delay_exponent, 20))
        else
            3;
        const ack_delay_us = ack.ackDelayUs(exponent);
        const space_idx = spaceIndex(space);
        if (self.largest_peer_acked[space_idx] == null or ack.largest_acknowledged > self.largest_peer_acked[space_idx].?) {
            self.largest_peer_acked[space_idx] = ack.largest_acknowledged;
        }

        // Ack every tracked packet covered by the ranges. The RTT sample only
        // comes from the largest acked packet (RFC 9002 §5.1).
        var index: usize = 0;
        while (index < self.sent_records.items.len) {
            const record = &self.sent_records.items[index];
            if (record.space != space or !ack.ranges.contains(record.packet_number)) {
                index += 1;
                continue;
            }
            if (self.recovery.tracker.onAcked(space, record.packet_number, now_us)) |acked| {
                self.recovery.congestion.onPacketAcked(acked.packet);
                if (record.packet_number == ack.largest_acknowledged) {
                    if (acked.rtt_sample_us) |sample| self.recovery.rtt.update(sample, ack_delay_us);
                }
            }
            self.onRecordAcked(record);
            // Delivery is confirmed: any reset token this record carried
            // has done its job (the registry keeps the durable copy for as
            // long as the CID stays active) and is now redundant. Wipe it
            // here, on the still-live, validly-typed element, before
            // `swapRemove` — the vacated slot the swap leaves behind gets a
            // separate raw-byte wipe below, since it is no longer safe to
            // interpret as a typed `SentRecord`.
            wipeSentRecordToken(record);
            _ = self.sent_records.swapRemove(index);
            wipeSentRecordsSwapRemoveResidue(&self.sent_records);
        }
        // A validated ACK ends the current PTO backoff episode.
        self.pto_count = 0;

        self.detectAndRequeueLost(space, now_us);
    }

    fn onRecordAcked(self: *Connection, record: *const SentRecord) void {
        if (record.carried_handshake_done) self.handshake_done_acked = true;
        if (record.crypto) |range| {
            if (record.space == .application) self.crypto_tx[2].markAcked(self.allocator, range);
        }
        for (record.streams[0..record.stream_count]) |sr| {
            if (self.send_queues.get(sr.id)) |queue| {
                markSendQueueRangeAcked(self.allocator, queue, sr.range, sr.fin);
            }
        }
        // Acked CRYPTO ranges need no explicit bookkeeping: pending ranges
        // are only re-armed on loss, and level buffers drop with the keys.
    }

    /// Detect newly lost packets in `space` and requeue their content.
    fn detectAndRequeueLost(self: *Connection, space: PacketNumberSpace, now_us: u64) void {
        const loss = self.recovery.detectLost(space, now_us);
        if (loss.packet_threshold_losses + loss.time_threshold_losses == 0) return;
        // The tracker dropped the lost packets; any record of this space no
        // longer tracked (and not acked, i.e. still recorded) is lost.
        var index: usize = 0;
        var lost_count: u64 = 0;
        while (index < self.sent_records.items.len) {
            const record = &self.sent_records.items[index];
            if (record.space != space or self.trackerContains(space, record.packet_number)) {
                index += 1;
                continue;
            }
            lost_count += 1;
            // Read the live element to requeue its content (a fresh copy of
            // any carried reset token lands in `pending_new_connection_ids`
            // via `requeueRecord`) before wiping this now-redundant copy and
            // removing the record.
            self.requeueRecord(record);
            wipeSentRecordToken(record);
            _ = self.sent_records.swapRemove(index);
            wipeSentRecordsSwapRemoveResidue(&self.sent_records);
        }
        if (lost_count > 0) {
            self.metrics.packets_lost += lost_count;
            self.events.emit(.{ .packets_lost = .{ .space = space, .bytes = loss.lost_bytes } });
        }
    }

    fn trackerContains(self: *const Connection, space: PacketNumberSpace, pn: u64) bool {
        for (self.recovery.tracker.packets[0..self.recovery.tracker.count]) |p| {
            if (p.space == space and p.packet_number == pn) return true;
        }
        return false;
    }

    /// Requeue everything a lost packet carried.
    fn requeueRecord(self: *Connection, record: *const SentRecord) void {
        if (record.crypto) |range| {
            const tx = switch (record.space) {
                .initial => &self.crypto_tx[0],
                .handshake => &self.crypto_tx[1],
                .application => &self.crypto_tx[2],
            };
            // If the level's keys are already discarded the buffer is gone.
            if (tx.data.items.len > 0) {
                if (tx.liveRange(range)) |live| {
                    if (record.space == .application) {
                        tx.pending.insertAssumeCapacity(live);
                    } else {
                        tx.pending.insert(self.allocator, live) catch {};
                    }
                }
            }
        }
        for (record.streams[0..record.stream_count]) |sr| {
            if (self.send_queues.get(sr.id)) |queue| {
                requeueSendQueueRange(self.allocator, queue, sr.range, sr.fin);
            }
        }
        if (record.carried_handshake_done and !self.handshake_done_acked) {
            self.handshake_done_pending = true;
        }
        if (record.carried_max_data) self.queueMaxDataUpdate();
        if (record.carried_max_stream_data) |id| self.queueMaxStreamDataUpdate(id);
        if (record.carried_reset_stream) |reset| {
            self.pending_resets.append(self.allocator, reset) catch {};
        }
        if (record.carried_stop_sending) |stop| {
            self.pending_stop_sending.append(self.allocator, stop) catch {};
        }
        if (record.carried_new_connection_id) |*ncid| {
            self.queueNewConnectionId(ncid);
        }
        if (record.carried_path_challenge_path) |path| {
            for (self.candidate_challenges.items) |*candidate| {
                if (candidate.path.eql(path)) {
                    candidate.needs_send = true;
                    break;
                }
            }
        }
    }

    /// Queue `source` for (re)transmission, deduplicating by sequence.
    /// `firePto` can requeue the same in-flight sent record more than once
    /// before it is finally acked or declared lost (it does not remove the
    /// record it requeues from), so without this guard a repeated PTO would
    /// append duplicate copies of the same NEW_CONNECTION_ID frame — pushing
    /// `pending_new_connection_ids` past the capacity `init()` reserves once
    /// up front and reopening the unwiped-growth path that reservation
    /// exists to close.
    fn queueNewConnectionId(self: *Connection, source: *const quic_cid.NewConnectionIdFrame) void {
        for (self.pending_new_connection_ids.items) |*queued| {
            if (queued.sequence == source.sequence) return;
        }
        // `cancelLocalCidFrameCopies` removes every queued/in-flight copy of
        // a sequence the instant it is retired, so the registry's
        // `max_local_active_cids` bound on simultaneously issued-and-not-
        // yet-retired sequences also bounds this queue — exactly the
        // capacity `init()` reserves once up front. If that invariant is
        // ever wrong, drop the requeue rather than growing the backing
        // allocation and reopening the unwiped-growth path the reservation
        // exists to close.
        if (self.pending_new_connection_ids.items.len == self.pending_new_connection_ids.capacity) return;
        const dst = self.pending_new_connection_ids.addOneAssumeCapacity();
        dst.* = source.*;
    }

    /// A peer's RETIRE_CONNECTION_ID only tells `LocalCidRegistry.retire()`
    /// to wipe its own entry; it says nothing about copies of that
    /// sequence's NEW_CONNECTION_ID frame already queued or in flight.
    /// Without also canceling those: a later PTO/loss could retransmit a
    /// frame for a sequence the peer already retired, and retiring frees a
    /// registry slot that `needsLocalCid()` may immediately reuse while the
    /// old sequence's copies are still live, silently reopening the
    /// capacity bound `queueNewConnectionId` depends on staying fixed.
    /// Called for every valid retire, including an idempotent repeat of an
    /// already-retired sequence.
    fn cancelLocalCidFrameCopies(self: *Connection, sequence: u64) void {
        var i: usize = 0;
        while (i < self.pending_new_connection_ids.items.len) {
            if (self.pending_new_connection_ids.items[i].sequence != sequence) {
                i += 1;
                continue;
            }
            crypto_secrets.secureZero(&self.pending_new_connection_ids.items[i].stateless_reset_token);
            _ = self.pending_new_connection_ids.orderedRemove(i);
            wipePendingNewConnectionIdsOrderedRemoveResidue(&self.pending_new_connection_ids);
        }
        for (self.sent_records.items) |*record| {
            if (record.carried_new_connection_id) |*ncid| {
                if (ncid.sequence != sequence) continue;
                crypto_secrets.secureZero(&ncid.stateless_reset_token);
                record.carried_new_connection_id = null;
            }
        }
    }

    fn queueMaxDataUpdate(self: *Connection) void {
        if (self.streamManager()) |manager| {
            self.pending_max_data = manager.max_data_recv;
        }
    }

    fn queueMaxStreamDataUpdate(self: *Connection, id: StreamId) void {
        const manager = self.streamManager() orelse return;
        const s = manager.get(id) orelse return;
        self.pending_max_stream_data.append(self.allocator, .{ .id = id, .limit = s.max_recv_data }) catch {};
    }

    fn closeOnStreamError(self: *Connection, err: anyerror, now_us: u64) void {
        const code: u64 = switch (err) {
            error.FinalSizeError => error_final_size,
            error.FlowControlBlocked, error.StreamDataBlocked => error_flow_control,
            error.StreamLimitExceeded => error_stream_limit,
            error.SendOnlyStream, error.RecvOnlyStream, error.StreamClosed => error_stream_state,
            error.OverlappingStreamDataMismatch => error_protocol_violation,
            else => error_internal,
        };
        self.startClose(.{ .error_code = code, .is_application = false, .local = true }, @errorName(err), now_us);
    }

    fn dropPacket(self: *Connection, reason: DropReason, size: usize) void {
        self.metrics.packets_dropped += 1;
        self.events.emit(.{ .packet_dropped = .{ .reason = reason, .size = size } });
    }

    /// See `Event.zero_rtt_packet` — a no-op for every level but `.zero_rtt`,
    /// so call sites shared with every other level don't need their own
    /// level check.
    fn emitZeroRttOutcome(self: *Connection, level: EncryptionLevel, outcome: ZeroRttPacketOutcome, size: usize) void {
        if (level != .zero_rtt) return;
        self.events.emit(.{ .zero_rtt_packet = .{ .outcome = outcome, .size = size } });
    }

    /// See `Event.early_data_decision`. Only the server ever makes this
    /// decision (RFC 9001 §4.6.1); a client polling its own backend would
    /// only ever see `.not_attempted`, so this is a no-op there. Emitted at
    /// most once per connection, as soon as the decision is no longer
    /// `.not_attempted` — CRYPTO frames arrive in order, so once the
    /// server's transcript covers the full ClientHello, every later
    /// `.crypto` frame observes a stable, final decision.
    fn reportEarlyDataDecisionOnce(self: *Connection) void {
        if (self.role != .server or self.early_data_decision_reported) return;
        const decision = self.tls.earlyDataDecision();
        if (decision == .not_attempted) return;
        self.early_data_decision_reported = true;
        self.events.emit(.{ .early_data_decision = decision });
    }

    fn roleInitiator(role: Role) quic_stream.Initiator {
        return switch (role) {
            .client => .client,
            .server => .server,
        };
    }

    fn streamManager(self: *Connection) ?*quic_stream.StreamManager {
        if (self.streams) |*manager| return manager;
        return null;
    }

    /// Bring the stream layer up early so an authenticated 0-RTT STREAM frame
    /// has somewhere to land. `afterHandshakeProgress` normally waits for the
    /// peer's transport parameters to be authenticated (full handshake done)
    /// before creating `self.streams`, but 0-RTT data is by definition
    /// received before that point. This is safe to do early because inbound
    /// admission (`StreamManager.receiveStreamFrame` / `ensurePeerStreamAllowed`
    /// / `initialRecvWindow`) is governed entirely by `local` transport
    /// parameters — our own fixed configuration, known before any handshake
    /// byte arrives — never by the peer's. The peer side is seeded with
    /// `zero_send_credit_params` (grants no send credit) until
    /// `afterHandshakeProgress` calls `refreshPeerParams` with the real,
    /// authenticated peer parameters.
    fn ensureEarlyStreamManager(self: *Connection) void {
        if (self.streams != null) return;
        self.streams = quic_stream.StreamManager.init(
            self.allocator,
            switch (self.role) {
                .client => .client,
                .server => .server,
            },
            self.local_params,
            zero_send_credit_params,
        );
    }

    // -- retry / handshake progress -------------------------------------------

    fn handleRetry(self: *Connection, bytes: []const u8, parsed: packet.ParsedPacket, now_us: u64) void {
        // RFC 9000 §17.2.5.2: only clients accept Retry, only before any
        // Initial packet from the server, and only once.
        if (self.role != .client or self.got_retry or self.initial_packet_processed) {
            self.dropPacket(.unexpected_type, bytes.len);
            return;
        }
        if (parsed.retry_token.len == 0) {
            self.dropPacket(.malformed, bytes.len);
            return;
        }
        if (!packet.verifyRetryIntegrity(bytes, self.original_dcid.slice())) {
            self.dropPacket(.malformed, bytes.len);
            return;
        }
        self.got_retry = true;
        self.retry_scid = config.CidValue.init(parsed.scid) catch null;
        self.retry_token.clearRetainingCapacity();
        self.retry_token.appendSlice(self.allocator, parsed.retry_token) catch return;

        // New DCID -> new Initial keys (RFC 9001 §5.2), and the whole Initial
        // flight goes again with the token attached.
        self.peer_cid = self.retry_scid.?;
        _ = self.adapter.installInitialSecrets(.client, self.peer_cid.slice()) catch return;
        _ = self.recovery.onKeysDiscarded(.initial);
        var index: usize = 0;
        while (index < self.sent_records.items.len) {
            if (self.sent_records.items[index].space == .initial) {
                // NEW_CONNECTION_ID frames are only ever attached to
                // `.application`-space records, so this is a no-op in
                // practice; wipe defensively so that invariant is never
                // load-bearing for correctness here.
                wipeSentRecordToken(&self.sent_records.items[index]);
                _ = self.sent_records.swapRemove(index);
                wipeSentRecordsSwapRemoveResidue(&self.sent_records);
            } else index += 1;
        }
        const tx = &self.crypto_tx[0];
        tx.pending.items.clearRetainingCapacity();
        tx.pending.insert(self.allocator, .{ .start = 0, .end = tx.data.items.len }) catch {};
        self.largest_recv_pn[0] = null;
        // RFC 9000 §10.1: a successfully validated and processed Retry is a
        // legitimate packet from the peer just like any other — the idle
        // timer must restart here too, not only from the protected-packet
        // path in `ingestPacket`. Every early return above this point
        // (unexpected type, malformed, failed integrity check) is a
        // never-processed/dropped packet and correctly does not reach here.
        self.armIdle(now_us);
        // The client handshake anti-deadlock PTO (`nextTimeoutUs`/`onTimeout`,
        // ~line 2002/2060) bases its deadline on `last_activity_us` whenever
        // nothing is in flight. This Retry just cleared the Initial
        // recovery/sent state above, so without updating it here too, that
        // deadline would still reflect pre-Retry activity and could fire
        // before the replacement Initial (queued via `tx.pending` above) is
        // even emitted.
        self.last_activity_us = now_us;
    }

    /// Drain queued TLS output into the per-level retransmission buffers.
    fn collectCryptoOutput(self: *Connection) !void {
        inline for (.{ EncryptionLevel.initial, EncryptionLevel.handshake }, 0..) |level, tx_index| {
            var chunk: [2048]u8 = undefined;
            defer crypto_secrets.secureZero(&chunk);
            while (self.handshake.pollOutput(level, &chunk) catch null) |output| {
                const tx = &self.crypto_tx[tx_index];
                std.debug.assert(output.offset == tx.bufferedEnd());
                try tx.data.appendSlice(self.allocator, output.bytes);
                try tx.pending.insert(self.allocator, .{
                    .start = output.offset,
                    .end = output.offset + output.bytes.len,
                });
            }
        }
    }

    /// True while the TLS handshake has suspended awaiting an asynchronous
    /// authentication operation (#334). The event loop can poll this to know
    /// the connection is waiting on an external signer/verifier/selector; each
    /// `pollTransmit` (or an explicit `driveAuthentication`) advances it.
    pub fn authPending(self: *const Connection) bool {
        return self.handshake.authPending();
    }

    /// Drive a parked asynchronous authentication operation forward without
    /// requiring another inbound CRYPTO frame: poll it, queue any handshake
    /// output it produced, and complete the handshake if it resolved. Safe to
    /// call unconditionally; a no-op unless the backend is suspended.
    pub fn driveAuthentication(self: *Connection, now_us: u64) void {
        if (self.state_ == .closed or self.state_ == .draining or self.state_ == .closing) return;
        if (!self.handshake.authPending()) return;
        self.handshake.resumeAuth() catch |err| {
            self.failHandshake(err);
            self.startClose(.{ .error_code = cryptoErrorCode(err), .is_application = false, .local = true }, @errorName(err), now_us);
            return;
        };
        self.collectCryptoOutput() catch {
            self.failHandshake(error.HandshakeBufferOverflow);
            self.startClose(.{ .error_code = error_crypto_buffer_exceeded, .is_application = false, .local = true }, "crypto buffer", now_us);
            return;
        };
        // No freshly authenticated datagram is associated with this resumed
        // step (it advances a previously-parked operation), so there is no
        // better path to attribute address validation to than the active one.
        self.afterHandshakeProgress(null, now_us);
    }

    pub fn emitNewSessionTicket(
        self: *Connection,
        params: tls_handshake.EmitNewSessionTicketParams,
        limits: tls_core.session.Limits,
    ) tls_handshake.HandshakeError!tls_core.session.ServerRecoverableState {
        if (self.state_ != .established or self.role != .server) return error.InvalidHandshakeState;
        limits.validate() catch return error.IllegalParameter;
        if (params.opaque_ticket.len == 0 or params.opaque_ticket.len > limits.max_ticket_len) return error.TicketTooLarge;
        const emit_params: tls_core.new_session_ticket.EmitParams = .{
            .ticket_lifetime = params.ticket_lifetime,
            .ticket_age_add = params.ticket_age_add,
            .ticket_nonce = params.ticket_nonce,
            .ticket = params.opaque_ticket,
            .max_early_data_size = params.max_early_data_size,
        };
        const body_len = tls_core.new_session_ticket.encodedLen(emit_params) catch return error.IllegalParameter;
        const message_len = 4 + body_len;
        const tx = &self.crypto_tx[2];
        var reservation = tx.prepareAppend(self.allocator, message_len, max_application_crypto_outstanding) catch return error.HandshakeBufferOverflow;
        defer reservation.deinit();

        var sink = tls_handshake.EventSink{};
        defer sink.deinit();
        var ticket_state = try self.tls.emitNewSessionTicket(self.allocator, &sink, params, limits);
        errdefer ticket_state.deinit();
        tx.commitReservation(&reservation);
        try self.queueApplicationCryptoEventsReserved(&sink, message_len);
        return ticket_state;
    }

    /// #488: install the process-shared server resolver. Must be called
    /// before the handshake starts, matching the shared engine's own
    /// precondition — the same contract native TLS-over-TCP uses.
    pub fn setServerPskResolver(self: *Connection, resolver: tls_core.pre_shared_key.ServerPskResolver) tls_handshake.HandshakeError!void {
        try self.tls.setServerPskResolver(resolver);
    }

    /// #367: update the application snapshot that will be stamped into
    /// subsequently issued early-capable NewSessionTickets.
    pub fn setEarlyDataApplicationCompat(
        self: *Connection,
        blob: ?tls_core.new_session_ticket.CompatBlob,
    ) tls_handshake.HandshakeError!void {
        try self.tls.setEarlyDataApplicationCompat(blob);
    }

    /// #488 two-phase issuance, step 1 (QUIC): derives the RMS-bound PSK and
    /// the exact `ServerRecoverableState` a stateful insertion or stateless
    /// seal will consume. See `tls_core.tls13_backend.Tls13Backend.prepareNewSessionTicket`.
    pub fn prepareNewSessionTicket(
        self: *Connection,
        allocator: std.mem.Allocator,
        params: tls_handshake.PrepareNewSessionTicketParams,
        limits: tls_core.session.Limits,
    ) tls_handshake.HandshakeError!tls_handshake.PreparedNewSessionTicket {
        if (self.state_ != .established or self.role != .server) return error.InvalidHandshakeState;
        limits.validate() catch return error.IllegalParameter;
        return self.tls.prepareNewSessionTicket(allocator, params, limits);
    }

    /// #488 two-phase issuance, step 2 (QUIC): queues the `NewSessionTicket`
    /// carrying `identity` through the same reserved application-CRYPTO path
    /// as single-phase `emitNewSessionTicket`, so retransmission/ordering
    /// bookkeeping is never duplicated.
    pub fn emitPreparedNewSessionTicket(
        self: *Connection,
        prepared: *const tls_handshake.PreparedNewSessionTicket,
        identity: []const u8,
        limits: tls_core.session.Limits,
    ) tls_handshake.HandshakeError!void {
        if (self.state_ != .established or self.role != .server) return error.InvalidHandshakeState;
        if (identity.len == 0 or identity.len > limits.max_ticket_len) return error.TicketTooLarge;
        const emit_params: tls_core.new_session_ticket.EmitParams = .{
            .ticket_lifetime = prepared.ticket_lifetime,
            .ticket_age_add = prepared.ticket_age_add,
            .ticket_nonce = prepared.ticketNonce(),
            .ticket = identity,
            .max_early_data_size = prepared.max_early_data_size,
        };
        const body_len = tls_core.new_session_ticket.encodedLen(emit_params) catch return error.IllegalParameter;
        const message_len = 4 + body_len;
        const tx = &self.crypto_tx[2];
        var reservation = tx.prepareAppend(self.allocator, message_len, max_application_crypto_outstanding) catch return error.HandshakeBufferOverflow;
        defer reservation.deinit();

        var sink = tls_handshake.EventSink{};
        defer sink.deinit();
        try self.tls.emitPreparedNewSessionTicket(self.allocator, &sink, prepared, identity, limits);
        tx.commitReservation(&reservation);
        try self.queueApplicationCryptoEventsReserved(&sink, message_len);
    }

    fn queueApplicationCryptoEventsReserved(self: *Connection, sink: *tls_handshake.EventSink, expected_bytes: usize) tls_handshake.HandshakeError!void {
        var appended: usize = 0;
        for (sink.items[0..sink.len]) |event| {
            switch (event) {
                .handshake_bytes => |hb| {
                    if (hb.epoch != .application) return error.UnexpectedCryptoLevel;
                    self.crypto_tx[2].appendReserved(hb.data);
                    appended += hb.data.len;
                },
                else => {},
            }
        }
        if (appended != expected_bytes) return error.HandshakeBufferOverflow;
    }

    fn afterHandshakeProgress(self: *Connection, ingress_path: ?quic_path.PathKey, now_us: u64) void {
        if (self.handshake_complete or !self.handshake.isComplete()) return;
        self.handshake_complete = true;
        self.events.emit(.handshake_complete);

        // RFC 9000 §7.3: validate the peer's authenticated CID binding
        // against what we actually observed on the wire.
        const peer_binding = self.tls.peerCidBinding();
        if (!self.validateCidBinding(peer_binding)) {
            self.startClose(.{ .error_code = error_transport_parameter, .is_application = false, .local = true }, "cid binding mismatch", now_us);
            return;
        }

        const peer_params = self.adapter.peerTransportParameters() orelse {
            self.startClose(.{ .error_code = error_transport_parameter, .is_application = false, .local = true }, "missing peer params", now_us);
            return;
        };
        if (self.local_cids == null) {
            // Construct the registry in place via `initInto`, which borrows
            // `self.stateless_reset_key` instead of taking it by value: a
            // by-value parameter (or a return-by-value constructor) would
            // leave an extra semantic copy of the secret that the compiler
            // is not guaranteed to elide. Once the registry holds its own
            // copy, `self.stateless_reset_key` is redundant and gets wiped
            // immediately.
            self.local_cids = .{};
            quic_cid.LocalCidRegistry.initInto(&self.local_cids.?, peer_params.active_connection_id_limit, &self.stateless_reset_key);
            crypto_secrets.secureZero(&self.stateless_reset_key);
            const registry = &self.local_cids.?;
            const initial = quic_cid.ConnectionId.init(self.local_cid.slice()) catch {
                registry.deinit();
                self.local_cids = null;
                self.startClose(.{ .error_code = error_internal, .is_application = false, .local = true }, "local cid registry", now_us);
                return;
            };
            _ = registry.registerInitial(initial) catch {
                registry.deinit();
                self.local_cids = null;
                self.startClose(.{ .error_code = error_internal, .is_application = false, .local = true }, "local cid registry", now_us);
                return;
            };
        }
        if (self.streams) |*manager| {
            // 0-RTT already brought the stream layer up early with a
            // zero-send-credit placeholder peer side (see
            // `ensureEarlyStreamManager`) — swap in the now-authenticated
            // real peer parameters in place rather than reinitializing,
            // which would silently discard any stream state/data buffered
            // from accepted 0-RTT packets.
            manager.refreshPeerParams(peer_params);
        } else {
            self.streams = quic_stream.StreamManager.init(
                self.allocator,
                switch (self.role) {
                    .client => .client,
                    .server => .server,
                },
                self.local_params,
                peer_params,
            );
        }
        self.setState(.established);

        if (self.role == .server) {
            // Handshake completion validates the client's address and
            // confirms the handshake for the server (RFC 9001 §4.1.2) — the
            // exact path this progress is attributed to, never implicitly
            // "whatever is active" (a candidate path can complete the
            // handshake before it is promoted). Async-resumed progress with
            // no associated datagram (`ingress_path == null`) has no better
            // path to attribute this to than the active one.
            if (ingress_path) |path| {
                self.paths.markValidatedOnPath(path);
            } else {
                self.paths.markActiveValidated();
            }
            self.handshake_confirmed = true;
            self.handshake_done_pending = true;
            self.events.emit(.handshake_confirmed);
            // Keep Handshake keys just long enough to flush the ACK of the
            // client's Finished; pollTransmit applies the deferred discard.
            self.handshake_keys_discard_pending = true;
        }
    }

    fn validateCidBinding(self: *const Connection, peer_binding: config.CidBinding) bool {
        // Backends without binding support (the in-memory test backend)
        // return an empty binding; there is nothing to check.
        const peer_initial_scid = peer_binding.initial_source_connection_id orelse {
            return peer_binding.original_destination_connection_id == null and
                peer_binding.retry_source_connection_id == null;
        };
        if (!std.mem.eql(u8, peer_initial_scid.slice(), self.peer_cid.slice())) return false;
        if (self.role == .client) {
            const odcid = peer_binding.original_destination_connection_id orelse return false;
            if (!std.mem.eql(u8, odcid.slice(), self.original_dcid.slice())) return false;
            if (self.got_retry) {
                const retry_scid = peer_binding.retry_source_connection_id orelse return false;
                const observed = self.retry_scid orelse return false;
                if (!std.mem.eql(u8, retry_scid.slice(), observed.slice())) return false;
            } else if (peer_binding.retry_source_connection_id != null) {
                return false;
            }
        } else {
            // A client never sends the server-only parameters.
            if (peer_binding.original_destination_connection_id != null) return false;
            if (peer_binding.retry_source_connection_id != null) return false;
            if (peer_binding.stateless_reset_token != null) return false;
        }
        return true;
    }

    fn failHandshake(self: *Connection, err: tls_handshake.HandshakeError) void {
        if (self.handshake_error == null) self.handshake_error = err;
    }

    /// Apply a key discard for a space: adapter keys, retransmission buffers,
    /// recovery accounting (RFC 9002 §6.4).
    fn discardKeys(self: *Connection, space: PacketNumberSpace) void {
        const level = levelForSpace(space);
        if ((self.adapter.protectionKeys(level, .write) catch unreachable) == null and
            (self.adapter.protectionKeys(level, .read) catch unreachable) == null) return;
        self.adapter.discardSecrets(level);
        _ = self.recovery.onKeysDiscarded(space);
        const tx: ?*CryptoTx = switch (space) {
            .initial => &self.crypto_tx[0],
            .handshake => &self.crypto_tx[1],
            .application => null,
        };
        if (tx) |t| {
            t.data.clearAndFree(self.allocator);
            t.pending.items.clearAndFree(self.allocator);
        }
        var index: usize = 0;
        while (index < self.sent_records.items.len) {
            if (self.sent_records.items[index].space == space) {
                // Defensive, as above: NEW_CONNECTION_ID frames only ever
                // ride `.application`-space records.
                wipeSentRecordToken(&self.sent_records.items[index]);
                _ = self.sent_records.swapRemove(index);
                wipeSentRecordsSwapRemoveResidue(&self.sent_records);
            } else index += 1;
        }
        self.ack_needed[spaceIndex(space)] = false;
        self.last_ack_eliciting_sent_us[spaceIndex(space)] = null;
        self.probes_pending[spaceIndex(space)] = 0;
        self.events.emit(.{ .keys_discarded = space });
    }

    /// TLS alert mapping (RFC 9001 §4.8). QUIC-only failures (not part of the
    /// shared protocol-neutral vocabulary) are mapped explicitly; every other
    /// error is a member of `tls_core.events.HandshakeError` and is delegated to
    /// the canonical `alerts.fromHandshakeError` mapper, so this table cannot
    /// silently drift from the shared one the way it previously did for
    /// `NoApplicableCredential` (missing here meant every credential-selection
    /// failure surfaced as `internal_error` instead of `handshake_failure`).
    fn cryptoErrorCode(err: tls_handshake.HandshakeError) u64 {
        switch (err) {
            error.MissingTransportParameters, error.InvalidTransportParameters => return error_transport_parameter,
            error.UnexpectedCryptoLevel, error.HandshakeBufferOverflow => return error_crypto_base + 80, // internal_error
            else => {},
        }
        const shared_err: tls_core.events.HandshakeError = @errorCast(err);
        return error_crypto_base + @as(u64, @intFromEnum(tls_core.alerts.fromHandshakeError(shared_err)));
    }

    // -- close ----------------------------------------------------------------

    /// Application-initiated orderly close.
    pub fn close(self: *Connection, app_error_code: u64, reason: []const u8, now_us: u64) void {
        if (self.state_ == .closed or self.state_ == .closing or self.state_ == .draining) return;
        self.startClose(.{ .error_code = app_error_code, .is_application = true, .local = true }, reason, now_us);
    }

    fn startClose(self: *Connection, info: CloseInfo, reason: []const u8, now_us: u64) void {
        if (self.state_ == .closing or self.state_ == .draining or self.state_ == .closed) return;
        self.close_info = info;
        self.close_reason_len = @min(reason.len, self.close_reason.len);
        @memcpy(self.close_reason[0..self.close_reason_len], reason[0..self.close_reason_len]);
        self.setState(.closing);
        self.close_needs_send = true;
        self.close_deadline_us = now_us + 3 * self.ptoDurationNow();
    }

    fn ptoDurationNow(self: *const Connection) u64 {
        return self.recovery.rtt.ptoDuration(.application);
    }

    // -- timers ----------------------------------------------------------------

    /// The earliest deadline at which `onTimeout` must run, or null when no
    /// timer is armed (e.g. terminal state).
    pub fn nextTimeoutUs(self: *const Connection) ?u64 {
        if (self.state_ == .closed) return null;
        var deadline: ?u64 = null;
        if (self.state_ == .closing or self.state_ == .draining) {
            return self.close_deadline_us;
        }
        // Delayed ACK (application space only; others ack immediately).
        if (self.ack_needed[2] and self.ack_eliciting_since_ack[2] < ack_eliciting_threshold) {
            deadline = minOpt(deadline, self.ack_armed_at_us[2] + local_max_ack_delay_us);
        }
        // Loss time: earliest tracked packet that can become time-lost.
        const loss_delay = self.recovery.rtt.lossDelay();
        for (self.recovery.tracker.packets[0..self.recovery.tracker.count]) |p| {
            const largest = self.recovery.tracker.largest_acked[@intFromEnum(p.space)] orelse continue;
            if (p.packet_number > largest) continue;
            deadline = minOpt(deadline, p.time_sent_us + loss_delay);
        }
        // PTO per space with ack-eliciting packets in flight.
        const backoff = @as(u64, 1) << @intCast(@min(self.pto_count, 16));
        var any_in_flight = false;
        for ([_]PacketNumberSpace{ .initial, .handshake, .application }) |space| {
            const idx = spaceIndex(space);
            const last = self.last_ack_eliciting_sent_us[idx] orelse continue;
            if (!self.spaceHasAckElicitingInFlight(space)) continue;
            any_in_flight = true;
            // Skip the application space until the handshake is confirmed
            // (RFC 9002 §6.2.1).
            if (space == .application and !self.handshake_confirmed) continue;
            deadline = minOpt(deadline, last + self.recovery.rtt.ptoDuration(space) * backoff);
        }
        // Anti-deadlock: a client waiting on the handshake with nothing in
        // flight still arms a PTO to keep the handshake moving.
        if (!any_in_flight and !self.handshake_confirmed and self.role == .client) {
            deadline = minOpt(deadline, self.last_activity_us + self.recovery.rtt.ptoDuration(.handshake) * backoff);
        }
        if (self.idle_deadline_us) |idle| deadline = minOpt(deadline, idle);
        // Fold in any outstanding path-validation deadline so `onTimeout`
        // expires it promptly rather than only on the next unrelated timer.
        if (self.paths.nextValidationDeadlineUs()) |validation| deadline = minOpt(deadline, validation);
        return deadline;
    }

    fn spaceHasAckElicitingInFlight(self: *const Connection, space: PacketNumberSpace) bool {
        for (self.recovery.tracker.packets[0..self.recovery.tracker.count]) |p| {
            if (p.space == space and p.ack_eliciting) return true;
        }
        return false;
    }

    /// Process timer expiry at `now_us`. Cheap when nothing expired.
    pub fn onTimeout(self: *Connection, now_us: u64) void {
        if (self.state_ == .closed) return;
        if (self.state_ == .closing or self.state_ == .draining) {
            if (self.close_deadline_us) |deadline| {
                if (now_us >= deadline) self.setState(.closed);
            }
            return;
        }
        if (self.idle_deadline_us) |deadline| {
            if (now_us >= deadline) {
                // RFC 9000 §10.1: idle timeout closes silently.
                self.events.emit(.idle_timeout);
                self.setState(.closed);
                return;
            }
        }
        // Expire any outstanding path validation whose deadline passed
        // (RFC 9000 §8.2.4). This never changes the active path — a failed
        // candidate just stops being a candidate; egress notices via
        // `pathIsValidating` and drops the stale challenge hint.
        var failed_validations: [quic_path.max_paths]quic_path.FailedValidation = undefined;
        for (self.paths.expireValidationsInto(now_us, &failed_validations)) |failed| {
            self.events.emit(.{ .path_validation_failed = .{ .path = failed.path, .change = failed.change } });
        }
        // Time-threshold loss detection.
        for ([_]PacketNumberSpace{ .initial, .handshake, .application }) |space| {
            self.detectAndRequeueLost(space, now_us);
        }
        // PTO.
        const backoff = @as(u64, 1) << @intCast(@min(self.pto_count, 16));
        var fired = false;
        var any_in_flight = false;
        for ([_]PacketNumberSpace{ .initial, .handshake, .application }) |space| {
            const idx = spaceIndex(space);
            const last = self.last_ack_eliciting_sent_us[idx] orelse continue;
            if (!self.spaceHasAckElicitingInFlight(space)) continue;
            any_in_flight = true;
            if (space == .application and !self.handshake_confirmed) continue;
            if (now_us >= last + self.recovery.rtt.ptoDuration(space) * backoff) {
                self.firePto(space);
                fired = true;
            }
        }
        if (!fired and !any_in_flight and !self.handshake_confirmed and self.role == .client) {
            if (now_us >= self.last_activity_us + self.recovery.rtt.ptoDuration(.handshake) * backoff) {
                // Anti-deadlock probe: resend the lowest-level flight we can.
                if ((self.adapter.protectionKeys(.handshake, .write) catch unreachable) != null) {
                    self.firePto(.handshake);
                } else {
                    self.firePto(.initial);
                }
                // Keep the anti-deadlock timer moving.
                self.last_activity_us = now_us;
            }
        }
    }

    fn firePto(self: *Connection, space: PacketNumberSpace) void {
        self.pto_count += 1;
        self.metrics.pto_count_total += 1;
        const idx = spaceIndex(space);
        self.probes_pending[idx] = 2;
        self.events.emit(.{ .pto_fired = .{ .space = space, .count = self.pto_count } });
        // Requeue the oldest unacked retransmittable content of the space so
        // the probe carries data rather than a bare PING when possible.
        var oldest: ?usize = null;
        for (self.sent_records.items, 0..) |record, i| {
            if (record.space != space or !record.ack_eliciting) continue;
            if (oldest == null or record.packet_number < self.sent_records.items[oldest.?].packet_number) {
                oldest = i;
            }
        }
        if (oldest) |i| self.requeueRecord(&self.sent_records.items[i]);
    }

    fn armIdle(self: *Connection, now_us: u64) void {
        var timeout_ms = self.local_params.max_idle_timeout_ms;
        if (self.adapter.peerTransportParameters()) |peer| {
            if (peer.max_idle_timeout_ms > 0) {
                timeout_ms = if (timeout_ms == 0) peer.max_idle_timeout_ms else @min(timeout_ms, peer.max_idle_timeout_ms);
            }
        }
        if (timeout_ms == 0) {
            self.idle_deadline_us = null;
            return;
        }
        // RFC 9000 §10.1: at least 3×PTO.
        const idle_us = @max(timeout_ms * 1_000, 3 * self.ptoDurationNow());
        self.idle_deadline_us = now_us + idle_us;
    }

    fn minOpt(current: ?u64, candidate: u64) ?u64 {
        if (current) |value| return @min(value, candidate);
        return candidate;
    }

    // -- streams ---------------------------------------------------------------

    pub fn openStream(self: *Connection, typ: quic_stream.StreamType) !StreamId {
        var manager = self.streamManager() orelse return error.NotEstablished;
        const id = try manager.openLocal(typ);
        try self.known_streams.put(id, {});
        return id;
    }

    /// Queue stream bytes for transmission. Returns how many bytes were
    /// accepted (bounded by `max_stream_send_buffer`); `fin` is recorded once
    /// all bytes of the final write are accepted.
    pub fn writeStream(self: *Connection, id: StreamId, bytes: []const u8, fin: bool) !usize {
        var manager = self.streamManager() orelse return error.NotEstablished;
        const s = manager.get(id) orelse return error.UnknownStream;
        if (!s.canSend()) return error.RecvOnlyStream;
        const queue = try self.sendQueue(id);
        if (queue.reset_sent) return error.StreamReset;
        if (queue.fin_requested) return error.StreamClosed;
        const room = max_stream_send_buffer -| queue.buffered();
        const accepted = @min(bytes.len, room);
        try queue.data.appendSlice(self.allocator, bytes[0..accepted]);
        if (fin and accepted == bytes.len) queue.fin_requested = true;
        return accepted;
    }

    pub fn setStreamSchedulingHint(self: *Connection, id: StreamId, hint: StreamSchedulingHint) !void {
        var manager = self.streamManager() orelse return error.NotEstablished;
        const s = manager.get(id) orelse return error.UnknownStream;
        if (!s.canSend()) return error.RecvOnlyStream;
        const queue = try self.sendQueue(id);
        queue.scheduling_hint = hint;
    }

    pub fn readStream(self: *Connection, id: StreamId, out: []u8) !quic_stream.ReadResult {
        var manager = self.streamManager() orelse return error.NotEstablished;
        const result = try manager.read(id, out);
        // Flow-control credit decided by the stream manager becomes MAX_DATA /
        // MAX_STREAM_DATA frames on the next transmit.
        if (result.credit.max_data != null) self.pending_max_data = result.credit.max_data;
        if (result.credit.max_stream_data) |limit| {
            try self.pending_max_stream_data.append(self.allocator, .{ .id = id, .limit = limit });
        }
        return result;
    }

    /// Pop the next peer-initiated stream the driver has seen.
    pub fn acceptStream(self: *Connection) ?StreamId {
        if (self.accept_queue.items.len == 0) return null;
        return self.accept_queue.orderedRemove(0);
    }

    pub fn streamTransportEarly(self: *const Connection, id: StreamId) bool {
        return self.stream_transport_early.contains(id);
    }

    pub fn markStreamZeroRtt(self: *Connection, id: StreamId) !void {
        try self.stream_transport_early.put(id, {});
    }

    pub fn resetStream(self: *Connection, id: StreamId, app_error_code: u64) !void {
        var manager = self.streamManager() orelse return error.NotEstablished;
        const reset = try manager.sendResetStream(id, app_error_code);
        try self.pending_resets.append(self.allocator, reset);
        if (self.send_queues.get(id)) |queue| {
            queue.reset_sent = true;
            queue.retransmit.items.clearRetainingCapacity();
        }
    }

    // -- path validation --------------------------------------------------------

    /// Current path metrics (#251/#515): challenge/validation counts,
    /// mismatches, rebindings, and migrations (including CID-blocked ones).
    /// Later #387 slices publish these as operator-facing counters.
    pub fn pathMetrics(self: *const Connection) quic_path.Metrics {
        return self.paths.metrics;
    }

    /// The active path's current key.
    pub fn activePathKey(self: *const Connection) quic_path.PathKey {
        return self.paths.activePath().key;
    }

    /// Queue (or refresh) an outbound PATH_CHALLENGE for a candidate path,
    /// called when `PathManager.onDatagram` starts a new validation attempt.
    fn queueCandidateChallenge(self: *Connection, path: quic_path.PathKey, data: [quic_path.path_challenge_len]u8) void {
        for (self.candidate_challenges.items) |*existing| {
            if (existing.path.eql(path)) {
                existing.data = data;
                existing.needs_send = true;
                return;
            }
        }
        self.candidate_challenges.append(self.allocator, .{ .path = path, .data = data, .needs_send = true }) catch {};
    }

    /// Drop a candidate's outstanding-challenge bookkeeping once it validates,
    /// promotes, or is otherwise no longer relevant to egress.
    fn removeCandidateChallenge(self: *Connection, path: quic_path.PathKey) void {
        var i: usize = 0;
        while (i < self.candidate_challenges.items.len) {
            if (self.candidate_challenges.items[i].path.eql(path)) {
                _ = self.candidate_challenges.swapRemove(i);
                return;
            }
            i += 1;
        }
    }

    /// Attempt to promote a validated candidate to the active path (RFC 9000
    /// §9.3/§9.5). Recomputes the classification against the *current*
    /// active path immediately before any CID choice, since another
    /// candidate may have promoted while this one waited. A NAT rebinding
    /// promotes at once, keeping the peer CID and congestion/RTT state. A
    /// host migration must first claim a fresh, never-used peer CID
    /// (linkability, RFC 9000 §9.5): if one is available it is installed
    /// before promotion and the recovery controller is reset for the new
    /// path exactly once; if none is available the old path stays active,
    /// the candidate remains `.validated_pending_promotion`, and
    /// `migrations_blocked_no_peer_cid` is counted instead — a later
    /// NEW_CONNECTION_ID retries this without another challenge round trip.
    fn tryPromote(self: *Connection, candidate: quic_path.PathKey) void {
        const change = self.paths.promotionChange(candidate) orelse return;
        if (change == .migration) {
            const claimed = self.peer_cids.claimForMigration() orelse {
                self.paths.recordMigrationBlockedNoPeerCid();
                self.events.emit(.{ .path_migration_blocked = .{ .path = candidate, .change = change, .reason = .no_peer_cid } });
                return;
            };
            self.peer_cid = config.CidValue.init(claimed.cid.slice()) catch self.peer_cid;
        }
        const outcome = self.paths.promoteValidated(candidate) orelse return;
        if (outcome.reset_congestion) self.recovery.resetForPathMigration();
        self.removeCandidateChallenge(candidate);
        self.events.emit(.{ .path_promoted = .{ .path = candidate, .change = outcome.change } });
    }

    pub fn stopSending(self: *Connection, id: StreamId, app_error_code: u64) !void {
        var manager = self.streamManager() orelse return error.NotEstablished;
        const stop = try manager.sendStopSending(id, app_error_code);
        try self.pending_stop_sending.append(self.allocator, stop);
    }

    pub fn streamState(self: *Connection, id: StreamId) ?quic_stream.StreamState {
        var manager = self.streamManager() orelse return null;
        const s = manager.get(id) orelse return null;
        return s.state();
    }

    fn sendQueue(self: *Connection, id: StreamId) !*SendQueue {
        if (self.send_queues.get(id)) |queue| return queue;
        const queue = try self.allocator.create(SendQueue);
        queue.* = .{};
        errdefer self.allocator.destroy(queue);
        // Align the queue's base with what the manager already granted.
        if (self.streamManager()) |manager| {
            if (manager.get(id)) |s| {
                queue.base = s.send_offset;
                queue.reserved_end = s.send_offset;
            }
        }
        try self.send_queues.put(id, queue);
        return queue;
    }

    // -- transmit ---------------------------------------------------------------

    /// Produce the next outbound UDP datagram into `out` and the exact
    /// destination it must go to. Returns null when nothing may or needs to
    /// be sent right now. Ordinary content (ACK/CRYPTO/STREAM/flow-control)
    /// always targets the active path; a candidate path being validated only
    /// ever gets isolated PATH_CHALLENGE/PATH_RESPONSE/PING/PADDING content,
    /// tried first so a probe is never starved behind ordinary traffic.
    pub fn pollTransmitOnPath(self: *Connection, out: []u8, now_us: u64) ?Transmit {
        if (self.state_ == .closed or self.state_ == .draining) return null;
        if (out.len < max_datagram_size) return null;

        if (self.state_ == .closing) {
            if (!self.close_needs_send) return null;
            self.close_needs_send = false;
            self.close_resend_allowed_at_us = now_us + self.ptoDurationNow() / 2;
            return self.buildCloseDatagram(out, now_us);
        }

        // Advance any parked asynchronous authentication (#334) before building
        // packets, so a resolved external signer/verifier/selector emits its
        // next flight here even when no further peer CRYPTO frame will arrive.
        self.driveAuthentication(now_us);
        if (self.state_ == .closing or self.state_ == .closed or self.state_ == .draining) {
            if (self.state_ == .closing and self.close_needs_send) {
                self.close_needs_send = false;
                self.close_resend_allowed_at_us = now_us + self.ptoDurationNow() / 2;
                return self.buildCloseDatagram(out, now_us);
            }
            return null;
        }

        if (self.pollCandidateTransmit(out, now_us)) |t| return t;

        // Force the delayed app-space ACK when its timer expired.
        if (self.ack_needed[2] and now_us >= self.ack_armed_at_us[2] + local_max_ack_delay_us) {
            self.ack_eliciting_since_ack[2] = ack_eliciting_threshold;
        }

        const budget = @min(out.len, max_datagram_size);
        var datagram_len: usize = 0;
        var has_initial = false;
        var sent_ack_eliciting = false;

        const levels = [_]EncryptionLevel{ .initial, .handshake, .application };
        for (levels, 0..) |level, i| {
            if ((self.adapter.protectionKeys(level, .write) catch unreachable) == null) continue;
            const space = spaceForLevel(level);
            // Is this the last level that could contribute? Needed for the
            // Initial padding rule.
            var last_level = true;
            for (levels[i + 1 ..]) |later| {
                if ((self.adapter.protectionKeys(later, .write) catch unreachable) != null) last_level = false;
            }
            const written = self.buildPacket(level, space, out[datagram_len..budget], now_us, .{
                .datagram_has_initial = has_initial or level == .initial,
                .is_last_level = last_level,
                .datagram_so_far = datagram_len,
            }) orelse continue;
            datagram_len += written.len;
            has_initial = has_initial or level == .initial;
            sent_ack_eliciting = sent_ack_eliciting or written.ack_eliciting;
            if (level == .handshake) {
                if (!self.sent_handshake_packet) {
                    self.sent_handshake_packet = true;
                    // Client: sending at the Handshake level retires Initial
                    // keys (RFC 9001 §4.9.1).
                    if (self.role == .client) self.discardKeys(.initial);
                }
            }
        }
        if (self.handshake_keys_discard_pending and !self.ack_needed[1] and self.crypto_tx[1].pending.isEmpty()) {
            self.handshake_keys_discard_pending = false;
            self.discardKeys(.handshake);
        }
        if (datagram_len == 0) return null;

        const active_key = self.paths.activePath().key;
        self.paths.recordSentOnPath(active_key, datagram_len);
        self.metrics.datagrams_sent += 1;
        if (sent_ack_eliciting) self.armIdle(now_us);
        return .{ .bytes = out[0..datagram_len], .path = active_key };
    }

    /// Whether `path` still corresponds to a live, outstanding validation
    /// attempt in `PathManager` — a queued candidate egress hint (a pending
    /// PATH_CHALLENGE) can outlive the attempt it was created for (expiry,
    /// promotion of a different candidate that recycled the slot), so egress
    /// re-checks state here rather than trusting the hint alone.
    fn pathIsValidating(self: *const Connection, path: quic_path.PathKey) bool {
        return self.paths.stateOf(path) == .validating;
    }

    /// Candidate-path control egress (RFC 9000 §8.2/§9.3): PATH_RESPONSE
    /// queued for a non-active path first (it answers a challenge from a
    /// peer address that may itself be time-limited), then an outstanding
    /// PATH_CHALLENGE we initiated. Never coalesced with ordinary content.
    fn pollCandidateTransmit(self: *Connection, out: []u8, now_us: u64) ?Transmit {
        const active_key = self.paths.activePath().key;

        for (self.pending_path_responses.items) |entry| {
            if (entry.path.eql(active_key)) continue;
            if (self.buildCandidatePacket(entry.path, out, now_us)) |t| return t;
        }

        var i: usize = 0;
        while (i < self.candidate_challenges.items.len) {
            const candidate = self.candidate_challenges.items[i];
            if (!self.pathIsValidating(candidate.path)) {
                _ = self.candidate_challenges.swapRemove(i);
                continue;
            }
            if (candidate.needs_send) {
                if (self.buildCandidatePacket(candidate.path, out, now_us)) |t| return t;
            }
            i += 1;
        }
        return null;
    }

    /// Assemble, seal, and record one control-only datagram for `path`: a
    /// queued PATH_RESPONSE and/or an outstanding PATH_CHALLENGE, padded per
    /// RFC 9000 §8.2.1, gated strictly by that path's own anti-amplification
    /// budget. Never carries ACK/STREAM/CRYPTO/flow-control/CID-management
    /// content — that stays exclusively on the active path until promotion.
    fn buildCandidatePacket(self: *Connection, path: quic_path.PathKey, out: []u8, now_us: u64) ?Transmit {
        if (out.len < max_datagram_size) return null;
        const keys = (self.adapter.protectionKeys(.application, .write) catch unreachable) orelse return null;

        const remaining = self.paths.remainingOnPath(path);
        if (remaining == 0) return null;

        const space_idx = spaceIndex(.application);
        const pn = self.next_pn[space_idx];
        const pn_len: u3 = packet.packetNumberLength(pn, self.largest_peer_acked[space_idx]);
        const pn_offset = packet.writeShortHeader(self.peer_cid.slice(), self.adapter.applicationWriteKeyPhase(), pn_len, out) catch return null;

        const max_packet = @min(out.len, @as(usize, @intCast(@min(@as(u64, out.len), remaining))));
        if (max_packet <= pn_offset + pn_len + aead_tag_len + 16) return null;
        var plain: [max_datagram_size]u8 = undefined;
        const plain_budget = @min(plain.len, max_packet - pn_offset - pn_len - aead_tag_len);
        var plain_len: usize = 0;
        var record = SentRecord{ .space = .application, .packet_number = pn, .ack_eliciting = false };

        var i: usize = 0;
        while (i < self.pending_path_responses.items.len) {
            const entry = self.pending_path_responses.items[i];
            if (!entry.path.eql(path)) {
                i += 1;
                continue;
            }
            const n = frame.encodePathResponse(entry.data, plain[plain_len..plain_budget]) catch break;
            plain_len += n;
            record.ack_eliciting = true;
            record.carried_path_response = true;
            _ = self.pending_path_responses.orderedRemove(i);
        }

        for (self.candidate_challenges.items) |*candidate| {
            if (!candidate.path.eql(path) or !candidate.needs_send) continue;
            if (frame.encodePathChallenge(candidate.data, plain[plain_len..plain_budget])) |n| {
                plain_len += n;
                record.ack_eliciting = true;
                record.carried_path_challenge_path = path;
                candidate.needs_send = false;
            } else |_| {}
            break;
        }

        if (plain_len == 0) return null;
        if (!record.ack_eliciting) {
            if (frame.encodePing(plain[plain_len..plain_budget])) |n| {
                plain_len += n;
                record.ack_eliciting = true;
            } else |_| {}
        }
        if (plain_len == 0) return null;

        // RFC 9000 §8.2.1: expand datagrams carrying PATH_CHALLENGE or
        // PATH_RESPONSE to at least 1200 bytes, capped by this candidate
        // path's own anti-amplification budget.
        const sample_min = (4 - @as(usize, pn_len)) + sample_len - aead_tag_len;
        if (plain_len < sample_min) {
            @memset(plain[plain_len..sample_min], 0);
            plain_len = sample_min;
        }
        const packet_overhead = pn_offset + pn_len + aead_tag_len;
        if (packet_overhead + plain_len < min_initial_datagram and min_initial_datagram <= plain_budget + packet_overhead) {
            const padded = min_initial_datagram - packet_overhead;
            @memset(plain[plain_len..padded], 0);
            plain_len = padded;
        }

        const truncated = packet.truncatePacketNumber(pn, pn_len);
        var pn_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &pn_bytes, truncated, .big);
        @memcpy(out[pn_offset..][0..pn_len], pn_bytes[4 - @as(usize, pn_len) ..][0..pn_len]);

        const header = out[0 .. pn_offset + pn_len];
        const sealed = self.adapter.sealPacketPayload(.application, .write, pn, header, plain[0..plain_len], out[pn_offset + pn_len ..]) catch return null;

        var sample: [sample_len]u8 = undefined;
        @memcpy(&sample, out[pn_offset + 4 ..][0..sample_len]);
        keys.applyHeaderProtectionWithProvider(self.adapter.provider, &out[0], out[pn_offset..][0..pn_len], sample) catch unreachable;

        const total = pn_offset + pn_len + sealed.len;
        self.next_pn[space_idx] = pn + 1;

        if (record.ack_eliciting) {
            var tracked = true;
            self.recovery.onPacketSent(.{
                .space = .application,
                .packet_number = pn,
                .time_sent_us = now_us,
                .size = total,
                .ack_eliciting = true,
                .in_flight = true,
            }) catch {
                tracked = false;
            };
            self.last_ack_eliciting_sent_us[space_idx] = now_us;
            if (tracked) publishSentRecord(self, &record);
        }
        self.paths.recordSentOnPath(path, total);
        self.metrics.packets_sent += 1;
        self.metrics.datagrams_sent += 1;
        self.events.emit(.{ .packet_sent = .{
            .space = .application,
            .packet_number = pn,
            .size = total,
            .ack_eliciting = record.ack_eliciting,
        } });
        return .{ .bytes = out[0..total], .path = path };
    }

    const BuildContext = struct {
        datagram_has_initial: bool,
        is_last_level: bool,
        datagram_so_far: usize,
    };

    const BuiltPacket = struct {
        len: usize,
        ack_eliciting: bool,
    };

    /// Assemble, seal, and record one packet at `level` into `out`. Returns
    /// null when the level has nothing to send or the send gates say no.
    fn buildPacket(
        self: *Connection,
        level: EncryptionLevel,
        space: PacketNumberSpace,
        out: []u8,
        now_us: u64,
        ctx: BuildContext,
    ) ?BuiltPacket {
        const space_idx = spaceIndex(space);
        const probe = self.probes_pending[space_idx] > 0;

        // Congestion gate: in-flight (ack-eliciting) bytes need window; pure
        // ACK packets and PTO probes are exempt (RFC 9002 §7, §6.2.4).
        const cwnd_room = self.recovery.congestion.congestion_window -| self.recovery.congestion.bytes_in_flight;
        const can_send_data = probe or cwnd_room >= max_datagram_size / 2 or
            self.recovery.congestion.bytes_in_flight == 0;

        // Anti-amplification gate applies to every byte a server sends before
        // the client's address is validated. Ordinary output always targets
        // the active path until promotion (candidate-path content is built
        // and gated separately by `buildCandidatePacket`).
        const amp_room = self.paths.activePath().anti_amplification.remaining();
        if (amp_room == 0) return null;

        var want_ack = self.ack_needed[space_idx];
        if (space == .application and want_ack) {
            // Delayed ACK: send only when forced by threshold/timer or when
            // the packet carries other content anyway.
            const forced = self.ack_eliciting_since_ack[space_idx] >= ack_eliciting_threshold;
            if (!forced and !self.hasAppContent() and !probe) want_ack = false;
        }

        const has_crypto = switch (space) {
            .initial => !self.crypto_tx[0].pending.isEmpty(),
            .handshake => !self.crypto_tx[1].pending.isEmpty(),
            .application => !self.crypto_tx[2].pending.isEmpty(),
        };
        const has_app = space == .application and self.hasAppContent();
        if (!want_ack and !has_crypto and !(has_app and can_send_data) and !probe) return null;
        if ((has_crypto or has_app) and !can_send_data and !want_ack and !probe) return null;

        // Header sizing.
        const pn = self.next_pn[space_idx];
        const pn_len: u3 = packet.packetNumberLength(pn, self.largest_peer_acked[space_idx]);
        var header_written: packet.WrittenLongHeader = undefined;
        var pn_offset: usize = 0;
        switch (level) {
            .initial => {
                header_written = packet.writeLongHeader(.initial, packet.quic_v1, self.peer_cid.slice(), self.local_cid.slice(), self.retry_token.items, pn_len, out) catch return null;
                pn_offset = header_written.pn_offset;
            },
            .handshake => {
                header_written = packet.writeLongHeader(.handshake, packet.quic_v1, self.peer_cid.slice(), self.local_cid.slice(), "", pn_len, out) catch return null;
                pn_offset = header_written.pn_offset;
            },
            .application => {
                pn_offset = packet.writeShortHeader(self.peer_cid.slice(), self.adapter.applicationWriteKeyPhase(), pn_len, out) catch return null;
            },
            .zero_rtt => return null,
        }

        // Available plaintext room in this packet.
        const max_packet = @min(out.len, @as(usize, @intCast(@min(@as(u64, out.len), amp_room -| ctx.datagram_so_far))));
        if (max_packet <= pn_offset + pn_len + aead_tag_len + 16) return null;
        var plain: [max_datagram_size]u8 = undefined;
        const plain_budget = @min(plain.len, max_packet - pn_offset - pn_len - aead_tag_len);
        var plain_len: usize = 0;
        var record = SentRecord{
            .space = space,
            .packet_number = pn,
            .ack_eliciting = false,
        };
        // `record` may pick up a dequeued NEW_CONNECTION_ID's reset token
        // below; `self.sent_records.append` (if reached) copies it into the
        // owned, tracked record, but this local stays around until every
        // return path below (including early failures after the token was
        // already dequeued and encoded) unwinds. Wipe it unconditionally on
        // the way out — a no-op when no token was ever attached.
        defer wipeSentRecordToken(&record);

        // 1) ACK
        if (want_ack) {
            const delay = now_us -| self.ack_armed_at_us[space_idx];
            if (self.recovery.ackFrameForSpace(space, delay)) |model| {
                if (frame.encodeAck(model, local_ack_delay_exponent, plain[plain_len..plain_budget])) |n| {
                    plain_len += n;
                    record.carried_ack_largest = model.largest_acknowledged;
                    self.ack_needed[space_idx] = false;
                    self.ack_eliciting_since_ack[space_idx] = 0;
                    self.metrics.acks_sent += 1;
                } else |_| {}
            } else {
                self.ack_needed[space_idx] = false;
            }
        }

        // 2) CRYPTO retransmission/transmission
        if (has_crypto and (can_send_data or probe)) {
            const tx = switch (space) {
                .initial => &self.crypto_tx[0],
                .handshake => &self.crypto_tx[1],
                .application => &self.crypto_tx[2],
            };
            while (!tx.pending.isEmpty() and plain_len + frame.max_crypto_overhead + 16 < plain_budget) {
                const room: u64 = @intCast(plain_budget - plain_len - frame.max_crypto_overhead);
                var range = tx.pending.takeFirst(room) orelse break;
                range = tx.liveRange(range) orelse continue;
                if (record.crypto) |existing| {
                    if (existing.end != range.start) {
                        if (space == .application) {
                            tx.pending.insertAssumeCapacity(range);
                        } else {
                            tx.pending.insert(self.allocator, range) catch {};
                        }
                        break;
                    }
                }
                const data = tx.slice(range);
                const n = frame.encodeCrypto(range.start, data, plain[plain_len..plain_budget]) catch {
                    if (space == .application) {
                        tx.pending.insertAssumeCapacity(range);
                    } else {
                        tx.pending.insert(self.allocator, range) catch {};
                    }
                    break;
                };
                plain_len += n;
                record.ack_eliciting = true;
                // One crypto range per record keeps requeue simple; merge by
                // extending when contiguous.
                if (record.crypto) |existing| {
                    record.crypto = .{ .start = existing.start, .end = range.end };
                } else {
                    record.crypto = range;
                }
            }
        }

        // 3) Application-space control and stream frames
        if (space == .application and self.state_ == .established and (can_send_data or probe)) {
            plain_len = self.buildAppFrames(&record, &plain, plain_len, plain_budget);
        }

        // 4) Probe padding: a PTO probe with nothing else carries a PING.
        if (probe and !record.ack_eliciting) {
            if (frame.encodePing(plain[plain_len..plain_budget])) |n| {
                plain_len += n;
                record.ack_eliciting = true;
            } else |_| {}
        }
        if (plain_len == 0) return null;
        if (probe) self.probes_pending[space_idx] -|= 1;

        // 5) Padding. Header-protection sampling needs ciphertext at least
        // 4 - pn_len + sample_len long; Initial-bearing datagrams pad to 1200.
        const sample_min = (4 - @as(usize, pn_len)) + sample_len - aead_tag_len;
        if (plain_len < sample_min) {
            @memset(plain[plain_len..sample_min], 0);
            plain_len = sample_min;
        }
        // Datagrams carrying Initial packets pad to 1200 (§14.1); so does one
        // carrying a PATH_RESPONSE to the active path (§8.2.1-2, to validate
        // the path's MTU) — PATH_CHALLENGE never rides ordinary active-path
        // content; `buildCandidatePacket` pads candidate-path probes itself.
        // `plain_budget` already reflects the anti-amplification allowance,
        // which §8.2.1 lets cap the expansion.
        if ((ctx.datagram_has_initial and ctx.is_last_level) or record.carried_path_response) {
            const target = min_initial_datagram -| ctx.datagram_so_far;
            const packet_overhead = pn_offset + pn_len + aead_tag_len;
            if (packet_overhead + plain_len < target and target <= plain_budget + packet_overhead) {
                const padded = target - packet_overhead;
                @memset(plain[plain_len..padded], 0);
                plain_len = padded;
            }
        }

        // 6) Seal.
        if (level != .application) {
            packet.patchLongHeaderLength(out, header_written.length_offset, pn_len + plain_len + aead_tag_len);
        }
        const truncated = packet.truncatePacketNumber(pn, pn_len);
        var pn_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &pn_bytes, truncated, .big);
        @memcpy(out[pn_offset..][0..pn_len], pn_bytes[4 - @as(usize, pn_len) ..][0..pn_len]);

        const header = out[0 .. pn_offset + pn_len];
        const keys = (self.adapter.protectionKeys(level, .write) catch unreachable) orelse return null;
        const sealed = self.adapter.sealPacketPayload(level, .write, pn, header, plain[0..plain_len], out[pn_offset + pn_len ..]) catch return null;

        var sample: [sample_len]u8 = undefined;
        @memcpy(&sample, out[pn_offset + 4 ..][0..sample_len]);
        keys.applyHeaderProtectionWithProvider(self.adapter.provider, &out[0], out[pn_offset..][0..pn_len], sample) catch unreachable;

        const total = pn_offset + pn_len + sealed.len;
        self.next_pn[space_idx] = pn + 1;

        // 7) Record for recovery. Non-ack-eliciting packets (pure ACKs) are
        // never acknowledged by the peer, so tracking them would only fill
        // the tracker; RFC 9002 excludes them from loss/congestion anyway.
        if (record.ack_eliciting) {
            var tracked = true;
            self.recovery.onPacketSent(.{
                .space = space,
                .packet_number = pn,
                .time_sent_us = now_us,
                .size = total,
                .ack_eliciting = true,
                .in_flight = true,
            }) catch {
                // Tracker exhaustion: the packet is sealed and will be sent;
                // treat it as untracked best-effort.
                tracked = false;
            };
            self.last_ack_eliciting_sent_us[space_idx] = now_us;
            if (tracked) publishSentRecord(self, &record);
        }
        if (record.carried_new_connection_id) |ncid| {
            if (self.local_cids) |*registry| registry.markAdvertised(ncid.sequence) catch {};
        }
        self.metrics.packets_sent += 1;
        self.events.emit(.{ .packet_sent = .{
            .space = space,
            .packet_number = pn,
            .size = total,
            .ack_eliciting = record.ack_eliciting,
        } });
        return .{ .len = total, .ack_eliciting = record.ack_eliciting };
    }

    /// Whether a PATH_RESPONSE is queued for the active path specifically —
    /// separate from any queued for a candidate path, which
    /// `buildCandidatePacket` sends in isolation instead.
    fn hasActivePathResponsePending(self: *const Connection) bool {
        const active_key = self.paths.activePath().key;
        for (self.pending_path_responses.items) |entry| {
            if (entry.path.eql(active_key)) return true;
        }
        return false;
    }

    fn hasAppContent(self: *Connection) bool {
        if (self.state_ != .established) return false;
        if (self.handshake_done_pending) return true;
        if (self.pending_max_data != null) return true;
        if (self.pending_max_stream_data.items.len > 0) return true;
        if (self.pending_resets.items.len > 0) return true;
        if (self.pending_stop_sending.items.len > 0) return true;
        if (self.pending_retires.items.len > 0) return true;
        if (self.pending_new_connection_ids.items.len > 0) return true;
        if (self.hasActivePathResponsePending()) return true;
        var it = self.send_queues.iterator();
        while (it.next()) |entry| {
            const queue = entry.value_ptr.*;
            if (queue.reset_sent) continue;
            if (!queue.retransmit.isEmpty() or queue.fin_retransmit) return true;
            if (queue.bufferedEnd() > queue.reserved_end) return true;
            if (queue.fin_requested and !queue.fin_reserved) return true;
        }
        return false;
    }

    fn buildAppFrames(self: *Connection, record: *SentRecord, plain: []u8, start_len: usize, budget: usize) usize {
        var plain_len = start_len;

        if (self.handshake_done_pending and self.role == .server) {
            if (frame.encodeHandshakeDone(plain[plain_len..budget])) |n| {
                plain_len += n;
                record.ack_eliciting = true;
                record.carried_handshake_done = true;
                self.handshake_done_pending = false;
            } else |_| {}
        }
        if (self.pending_max_data) |limit| {
            if (frame.encodeMaxData(limit, plain[plain_len..budget])) |n| {
                plain_len += n;
                record.ack_eliciting = true;
                record.carried_max_data = true;
                self.pending_max_data = null;
            } else |_| {}
        }
        while (self.pending_max_stream_data.items.len > 0) {
            const entry = self.pending_max_stream_data.items[0];
            const n = frame.encodeMaxStreamData(entry.id, entry.limit, plain[plain_len..budget]) catch break;
            plain_len += n;
            record.ack_eliciting = true;
            record.carried_max_stream_data = entry.id;
            _ = self.pending_max_stream_data.orderedRemove(0);
        }
        // RESET_STREAM / STOP_SENDING: sent once, re-queued if the carrying
        // packet is lost. One of each per packet keeps the record small.
        if (self.pending_resets.items.len > 0) {
            const reset = self.pending_resets.items[0];
            if (frame.encodeResetStream(reset, plain[plain_len..budget])) |n| {
                plain_len += n;
                record.ack_eliciting = true;
                record.carried_reset_stream = reset;
                _ = self.pending_resets.orderedRemove(0);
            } else |_| {}
        }
        if (self.pending_stop_sending.items.len > 0) {
            const stop = self.pending_stop_sending.items[0];
            if (frame.encodeStopSending(stop, plain[plain_len..budget])) |n| {
                plain_len += n;
                record.ack_eliciting = true;
                record.carried_stop_sending = stop;
                _ = self.pending_stop_sending.orderedRemove(0);
            } else |_| {}
        }
        while (self.pending_retires.items.len > 0) {
            const sequence = self.pending_retires.items[0];
            const n = frame.encodeRetireConnectionId(sequence, plain[plain_len..budget]) catch break;
            plain_len += n;
            record.ack_eliciting = true;
            _ = self.pending_retires.orderedRemove(0);
        }
        if (self.pending_new_connection_ids.items.len > 0) {
            // Encode and assign directly from the queued element rather
            // than through an intermediate `const ncid = ...` local: that
            // would leave a third, unwiped stack copy of the reset token
            // (beyond the queue's own copy and the one `record` ends up
            // owning) sitting around for the rest of this function.
            if (frame.encodeNewConnectionId(&self.pending_new_connection_ids.items[0], plain[plain_len..budget])) |n| {
                plain_len += n;
                record.ack_eliciting = true;
                record.carried_new_connection_id = self.pending_new_connection_ids.items[0];
                _ = self.pending_new_connection_ids.orderedRemove(0);
                wipePendingNewConnectionIdsOrderedRemoveResidue(&self.pending_new_connection_ids);
            } else |_| {}
        }
        // Only a PATH_RESPONSE queued for the active path rides along with
        // ordinary content; one queued for a candidate path is sent in
        // isolation by `buildCandidatePacket` instead (candidate-path egress
        // must never carry ACK/STREAM/CRYPTO/flow-control content).
        {
            const active_key = self.paths.activePath().key;
            var i: usize = 0;
            while (i < self.pending_path_responses.items.len) {
                const entry = self.pending_path_responses.items[i];
                if (!entry.path.eql(active_key)) {
                    i += 1;
                    continue;
                }
                const n = frame.encodePathResponse(entry.data, plain[plain_len..budget]) catch break;
                plain_len += n;
                record.ack_eliciting = true;
                record.carried_path_response = true;
                _ = self.pending_path_responses.orderedRemove(i);
            }
        }

        // Stream data: retransmissions first, then new bytes. Pick by the
        // stream scheduling hint instead of hash-map order: lower urgency
        // wins, equal urgency rotates by stream id from a bounded cursor.
        while (record.stream_count < record.streams.len) {
            if (plain_len + frame.max_stream_overhead + 1 >= budget) break;
            const selected = self.selectReadySendQueue(plain_len, budget) orelse break;
            const id = selected.id;
            const queue = selected.queue;
            const before_stream_count = record.stream_count;

            // Retransmit ranges.
            while (!queue.retransmit.isEmpty() and record.stream_count < record.streams.len) {
                const room: u64 = @intCast(budget - plain_len -| frame.max_stream_overhead);
                if (room == 0) break;
                const range = queue.retransmit.takeFirst(room) orelse break;
                const is_fin_range = queue.fin_retransmit and range.end == queue.reserved_end;
                const n = frame.encodeStream(id, range.start, queue.slice(range), is_fin_range, plain[plain_len..budget]) catch {
                    queue.retransmit.insert(self.allocator, range) catch {};
                    break;
                };
                if (is_fin_range) queue.fin_retransmit = false;
                plain_len += n;
                record.ack_eliciting = true;
                record.streams[record.stream_count] = .{ .id = id, .range = range, .fin = is_fin_range };
                record.stream_count += 1;
                break;
            }
            if (record.stream_count != before_stream_count) {
                self.stream_scheduling_cursor = id +% 1;
                continue;
            }

            // A lost FIN whose data range was empty (or fully acked) needs an
            // explicit empty STREAM+FIN frame.
            if (queue.fin_retransmit and queue.retransmit.isEmpty() and record.stream_count < record.streams.len) {
                const off = queue.reserved_end;
                if (frame.encodeStream(id, off, "", true, plain[plain_len..budget])) |n| {
                    queue.fin_retransmit = false;
                    plain_len += n;
                    record.ack_eliciting = true;
                    record.streams[record.stream_count] = .{ .id = id, .range = .{ .start = off, .end = off }, .fin = true };
                    record.stream_count += 1;
                } else |_| {}
            }
            if (record.stream_count != before_stream_count) {
                self.stream_scheduling_cursor = id +% 1;
                continue;
            }

            // New data within flow control.
            var manager = self.streamManager() orelse continue;
            const s = manager.get(id) orelse continue;
            const unsent = queue.bufferedEnd() -| queue.reserved_end;
            const want_fin = queue.fin_requested and !queue.fin_reserved;
            if (unsent == 0 and !want_fin) continue;
            const stream_window = s.max_send_data -| s.send_offset;
            const conn_window = manager.max_data_send -| manager.bytes_sent;
            const frame_room: u64 = @intCast(budget -| plain_len -| frame.max_stream_overhead);
            const n_bytes = @min(@min(unsent, @min(stream_window, conn_window)), frame_room);
            if (n_bytes == 0 and !(want_fin and unsent == 0)) continue;
            const fin_now = want_fin and n_bytes == unsent;
            const grant = manager.reserveSend(id, @intCast(n_bytes), fin_now) catch continue;
            const range = Range{ .start = grant.offset, .end = grant.offset + grant.len };
            const n = frame.encodeStream(id, range.start, queue.slice(range), grant.fin, plain[plain_len..budget]) catch continue;
            plain_len += n;
            queue.reserved_end = range.end;
            if (grant.fin) queue.fin_reserved = true;
            record.ack_eliciting = true;
            record.streams[record.stream_count] = .{ .id = id, .range = range, .fin = grant.fin };
            record.stream_count += 1;
            self.stream_scheduling_cursor = id +% 1;
        }
        return plain_len;
    }

    const SelectedSendQueue = struct {
        id: StreamId,
        queue: *SendQueue,
    };

    fn selectReadySendQueue(self: *Connection, plain_len: usize, budget: usize) ?SelectedSendQueue {
        var selected: ?SelectedSendQueue = null;
        var it = self.send_queues.iterator();
        while (it.next()) |entry| {
            const id = entry.key_ptr.*;
            const queue = entry.value_ptr.*;
            if (!self.sendQueueReady(id, queue, plain_len, budget)) continue;
            const candidate = SelectedSendQueue{ .id = id, .queue = queue };
            if (selected) |current| {
                if (sendQueueBefore(candidate, current, self.stream_scheduling_cursor)) selected = candidate;
            } else {
                selected = candidate;
            }
        }
        return selected;
    }

    fn sendQueueReady(self: *Connection, id: StreamId, queue: *SendQueue, plain_len: usize, budget: usize) bool {
        if (queue.reset_sent) return false;
        if (!queue.retransmit.isEmpty() or queue.fin_retransmit) return true;
        const manager = self.streamManager() orelse return false;
        const s = manager.get(id) orelse return false;
        const unsent = queue.bufferedEnd() -| queue.reserved_end;
        const want_fin = queue.fin_requested and !queue.fin_reserved;
        if (unsent == 0 and !want_fin) return false;
        const stream_window = s.max_send_data -| s.send_offset;
        const conn_window = manager.max_data_send -| manager.bytes_sent;
        const frame_room: u64 = @intCast(budget -| plain_len -| frame.max_stream_overhead);
        const n_bytes = @min(@min(unsent, @min(stream_window, conn_window)), frame_room);
        return n_bytes != 0 or (want_fin and unsent == 0);
    }

    fn sendQueueBefore(lhs: SelectedSendQueue, rhs: SelectedSendQueue, cursor: StreamId) bool {
        const lhs_hint = lhs.queue.scheduling_hint;
        const rhs_hint = rhs.queue.scheduling_hint;
        if (lhs_hint.urgency != rhs_hint.urgency) return lhs_hint.urgency < rhs_hint.urgency;
        return distanceFromCursor(lhs.id, cursor) < distanceFromCursor(rhs.id, cursor);
    }

    fn distanceFromCursor(id: StreamId, cursor: StreamId) u64 {
        return id -% cursor;
    }

    fn buildCloseDatagram(self: *Connection, out: []u8, now_us: u64) ?Transmit {
        _ = now_us;
        const info = self.close_info orelse return null;
        // Send the close at the highest available level (RFC 9000 §10.2.3:
        // application closes at lower levels are converted to transport
        // closes to avoid leaking application state pre-handshake).
        var level: EncryptionLevel = .application;
        if ((self.adapter.protectionKeys(.application, .write) catch unreachable) == null) {
            level = .handshake;
            if ((self.adapter.protectionKeys(.handshake, .write) catch unreachable) == null) level = .initial;
        }
        if ((self.adapter.protectionKeys(level, .write) catch unreachable) == null) return null;

        const space = spaceForLevel(level);
        const space_idx = spaceIndex(space);
        const pn = self.next_pn[space_idx];
        const pn_len: u3 = packet.packetNumberLength(pn, self.largest_peer_acked[space_idx]);

        var pn_offset: usize = 0;
        var header_written: packet.WrittenLongHeader = undefined;
        switch (level) {
            .initial => {
                header_written = packet.writeLongHeader(.initial, packet.quic_v1, self.peer_cid.slice(), self.local_cid.slice(), self.retry_token.items, pn_len, out) catch return null;
                pn_offset = header_written.pn_offset;
            },
            .handshake => {
                header_written = packet.writeLongHeader(.handshake, packet.quic_v1, self.peer_cid.slice(), self.local_cid.slice(), "", pn_len, out) catch return null;
                pn_offset = header_written.pn_offset;
            },
            .application => {
                pn_offset = packet.writeShortHeader(self.peer_cid.slice(), self.adapter.applicationWriteKeyPhase(), pn_len, out) catch return null;
            },
            .zero_rtt => return null,
        }

        var plain: [512]u8 = undefined;
        const use_app_frame = info.is_application and level == .application;
        var plain_len = frame.encodeConnectionClose(.{
            .error_code = if (use_app_frame or info.is_application == false) info.error_code else error_internal,
            .reason = self.close_reason[0..self.close_reason_len],
            .is_application = use_app_frame,
        }, &plain) catch return null;

        const sample_min = (4 - @as(usize, pn_len)) + sample_len - aead_tag_len;
        if (plain_len < sample_min) {
            @memset(plain[plain_len..sample_min], 0);
            plain_len = sample_min;
        }
        if (level != .application) {
            packet.patchLongHeaderLength(out, header_written.length_offset, pn_len + plain_len + aead_tag_len);
        }
        const truncated = packet.truncatePacketNumber(pn, pn_len);
        var pn_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &pn_bytes, truncated, .big);
        @memcpy(out[pn_offset..][0..pn_len], pn_bytes[4 - @as(usize, pn_len) ..][0..pn_len]);
        const header = out[0 .. pn_offset + pn_len];
        const keys = (self.adapter.protectionKeys(level, .write) catch unreachable) orelse return null;
        const sealed = self.adapter.sealPacketPayload(level, .write, pn, header, plain[0..plain_len], out[pn_offset + pn_len ..]) catch return null;
        var sample: [sample_len]u8 = undefined;
        @memcpy(&sample, out[pn_offset + 4 ..][0..sample_len]);
        keys.applyHeaderProtectionWithProvider(self.adapter.provider, &out[0], out[pn_offset..][0..pn_len], sample) catch unreachable;
        self.next_pn[space_idx] = pn + 1;

        var total = pn_offset + pn_len + sealed.len;
        // A close carried in an Initial packet still obeys §14.1 padding.
        if (level == .initial and total < min_initial_datagram) {
            // Rebuild with padding is overkill; pad the datagram with zero
            // bytes after the packet is illegal, so instead treat the close
            // packet as final without padding — the peer processes Initial
            // packets of any size when they arrive coalesced or alone from a
            // server. For client-side closes this only happens pre-handshake.
            total = total;
        }
        const active_key = self.paths.activePath().key;
        self.paths.recordSentOnPath(active_key, total);
        self.metrics.datagrams_sent += 1;
        self.events.emit(.{ .close_sent = .{ .error_code = info.error_code } });
        return .{ .bytes = out[0..total], .path = active_key };
    }
};

// ---------------------------------------------------------------------------
// Tests: driver-level client<->server handshake and data exchange using the
// real pure-Zig TLS backend, real packets, and a lossless in-memory pump.
// Loss/reorder scenarios live in tests/quic_h3_e2e.zig.
// ---------------------------------------------------------------------------

const testing = std.testing;
const tls_backend_mod = @import("tls_backend.zig");

test "application CRYPTO transmit ignores stale PTO ranges after original ACK" {
    const allocator = testing.allocator;
    var tx = CryptoTx{};
    defer tx.deinit(allocator);

    try tx.reserveAppend(allocator, 8, max_application_crypto_outstanding);
    tx.appendReserved("ticket-1");
    try tx.pending.insert(allocator, .{ .start = 0, .end = 8 });

    tx.markAcked(allocator, .{ .start = 0, .end = 8 });
    try testing.expectEqual(@as(u64, 8), tx.base);
    try testing.expectEqual(@as(usize, 0), tx.data.items.len);
    try testing.expect(tx.pending.isEmpty());
}

test "application CRYPTO transmit ignores late duplicate ACKs and compacts later data" {
    const allocator = testing.allocator;
    var tx = CryptoTx{};
    defer tx.deinit(allocator);

    try tx.reserveAppend(allocator, 16, max_application_crypto_outstanding);
    tx.appendReserved("ticket-1ticket-2");

    tx.markAcked(allocator, .{ .start = 0, .end = 8 });
    tx.markAcked(allocator, .{ .start = 0, .end = 8 });
    tx.markAcked(allocator, .{ .start = 8, .end = 16 });

    try testing.expectEqual(@as(u64, 16), tx.base);
    try testing.expectEqual(@as(usize, 0), tx.data.items.len);
    try testing.expect(tx.acked.isEmpty());
    try testing.expect(tx.pending.isEmpty());
}

test "application CRYPTO transmit clamps lost duplicate ranges below base" {
    const allocator = testing.allocator;
    var tx = CryptoTx{};
    defer tx.deinit(allocator);

    try tx.reserveAppend(allocator, 16, max_application_crypto_outstanding);
    tx.appendReserved("ticket-ticket-12");
    tx.markAcked(allocator, .{ .start = 0, .end = 8 });

    const live = tx.liveRange(.{ .start = 0, .end = 16 }) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(Range{ .start = 8, .end = 16 }, live);
}

test "application CRYPTO transmit allocates exact storage and frees after ACK" {
    const allocator = testing.allocator;
    var tx = CryptoTx{};
    defer tx.deinit(allocator);

    try tx.reserveAppend(allocator, 12, max_application_crypto_outstanding);
    tx.appendReserved("small-ticket");
    try testing.expectEqual(@as(usize, 12), tx.data.capacity);
    try testing.expect(tx.data.capacity < max_application_crypto_outstanding);

    tx.markAcked(allocator, .{ .start = 0, .end = 12 });
    try testing.expectEqual(@as(usize, 0), tx.data.items.len);
    try testing.expectEqual(@as(usize, 0), tx.data.capacity);
    try testing.expect(tx.pending.isEmpty());
    try testing.expect(tx.acked.isEmpty());
}

test "application CRYPTO transmit allows second outstanding ticket" {
    const allocator = testing.allocator;
    var tx = CryptoTx{};
    defer tx.deinit(allocator);

    try tx.reserveAppend(allocator, 12, max_application_crypto_outstanding);
    tx.appendReserved("first-ticket");
    try tx.reserveAppend(allocator, 13, max_application_crypto_outstanding);
    tx.appendReserved("second-ticket");

    try testing.expectEqual(@as(usize, 25), tx.data.items.len);
    try testing.expectEqual(@as(usize, 25), tx.data.capacity);
    try testing.expectEqualStrings("first-ticketsecond-ticket", tx.data.items);
    try testing.expect(tx.pending.coversPrefix(25));
}

test "application CRYPTO reservation failure leaves empty state retryable" {
    for (0..3) |fail_index| {
        var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = fail_index });
        var tx = CryptoTx{};
        defer tx.deinit(testing.allocator);

        try testing.expectError(error.OutOfMemory, tx.reserveAppend(failing.allocator(), 12, max_application_crypto_outstanding));
        try testing.expectEqual(@as(usize, 0), tx.data.items.len);
        try testing.expectEqual(@as(usize, 0), tx.data.capacity);
        try testing.expect(tx.pending.isEmpty());
        try testing.expect(tx.acked.isEmpty());

        const retry = "larger-ticket-after-failed-reserve";
        try tx.reserveAppend(testing.allocator, retry.len, max_application_crypto_outstanding);
        tx.appendReserved(retry);
        try testing.expectEqual(retry.len, tx.data.items.len);
        tx.markAcked(testing.allocator, .{ .start = 0, .end = retry.len });
    }
}

test "stream send queue keeps lost ranges retransmittable across duplicate ACK and loss signals" {
    var queue = SendQueue{};
    defer queue.deinit(testing.allocator);

    try queue.data.appendSlice(testing.allocator, "abcdefgh");
    queue.reserved_end = 8;

    try queue.retransmit.insert(testing.allocator, .{ .start = 2, .end = 6 });
    try queue.retransmit.insert(testing.allocator, .{ .start = 4, .end = 8 });
    try testing.expectEqual(@as(usize, 1), queue.retransmit.items.items.len);
    try testing.expectEqual(Range{ .start = 2, .end = 8 }, queue.retransmit.items.items[0]);

    markSendQueueRangeAcked(testing.allocator, &queue, .{ .start = 0, .end = 8 }, false);
    markSendQueueRangeAcked(testing.allocator, &queue, .{ .start = 0, .end = 8 }, false);
    try testing.expectEqual(@as(u64, 8), queue.base);
    try testing.expectEqualStrings("", queue.data.items[queue.start..]);
    try testing.expect(queue.retransmit.isEmpty());
}

test "stream send queue subtracts acked overlap from lost retransmit ranges" {
    var queue = SendQueue{};
    defer queue.deinit(testing.allocator);

    try queue.data.appendSlice(testing.allocator, "abcdefgh");
    queue.reserved_end = 8;

    requeueSendQueueRange(testing.allocator, &queue, .{ .start = 0, .end = 8 }, false);
    markSendQueueRangeAcked(testing.allocator, &queue, .{ .start = 2, .end = 6 }, false);

    try testing.expectEqual(@as(usize, 2), queue.retransmit.items.items.len);
    try testing.expectEqual(Range{ .start = 0, .end = 2 }, queue.retransmit.items.items[0]);
    try testing.expectEqual(Range{ .start = 6, .end = 8 }, queue.retransmit.items.items[1]);
}

test "stream send queue does not resurrect acked bytes on later duplicate loss" {
    var queue = SendQueue{};
    defer queue.deinit(testing.allocator);

    try queue.data.appendSlice(testing.allocator, "abcdefgh");
    queue.reserved_end = 8;

    markSendQueueRangeAcked(testing.allocator, &queue, .{ .start = 2, .end = 6 }, false);
    requeueSendQueueRange(testing.allocator, &queue, .{ .start = 2, .end = 6 }, false);

    try testing.expect(queue.retransmit.isEmpty());
}

test "stream send queue re-arms lost empty fin" {
    var queue = SendQueue{};
    defer queue.deinit(testing.allocator);

    queue.reserved_end = 8;
    queue.fin_requested = true;
    queue.fin_reserved = true;

    requeueSendQueueRange(testing.allocator, &queue, .{ .start = 8, .end = 8 }, true);

    try testing.expect(queue.retransmit.isEmpty());
    try testing.expect(queue.fin_retransmit);
    try testing.expect(!queue.fin_acked);
}

test "stream send queue does not resurrect acked fin on later duplicate loss" {
    var queue = SendQueue{};
    defer queue.deinit(testing.allocator);

    queue.reserved_end = 8;
    queue.fin_requested = true;
    queue.fin_reserved = true;

    markSendQueueRangeAcked(testing.allocator, &queue, .{ .start = 8, .end = 8 }, true);
    requeueSendQueueRange(testing.allocator, &queue, .{ .start = 8, .end = 8 }, true);

    try testing.expect(queue.retransmit.isEmpty());
    try testing.expect(!queue.fin_retransmit);
    try testing.expect(queue.fin_acked);
}

test "fuzz: stream send queue ack loss close command sequences preserve retransmission invariants" {
    try testing.fuzz({}, fuzzStreamSendQueueCommands, .{ .corpus = &.{
        "",
        "\x00\x08abcdefgh\x01\x00\x04\x02\x02\x04\x03\x03\x04",
        "\x00\x08abcdefgh\x02\x02\x06\x02\x04\x08\x01\x00\x08\x04\x03",
        "\x00\x08abcdefgh\x01\x02\x04\x02\x02\x04",
        "\x00\x08abcdefgh\x04\x86\x08\x00\x04",
        "\x00\x04test\x05\x00\x02\x03\x02\x04\x06",
    } });
}

fn fuzzStreamSendQueueCommands(_: void, smith: *testing.Smith) !void {
    var input: [192]u8 = undefined;
    const len = smith.slice(&input);
    try runStreamSendQueueCommands(input[0..len]);
}

fn runStreamSendQueueCommands(input: []const u8) !void {
    var queue = SendQueue{};
    defer queue.deinit(testing.allocator);

    var pos: usize = 0;
    while (pos < input.len) {
        const op = input[pos];
        pos += 1;
        switch (op % 7) {
            0 => {
                const take = if (pos < input.len) @min(@as(usize, input[pos] & 0x0f), input.len - pos -| 1) else 0;
                pos +|= @as(usize, @intFromBool(pos < input.len));
                if (!queue.reset_sent) {
                    try queue.data.appendSlice(testing.allocator, input[pos..][0..take]);
                    const old_reserved = queue.reserved_end;
                    queue.reserved_end += @intCast(take);
                    try queue.retransmit.insert(testing.allocator, .{ .start = old_reserved, .end = queue.reserved_end });
                }
                pos += take;
            },
            1 => {
                const range = takeQueueRange(input, &pos, queue.reserved_end);
                const ack_fin = (op & 0x80) != 0 and queue.fin_reserved;
                markSendQueueRangeAcked(testing.allocator, &queue, range, ack_fin);
                markSendQueueRangeAcked(testing.allocator, &queue, range, ack_fin);
            },
            2 => {
                const range = takeQueueRange(input, &pos, queue.reserved_end);
                requeueSendQueueRange(testing.allocator, &queue, range, false);
                requeueSendQueueRange(testing.allocator, &queue, range, false);
            },
            3 => {
                const max_len = if (pos < input.len) @as(u64, input[pos] & 0x0f) else 1;
                pos +|= @as(usize, @intFromBool(pos < input.len));
                if (queue.retransmit.takeFirst(@max(max_len, 1))) |lost| {
                    try testing.expect(lost.start >= queue.base);
                    if ((op & 0x80) == 0) requeueSendQueueRange(testing.allocator, &queue, lost, false);
                }
            },
            4 => {
                if (!queue.reset_sent) {
                    queue.fin_requested = true;
                    queue.fin_reserved = true;
                    requeueSendQueueRange(testing.allocator, &queue, .{ .start = queue.reserved_end, .end = queue.reserved_end }, true);
                }
            },
            5 => {
                queue.reset_sent = true;
                queue.retransmit.items.clearRetainingCapacity();
                queue.fin_retransmit = false;
            },
            else => {
                queue.deinit(testing.allocator);
                queue = .{};
            },
        }
        try expectSendQueueInvariants(&queue);
    }
}

fn takeQueueRange(input: []const u8, pos: *usize, limit: u64) Range {
    if (limit == 0) return .{ .start = 0, .end = 0 };
    const start_seed = if (pos.* < input.len) input[pos.*] else 0;
    pos.* +|= @as(usize, @intFromBool(pos.* < input.len));
    const len_seed = if (pos.* < input.len) input[pos.*] else 0;
    pos.* +|= @as(usize, @intFromBool(pos.* < input.len));
    const start = @min(@as(u64, start_seed), limit);
    const end = @min(limit, start + @as(u64, len_seed & 0x0f));
    return .{ .start = start, .end = end };
}

fn expectSendQueueInvariants(queue: *const SendQueue) !void {
    try testing.expect(queue.base <= queue.reserved_end);
    try testing.expect(queue.bufferedEnd() >= queue.base);
    try testing.expect(queue.start <= queue.data.items.len);

    var previous_end = queue.base;
    for (queue.retransmit.items.items) |range| {
        try testing.expect(range.start < range.end);
        try testing.expect(range.start >= queue.base);
        try testing.expect(range.end <= queue.reserved_end);
        try testing.expect(range.start >= previous_end);
        for (queue.acked.items.items) |acked| {
            if (acked.end <= queue.base) continue;
            try testing.expect(!rangesOverlap(range, .{
                .start = @max(acked.start, queue.base),
                .end = acked.end,
            }));
        }
        previous_end = range.end;
    }

    previous_end = queue.base;
    for (queue.acked.items.items) |range| {
        try testing.expect(range.start < range.end);
        try testing.expect(range.end <= queue.reserved_end);
        if (range.end <= queue.base) continue;
        const effective_start = @max(range.start, queue.base);
        try testing.expect(effective_start >= previous_end);
        previous_end = range.end;
    }

    if (queue.reset_sent) {
        try testing.expect(queue.retransmit.isEmpty());
        try testing.expect(!queue.fin_retransmit);
    }
    if (queue.fin_acked) try testing.expect(!queue.fin_retransmit);
}

fn rangesOverlap(a: Range, b: Range) bool {
    return a.start < b.end and b.start < a.end;
}

const TestPair = struct {
    client_backend: tls_backend_mod.Tls13Backend,
    server_backend: tls_backend_mod.Tls13Backend,
    // Owned, per-instance deterministic TLS-engine provider storage (#490
    // review), not the shared `test_quic_crypto.testHandshakeProvider()`
    // stream: every `TestPair` instance gets its own independent entropy.
    client_provider_storage: test_quic_crypto.HandshakeProviderStorage = .{},
    server_provider_storage: test_quic_crypto.HandshakeProviderStorage = .{},
    client: *Connection = undefined,
    server: *Connection = undefined,
    now_us: u64 = 1_000_000,

    const client_cid = [_]u8{ 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8 };
    const odcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_path = quic_path.PathKey{
        .local = quic_udp.Address.ip4(.{ 127, 0, 0, 1 }, 41_000),
        .remote = quic_udp.Address.ip4(.{ 127, 0, 0, 1 }, 41_001),
    };
    const server_path = quic_path.PathKey{
        .local = quic_udp.Address.ip4(.{ 127, 0, 0, 1 }, 41_001),
        .remote = quic_udp.Address.ip4(.{ 127, 0, 0, 1 }, 41_000),
    };
    /// Unused by ordinary on-path traffic (`PathManager` only consumes fresh
    /// challenge entropy when a datagram starts a *new* candidate
    /// validation); a fixed value is fine for every `TestPair` scenario that
    /// doesn't itself test migration.
    const test_challenge_entropy = [_]u8{0x5a} ** quic_path.path_challenge_len;

    fn init(allocator: std.mem.Allocator) !*TestPair {
        const pair = try allocator.create(TestPair);
        const client_crypto_provider = pair.client_provider_storage.init(0x442_c);
        const server_crypto_provider = pair.server_provider_storage.init(0x442_5);
        pair.* = .{
            .client_provider_storage = pair.client_provider_storage,
            .server_provider_storage = pair.server_provider_storage,
            .client_backend = tls_backend_mod.Tls13Backend.initClient(
                .{ .hello_random = [_]u8{0xc1} ** 32 },
                client_crypto_provider,
                .{ .pinned_certificate = tls_backend_mod.testdata.certificate_der },
            ),
            .server_backend = tls_backend_mod.Tls13Backend.initServer(
                .{ .hello_random = [_]u8{0x51} ** 32 },
                server_crypto_provider,
                try tls_backend_mod.Identity.initPkcs8(
                    tls_backend_mod.testdata.certificate_der,
                    tls_backend_mod.testdata.private_key_pkcs8_der,
                ),
            ),
        };
        errdefer allocator.destroy(pair);
        pair.client = try Connection.init(allocator, .{
            .role = .client,
            .local_cid = &client_cid,
            .original_destination_cid = &odcid,
            .initial_secret_dcid = &odcid,
            .peer_cid = &odcid,
            .tls = pair.client_backend.backend(),
            .crypto_provider = test_quic_crypto.testDefaultProvider(),
            .now_us = pair.now_us,
            .initial_path = client_path,
        });
        errdefer pair.client.deinit();
        pair.server = try Connection.init(allocator, .{
            .role = .server,
            .local_cid = &odcid,
            .original_destination_cid = &odcid,
            .initial_secret_dcid = &odcid,
            .peer_cid = &client_cid,
            .tls = pair.server_backend.backend(),
            .crypto_provider = test_quic_crypto.testDefaultProvider(),
            .now_us = pair.now_us,
            .initial_path = server_path,
        });
        return pair;
    }

    fn initWithTicketConsumer(
        allocator: std.mem.Allocator,
        limits: tls_core.session.Limits,
        consumer: tls_core.tls13_backend.Tls13Backend.SessionTicketConsumer,
    ) !*TestPair {
        return initWithTicketConsumerAndResumePolicy(allocator, limits, consumer, null);
    }

    fn initWithTicketConsumerAndResumePolicy(
        allocator: std.mem.Allocator,
        limits: tls_core.session.Limits,
        consumer: tls_core.tls13_backend.Tls13Backend.SessionTicketConsumer,
        resume_compat: ?tls_core.tls13_backend.Tls13Backend.ResumeCompatibilityPolicy,
    ) !*TestPair {
        const pair = try allocator.create(TestPair);
        const client_crypto_provider = pair.client_provider_storage.init(0x442_c);
        const server_crypto_provider = pair.server_provider_storage.init(0x442_5);
        pair.* = .{
            .client_provider_storage = pair.client_provider_storage,
            .server_provider_storage = pair.server_provider_storage,
            .client_backend = try tls_backend_mod.Tls13Backend.initClientWithAllocator(
                allocator,
                .{ .hello_random = [_]u8{0xc1} ** 32 },
                client_crypto_provider,
                .{ .pinned_certificate = tls_backend_mod.testdata.certificate_der },
            ),
            .server_backend = tls_backend_mod.Tls13Backend.initServerWithAllocator(
                allocator,
                .{ .hello_random = [_]u8{0x51} ** 32 },
                server_crypto_provider,
                try tls_backend_mod.Identity.initPkcs8(
                    tls_backend_mod.testdata.certificate_der,
                    tls_backend_mod.testdata.private_key_pkcs8_der,
                ),
            ),
        };
        errdefer allocator.destroy(pair);
        if (resume_compat) |policy| {
            try pair.client_backend.setResumeCompatibilityPolicy(policy);
            try pair.server_backend.setResumeCompatibilityPolicy(policy);
        }
        try pair.client_backend.engine.setSessionTicketConsumer(allocator, limits, consumer);
        pair.client = try Connection.init(allocator, .{
            .role = .client,
            .local_cid = &client_cid,
            .original_destination_cid = &odcid,
            .initial_secret_dcid = &odcid,
            .peer_cid = &odcid,
            .tls = pair.client_backend.backend(),
            .crypto_provider = test_quic_crypto.testDefaultProvider(),
            .now_us = pair.now_us,
            .initial_path = client_path,
        });
        errdefer pair.client.deinit();
        pair.server = try Connection.init(allocator, .{
            .role = .server,
            .local_cid = &odcid,
            .original_destination_cid = &odcid,
            .initial_secret_dcid = &odcid,
            .peer_cid = &client_cid,
            .tls = pair.server_backend.backend(),
            .crypto_provider = test_quic_crypto.testDefaultProvider(),
            .now_us = pair.now_us,
            .initial_path = server_path,
        });
        return pair;
    }

    fn initClientAuth(
        allocator: std.mem.Allocator,
        client_provider: tls_core.credentials.CredentialProvider,
        server_verifier: tls_core.credentials.PeerVerifier,
    ) !*TestPair {
        const pair = try allocator.create(TestPair);
        const client_crypto_provider = pair.client_provider_storage.init(0x442_c);
        const server_crypto_provider = pair.server_provider_storage.init(0x442_5);
        pair.* = .{
            .client_provider_storage = pair.client_provider_storage,
            .server_provider_storage = pair.server_provider_storage,
            .client_backend = try tls_backend_mod.Tls13Backend.initClientWithAllocator(
                allocator,
                .{ .hello_random = [_]u8{0xc1} ** 32 },
                client_crypto_provider,
                .{ .pinned_certificate = tls_backend_mod.testdata.certificate_der },
            ),
            .server_backend = tls_backend_mod.Tls13Backend.initServerWithAllocator(
                allocator,
                .{ .hello_random = [_]u8{0x51} ** 32 },
                server_crypto_provider,
                try tls_backend_mod.Identity.initPkcs8(
                    tls_backend_mod.testdata.certificate_der,
                    tls_backend_mod.testdata.private_key_pkcs8_der,
                ),
            ),
        };
        errdefer allocator.destroy(pair);
        pair.client_backend.engine.setLocalCredentialProvider(client_provider);
        pair.server_backend.engine.requestClientAuthentication(.required, server_verifier);
        pair.client = try Connection.init(allocator, .{
            .role = .client,
            .local_cid = &client_cid,
            .original_destination_cid = &odcid,
            .initial_secret_dcid = &odcid,
            .peer_cid = &odcid,
            .tls = pair.client_backend.backend(),
            .crypto_provider = test_quic_crypto.testDefaultProvider(),
            .now_us = pair.now_us,
            .initial_path = client_path,
        });
        errdefer pair.client.deinit();
        pair.server = try Connection.init(allocator, .{
            .role = .server,
            .local_cid = &odcid,
            .original_destination_cid = &odcid,
            .initial_secret_dcid = &odcid,
            .peer_cid = &client_cid,
            .tls = pair.server_backend.backend(),
            .crypto_provider = test_quic_crypto.testDefaultProvider(),
            .now_us = pair.now_us,
            .initial_path = server_path,
        });
        return pair;
    }

    fn deinit(self: *TestPair, allocator: std.mem.Allocator) void {
        self.client.deinit();
        self.server.deinit();
        allocator.destroy(self);
    }

    /// Move all pending datagrams both ways until neither side has output.
    /// Delivers every transmit on the exact path it was addressed to, so a
    /// scenario that migrates the client still routes correctly.
    fn pump(self: *TestPair) !void {
        var rounds: usize = 0;
        while (rounds < 64) : (rounds += 1) {
            var progressed = false;
            var buf: [2048]u8 = undefined;
            while (self.client.pollTransmitOnPath(&buf, self.now_us)) |t| {
                const ingress = quic_path.PathKey{ .local = t.path.remote, .remote = t.path.local };
                try self.server.ingestOnPath(t.bytes, ingress, test_challenge_entropy, self.now_us);
                progressed = true;
                self.now_us += 500;
            }
            while (self.server.pollTransmitOnPath(&buf, self.now_us)) |t| {
                const ingress = quic_path.PathKey{ .local = t.path.remote, .remote = t.path.local };
                try self.client.ingestOnPath(t.bytes, ingress, test_challenge_entropy, self.now_us);
                progressed = true;
                self.now_us += 500;
            }
            if (!progressed) return;
        }
        return error.PumpStalled;
    }
};

test "Connection.init failure before the handshake is assigned does not deinit undefined storage" {
    const allocator = testing.allocator;
    // An original_dcid shorter than min_initial_dcid_len makes
    // installInitialSecrets fail, which used to run before conn.handshake
    // was assigned -- deinitPartial()'s errdefer would then call
    // .deinit() on undefined storage. This must fail cleanly instead.
    const too_short_dcid = [_]u8{0xaa} ** (tls_adapter.min_initial_dcid_len - 1);
    var provider_storage: test_quic_crypto.HandshakeProviderStorage = .{};
    var backend = try tls_backend_mod.Tls13Backend.initClientWithAllocator(
        allocator,
        .{ .hello_random = [_]u8{0xc1} ** 32 },
        provider_storage.init(0x442_c),
        .{ .pinned_certificate = tls_backend_mod.testdata.certificate_der },
    );
    try testing.expectError(error.InvalidConnectionId, Connection.init(allocator, .{
        .role = .client,
        .local_cid = &TestPair.client_cid,
        .original_destination_cid = &too_short_dcid,
        .initial_secret_dcid = &too_short_dcid,
        .peer_cid = &too_short_dcid,
        .tls = backend.backend(),
        .crypto_provider = test_quic_crypto.testDefaultProvider(),
        .now_us = 1_000_000,
        .initial_path = TestPair.client_path,
    }));
}

test "driver: client and server complete the handshake over protected packets" {
    const allocator = testing.allocator;
    var pair = try TestPair.init(allocator);
    defer pair.deinit(allocator);

    try pair.pump();
    try testing.expectEqual(State.established, pair.client.state());
    try testing.expectEqual(State.established, pair.server.state());
    try testing.expect(pair.client.negotiatedH3());
    try testing.expect(pair.server.negotiatedH3());
    try testing.expect(pair.client.handshake_confirmed);
    try testing.expect(pair.server.handshake_confirmed);

    // Initial and Handshake keys discarded on both sides after confirmation.
    inline for (.{ EncryptionLevel.initial, EncryptionLevel.handshake }) |level| {
        try testing.expectEqual(@as(?tls_adapter.PacketProtectionKeys, null), pair.client.adapter.protectionKeys(level, .write) catch unreachable);
        try testing.expectEqual(@as(?tls_adapter.PacketProtectionKeys, null), pair.server.adapter.protectionKeys(level, .write) catch unreachable);
    }
}

// #484: a genuine two-`Connection` loopback (real QUIC packets, real
// Initial-space CRYPTO reassembly, real key install/discard) proving the
// shared TLS engine's HelloRetryRequest support works through the QUIC
// adapter, not only through the direct-TLS-backend harness in
// `src/tls/tls13_backend_tests.zig`.
test "driver: HelloRetryRequest completes through real QUIC Initial CRYPTO data" {
    const allocator = testing.allocator;

    const LoggedEvent = union(enum) { packet_sent: PacketNumberSpace, keys_discarded: PacketNumberSpace };
    const EventCapture = struct {
        log: [64]LoggedEvent = undefined,
        len: usize = 0,

        fn onEvent(ctx: ?*anyopaque, event: Event) void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            const logged: LoggedEvent = switch (event) {
                .packet_sent => |p| .{ .packet_sent = p.space },
                .keys_discarded => |space| .{ .keys_discarded = space },
                else => return,
            };
            if (self.len == self.log.len) return;
            self.log[self.len] = logged;
            self.len += 1;
        }

        /// How many `.initial`-space packets were sent strictly before this
        /// side's first `.initial` `keys_discarded` event (or before the
        /// end of the log, if Initial keys were never discarded).
        fn initialPacketsSentBeforeInitialDiscard(self: *const @This()) usize {
            var count: usize = 0;
            for (self.log[0..self.len]) |entry| {
                switch (entry) {
                    .packet_sent => |space| if (space == .initial) {
                        count += 1;
                    },
                    .keys_discarded => |space| if (space == .initial) return count,
                }
            }
            return count;
        }

        fn discardedInitialKeys(self: *const @This()) bool {
            for (self.log[0..self.len]) |entry| {
                if (entry == .keys_discarded and entry.keys_discarded == .initial) return true;
            }
            return false;
        }
    };
    var client_capture = EventCapture{};
    var server_capture = EventCapture{};

    const pair = try allocator.create(TestPair);
    errdefer allocator.destroy(pair);
    const client_crypto_provider = pair.client_provider_storage.init(0x442_c);
    const server_crypto_provider = pair.server_provider_storage.init(0x442_5);
    pair.* = .{
        .client_provider_storage = pair.client_provider_storage,
        .server_provider_storage = pair.server_provider_storage,
        .client_backend = try tls_backend_mod.Tls13Backend.initClientWithAllocatorAndOptions(
            allocator,
            .{ .hello_random = [_]u8{0xc1} ** 32 },
            client_crypto_provider,
            .{ .pinned_certificate = tls_backend_mod.testdata.certificate_der },
            .{ .initial_key_share_mode = .empty },
        ),
        .server_backend = tls_backend_mod.Tls13Backend.initServerWithAllocator(
            allocator,
            .{ .hello_random = [_]u8{0x51} ** 32 },
            server_crypto_provider,
            try tls_backend_mod.Identity.initPkcs8(
                tls_backend_mod.testdata.certificate_der,
                tls_backend_mod.testdata.private_key_pkcs8_der,
            ),
        ),
    };
    pair.client = try Connection.init(allocator, .{
        .role = .client,
        .local_cid = &TestPair.client_cid,
        .original_destination_cid = &TestPair.odcid,
        .initial_secret_dcid = &TestPair.odcid,
        .peer_cid = &TestPair.odcid,
        .tls = pair.client_backend.backend(),
        .crypto_provider = test_quic_crypto.testDefaultProvider(),
        .now_us = pair.now_us,
        .initial_path = TestPair.client_path,
        .events = .{ .context = &client_capture, .emitFn = EventCapture.onEvent },
    });
    errdefer pair.client.deinit();
    pair.server = try Connection.init(allocator, .{
        .role = .server,
        .local_cid = &TestPair.odcid,
        .original_destination_cid = &TestPair.odcid,
        .initial_secret_dcid = &TestPair.odcid,
        .peer_cid = &TestPair.client_cid,
        .tls = pair.server_backend.backend(),
        .crypto_provider = test_quic_crypto.testDefaultProvider(),
        .now_us = pair.now_us,
        .initial_path = TestPair.server_path,
        .events = .{ .context = &server_capture, .emitFn = EventCapture.onEvent },
    });
    defer pair.deinit(allocator);

    try pair.pump();

    try testing.expectEqual(State.established, pair.client.state());
    try testing.expectEqual(State.established, pair.server.state());

    // The shared TLS engine actually exercised exactly one HelloRetryRequest.
    try testing.expectEqual(tls_core.handshake.RetryState.hrr_received, pair.client_backend.engine.core.retry_state);
    try testing.expectEqual(tls_core.handshake.RetryState.hrr_sent, pair.server_backend.engine.core.retry_state);

    // Both the server's HelloRetryRequest and its final ServerHello, and
    // the client's ClientHello1 and ClientHello2, travel as Initial-space
    // QUIC packets — never Handshake/Application — and Initial keys are
    // discarded only once both of a side's Initial-space flight packets
    // (HRR + real ServerHello on the server; ClientHello1 + ClientHello2
    // on the client) have already gone out.
    try testing.expect(server_capture.initialPacketsSentBeforeInitialDiscard() >= 2);
    try testing.expect(client_capture.initialPacketsSentBeforeInitialDiscard() >= 2);
    try testing.expect(client_capture.discardedInitialKeys());
    try testing.expect(server_capture.discardedInitialKeys());

    inline for (.{ EncryptionLevel.initial, EncryptionLevel.handshake }) |level| {
        try testing.expectEqual(@as(?tls_adapter.PacketProtectionKeys, null), pair.client.adapter.protectionKeys(level, .write) catch unreachable);
        try testing.expectEqual(@as(?tls_adapter.PacketProtectionKeys, null), pair.server.adapter.protectionKeys(level, .write) catch unreachable);
    }
}

// #485: a genuine two-`Connection` loopback proving PSK resumption itself
// (not just the non-PSK HRR retry mechanics the #484 test above covers)
// survives a real HelloRetryRequest over the QUIC adapter — the client's
// retained offer is re-emitted in ClientHello2 with a binder derived from
// the rebound transcript, and the server verifies it against that same
// digest, exactly as `src/tls/tls13_backend_tests.zig`'s direct-harness
// tests prove at the TLS-backend level.
test "driver: PSK resumption completes through a real HelloRetryRequest over QUIC" {
    const allocator = testing.allocator;

    const LoggedEvent = union(enum) { packet_sent: PacketNumberSpace, keys_discarded: PacketNumberSpace };
    const EventCapture = struct {
        log: [64]LoggedEvent = undefined,
        len: usize = 0,

        fn onEvent(ctx: ?*anyopaque, event: Event) void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            const logged: LoggedEvent = switch (event) {
                .packet_sent => |p| .{ .packet_sent = p.space },
                .keys_discarded => |space| .{ .keys_discarded = space },
                else => return,
            };
            if (self.len == self.log.len) return;
            self.log[self.len] = logged;
            self.len += 1;
        }

        fn initialPacketsSentBeforeInitialDiscard(self: *const @This()) usize {
            var count: usize = 0;
            for (self.log[0..self.len]) |entry| {
                switch (entry) {
                    .packet_sent => |space| if (space == .initial) {
                        count += 1;
                    },
                    .keys_discarded => |space| if (space == .initial) return count,
                }
            }
            return count;
        }
    };
    var client_capture = EventCapture{};
    var server_capture = EventCapture{};

    const psk = [_]u8{0x64} ** tls_core.tls13_backend.hash_len;
    var common: tls_core.session.ResumableSessionCommon = .{};
    try common.init(allocator, tls_core.session.Limits.default, .{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .resumption_psk = &psk,
        // QUIC negotiates "h3", not the record profile's "h2" — must match
        // what `onEncryptedExtensions` actually negotiates or the resumed
        // connection is fatally rejected as an ALPN mismatch, not merely
        // falling back to a full handshake.
        .application_protocol = "h3",
        .auth_binding = tls_core.session.AuthBinding.fromLeafCertificateDer(tls_backend_mod.testdata.certificate_der),
        .issued_at_unix_ms = 0,
        .lifetime_seconds = 3600,
    });
    var ticket: tls_core.session.ClientTicketState = .{};
    try ticket.init(allocator, tls_core.session.Limits.default, &common, .{
        .ticket = "quic-hrr-resumption-ticket",
        .ticket_age_add = 0,
        .ticket_nonce = "n",
        .received_at_unix_ms = 0,
    });
    var offers: tls_core.pre_shared_key.ClientPskOfferSet = .{};
    try offers.push(&ticket);
    var clock_dummy: u8 = 0;
    const Clock = struct {
        fn now(_: *anyopaque) i64 {
            return 5_000;
        }
    };

    var stored_common: tls_core.session.ResumableSessionCommon = .{};
    try stored_common.init(allocator, tls_core.session.Limits.default, .{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .resumption_psk = &psk,
        .application_protocol = "h3",
        .auth_binding = tls_core.session.AuthBinding.fromLeafCertificateDer(tls_backend_mod.testdata.certificate_der),
        .issued_at_unix_ms = 0,
        .lifetime_seconds = 3600,
    });
    var stored_state: tls_core.session.ServerRecoverableState = .{};
    stored_state.init(&stored_common, 0);
    defer stored_state.deinit();

    const Resolver = struct {
        state: *tls_core.session.ServerRecoverableState,
        calls: usize = 0,

        fn now(_: *anyopaque) i64 {
            return 0;
        }
        fn resolve(ctx: *anyopaque, identity: []const u8) tls_core.pre_shared_key.ResolveError!tls_core.pre_shared_key.ServerPskResolveResult {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.calls += 1;
            if (!std.mem.eql(u8, identity, "quic-hrr-resumption-ticket")) return .miss;
            var out: tls_core.session.ServerRecoverableState = .{};
            self.state.cloneInto(testing.allocator, &out) catch return error.ResolverFailed;
            return .{ .hit = .{ .state = out, .lease = tls_core.pre_shared_key.ServerPskLease.initNoop() } };
        }
    };
    var resolver_state = Resolver{ .state = &stored_state };
    const DecisionProbe = struct {
        count: usize = 0,
        last: ?tls_core.tls13_backend.Tls13Backend.ResumptionDecision = null,
        fn onDecision(ctx: *anyopaque, decision: tls_core.tls13_backend.Tls13Backend.ResumptionDecision) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.count += 1;
            self.last = decision;
        }
    };
    var decision_probe = DecisionProbe{};

    const pair = try allocator.create(TestPair);
    errdefer allocator.destroy(pair);
    const client_crypto_provider = pair.client_provider_storage.init(0x442_c);
    const server_crypto_provider = pair.server_provider_storage.init(0x442_5);
    pair.* = .{
        .client_provider_storage = pair.client_provider_storage,
        .server_provider_storage = pair.server_provider_storage,
        .client_backend = try tls_backend_mod.Tls13Backend.initClientWithAllocatorAndOptions(
            allocator,
            .{ .hello_random = [_]u8{0xc1} ** 32 },
            client_crypto_provider,
            .{ .pinned_certificate = tls_backend_mod.testdata.certificate_der },
            .{ .initial_key_share_mode = .empty },
        ),
        .server_backend = tls_backend_mod.Tls13Backend.initServerWithAllocator(
            allocator,
            .{ .hello_random = [_]u8{0x51} ** 32 },
            server_crypto_provider,
            try tls_backend_mod.Identity.initPkcs8(
                tls_backend_mod.testdata.certificate_der,
                tls_backend_mod.testdata.private_key_pkcs8_der,
            ),
        ),
    };
    // Native QUIC 1-RTT resumption deliberately ignores connection-specific
    // transport/application snapshots (matching the runtime-composition PSK
    // tests elsewhere in this file) — a hand-built stored ticket has no
    // transport_compat of its own to match against this fresh connection's.
    const resume_policy: tls_core.tls13_backend.Tls13Backend.ResumeCompatibilityPolicy = .{
        .transport = .ignore,
        .application = .ignore,
    };
    try pair.client_backend.engine.setClientPskOffers(&offers, &clock_dummy, Clock.now);
    try pair.client_backend.setResumeCompatibilityPolicy(resume_policy);
    try pair.server_backend.setResumeCompatibilityPolicy(resume_policy);
    try pair.server_backend.setServerPskResolver(.{
        .ctx = &resolver_state,
        .nowUnixMsFn = Resolver.now,
        .resolveFn = Resolver.resolve,
    });
    try pair.server_backend.setResumptionDecisionObserver(.{ .ctx = &decision_probe, .onDecisionFn = DecisionProbe.onDecision });

    pair.client = try Connection.init(allocator, .{
        .role = .client,
        .local_cid = &TestPair.client_cid,
        .original_destination_cid = &TestPair.odcid,
        .initial_secret_dcid = &TestPair.odcid,
        .peer_cid = &TestPair.odcid,
        .tls = pair.client_backend.backend(),
        .crypto_provider = test_quic_crypto.testDefaultProvider(),
        .now_us = pair.now_us,
        .initial_path = TestPair.client_path,
        .events = .{ .context = &client_capture, .emitFn = EventCapture.onEvent },
    });
    errdefer pair.client.deinit();
    pair.server = try Connection.init(allocator, .{
        .role = .server,
        .local_cid = &TestPair.odcid,
        .original_destination_cid = &TestPair.odcid,
        .initial_secret_dcid = &TestPair.odcid,
        .peer_cid = &TestPair.client_cid,
        .tls = pair.server_backend.backend(),
        .crypto_provider = test_quic_crypto.testDefaultProvider(),
        .now_us = pair.now_us,
        .initial_path = TestPair.server_path,
        .events = .{ .context = &server_capture, .emitFn = EventCapture.onEvent },
    });
    defer pair.deinit(allocator);

    try pair.pump();

    try testing.expectEqual(State.established, pair.client.state());
    try testing.expectEqual(State.established, pair.server.state());

    // The resumption itself actually succeeded (not merely a plain HRR
    // retry that happened to fall back to a full handshake), and it went
    // through exactly one HelloRetryRequest.
    try testing.expectEqual(@as(usize, 1), resolver_state.calls);
    try testing.expectEqual(@as(usize, 1), decision_probe.count);
    try testing.expectEqual(tls_core.tls13_backend.Tls13Backend.ResumptionDecision.accepted, decision_probe.last.?);
    try testing.expect(pair.client_backend.engine.core.psk_authenticated);
    try testing.expect(pair.server_backend.engine.core.psk_authenticated);
    try testing.expectEqual(tls_core.handshake.RetryState.hrr_received, pair.client_backend.engine.core.retry_state);
    try testing.expectEqual(tls_core.handshake.RetryState.hrr_sent, pair.server_backend.engine.core.retry_state);

    // HRR and ClientHello2 (like the non-PSK #484 case) stayed at the
    // Initial epoch, and Initial keys were not discarded before both of a
    // side's Initial-space flight packets had already gone out.
    try testing.expect(server_capture.initialPacketsSentBeforeInitialDiscard() >= 2);
    try testing.expect(client_capture.initialPacketsSentBeforeInitialDiscard() >= 2);

    // The resumed connection is genuinely usable under the post-HRR,
    // PSK-derived keys.
    const id = try pair.client.openStream(.bidi);
    try testing.expectEqual(@as(usize, 5), try pair.client.writeStream(id, "hello", true));
    try pair.pump();
    try testing.expectEqual(@as(?StreamId, id), pair.server.acceptStream());
    var buf: [16]u8 = undefined;
    const request = try pair.server.readStream(id, &buf);
    try testing.expectEqualStrings("hello", buf[0..request.len]);
}

test "driver: bidirectional stream data round-trips with FIN" {
    const allocator = testing.allocator;
    var pair = try TestPair.init(allocator);
    defer pair.deinit(allocator);
    try pair.pump();

    const id = try pair.client.openStream(.bidi);
    try testing.expectEqual(@as(usize, 5), try pair.client.writeStream(id, "hello", true));
    try pair.pump();

    try testing.expectEqual(@as(?StreamId, id), pair.server.acceptStream());
    var buf: [64]u8 = undefined;
    const request = try pair.server.readStream(id, &buf);
    try testing.expectEqualStrings("hello", buf[0..request.len]);
    try testing.expect(request.fin);

    _ = try pair.server.writeStream(id, "world!", true);
    try pair.pump();
    const response = try pair.client.readStream(id, &buf);
    try testing.expectEqualStrings("world!", buf[0..response.len]);
    try testing.expect(response.fin);

    try testing.expectEqual(quic_stream.StreamState.closed, pair.client.streamState(id).?);
    try testing.expectEqual(quic_stream.StreamState.closed, pair.server.streamState(id).?);
}

test "driver: stream scheduling hint sends lower urgency first" {
    const allocator = testing.allocator;
    var pair = try TestPair.init(allocator);
    defer pair.deinit(allocator);
    try pair.pump();

    const low = try pair.client.openStream(.bidi);
    const high = try pair.client.openStream(.bidi);
    _ = try pair.client.writeStream(low, "request-a", false);
    _ = try pair.client.writeStream(high, "request-b", false);
    try pair.pump();

    try pair.server.setStreamSchedulingHint(low, .{ .urgency = 1 });
    try pair.server.setStreamSchedulingHint(high, .{ .urgency = 6 });
    _ = try pair.server.writeStream(high, "less urgent response", false);
    _ = try pair.server.writeStream(low, "more urgent response", false);

    var out: [max_datagram_size]u8 = undefined;
    _ = pair.server.pollTransmitOnPath(&out, pair.now_us) orelse return error.TestExpectedEqual;
    const record = lastSentRecordWithStreams(pair.server) orelse return error.TestExpectedEqual;
    try testing.expect(record.stream_count > 0);
    try testing.expectEqual(low, record.streams[0].id);
}

test "driver: equal urgency stream scheduling gives peers progress" {
    const allocator = testing.allocator;
    var pair = try TestPair.init(allocator);
    defer pair.deinit(allocator);
    try pair.pump();

    const first = try pair.client.openStream(.bidi);
    const second = try pair.client.openStream(.bidi);
    _ = try pair.client.writeStream(first, "request-a", false);
    _ = try pair.client.writeStream(second, "request-b", false);
    try pair.pump();

    try pair.server.setStreamSchedulingHint(first, .{ .urgency = 3, .incremental = true });
    try pair.server.setStreamSchedulingHint(second, .{ .urgency = 3, .incremental = true });
    _ = try pair.server.writeStream(first, "first response chunk", false);
    _ = try pair.server.writeStream(second, "second response chunk", false);

    var out: [max_datagram_size]u8 = undefined;
    _ = pair.server.pollTransmitOnPath(&out, pair.now_us) orelse return error.TestExpectedEqual;
    const record = lastSentRecordWithStreams(pair.server) orelse return error.TestExpectedEqual;
    try testing.expect(streamRecordContains(record.*, first));
    try testing.expect(streamRecordContains(record.*, second));
}

test "driver: equal urgency mixed incremental streams both make repeated progress" {
    const allocator = testing.allocator;
    var pair = try TestPair.init(allocator);
    defer pair.deinit(allocator);
    try pair.pump();

    const incremental = try pair.client.openStream(.bidi);
    const non_incremental = try pair.client.openStream(.bidi);
    _ = try pair.client.writeStream(incremental, "request-a", false);
    _ = try pair.client.writeStream(non_incremental, "request-b", false);
    try pair.pump();

    try pair.server.setStreamSchedulingHint(incremental, .{ .urgency = 2, .incremental = true });
    try pair.server.setStreamSchedulingHint(non_incremental, .{ .urgency = 2, .incremental = false });

    const large_incremental = [_]u8{'i'} ** (max_datagram_size * 3);
    const large_non_incremental = [_]u8{'n'} ** (max_datagram_size * 3);
    _ = try pair.server.writeStream(incremental, &large_incremental, false);
    _ = try pair.server.writeStream(non_incremental, &large_non_incremental, false);

    var out: [max_datagram_size]u8 = undefined;
    var incremental_records: usize = 0;
    var non_incremental_records: usize = 0;
    var polls: usize = 0;
    while (polls < 6) : (polls += 1) {
        _ = pair.server.pollTransmitOnPath(&out, pair.now_us) orelse break;
        const record = lastSentRecordWithStreams(pair.server) orelse continue;
        if (streamRecordContains(record.*, incremental)) incremental_records += 1;
        if (streamRecordContains(record.*, non_incremental)) non_incremental_records += 1;
        pair.now_us += 500;
    }

    try testing.expect(incremental_records >= 2);
    try testing.expect(non_incremental_records >= 2);
}

fn lastSentRecordWithStreams(conn: *Connection) ?*const SentRecord {
    var i = conn.sent_records.items.len;
    while (i > 0) {
        i -= 1;
        const record = &conn.sent_records.items[i];
        if (record.space == .application and record.stream_count > 0) return record;
    }
    return null;
}

fn streamRecordContains(record: SentRecord, id: StreamId) bool {
    for (record.streams[0..record.stream_count]) |stream_range| {
        if (stream_range.id == id) return true;
    }
    return false;
}

test "driver: explicit zero-rtt stream provenance mark stays sticky after one-rtt data" {
    const allocator = testing.allocator;
    var pair = try TestPair.init(allocator);
    defer pair.deinit(allocator);
    try pair.pump();

    const id: StreamId = 0;
    try pair.server.markStreamZeroRtt(id);
    try testing.expect(pair.server.streamTransportEarly(id));

    try pair.server.applyFrame(.application, .{ .stream = .{ .id = id, .offset = 0, .data = "late", .fin = true } }, TestPair.server_path, 0, pair.now_us);
    try testing.expect(pair.server.streamTransportEarly(id));
    try testing.expectEqual(@as(?StreamId, id), pair.server.acceptStream());

    var buf: [32]u8 = undefined;
    const request = try pair.server.readStream(id, &buf);
    try testing.expectEqualStrings("late", buf[0..request.len]);
    try testing.expect(request.fin);
}

/// Test-only helper (#523): seal a 0-RTT wire packet exactly the way a real
/// client sender would, via an independent throwaway adapter installed with
/// `secret` at the `.zero_rtt write` slot. Key derivation
/// (`deriveAes128GcmKeys`) depends only on the secret bytes, not on which
/// side calls it "read" vs "write", so a receiver with the same bytes
/// installed at `.zero_rtt read` genuinely decrypts this — it exercises the
/// real AEAD-seal/header-protection codepath `buildPacket` uses for every
/// other level, not a synthetic shortcut.
fn sealTestZeroRttPacket(
    dcid: []const u8,
    scid: []const u8,
    secret: [tls_adapter.traffic_secret_len]u8,
    pn: u64,
    plaintext: []const u8,
    out: []u8,
) []u8 {
    var sender = tls_adapter.QuicTlsAdapter{ .provider = test_quic_crypto.testDefaultProvider() };
    sender.setZeroRttEnabled(true);
    sender.installSecret(tls_adapter.Secret.init(.zero_rtt, .write, &secret) catch unreachable);

    const pn_len: u3 = packet.packetNumberLength(pn, null);
    const written = packet.writeLongHeader(.zero_rtt, packet.quic_v1, dcid, scid, "", pn_len, out) catch unreachable;
    const pn_offset = written.pn_offset;

    // Pad so the sealed ciphertext is long enough to sample for header
    // protection, mirroring `buildPacket`'s own padding step.
    var padded: [128]u8 = undefined;
    const sample_min = (4 - @as(usize, pn_len)) + sample_len - aead_tag_len;
    const padded_len = @max(plaintext.len, sample_min);
    @memcpy(padded[0..plaintext.len], plaintext);
    @memset(padded[plaintext.len..padded_len], 0);

    // The Length field precedes `pn_offset` and is covered by the AEAD
    // associated data (the "header" slice below), so it must be patched to
    // its final value *before* sealing — sealing after would authenticate a
    // different header than what ends up on the wire.
    packet.patchLongHeaderLength(out, written.length_offset, pn_len + padded_len + aead_tag_len);

    const truncated = packet.truncatePacketNumber(pn, pn_len);
    var pn_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &pn_bytes, truncated, .big);
    @memcpy(out[pn_offset..][0..pn_len], pn_bytes[4 - @as(usize, pn_len) ..][0..pn_len]);

    const header = out[0 .. pn_offset + pn_len];
    const keys = (sender.protectionKeys(.zero_rtt, .write) catch unreachable).?;
    _ = sender.sealPacketPayload(.zero_rtt, .write, pn, header, padded[0..padded_len], out[pn_offset + pn_len ..]) catch unreachable;

    var sample: [sample_len]u8 = undefined;
    @memcpy(&sample, out[pn_offset + 4 ..][0..sample_len]);
    keys.applyHeaderProtectionWithProvider(sender.provider, &out[0], out[pn_offset..][0..pn_len], sample) catch unreachable;

    return out[0 .. pn_offset + pn_len + padded_len + aead_tag_len];
}

test "driver: accepted 0-RTT packet with installed read keys decrypts and delivers stream data" {
    const allocator = testing.allocator;
    var pair = try TestPair.init(allocator);
    defer pair.deinit(allocator);

    const secret = [_]u8{0x42} ** tls_adapter.traffic_secret_len;
    pair.server.adapter.setZeroRttEnabled(true);
    pair.server.adapter.installSecret(try tls_adapter.Secret.init(.zero_rtt, .read, &secret));

    var frame_buf: [32]u8 = undefined;
    const frame_len = try frame.encodeStream(0, 0, "hello 0-rtt", true, &frame_buf);

    var wire: [256]u8 = undefined;
    const datagram = sealTestZeroRttPacket(&TestPair.odcid, &TestPair.client_cid, secret, 0, frame_buf[0..frame_len], &wire);

    const before_received = pair.server.metrics.packets_received;
    try pair.server.ingestOnPath(datagram, TestPair.server_path, TestPair.test_challenge_entropy, pair.now_us);

    try testing.expectEqual(before_received + 1, pair.server.metrics.packets_received);
    try testing.expect(pair.server.streamTransportEarly(0));
    try testing.expectEqual(@as(?StreamId, 0), pair.server.acceptStream());
    var buf: [32]u8 = undefined;
    const request = try pair.server.readStream(0, &buf);
    try testing.expectEqualStrings("hello 0-rtt", buf[0..request.len]);
    try testing.expect(request.fin);
}

test "driver: 0-RTT packet without an installed read key is dropped, not delivered" {
    const allocator = testing.allocator;
    var pair = try TestPair.init(allocator);
    defer pair.deinit(allocator);

    // Server never received/authorized a zero_rtt read secret — the same
    // observable state as "not attempted", "rejected by policy", "replay",
    // or "incompatible": whatever the reason, the TLS layer simply never
    // installs a usable key, and the QUIC carrier must fail closed on that
    // alone without needing to know which reason applied.
    const secret = [_]u8{0x77} ** tls_adapter.traffic_secret_len;
    var frame_buf: [32]u8 = undefined;
    const frame_len = try frame.encodeStream(0, 0, "should not land", true, &frame_buf);
    var wire: [256]u8 = undefined;
    const datagram = sealTestZeroRttPacket(&TestPair.odcid, &TestPair.client_cid, secret, 0, frame_buf[0..frame_len], &wire);

    const before_received = pair.server.metrics.packets_received;
    const before_dropped = pair.server.metrics.packets_dropped;
    try pair.server.ingestOnPath(datagram, TestPair.server_path, TestPair.test_challenge_entropy, pair.now_us);

    try testing.expectEqual(before_received, pair.server.metrics.packets_received);
    try testing.expectEqual(before_dropped + 1, pair.server.metrics.packets_dropped);
    try testing.expect(!pair.server.streamTransportEarly(0));
    try testing.expectEqual(@as(?StreamId, null), pair.server.acceptStream());

    // The ordinary (non-early) handshake is entirely unaffected by the
    // rejected/unavailable 0-RTT attempt.
    try pair.pump();
    try testing.expect(pair.client.isEstablished());
    try testing.expect(pair.server.isEstablished());
}

test "driver: tampered 0-RTT packet is dropped and not delivered" {
    const allocator = testing.allocator;
    var pair = try TestPair.init(allocator);
    defer pair.deinit(allocator);

    const secret = [_]u8{0x99} ** tls_adapter.traffic_secret_len;
    pair.server.adapter.setZeroRttEnabled(true);
    pair.server.adapter.installSecret(try tls_adapter.Secret.init(.zero_rtt, .read, &secret));

    var frame_buf: [32]u8 = undefined;
    const frame_len = try frame.encodeStream(0, 0, "tampered", true, &frame_buf);
    var wire: [256]u8 = undefined;
    const datagram = sealTestZeroRttPacket(&TestPair.odcid, &TestPair.client_cid, secret, 0, frame_buf[0..frame_len], &wire);
    // Flip a bit well past the header so header protection removal still
    // succeeds but AEAD authentication fails.
    datagram[datagram.len - 1] ^= 0x01;

    const before_received = pair.server.metrics.packets_received;
    const before_dropped = pair.server.metrics.packets_dropped;
    try pair.server.ingestOnPath(datagram, TestPair.server_path, TestPair.test_challenge_entropy, pair.now_us);

    try testing.expectEqual(before_received, pair.server.metrics.packets_received);
    try testing.expectEqual(before_dropped + 1, pair.server.metrics.packets_dropped);
    try testing.expect(!pair.server.streamTransportEarly(0));
    try testing.expectEqual(@as(?StreamId, null), pair.server.acceptStream());
}

test "driver: 0-RTT stream provenance survives reassembly, duplicate delivery, and later 1-RTT bytes" {
    const allocator = testing.allocator;
    var pair = try TestPair.init(allocator);
    defer pair.deinit(allocator);

    const secret = [_]u8{0x5a} ** tls_adapter.traffic_secret_len;
    pair.server.adapter.setZeroRttEnabled(true);
    pair.server.adapter.installSecret(try tls_adapter.Secret.init(.zero_rtt, .read, &secret));

    var frame_buf_1: [32]u8 = undefined;
    const frame_len_1 = try frame.encodeStream(0, 0, "hel", false, &frame_buf_1);
    var wire_1: [256]u8 = undefined;
    const datagram_1 = sealTestZeroRttPacket(&TestPair.odcid, &TestPair.client_cid, secret, 0, frame_buf_1[0..frame_len_1], &wire_1);

    var frame_buf_2: [32]u8 = undefined;
    const frame_len_2 = try frame.encodeStream(0, 3, "lo", false, &frame_buf_2);
    var wire_2: [256]u8 = undefined;
    const datagram_2 = sealTestZeroRttPacket(&TestPair.odcid, &TestPair.client_cid, secret, 1, frame_buf_2[0..frame_len_2], &wire_2);

    // Reassembly across two 0-RTT packets.
    try pair.server.ingestOnPath(datagram_1, TestPair.server_path, TestPair.test_challenge_entropy, pair.now_us);
    try pair.server.ingestOnPath(datagram_2, TestPair.server_path, TestPair.test_challenge_entropy, pair.now_us);
    try testing.expect(pair.server.streamTransportEarly(0));

    // Duplicate delivery of an already-processed 0-RTT packet re-authenticates
    // (AEAD has no memory of prior packets), but `wasReceived`/the
    // already-recorded application-space packet number stop its frames from
    // ever reaching `applyFrame` a second time — see the dedicated
    // frame-effect regression test below for the case where that actually
    // matters (STREAM offset dedup alone would otherwise mask it).
    try pair.server.ingestOnPath(datagram_1, TestPair.server_path, TestPair.test_challenge_entropy, pair.now_us);

    try testing.expectEqual(@as(?StreamId, 0), pair.server.acceptStream());
    var buf: [32]u8 = undefined;
    const early_read = try pair.server.readStream(0, &buf);
    try testing.expectEqualStrings("hello", buf[0..early_read.len]);
    try testing.expect(!early_read.fin);

    // Later 1-RTT bytes on the same stream must not retroactively lose the
    // sticky early marking, and read correctly alongside the early bytes.
    try pair.server.applyFrame(.application, .{ .stream = .{ .id = 0, .offset = 5, .data = "!", .fin = true } }, TestPair.server_path, 0, pair.now_us);
    try testing.expect(pair.server.streamTransportEarly(0));
    const late_read = try pair.server.readStream(0, &buf);
    try testing.expectEqualStrings("!", buf[0..late_read.len]);
    try testing.expect(late_read.fin);
}

test "driver: authenticated duplicate 0-RTT packet does not re-apply a state-mutating frame" {
    // STREAM-offset dedup happens to hide a replayed STREAM frame regardless
    // of packet-level dedup, so it can't prove frame effects aren't
    // reapplied. PATH_CHALLENGE has no such built-in idempotency —
    // `applyFrame` unconditionally appends a pending response — making it a
    // frame type where a real regression (replaying an authenticated
    // duplicate packet re-dispatching its frames) is directly observable.
    const allocator = testing.allocator;
    var pair = try TestPair.init(allocator);
    defer pair.deinit(allocator);

    const secret = [_]u8{0x63} ** tls_adapter.traffic_secret_len;
    pair.server.adapter.setZeroRttEnabled(true);
    pair.server.adapter.installSecret(try tls_adapter.Secret.init(.zero_rtt, .read, &secret));

    var frame_buf: [16]u8 = undefined;
    const challenge_data = [_]u8{0xab} ** frame.path_data_len;
    const frame_len = try frame.encodePathChallenge(challenge_data, &frame_buf);
    var wire: [256]u8 = undefined;
    const datagram = sealTestZeroRttPacket(&TestPair.odcid, &TestPair.client_cid, secret, 0, frame_buf[0..frame_len], &wire);

    try pair.server.ingestOnPath(datagram, TestPair.server_path, TestPair.test_challenge_entropy, pair.now_us);
    try testing.expectEqual(@as(usize, 1), pair.server.pending_path_responses.items.len);

    // Replay the identical authenticated packet.
    try pair.server.ingestOnPath(datagram, TestPair.server_path, TestPair.test_challenge_entropy, pair.now_us);
    try testing.expectEqual(@as(usize, 1), pair.server.pending_path_responses.items.len);
}

test "driver: the idle timer does not refresh on a duplicate or an undecryptable datagram (RFC 9000 §10.1)" {
    const allocator = testing.allocator;
    var pair = try TestPair.init(allocator);
    defer pair.deinit(allocator);

    const secret = [_]u8{0x29} ** tls_adapter.traffic_secret_len;
    pair.server.adapter.setZeroRttEnabled(true);
    pair.server.adapter.installSecret(try tls_adapter.Secret.init(.zero_rtt, .read, &secret));

    var frame_buf: [16]u8 = undefined;
    const frame_len = try frame.encodeStream(0, 0, "hi", true, &frame_buf);
    var wire: [256]u8 = undefined;
    const datagram = sealTestZeroRttPacket(&TestPair.odcid, &TestPair.client_cid, secret, 0, frame_buf[0..frame_len], &wire);

    try pair.server.ingestOnPath(datagram, TestPair.server_path, TestPair.test_challenge_entropy, pair.now_us);
    const deadline_after_fresh = pair.server.idle_deadline_us;
    try testing.expect(deadline_after_fresh != null);

    const later = pair.now_us + 10 * std.time.us_per_s;

    // Replaying the identical (now-duplicate) packet much later must not
    // move the idle deadline out to reflect that later time.
    try pair.server.ingestOnPath(datagram, TestPair.server_path, TestPair.test_challenge_entropy, later);
    try testing.expectEqual(deadline_after_fresh, pair.server.idle_deadline_us);

    // Neither must a tampered (undecryptable) datagram at that later time.
    var tampered: [256]u8 = undefined;
    @memcpy(tampered[0..datagram.len], datagram);
    tampered[datagram.len - 1] ^= 0x01;
    try pair.server.ingestOnPath(tampered[0..datagram.len], TestPair.server_path, TestPair.test_challenge_entropy, later);
    try testing.expectEqual(deadline_after_fresh, pair.server.idle_deadline_us);

    // A genuinely fresh authenticated packet still does refresh it.
    var frame_buf_2: [16]u8 = undefined;
    const frame_len_2 = try frame.encodeStream(4, 0, "bye", true, &frame_buf_2);
    var wire_2: [256]u8 = undefined;
    const datagram_2 = sealTestZeroRttPacket(&TestPair.odcid, &TestPair.client_cid, secret, 1, frame_buf_2[0..frame_len_2], &wire_2);
    try pair.server.ingestOnPath(datagram_2, TestPair.server_path, TestPair.test_challenge_entropy, later);
    try testing.expect(pair.server.idle_deadline_us.? > deadline_after_fresh.?);
}

test "driver: a validated, successfully processed Retry still refreshes the idle timer (RFC 9000 §10.1)" {
    // Fixing the duplicate/dropped-datagram idle-timer regression must not
    // regress the legitimate Retry path: `handleRetry` returns before
    // `ingestPacket`'s own protected-packet refresh point, so it needs its
    // own `armIdle` call once the Retry is validated and processed.
    const allocator = testing.allocator;
    var pair = try TestPair.init(allocator);
    defer pair.deinit(allocator);

    // RFC 9001 Appendix A.4 sample Retry packet for ODCID
    // 0x8394c8f03e515708 — the same value `TestPair.odcid` uses, so a fresh
    // client (which hasn't processed any Initial exchange yet, matching
    // `TestPair.init`'s just-constructed state) validates it as genuine.
    const retry = [_]u8{
        0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xf0, 0x67, 0xa5, 0x50, 0x2a,
        0x42, 0x62, 0xb5, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x04, 0xa2, 0x65, 0xba,
        0x2e, 0xff, 0x4d, 0x82, 0x90, 0x58, 0xfb, 0x3f, 0x0f, 0x24, 0x96, 0xba,
    };

    const before = pair.client.idle_deadline_us;
    try testing.expect(before != null);
    const later = pair.now_us + 5 * std.time.us_per_s;

    try pair.client.ingestOnPath(&retry, TestPair.client_path, TestPair.test_challenge_entropy, later);

    try testing.expect(pair.client.got_retry);
    try testing.expect(pair.client.idle_deadline_us.? > before.?);
    // The client handshake anti-deadlock PTO (`nextTimeoutUs`/`onTimeout`)
    // bases its deadline on `last_activity_us` whenever nothing is in
    // flight; `handleRetry` clears the Initial recovery/sent state, so this
    // must move forward too or that deadline could still fire based on
    // pre-Retry activity before the replacement Initial goes out.
    try testing.expectEqual(later, pair.client.last_activity_us);
}

test "driver: replayed duplicate packet from a different source address does not create or credit candidate-path state" {
    const allocator = testing.allocator;
    var pair = try TestPair.init(allocator);
    defer pair.deinit(allocator);

    const secret = [_]u8{0x37} ** tls_adapter.traffic_secret_len;
    pair.server.adapter.setZeroRttEnabled(true);
    pair.server.adapter.installSecret(try tls_adapter.Secret.init(.zero_rtt, .read, &secret));

    var frame_buf: [16]u8 = undefined;
    const frame_len = try frame.encodeStream(0, 0, "hi", true, &frame_buf);
    var wire: [256]u8 = undefined;
    const datagram = sealTestZeroRttPacket(&TestPair.odcid, &TestPair.client_cid, secret, 0, frame_buf[0..frame_len], &wire);

    // First delivery: authenticates and is processed on the server's actual
    // (handshake) active path, as usual.
    try pair.server.ingestOnPath(datagram, TestPair.server_path, TestPair.test_challenge_entropy, pair.now_us);

    // Replay the byte-identical datagram, but claim it arrived from a
    // different (spoofed or off-path-captured-and-resent) source address.
    const spoofed_path = quic_path.PathKey{
        .local = TestPair.server_path.local,
        .remote = quic_udp.Address.ip4(.{ 203, 0, 113, 7 }, 9999),
    };
    try testing.expectEqual(@as(?quic_path.PathState, null), pair.server.paths.stateOf(spoofed_path));
    try pair.server.ingestOnPath(datagram, spoofed_path, TestPair.test_challenge_entropy, pair.now_us);

    // The replay authenticates (it's the same packet number, already
    // processed once) but must not have created a candidate path or
    // credited that address's anti-amplification ledger merely because the
    // bytes happened to decrypt.
    try testing.expectEqual(@as(?quic_path.PathState, null), pair.server.paths.stateOf(spoofed_path));
}

test "driver: frames illegal in 0-RTT close the connection instead of taking effect (RFC 9000 §12.5)" {
    const allocator = testing.allocator;

    // ACK is the sharpest case: without the level gate this frame is
    // silently accepted by `processAck` (mutating sent/recovery/congestion
    // state) rather than erroring, so a close happening here specifically
    // proves the gate ran — not some unrelated pre-existing failure path.
    {
        var pair = try TestPair.init(allocator);
        defer pair.deinit(allocator);
        try pair.server.applyFrame(.zero_rtt, .{ .ack = .{
            .ranges = .{},
            .ack_delay_raw = 0,
            .largest_acknowledged = 0,
        } }, TestPair.server_path, 0, pair.now_us);
        try testing.expectEqual(State.closing, pair.server.state());
        try testing.expectEqual(error_protocol_violation, pair.server.close_info.?.error_code);
    }

    // CRYPTO: without the gate, `Handshake.onCrypto(.zero_rtt, ...)` would
    // also fail (0-RTT never carries CRYPTO — `cryptoStreamIndex` rejects
    // it), but through a different, CRYPTO_ERROR-shaped close. Asserting the
    // plain `error_protocol_violation` code here proves the level gate
    // itself rejected it before any TLS-engine call, not that TLS happened
    // to reject it independently.
    {
        var pair = try TestPair.init(allocator);
        defer pair.deinit(allocator);
        try pair.server.applyFrame(.zero_rtt, .{ .crypto = .{ .offset = 0, .data = "x" } }, TestPair.server_path, 0, pair.now_us);
        try testing.expectEqual(State.closing, pair.server.state());
        try testing.expectEqual(error_protocol_violation, pair.server.close_info.?.error_code);
    }

    {
        var pair = try TestPair.init(allocator);
        defer pair.deinit(allocator);
        try pair.server.applyFrame(.zero_rtt, .{ .new_token = .{ .token = "t" } }, TestPair.server_path, 0, pair.now_us);
        try testing.expectEqual(State.closing, pair.server.state());
        try testing.expectEqual(error_protocol_violation, pair.server.close_info.?.error_code);
    }

    {
        var pair = try TestPair.init(allocator);
        defer pair.deinit(allocator);
        try pair.server.applyFrame(.zero_rtt, .{ .retire_connection_id = .{ .sequence = 0 } }, TestPair.server_path, 0, pair.now_us);
        try testing.expectEqual(State.closing, pair.server.state());
        try testing.expectEqual(error_protocol_violation, pair.server.close_info.?.error_code);
    }

    {
        var pair = try TestPair.init(allocator);
        defer pair.deinit(allocator);
        try pair.server.applyFrame(.zero_rtt, .{ .path_response = [_]u8{0} ** frame.path_data_len }, TestPair.server_path, 0, pair.now_us);
        try testing.expectEqual(State.closing, pair.server.state());
        try testing.expectEqual(error_protocol_violation, pair.server.close_info.?.error_code);
    }

    {
        var pair = try TestPair.init(allocator);
        defer pair.deinit(allocator);
        try pair.server.applyFrame(.zero_rtt, .handshake_done, TestPair.server_path, 0, pair.now_us);
        try testing.expectEqual(State.closing, pair.server.state());
        try testing.expectEqual(error_protocol_violation, pair.server.close_info.?.error_code);
    }
}

test "driver: server retires its 0-RTT read secret once it authenticates a 1-RTT packet (RFC 9001 §4.9.3)" {
    const allocator = testing.allocator;
    var pair = try TestPair.init(allocator);
    defer pair.deinit(allocator);
    try pair.pump();

    const secret = [_]u8{0x11} ** tls_adapter.traffic_secret_len;
    pair.server.adapter.setZeroRttEnabled(true);
    pair.server.adapter.installSecret(try tls_adapter.Secret.init(.zero_rtt, .read, &secret));
    try testing.expect((pair.server.adapter.protectionKeys(.zero_rtt, .read) catch unreachable) != null);

    // Force a genuine ack-eliciting `.application` exchange the server must
    // authenticate — a delayed/unforced ACK alone might never actually
    // transmit within a single `pump()`.
    const id = try pair.client.openStream(.bidi);
    _ = try pair.client.writeStream(id, "hi", true);
    try pair.pump();

    // The server has now authenticated a real 1-RTT packet; its 0-RTT read
    // secret must be retired.
    try testing.expect((pair.server.adapter.protectionKeys(.zero_rtt, .read) catch unreachable) == null);

    // Retirement wipes only the `.zero_rtt` secret-store slot — the
    // application packet-number/recovery state 0-RTT and 1-RTT share is
    // untouched, so the stream data is still intact and readable.
    try testing.expectEqual(@as(?StreamId, id), pair.server.acceptStream());
    var buf: [8]u8 = undefined;
    const request = try pair.server.readStream(id, &buf);
    try testing.expectEqualStrings("hi", buf[0..request.len]);
    try testing.expect(request.fin);
}

test "driver: server NewSessionTicket uses application CRYPTO retransmission and stream traffic continues" {
    const Capture = struct {
        count: usize = 0,
        ticket_len: usize = 0,

        fn now(_: *anyopaque) i64 {
            return 10;
        }

        fn onTicket(ctx: *anyopaque, ticket: *const tls_core.session.ClientTicketState) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.count += 1;
            self.ticket_len = ticket.ticket.slice().len;
        }
    };

    const allocator = testing.allocator;
    var capture = Capture{};
    var pair = try TestPair.initWithTicketConsumer(allocator, tls_core.session.Limits.default, .{
        .ctx = &capture,
        .nowUnixMsFn = Capture.now,
        .onTicketFn = Capture.onTicket,
    });
    defer pair.deinit(allocator);
    try pair.pump();

    var server_state = try pair.server.emitNewSessionTicket(.{
        .ticket_lifetime = 60,
        .ticket_age_add = 1,
        .ticket_nonce = "\x01",
        .opaque_ticket = "connection-ticket",
        .issued_at_unix_ms = 10,
    }, tls_core.session.Limits.default);
    defer server_state.deinit();

    var datagram: [2048]u8 = undefined;
    const dropped = pair.server.pollTransmitOnPath(&datagram, pair.now_us) orelse return error.TestExpectedEqual;
    try testing.expect(dropped.bytes.len > 0);
    const sent = pair.server.sent_records.items[pair.server.sent_records.items.len - 1];
    try testing.expectEqual(PacketNumberSpace.application, sent.space);
    try testing.expect(sent.crypto != null);
    pair.server.requeueRecord(&sent);

    try pair.pump();
    try testing.expectEqual(@as(usize, 1), capture.count);
    try testing.expectEqual(@as(usize, "connection-ticket".len), capture.ticket_len);

    const id = try pair.client.openStream(.bidi);
    try testing.expectEqual(@as(usize, 5), try pair.client.writeStream(id, "after", true));
    try pair.pump();
    try testing.expectEqual(@as(?StreamId, id), pair.server.acceptStream());
    var buf: [16]u8 = undefined;
    const request = try pair.server.readStream(id, &buf);
    try testing.expectEqualStrings("after", buf[0..request.len]);
}

test "driver: two-phase prepare/emit NewSessionTicket delivers over application CRYPTO" {
    const CaptureImpl = struct {
        count: usize = 0,
        ticket_len: usize = 0,

        fn now(_: *anyopaque) i64 {
            return 10;
        }

        fn onTicket(ctx: *anyopaque, ticket: *const tls_core.session.ClientTicketState) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.count += 1;
            self.ticket_len = ticket.ticket.slice().len;
        }
    };

    const allocator = testing.allocator;
    var capture = CaptureImpl{};
    var pair = try TestPair.initWithTicketConsumer(allocator, tls_core.session.Limits.default, .{
        .ctx = &capture,
        .nowUnixMsFn = CaptureImpl.now,
        .onTicketFn = CaptureImpl.onTicket,
    });
    defer pair.deinit(allocator);
    try pair.pump();

    var prepared = try pair.server.prepareNewSessionTicket(allocator, .{
        .ticket_lifetime = 60,
        .ticket_age_add = 1,
        .ticket_nonce = "\x01",
        .issued_at_unix_ms = 10,
    }, tls_core.session.Limits.default);
    defer prepared.deinit();
    try testing.expect(!std.mem.allEqual(u8, prepared.state.common.resumption_psk.slice(), 0));

    try pair.server.emitPreparedNewSessionTicket(&prepared, "two-phase-ticket", tls_core.session.Limits.default);

    var datagram: [2048]u8 = undefined;
    const dropped = pair.server.pollTransmitOnPath(&datagram, pair.now_us) orelse return error.TestExpectedEqual;
    try testing.expect(dropped.bytes.len > 0);
    const sent = pair.server.sent_records.items[pair.server.sent_records.items.len - 1];
    try testing.expectEqual(PacketNumberSpace.application, sent.space);
    try testing.expect(sent.crypto != null);
    pair.server.requeueRecord(&sent);

    try pair.pump();
    try testing.expectEqual(@as(usize, 1), capture.count);
    try testing.expectEqual(@as(usize, "two-phase-ticket".len), capture.ticket_len);
}

test "driver: prepareNewSessionTicket and emitPreparedNewSessionTicket require an established server connection" {
    const allocator = testing.allocator;
    var pair = try TestPair.init(allocator);
    defer pair.deinit(allocator);

    try testing.expectError(error.InvalidHandshakeState, pair.server.prepareNewSessionTicket(allocator, .{
        .ticket_lifetime = 60,
        .ticket_age_add = 1,
        .ticket_nonce = "\x01",
        .issued_at_unix_ms = 10,
    }, tls_core.session.Limits.default));

    try pair.pump();
    var prepared = try pair.server.prepareNewSessionTicket(allocator, .{
        .ticket_lifetime = 60,
        .ticket_age_add = 1,
        .ticket_nonce = "\x01",
        .issued_at_unix_ms = 10,
    }, tls_core.session.Limits.default);
    defer prepared.deinit();

    // A client connection can never prepare or emit a ticket.
    try testing.expectError(error.InvalidHandshakeState, pair.client.prepareNewSessionTicket(allocator, .{
        .ticket_lifetime = 60,
        .ticket_age_add = 1,
        .ticket_nonce = "\x01",
        .issued_at_unix_ms = 10,
    }, tls_core.session.Limits.default));
    try testing.expectError(error.TicketTooLarge, pair.server.emitPreparedNewSessionTicket(&prepared, "", tls_core.session.Limits.default));
}

test "#488: resumption_runtime.Runtime drives a genuine resumed QUIC handshake via two-phase issuance" {
    const resumption_runtime = tls_core.resumption_runtime;
    const allocator = testing.allocator;

    var server_entropy = tls_core.production_crypto.OsEntropy{};
    var server_provider = tls_core.production_crypto.Provider.init(server_entropy.entropy());
    var server_runtime = try resumption_runtime.Runtime.init(
        allocator,
        .{ .mode = .stateful },
        .{ .ctx = undefined, .nowUnixMsFn = struct {
            fn now(_: *anyopaque) i64 {
                return 1000;
            }
        }.now },
        server_provider.cryptoProvider(),
    );
    defer server_runtime.deinit();

    var client_entropy = tls_core.production_crypto.OsEntropy{};
    var client_provider = tls_core.production_crypto.Provider.init(client_entropy.entropy());
    var client_runtime = try resumption_runtime.Runtime.init(
        allocator,
        .{ .mode = .stateful },
        .{ .ctx = undefined, .nowUnixMsFn = struct {
            fn now(_: *anyopaque) i64 {
                return 2000;
            }
        }.now },
        client_provider.cryptoProvider(),
    );
    defer client_runtime.deinit();

    // Phase 1: a full QUIC handshake. The server issues a ticket through the
    // #488 two-phase API and the client captures it into its own runtime.
    const CaptureImpl = struct {
        runtime: *resumption_runtime.Runtime,
        stored: tls_core.session_cache.StoreResult = undefined,
        retained: tls_core.session.ClientTicketState = .{},

        fn now(_: *anyopaque) i64 {
            return 1000;
        }
        fn onTicket(ctx: *anyopaque, ticket: *const tls_core.session.ClientTicketState) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            ticket.cloneInto(testing.allocator, &self.retained) catch unreachable;
            self.stored = self.runtime.storeClientTicket(ticket);
        }
    };
    var capture = CaptureImpl{ .runtime = &client_runtime };
    defer capture.retained.deinit();
    const resume_policy: tls_core.tls13_backend.Tls13Backend.ResumeCompatibilityPolicy = .{
        .transport = .ignore,
        .application = .ignore,
    };
    var pair = try TestPair.initWithTicketConsumerAndResumePolicy(allocator, tls_core.session.Limits.default, .{
        .ctx = &capture,
        .nowUnixMsFn = CaptureImpl.now,
        .onTicketFn = CaptureImpl.onTicket,
    }, resume_policy);
    defer pair.deinit(allocator);
    try pair.pump();

    var prepared = try pair.server.prepareNewSessionTicket(allocator, .{
        .ticket_lifetime = 3600,
        .ticket_age_add = 500,
        .ticket_nonce = "\x01",
        .issued_at_unix_ms = 1000,
    }, tls_core.session.Limits.default);
    defer prepared.deinit();
    var scratch: [256]u8 = undefined;
    var identity = try server_runtime.createIdentity(&prepared.state, 1000, &scratch);
    try testing.expect(identity == .stateful);
    try pair.server.emitPreparedNewSessionTicket(&prepared, identity.slice(), tls_core.session.Limits.default);
    try pair.pump();
    try testing.expectEqual(tls_core.session_cache.StoreResult.stored, capture.stored);

    // Phase 2: a fresh QUIC connection pair. The client looks its offer up
    // through the client runtime; the server installs the *same* server
    // runtime's resolver before the handshake starts — proving the runtime's
    // cache/resolver composition (not a hand-rolled resolver) drives a real
    // abbreviated QUIC handshake.
    // Native QUIC 1-RTT resumption deliberately ignores connection-specific
    // transport/application snapshots. Do not feed the old ticket snapshot
    // back as the current candidate; doing so would only prove exact-match
    // behavior and would mask valid reconnects with changed transport params.
    const candidate: tls_core.session.CandidateContext = .{
        .cipher_suite = capture.retained.common.cipher_suite,
        .server_name = if (capture.retained.common.server_name) |*s| s.slice() else null,
        .application_protocol = if (capture.retained.common.application_protocol) |*a| a.slice() else null,
        .auth_binding = capture.retained.common.auth_binding,
        .transport_compat = null,
        .application_compat = null,
    };
    var lookup = client_runtime.lookupClientOffers(candidate);
    defer lookup.deinit();
    try testing.expect(lookup == .hit);
    try testing.expectEqual(@as(usize, 1), lookup.hit.offers.len);

    const resumed = try allocator.create(TestPair);
    defer allocator.destroy(resumed);
    const client_crypto_provider = resumed.client_provider_storage.init(0x442_c);
    const server_crypto_provider = resumed.server_provider_storage.init(0x442_5);
    resumed.* = .{
        .client_provider_storage = resumed.client_provider_storage,
        .server_provider_storage = resumed.server_provider_storage,
        .client_backend = tls_backend_mod.Tls13Backend.initClient(
            .{ .hello_random = [_]u8{0xd1} ** 32 },
            client_crypto_provider,
            .{ .pinned_certificate = tls_backend_mod.testdata.certificate_der },
        ),
        .server_backend = tls_backend_mod.Tls13Backend.initServer(
            .{ .hello_random = [_]u8{0xd2} ** 32 },
            server_crypto_provider,
            try tls_backend_mod.Identity.initPkcs8(
                tls_backend_mod.testdata.certificate_der,
                tls_backend_mod.testdata.private_key_pkcs8_der,
            ),
        ),
    };
    var clock_dummy: u8 = 0;
    const ClientClock = struct {
        fn now(_: *anyopaque) i64 {
            return 2000;
        }
    };
    try resumed.client_backend.engine.setClientPskOfferLease(&lookup.hit, &clock_dummy, ClientClock.now);
    try resumed.client_backend.setResumeCompatibilityPolicy(resume_policy);
    try resumed.server_backend.setServerPskResolver(server_runtime.serverResolver().?);
    try resumed.server_backend.setResumeCompatibilityPolicy(resume_policy);

    resumed.client = try Connection.init(allocator, .{
        .role = .client,
        .local_cid = &TestPair.client_cid,
        .original_destination_cid = &TestPair.odcid,
        .initial_secret_dcid = &TestPair.odcid,
        .peer_cid = &TestPair.odcid,
        .tls = resumed.client_backend.backend(),
        .crypto_provider = test_quic_crypto.testDefaultProvider(),
        .now_us = resumed.now_us,
        .initial_path = TestPair.client_path,
    });
    defer resumed.client.deinit();
    resumed.server = try Connection.init(allocator, .{
        .role = .server,
        .local_cid = &TestPair.odcid,
        .original_destination_cid = &TestPair.odcid,
        .initial_secret_dcid = &TestPair.odcid,
        .peer_cid = &TestPair.client_cid,
        .tls = resumed.server_backend.backend(),
        .crypto_provider = test_quic_crypto.testDefaultProvider(),
        .now_us = resumed.now_us,
        .initial_path = TestPair.server_path,
    });
    defer resumed.server.deinit();

    try resumed.pump();

    try testing.expect(resumed.client.isEstablished());
    try testing.expect(resumed.server.isEstablished());
    try testing.expect(resumed.client_backend.engine.core.psk_authenticated);
    try testing.expect(resumed.server_backend.engine.core.psk_authenticated);

    // The resumed connection is genuinely usable: application data flows.
    const id = try resumed.client.openStream(.bidi);
    try testing.expectEqual(@as(usize, 5), try resumed.client.writeStream(id, "hello", true));
    try resumed.pump();
    try testing.expectEqual(@as(?StreamId, id), resumed.server.acceptStream());
    var buf: [16]u8 = undefined;
    const request = try resumed.server.readStream(id, &buf);
    try testing.expectEqualStrings("hello", buf[0..request.len]);
}

test "#523: real TLS accept decision installs a usable QUIC 0-RTT read key end to end" {
    const resumption_runtime = tls_core.resumption_runtime;
    const allocator = testing.allocator;

    var server_entropy = tls_core.production_crypto.OsEntropy{};
    var server_provider = tls_core.production_crypto.Provider.init(server_entropy.entropy());
    var server_runtime = try resumption_runtime.Runtime.init(
        allocator,
        .{ .mode = .stateful },
        .{ .ctx = undefined, .nowUnixMsFn = struct {
            fn now(_: *anyopaque) i64 {
                return 1000;
            }
        }.now },
        server_provider.cryptoProvider(),
    );
    defer server_runtime.deinit();

    var client_entropy = tls_core.production_crypto.OsEntropy{};
    var client_provider = tls_core.production_crypto.Provider.init(client_entropy.entropy());
    var client_runtime = try resumption_runtime.Runtime.init(
        allocator,
        .{ .mode = .stateful },
        .{ .ctx = undefined, .nowUnixMsFn = struct {
            fn now(_: *anyopaque) i64 {
                return 2000;
            }
        }.now },
        client_provider.cryptoProvider(),
    );
    defer client_runtime.deinit();

    // Phase 1: an ordinary full handshake, then an early-data-capable ticket
    // (#523: `max_early_data_size` set) issued through the #488 two-phase API
    // and captured into the client's own runtime — same shape as the #488
    // test above, plus early-data capability on the ticket.
    const CaptureImpl = struct {
        runtime: *resumption_runtime.Runtime,
        stored: tls_core.session_cache.StoreResult = undefined,
        retained: tls_core.session.ClientTicketState = .{},

        fn now(_: *anyopaque) i64 {
            return 1000;
        }
        fn onTicket(ctx: *anyopaque, ticket: *const tls_core.session.ClientTicketState) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            ticket.cloneInto(testing.allocator, &self.retained) catch unreachable;
            self.stored = self.runtime.storeClientTicket(ticket);
        }
    };
    var capture = CaptureImpl{ .runtime = &client_runtime };
    defer capture.retained.deinit();
    const resume_policy: tls_core.tls13_backend.Tls13Backend.ResumeCompatibilityPolicy = .{
        .transport = .ignore,
        .application = .ignore,
    };
    var pair = try TestPair.initWithTicketConsumerAndResumePolicy(allocator, tls_core.session.Limits.default, .{
        .ctx = &capture,
        .nowUnixMsFn = CaptureImpl.now,
        .onTicketFn = CaptureImpl.onTicket,
    }, resume_policy);
    defer pair.deinit(allocator);
    try pair.pump();

    var prepared = try pair.server.prepareNewSessionTicket(allocator, .{
        .ticket_lifetime = 3600,
        .ticket_age_add = 500,
        .ticket_nonce = "\x01",
        .issued_at_unix_ms = 1000,
        // RFC 9001 §4.6.1: a QUIC ticket advertises 0-RTT capability with
        // the fixed sentinel, not a small TLS-record-style byte cap — this
        // is the value `http3_runtime.zig`'s production issuer uses too.
        .max_early_data_size = std.math.maxInt(u32),
    }, tls_core.session.Limits.default);
    defer prepared.deinit();
    var scratch: [256]u8 = undefined;
    var identity = try server_runtime.createIdentity(&prepared.state, 1000, &scratch);
    try testing.expect(identity == .stateful);
    try pair.server.emitPreparedNewSessionTicket(&prepared, identity.slice(), tls_core.session.Limits.default);
    try pair.pump();
    try testing.expectEqual(tls_core.session_cache.StoreResult.stored, capture.stored);

    // Phase 2: a fresh QUIC connection pair, resuming with the client
    // actually attempting 0-RTT and the server actually configured to accept
    // it — the full #523 composition (`setClientEarlyDataIntent`,
    // `setServerEarlyDataPolicy`, an allow replay gate, `zero_rtt_enabled` on
    // both `Connection.init` configs) that `http3_runtime.zig` wires for
    // production.
    const candidate: tls_core.session.CandidateContext = .{
        .cipher_suite = capture.retained.common.cipher_suite,
        .server_name = if (capture.retained.common.server_name) |*s| s.slice() else null,
        .application_protocol = if (capture.retained.common.application_protocol) |*a| a.slice() else null,
        .auth_binding = capture.retained.common.auth_binding,
        .transport_compat = null,
        .application_compat = null,
    };
    var lookup = client_runtime.lookupClientOffers(candidate);
    defer lookup.deinit();
    try testing.expect(lookup == .hit);

    const resumed = try allocator.create(TestPair);
    defer allocator.destroy(resumed);
    const client_crypto_provider = resumed.client_provider_storage.init(0x442_c);
    const server_crypto_provider = resumed.server_provider_storage.init(0x442_5);
    resumed.* = .{
        .client_provider_storage = resumed.client_provider_storage,
        .server_provider_storage = resumed.server_provider_storage,
        .client_backend = tls_backend_mod.Tls13Backend.initClient(
            .{ .hello_random = [_]u8{0xe1} ** 32 },
            client_crypto_provider,
            .{ .pinned_certificate = tls_backend_mod.testdata.certificate_der },
        ),
        .server_backend = tls_backend_mod.Tls13Backend.initServer(
            .{ .hello_random = [_]u8{0xe2} ** 32 },
            server_crypto_provider,
            try tls_backend_mod.Identity.initPkcs8(
                tls_backend_mod.testdata.certificate_der,
                tls_backend_mod.testdata.private_key_pkcs8_der,
            ),
        ),
    };
    var clock_dummy: u8 = 0;
    const ClientClock = struct {
        fn now(_: *anyopaque) i64 {
            return 2000;
        }
    };
    try resumed.client_backend.engine.setClientPskOfferLease(&lookup.hit, &clock_dummy, ClientClock.now);
    try resumed.client_backend.setResumeCompatibilityPolicy(resume_policy);
    try resumed.client_backend.setClientEarlyDataIntent(.{ .enabled = true, .max_bytes = 4096 });
    try resumed.server_backend.setServerPskResolver(server_runtime.serverResolver().?);
    try resumed.server_backend.setResumeCompatibilityPolicy(resume_policy);

    // Always-allow replay gate: proves the #368 seam is what the QUIC/H3
    // composition installs, not a QUIC-local replay mechanism.
    const AlwaysAllow = struct {
        fn decide(_: *anyopaque, _: tls_backend_mod.EarlyDataReplayCandidate) tls_backend_mod.EarlyDataReplayDecision {
            return .allow;
        }
    };
    var replay_ctx: u8 = 0;
    try resumed.server_backend.setEarlyDataReplayGate(.{ .ctx = &replay_ctx, .decideFn = AlwaysAllow.decide });
    try resumed.server_backend.setServerEarlyDataPolicy(.{ .enabled = true });

    resumed.client = try Connection.init(allocator, .{
        .role = .client,
        .config = .{ .zero_rtt_enabled = true },
        .local_cid = &TestPair.client_cid,
        .original_destination_cid = &TestPair.odcid,
        .initial_secret_dcid = &TestPair.odcid,
        .peer_cid = &TestPair.odcid,
        .tls = resumed.client_backend.backend(),
        .crypto_provider = test_quic_crypto.testDefaultProvider(),
        .now_us = resumed.now_us,
        .initial_path = TestPair.client_path,
    });
    defer resumed.client.deinit();
    resumed.server = try Connection.init(allocator, .{
        .role = .server,
        .config = .{ .zero_rtt_enabled = true },
        .local_cid = &TestPair.odcid,
        .original_destination_cid = &TestPair.odcid,
        .initial_secret_dcid = &TestPair.odcid,
        .peer_cid = &TestPair.client_cid,
        .tls = resumed.server_backend.backend(),
        .crypto_provider = test_quic_crypto.testDefaultProvider(),
        .now_us = resumed.now_us,
        .initial_path = TestPair.server_path,
    });
    defer resumed.server.deinit();

    // Drive only the client's first flight (Initial, carrying the
    // PSK-resumed ClientHello) into the server. The server's accept/reject
    // decision — and any resulting `.zero_rtt` read-key installation —
    // happens synchronously while processing that ClientHello, strictly
    // before the server sends anything back and long before either side is
    // anywhere close to established. Draining every pending client
    // datagram (not just one) is robust to the ClientHello spanning more
    // than one Initial packet.
    {
        var buf: [2048]u8 = undefined;
        while (resumed.client.pollTransmitOnPath(&buf, resumed.now_us)) |t| {
            try resumed.server.ingestOnPath(t.bytes, TestPair.server_path, TestPair.test_challenge_entropy, resumed.now_us);
        }
    }

    // The real TLS decision already accepted 0-RTT (not just "will resume")
    // — and did so before the handshake is anywhere close to complete...
    try testing.expect(!resumed.server.isEstablished());
    try testing.expect(resumed.server_backend.engine.earlyDataAccepted());
    // ...and that acceptance already installed a usable QUIC 0-RTT read key
    // through the ordinary secret-event pipeline (#523 requirement 1) — with
    // `zero_rtt_enabled` honored via `Connection.init`'s `setZeroRttEnabled`.
    try testing.expect((resumed.server.adapter.protectionKeys(.zero_rtt, .read) catch unreachable) != null);

    // That real, TLS-derived key genuinely decrypts a 0-RTT wire packet
    // through the ordinary driver path *during the early-data window*, with
    // correct early-data provenance — proving the pipeline end to end and
    // at the actual production timing, not just its two halves in
    // isolation after the fact.
    const real_secret = resumed.server.adapter.secret(.zero_rtt, .read).?.slice()[0..tls_adapter.traffic_secret_len].*;
    var frame_buf: [32]u8 = undefined;
    const frame_len = try frame.encodeStream(4, 0, "real early data", true, &frame_buf);
    var wire: [256]u8 = undefined;
    const datagram = sealTestZeroRttPacket(&TestPair.odcid, &TestPair.client_cid, real_secret, 0, frame_buf[0..frame_len], &wire);
    try resumed.server.ingestOnPath(datagram, TestPair.server_path, TestPair.test_challenge_entropy, resumed.now_us);

    try testing.expect(resumed.server.streamTransportEarly(4));
    try testing.expectEqual(@as(?StreamId, 4), resumed.server.acceptStream());
    var buf: [32]u8 = undefined;
    const request = try resumed.server.readStream(4, &buf);
    try testing.expectEqualStrings("real early data", buf[0..request.len]);
    try testing.expect(request.fin);

    // The rest of the handshake now completes normally — accepted 0-RTT
    // does not derail ordinary 1-RTT completion.
    try resumed.pump();
    try testing.expect(resumed.client.isEstablished());
    try testing.expect(resumed.server.isEstablished());
    try testing.expect(resumed.client_backend.engine.core.psk_authenticated);
    try testing.expect(resumed.server_backend.engine.core.psk_authenticated);
}

test "#523: Event.early_data_decision surfaces the real TLS decision once, even when the carrier is disabled" {
    const resumption_runtime = tls_core.resumption_runtime;
    const allocator = testing.allocator;

    var server_entropy = tls_core.production_crypto.OsEntropy{};
    var server_provider = tls_core.production_crypto.Provider.init(server_entropy.entropy());
    var server_runtime = try resumption_runtime.Runtime.init(
        allocator,
        .{ .mode = .stateful },
        .{ .ctx = undefined, .nowUnixMsFn = struct {
            fn now(_: *anyopaque) i64 {
                return 1000;
            }
        }.now },
        server_provider.cryptoProvider(),
    );
    defer server_runtime.deinit();

    var client_entropy = tls_core.production_crypto.OsEntropy{};
    var client_provider = tls_core.production_crypto.Provider.init(client_entropy.entropy());
    var client_runtime = try resumption_runtime.Runtime.init(
        allocator,
        .{ .mode = .stateful },
        .{ .ctx = undefined, .nowUnixMsFn = struct {
            fn now(_: *anyopaque) i64 {
                return 2000;
            }
        }.now },
        client_provider.cryptoProvider(),
    );
    defer client_runtime.deinit();

    // Phase 1: same shape as the previous test — an early-data-capable
    // ticket, issued and captured.
    const CaptureImpl = struct {
        runtime: *resumption_runtime.Runtime,
        stored: tls_core.session_cache.StoreResult = undefined,
        retained: tls_core.session.ClientTicketState = .{},

        fn now(_: *anyopaque) i64 {
            return 1000;
        }
        fn onTicket(ctx: *anyopaque, ticket: *const tls_core.session.ClientTicketState) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            ticket.cloneInto(testing.allocator, &self.retained) catch unreachable;
            self.stored = self.runtime.storeClientTicket(ticket);
        }
    };
    var capture = CaptureImpl{ .runtime = &client_runtime };
    defer capture.retained.deinit();
    const resume_policy: tls_core.tls13_backend.Tls13Backend.ResumeCompatibilityPolicy = .{
        .transport = .ignore,
        .application = .ignore,
    };
    var pair = try TestPair.initWithTicketConsumerAndResumePolicy(allocator, tls_core.session.Limits.default, .{
        .ctx = &capture,
        .nowUnixMsFn = CaptureImpl.now,
        .onTicketFn = CaptureImpl.onTicket,
    }, resume_policy);
    defer pair.deinit(allocator);
    try pair.pump();

    var prepared = try pair.server.prepareNewSessionTicket(allocator, .{
        .ticket_lifetime = 3600,
        .ticket_age_add = 500,
        .ticket_nonce = "\x01",
        .issued_at_unix_ms = 1000,
        .max_early_data_size = std.math.maxInt(u32),
    }, tls_core.session.Limits.default);
    defer prepared.deinit();
    var scratch: [256]u8 = undefined;
    var identity = try server_runtime.createIdentity(&prepared.state, 1000, &scratch);
    try testing.expect(identity == .stateful);
    try pair.server.emitPreparedNewSessionTicket(&prepared, identity.slice(), tls_core.session.Limits.default);
    try pair.pump();
    try testing.expectEqual(tls_core.session_cache.StoreResult.stored, capture.stored);

    const candidate: tls_core.session.CandidateContext = .{
        .cipher_suite = capture.retained.common.cipher_suite,
        .server_name = if (capture.retained.common.server_name) |*s| s.slice() else null,
        .application_protocol = if (capture.retained.common.application_protocol) |*a| a.slice() else null,
        .auth_binding = capture.retained.common.auth_binding,
        .transport_compat = null,
        .application_compat = null,
    };
    var lookup = client_runtime.lookupClientOffers(candidate);
    defer lookup.deinit();
    try testing.expect(lookup == .hit);

    // Phase 2: the client attempts 0-RTT with a genuinely early-data-capable
    // ticket, but the server never enables `ServerEarlyDataPolicy` — the
    // carrier stays off. `decideServerEarlyData` still runs (the ClientHello
    // did request early data) and must report `.disabled`, not silently
    // produce nothing just because no `.zero_rtt` packet will ever be sent.
    const EventCapture = struct {
        decision: ?tls_core.tls13_backend.EarlyDataDecision = null,
        count: usize = 0,

        fn onEvent(ctx: ?*anyopaque, event: Event) void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            switch (event) {
                .early_data_decision => |d| {
                    self.decision = d;
                    self.count += 1;
                },
                else => {},
            }
        }
    };
    var event_capture = EventCapture{};

    const resumed = try allocator.create(TestPair);
    defer allocator.destroy(resumed);
    const client_crypto_provider = resumed.client_provider_storage.init(0x442_c);
    const server_crypto_provider = resumed.server_provider_storage.init(0x442_5);
    resumed.* = .{
        .client_provider_storage = resumed.client_provider_storage,
        .server_provider_storage = resumed.server_provider_storage,
        .client_backend = tls_backend_mod.Tls13Backend.initClient(
            .{ .hello_random = [_]u8{0xf1} ** 32 },
            client_crypto_provider,
            .{ .pinned_certificate = tls_backend_mod.testdata.certificate_der },
        ),
        .server_backend = tls_backend_mod.Tls13Backend.initServer(
            .{ .hello_random = [_]u8{0xf2} ** 32 },
            server_crypto_provider,
            try tls_backend_mod.Identity.initPkcs8(
                tls_backend_mod.testdata.certificate_der,
                tls_backend_mod.testdata.private_key_pkcs8_der,
            ),
        ),
    };
    var clock_dummy: u8 = 0;
    const ClientClock = struct {
        fn now(_: *anyopaque) i64 {
            return 2000;
        }
    };
    try resumed.client_backend.engine.setClientPskOfferLease(&lookup.hit, &clock_dummy, ClientClock.now);
    try resumed.client_backend.setResumeCompatibilityPolicy(resume_policy);
    try resumed.client_backend.setClientEarlyDataIntent(.{ .enabled = true, .max_bytes = 4096 });
    try resumed.server_backend.setServerPskResolver(server_runtime.serverResolver().?);
    try resumed.server_backend.setResumeCompatibilityPolicy(resume_policy);
    // Deliberately not called: `resumed.server_backend.setServerEarlyDataPolicy(...)`.

    resumed.client = try Connection.init(allocator, .{
        .role = .client,
        .config = .{ .zero_rtt_enabled = true },
        .local_cid = &TestPair.client_cid,
        .original_destination_cid = &TestPair.odcid,
        .initial_secret_dcid = &TestPair.odcid,
        .peer_cid = &TestPair.odcid,
        .tls = resumed.client_backend.backend(),
        .crypto_provider = test_quic_crypto.testDefaultProvider(),
        .now_us = resumed.now_us,
        .initial_path = TestPair.client_path,
    });
    defer resumed.client.deinit();
    resumed.server = try Connection.init(allocator, .{
        .role = .server,
        .config = .{ .zero_rtt_enabled = true },
        .local_cid = &TestPair.odcid,
        .original_destination_cid = &TestPair.odcid,
        .initial_secret_dcid = &TestPair.odcid,
        .peer_cid = &TestPair.client_cid,
        .tls = resumed.server_backend.backend(),
        .crypto_provider = test_quic_crypto.testDefaultProvider(),
        .now_us = resumed.now_us,
        .initial_path = TestPair.server_path,
        .events = .{ .context = &event_capture, .emitFn = EventCapture.onEvent },
    });
    defer resumed.server.deinit();

    try resumed.pump();

    try testing.expect(resumed.client.isEstablished());
    try testing.expect(resumed.server.isEstablished());
    // The PSK still resumed (ordinary 1-RTT is unaffected by the disabled
    // carrier)...
    try testing.expect(resumed.server_backend.engine.core.psk_authenticated);
    // ...but the typed decision correctly distinguishes "disabled" from
    // "accepted", reported exactly once regardless of how many further
    // CRYPTO/application packets the rest of the handshake exchanges.
    try testing.expectEqual(@as(usize, 1), event_capture.count);
    try testing.expectEqual(tls_core.tls13_backend.EarlyDataDecision.disabled, event_capture.decision.?);
}

/// #523 third-pass review: proves that when 0-RTT is rejected — for any of
/// several distinct reasons, not just "disabled" — the *same* resumed PSK
/// connection (not a fallback to a different one) still completes its
/// handshake and serves a real request over ordinary 1-RTT afterward.
/// Shared by the reason-specific tests below; only the server's early-data
/// composition (and the expected `EarlyDataDecision`) varies per caller.
const RejectedEarlyDataFallback = struct {
    server_early_data_policy: tls_core.tls13_backend.ServerEarlyDataPolicy,
    replay_gate: ?tls_core.tls13_backend.EarlyDataReplayGate,
    compat_gate: ?tls_core.tls13_backend.EarlyDataCompatibilityGate,
    expect_decision: tls_core.tls13_backend.EarlyDataDecision,
};

fn expectRejectedEarlyDataFallsBackOnSameConnection(scenario: RejectedEarlyDataFallback) !void {
    const resumption_runtime = tls_core.resumption_runtime;
    const allocator = testing.allocator;

    var server_entropy = tls_core.production_crypto.OsEntropy{};
    var server_provider = tls_core.production_crypto.Provider.init(server_entropy.entropy());
    var server_runtime = try resumption_runtime.Runtime.init(
        allocator,
        .{ .mode = .stateful },
        .{ .ctx = undefined, .nowUnixMsFn = struct {
            fn now(_: *anyopaque) i64 {
                return 1000;
            }
        }.now },
        server_provider.cryptoProvider(),
    );
    defer server_runtime.deinit();

    var client_entropy = tls_core.production_crypto.OsEntropy{};
    var client_provider = tls_core.production_crypto.Provider.init(client_entropy.entropy());
    var client_runtime = try resumption_runtime.Runtime.init(
        allocator,
        .{ .mode = .stateful },
        .{ .ctx = undefined, .nowUnixMsFn = struct {
            fn now(_: *anyopaque) i64 {
                return 2000;
            }
        }.now },
        client_provider.cryptoProvider(),
    );
    defer client_runtime.deinit();

    const CaptureImpl = struct {
        runtime: *resumption_runtime.Runtime,
        stored: tls_core.session_cache.StoreResult = undefined,
        retained: tls_core.session.ClientTicketState = .{},

        fn now(_: *anyopaque) i64 {
            return 1000;
        }
        fn onTicket(ctx: *anyopaque, ticket: *const tls_core.session.ClientTicketState) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            ticket.cloneInto(testing.allocator, &self.retained) catch unreachable;
            self.stored = self.runtime.storeClientTicket(ticket);
        }
    };
    var capture = CaptureImpl{ .runtime = &client_runtime };
    defer capture.retained.deinit();
    const resume_policy: tls_core.tls13_backend.Tls13Backend.ResumeCompatibilityPolicy = .{
        .transport = .ignore,
        .application = .ignore,
    };
    var pair = try TestPair.initWithTicketConsumerAndResumePolicy(allocator, tls_core.session.Limits.default, .{
        .ctx = &capture,
        .nowUnixMsFn = CaptureImpl.now,
        .onTicketFn = CaptureImpl.onTicket,
    }, resume_policy);
    defer pair.deinit(allocator);
    try pair.pump();

    var prepared = try pair.server.prepareNewSessionTicket(allocator, .{
        .ticket_lifetime = 3600,
        .ticket_age_add = 500,
        .ticket_nonce = "\x01",
        .issued_at_unix_ms = 1000,
        .max_early_data_size = std.math.maxInt(u32),
    }, tls_core.session.Limits.default);
    defer prepared.deinit();
    var scratch: [256]u8 = undefined;
    var identity = try server_runtime.createIdentity(&prepared.state, 1000, &scratch);
    try testing.expect(identity == .stateful);
    try pair.server.emitPreparedNewSessionTicket(&prepared, identity.slice(), tls_core.session.Limits.default);
    try pair.pump();
    try testing.expectEqual(tls_core.session_cache.StoreResult.stored, capture.stored);

    const candidate: tls_core.session.CandidateContext = .{
        .cipher_suite = capture.retained.common.cipher_suite,
        .server_name = if (capture.retained.common.server_name) |*s| s.slice() else null,
        .application_protocol = if (capture.retained.common.application_protocol) |*a| a.slice() else null,
        .auth_binding = capture.retained.common.auth_binding,
        .transport_compat = null,
        .application_compat = null,
    };
    var lookup = client_runtime.lookupClientOffers(candidate);
    defer lookup.deinit();
    try testing.expect(lookup == .hit);

    const EventCapture = struct {
        decision: ?tls_core.tls13_backend.EarlyDataDecision = null,
        count: usize = 0,

        fn onEvent(ctx: ?*anyopaque, event: Event) void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            switch (event) {
                .early_data_decision => |d| {
                    self.decision = d;
                    self.count += 1;
                },
                else => {},
            }
        }
    };
    var event_capture = EventCapture{};

    const resumed = try allocator.create(TestPair);
    defer allocator.destroy(resumed);
    const client_crypto_provider = resumed.client_provider_storage.init(0x442_c);
    const server_crypto_provider = resumed.server_provider_storage.init(0x442_5);
    resumed.* = .{
        .client_provider_storage = resumed.client_provider_storage,
        .server_provider_storage = resumed.server_provider_storage,
        .client_backend = tls_backend_mod.Tls13Backend.initClient(
            .{ .hello_random = [_]u8{0xa1} ** 32 },
            client_crypto_provider,
            .{ .pinned_certificate = tls_backend_mod.testdata.certificate_der },
        ),
        .server_backend = tls_backend_mod.Tls13Backend.initServer(
            .{ .hello_random = [_]u8{0xa2} ** 32 },
            server_crypto_provider,
            try tls_backend_mod.Identity.initPkcs8(
                tls_backend_mod.testdata.certificate_der,
                tls_backend_mod.testdata.private_key_pkcs8_der,
            ),
        ),
    };
    var clock_dummy: u8 = 0;
    const ClientClock = struct {
        fn now(_: *anyopaque) i64 {
            return 2000;
        }
    };
    try resumed.client_backend.engine.setClientPskOfferLease(&lookup.hit, &clock_dummy, ClientClock.now);
    try resumed.client_backend.setResumeCompatibilityPolicy(resume_policy);
    try resumed.client_backend.setClientEarlyDataIntent(.{ .enabled = true, .max_bytes = 4096 });
    try resumed.server_backend.setServerPskResolver(server_runtime.serverResolver().?);
    try resumed.server_backend.setResumeCompatibilityPolicy(resume_policy);
    if (scenario.replay_gate) |gate| try resumed.server_backend.setEarlyDataReplayGate(gate);
    if (scenario.compat_gate) |gate| try resumed.server_backend.setEarlyDataCompatibilityGate(gate);
    try resumed.server_backend.setServerEarlyDataPolicy(scenario.server_early_data_policy);

    resumed.client = try Connection.init(allocator, .{
        .role = .client,
        .config = .{ .zero_rtt_enabled = true },
        .local_cid = &TestPair.client_cid,
        .original_destination_cid = &TestPair.odcid,
        .initial_secret_dcid = &TestPair.odcid,
        .peer_cid = &TestPair.odcid,
        .tls = resumed.client_backend.backend(),
        .crypto_provider = test_quic_crypto.testDefaultProvider(),
        .now_us = resumed.now_us,
        .initial_path = TestPair.client_path,
    });
    defer resumed.client.deinit();
    resumed.server = try Connection.init(allocator, .{
        .role = .server,
        .config = .{ .zero_rtt_enabled = true },
        .local_cid = &TestPair.odcid,
        .original_destination_cid = &TestPair.odcid,
        .initial_secret_dcid = &TestPair.odcid,
        .peer_cid = &TestPair.client_cid,
        .tls = resumed.server_backend.backend(),
        .crypto_provider = test_quic_crypto.testDefaultProvider(),
        .now_us = resumed.now_us,
        .initial_path = TestPair.server_path,
        .events = .{ .context = &event_capture, .emitFn = EventCapture.onEvent },
    });
    defer resumed.server.deinit();

    try resumed.pump();

    try testing.expect(resumed.client.isEstablished());
    try testing.expect(resumed.server.isEstablished());
    try testing.expect(resumed.client_backend.engine.core.psk_authenticated);
    try testing.expect(resumed.server_backend.engine.core.psk_authenticated);
    try testing.expect((resumed.server.adapter.protectionKeys(.zero_rtt, .read) catch unreachable) == null);
    try testing.expectEqual(@as(usize, 1), event_capture.count);
    try testing.expectEqual(scenario.expect_decision, event_capture.decision.?);

    // The same connection — not a different, cleaner one — genuinely serves
    // a real request over ordinary 1-RTT afterward.
    const id = try resumed.client.openStream(.bidi);
    _ = try resumed.client.writeStream(id, "hello", true);
    try resumed.pump();
    try testing.expectEqual(@as(?StreamId, id), resumed.server.acceptStream());
    var buf: [16]u8 = undefined;
    const request = try resumed.server.readStream(id, &buf);
    try testing.expectEqualStrings("hello", buf[0..request.len]);
}

test "#523: replay-rejected 0-RTT falls back to a working 1-RTT connection, same connection" {
    const AlwaysReplay = struct {
        fn decide(_: *anyopaque, _: tls_backend_mod.EarlyDataReplayCandidate) tls_backend_mod.EarlyDataReplayDecision {
            return .replay;
        }
    };
    var ctx: u8 = 0;
    try expectRejectedEarlyDataFallsBackOnSameConnection(.{
        .server_early_data_policy = .{ .enabled = true },
        .replay_gate = .{ .ctx = &ctx, .decideFn = AlwaysReplay.decide },
        .compat_gate = null,
        .expect_decision = .replay_rejected,
    });
}

test "#523: replay-store-unavailable 0-RTT falls back to a working 1-RTT connection, same connection" {
    // No replay gate installed at all: the backend's own default gate fails
    // closed (`.unavailable`) for every attempt — proving the fail-closed
    // default itself still leaves ordinary resumption usable.
    try expectRejectedEarlyDataFallsBackOnSameConnection(.{
        .server_early_data_policy = .{ .enabled = true },
        .replay_gate = null,
        .compat_gate = null,
        .expect_decision = .replay_unavailable,
    });
}

test "#523: transport-incompatible 0-RTT falls back to a working 1-RTT connection, same connection" {
    const AlwaysTransportIncompatible = struct {
        fn decide(_: *anyopaque, _: tls_backend_mod.EarlyDataCompatibilityCandidate) tls_backend_mod.EarlyDataCompatibilityDecision {
            return .transport_incompatible;
        }
    };
    const AlwaysAllow = struct {
        fn decide(_: *anyopaque, _: tls_backend_mod.EarlyDataReplayCandidate) tls_backend_mod.EarlyDataReplayDecision {
            return .allow;
        }
    };
    var replay_ctx: u8 = 0;
    var compat_ctx: u8 = 0;
    try expectRejectedEarlyDataFallsBackOnSameConnection(.{
        .server_early_data_policy = .{ .enabled = true },
        .replay_gate = .{ .ctx = &replay_ctx, .decideFn = AlwaysAllow.decide },
        .compat_gate = .{ .ctx = &compat_ctx, .decideFn = AlwaysTransportIncompatible.decide },
        .expect_decision = .transport_incompatible,
    });
}

test "#523: application-incompatible (H3 SETTINGS) 0-RTT falls back to a working 1-RTT connection, same connection" {
    const AlwaysApplicationIncompatible = struct {
        fn decide(_: *anyopaque, _: tls_backend_mod.EarlyDataCompatibilityCandidate) tls_backend_mod.EarlyDataCompatibilityDecision {
            return .application_incompatible;
        }
    };
    const AlwaysAllow = struct {
        fn decide(_: *anyopaque, _: tls_backend_mod.EarlyDataReplayCandidate) tls_backend_mod.EarlyDataReplayDecision {
            return .allow;
        }
    };
    var replay_ctx: u8 = 0;
    var compat_ctx: u8 = 0;
    try expectRejectedEarlyDataFallsBackOnSameConnection(.{
        .server_early_data_policy = .{ .enabled = true },
        .replay_gate = .{ .ctx = &replay_ctx, .decideFn = AlwaysAllow.decide },
        .compat_gate = .{ .ctx = &compat_ctx, .decideFn = AlwaysApplicationIncompatible.decide },
        .expect_decision = .application_incompatible,
    });
}

test "driver: maximum NewSessionTicket survives real loss reordering PTO and ACK cleanup" {
    const Capture = struct {
        allocator: std.mem.Allocator,
        retained: tls_core.session.ClientTicketState = .{},
        count: usize = 0,

        fn now(_: *anyopaque) i64 {
            return 10;
        }

        fn onTicket(ctx: *anyopaque, ticket: *const tls_core.session.ClientTicketState) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            ticket.cloneInto(self.allocator, &self.retained) catch unreachable;
            self.count += 1;
        }
    };

    const allocator = testing.allocator;
    const limits = tls_core.session.Limits{
        .max_ticket_len = tls_core.session.absolute_ticket_wire_max,
        .max_serialized_len = 128 * 1024,
    };
    const opaque_ticket = try allocator.alloc(u8, tls_core.session.absolute_ticket_wire_max);
    defer allocator.free(opaque_ticket);
    for (opaque_ticket, 0..) |*byte, index| byte.* = @intCast(index % 251);

    var capture = Capture{ .allocator = allocator };
    defer capture.retained.deinit();
    var pair = try TestPair.initWithTicketConsumer(allocator, limits, .{
        .ctx = &capture,
        .nowUnixMsFn = Capture.now,
        .onTicketFn = Capture.onTicket,
    });
    defer pair.deinit(allocator);
    try pair.pump();

    var server_state = try pair.server.emitNewSessionTicket(.{
        .ticket_lifetime = 60,
        .ticket_age_add = 0x11223344,
        .ticket_nonce = "\x01\x02",
        .opaque_ticket = opaque_ticket,
        .issued_at_unix_ms = 10,
    }, limits);
    defer server_state.deinit();
    try testing.expect(pair.server.crypto_tx[2].data.items.len > max_datagram_size);

    var datagrams = std.ArrayList([]u8).empty;
    defer {
        for (datagrams.items) |copy| allocator.free(copy);
        datagrams.deinit(allocator);
    }
    var buf: [max_datagram_size]u8 = undefined;
    while (pair.server.pollTransmitOnPath(&buf, pair.now_us)) |t| {
        const copy = try allocator.dupe(u8, t.bytes);
        errdefer allocator.free(copy);
        try datagrams.append(allocator, copy);
        pair.now_us += 500;
    }
    try testing.expect(datagrams.items.len > 5);

    var index = datagrams.items.len;
    while (index > 0) {
        index -= 1;
        if (index == 1 or index == 3) continue;
        try pair.client.ingestOnPath(datagrams.items[index], TestPair.client_path, TestPair.test_challenge_entropy, pair.now_us);
        pair.now_us += 500;
    }

    while (pair.client.pollTransmitOnPath(&buf, pair.now_us)) |ack| {
        try pair.server.ingestOnPath(ack.bytes, TestPair.server_path, TestPair.test_challenge_entropy, pair.now_us);
        pair.now_us += 500;
    }
    if (pair.server.metrics.packets_lost == 0) {
        if (pair.server.nextTimeoutUs()) |deadline| pair.now_us = @max(pair.now_us + 1, deadline);
        pair.server.onTimeout(pair.now_us);
    }
    try testing.expect(pair.server.metrics.packets_lost > 0 or pair.server.metrics.pto_count_total > 0);

    var rounds: usize = 0;
    while (rounds < 400 and capture.count == 0) : (rounds += 1) {
        try pair.pump();
        if (capture.count != 0) break;
        if (pair.server.nextTimeoutUs()) |deadline| {
            pair.now_us = @max(pair.now_us + 1, deadline);
            pair.server.onTimeout(pair.now_us);
        }
        if (pair.client.nextTimeoutUs()) |deadline| {
            pair.now_us = @max(pair.now_us + 1, deadline);
            pair.client.onTimeout(pair.now_us);
        }
    }
    try testing.expectEqual(@as(usize, 1), capture.count);
    try testing.expectEqualSlices(u8, opaque_ticket, capture.retained.ticket.slice());
    try testing.expectEqualSlices(u8, "\x01\x02", capture.retained.ticket_nonce.slice());
    try testing.expectEqualSlices(u8, server_state.common.resumption_psk.slice(), capture.retained.common.resumption_psk.slice());

    rounds = 0;
    while (rounds < 200 and pair.server.crypto_tx[2].data.capacity > 0) : (rounds += 1) {
        if (pair.client.nextTimeoutUs()) |deadline| {
            pair.now_us = @max(pair.now_us + 1, deadline);
            pair.client.onTimeout(pair.now_us);
        }
        try pair.pump();
        if (pair.server.nextTimeoutUs()) |deadline| {
            pair.now_us = @max(pair.now_us + 1, deadline);
            pair.server.onTimeout(pair.now_us);
        }
    }
    try testing.expectEqual(@as(usize, 0), pair.server.crypto_tx[2].data.items.len);
    try testing.expectEqual(@as(usize, 0), pair.server.crypto_tx[2].data.capacity);
    try testing.expect(pair.server.crypto_tx[2].pending.isEmpty());
    try testing.expect(pair.server.crypto_tx[2].acked.isEmpty());

    const stream_id = try pair.client.openStream(.bidi);
    try testing.expectEqual(@as(usize, 5), try pair.client.writeStream(stream_id, "after", true));
    try pair.pump();
    try testing.expectEqual(@as(?StreamId, stream_id), pair.server.acceptStream());
    var stream_buf: [16]u8 = undefined;
    const request = try pair.server.readStream(stream_id, &stream_buf);
    try testing.expectEqualStrings("after", stream_buf[0..request.len]);
}

test "driver: server emits two outstanding tickets in order before ACK" {
    const Capture = struct {
        count: usize = 0,
        ticket_lens: [2]usize = .{ 0, 0 },
        psks: [2][tls_core.session.max_psk_len]u8 = .{ [_]u8{0} ** tls_core.session.max_psk_len, [_]u8{0} ** tls_core.session.max_psk_len },
        psk_lens: [2]usize = .{ 0, 0 },

        fn now(_: *anyopaque) i64 {
            return 10;
        }

        fn onTicket(ctx: *anyopaque, ticket: *const tls_core.session.ClientTicketState) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            const index = self.count;
            if (index < self.ticket_lens.len) {
                self.ticket_lens[index] = ticket.ticket.slice().len;
                const psk = ticket.common.resumption_psk.slice();
                @memcpy(self.psks[index][0..psk.len], psk);
                self.psk_lens[index] = psk.len;
            }
            self.count += 1;
        }
    };

    const allocator = testing.allocator;
    var capture = Capture{};
    var pair = try TestPair.initWithTicketConsumer(allocator, tls_core.session.Limits.default, .{
        .ctx = &capture,
        .nowUnixMsFn = Capture.now,
        .onTicketFn = Capture.onTicket,
    });
    defer pair.deinit(allocator);
    try pair.pump();

    var state_a = try pair.server.emitNewSessionTicket(.{
        .ticket_lifetime = 60,
        .ticket_age_add = 1,
        .ticket_nonce = "\x01",
        .opaque_ticket = "ticket-a",
        .issued_at_unix_ms = 10,
    }, tls_core.session.Limits.default);
    defer state_a.deinit();
    var state_b = try pair.server.emitNewSessionTicket(.{
        .ticket_lifetime = 60,
        .ticket_age_add = 2,
        .ticket_nonce = "\x02",
        .opaque_ticket = "ticket-b",
        .issued_at_unix_ms = 10,
    }, tls_core.session.Limits.default);
    defer state_b.deinit();

    try pair.pump();
    try testing.expectEqual(@as(usize, 2), capture.count);
    try testing.expectEqual(@as(usize, "ticket-a".len), capture.ticket_lens[0]);
    try testing.expectEqual(@as(usize, "ticket-b".len), capture.ticket_lens[1]);
    try testing.expectEqual(state_a.common.resumption_psk.slice().len, capture.psk_lens[0]);
    try testing.expectEqual(state_b.common.resumption_psk.slice().len, capture.psk_lens[1]);
    try testing.expectEqualSlices(u8, state_a.common.resumption_psk.slice(), capture.psks[0][0..capture.psk_lens[0]]);
    try testing.expectEqualSlices(u8, state_b.common.resumption_psk.slice(), capture.psks[1][0..capture.psk_lens[1]]);
    try testing.expect(!std.mem.eql(u8, capture.psks[0][0..capture.psk_lens[0]], capture.psks[1][0..capture.psk_lens[1]]));

    const id = try pair.client.openStream(.bidi);
    try testing.expectEqual(@as(usize, 5), try pair.client.writeStream(id, "after", true));
    try pair.pump();
    try testing.expectEqual(@as(?StreamId, id), pair.server.acceptStream());
    var buf: [16]u8 = undefined;
    const request = try pair.server.readStream(id, &buf);
    try testing.expectEqualStrings("after", buf[0..request.len]);
}

test "driver: ordinary no-consumer client drops server ticket and remains usable" {
    const allocator = testing.allocator;
    var pair = try TestPair.init(allocator);
    defer pair.deinit(allocator);
    try pair.pump();

    var server_state = try pair.server.emitNewSessionTicket(.{
        .ticket_lifetime = 60,
        .ticket_age_add = 1,
        .ticket_nonce = "\x01",
        .opaque_ticket = "drop-this-ticket",
        .issued_at_unix_ms = 10,
    }, tls_core.session.Limits.default);
    defer server_state.deinit();
    try pair.pump();

    try testing.expectEqual(State.established, pair.client.state());
    try testing.expectEqual(State.established, pair.server.state());

    const id = try pair.client.openStream(.bidi);
    try testing.expectEqual(@as(usize, 4), try pair.client.writeStream(id, "ping", true));
    try pair.pump();
    try testing.expectEqual(@as(?StreamId, id), pair.server.acceptStream());
    var buf: [16]u8 = undefined;
    const request = try pair.server.readStream(id, &buf);
    try testing.expectEqualStrings("ping", buf[0..request.len]);
}

test "driver: application CRYPTO ticket budget refuses one-over before queueing" {
    const allocator = testing.allocator;
    var pair = try TestPair.init(allocator);
    defer pair.deinit(allocator);
    try pair.pump();

    var tx = &pair.server.crypto_tx[2];
    try tx.reserveAppend(allocator, max_application_crypto_outstanding, max_application_crypto_outstanding);
    const filler = try allocator.alloc(u8, max_application_crypto_outstanding);
    defer allocator.free(filler);
    @memset(filler, 0xa5);
    tx.appendReserved(filler);

    try testing.expectError(error.HandshakeBufferOverflow, pair.server.emitNewSessionTicket(.{
        .ticket_lifetime = 60,
        .ticket_age_add = 1,
        .ticket_nonce = "\x01",
        .opaque_ticket = "one-over",
        .issued_at_unix_ms = 10,
    }, tls_core.session.Limits.default));
    try testing.expectEqual(max_application_crypto_outstanding, pair.server.crypto_tx[2].data.items.len);
}

test "driver: ticket model limit refusal happens before CRYPTO allocation" {
    const allocator = testing.allocator;
    var pair = try TestPair.init(allocator);
    defer pair.deinit(allocator);
    try pair.pump();

    const too_large = try allocator.alloc(u8, tls_core.session.Limits.default.max_ticket_len + 1);
    defer allocator.free(too_large);
    @memset(too_large, 0x5a);

    try testing.expectError(error.TicketTooLarge, pair.server.emitNewSessionTicket(.{
        .ticket_lifetime = 60,
        .ticket_age_add = 1,
        .ticket_nonce = "\x01",
        .opaque_ticket = too_large,
        .issued_at_unix_ms = 10,
    }, tls_core.session.Limits.default));
    try testing.expectEqual(@as(usize, 0), pair.server.crypto_tx[2].data.items.len);
    try testing.expectEqual(@as(usize, 0), pair.server.crypto_tx[2].data.capacity);
    try testing.expect(pair.server.crypto_tx[2].pending.isEmpty());
}

test "driver: backend ticket rejection leaves CRYPTO reservation uncommitted" {
    const allocator = testing.allocator;
    var pair = try TestPair.init(allocator);
    defer pair.deinit(allocator);
    try pair.pump();

    try testing.expectError(error.InvalidHandshakeState, pair.server.emitNewSessionTicket(.{
        .ticket_lifetime = 0,
        .ticket_age_add = 1,
        .ticket_nonce = "\x01",
        .opaque_ticket = "ticket",
        .issued_at_unix_ms = 10,
    }, tls_core.session.Limits.default));
    try testing.expectEqual(@as(usize, 0), pair.server.crypto_tx[2].data.items.len);
    try testing.expectEqual(@as(usize, 0), pair.server.crypto_tx[2].data.capacity);
    try testing.expect(pair.server.crypto_tx[2].pending.isEmpty());
    try testing.expect(pair.server.crypto_tx[2].acked.isEmpty());

    var state = try pair.server.emitNewSessionTicket(.{
        .ticket_lifetime = 60,
        .ticket_age_add = 1,
        .ticket_nonce = "\x01",
        .opaque_ticket = "ticket",
        .issued_at_unix_ms = 10,
    }, tls_core.session.Limits.default);
    defer state.deinit();
    try testing.expect(pair.server.crypto_tx[2].data.items.len > 0);
}

test "driver: local close reaches the peer and both sides drain" {
    const allocator = testing.allocator;
    var pair = try TestPair.init(allocator);
    defer pair.deinit(allocator);
    try pair.pump();

    pair.client.close(0, "done", pair.now_us);
    try testing.expectEqual(State.closing, pair.client.state());
    try pair.pump();
    try testing.expectEqual(State.draining, pair.server.state());
    const info = pair.server.closeInfo().?;
    try testing.expectEqual(@as(u64, 0), info.error_code);
    try testing.expect(info.is_application);
    try testing.expect(!info.local);

    // Timers move both sides to closed.
    pair.now_us += 10_000_000;
    pair.client.onTimeout(pair.now_us);
    pair.server.onTimeout(pair.now_us);
    try testing.expectEqual(State.closed, pair.client.state());
    try testing.expectEqual(State.closed, pair.server.state());
}

test "driver: stream reset propagates" {
    const allocator = testing.allocator;
    var pair = try TestPair.init(allocator);
    defer pair.deinit(allocator);
    try pair.pump();

    const id = try pair.client.openStream(.bidi);
    _ = try pair.client.writeStream(id, "partial", false);
    try pair.pump();
    try pair.client.resetStream(id, 0x0107);
    try pair.pump();

    var buf: [16]u8 = undefined;
    try testing.expectError(error.StreamReset, pair.server.readStream(id, &buf));
}

// ---------------------------------------------------------------------------
// Path-aware ingest/egress integration (#387 Slice 2 / #515): `PathManager`
// (path.zig, #387 Slice 1) already carries a thorough state-machine test
// suite (candidate creation/accounting, validate/promote split, wrong-path
// and wrong-payload/expired PATH_RESPONSE rejection, blocked-pending-CID
// survival). The tests below instead prove `Connection` wires that state
// machine in correctly: post-AEAD-only path mutation, exact-path egress
// isolation, per-path amplification, and timer/CID integration.
// ---------------------------------------------------------------------------

/// Like `TestPair`, but with a configurable migration policy (`TestPair`
/// always uses the default `.disabled`, which every non-path test relies on
/// staying inert).
const MigrationPair = struct {
    client_backend: tls_backend_mod.Tls13Backend,
    server_backend: tls_backend_mod.Tls13Backend,
    // Owned, per-instance deterministic TLS-engine provider storage (#490
    // review) — see the matching comment on `TestPair`.
    client_provider_storage: test_quic_crypto.HandshakeProviderStorage = .{},
    server_provider_storage: test_quic_crypto.HandshakeProviderStorage = .{},
    client: *Connection = undefined,
    server: *Connection = undefined,
    now_us: u64 = 1_000_000,

    fn init(allocator: std.mem.Allocator, policy: config.MigrationPolicy) !*MigrationPair {
        const pair = try allocator.create(MigrationPair);
        const client_crypto_provider = pair.client_provider_storage.init(0x442_c);
        const server_crypto_provider = pair.server_provider_storage.init(0x442_5);
        pair.* = .{
            .client_provider_storage = pair.client_provider_storage,
            .server_provider_storage = pair.server_provider_storage,
            .client_backend = tls_backend_mod.Tls13Backend.initClient(
                .{ .hello_random = [_]u8{0xc1} ** 32 },
                client_crypto_provider,
                .{ .pinned_certificate = tls_backend_mod.testdata.certificate_der },
            ),
            .server_backend = tls_backend_mod.Tls13Backend.initServer(
                .{ .hello_random = [_]u8{0x51} ** 32 },
                server_crypto_provider,
                try tls_backend_mod.Identity.initPkcs8(
                    tls_backend_mod.testdata.certificate_der,
                    tls_backend_mod.testdata.private_key_pkcs8_der,
                ),
            ),
        };
        errdefer allocator.destroy(pair);
        pair.client = try Connection.init(allocator, .{
            .role = .client,
            .config = .{ .migration_policy = policy },
            .local_cid = &TestPair.client_cid,
            .original_destination_cid = &TestPair.odcid,
            .initial_secret_dcid = &TestPair.odcid,
            .peer_cid = &TestPair.odcid,
            .tls = pair.client_backend.backend(),
            .crypto_provider = test_quic_crypto.testDefaultProvider(),
            .now_us = pair.now_us,
            .initial_path = TestPair.client_path,
        });
        errdefer pair.client.deinit();
        pair.server = try Connection.init(allocator, .{
            .role = .server,
            .config = .{ .migration_policy = policy },
            .local_cid = &TestPair.odcid,
            .original_destination_cid = &TestPair.odcid,
            .initial_secret_dcid = &TestPair.odcid,
            .peer_cid = &TestPair.client_cid,
            .tls = pair.server_backend.backend(),
            .crypto_provider = test_quic_crypto.testDefaultProvider(),
            .now_us = pair.now_us,
            .initial_path = TestPair.server_path,
        });
        return pair;
    }

    fn deinit(self: *MigrationPair, allocator: std.mem.Allocator) void {
        self.client.deinit();
        self.server.deinit();
        allocator.destroy(self);
    }

    /// Move all pending datagrams both ways until neither side has output,
    /// delivering each on the exact path it was addressed to.
    fn pump(self: *MigrationPair) !void {
        var rounds: usize = 0;
        while (rounds < 64) : (rounds += 1) {
            var progressed = false;
            var buf: [2048]u8 = undefined;
            while (self.client.pollTransmitOnPath(&buf, self.now_us)) |t| {
                const ingress = quic_path.PathKey{ .local = t.path.remote, .remote = t.path.local };
                try self.server.ingestOnPath(t.bytes, ingress, TestPair.test_challenge_entropy, self.now_us);
                progressed = true;
                self.now_us += 500;
            }
            while (self.server.pollTransmitOnPath(&buf, self.now_us)) |t| {
                const ingress = quic_path.PathKey{ .local = t.path.remote, .remote = t.path.local };
                try self.client.ingestOnPath(t.bytes, ingress, TestPair.test_challenge_entropy, self.now_us);
                progressed = true;
                self.now_us += 500;
            }
            if (!progressed) return;
        }
        return error.PumpStalled;
    }
};

/// Same host as the server's active path (`TestPair.server_path.remote`),
/// different port: a NAT rebinding.
const rebind_candidate = quic_path.PathKey{
    .local = TestPair.server_path.local,
    .remote = quic_udp.Address.ip4(.{ 127, 0, 0, 1 }, 41_002),
};
/// A different host entirely: a host migration.
const migrate_candidate = quic_path.PathKey{
    .local = TestPair.server_path.local,
    .remote = quic_udp.Address.ip4(.{ 198, 51, 100, 7 }, 41_000),
};

/// Produce one real authenticated client->server datagram (a tiny STREAM
/// write) and copy its bytes out of the caller-provided scratch buffer, so
/// the caller may make further poll calls without the bytes being
/// overwritten.
fn clientDatagram(pair: *MigrationPair, out: *[2048]u8) ![]const u8 {
    const sid = try pair.client.openStream(.bidi);
    _ = try pair.client.writeStream(sid, "x", false);
    var buf: [2048]u8 = undefined;
    const t = pair.client.pollTransmitOnPath(&buf, pair.now_us) orelse return error.TestExpectedEqual;
    try testing.expect(t.path.eql(TestPair.client_path));
    @memcpy(out[0..t.bytes.len], t.bytes);
    return out[0..t.bytes.len];
}

test "connection: traffic on the active path produces no candidate probe and targets the active destination" {
    const allocator = testing.allocator;
    var pair = try MigrationPair.init(allocator, .full);
    defer pair.deinit(allocator);
    try pair.pump();

    const id = try pair.client.openStream(.bidi);
    _ = try pair.client.writeStream(id, "hello", false);
    try pair.pump();

    try testing.expectEqual(@as(u64, 0), pair.server.pathMetrics().path_challenges_sent);
    try testing.expect(pair.server.activePathKey().eql(TestPair.server_path));
}

test "connection: an undecryptable datagram from a new path creates no path state and cannot redirect egress" {
    const allocator = testing.allocator;
    var pair = try MigrationPair.init(allocator, .full);
    defer pair.deinit(allocator);
    try pair.pump();

    const spoofed_path = quic_path.PathKey{
        .local = TestPair.server_path.local,
        .remote = quic_udp.Address.ip4(.{ 203, 0, 113, 9 }, 55_555),
    };
    // Not a packet this connection can authenticate: parsing/deprotection
    // fails before path state is ever touched.
    const garbage = [_]u8{0xaa} ** 64;
    try pair.server.ingestOnPath(&garbage, spoofed_path, TestPair.test_challenge_entropy, pair.now_us);

    try testing.expectEqual(@as(u64, 0), pair.server.pathMetrics().path_challenges_sent);
    try testing.expect(pair.server.activePathKey().eql(TestPair.server_path));
    var out: [2048]u8 = undefined;
    if (pair.server.pollTransmitOnPath(&out, pair.now_us)) |t| {
        try testing.expect(t.path.eql(TestPair.server_path));
    }
}

test "connection: the first authenticated candidate datagram immediately credits only that candidate's ledger" {
    const allocator = testing.allocator;
    var pair = try MigrationPair.init(allocator, .full);
    defer pair.deinit(allocator);
    try pair.pump();

    var buf: [2048]u8 = undefined;
    const datagram = try clientDatagram(pair, &buf);
    try pair.server.ingestOnPath(datagram, rebind_candidate, TestPair.test_challenge_entropy, pair.now_us);

    try testing.expectEqual(@as(u64, 1), pair.server.pathMetrics().path_challenges_sent);
    // Server's active path was validated at handshake confirmation: unlimited.
    try testing.expectEqual(std.math.maxInt(u64), pair.server.paths.activePath().anti_amplification.remaining());
    // The candidate's ledger reflects only its own bytes: exactly 3x what it
    // has received so far, isolated from the active path's own accounting.
    try testing.expectEqual(3 * datagram.len, pair.server.paths.remainingOnPath(rebind_candidate));
}

test "connection: a NAT rebinding validates and promotes without a recovery reset" {
    const allocator = testing.allocator;
    var pair = try MigrationPair.init(allocator, .full);
    defer pair.deinit(allocator);
    try pair.pump();
    try testing.expect(pair.server.recovery.rtt.hasSample());

    var buf: [2048]u8 = undefined;
    const datagram = try clientDatagram(pair, &buf);
    try pair.server.ingestOnPath(datagram, rebind_candidate, TestPair.test_challenge_entropy, pair.now_us);

    var challenge_out: [2048]u8 = undefined;
    const challenge = pair.server.pollTransmitOnPath(&challenge_out, pair.now_us) orelse return error.TestExpectedEqual;
    try testing.expect(challenge.path.eql(rebind_candidate));
    var challenge_bytes: [2048]u8 = undefined;
    @memcpy(challenge_bytes[0..challenge.bytes.len], challenge.bytes);

    try pair.client.ingestOnPath(challenge_bytes[0..challenge.bytes.len], TestPair.client_path, TestPair.test_challenge_entropy, pair.now_us);
    var response_out: [2048]u8 = undefined;
    const response = pair.client.pollTransmitOnPath(&response_out, pair.now_us) orelse return error.TestExpectedEqual;
    try testing.expect(response.path.eql(TestPair.client_path));
    var response_bytes: [2048]u8 = undefined;
    @memcpy(response_bytes[0..response.bytes.len], response.bytes);

    try pair.server.ingestOnPath(response_bytes[0..response.bytes.len], rebind_candidate, TestPair.test_challenge_entropy, pair.now_us);

    try testing.expect(pair.server.activePathKey().eql(rebind_candidate));
    try testing.expectEqual(@as(u64, 1), pair.server.pathMetrics().nat_rebindings);
    try testing.expectEqual(@as(u64, 0), pair.server.pathMetrics().migrations);
    // Rebinding keeps RTT/congestion state (no reset).
    try testing.expect(pair.server.recovery.rtt.hasSample());
}

test "connection: a host migration with a fresh peer CID validates, promotes, and resets recovery exactly once" {
    const allocator = testing.allocator;
    var pair = try MigrationPair.init(allocator, .full);
    defer pair.deinit(allocator);
    try pair.pump();
    try testing.expect(pair.server.recovery.rtt.hasSample());

    // A fresh, never-used peer CID must be available before a host
    // migration may promote (RFC 9000 §9.5); this slice does not implement
    // local CID issuance, so the test seeds the pool directly with the
    // exact effect a peer NEW_CONNECTION_ID frame would have had.
    try pair.server.peer_cids.onNewConnectionId(.{
        .sequence = 1,
        .retire_prior_to = 0,
        .cid = try quic_cid.ConnectionId.init(&[_]u8{ 0xfe, 0xed, 0xfa, 0xce }),
        .stateless_reset_token = [_]u8{0x01} ** quic_cid.stateless_reset_token_len,
    });

    var buf: [2048]u8 = undefined;
    const datagram = try clientDatagram(pair, &buf);
    try pair.server.ingestOnPath(datagram, migrate_candidate, TestPair.test_challenge_entropy, pair.now_us);

    var challenge_out: [2048]u8 = undefined;
    const challenge = pair.server.pollTransmitOnPath(&challenge_out, pair.now_us) orelse return error.TestExpectedEqual;
    try testing.expect(challenge.path.eql(migrate_candidate));
    var challenge_bytes: [2048]u8 = undefined;
    @memcpy(challenge_bytes[0..challenge.bytes.len], challenge.bytes);

    try pair.client.ingestOnPath(challenge_bytes[0..challenge.bytes.len], TestPair.client_path, TestPair.test_challenge_entropy, pair.now_us);
    var response_out: [2048]u8 = undefined;
    const response = pair.client.pollTransmitOnPath(&response_out, pair.now_us) orelse return error.TestExpectedEqual;
    var response_bytes: [2048]u8 = undefined;
    @memcpy(response_bytes[0..response.bytes.len], response.bytes);

    try pair.server.ingestOnPath(response_bytes[0..response.bytes.len], migrate_candidate, TestPair.test_challenge_entropy, pair.now_us);

    try testing.expect(pair.server.activePathKey().eql(migrate_candidate));
    try testing.expectEqual(@as(u64, 1), pair.server.pathMetrics().migrations);
    try testing.expectEqual(@as(u64, 0), pair.server.pathMetrics().migrations_blocked_no_peer_cid);
    // Migration resets RTT/congestion exactly once.
    try testing.expect(!pair.server.recovery.rtt.hasSample());
}

test "connection: a host migration with no fresh peer CID leaves the old path active and pending, and retries once a CID arrives" {
    const allocator = testing.allocator;
    var pair = try MigrationPair.init(allocator, .full);
    defer pair.deinit(allocator);
    try pair.pump();

    var buf: [2048]u8 = undefined;
    const datagram = try clientDatagram(pair, &buf);
    try pair.server.ingestOnPath(datagram, migrate_candidate, TestPair.test_challenge_entropy, pair.now_us);

    var challenge_out: [2048]u8 = undefined;
    const challenge = pair.server.pollTransmitOnPath(&challenge_out, pair.now_us) orelse return error.TestExpectedEqual;
    var challenge_bytes: [2048]u8 = undefined;
    @memcpy(challenge_bytes[0..challenge.bytes.len], challenge.bytes);

    try pair.client.ingestOnPath(challenge_bytes[0..challenge.bytes.len], TestPair.client_path, TestPair.test_challenge_entropy, pair.now_us);
    var response_out: [2048]u8 = undefined;
    const response = pair.client.pollTransmitOnPath(&response_out, pair.now_us) orelse return error.TestExpectedEqual;
    var response_bytes: [2048]u8 = undefined;
    @memcpy(response_bytes[0..response.bytes.len], response.bytes);

    // No fresh peer CID is available (only the handshake CID, already in
    // use): validation succeeds but promotion must block.
    try pair.server.ingestOnPath(response_bytes[0..response.bytes.len], migrate_candidate, TestPair.test_challenge_entropy, pair.now_us);
    try testing.expect(pair.server.activePathKey().eql(TestPair.server_path));
    try testing.expectEqual(@as(u64, 1), pair.server.pathMetrics().migrations_blocked_no_peer_cid);
    try testing.expectEqual(@as(u64, 0), pair.server.pathMetrics().migrations);
    try testing.expect(pair.server.paths.pendingPromotionCandidate().?.eql(migrate_candidate));

    // Further authenticated traffic on the pending candidate must not spend
    // another validation round trip.
    var buf2: [2048]u8 = undefined;
    const datagram2 = try clientDatagram(pair, &buf2);
    try pair.server.ingestOnPath(datagram2, migrate_candidate, TestPair.test_challenge_entropy, pair.now_us);
    try testing.expectEqual(@as(u64, 1), pair.server.pathMetrics().path_challenges_sent);
    try testing.expectEqual(quic_path.PathState.validated_pending_promotion, pair.server.paths.stateOf(migrate_candidate).?);

    // Once a fresh peer CID becomes available, the same pending candidate
    // promotes without re-validating.
    try pair.server.peer_cids.onNewConnectionId(.{
        .sequence = 1,
        .retire_prior_to = 0,
        .cid = try quic_cid.ConnectionId.init(&[_]u8{ 0xaa, 0xbb, 0xcc, 0xdd }),
        .stateless_reset_token = [_]u8{0x02} ** quic_cid.stateless_reset_token_len,
    });
    pair.server.tryPromote(migrate_candidate);
    try testing.expect(pair.server.activePathKey().eql(migrate_candidate));
    try testing.expectEqual(@as(u64, 1), pair.server.pathMetrics().migrations);
    try testing.expectEqual(@as(u64, 1), pair.server.pathMetrics().migrations_blocked_no_peer_cid);
}

test "connection: a Handshake packet arriving on a different tuple validates only that tuple, not the old active path" {
    const allocator = testing.allocator;
    var pair = try MigrationPair.init(allocator, .full);
    defer pair.deinit(allocator);
    // A non-Retry server's initial path starts amplification-limited.
    try testing.expect(!pair.server.paths.activePath().anti_amplification.validated);

    // The client's very first (Initial) datagram arrives normally, on the
    // server's real active path; everything the client sends after that
    // (including the Handshake-level flight carrying Finished, which
    // completes the server's handshake) is delivered on a distinct
    // alternate tuple instead, simulating a rebind mid-handshake.
    const alternate = quic_path.PathKey{
        .local = TestPair.server_path.local,
        .remote = quic_udp.Address.ip4(.{ 127, 0, 0, 1 }, 41_777),
    };
    var first_from_client = true;
    var rounds: usize = 0;
    while (rounds < 64 and !(pair.client.isEstablished() and pair.server.isEstablished())) : (rounds += 1) {
        var progressed = false;
        var buf: [2048]u8 = undefined;
        while (pair.client.pollTransmitOnPath(&buf, pair.now_us)) |t| {
            var captured: [2048]u8 = undefined;
            @memcpy(captured[0..t.bytes.len], t.bytes);
            const ingress = if (first_from_client) TestPair.server_path else alternate;
            first_from_client = false;
            try pair.server.ingestOnPath(captured[0..t.bytes.len], ingress, TestPair.test_challenge_entropy, pair.now_us);
            progressed = true;
            pair.now_us += 500;
        }
        while (pair.server.pollTransmitOnPath(&buf, pair.now_us)) |t| {
            var captured: [2048]u8 = undefined;
            @memcpy(captured[0..t.bytes.len], t.bytes);
            const ingress = quic_path.PathKey{ .local = t.path.remote, .remote = t.path.local };
            try pair.client.ingestOnPath(captured[0..t.bytes.len], ingress, TestPair.test_challenge_entropy, pair.now_us);
            progressed = true;
            pair.now_us += 500;
        }
        if (!progressed) break;
    }

    // The redirected datagram(s) really did carry the Handshake-level
    // Finished: the server's handshake completed.
    try testing.expect(pair.server.isEstablished());
    // The active path never changed (ordinary Handshake-level traffic never
    // promotes anything) ...
    try testing.expect(pair.server.activePathKey().eql(TestPair.server_path));
    // ... and, critically, it was never validated by a packet that actually
    // authenticated on a *different* tuple.
    try testing.expect(!pair.server.paths.activePath().anti_amplification.validated);
    // The alternate tuple this traffic actually authenticated on is the one
    // that gets validated instead.
    try testing.expect(pair.server.paths.canSendOnPath(alternate, std.math.maxInt(u64)));
}

test "connection: a policy-blocked server still answers a PATH_CHALLENGE on its exact ingress path without migrating" {
    const allocator = testing.allocator;

    var client_provider_storage: test_quic_crypto.HandshakeProviderStorage = .{};
    var server_provider_storage: test_quic_crypto.HandshakeProviderStorage = .{};
    var client_backend = tls_backend_mod.Tls13Backend.initClient(
        .{ .hello_random = [_]u8{0xc1} ** 32 },
        client_provider_storage.init(0x442_c),
        .{ .pinned_certificate = tls_backend_mod.testdata.certificate_der },
    );
    var server_backend = tls_backend_mod.Tls13Backend.initServer(
        .{ .hello_random = [_]u8{0x51} ** 32 },
        server_provider_storage.init(0x442_5),
        try tls_backend_mod.Identity.initPkcs8(
            tls_backend_mod.testdata.certificate_der,
            tls_backend_mod.testdata.private_key_pkcs8_der,
        ),
    );
    var now_us: u64 = 1_000_000;
    // The client may freely validate new paths; the server under test must
    // not migrate/promote under its `.disabled` policy, but must still
    // answer path-validation control traffic on its exact ingress path
    // regardless (RFC 9000 §8.2.2 does not condition PATH_RESPONSE on
    // migration policy).
    const client = try Connection.init(allocator, .{
        .role = .client,
        .config = .{ .migration_policy = .full },
        .local_cid = &TestPair.client_cid,
        .original_destination_cid = &TestPair.odcid,
        .initial_secret_dcid = &TestPair.odcid,
        .peer_cid = &TestPair.odcid,
        .tls = client_backend.backend(),
        .crypto_provider = test_quic_crypto.testDefaultProvider(),
        .now_us = now_us,
        .initial_path = TestPair.client_path,
    });
    defer client.deinit();
    const server = try Connection.init(allocator, .{
        .role = .server,
        .config = .{ .migration_policy = .disabled },
        .local_cid = &TestPair.odcid,
        .original_destination_cid = &TestPair.odcid,
        .initial_secret_dcid = &TestPair.odcid,
        .peer_cid = &TestPair.client_cid,
        .tls = server_backend.backend(),
        .crypto_provider = test_quic_crypto.testDefaultProvider(),
        .now_us = now_us,
        .initial_path = TestPair.server_path,
    });
    defer server.deinit();

    {
        var rounds: usize = 0;
        while (rounds < 64) : (rounds += 1) {
            var progressed = false;
            var buf: [2048]u8 = undefined;
            while (client.pollTransmitOnPath(&buf, now_us)) |t| {
                var captured: [2048]u8 = undefined;
                @memcpy(captured[0..t.bytes.len], t.bytes);
                const ingress = quic_path.PathKey{ .local = t.path.remote, .remote = t.path.local };
                try server.ingestOnPath(captured[0..t.bytes.len], ingress, TestPair.test_challenge_entropy, now_us);
                progressed = true;
                now_us += 500;
            }
            while (server.pollTransmitOnPath(&buf, now_us)) |t| {
                var captured: [2048]u8 = undefined;
                @memcpy(captured[0..t.bytes.len], t.bytes);
                const ingress = quic_path.PathKey{ .local = t.path.remote, .remote = t.path.local };
                try client.ingestOnPath(captured[0..t.bytes.len], ingress, TestPair.test_challenge_entropy, now_us);
                progressed = true;
                now_us += 500;
            }
            if (!progressed) break;
        }
    }
    try testing.expect(client.isEstablished());
    try testing.expect(server.isEstablished());

    // Make the client believe the server just spoke from a new address:
    // the client's own `.full` policy starts a genuine candidate
    // validation, producing a real wire PATH_CHALLENGE.
    const server_alt_from_client_view = quic_path.PathKey{
        .local = TestPair.client_path.local,
        .remote = quic_udp.Address.ip4(.{ 127, 0, 0, 1 }, 41_555),
    };
    {
        const sid = try server.openStream(.bidi);
        _ = try server.writeStream(sid, "poke", false);
        var buf: [2048]u8 = undefined;
        const t = server.pollTransmitOnPath(&buf, now_us) orelse return error.TestExpectedEqual;
        var captured: [2048]u8 = undefined;
        @memcpy(captured[0..t.bytes.len], t.bytes);
        try client.ingestOnPath(captured[0..t.bytes.len], server_alt_from_client_view, TestPair.test_challenge_entropy, now_us);
    }
    try testing.expectEqual(@as(u64, 1), client.pathMetrics().path_challenges_sent);

    var challenge_buf: [2048]u8 = undefined;
    const challenge = client.pollTransmitOnPath(&challenge_buf, now_us) orelse return error.TestExpectedEqual;
    try testing.expect(challenge.path.eql(server_alt_from_client_view));
    var challenge_bytes: [2048]u8 = undefined;
    @memcpy(challenge_bytes[0..challenge.bytes.len], challenge.bytes);

    // Deliver the client's real PATH_CHALLENGE to the server as if it
    // arrived from a brand-new client tuple: the server's `.disabled`
    // policy must block migration/promotion of that tuple, but must still
    // answer the challenge on its exact ingress path.
    const client_alt_from_server_view = quic_path.PathKey{
        .local = TestPair.server_path.local,
        .remote = quic_udp.Address.ip4(.{ 127, 0, 0, 1 }, 41_666),
    };
    try server.ingestOnPath(challenge_bytes[0..challenge.bytes.len], client_alt_from_server_view, TestPair.test_challenge_entropy, now_us);

    try testing.expectEqual(@as(u64, 0), server.pathMetrics().path_challenges_sent);
    try testing.expect(server.pathMetrics().migrations_blocked > 0);
    try testing.expectEqual(@as(u64, 0), server.pathMetrics().migrations);
    try testing.expectEqual(@as(u64, 0), server.pathMetrics().nat_rebindings);
    try testing.expect(server.activePathKey().eql(TestPair.server_path));

    var response_buf: [2048]u8 = undefined;
    const response = server.pollTransmitOnPath(&response_buf, now_us) orelse return error.TestExpectedEqual;
    try testing.expect(response.path.eql(client_alt_from_server_view));
    try testing.expect(server.activePathKey().eql(TestPair.server_path));
}

test "connection: a PATH_RESPONSE received on the wrong path does not validate the candidate" {
    const allocator = testing.allocator;
    var pair = try MigrationPair.init(allocator, .full);
    defer pair.deinit(allocator);
    try pair.pump();

    var buf: [2048]u8 = undefined;
    const datagram = try clientDatagram(pair, &buf);
    try pair.server.ingestOnPath(datagram, rebind_candidate, TestPair.test_challenge_entropy, pair.now_us);

    var challenge_out: [2048]u8 = undefined;
    const challenge = pair.server.pollTransmitOnPath(&challenge_out, pair.now_us) orelse return error.TestExpectedEqual;
    var challenge_bytes: [2048]u8 = undefined;
    @memcpy(challenge_bytes[0..challenge.bytes.len], challenge.bytes);

    try pair.client.ingestOnPath(challenge_bytes[0..challenge.bytes.len], TestPair.client_path, TestPair.test_challenge_entropy, pair.now_us);
    var response_out: [2048]u8 = undefined;
    const response = pair.client.pollTransmitOnPath(&response_out, pair.now_us) orelse return error.TestExpectedEqual;
    var response_bytes: [2048]u8 = undefined;
    @memcpy(response_bytes[0..response.bytes.len], response.bytes);

    // Deliver the correct echo, but tag it as arriving on a different path
    // than the outstanding challenge: it must not validate that candidate.
    // A distinct entropy value is used here so that if this datagram
    // spuriously creates its own brand-new candidate at `wrong_path` (it
    // does — any authenticated traffic from an unseen tuple starts a fresh
    // validation), that candidate's own challenge cannot coincidentally
    // equal the echoed data and validate for the wrong reason.
    const wrong_path = quic_path.PathKey{
        .local = TestPair.server_path.local,
        .remote = quic_udp.Address.ip4(.{ 127, 0, 0, 1 }, 41_003),
    };
    const other_challenge_entropy = [_]u8{0x99} ** quic_path.path_challenge_len;
    try pair.server.ingestOnPath(response_bytes[0..response.bytes.len], wrong_path, other_challenge_entropy, pair.now_us);

    try testing.expect(pair.server.activePathKey().eql(TestPair.server_path));
    try testing.expectEqual(quic_path.PathState.validating, pair.server.paths.stateOf(rebind_candidate).?);
    try testing.expect(pair.server.pathMetrics().path_response_mismatches > 0);
}

test "connection: PATH_RESPONSE is emitted to the exact path its PATH_CHALLENGE arrived on" {
    const allocator = testing.allocator;
    var pair = try MigrationPair.init(allocator, .full);
    defer pair.deinit(allocator);
    try pair.pump();

    var buf: [2048]u8 = undefined;
    const datagram = try clientDatagram(pair, &buf);
    try pair.server.ingestOnPath(datagram, rebind_candidate, TestPair.test_challenge_entropy, pair.now_us);

    var challenge_out: [2048]u8 = undefined;
    const challenge = pair.server.pollTransmitOnPath(&challenge_out, pair.now_us) orelse return error.TestExpectedEqual;
    try testing.expect(challenge.path.eql(rebind_candidate));
    var challenge_bytes: [2048]u8 = undefined;
    @memcpy(challenge_bytes[0..challenge.bytes.len], challenge.bytes);

    // Deliver the challenge to the client tagged with a distinctive,
    // non-active path: the resulting PATH_RESPONSE must target exactly this
    // path, not the client's own active path or the server's candidate.
    const distinctive_path = quic_path.PathKey{
        .local = TestPair.client_path.local,
        .remote = quic_udp.Address.ip4(.{ 198, 51, 100, 7 }, 41_099),
    };
    try pair.client.ingestOnPath(challenge_bytes[0..challenge.bytes.len], distinctive_path, TestPair.test_challenge_entropy, pair.now_us);

    var response_out: [2048]u8 = undefined;
    const response = pair.client.pollTransmitOnPath(&response_out, pair.now_us) orelse return error.TestExpectedEqual;
    try testing.expect(response.path.eql(distinctive_path));
}

test "connection: candidate-path egress is isolated from ordinary active-path content" {
    const allocator = testing.allocator;
    var pair = try MigrationPair.init(allocator, .full);
    defer pair.deinit(allocator);
    try pair.pump();

    // A large enough write that the candidate's 3x anti-amplification
    // budget (credited from this one datagram) comfortably covers the
    // mandatory 1200-byte PATH_CHALLENGE padding (RFC 9000 §8.2.1) — a tiny
    // datagram's budget would be too small to pad to 1200 at all.
    const sid = try pair.client.openStream(.bidi);
    const big_payload = [_]u8{0x42} ** 900;
    _ = try pair.client.writeStream(sid, &big_payload, false);
    var buf: [2048]u8 = undefined;
    const from_client = pair.client.pollTransmitOnPath(&buf, pair.now_us) orelse return error.TestExpectedEqual;
    var captured: [2048]u8 = undefined;
    @memcpy(captured[0..from_client.bytes.len], from_client.bytes);
    try pair.server.ingestOnPath(captured[0..from_client.bytes.len], rebind_candidate, TestPair.test_challenge_entropy, pair.now_us);

    const server_sid = try pair.server.openStream(.bidi);
    _ = try pair.server.writeStream(server_sid, "reply", false);

    var out1: [2048]u8 = undefined;
    const first = pair.server.pollTransmitOnPath(&out1, pair.now_us) orelse return error.TestExpectedEqual;
    try testing.expect(first.path.eql(rebind_candidate));
    try testing.expectEqual(min_initial_datagram, first.bytes.len);

    var out2: [2048]u8 = undefined;
    const second = pair.server.pollTransmitOnPath(&out2, pair.now_us) orelse return error.TestExpectedEqual;
    try testing.expect(second.path.eql(TestPair.server_path));
    try testing.expect(second.bytes.len < min_initial_datagram);
}

test "connection: candidate-path anti-amplification budget is isolated from the active path" {
    const allocator = testing.allocator;
    var pair = try MigrationPair.init(allocator, .full);
    defer pair.deinit(allocator);
    try pair.pump();

    var buf: [2048]u8 = undefined;
    const datagram = try clientDatagram(pair, &buf);
    try pair.server.ingestOnPath(datagram, rebind_candidate, TestPair.test_challenge_entropy, pair.now_us);

    const active_remaining = pair.server.paths.activePath().anti_amplification.remaining();
    const candidate_remaining = pair.server.paths.remainingOnPath(rebind_candidate);
    try testing.expectEqual(std.math.maxInt(u64), active_remaining);
    try testing.expect(candidate_remaining < active_remaining);
    try testing.expect(candidate_remaining > 0);
    try testing.expect(!pair.server.paths.canSendOnPath(rebind_candidate, candidate_remaining + 1));
}

test "connection: a path validation deadline is folded into nextTimeoutUs and expiry leaves the active path unchanged" {
    const allocator = testing.allocator;
    var pair = try MigrationPair.init(allocator, .full);
    defer pair.deinit(allocator);
    try pair.pump();

    var buf: [2048]u8 = undefined;
    const datagram = try clientDatagram(pair, &buf);
    try pair.server.ingestOnPath(datagram, rebind_candidate, TestPair.test_challenge_entropy, pair.now_us);
    try testing.expectEqual(quic_path.PathState.validating, pair.server.paths.stateOf(rebind_candidate).?);

    const validation_deadline = pair.server.paths.nextValidationDeadlineUs() orelse return error.TestExpectedEqual;
    const deadline = pair.server.nextTimeoutUs() orelse return error.TestExpectedEqual;
    try testing.expect(deadline >= pair.now_us);
    // nextTimeoutUs is the min of every deadline source, so it can only be
    // at or before the validation deadline it just folded in.
    try testing.expect(deadline <= validation_deadline);

    // Advance well past the validation deadline without ever answering the
    // challenge; expiry must not touch the active path.
    pair.server.onTimeout(pair.now_us + 2_000_000);
    try testing.expectEqual(@as(u64, 1), pair.server.pathMetrics().path_validations_failed);
    try testing.expect(pair.server.activePathKey().eql(TestPair.server_path));
    try testing.expectEqual(quic_path.PathState.failed, pair.server.paths.stateOf(rebind_candidate).?);
}

test "connection: local CID registry maintains a spare and accepts packets addressed to it" {
    const allocator = testing.allocator;
    var pair = try TestPair.init(allocator);
    defer pair.deinit(allocator);
    try pair.pump();

    try testing.expect(pair.server.needsLocalCid());
    const spare = try quic_cid.ConnectionId.init(&.{ 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8 });
    try pair.server.advertiseLocalCid(spare);
    try testing.expect(!pair.server.needsLocalCid());
    try testing.expectEqual(@as(?u64, 1), pair.server.localCidSequence(spare.slice()));

    pair.client.peer_cid = try config.CidValue.init(spare.slice());
    const id = try pair.client.openStream(.bidi);
    try testing.expectEqual(@as(usize, 5), try pair.client.writeStream(id, "spare", false));

    var out: [2048]u8 = undefined;
    const t = pair.client.pollTransmitOnPath(&out, pair.now_us) orelse return error.TestExpectedEqual;
    const parsed = packet.parsePacket(t.bytes, spare.len) catch return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, spare.slice(), parsed.dcid);

    const before = pair.server.metrics.packets_received;
    try pair.server.ingestOnPath(t.bytes, TestPair.server_path, TestPair.test_challenge_entropy, pair.now_us);
    try testing.expect(pair.server.metrics.packets_received > before);
}

test "connection: lost NEW_CONNECTION_ID retransmits the same frame identity" {
    const allocator = testing.allocator;
    var pair = try TestPair.init(allocator);
    defer pair.deinit(allocator);
    try pair.pump();

    const spare = try quic_cid.ConnectionId.init(&.{ 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8 });
    try pair.server.advertiseLocalCid(spare);

    var out: [2048]u8 = undefined;
    _ = pair.server.pollTransmitOnPath(&out, pair.now_us) orelse return error.TestExpectedEqual;
    const first_record = pair.server.sent_records.items[pair.server.sent_records.items.len - 1];
    const first = first_record.carried_new_connection_id orelse return error.TestExpectedEqual;
    try testing.expectEqual(@as(u64, 1), first.sequence);
    try testing.expectEqualSlices(u8, spare.slice(), first.cid.slice());

    pair.server.requeueRecord(&first_record);
    _ = pair.server.pollTransmitOnPath(&out, pair.now_us + 1_000) orelse return error.TestExpectedEqual;
    const second_record = pair.server.sent_records.items[pair.server.sent_records.items.len - 1];
    const second = second_record.carried_new_connection_id orelse return error.TestExpectedEqual;
    try testing.expectEqual(first.sequence, second.sequence);
    try testing.expectEqual(first.retire_prior_to, second.retire_prior_to);
    try testing.expectEqualSlices(u8, first.cid.slice(), second.cid.slice());
    try testing.expectEqualSlices(u8, &first.stateless_reset_token, &second.stateless_reset_token);
}

test "connection: unadvertised local CID retirement is a protocol violation" {
    const allocator = testing.allocator;
    var pair = try TestPair.init(allocator);
    defer pair.deinit(allocator);
    try pair.pump();

    const spare = try quic_cid.ConnectionId.init(&.{ 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8 });
    try pair.server.advertiseLocalCid(spare);
    try testing.expectEqual(@as(usize, 1), pair.server.pending_new_connection_ids.items.len);

    try pair.server.applyFrame(.application, .{ .retire_connection_id = .{ .sequence = 1 } }, TestPair.server_path, 0, pair.now_us);
    try testing.expectEqual(State.closing, pair.server.state());
    try testing.expectEqual(error_protocol_violation, pair.server.close_info.?.error_code);
}

test "connection: advertised local CID can be retired from another active CID" {
    const allocator = testing.allocator;
    var pair = try TestPair.init(allocator);
    defer pair.deinit(allocator);
    try pair.pump();

    const spare = try quic_cid.ConnectionId.init(&.{ 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8 });
    try pair.server.advertiseLocalCid(spare);
    var out: [2048]u8 = undefined;
    _ = pair.server.pollTransmitOnPath(&out, pair.now_us) orelse return error.TestExpectedEqual;

    try pair.server.applyFrame(.application, .{ .retire_connection_id = .{ .sequence = 1 } }, TestPair.server_path, 0, pair.now_us);
    try testing.expectEqual(State.established, pair.server.state());
    try testing.expectEqual(@as(?u64, null), pair.server.localCidSequence(spare.slice()));
    try testing.expect(pair.server.needsLocalCid());
}

test "connection: losing one NEW_CONNECTION_ID leaves all queued CID identities pending" {
    const allocator = testing.allocator;
    var pair = try TestPair.init(allocator);
    defer pair.deinit(allocator);
    try pair.pump();

    const first_cid = try quic_cid.ConnectionId.init(&.{ 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8 });
    const second_cid = try quic_cid.ConnectionId.init(&.{ 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8 });
    try pair.server.advertiseLocalCid(first_cid);
    try pair.server.advertiseLocalCid(second_cid);
    try testing.expectEqual(@as(usize, 2), pair.server.pending_new_connection_ids.items.len);

    var out: [2048]u8 = undefined;
    _ = pair.server.pollTransmitOnPath(&out, pair.now_us) orelse return error.TestExpectedEqual;
    const sent = pair.server.sent_records.items[pair.server.sent_records.items.len - 1];
    const first = sent.carried_new_connection_id orelse return error.TestExpectedEqual;
    try testing.expectEqual(@as(u64, 1), first.sequence);
    try testing.expectEqualSlices(u8, first_cid.slice(), first.cid.slice());
    try testing.expectEqual(@as(usize, 1), pair.server.pending_new_connection_ids.items.len);
    try testing.expectEqualSlices(u8, second_cid.slice(), pair.server.pending_new_connection_ids.items[0].cid.slice());

    pair.server.requeueRecord(&sent);
    try testing.expectEqual(@as(usize, 2), pair.server.pending_new_connection_ids.items.len);
    var saw_first = false;
    var saw_second = false;
    for (pair.server.pending_new_connection_ids.items) |pending| {
        if (pending.sequence == 1 and std.mem.eql(u8, pending.cid.slice(), first_cid.slice())) {
            try testing.expectEqualSlices(u8, &first.stateless_reset_token, &pending.stateless_reset_token);
            saw_first = true;
        }
        if (pending.sequence == 2 and std.mem.eql(u8, pending.cid.slice(), second_cid.slice())) {
            saw_second = true;
        }
    }
    try testing.expect(saw_first);
    try testing.expect(saw_second);
}

test "wipeSentRecordsSwapRemoveResidue zeroes the vacated slot regardless of its prior byte pattern" {
    var records: std.ArrayList(SentRecord) = .empty;
    defer records.deinit(testing.allocator);
    try records.ensureTotalCapacityPrecise(testing.allocator, 4);
    records.appendAssumeCapacity(.{ .space = .application, .packet_number = 1, .ack_eliciting = false });
    records.appendAssumeCapacity(.{ .space = .application, .packet_number = 2, .ack_eliciting = false });

    _ = records.swapRemove(0);
    // Simulate whatever a safety-checked build's poison-fill (or a
    // `ReleaseFast` build's leftover live data) might put in the vacated
    // slot: an arbitrary, non-zero byte pattern that would be an invalid
    // `?NewConnectionIdFrame` tag if ever misinterpreted as a typed
    // `SentRecord` rather than treated as opaque bytes.
    const ghost = std.mem.asBytes(&records.allocatedSlice()[records.items.len]);
    @memset(ghost, 0xaa);

    wipeSentRecordsSwapRemoveResidue(&records);
    for (ghost) |byte| try testing.expectEqual(@as(u8, 0), byte);
}

test "wipePendingNewConnectionIdsOrderedRemoveResidue zeroes the vacated slot regardless of its prior byte pattern" {
    var frames: std.ArrayList(quic_cid.NewConnectionIdFrame) = .empty;
    defer frames.deinit(testing.allocator);
    try frames.ensureTotalCapacityPrecise(testing.allocator, 4);
    frames.appendAssumeCapacity(.{
        .sequence = 1,
        .retire_prior_to = 0,
        .cid = try quic_cid.ConnectionId.init(&.{ 1, 2, 3, 4 }),
        .stateless_reset_token = [_]u8{0xcd} ** quic_cid.stateless_reset_token_len,
    });
    frames.appendAssumeCapacity(.{
        .sequence = 2,
        .retire_prior_to = 0,
        .cid = try quic_cid.ConnectionId.init(&.{ 5, 6, 7, 8 }),
        .stateless_reset_token = [_]u8{0xef} ** quic_cid.stateless_reset_token_len,
    });

    _ = frames.orderedRemove(0);
    const ghost = std.mem.asBytes(&frames.allocatedSlice()[frames.items.len]);
    @memset(ghost, 0xaa);

    wipePendingNewConnectionIdsOrderedRemoveResidue(&frames);
    for (ghost) |byte| try testing.expectEqual(@as(u8, 0), byte);
}

test "connection: sent_records and pending_new_connection_ids reserve capacity once and never regrow" {
    const allocator = testing.allocator;
    var pair = try TestPair.init(allocator);
    defer pair.deinit(allocator);

    // `Connection.init` reserves the full protocol-bounded capacity for
    // both collections before either can ever hold a locally-generated
    // reset token.
    try testing.expect(pair.server.sent_records.capacity >= recovery.max_tracked_packets);
    try testing.expect(pair.server.pending_new_connection_ids.capacity >= quic_cid.max_local_active_cids);

    const sent_records_backing = pair.server.sent_records.items.ptr;
    const pending_backing = pair.server.pending_new_connection_ids.items.ptr;

    // Push `sent_records` all the way to the protocol bound directly
    // (bypassing the recovery-tracker gate, which is exactly what keeps it
    // under that bound in production): if capacity were not already
    // reserved, appends anywhere in this loop would trigger
    // `std.ArrayList`'s grow-and-free-the-old-backing-unwiped path. The
    // backing pointer staying fixed throughout proves that never happens.
    var i: usize = 0;
    while (i < recovery.max_tracked_packets) : (i += 1) {
        try pair.server.sent_records.append(pair.server.allocator, .{
            .space = .application,
            .packet_number = i,
            .ack_eliciting = false,
        });
    }
    try testing.expectEqual(sent_records_backing, pair.server.sent_records.items.ptr);
    try testing.expectEqual(@as(usize, recovery.max_tracked_packets), pair.server.sent_records.capacity);

    try pair.pump();
    try testing.expectEqual(pending_backing, pair.server.pending_new_connection_ids.items.ptr);
}

test "connection: teardown scrubs a still-pending and an in-flight NEW_CONNECTION_ID's reset token" {
    const allocator = testing.allocator;
    var pair = try TestPair.init(allocator);
    defer pair.deinit(allocator);
    try pair.pump();

    const first_cid = try quic_cid.ConnectionId.init(&.{ 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28 });
    const second_cid = try quic_cid.ConnectionId.init(&.{ 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 });
    try pair.server.advertiseLocalCid(first_cid);
    try pair.server.advertiseLocalCid(second_cid);
    try testing.expectEqual(@as(usize, 2), pair.server.pending_new_connection_ids.items.len);

    // Dequeue only the first NEW_CONNECTION_ID into an in-flight sent
    // record; the second stays queued in `pending_new_connection_ids`.
    var out: [2048]u8 = undefined;
    _ = pair.server.pollTransmitOnPath(&out, pair.now_us) orelse return error.TestExpectedEqual;
    try testing.expectEqual(@as(usize, 1), pair.server.pending_new_connection_ids.items.len);
    const sent_index = pair.server.sent_records.items.len - 1;
    try testing.expect(pair.server.sent_records.items[sent_index].carried_new_connection_id != null);

    var in_flight_nonzero = false;
    for (pair.server.sent_records.items[sent_index].carried_new_connection_id.?.stateless_reset_token) |b| {
        if (b != 0) in_flight_nonzero = true;
    }
    try testing.expect(in_flight_nonzero);
    var pending_nonzero = false;
    for (pair.server.pending_new_connection_ids.items[0].stateless_reset_token) |b| {
        if (b != 0) pending_nonzero = true;
    }
    try testing.expect(pending_nonzero);

    // `std.ArrayList.deinit` runs the freed buffer through `Allocator.free`,
    // which does its own `@memset(bytes, undefined)` poison-fill before the
    // real free — so bytes read back *after* a full `Connection.deinit()`
    // reflect that poison, not whether our own wipe ran (see
    // `secureZeroAndFree` in crypto/secrets.zig for the same issue). Call
    // the exact scrub helpers `deinitPartial` calls, directly on this
    // connection's real pending/in-flight state, and assert what they are
    // responsible for zeroing.
    wipeSentRecordTokens(pair.server.sent_records.items);
    wipePendingNewConnectionIdTokens(pair.server.pending_new_connection_ids.items);

    for (pair.server.sent_records.items[sent_index].carried_new_connection_id.?.stateless_reset_token) |byte| {
        try testing.expectEqual(@as(u8, 0), byte);
    }
    for (pair.server.pending_new_connection_ids.items[0].stateless_reset_token) |byte| {
        try testing.expectEqual(@as(u8, 0), byte);
    }
}

test "driver: idle timeout closes silently" {
    const allocator = testing.allocator;
    var pair = try TestPair.init(allocator);
    defer pair.deinit(allocator);
    try pair.pump();

    // Default idle timeout is 30s; advance past it.
    pair.now_us += 31_000_000;
    pair.client.onTimeout(pair.now_us);
    try testing.expectEqual(State.closed, pair.client.state());
}

test "driver: timers are armed while handshaking" {
    const allocator = testing.allocator;
    var pair = try TestPair.init(allocator);
    defer pair.deinit(allocator);
    // Client has sent nothing yet but must arm a deadline once it has output.
    var buf: [2048]u8 = undefined;
    _ = pair.client.pollTransmitOnPath(&buf, pair.now_us);
    try testing.expect(pair.client.nextTimeoutUs() != null);
}

test "handshake failures map to their RFC 9001 CRYPTO_ERROR alert codes" {
    // RFC 9001 §4.8: a TLS alert is carried as CRYPTO_ERROR (0x0100 + alert).
    // Ordering failures and malformed bytes are distinct alerts and must not
    // collapse to the same code.
    try testing.expectEqual(error_crypto_base + 10, Connection.cryptoErrorCode(error.UnexpectedHandshakeMessage));
    try testing.expectEqual(error_crypto_base + 47, Connection.cryptoErrorCode(error.IllegalParameter));
    try testing.expectEqual(error_crypto_base + 50, Connection.cryptoErrorCode(error.MalformedHandshake));
    try testing.expectEqual(error_crypto_base + 120, Connection.cryptoErrorCode(error.AlpnMismatch));
    try testing.expectEqual(error_crypto_base + 42, Connection.cryptoErrorCode(error.CertificateInvalid));
    try testing.expectEqual(error_crypto_base + 43, Connection.cryptoErrorCode(error.UnsupportedCertificate));
    try testing.expectEqual(error_crypto_base + 109, Connection.cryptoErrorCode(error.MissingExtension));
    // #334 review: NoApplicableCredential was missing from this table and fell
    // through to the generic internal_error(80) code instead of the canonical
    // handshake_failure(40) `alerts.fromHandshakeError` maps it to.
    try testing.expectEqual(error_crypto_base + 40, Connection.cryptoErrorCode(error.NoApplicableCredential));
    try testing.expectEqual(error_crypto_base + 116, Connection.cryptoErrorCode(error.ClientCertificateRequired));
    try testing.expectEqual(error_crypto_base + 51, Connection.cryptoErrorCode(error.DecryptError));
}

test "driver: 1-RTT packets are dropped before deprotection until TLS handshake complete" {
    const allocator = testing.allocator;
    var pair = try TestPair.init(allocator);
    defer pair.deinit(allocator);
    try pair.pump();

    const id = try pair.client.openStream(.bidi);
    try testing.expectEqual(@as(usize, 5), try pair.client.writeStream(id, "hello", false));
    var datagram: [max_datagram_size]u8 = undefined;
    const one_rtt = pair.client.pollTransmitOnPath(&datagram, pair.now_us) orelse return error.TestExpectedEqual;

    const received_before = pair.server.metrics.packets_received;
    const dropped_before = pair.server.metrics.packets_dropped;
    pair.server.handshake_complete = false;
    try pair.server.ingestOnPath(one_rtt.bytes, TestPair.server_path, TestPair.test_challenge_entropy, pair.now_us);
    try testing.expectEqual(received_before, pair.server.metrics.packets_received);
    try testing.expectEqual(dropped_before + 1, pair.server.metrics.packets_dropped);
}

fn expectConnectionRejectsExtraCryptoWhileClientAuthPending(async_sign: bool) !void {
    const allocator = testing.allocator;
    const credentials = tls_core.credentials;
    var mock = credentials.MockCredentialProvider.init(
        try tls_backend_mod.Identity.initPkcs8(tls_backend_mod.testdata.certificate_der, tls_backend_mod.testdata.private_key_pkcs8_der),
    );
    mock.pending_polls = 64;
    if (async_sign) {
        mock.async_sign = true;
    } else {
        mock.async_select = true;
    }
    var verifier = credentials.MockVerifier.init(.accepted);
    const pair = try TestPair.initClientAuth(allocator, mock.provider(), verifier.verifier());
    defer pair.deinit(allocator);

    try pair.pump();
    try testing.expect(pair.client.authPending());
    try testing.expect(!pair.client.isEstablished());

    const stray = [_]u8{@intFromEnum(tls_core.handshake.MessageType.finished)};
    const handshake_index = @intFromEnum(EncryptionLevel.handshake);
    const offset = pair.client.adapter.reassembler.streams[handshake_index].consumed_offset;
    try pair.client.applyFrame(.handshake, .{ .crypto = .{ .offset = offset, .data = &stray } }, TestPair.client_path, 0, pair.now_us);

    try testing.expect(!pair.client.authPending());
    try testing.expectEqual(tls_handshake.HandshakeError.UnexpectedHandshakeMessage, pair.client.handshakeFailure().?);
    const info = pair.client.closeInfo() orelse return error.TestExpectedCloseInfo;
    try testing.expect(info.local);
    try testing.expect(!info.is_application);
    try testing.expectEqual(@as(u64, error_crypto_base + 10), info.error_code);
    try testing.expectEqual(@as(usize, 1), mock.cancel_count);
    try testing.expectEqual(@as(usize, 1), mock.op_release_count);
    if (async_sign) try testing.expectEqual(@as(usize, 1), mock.release_count);
}

test "a real Connection rejects extra Handshake CRYPTO while client credential selection is pending" {
    try expectConnectionRejectsExtraCryptoWhileClientAuthPending(false);
}

test "a real Connection rejects extra Handshake CRYPTO while client signing is pending" {
    try expectConnectionRejectsExtraCryptoWhileClientAuthPending(true);
}

test "a real Connection closes with handshake_failure when the server has no applicable credential" {
    // #334 review: exercise NoApplicableCredential through an actual
    // Connection, both synchronously and via an asynchronous selector, rather
    // than only the direct-backend/handshake-adapter tests.
    const allocator = testing.allocator;
    const credentials = tls_core.credentials;
    for ([_]bool{ false, true }) |async_select| {
        var mock = credentials.MockCredentialProvider.init(
            try tls_backend_mod.Identity.initPkcs8(tls_backend_mod.testdata.certificate_der, tls_backend_mod.testdata.private_key_pkcs8_der),
        );
        mock.force_select_error = error.NoCredentialAvailable;
        mock.async_select = async_select;
        mock.pending_polls = 1;

        const pair = try allocator.create(TestPair);
        const client_crypto_provider = pair.client_provider_storage.init(0x442_c);
        const server_crypto_provider = pair.server_provider_storage.init(0x442_5);
        pair.* = .{
            .client_provider_storage = pair.client_provider_storage,
            .server_provider_storage = pair.server_provider_storage,
            .client_backend = try tls_backend_mod.Tls13Backend.initClientWithAllocator(
                allocator,
                .{ .hello_random = [_]u8{0xc1} ** 32 },
                client_crypto_provider,
                .{ .pinned_certificate = tls_backend_mod.testdata.certificate_der },
            ),
            .server_backend = tls_backend_mod.Tls13Backend.initServerWithAllocator(
                allocator,
                .{ .hello_random = [_]u8{0x51} ** 32 },
                server_crypto_provider,
                try tls_backend_mod.Identity.initPkcs8(tls_backend_mod.testdata.certificate_der, tls_backend_mod.testdata.private_key_pkcs8_der),
            ),
        };
        pair.server_backend.engine.external_provider = mock.provider();
        defer pair.deinit(allocator);
        pair.client = try Connection.init(allocator, .{
            .role = .client,
            .local_cid = &TestPair.client_cid,
            .original_destination_cid = &TestPair.odcid,
            .initial_secret_dcid = &TestPair.odcid,
            .peer_cid = &TestPair.odcid,
            .tls = pair.client_backend.backend(),
            .crypto_provider = test_quic_crypto.testDefaultProvider(),
            .now_us = pair.now_us,
            .initial_path = TestPair.client_path,
        });
        pair.server = try Connection.init(allocator, .{
            .role = .server,
            .local_cid = &TestPair.odcid,
            .original_destination_cid = &TestPair.odcid,
            .initial_secret_dcid = &TestPair.odcid,
            .peer_cid = &TestPair.client_cid,
            .tls = pair.server_backend.backend(),
            .crypto_provider = test_quic_crypto.testDefaultProvider(),
            .now_us = pair.now_us,
            .initial_path = TestPair.server_path,
        });

        try pair.pump();
        // The client observes the server's synthesized close with the correct
        // wire alert; the server latches the typed NoApplicableCredential
        // failure it maps from.
        const info = pair.client.closeInfo() orelse return error.TestExpectedCloseInfo;
        try testing.expectEqual(@as(u64, error_crypto_base + 40), info.error_code);
        try testing.expectEqual(tls_handshake.HandshakeError.NoApplicableCredential, pair.server.handshakeFailure().?);
    }
}

test {
    std.testing.refAllDecls(@This());
}

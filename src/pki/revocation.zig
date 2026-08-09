//! Certificate-status policy seam for CRLs, OCSP, stapling, and must-staple
//! (#349).
//!
//! This module decides what a path's *certificate-status evidence* means. It
//! never fetches anything: no socket, no file, no clock. Evidence arrives as
//! caller-supplied `StatusAssertion` values, and the validator turns them into
//! an explicit `Report` recording, per certificate, exactly what was checked
//! and what was not. Nothing here silently pretends revocation was checked.
//!
//! ## Why the seam looks like this
//!
//! Online revocation fetching is not implemented yet. Rather than leave the
//! question undefined, the policy is explicit and the default (`Mode.disabled`)
//! says so in the result: every entry is `not_checked_policy_disabled`, and a
//! must-staple certificate accepted under it sets `Report.must_staple_unenforced`.
//! An operator can therefore tell a "no revocation check happened" acceptance
//! from a "status was checked and is good" acceptance.
//!
//! A future OCSP/CRL fetch-and-cache provider produces `StatusAssertion`
//! values before validation runs — see `Provider`. That keeps network I/O,
//! caching, and responder-signature verification outside both the TLS
//! handshake and the path-validation API, which is why adding one later
//! changes no signature in `path_validator`.
//!
//! ## Trust boundary
//!
//! `StatusAssertion.signature_verified` is asserted by whoever produced the
//! evidence, not by this module: verifying an OCSP responder signature needs
//! its own delegated-responder path validation, and CRL verification needs the
//! CRL issuer's key. With `Configuration.require_signature_verified` (the
//! default), unverified evidence never counts as a completed check — a peer
//! cannot manufacture a "good" status by stapling bytes nobody authenticated.
//! A *revoked* assertion is honored even when unverified: the only party that
//! can supply attacker-chosen stapled bytes is the peer being authenticated,
//! and revoking itself is not an attack worth defending against.

const std = @import("std");
const path_builder = @import("path_builder.zig");
const x509 = @import("x509.zig");

/// Certificate-status policy. Ordered from least to most demanding.
pub const Mode = enum {
    /// No status is consulted. Explicitly recorded in the report; must-staple
    /// is not enforced because no evidence channel exists in this mode.
    disabled,
    /// Only stapled evidence is consulted. Absent stapling is accepted (and
    /// recorded); stapled evidence that is present but unusable is rejected.
    stapled_only,
    /// All supplied evidence is consulted. Revoked rejects; missing, stale,
    /// defective, or unknown status is recorded and accepted.
    soft_fail,
    /// Every non-anchor certificate needs usable, good status evidence.
    strict,
};

/// Where a status assertion came from. Precedence for selection is the
/// declaration order: fresher, peer-delivered stapled evidence outranks a
/// cache, which outranks a periodically distributed CRL set.
pub const Source = enum {
    stapled_ocsp,
    cached_ocsp,
    crl_set,
};

pub const Status = enum { good, revoked, unknown };

/// RFC 5280 §5.3.1 CRLReason values, carried through for logging and for
/// operators who treat `certificate_hold` differently from a key compromise.
pub const CrlReason = enum(u8) {
    unspecified = 0,
    key_compromise = 1,
    ca_compromise = 2,
    affiliation_changed = 3,
    superseded = 4,
    cessation_of_operation = 5,
    certificate_hold = 6,
    remove_from_crl = 8,
    privilege_withdrawn = 9,
    aa_compromise = 10,
};

/// Why supplied evidence cannot be used at all. Reported by the producing
/// provider; this module never decodes an OCSP response or a CRL.
pub const Defect = enum {
    malformed_encoding,
    unsupported_response_type,
    responder_not_authorized,
    signature_invalid,
    /// The evidence covers a different certificate than it was filed under.
    identity_mismatch,
    /// The responder answered with an error status (RFC 6960 §2.3).
    responder_error,
};

/// One certificate-status assertion supplied by the caller. Timestamps are
/// Unix seconds on the same scale as `validation_time`; all are optional
/// because CRL sets and cache entries do not all carry every field.
pub const StatusAssertion = struct {
    /// Leaf-first index of the certificate this assertion covers.
    certificate_index: usize,
    source: Source,
    status: Status = .unknown,
    /// Set when the evidence could not be interpreted. A defective assertion
    /// never contributes a status, whatever `status` says.
    defect: ?Defect = null,
    revocation_reason: ?CrlReason = null,
    revoked_at: ?i64 = null,
    this_update: ?i64 = null,
    next_update: ?i64 = null,
    produced_at: ?i64 = null,
    /// True only when the producer verified the responder or CRL signature
    /// against an issuer authorized to answer for this certificate.
    signature_verified: bool = false,
    /// Borrowed encoded evidence, retained for logging and future
    /// implementations. Never decoded here.
    raw: []const u8 = &.{},
};

/// The per-connection status evidence available to one validation.
pub const Evidence = struct {
    /// Borrowed for the evaluation call.
    assertions: []const StatusAssertion = &.{},

    pub fn stapledFor(self: Evidence, certificate_index: usize) ?*const StatusAssertion {
        for (self.assertions) |*assertion| {
            if (assertion.source == .stapled_ocsp and assertion.certificate_index == certificate_index) {
                return assertion;
            }
        }
        return null;
    }
};

pub const Freshness = struct {
    /// Tolerance applied on both sides of every timestamp comparison.
    clock_skew_seconds: i64 = 300,
    /// Maximum accepted age of `this_update`. Null accepts any age, which
    /// also means an assertion without `this_update` stays usable.
    maximum_age_seconds: ?i64 = 7 * 24 * 60 * 60,
    /// RFC 6960 §2.4 permits an absent nextUpdate, but evidence with no stated
    /// expiry cannot be aged out of a cache, so it is unusable by default.
    require_next_update: bool = true,
};

pub const Limits = struct {
    maximum_assertions: usize = 64,
    /// Bounds the retained `raw` evidence a caller may attach per assertion.
    maximum_evidence_bytes: usize = 64 * 1024,
};

pub const Configuration = struct {
    mode: Mode = .disabled,
    freshness: Freshness = .{},
    /// Treat evidence nobody authenticated as unusable. Turning this off makes
    /// a "good" status assertable by whoever supplies the bytes.
    require_signature_verified: bool = true,
    /// Honor RFC 7633 must-staple. Has no effect in `.disabled` mode, which
    /// records `Report.must_staple_unenforced` instead.
    enforce_must_staple: bool = true,
    limits: Limits = .{},
};

/// What the policy concluded for one certificate. Every acceptance carries one
/// of these per non-anchor certificate, so "not checked" is always visible.
pub const Determination = enum {
    not_checked_policy_disabled,
    /// The certificate publishes neither an OCSP responder nor a CRL
    /// distribution point, so no provider could ever obtain status for it.
    not_checked_no_status_source,
    not_checked_no_evidence,
    not_checked_defective_evidence,
    not_checked_stale_evidence,
    not_checked_unauthenticated_evidence,
    /// Usable evidence that asserts neither good nor revoked.
    not_checked_status_unknown,
    checked_good,
    checked_revoked,

    pub fn isChecked(self: Determination) bool {
        return self == .checked_good or self == .checked_revoked;
    }
};

pub const Entry = struct {
    certificate_index: usize,
    determination: Determination,
    /// The assertion the determination came from, when one was consulted.
    source: ?Source = null,
    defect: ?Defect = null,
    revocation_reason: ?CrlReason = null,
    this_update: ?i64 = null,
    next_update: ?i64 = null,
    /// This certificate asserts RFC 7633 must-staple.
    must_staple: bool = false,
};

/// The status evidence that was actually consulted for an accepted path.
pub const Report = struct {
    mode: Mode,
    /// Owned, leaf-first, one entry per non-anchor certificate.
    entries: []const Entry,
    /// A must-staple certificate was accepted without the assertion being
    /// enforced, because status checking is disabled.
    must_staple_unenforced: bool,

    pub fn deinit(self: *Report, allocator: std.mem.Allocator) void {
        allocator.free(self.entries);
        self.* = undefined;
    }

    /// True when every non-anchor certificate has a completed status check.
    pub fn allChecked(self: *const Report) bool {
        for (self.entries) |entry| {
            if (!entry.determination.isChecked()) return false;
        }
        return self.entries.len != 0;
    }

    pub fn entryFor(self: *const Report, certificate_index: usize) ?*const Entry {
        for (self.entries) |*entry| {
            if (entry.certificate_index == certificate_index) return entry;
        }
        return null;
    }
};

pub const FailureReason = enum {
    certificate_revoked,
    /// The mode requires a status answer and none was usable.
    status_unavailable,
    status_stale,
    status_malformed,
    status_unauthenticated,
    must_staple_not_satisfied,
    /// The certificate publishes no revocation mechanism at all, so a strict
    /// policy can never be satisfied for it.
    status_source_unsupported,
    /// The caller filed evidence against a certificate index the path does not
    /// contain, or against the trust anchor.
    evidence_index_invalid,
    resource_limit_exceeded,
    out_of_memory,
};

pub const Failure = struct {
    reason: FailureReason,
    /// Leaf-first index; null when no certificate can be identified.
    certificate_index: ?usize,
    source: ?Source = null,
    defect: ?Defect = null,
    revocation_reason: ?CrlReason = null,
};

pub const Outcome = union(enum) {
    accepted: Report,
    rejected: Failure,
};

/// Interface for a future fetch-and-cache status provider. Implementations run
/// *before* validation and hand back evidence; the validator itself never
/// calls one, which is what keeps ambient network I/O out of path validation.
/// The returned assertions borrow storage the implementation owns and must
/// outlive the validation call.
pub const Provider = struct {
    context: *const anyopaque,
    vtable: *const VTable,

    pub const Request = struct {
        /// Leaf-first path the caller is about to validate.
        path: path_builder.Path,
        /// Unix seconds the caller will validate at.
        validation_time: i64,
        /// Status responses the peer delivered in-band (TLS stapling).
        stapled: []const StatusAssertion = &.{},
    };

    pub const VTable = struct {
        collect: *const fn (
            context: *const anyopaque,
            allocator: std.mem.Allocator,
            request: Request,
        ) error{OutOfMemory}!Evidence,
    };

    pub fn collect(
        self: Provider,
        allocator: std.mem.Allocator,
        request: Request,
    ) error{OutOfMemory}!Evidence {
        return self.vtable.collect(self.context, allocator, request);
    }
};

/// Evaluate certificate-status policy over one leaf-first, anchor-last path.
///
/// The terminal trust anchor is excluded: an anchor's revocation status is
/// trust configuration, removed by editing the trust store, not by consulting
/// a responder the anchor itself would name.
pub fn evaluatePath(
    allocator: std.mem.Allocator,
    path: path_builder.Path,
    config: Configuration,
    evidence: Evidence,
    validation_time: i64,
) Outcome {
    if (path.elements.len < 2) {
        return .{ .rejected = .{ .reason = .evidence_index_invalid, .certificate_index = null } };
    }
    const certificate_count = path.elements.len - 1;

    if (evidence.assertions.len > config.limits.maximum_assertions) {
        return .{ .rejected = .{ .reason = .resource_limit_exceeded, .certificate_index = null } };
    }
    for (evidence.assertions) |assertion| {
        if (assertion.raw.len > config.limits.maximum_evidence_bytes) {
            return .{ .rejected = .{
                .reason = .resource_limit_exceeded,
                .certificate_index = assertion.certificate_index,
                .source = assertion.source,
            } };
        }
        if (assertion.certificate_index >= certificate_count) {
            return .{ .rejected = .{
                .reason = .evidence_index_invalid,
                .certificate_index = assertion.certificate_index,
                .source = assertion.source,
            } };
        }
    }

    // RFC 7633 §4.2.3: a CA asserting the feature obliges the certificates it
    // issues, so any must-staple assertion in the path binds the leaf.
    var must_staple_required = false;
    for (path.elements[0..certificate_count]) |element| {
        if (element.certificate.mustStaple()) must_staple_required = true;
    }

    const entries = allocator.alloc(Entry, certificate_count) catch {
        return .{ .rejected = .{ .reason = .out_of_memory, .certificate_index = null } };
    };

    for (path.elements[0..certificate_count], 0..) |element, certificate_index| {
        entries[certificate_index] = .{
            .certificate_index = certificate_index,
            .determination = .not_checked_policy_disabled,
            .must_staple = element.certificate.mustStaple(),
        };
    }

    if (config.mode == .disabled) {
        return .{ .accepted = .{
            .mode = config.mode,
            .entries = entries,
            .must_staple_unenforced = must_staple_required,
        } };
    }

    for (path.elements[0..certificate_count], 0..) |element, certificate_index| {
        const selection = select(evidence, certificate_index, config, validation_time);
        var entry = &entries[certificate_index];
        entry.source = selection.source;
        entry.defect = selection.defect;
        entry.revocation_reason = selection.revocation_reason;
        entry.this_update = selection.this_update;
        entry.next_update = selection.next_update;
        entry.determination = determination(selection, element.certificate);

        if (rejectionFor(entry.*, config.mode)) |failure| {
            allocator.free(entries);
            return .{ .rejected = failure };
        }
    }

    if (must_staple_required and config.enforce_must_staple) {
        const leaf_entry = entries[0];
        const satisfied = leaf_entry.source == .stapled_ocsp and
            leaf_entry.determination == .checked_good;
        if (!satisfied) {
            const failure = Failure{
                .reason = .must_staple_not_satisfied,
                .certificate_index = 0,
                .source = leaf_entry.source,
                .defect = leaf_entry.defect,
            };
            allocator.free(entries);
            return .{ .rejected = failure };
        }
    }

    return .{ .accepted = .{
        .mode = config.mode,
        .entries = entries,
        .must_staple_unenforced = false,
    } };
}

/// Why a usable-looking assertion could not be used.
const Blocker = enum { defective, unauthenticated, stale };

const Selection = struct {
    source: ?Source = null,
    status: ?Status = null,
    blocker: ?Blocker = null,
    defect: ?Defect = null,
    revocation_reason: ?CrlReason = null,
    this_update: ?i64 = null,
    next_update: ?i64 = null,
};

/// Choose the assertion that decides this certificate.
///
/// Revoked wins over everything, from any consulted source, so that a second
/// source cannot launder a revocation away. Otherwise the highest-precedence
/// source with a usable answer decides; when nothing is usable, the
/// highest-precedence blocked assertion is reported so the operator learns why.
fn select(
    evidence: Evidence,
    certificate_index: usize,
    config: Configuration,
    validation_time: i64,
) Selection {
    var best: Selection = .{};
    var best_rank: usize = std.math.maxInt(usize);
    var blocked: Selection = .{};
    var blocked_rank: usize = std.math.maxInt(usize);

    for (evidence.assertions) |assertion| {
        if (assertion.certificate_index != certificate_index) continue;
        if (!consults(config.mode, assertion.source)) continue;

        const candidate = Selection{
            .source = assertion.source,
            .status = assertion.status,
            .defect = assertion.defect,
            .revocation_reason = assertion.revocation_reason,
            .this_update = assertion.this_update,
            .next_update = assertion.next_update,
        };

        if (assertion.defect) |defect| {
            const rank = sourceRank(assertion.source);
            if (rank < blocked_rank) {
                blocked_rank = rank;
                blocked = candidate;
                blocked.status = null;
                blocked.blocker = .defective;
                blocked.defect = defect;
            }
            continue;
        }

        // Revocation is honored even from stale or unauthenticated evidence:
        // ignoring it could only ever help a certificate its own issuer has
        // withdrawn. See the trust-boundary note at the top of this file.
        if (assertion.status == .revoked) {
            var revoked = candidate;
            revoked.status = .revoked;
            return revoked;
        }

        if (config.require_signature_verified and !assertion.signature_verified) {
            const rank = sourceRank(assertion.source);
            if (rank < blocked_rank) {
                blocked_rank = rank;
                blocked = candidate;
                blocked.status = null;
                blocked.blocker = .unauthenticated;
            }
            continue;
        }

        if (!isFresh(assertion, config.freshness, validation_time)) {
            const rank = sourceRank(assertion.source);
            if (rank < blocked_rank) {
                blocked_rank = rank;
                blocked = candidate;
                blocked.status = null;
                blocked.blocker = .stale;
            }
            continue;
        }

        // Prefer the highest-precedence source, and a definite answer over an
        // `unknown` from the same source.
        const rank = sourceRank(assertion.source) * 2 + @intFromBool(assertion.status == .unknown);
        if (rank < best_rank) {
            best_rank = rank;
            best = candidate;
        }
    }

    if (best.status != null) return best;
    return blocked;
}

fn consults(mode: Mode, source: Source) bool {
    return switch (mode) {
        .disabled => false,
        .stapled_only => source == .stapled_ocsp,
        .soft_fail, .strict => true,
    };
}

fn sourceRank(source: Source) usize {
    return @intFromEnum(source);
}

fn isFresh(assertion: StatusAssertion, freshness: Freshness, validation_time: i64) bool {
    const skew = freshness.clock_skew_seconds;

    if (assertion.this_update) |this_update| {
        if (this_update -| skew > validation_time) return false;
        if (freshness.maximum_age_seconds) |maximum_age| {
            if (validation_time -| this_update > maximum_age +| skew) return false;
        }
    } else if (freshness.maximum_age_seconds != null) {
        // Age cannot be bounded without a stated issuance time.
        return false;
    }

    if (assertion.next_update) |next_update| {
        if (validation_time > next_update +| skew) return false;
        if (assertion.this_update) |this_update| {
            if (next_update < this_update) return false;
        }
    } else if (freshness.require_next_update) {
        return false;
    }

    return true;
}

fn determination(selection: Selection, certificate: *const x509.Certificate) Determination {
    if (selection.status) |status| {
        return switch (status) {
            .good => .checked_good,
            .revoked => .checked_revoked,
            .unknown => .not_checked_status_unknown,
        };
    }
    if (selection.blocker) |blocker| {
        return switch (blocker) {
            .defective => .not_checked_defective_evidence,
            .unauthenticated => .not_checked_unauthenticated_evidence,
            .stale => .not_checked_stale_evidence,
        };
    }
    if (!publishesStatusSource(certificate)) return .not_checked_no_status_source;
    return .not_checked_no_evidence;
}

fn publishesStatusSource(certificate: *const x509.Certificate) bool {
    if (certificate.hasOcspResponder()) return true;
    const points = certificate.crlDistributionPoints() orelse return false;
    return points.len != 0;
}

/// Map one certificate's determination to a rejection, if the mode demands it.
///
/// `stapled_only` deliberately accepts *absent* stapling — the peer never
/// promised any — but rejects stapling that is present and unusable, because
/// that is a broken promise rather than a missing one.
fn rejectionFor(entry: Entry, mode: Mode) ?Failure {
    const failure = Failure{
        .reason = .status_unavailable,
        .certificate_index = entry.certificate_index,
        .source = entry.source,
        .defect = entry.defect,
        .revocation_reason = entry.revocation_reason,
    };

    if (entry.determination == .checked_revoked) {
        var revoked = failure;
        revoked.reason = .certificate_revoked;
        return revoked;
    }
    if (entry.determination == .checked_good) return null;

    const evidence_present = entry.source != null;
    const enforce = switch (mode) {
        .disabled => false,
        .stapled_only => evidence_present,
        .soft_fail => false,
        .strict => true,
    };
    if (!enforce) return null;

    var rejected = failure;
    rejected.reason = switch (entry.determination) {
        .not_checked_defective_evidence => .status_malformed,
        .not_checked_stale_evidence => .status_stale,
        .not_checked_unauthenticated_evidence => .status_unauthenticated,
        .not_checked_no_status_source => .status_source_unsupported,
        else => .status_unavailable,
    };
    return rejected;
}

const testing = std.testing;

test "freshness bounds accept only evidence inside the stated window" {
    const now: i64 = 1_000_000;
    const freshness = Freshness{};
    try testing.expect(isFresh(.{
        .certificate_index = 0,
        .source = .stapled_ocsp,
        .this_update = now - 60,
        .next_update = now + 3600,
    }, freshness, now));
    try testing.expect(!isFresh(.{
        .certificate_index = 0,
        .source = .stapled_ocsp,
        .this_update = now - 60,
        .next_update = now - 3600,
    }, freshness, now));
    try testing.expect(!isFresh(.{
        .certificate_index = 0,
        .source = .stapled_ocsp,
        .this_update = now + 3600,
        .next_update = now + 7200,
    }, freshness, now));
    try testing.expect(!isFresh(.{
        .certificate_index = 0,
        .source = .stapled_ocsp,
        .this_update = now - 60,
    }, freshness, now));
    try testing.expect(!isFresh(.{
        .certificate_index = 0,
        .source = .stapled_ocsp,
        .next_update = now + 3600,
    }, freshness, now));
    // nextUpdate before thisUpdate is incoherent regardless of the window.
    try testing.expect(!isFresh(.{
        .certificate_index = 0,
        .source = .stapled_ocsp,
        .this_update = now - 60,
        .next_update = now - 120,
    }, .{ .clock_skew_seconds = 86_400 }, now));
}

test "clock skew is applied on both sides of the window" {
    const now: i64 = 1_000_000;
    const freshness = Freshness{ .clock_skew_seconds = 300 };
    try testing.expect(isFresh(.{
        .certificate_index = 0,
        .source = .stapled_ocsp,
        .this_update = now + 200,
        .next_update = now + 3600,
    }, freshness, now));
    // Expired by less than the skew allowance is still usable.
    try testing.expect(isFresh(.{
        .certificate_index = 0,
        .source = .stapled_ocsp,
        .this_update = now - 400,
        .next_update = now - 200,
    }, freshness, now));
}

test {
    testing.refAllDecls(@This());
}

//! Certificate-status policy fixtures (#349).
//!
//! These exercise `revocation.evaluatePath` directly, so the certificates only
//! have to parse — signatures are validated one layer up, in
//! `path_validator_tests.zig`, which also covers the wired-through policy.

const std = @import("std");
const der = @import("der.zig");
const oid = @import("oid.zig");
const path_builder = @import("path_builder.zig");
const revocation = @import("revocation.zig");
const x509 = @import("x509.zig");

const testing = std.testing;
const validation_time: i64 = 1_782_864_000; // 2026-07-01T00:00:00Z

fn tlv(arena: std.mem.Allocator, tag: u8, parts: []const []const u8) ![]u8 {
    var total: usize = 0;
    for (parts) |part| total += part.len;
    var len_buf: [9]u8 = undefined;
    const len_len = try der.encodeLength(total, &len_buf);
    const out = try arena.alloc(u8, 1 + len_len + total);
    out[0] = tag;
    @memcpy(out[1 .. 1 + len_len], len_buf[0..len_len]);
    var offset = 1 + len_len;
    for (parts) |part| {
        @memcpy(out[offset .. offset + part.len], part);
        offset += part.len;
    }
    return out;
}

fn oidTlv(arena: std.mem.Allocator, components: []const u32) ![]u8 {
    var buffer: [64]u8 = undefined;
    const len = try oid.encodeComponents(components, &buffer);
    return tlv(arena, 0x06, &.{buffer[0..len]});
}

fn algorithmEd25519(arena: std.mem.Allocator) ![]u8 {
    return tlv(arena, 0x30, &.{try oidTlv(arena, &oid.well_known.ed25519)});
}

fn nameWithCn(arena: std.mem.Allocator, common_name: []const u8) ![]u8 {
    const attribute = try tlv(arena, 0x30, &.{
        try oidTlv(arena, &oid.well_known.common_name),
        try tlv(arena, 0x0c, &.{common_name}),
    });
    return tlv(arena, 0x30, &.{try tlv(arena, 0x31, &.{attribute})});
}

fn extensionTlv(arena: std.mem.Allocator, components: []const u32, critical: bool, value: []const u8) ![]u8 {
    if (critical) {
        return tlv(arena, 0x30, &.{
            try oidTlv(arena, components),
            try tlv(arena, 0x01, &.{&[_]u8{0xff}}),
            try tlv(arena, 0x04, &.{value}),
        });
    }
    return tlv(arena, 0x30, &.{
        try oidTlv(arena, components),
        try tlv(arena, 0x04, &.{value}),
    });
}

const StatusSource = enum { none, ocsp, crl, both };

const Spec = struct {
    subject: []const u8,
    issuer: []const u8,
    ca: bool = false,
    status_source: StatusSource = .ocsp,
    tls_features: ?[]const u16 = null,
    raw_tls_features: ?[]const u8 = null,
    tls_features_critical: bool = false,
};

const Fixtures = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    certs: std.ArrayList(x509.Certificate) = .empty,

    fn init(allocator: std.mem.Allocator) Fixtures {
        return .{ .allocator = allocator, .arena = std.heap.ArenaAllocator.init(allocator) };
    }

    fn deinit(self: *Fixtures) void {
        for (self.certs.items) |*certificate| certificate.deinit(self.allocator);
        self.certs.deinit(self.allocator);
        self.arena.deinit();
        self.* = undefined;
    }

    fn add(self: *Fixtures, spec: Spec) !void {
        const arena = self.arena.allocator();
        var extensions: std.ArrayList([]const u8) = .empty;
        defer extensions.deinit(arena);

        try extensions.append(arena, try extensionTlv(
            arena,
            &oid.well_known.basic_constraints,
            true,
            if (spec.ca)
                try tlv(arena, 0x30, &.{try tlv(arena, 0x01, &.{&[_]u8{0xff}})})
            else
                try tlv(arena, 0x30, &.{}),
        ));

        if (spec.status_source == .ocsp or spec.status_source == .both) {
            const description = try tlv(arena, 0x30, &.{
                try oidTlv(arena, &oid.well_known.aia_ocsp),
                try tlv(arena, 0x86, &.{"http://ocsp.example.com"}),
            });
            try extensions.append(arena, try extensionTlv(
                arena,
                &oid.well_known.authority_info_access,
                false,
                try tlv(arena, 0x30, &.{description}),
            ));
        }
        if (spec.status_source == .crl or spec.status_source == .both) {
            const full_name = try tlv(arena, 0xa0, &.{
                try tlv(arena, 0xa0, &.{try tlv(arena, 0x86, &.{"http://crl.example.com/a.crl"})}),
            });
            try extensions.append(arena, try extensionTlv(
                arena,
                &oid.well_known.crl_distribution_points,
                false,
                try tlv(arena, 0x30, &.{try tlv(arena, 0x30, &.{full_name})}),
            ));
        }
        if (spec.tls_features) |features| {
            var parts: std.ArrayList([]const u8) = .empty;
            defer parts.deinit(arena);
            for (features) |feature| {
                try parts.append(arena, try tlv(arena, 0x02, &.{try integerContent(arena, feature)}));
            }
            try extensions.append(arena, try extensionTlv(
                arena,
                &oid.well_known.tls_feature,
                spec.tls_features_critical,
                try tlv(arena, 0x30, parts.items),
            ));
        }
        if (spec.raw_tls_features) |value| {
            try extensions.append(arena, try extensionTlv(
                arena,
                &oid.well_known.tls_feature,
                spec.tls_features_critical,
                value,
            ));
        }

        var tbs_parts: std.ArrayList([]const u8) = .empty;
        defer tbs_parts.deinit(arena);
        try tbs_parts.append(arena, try tlv(arena, 0xa0, &.{try tlv(arena, 0x02, &.{&[_]u8{2}})}));
        const serial: u8 = @intCast(self.certs.items.len + 1);
        try tbs_parts.append(arena, try tlv(arena, 0x02, &.{&[_]u8{serial}}));
        try tbs_parts.append(arena, try algorithmEd25519(arena));
        try tbs_parts.append(arena, try nameWithCn(arena, spec.issuer));
        try tbs_parts.append(arena, try tlv(arena, 0x30, &.{
            try tlv(arena, 0x17, &.{"260101000000Z"}),
            try tlv(arena, 0x17, &.{"270101000000Z"}),
        }));
        try tbs_parts.append(arena, try nameWithCn(arena, spec.subject));
        const public_key = [_]u8{0} ** 33;
        try tbs_parts.append(arena, try tlv(arena, 0x30, &.{
            try algorithmEd25519(arena),
            try tlv(arena, 0x03, &.{&public_key}),
        }));
        try tbs_parts.append(arena, try tlv(arena, 0xa3, &.{try tlv(arena, 0x30, extensions.items)}));

        const signature = [_]u8{0} ** 65;
        const certificate_der = try tlv(arena, 0x30, &.{
            try tlv(arena, 0x30, tbs_parts.items),
            try algorithmEd25519(arena),
            try tlv(arena, 0x03, &.{&signature}),
        });

        const certificate = try x509.Certificate.parse(self.allocator, certificate_der, .{});
        errdefer {
            var owned = certificate;
            owned.deinit(self.allocator);
        }
        try self.certs.append(self.allocator, certificate);
    }

    fn path(self: *Fixtures, storage: []path_builder.Element) path_builder.Path {
        for (self.certs.items, 0..) |*certificate, index| {
            storage[index] = .{
                .certificate = certificate,
                .source = if (index == 0)
                    .leaf
                else if (index == self.certs.items.len - 1)
                    .anchor
                else
                    .intermediate,
                .input_index = if (index == 0) 0 else index - 1,
            };
        }
        return .{ .elements = storage[0..self.certs.items.len] };
    }
};

fn integerContent(arena: std.mem.Allocator, value: u16) ![]const u8 {
    var encoded: [3]u8 = undefined;
    encoded[0] = 0;
    std.mem.writeInt(u16, encoded[1..3], value, .big);
    var first: usize = 1;
    while (first < 2 and encoded[first] == 0) first += 1;
    if (encoded[first] & 0x80 != 0) first -= 1;
    return arena.dupe(u8, encoded[first..]);
}

/// leaf → anchor, leaf publishing the requested status source.
fn twoCertPath(fx: *Fixtures, storage: []path_builder.Element, leaf: Spec) !path_builder.Path {
    try fx.add(leaf);
    try fx.add(.{ .subject = "Root", .issuer = "Root", .ca = true, .status_source = .none });
    return fx.path(storage);
}

fn expectAccepted(outcome: *revocation.Outcome) !revocation.Report {
    switch (outcome.*) {
        .accepted => |report| return report,
        .rejected => |failure| {
            std.debug.print("unexpected status rejection: {s} at {?}\n", .{ @tagName(failure.reason), failure.certificate_index });
            return error.TestUnexpectedResult;
        },
    }
}

fn expectRejected(
    outcome: revocation.Outcome,
    reason: revocation.FailureReason,
    certificate_index: ?usize,
) !void {
    switch (outcome) {
        .accepted => return error.TestUnexpectedResult,
        .rejected => |failure| {
            try testing.expectEqual(reason, failure.reason);
            try testing.expectEqual(certificate_index, failure.certificate_index);
        },
    }
}

fn stapled(status: revocation.Status) revocation.StatusAssertion {
    return .{
        .certificate_index = 0,
        .source = .stapled_ocsp,
        .status = status,
        .signature_verified = true,
        .this_update = validation_time - 3600,
        .next_update = validation_time + 3600,
    };
}

test "disabled policy records that nothing was checked" {
    const allocator = testing.allocator;
    var fx = Fixtures.init(allocator);
    defer fx.deinit();
    var storage: [4]path_builder.Element = undefined;
    const path = try twoCertPath(&fx, &storage, .{ .subject = "leaf", .issuer = "Root" });

    var outcome = revocation.evaluatePath(allocator, path, .{}, .{}, validation_time);
    var report = try expectAccepted(&outcome);
    defer report.deinit(allocator);

    try testing.expectEqual(revocation.Mode.disabled, report.mode);
    // One entry per non-anchor certificate; the anchor is trust configuration.
    try testing.expectEqual(@as(usize, 1), report.entries.len);
    try testing.expectEqual(revocation.Determination.not_checked_policy_disabled, report.entries[0].determination);
    try testing.expect(!report.allChecked());
    try testing.expect(!report.must_staple_unenforced);
}

test "stapled good status is recorded as a completed check" {
    const allocator = testing.allocator;
    var fx = Fixtures.init(allocator);
    defer fx.deinit();
    var storage: [4]path_builder.Element = undefined;
    const path = try twoCertPath(&fx, &storage, .{ .subject = "leaf", .issuer = "Root" });

    const assertions = [_]revocation.StatusAssertion{stapled(.good)};
    for ([_]revocation.Mode{ .stapled_only, .soft_fail, .strict }) |mode| {
        var outcome = revocation.evaluatePath(
            allocator,
            path,
            .{ .mode = mode },
            .{ .assertions = &assertions },
            validation_time,
        );
        var report = try expectAccepted(&outcome);
        defer report.deinit(allocator);
        try testing.expectEqual(revocation.Determination.checked_good, report.entries[0].determination);
        try testing.expectEqual(revocation.Source.stapled_ocsp, report.entries[0].source.?);
        try testing.expect(report.allChecked());
    }
}

test "stapled revoked status rejects in every consulting mode" {
    const allocator = testing.allocator;
    var fx = Fixtures.init(allocator);
    defer fx.deinit();
    var storage: [4]path_builder.Element = undefined;
    const path = try twoCertPath(&fx, &storage, .{ .subject = "leaf", .issuer = "Root" });

    var assertion = stapled(.revoked);
    assertion.revocation_reason = .key_compromise;
    assertion.revoked_at = validation_time - 86_400;
    const assertions = [_]revocation.StatusAssertion{assertion};

    for ([_]revocation.Mode{ .stapled_only, .soft_fail, .strict }) |mode| {
        const outcome = revocation.evaluatePath(
            allocator,
            path,
            .{ .mode = mode },
            .{ .assertions = &assertions },
            validation_time,
        );
        try expectRejected(outcome, .certificate_revoked, 0);
        switch (outcome) {
            .rejected => |failure| try testing.expectEqual(revocation.CrlReason.key_compromise, failure.revocation_reason.?),
            .accepted => unreachable,
        }
    }
}

test "revoked evidence wins over a good answer from another source" {
    const allocator = testing.allocator;
    var fx = Fixtures.init(allocator);
    defer fx.deinit();
    var storage: [4]path_builder.Element = undefined;
    const path = try twoCertPath(&fx, &storage, .{ .subject = "leaf", .issuer = "Root" });

    var crl_revoked = stapled(.revoked);
    crl_revoked.source = .crl_set;
    const assertions = [_]revocation.StatusAssertion{ stapled(.good), crl_revoked };

    const outcome = revocation.evaluatePath(
        allocator,
        path,
        .{ .mode = .soft_fail },
        .{ .assertions = &assertions },
        validation_time,
    );
    try expectRejected(outcome, .certificate_revoked, 0);
}

test "revoked evidence is honored even when unauthenticated or stale" {
    const allocator = testing.allocator;
    var fx = Fixtures.init(allocator);
    defer fx.deinit();
    var storage: [4]path_builder.Element = undefined;
    const path = try twoCertPath(&fx, &storage, .{ .subject = "leaf", .issuer = "Root" });

    var unauthenticated = stapled(.revoked);
    unauthenticated.signature_verified = false;
    var stale = stapled(.revoked);
    stale.next_update = validation_time - 86_400;

    for ([_]revocation.StatusAssertion{ unauthenticated, stale }) |assertion| {
        const assertions = [_]revocation.StatusAssertion{assertion};
        const outcome = revocation.evaluatePath(
            allocator,
            path,
            .{ .mode = .soft_fail },
            .{ .assertions = &assertions },
            validation_time,
        );
        try expectRejected(outcome, .certificate_revoked, 0);
    }
}

test "missing status is accepted below strict and rejected by it" {
    const allocator = testing.allocator;
    var fx = Fixtures.init(allocator);
    defer fx.deinit();
    var storage: [4]path_builder.Element = undefined;
    const path = try twoCertPath(&fx, &storage, .{ .subject = "leaf", .issuer = "Root" });

    for ([_]revocation.Mode{ .stapled_only, .soft_fail }) |mode| {
        var outcome = revocation.evaluatePath(allocator, path, .{ .mode = mode }, .{}, validation_time);
        var report = try expectAccepted(&outcome);
        defer report.deinit(allocator);
        try testing.expectEqual(revocation.Determination.not_checked_no_evidence, report.entries[0].determination);
        try testing.expectEqual(@as(?revocation.Source, null), report.entries[0].source);
    }

    const outcome = revocation.evaluatePath(allocator, path, .{ .mode = .strict }, .{}, validation_time);
    try expectRejected(outcome, .status_unavailable, 0);
}

test "stale stapled evidence is rejected where stapling is consulted" {
    const allocator = testing.allocator;
    var fx = Fixtures.init(allocator);
    defer fx.deinit();
    var storage: [4]path_builder.Element = undefined;
    const path = try twoCertPath(&fx, &storage, .{ .subject = "leaf", .issuer = "Root" });

    var stale = stapled(.good);
    stale.this_update = validation_time - 30 * 86_400;
    stale.next_update = validation_time - 29 * 86_400;
    const assertions = [_]revocation.StatusAssertion{stale};

    for ([_]revocation.Mode{ .stapled_only, .strict }) |mode| {
        const outcome = revocation.evaluatePath(
            allocator,
            path,
            .{ .mode = mode },
            .{ .assertions = &assertions },
            validation_time,
        );
        try expectRejected(outcome, .status_stale, 0);
    }

    var outcome = revocation.evaluatePath(
        allocator,
        path,
        .{ .mode = .soft_fail },
        .{ .assertions = &assertions },
        validation_time,
    );
    var report = try expectAccepted(&outcome);
    defer report.deinit(allocator);
    try testing.expectEqual(revocation.Determination.not_checked_stale_evidence, report.entries[0].determination);
    try testing.expectEqual(stale.next_update, report.entries[0].next_update);
}

test "malformed stapled evidence is rejected where stapling is consulted" {
    const allocator = testing.allocator;
    var fx = Fixtures.init(allocator);
    defer fx.deinit();
    var storage: [4]path_builder.Element = undefined;
    const path = try twoCertPath(&fx, &storage, .{ .subject = "leaf", .issuer = "Root" });

    var malformed = stapled(.good);
    malformed.defect = .malformed_encoding;
    const assertions = [_]revocation.StatusAssertion{malformed};

    for ([_]revocation.Mode{ .stapled_only, .strict }) |mode| {
        const outcome = revocation.evaluatePath(
            allocator,
            path,
            .{ .mode = mode },
            .{ .assertions = &assertions },
            validation_time,
        );
        try expectRejected(outcome, .status_malformed, 0);
        switch (outcome) {
            .rejected => |failure| try testing.expectEqual(revocation.Defect.malformed_encoding, failure.defect.?),
            .accepted => unreachable,
        }
    }

    var outcome = revocation.evaluatePath(
        allocator,
        path,
        .{ .mode = .soft_fail },
        .{ .assertions = &assertions },
        validation_time,
    );
    var report = try expectAccepted(&outcome);
    defer report.deinit(allocator);
    try testing.expectEqual(revocation.Determination.not_checked_defective_evidence, report.entries[0].determination);
}

test "unauthenticated evidence never counts as a completed check" {
    const allocator = testing.allocator;
    var fx = Fixtures.init(allocator);
    defer fx.deinit();
    var storage: [4]path_builder.Element = undefined;
    const path = try twoCertPath(&fx, &storage, .{ .subject = "leaf", .issuer = "Root" });

    var unverified = stapled(.good);
    unverified.signature_verified = false;
    const assertions = [_]revocation.StatusAssertion{unverified};

    const outcome = revocation.evaluatePath(
        allocator,
        path,
        .{ .mode = .strict },
        .{ .assertions = &assertions },
        validation_time,
    );
    try expectRejected(outcome, .status_unauthenticated, 0);

    // Opting out downgrades the trust boundary and makes the same bytes count.
    var relaxed = revocation.evaluatePath(
        allocator,
        path,
        .{ .mode = .strict, .require_signature_verified = false },
        .{ .assertions = &assertions },
        validation_time,
    );
    var report = try expectAccepted(&relaxed);
    defer report.deinit(allocator);
    try testing.expectEqual(revocation.Determination.checked_good, report.entries[0].determination);
}

test "must-staple requires stapled good status once a mode consults status" {
    const allocator = testing.allocator;
    var fx = Fixtures.init(allocator);
    defer fx.deinit();
    var storage: [4]path_builder.Element = undefined;
    const path = try twoCertPath(&fx, &storage, .{
        .subject = "leaf",
        .issuer = "Root",
        .tls_features = &.{x509.TlsFeatures.status_request},
    });
    try testing.expect(fx.certs.items[0].mustStaple());

    // No staple at all: soft-fail would otherwise accept.
    const missing = revocation.evaluatePath(
        allocator,
        path,
        .{ .mode = .soft_fail },
        .{},
        validation_time,
    );
    try expectRejected(missing, .must_staple_not_satisfied, 0);

    // A cached answer is not a staple.
    var cached = stapled(.good);
    cached.source = .cached_ocsp;
    const cached_assertions = [_]revocation.StatusAssertion{cached};
    const wrong_source = revocation.evaluatePath(
        allocator,
        path,
        .{ .mode = .soft_fail },
        .{ .assertions = &cached_assertions },
        validation_time,
    );
    try expectRejected(wrong_source, .must_staple_not_satisfied, 0);

    // A good staple satisfies it.
    const good_assertions = [_]revocation.StatusAssertion{stapled(.good)};
    var outcome = revocation.evaluatePath(
        allocator,
        path,
        .{ .mode = .soft_fail },
        .{ .assertions = &good_assertions },
        validation_time,
    );
    var report = try expectAccepted(&outcome);
    defer report.deinit(allocator);
    try testing.expect(report.entries[0].must_staple);
    try testing.expect(!report.must_staple_unenforced);
}

test "must-staple is explicitly unenforced, not silently satisfied, when disabled" {
    const allocator = testing.allocator;
    var fx = Fixtures.init(allocator);
    defer fx.deinit();
    var storage: [4]path_builder.Element = undefined;
    const path = try twoCertPath(&fx, &storage, .{
        .subject = "leaf",
        .issuer = "Root",
        .tls_features = &.{x509.TlsFeatures.status_request},
    });

    var outcome = revocation.evaluatePath(allocator, path, .{}, .{}, validation_time);
    var report = try expectAccepted(&outcome);
    defer report.deinit(allocator);
    try testing.expect(report.must_staple_unenforced);
    try testing.expect(report.entries[0].must_staple);
}

test "must-staple enforcement can be disabled explicitly" {
    const allocator = testing.allocator;
    var fx = Fixtures.init(allocator);
    defer fx.deinit();
    var storage: [4]path_builder.Element = undefined;
    const path = try twoCertPath(&fx, &storage, .{
        .subject = "leaf",
        .issuer = "Root",
        .tls_features = &.{x509.TlsFeatures.status_request},
    });

    var outcome = revocation.evaluatePath(
        allocator,
        path,
        .{ .mode = .soft_fail, .enforce_must_staple = false },
        .{},
        validation_time,
    );
    var report = try expectAccepted(&outcome);
    defer report.deinit(allocator);
    try testing.expectEqual(revocation.Determination.not_checked_no_evidence, report.entries[0].determination);
}

test "an issuing CA can assert must-staple for the certificates below it" {
    const allocator = testing.allocator;
    var fx = Fixtures.init(allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "leaf", .issuer = "Intermediate" });
    try fx.add(.{
        .subject = "Intermediate",
        .issuer = "Root",
        .ca = true,
        .tls_features = &.{x509.TlsFeatures.status_request},
    });
    try fx.add(.{ .subject = "Root", .issuer = "Root", .ca = true, .status_source = .none });
    var storage: [4]path_builder.Element = undefined;
    const path = fx.path(&storage);

    const outcome = revocation.evaluatePath(
        allocator,
        path,
        .{ .mode = .soft_fail },
        .{},
        validation_time,
    );
    try expectRejected(outcome, .must_staple_not_satisfied, 0);
}

test "a certificate publishing no status source is unsupported under strict" {
    const allocator = testing.allocator;
    var fx = Fixtures.init(allocator);
    defer fx.deinit();
    var storage: [4]path_builder.Element = undefined;
    const path = try twoCertPath(&fx, &storage, .{
        .subject = "leaf",
        .issuer = "Root",
        .status_source = .none,
    });

    const outcome = revocation.evaluatePath(allocator, path, .{ .mode = .strict }, .{}, validation_time);
    try expectRejected(outcome, .status_source_unsupported, 0);

    var soft = revocation.evaluatePath(allocator, path, .{ .mode = .soft_fail }, .{}, validation_time);
    var report = try expectAccepted(&soft);
    defer report.deinit(allocator);
    try testing.expectEqual(revocation.Determination.not_checked_no_status_source, report.entries[0].determination);
}

test "a CRL distribution point counts as a status source" {
    const allocator = testing.allocator;
    var fx = Fixtures.init(allocator);
    defer fx.deinit();
    var storage: [4]path_builder.Element = undefined;
    const path = try twoCertPath(&fx, &storage, .{
        .subject = "leaf",
        .issuer = "Root",
        .status_source = .crl,
    });

    try testing.expect(!fx.certs.items[0].hasOcspResponder());
    try testing.expect(fx.certs.items[0].crlDistributionPoints().?.len == 1);

    const outcome = revocation.evaluatePath(allocator, path, .{ .mode = .strict }, .{}, validation_time);
    try expectRejected(outcome, .status_unavailable, 0);
}

test "stapled-only mode ignores cached and CRL evidence" {
    const allocator = testing.allocator;
    var fx = Fixtures.init(allocator);
    defer fx.deinit();
    var storage: [4]path_builder.Element = undefined;
    const path = try twoCertPath(&fx, &storage, .{ .subject = "leaf", .issuer = "Root" });

    var cached = stapled(.good);
    cached.source = .cached_ocsp;
    var crl_stale = stapled(.good);
    crl_stale.source = .crl_set;
    crl_stale.next_update = validation_time - 86_400;
    const assertions = [_]revocation.StatusAssertion{ cached, crl_stale };

    var outcome = revocation.evaluatePath(
        allocator,
        path,
        .{ .mode = .stapled_only },
        .{ .assertions = &assertions },
        validation_time,
    );
    var report = try expectAccepted(&outcome);
    defer report.deinit(allocator);
    try testing.expectEqual(revocation.Determination.not_checked_no_evidence, report.entries[0].determination);

    // The same evidence decides under soft-fail, where every source counts.
    var consulted = revocation.evaluatePath(
        allocator,
        path,
        .{ .mode = .soft_fail },
        .{ .assertions = &assertions },
        validation_time,
    );
    var consulted_report = try expectAccepted(&consulted);
    defer consulted_report.deinit(allocator);
    try testing.expectEqual(revocation.Determination.checked_good, consulted_report.entries[0].determination);
    try testing.expectEqual(revocation.Source.cached_ocsp, consulted_report.entries[0].source.?);
}

test "stapled evidence outranks a cached answer for the same certificate" {
    const allocator = testing.allocator;
    var fx = Fixtures.init(allocator);
    defer fx.deinit();
    var storage: [4]path_builder.Element = undefined;
    const path = try twoCertPath(&fx, &storage, .{ .subject = "leaf", .issuer = "Root" });

    var cached_unknown = stapled(.unknown);
    cached_unknown.source = .cached_ocsp;
    const assertions = [_]revocation.StatusAssertion{ cached_unknown, stapled(.good) };

    var outcome = revocation.evaluatePath(
        allocator,
        path,
        .{ .mode = .strict },
        .{ .assertions = &assertions },
        validation_time,
    );
    var report = try expectAccepted(&outcome);
    defer report.deinit(allocator);
    try testing.expectEqual(revocation.Source.stapled_ocsp, report.entries[0].source.?);
}

test "an unknown status is not a completed check under strict" {
    const allocator = testing.allocator;
    var fx = Fixtures.init(allocator);
    defer fx.deinit();
    var storage: [4]path_builder.Element = undefined;
    const path = try twoCertPath(&fx, &storage, .{ .subject = "leaf", .issuer = "Root" });

    const assertions = [_]revocation.StatusAssertion{stapled(.unknown)};
    const outcome = revocation.evaluatePath(
        allocator,
        path,
        .{ .mode = .strict },
        .{ .assertions = &assertions },
        validation_time,
    );
    try expectRejected(outcome, .status_unavailable, 0);

    var soft = revocation.evaluatePath(
        allocator,
        path,
        .{ .mode = .soft_fail },
        .{ .assertions = &assertions },
        validation_time,
    );
    var report = try expectAccepted(&soft);
    defer report.deinit(allocator);
    try testing.expectEqual(revocation.Determination.not_checked_status_unknown, report.entries[0].determination);
}

test "strict mode requires status for intermediates as well as the leaf" {
    const allocator = testing.allocator;
    var fx = Fixtures.init(allocator);
    defer fx.deinit();
    try fx.add(.{ .subject = "leaf", .issuer = "Intermediate" });
    try fx.add(.{ .subject = "Intermediate", .issuer = "Root", .ca = true });
    try fx.add(.{ .subject = "Root", .issuer = "Root", .ca = true, .status_source = .none });
    var storage: [4]path_builder.Element = undefined;
    const path = fx.path(&storage);

    const assertions = [_]revocation.StatusAssertion{stapled(.good)};
    const outcome = revocation.evaluatePath(
        allocator,
        path,
        .{ .mode = .strict },
        .{ .assertions = &assertions },
        validation_time,
    );
    try expectRejected(outcome, .status_unavailable, 1);

    var intermediate = stapled(.good);
    intermediate.certificate_index = 1;
    intermediate.source = .cached_ocsp;
    const both = [_]revocation.StatusAssertion{ stapled(.good), intermediate };
    var accepted = revocation.evaluatePath(
        allocator,
        path,
        .{ .mode = .strict },
        .{ .assertions = &both },
        validation_time,
    );
    var report = try expectAccepted(&accepted);
    defer report.deinit(allocator);
    try testing.expectEqual(@as(usize, 2), report.entries.len);
    try testing.expect(report.allChecked());
    try testing.expect(report.entryFor(1).?.determination == .checked_good);
}

test "evidence filed against the anchor or beyond the path is rejected" {
    const allocator = testing.allocator;
    var fx = Fixtures.init(allocator);
    defer fx.deinit();
    var storage: [4]path_builder.Element = undefined;
    const path = try twoCertPath(&fx, &storage, .{ .subject = "leaf", .issuer = "Root" });

    var anchor_evidence = stapled(.good);
    anchor_evidence.certificate_index = 1; // the trust anchor
    const assertions = [_]revocation.StatusAssertion{anchor_evidence};
    const outcome = revocation.evaluatePath(
        allocator,
        path,
        .{ .mode = .soft_fail },
        .{ .assertions = &assertions },
        validation_time,
    );
    try expectRejected(outcome, .evidence_index_invalid, 1);
}

test "evidence volume and size are bounded" {
    const allocator = testing.allocator;
    var fx = Fixtures.init(allocator);
    defer fx.deinit();
    var storage: [4]path_builder.Element = undefined;
    const path = try twoCertPath(&fx, &storage, .{ .subject = "leaf", .issuer = "Root" });

    var many: [5]revocation.StatusAssertion = undefined;
    for (&many) |*assertion| assertion.* = stapled(.good);
    const too_many = revocation.evaluatePath(
        allocator,
        path,
        .{ .mode = .soft_fail, .limits = .{ .maximum_assertions = 4 } },
        .{ .assertions = &many },
        validation_time,
    );
    try expectRejected(too_many, .resource_limit_exceeded, null);

    var oversized = stapled(.good);
    oversized.raw = &[_]u8{0} ** 64;
    const oversized_assertions = [_]revocation.StatusAssertion{oversized};
    const too_large = revocation.evaluatePath(
        allocator,
        path,
        .{ .mode = .soft_fail, .limits = .{ .maximum_evidence_bytes = 32 } },
        .{ .assertions = &oversized_assertions },
        validation_time,
    );
    try expectRejected(too_large, .resource_limit_exceeded, 0);
}

test "evidence lookup helper finds only stapled entries" {
    const cached = revocation.StatusAssertion{
        .certificate_index = 0,
        .source = .cached_ocsp,
        .status = .good,
    };
    const evidence = revocation.Evidence{ .assertions = &[_]revocation.StatusAssertion{ cached, stapled(.good) } };
    try testing.expectEqual(revocation.Source.stapled_ocsp, evidence.stapledFor(0).?.source);
    try testing.expectEqual(@as(?*const revocation.StatusAssertion, null), evidence.stapledFor(1));
}

test "TLS feature extension parses, bounds, and rejects malformed encodings" {
    const allocator = testing.allocator;
    var fx = Fixtures.init(allocator);
    defer fx.deinit();

    try fx.add(.{
        .subject = "leaf",
        .issuer = "Root",
        .tls_features = &.{ x509.TlsFeatures.status_request, x509.TlsFeatures.status_request_v2 },
        .tls_features_critical = true,
    });
    const features = fx.certs.items[0].tlsFeatures().?;
    try testing.expectEqual(@as(usize, 2), features.features.len);
    try testing.expect(features.contains(x509.TlsFeatures.status_request_v2));
    try testing.expect(features.requiresStapledStatus());
    // The extension is now parsed, so a critical instance is handled.
    try testing.expect(!fx.certs.items[0].hasUnhandledCriticalExtension());

    // A feature the certificate does not assert does not require stapling.
    try fx.add(.{ .subject = "other", .issuer = "Root", .tls_features = &.{22} });
    try testing.expect(!fx.certs.items[1].mustStaple());

    // Empty SEQUENCE, a negative value, and a value beyond the 16-bit TLS
    // ExtensionType registry are all structural errors.
    try testing.expectError(error.MalformedExtension, fx.add(.{
        .subject = "empty",
        .issuer = "Root",
        .raw_tls_features = &.{ 0x30, 0x00 },
    }));
    try testing.expectError(error.MalformedExtension, fx.add(.{
        .subject = "negative",
        .issuer = "Root",
        .raw_tls_features = &.{ 0x30, 0x03, 0x02, 0x01, 0xff },
    }));
    try testing.expectError(error.MalformedExtension, fx.add(.{
        .subject = "oversized",
        .issuer = "Root",
        .raw_tls_features = &.{ 0x30, 0x05, 0x02, 0x03, 0x01, 0x00, 0x00 },
    }));
}

test {
    testing.refAllDecls(@This());
}

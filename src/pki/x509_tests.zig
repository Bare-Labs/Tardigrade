//! X.509 certificate model regression and adversarial tests (#341).
//!
//! Real-world fixtures under `testdata/` were generated with OpenSSL 3.0:
//! an RSA-2048 self-signed CA (name constraints, 2059 expiry), a P-256
//! leaf signed by that CA (SAN, EKU, AKI with issuer+serial, AIA, CRLDP,
//! policies), a self-signed Ed25519 certificate, and a v1 certificate.
//! Synthetic corpora are built with a minimal DER builder.

const std = @import("std");
const der = @import("der.zig");
const oid = @import("oid.zig");
const pem = @import("pem.zig");
const x509 = @import("x509.zig");

const testing = std.testing;

const rsa_ca_pem = @embedFile("testdata/rsa_ca.crt");
const ecdsa_leaf_pem = @embedFile("testdata/ecdsa_leaf.crt");
const ed25519_pem = @embedFile("testdata/ed25519.crt");
const v1_leaf_pem = @embedFile("testdata/v1_leaf.crt");

fn loadFixture(allocator: std.mem.Allocator, pem_text: []const u8) !pem.Certificate {
    return pem.loadCertificatePem(allocator, pem_text, .{});
}

test "RSA CA fixture parses into typed fields" {
    const allocator = testing.allocator;
    var fixture = try loadFixture(allocator, rsa_ca_pem);
    defer fixture.deinit(allocator);

    var cert = try x509.Certificate.parse(allocator, fixture.der, .{});
    defer cert.deinit(allocator);

    try testing.expectEqual(x509.Version.v3, cert.version);
    try testing.expectEqual(x509.SignatureAlgorithm.rsa_pkcs1_sha256, cert.signatureAlgorithm());
    try testing.expectEqual(x509.PublicKeyType.rsa, cert.subject_public_key_info.key_type);
    try testing.expect(!cert.serial_number.isNegative());
    try testing.expect(cert.isSelfIssued());
    try testing.expect(!cert.hasUnhandledCriticalExtension());

    // TBS bytes are preserved exactly: they sit inside `raw` and start with
    // a SEQUENCE tag.
    try testing.expect(cert.tbs_raw.len > 0);
    try testing.expectEqual(@as(u8, 0x30), cert.tbs_raw[0]);
    const tbs_offset = @intFromPtr(cert.tbs_raw.ptr) - @intFromPtr(cert.raw.ptr);
    try testing.expect(tbs_offset <= 4);
    try testing.expectEqualSlices(u8, cert.raw[tbs_offset..][0..cert.tbs_raw.len], cert.tbs_raw);

    const cn = cert.subject.commonName() orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("Tardigrade Test RSA CA", cn);
    const org = cert.subject.findAttribute(&oid.well_known.organization) orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("Tardigrade Test", org.value);

    // Expires 2059: GeneralizedTime after the 2050 UTCTime cutoff.
    try testing.expectEqual(x509.TimeEncoding.utc, cert.validity.not_before.encoding);
    try testing.expectEqual(x509.TimeEncoding.generalized, cert.validity.not_after.encoding);
    try testing.expectEqual(@as(u16, 2059), cert.validity.not_after.year);
    try testing.expect(cert.validity.not_before.order(cert.validity.not_after) == .lt);

    const bc = cert.basicConstraints() orelse return error.TestUnexpectedResult;
    try testing.expect(bc.is_ca);
    try testing.expectEqual(@as(?u32, 1), bc.max_path_len);
    const bc_ext = cert.findExtension(&oid.well_known.basic_constraints).?;
    try testing.expect(bc_ext.critical);

    const ku = cert.keyUsage() orelse return error.TestUnexpectedResult;
    try testing.expect(ku.key_cert_sign);
    try testing.expect(ku.crl_sign);
    try testing.expect(!ku.digital_signature);

    const nc = cert.nameConstraints() orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(usize, 1), nc.permitted.len);
    try testing.expectEqualStrings(".example.com", nc.permitted[0].base.dns_name);
    try testing.expectEqual(@as(usize, 1), nc.excluded.len);
    // Name-constraint IP form is address plus mask.
    try testing.expectEqual(@as(usize, 8), nc.excluded[0].base.ip_address.len);
    try testing.expectEqualSlices(u8, &.{ 10, 0, 0, 0, 255, 0, 0, 0 }, nc.excluded[0].base.ip_address);

    const ski = cert.subjectKeyIdentifier() orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(usize, 20), ski.len);
    const aki = cert.authorityKeyIdentifier() orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, ski, aki.key_identifier.?);

    try testing.expect(cert.signature_value.data.len > 0);
    try testing.expectEqual(@as(u3, 0), cert.signature_value.unused_bits);
}

test "ECDSA P-256 leaf fixture parses SAN, EKU, AKI, AIA, CRLDP, and policies" {
    const allocator = testing.allocator;
    var fixture = try loadFixture(allocator, ecdsa_leaf_pem);
    defer fixture.deinit(allocator);

    var cert = try x509.Certificate.parse(allocator, fixture.der, .{});
    defer cert.deinit(allocator);

    try testing.expectEqual(x509.Version.v3, cert.version);
    // Signed by the RSA CA; the key itself is P-256.
    try testing.expectEqual(x509.SignatureAlgorithm.rsa_pkcs1_sha256, cert.signatureAlgorithm());
    try testing.expectEqual(x509.PublicKeyType.ecdsa_p256, cert.subject_public_key_info.key_type);
    try testing.expect(cert.subject_public_key_info.named_curve.?.eqlComponents(&oid.well_known.secp256r1));
    try testing.expect(!cert.isSelfIssued());
    try testing.expect(!cert.hasUnhandledCriticalExtension());

    const san = cert.subjectAltName() orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(usize, 6), san.len);
    try testing.expectEqualStrings("leaf.example.com", san[0].dns_name);
    try testing.expectEqualStrings("*.leaf.example.com", san[1].dns_name);
    try testing.expectEqualSlices(u8, &.{ 127, 0, 0, 1 }, san[2].ip_address);
    try testing.expectEqual(@as(usize, 16), san[3].ip_address.len);
    try testing.expectEqualStrings("admin@example.com", san[4].rfc822_name);
    try testing.expectEqualStrings("https://leaf.example.com/app", san[5].uniform_resource_identifier);

    const eku = cert.extendedKeyUsage() orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(usize, 2), eku.purposes.len);
    try testing.expect(eku.allowsServerAuth());
    try testing.expect(eku.allowsClientAuth());
    try testing.expect(!eku.contains(&oid.well_known.code_signing));

    const bc = cert.basicConstraints() orelse return error.TestUnexpectedResult;
    try testing.expect(!bc.is_ca);
    try testing.expectEqual(@as(?u32, null), bc.max_path_len);

    const ku = cert.keyUsage() orelse return error.TestUnexpectedResult;
    try testing.expect(ku.digital_signature);
    try testing.expect(!ku.key_cert_sign);

    // AKI generated with issuer:always carries all three fields.
    const aki = cert.authorityKeyIdentifier() orelse return error.TestUnexpectedResult;
    try testing.expect(aki.key_identifier != null);
    try testing.expect(aki.authority_cert_issuer_raw != null);
    try testing.expect(aki.authority_cert_serial != null);

    const aia_ext = cert.findExtension(&oid.well_known.authority_info_access) orelse return error.TestUnexpectedResult;
    const aia = aia_ext.parsed.authority_info_access;
    try testing.expectEqual(@as(usize, 2), aia.len);
    try testing.expect(aia[0].method.eqlComponents(&oid.well_known.aia_ocsp));
    try testing.expectEqualStrings("http://ocsp.example.com", aia[0].location.uniform_resource_identifier);
    try testing.expect(aia[1].method.eqlComponents(&oid.well_known.aia_ca_issuers));
    try testing.expectEqualStrings("http://ca.example.com/ca.der", aia[1].location.uniform_resource_identifier);

    const crldp_ext = cert.findExtension(&oid.well_known.crl_distribution_points) orelse return error.TestUnexpectedResult;
    const points = crldp_ext.parsed.crl_distribution_points;
    try testing.expectEqual(@as(usize, 1), points.len);
    try testing.expectEqual(@as(usize, 1), points[0].full_names.len);
    try testing.expectEqualStrings("http://crl.example.com/ca.crl", points[0].full_names[0].uniform_resource_identifier);

    const policies_ext = cert.findExtension(&oid.well_known.certificate_policies) orelse return error.TestUnexpectedResult;
    const policies = policies_ext.parsed.certificate_policies;
    try testing.expectEqual(@as(usize, 1), policies.len);
    try testing.expect(policies[0].policy.eqlComponents(&.{ 1, 3, 6, 1, 4, 1, 99999, 1 }));
    try testing.expectEqual(@as(usize, 0), policies[0].qualifiers.len);
}

test "Ed25519 fixture parses" {
    const allocator = testing.allocator;
    var fixture = try loadFixture(allocator, ed25519_pem);
    defer fixture.deinit(allocator);

    var cert = try x509.Certificate.parse(allocator, fixture.der, .{});
    defer cert.deinit(allocator);

    try testing.expectEqual(x509.SignatureAlgorithm.ed25519, cert.signatureAlgorithm());
    try testing.expectEqual(x509.PublicKeyType.ed25519, cert.subject_public_key_info.key_type);
    // Ed25519 keys are 32 bytes with no unused bits.
    try testing.expectEqual(@as(usize, 32), cert.subject_public_key_info.subject_public_key.data.len);
    try testing.expectEqual(@as(usize, 64), cert.signature_value.data.len);

    const san = cert.subjectAltName() orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("ed25519.example.com", san[0].dns_name);
    const bc = cert.basicConstraints() orelse return error.TestUnexpectedResult;
    try testing.expect(!bc.is_ca);
}

test "v1 fixture parses without extensions or unique identifiers" {
    const allocator = testing.allocator;
    var fixture = try loadFixture(allocator, v1_leaf_pem);
    defer fixture.deinit(allocator);

    var cert = try x509.Certificate.parse(allocator, fixture.der, .{});
    defer cert.deinit(allocator);

    try testing.expectEqual(x509.Version.v1, cert.version);
    try testing.expectEqual(@as(usize, 0), cert.extensions.len);
    try testing.expectEqual(@as(?der.BitStringView, null), cert.issuer_unique_id);
    try testing.expectEqual(@as(?der.BitStringView, null), cert.subject_unique_id);
    try testing.expectEqual(@as(?x509.BasicConstraints, null), cert.basicConstraints());
    const cn = cert.subject.commonName() orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("leaf.example.com", cn);
}

// --- Synthetic corpora ------------------------------------------------------

/// Concatenate `parts` into one TLV with a single-byte tag.
fn tlv(arena: std.mem.Allocator, tag: u8, parts: []const []const u8) ![]u8 {
    var total: usize = 0;
    for (parts) |part| total += part.len;
    var len_buf: [9]u8 = undefined;
    const len_len = try der.encodeLength(total, &len_buf);
    var out = try arena.alloc(u8, 1 + len_len + total);
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
    var buf: [64]u8 = undefined;
    const n = try oid.encodeComponents(components, &buf);
    return tlv(arena, 0x06, &.{buf[0..n]});
}

const ed25519_components = [_]u32{ 1, 3, 101, 112 };
const ecdsa_sha256_components = [_]u32{ 1, 2, 840, 10045, 4, 3, 2 };

fn algorithmEd25519(arena: std.mem.Allocator) ![]u8 {
    return tlv(arena, 0x30, &.{try oidTlv(arena, &ed25519_components)});
}

fn nameWithCn(arena: std.mem.Allocator, cn: []const u8) ![]u8 {
    return nameWithCnTag(arena, 0x0c, cn);
}

fn nameWithCnTag(arena: std.mem.Allocator, value_tag: u8, cn: []const u8) ![]u8 {
    const atv = try tlv(arena, 0x30, &.{
        try oidTlv(arena, &oid.well_known.common_name),
        try tlv(arena, value_tag, &.{cn}),
    });
    return tlv(arena, 0x30, &.{try tlv(arena, 0x31, &.{atv})});
}

/// A Name with one domainComponent RDN per label, e.g. `["EXAMPLE", "COM"]`
/// for `DC=EXAMPLE,DC=COM`.
fn dnWithDomainComponents(arena: std.mem.Allocator, labels: []const []const u8, value_tag: u8) ![]u8 {
    var rdns: std.ArrayList([]const u8) = .empty;
    defer rdns.deinit(arena);
    for (labels) |label| {
        const atv = try tlv(arena, 0x30, &.{
            try oidTlv(arena, &oid.well_known.domain_component),
            try tlv(arena, value_tag, &.{label}),
        });
        try rdns.append(arena, try tlv(arena, 0x31, &.{atv}));
    }
    return tlv(arena, 0x30, rdns.items);
}

fn utcValidity(arena: std.mem.Allocator) ![]u8 {
    return tlv(arena, 0x30, &.{
        try tlv(arena, 0x17, &.{"260101000000Z"}),
        try tlv(arena, 0x17, &.{"270101000000Z"}),
    });
}

fn spkiEd25519(arena: std.mem.Allocator) ![]u8 {
    const key = [_]u8{0x00} ++ [_]u8{0xaa} ** 32;
    return tlv(arena, 0x30, &.{
        try algorithmEd25519(arena),
        try tlv(arena, 0x03, &.{&key}),
    });
}

fn signatureBits(arena: std.mem.Allocator) ![]u8 {
    const sig = [_]u8{0x00} ++ [_]u8{0xbb} ** 64;
    return tlv(arena, 0x03, &.{&sig});
}

const TbsOptions = struct {
    /// Full [0] EXPLICIT version TLV; null omits the field (v1).
    version: ?[]const u8 = null,
    inner_algorithm: ?[]const u8 = null,
    /// Full [3] extensions TLV.
    extensions_wrapper: ?[]const u8 = null,
    /// Raw TLVs appended between SPKI and extensions (unique IDs).
    trailing: []const []const u8 = &.{},
};

fn versionTlv(arena: std.mem.Allocator, value: u8) ![]u8 {
    return tlv(arena, 0xa0, &.{try tlv(arena, 0x02, &.{&[_]u8{value}})});
}

fn buildTbs(arena: std.mem.Allocator, options: TbsOptions) ![]u8 {
    var parts: std.ArrayList([]const u8) = .empty;
    defer parts.deinit(arena);
    if (options.version) |version| try parts.append(arena, version);
    try parts.append(arena, try tlv(arena, 0x02, &.{&[_]u8{0x01}}));
    try parts.append(arena, options.inner_algorithm orelse try algorithmEd25519(arena));
    try parts.append(arena, try nameWithCn(arena, "Synthetic Issuer"));
    try parts.append(arena, try utcValidity(arena));
    try parts.append(arena, try nameWithCn(arena, "Synthetic Subject"));
    try parts.append(arena, try spkiEd25519(arena));
    for (options.trailing) |extra| try parts.append(arena, extra);
    if (options.extensions_wrapper) |extensions| try parts.append(arena, extensions);
    return tlv(arena, 0x30, parts.items);
}

fn buildCertificate(arena: std.mem.Allocator, options: TbsOptions) ![]u8 {
    return tlv(arena, 0x30, &.{
        try buildTbs(arena, options),
        try algorithmEd25519(arena),
        try signatureBits(arena),
    });
}

fn extensionTlv(arena: std.mem.Allocator, ext_oid: []const u32, critical: bool, value: []const u8) ![]u8 {
    var parts: std.ArrayList([]const u8) = .empty;
    defer parts.deinit(arena);
    try parts.append(arena, try oidTlv(arena, ext_oid));
    if (critical) try parts.append(arena, try tlv(arena, 0x01, &.{&[_]u8{0xff}}));
    try parts.append(arena, try tlv(arena, 0x04, &.{value}));
    return tlv(arena, 0x30, parts.items);
}

fn extensionsWrapper(arena: std.mem.Allocator, extensions: []const []const u8) ![]u8 {
    return tlv(arena, 0xa3, &.{try tlv(arena, 0x30, extensions)});
}

const unknown_ext_oid = [_]u32{ 1, 3, 6, 1, 4, 1, 99999, 99 };

test "synthetic v3 certificate round-trips through the builder" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    const san_value = try tlv(arena, 0x30, &.{try tlv(arena, 0x82, &.{"a.test"})});
    const bytes = try buildCertificate(arena, .{
        .version = try versionTlv(arena, 2),
        .extensions_wrapper = try extensionsWrapper(arena, &.{
            try extensionTlv(arena, &oid.well_known.subject_alt_name, false, san_value),
        }),
    });

    var cert = try x509.Certificate.parse(testing.allocator, bytes, .{});
    defer cert.deinit(testing.allocator);
    try testing.expectEqual(x509.Version.v3, cert.version);
    try testing.expectEqual(x509.SignatureAlgorithm.ed25519, cert.signatureAlgorithm());
    try testing.expectEqualStrings("Synthetic Subject", cert.subject.commonName().?);
    try testing.expectEqualStrings("a.test", cert.subjectAltName().?[0].dns_name);
    try testing.expectEqualSlices(u8, bytes, cert.raw);
}

test "inner and outer signature algorithm mismatch fails typed" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    const mismatched_inner = try tlv(arena, 0x30, &.{try oidTlv(arena, &ecdsa_sha256_components)});
    const bytes = try buildCertificate(arena, .{
        .version = try versionTlv(arena, 2),
        .inner_algorithm = mismatched_inner,
    });
    try testing.expectError(error.SignatureAlgorithmMismatch, x509.Certificate.parse(testing.allocator, bytes, .{}));
}

test "explicit default version encoding fails typed" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    const bytes = try buildCertificate(arena, .{ .version = try versionTlv(arena, 0) });
    try testing.expectError(error.UnsupportedVersion, x509.Certificate.parse(testing.allocator, bytes, .{}));

    const future = try buildCertificate(arena, .{ .version = try versionTlv(arena, 3) });
    try testing.expectError(error.UnsupportedVersion, x509.Certificate.parse(testing.allocator, future, .{}));
}

test "extensions require v3 and unique identifiers require v2 or v3" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    const san_value = try tlv(arena, 0x30, &.{try tlv(arena, 0x82, &.{"a.test"})});
    const extensions = try extensionsWrapper(arena, &.{
        try extensionTlv(arena, &oid.well_known.subject_alt_name, false, san_value),
    });

    // Extensions without a version field (v1).
    const v1_with_extensions = try buildCertificate(arena, .{ .extensions_wrapper = extensions });
    try testing.expectError(error.UnsupportedVersion, x509.Certificate.parse(testing.allocator, v1_with_extensions, .{}));

    // Extensions on v2.
    const v2_with_extensions = try buildCertificate(arena, .{
        .version = try versionTlv(arena, 1),
        .extensions_wrapper = extensions,
    });
    try testing.expectError(error.UnsupportedVersion, x509.Certificate.parse(testing.allocator, v2_with_extensions, .{}));

    // issuerUniqueID on v1.
    const unique_id = try tlv(arena, 0x81, &.{&[_]u8{ 0x00, 0x99 }});
    const v1_with_unique = try buildCertificate(arena, .{ .trailing = &.{unique_id} });
    try testing.expectError(error.UnsupportedVersion, x509.Certificate.parse(testing.allocator, v1_with_unique, .{}));

    // issuerUniqueID on v2 parses.
    const v2_with_unique = try buildCertificate(arena, .{
        .version = try versionTlv(arena, 1),
        .trailing = &.{unique_id},
    });
    var cert = try x509.Certificate.parse(testing.allocator, v2_with_unique, .{});
    defer cert.deinit(testing.allocator);
    try testing.expectEqual(x509.Version.v2, cert.version);
    try testing.expectEqualSlices(u8, &.{0x99}, cert.issuer_unique_id.?.data);
    try testing.expectEqual(@as(?der.BitStringView, null), cert.subject_unique_id);
}

test "duplicate extension OIDs fail typed" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    const san_value = try tlv(arena, 0x30, &.{try tlv(arena, 0x82, &.{"a.test"})});
    const san_ext = try extensionTlv(arena, &oid.well_known.subject_alt_name, false, san_value);
    const bytes = try buildCertificate(arena, .{
        .version = try versionTlv(arena, 2),
        .extensions_wrapper = try extensionsWrapper(arena, &.{ san_ext, san_ext }),
    });
    try testing.expectError(error.DuplicateExtension, x509.Certificate.parse(testing.allocator, bytes, .{}));
}

test "unknown critical extensions are retained and surfaced for fail-closed validation" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    const payload = try tlv(arena, 0x04, &.{"opaque"});
    const critical_bytes = try buildCertificate(arena, .{
        .version = try versionTlv(arena, 2),
        .extensions_wrapper = try extensionsWrapper(arena, &.{
            try extensionTlv(arena, &unknown_ext_oid, true, payload),
        }),
    });
    var critical_cert = try x509.Certificate.parse(testing.allocator, critical_bytes, .{});
    defer critical_cert.deinit(testing.allocator);
    try testing.expect(critical_cert.hasUnhandledCriticalExtension());
    const retained = critical_cert.findExtension(&unknown_ext_oid).?;
    try testing.expect(retained.critical);
    try testing.expect(retained.parsed == .unrecognized);
    try testing.expectEqualSlices(u8, payload, retained.value);

    // The same unknown extension without criticality is retained and ignored.
    const benign_bytes = try buildCertificate(arena, .{
        .version = try versionTlv(arena, 2),
        .extensions_wrapper = try extensionsWrapper(arena, &.{
            try extensionTlv(arena, &unknown_ext_oid, false, payload),
        }),
    });
    var benign_cert = try x509.Certificate.parse(testing.allocator, benign_bytes, .{});
    defer benign_cert.deinit(testing.allocator);
    try testing.expect(!benign_cert.hasUnhandledCriticalExtension());
}

test "explicit critical FALSE and explicit cA FALSE fail typed" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    // critical FALSE spelled out violates DER DEFAULT omission.
    const san_value = try tlv(arena, 0x30, &.{try tlv(arena, 0x82, &.{"a.test"})});
    const explicit_false_ext = try tlv(arena, 0x30, &.{
        try oidTlv(arena, &oid.well_known.subject_alt_name),
        try tlv(arena, 0x01, &.{&[_]u8{0x00}}),
        try tlv(arena, 0x04, &.{san_value}),
    });
    const bytes = try buildCertificate(arena, .{
        .version = try versionTlv(arena, 2),
        .extensions_wrapper = try extensionsWrapper(arena, &.{explicit_false_ext}),
    });
    try testing.expectError(error.MalformedExtension, x509.Certificate.parse(testing.allocator, bytes, .{}));

    // cA FALSE spelled out inside BasicConstraints.
    const bc_value = try tlv(arena, 0x30, &.{try tlv(arena, 0x01, &.{&[_]u8{0x00}})});
    const bc_bytes = try buildCertificate(arena, .{
        .version = try versionTlv(arena, 2),
        .extensions_wrapper = try extensionsWrapper(arena, &.{
            try extensionTlv(arena, &oid.well_known.basic_constraints, true, bc_value),
        }),
    });
    try testing.expectError(error.MalformedExtension, x509.Certificate.parse(testing.allocator, bc_bytes, .{}));
}

test "pathLen without cA and unknown Key Usage bits fail typed" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    // pathLenConstraint is forbidden unless cA is asserted TRUE.
    const path_len_without_ca = try tlv(arena, 0x30, &.{try tlv(arena, 0x02, &.{&[_]u8{0}})});
    const bad_path_len = try buildCertificate(arena, .{
        .version = try versionTlv(arena, 2),
        .extensions_wrapper = try extensionsWrapper(arena, &.{
            try extensionTlv(arena, &oid.well_known.basic_constraints, true, path_len_without_ca),
        }),
    });
    try testing.expectError(error.MalformedExtension, x509.Certificate.parse(testing.allocator, bad_path_len, .{}));

    // Key Usage assigns only bits 0..8. Bit 9 is canonically encoded here
    // but unknown to RFC 5280 and therefore rejected by the strict parser.
    const unknown_key_usage = try tlv(arena, 0x03, &.{&[_]u8{ 6, 0, 0x40 }});
    const bad_key_usage = try buildCertificate(arena, .{
        .version = try versionTlv(arena, 2),
        .extensions_wrapper = try extensionsWrapper(arena, &.{
            try extensionTlv(arena, &oid.well_known.key_usage, true, unknown_key_usage),
        }),
    });
    try testing.expectError(error.MalformedExtension, x509.Certificate.parse(testing.allocator, bad_key_usage, .{}));

    const empty_key_usage = try tlv(arena, 0x03, &.{&[_]u8{0}});
    const empty_key_usage_certificate = try buildCertificate(arena, .{
        .version = try versionTlv(arena, 2),
        .extensions_wrapper = try extensionsWrapper(arena, &.{
            try extensionTlv(arena, &oid.well_known.key_usage, true, empty_key_usage),
        }),
    });
    try testing.expectError(
        error.MalformedExtension,
        x509.Certificate.parse(testing.allocator, empty_key_usage_certificate, .{}),
    );
}

test "malformed structures fail deterministically" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    const valid = try buildCertificate(arena, .{ .version = try versionTlv(arena, 2) });

    // Truncation at every prefix fails without crashing; full input parses.
    var prefix_len: usize = 0;
    while (prefix_len < valid.len) : (prefix_len += 7) {
        const result = x509.Certificate.parse(testing.allocator, valid[0..prefix_len], .{});
        try testing.expectError(error.MalformedCertificate, result);
    }

    // Trailing bytes after the certificate.
    const trailing = try std.mem.concat(arena, u8, &.{ valid, "\x00" });
    try testing.expectError(error.MalformedCertificate, x509.Certificate.parse(testing.allocator, trailing, .{}));

    // Empty extensions SEQUENCE violates SIZE (1..MAX).
    const empty_extensions = try buildCertificate(arena, .{
        .version = try versionTlv(arena, 2),
        .extensions_wrapper = try tlv(arena, 0xa3, &.{try tlv(arena, 0x30, &.{})}),
    });
    try testing.expectError(error.MalformedExtension, x509.Certificate.parse(testing.allocator, empty_extensions, .{}));

    // GeneralizedTime before 2050 must have used UTCTime.
    const bad_validity = try tlv(arena, 0x30, &.{
        try tlv(arena, 0x18, &.{"20260101000000Z"}),
        try tlv(arena, 0x18, &.{"20270101000000Z"}),
    });
    const bad_time_tbs = blk: {
        // Rebuild manually with the invalid validity in place.
        var list: std.ArrayList([]const u8) = .empty;
        defer list.deinit(arena);
        try list.append(arena, try versionTlv(arena, 2));
        try list.append(arena, try tlv(arena, 0x02, &.{&[_]u8{0x01}}));
        try list.append(arena, try algorithmEd25519(arena));
        try list.append(arena, try nameWithCn(arena, "Synthetic Issuer"));
        try list.append(arena, bad_validity);
        try list.append(arena, try nameWithCn(arena, "Synthetic Subject"));
        try list.append(arena, try spkiEd25519(arena));
        break :blk try tlv(arena, 0x30, list.items);
    };
    const bad_time_cert = try tlv(arena, 0x30, &.{
        bad_time_tbs,
        try algorithmEd25519(arena),
        try signatureBits(arena),
    });
    try testing.expectError(error.MalformedValidity, x509.Certificate.parse(testing.allocator, bad_time_cert, .{}));

    // SAN iPAddress with an invalid length.
    const bad_ip_san = try tlv(arena, 0x30, &.{try tlv(arena, 0x87, &.{&[_]u8{ 1, 2, 3, 4, 5 }})});
    const bad_ip_cert = try buildCertificate(arena, .{
        .version = try versionTlv(arena, 2),
        .extensions_wrapper = try extensionsWrapper(arena, &.{
            try extensionTlv(arena, &oid.well_known.subject_alt_name, false, bad_ip_san),
        }),
    });
    try testing.expectError(error.MalformedExtension, x509.Certificate.parse(testing.allocator, bad_ip_cert, .{}));

    // Empty RDN SET inside a name.
    const empty_rdn_name = try tlv(arena, 0x30, &.{try tlv(arena, 0x31, &.{})});
    const bad_name_tbs = blk: {
        var list: std.ArrayList([]const u8) = .empty;
        defer list.deinit(arena);
        try list.append(arena, try versionTlv(arena, 2));
        try list.append(arena, try tlv(arena, 0x02, &.{&[_]u8{0x01}}));
        try list.append(arena, try algorithmEd25519(arena));
        try list.append(arena, empty_rdn_name);
        try list.append(arena, try utcValidity(arena));
        try list.append(arena, try nameWithCn(arena, "Synthetic Subject"));
        try list.append(arena, try spkiEd25519(arena));
        break :blk try tlv(arena, 0x30, list.items);
    };
    const bad_name_cert = try tlv(arena, 0x30, &.{
        bad_name_tbs,
        try algorithmEd25519(arena),
        try signatureBits(arena),
    });
    try testing.expectError(error.MalformedName, x509.Certificate.parse(testing.allocator, bad_name_cert, .{}));

    // EC SPKI without curve parameters.
    const ec_alg = try tlv(arena, 0x30, &.{try oidTlv(arena, &oid.well_known.ec_public_key)});
    const key = [_]u8{0x00} ++ [_]u8{0xaa} ** 32;
    const bad_spki = try tlv(arena, 0x30, &.{ ec_alg, try tlv(arena, 0x03, &.{&key}) });
    const bad_spki_tbs = blk: {
        var list: std.ArrayList([]const u8) = .empty;
        defer list.deinit(arena);
        try list.append(arena, try versionTlv(arena, 2));
        try list.append(arena, try tlv(arena, 0x02, &.{&[_]u8{0x01}}));
        try list.append(arena, try algorithmEd25519(arena));
        try list.append(arena, try nameWithCn(arena, "Synthetic Issuer"));
        try list.append(arena, try utcValidity(arena));
        try list.append(arena, try nameWithCn(arena, "Synthetic Subject"));
        try list.append(arena, bad_spki);
        break :blk try tlv(arena, 0x30, list.items);
    };
    const bad_spki_cert = try tlv(arena, 0x30, &.{
        bad_spki_tbs,
        try algorithmEd25519(arena),
        try signatureBits(arena),
    });
    try testing.expectError(error.MalformedPublicKeyInfo, x509.Certificate.parse(testing.allocator, bad_spki_cert, .{}));
}

test "constructed encodings of known directory-string tags fail typed" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    // A constructed UTF8String (0x0c | 0x20) wrapping a primitive segment is
    // valid BER but not DER; the value must not be retained as unknown.
    const constructed_utf8 = try tlv(arena, 0x2c, &.{try tlv(arena, 0x0c, &.{"CN"})});
    const atv = try tlv(arena, 0x30, &.{
        try oidTlv(arena, &oid.well_known.common_name),
        constructed_utf8,
    });
    const bad_name = try tlv(arena, 0x30, &.{try tlv(arena, 0x31, &.{atv})});
    const bad_cert = blk: {
        var list: std.ArrayList([]const u8) = .empty;
        defer list.deinit(arena);
        try list.append(arena, try versionTlv(arena, 2));
        try list.append(arena, try tlv(arena, 0x02, &.{&[_]u8{0x01}}));
        try list.append(arena, try algorithmEd25519(arena));
        try list.append(arena, try nameWithCn(arena, "Synthetic Issuer"));
        try list.append(arena, try utcValidity(arena));
        try list.append(arena, bad_name);
        try list.append(arena, try spkiEd25519(arena));
        const bad_tbs = try tlv(arena, 0x30, list.items);
        break :blk try tlv(arena, 0x30, &.{
            bad_tbs,
            try algorithmEd25519(arena),
            try signatureBits(arena),
        });
    };
    try testing.expectError(error.MalformedName, x509.Certificate.parse(testing.allocator, bad_cert, .{}));

    // A genuinely unknown attribute-value tag is still retained raw, even
    // when constructed (e.g. a SEQUENCE-valued attribute).
    const seq_value = try tlv(arena, 0x30, &.{try tlv(arena, 0x0c, &.{"inner"})});
    const seq_atv = try tlv(arena, 0x30, &.{
        try oidTlv(arena, &oid.well_known.common_name),
        seq_value,
    });
    const seq_name = try tlv(arena, 0x30, &.{try tlv(arena, 0x31, &.{seq_atv})});
    const seq_cert = blk: {
        var list: std.ArrayList([]const u8) = .empty;
        defer list.deinit(arena);
        try list.append(arena, try versionTlv(arena, 2));
        try list.append(arena, try tlv(arena, 0x02, &.{&[_]u8{0x01}}));
        try list.append(arena, try algorithmEd25519(arena));
        try list.append(arena, try nameWithCn(arena, "Synthetic Issuer"));
        try list.append(arena, try utcValidity(arena));
        try list.append(arena, seq_name);
        try list.append(arena, try spkiEd25519(arena));
        const seq_tbs = try tlv(arena, 0x30, list.items);
        break :blk try tlv(arena, 0x30, &.{
            seq_tbs,
            try algorithmEd25519(arena),
            try signatureBits(arena),
        });
    };
    var cert = try x509.Certificate.parse(testing.allocator, seq_cert, .{});
    defer cert.deinit(testing.allocator);
    try testing.expect(cert.subject.rdns[0].attributes[0].value_tag.constructed);
}

test "DistributionPoint fields must be ordered, unique, and well-formed" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    const uri_name = try tlv(arena, 0x86, &.{"http://crl.example.com/ca.crl"});
    const dp_name = try tlv(arena, 0xa0, &.{try tlv(arena, 0xa0, &.{uri_name})});
    const valid_reasons = try tlv(arena, 0x81, &.{&[_]u8{ 0x01, 0x40 }});
    const valid_issuer = try tlv(arena, 0xa2, &.{uri_name});

    const CaseExpectation = enum { parses, fails };
    const cases = [_]struct {
        parts: []const []const u8,
        expected: CaseExpectation,
    }{
        // All three fields in order.
        .{ .parts = &.{ dp_name, valid_reasons, valid_issuer }, .expected = .parses },
        // cRLIssuer alone satisfies the presence rule.
        .{ .parts = &.{valid_issuer}, .expected = .parses },
        // Duplicate [0].
        .{ .parts = &.{ dp_name, dp_name }, .expected = .fails },
        // Out of order: [1] before [0].
        .{ .parts = &.{ valid_reasons, dp_name }, .expected = .fails },
        // reasons alone (RFC 5280 §4.2.1.13).
        .{ .parts = &.{valid_reasons}, .expected = .fails },
        // Empty DistributionPoint.
        .{ .parts = &.{}, .expected = .fails },
    };

    for (cases) |case| {
        const point = try tlv(arena, 0x30, case.parts);
        const value = try tlv(arena, 0x30, &.{point});
        const bytes = try buildCertificate(arena, .{
            .version = try versionTlv(arena, 2),
            .extensions_wrapper = try extensionsWrapper(arena, &.{
                try extensionTlv(arena, &oid.well_known.crl_distribution_points, false, value),
            }),
        });
        const result = x509.Certificate.parse(testing.allocator, bytes, .{});
        switch (case.expected) {
            .parses => {
                var cert = try result;
                cert.deinit(testing.allocator);
            },
            .fails => try testing.expectError(error.MalformedExtension, result),
        }
    }

    // Malformed reasons payload: unused-bit count above 7.
    const bad_reasons = try tlv(arena, 0x81, &.{&[_]u8{ 0x08, 0xff }});
    // Constructed reasons field.
    const constructed_reasons = try tlv(arena, 0xa1, &.{&[_]u8{ 0x01, 0x40 }});
    // cRLIssuer containing a non-GeneralName element.
    const bad_issuer = try tlv(arena, 0xa2, &.{try tlv(arena, 0x0c, &.{"nope"})});
    // Primitive cRLIssuer field.
    const primitive_issuer = try tlv(arena, 0x82, &.{"nope"});
    // Empty cRLIssuer violates GeneralNames SIZE (1..MAX).
    const empty_issuer = try tlv(arena, 0xa2, &.{});
    // Primitive distributionPoint wrapper.
    const primitive_dp = try tlv(arena, 0x80, &.{"nope"});

    for ([_][]const []const u8{
        &.{ dp_name, bad_reasons },
        &.{ dp_name, constructed_reasons },
        &.{ dp_name, valid_reasons, bad_issuer },
        &.{ dp_name, valid_reasons, primitive_issuer },
        &.{ dp_name, valid_reasons, empty_issuer },
        &.{primitive_dp},
    }) |parts| {
        const point = try tlv(arena, 0x30, parts);
        const value = try tlv(arena, 0x30, &.{point});
        const bytes = try buildCertificate(arena, .{
            .version = try versionTlv(arena, 2),
            .extensions_wrapper = try extensionsWrapper(arena, &.{
                try extensionTlv(arena, &oid.well_known.crl_distribution_points, false, value),
            }),
        });
        try testing.expectError(error.MalformedExtension, x509.Certificate.parse(testing.allocator, bytes, .{}));
    }
}

test "directoryName SAN entries retain the Name TLV for later parsing" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    const dir_name = try nameWithCn(arena, "Directory CN");
    // directoryName [4] is EXPLICIT: constructed context tag wrapping Name.
    const san_value = try tlv(arena, 0x30, &.{try tlv(arena, 0xa4, &.{dir_name})});
    const bytes = try buildCertificate(arena, .{
        .version = try versionTlv(arena, 2),
        .extensions_wrapper = try extensionsWrapper(arena, &.{
            try extensionTlv(arena, &oid.well_known.subject_alt_name, false, san_value),
        }),
    });

    var cert = try x509.Certificate.parse(testing.allocator, bytes, .{});
    defer cert.deinit(testing.allocator);
    const san = cert.subjectAltName().?;
    try testing.expectEqualSlices(u8, dir_name, san[0].directory_name);

    const parsed_name = try x509.parseNameRaw(arena, san[0].directory_name, .{});
    try testing.expectEqualStrings("Directory CN", parsed_name.commonName().?);
}

test "extension count limit fails typed" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    const payload = try tlv(arena, 0x04, &.{"x"});
    const other_oid = [_]u32{ 1, 3, 6, 1, 4, 1, 99999, 100 };
    const bytes = try buildCertificate(arena, .{
        .version = try versionTlv(arena, 2),
        .extensions_wrapper = try extensionsWrapper(arena, &.{
            try extensionTlv(arena, &unknown_ext_oid, false, payload),
            try extensionTlv(arena, &other_oid, false, payload),
        }),
    });
    var limits: x509.Limits = .{};
    limits.max_extensions = 1;
    try testing.expectError(error.CountLimitExceeded, x509.Certificate.parse(testing.allocator, bytes, limits));
}

test "name chaining unifies PrintableString and UTF8String with case and space folding" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    // RFC 5280 §7.1: the same value in different DirectoryString encodings
    // must chain even though the encodings differ byte-for-byte.
    const utf8_name = try x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, "Example CA"), .{});
    const printable_name = try x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x13, "Example CA"), .{});
    try testing.expect(utf8_name.eqlForChaining(&printable_name));
    try testing.expect(!utf8_name.eqlEncoding(&printable_name));

    // Rules (c)/(d): case-insensitive, leading/trailing white space dropped,
    // internal runs collapsed.
    const noisy_name = try x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x13, "  EXAMPLE   ca "), .{});
    try testing.expect(utf8_name.eqlForChaining(&noisy_name));

    // Different values do not chain.
    const different_name = try x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, "Example CA 2"), .{});
    try testing.expect(!utf8_name.eqlForChaining(&different_name));

    // BMPString sits outside the caseIgnore class: exact bytes under its
    // own tag, so the same text does not chain with the UTF8String form.
    const bmp_text = [_]u8{ 0, 'E', 0, 'x', 0, 'a', 0, 'm', 0, 'p', 0, 'l', 0, 'e', 0, ' ', 0, 'C', 0, 'A' };
    const bmp_name = try x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x1e, &bmp_text), .{});
    try testing.expect(!utf8_name.eqlForChaining(&bmp_name));
}

test "name chaining uses RFC 4518 DirectoryString preparation" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    const sharp_s = try x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, "Straße"), .{});
    const ss = try x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, "STRASSE"), .{});
    try testing.expect(sharp_s.eqlForChaining(&ss));
    try testing.expect(!sharp_s.eqlEncoding(&ss));

    const soft_hyphen = try x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, "soft\u{00AD}hyphen"), .{});
    const no_hyphen = try x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, "softhyphen"), .{});
    try testing.expect(soft_hyphen.eqlForChaining(&no_hyphen));

    const composed = try x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, "\u{00E9}"), .{});
    const decomposed = try x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, "e\u{0301}"), .{});
    try testing.expect(composed.eqlForChaining(&decomposed));

    const full_width = try x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, "\u{FF21}\u{FF23}\u{FF2D}\u{FF25}"), .{});
    const ascii = try x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, "ACME"), .{});
    try testing.expect(full_width.eqlForChaining(&ascii));

    const nbsp_name = try x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, "Example\u{00A0}CA"), .{});
    const space_name = try x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, "Example CA"), .{});
    try testing.expect(nbsp_name.eqlForChaining(&space_name));

    const spaced_mn = try x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, " \u{0301}A"), .{});
    const bare_mn = try x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, "\u{0301}A"), .{});
    try testing.expect(!spaced_mn.eqlForChaining(&bare_mn));

    const spaced_mc_ccc0 = try x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, " \u{093E}A"), .{});
    const bare_mc_ccc0 = try x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, "\u{093E}A"), .{});
    try testing.expect(!spaced_mc_ccc0.eqlForChaining(&bare_mc_ccc0));

    // RFC 4518 Appendix A is the definitive combining-mark table. U+05BD is
    // classified Mn by Unicode 3.2 but intentionally absent from Appendix A,
    // so a preceding U+0020 remains an insignificant leading space.
    const spaced_non_appendix_a_mark = try x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, " \u{05BD}A"), .{});
    const bare_non_appendix_a_mark = try x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, "\u{05BD}A"), .{});
    try testing.expect(spaced_non_appendix_a_mark.eqlForChaining(&bare_non_appendix_a_mark));

    const different = try x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, "STRASZE"), .{});
    try testing.expect(!sharp_s.eqlForChaining(&different));
}

test "name chaining accepts Unicode 3.2 assigned values absent from RFC 3454 B.2" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    _ = try x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, "\u{10A0}"), .{});
    _ = try x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, "\u{04C0}"), .{});

    try testing.expectError(
        error.NamePreparationFailed,
        x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, "\u{2D00}"), .{}),
    );
    try testing.expectError(
        error.NamePreparationFailed,
        x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, "\u{04CF}"), .{}),
    );
}

test "name chaining rejects undefined RFC 4518 stored DirectoryString preparation" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    try testing.expectError(
        error.NamePreparationFailed,
        x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, "\u{E000}"), .{}),
    );
    try testing.expectError(
        error.NamePreparationFailed,
        x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, "\u{0221}"), .{}),
    );
    try testing.expectError(
        error.NamePreparationFailed,
        x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, "\u{1C90}"), .{}),
    );
    try testing.expectError(
        error.NamePreparationFailed,
        x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, "\u{1E900}"), .{}),
    );
    try testing.expectError(
        error.NamePreparationFailed,
        x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, "\u{A7B0}"), .{}),
    );
}

test "domainComponent RDN values compare with caseIgnoreIA5Match" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    // RFC 5280 §7.1 / RFC 4517 §4.2.3: domainComponent (IA5String) chains
    // case-insensitively — DC=EXAMPLE,DC=COM must chain to dc=example,dc=com.
    const upper = try x509.parseNameRaw(arena, try dnWithDomainComponents(arena, &.{ "EXAMPLE", "COM" }, 0x16), .{});
    const lower = try x509.parseNameRaw(arena, try dnWithDomainComponents(arena, &.{ "example", "com" }, 0x16), .{});
    try testing.expect(upper.eqlForChaining(&lower));
    try testing.expect(!upper.eqlEncoding(&lower));

    const different = try x509.parseNameRaw(arena, try dnWithDomainComponents(arena, &.{ "example", "net" }, 0x16), .{});
    try testing.expect(!upper.eqlForChaining(&different));
}

test "directoryName subtree matching reuses canonical RDN prefix keys" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    const base = try x509.parseNameRaw(arena, try dnWithDomainComponents(arena, &.{"EXAMPLE"}, 0x16), .{});
    const descendant = try x509.parseNameRaw(arena, try dnWithDomainComponents(arena, &.{ "example", "COM" }, 0x16), .{});
    const sibling = try x509.parseNameRaw(arena, try dnWithDomainComponents(arena, &.{ "other", "COM" }, 0x16), .{});

    try testing.expect(descendant.isWithinSubtree(&base));
    try testing.expect(base.isWithinSubtree(&base));
    try testing.expect(!base.isWithinSubtree(&descendant));
    try testing.expect(!sibling.isWithinSubtree(&base));
}

test "isSelfIssued uses RFC 4518 name chaining, not encoding equality" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    // RFC 5280 defines self-issued via §7.1 name chaining, not encoding
    // identity. This pair depends on RFC 3454 B.2 one-to-many mapping.
    var list: std.ArrayList([]const u8) = .empty;
    defer list.deinit(arena);
    try list.append(arena, try versionTlv(arena, 2));
    try list.append(arena, try tlv(arena, 0x02, &.{&[_]u8{0x01}}));
    try list.append(arena, try algorithmEd25519(arena));
    try list.append(arena, try nameWithCnTag(arena, 0x0c, "Straße CA"));
    try list.append(arena, try utcValidity(arena));
    try list.append(arena, try nameWithCnTag(arena, 0x0c, "STRASSE CA"));
    try list.append(arena, try spkiEd25519(arena));
    const tbs = try tlv(arena, 0x30, list.items);
    const bytes = try tlv(arena, 0x30, &.{ tbs, try algorithmEd25519(arena), try signatureBits(arena) });

    var cert = try x509.Certificate.parse(testing.allocator, bytes, .{});
    defer cert.deinit(testing.allocator);
    try testing.expect(!cert.issuer.eqlEncoding(&cert.subject));
    try testing.expect(cert.issuer.eqlForChaining(&cert.subject));
    try testing.expect(cert.isSelfIssued());
}

test "name chaining keys are structure-sensitive" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    const cn_atv = try tlv(arena, 0x30, &.{
        try oidTlv(arena, &oid.well_known.common_name),
        try tlv(arena, 0x0c, &.{"A"}),
    });
    const org_atv = try tlv(arena, 0x30, &.{
        try oidTlv(arena, &oid.well_known.organization),
        try tlv(arena, 0x0c, &.{"B"}),
    });

    // One RDN holding both attributes is distinct from two single-attribute
    // RDNs carrying the same values (the count prefixes keep the flat key
    // injective).
    const multi_attribute = try tlv(arena, 0x30, &.{try tlv(arena, 0x31, &.{ cn_atv, org_atv })});
    const multi_rdn = try tlv(arena, 0x30, &.{
        try tlv(arena, 0x31, &.{cn_atv}),
        try tlv(arena, 0x31, &.{org_atv}),
    });
    const combined = try x509.parseNameRaw(arena, multi_attribute, .{});
    const sequential = try x509.parseNameRaw(arena, multi_rdn, .{});
    try testing.expect(!combined.eqlForChaining(&sequential));

    // Same structure, same values: chains regardless of value encodings.
    const printable_cn_atv = try tlv(arena, 0x30, &.{
        try oidTlv(arena, &oid.well_known.common_name),
        try tlv(arena, 0x13, &.{"A"}),
    });
    const multi_attribute_printable = try tlv(arena, 0x30, &.{try tlv(arena, 0x31, &.{ printable_cn_atv, org_atv })});
    const combined_printable = try x509.parseNameRaw(arena, multi_attribute_printable, .{});
    try testing.expect(combined.eqlForChaining(&combined_printable));
}

test "name chaining key construction is leak-free across allocation failure points" {
    var fixture_arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer fixture_arena.deinit();
    const fixture_allocator = fixture_arena.allocator();
    const name_der = try nameWithCnTag(fixture_allocator, 0x0c, "Straße \u{00AD} \u{FF21}\u{FF23}\u{FF2D}\u{FF25}");

    try testing.checkAllAllocationFailures(testing.allocator, struct {
        fn run(inner_allocator: std.mem.Allocator, der_bytes: []const u8) !void {
            var arena_inst = std.heap.ArenaAllocator.init(inner_allocator);
            defer arena_inst.deinit();
            _ = try x509.parseNameRaw(arena_inst.allocator(), der_bytes, .{});
        }
    }.run, .{name_der});
}

test "parser is leak-free across allocation failure points" {
    const allocator = testing.allocator;
    var fixture = try loadFixture(allocator, ecdsa_leaf_pem);
    defer fixture.deinit(allocator);

    try testing.checkAllAllocationFailures(allocator, struct {
        fn run(inner_allocator: std.mem.Allocator, der_bytes: []const u8) !void {
            var cert = try x509.Certificate.parse(inner_allocator, der_bytes, .{});
            cert.deinit(inner_allocator);
        }
    }.run, .{fixture.der});
}

test "fuzz entrypoint tolerates arbitrary and hostile input" {
    const allocator = testing.allocator;
    x509.fuzzParseCertificate(allocator, "");
    x509.fuzzParseCertificate(allocator, "\x30\x03\x02\x01\x01");
    x509.fuzzParseCertificate(allocator, "\x30\x82\xff\xff" ++ "\x00" ** 32);
    x509.fuzzParseCertificate(allocator, @embedFile("pki_malformed_der"));

    var fixture = try loadFixture(allocator, rsa_ca_pem);
    defer fixture.deinit(allocator);
    x509.fuzzParseCertificate(allocator, fixture.der);

    // Bit-flip corpus over a real certificate.
    var mutated = try allocator.dupe(u8, fixture.der);
    defer allocator.free(mutated);
    var index: usize = 0;
    while (index < mutated.len) : (index += 11) {
        mutated[index] ^= 0x40;
        x509.fuzzParseCertificate(allocator, mutated);
        mutated[index] ^= 0x40;
    }
}

test "reduced differential corpus is bounded and documented" {
    const reduced_corpus = @import("pki_reduced_corpus");
    try testing.expect(reduced_corpus.entries.len >= 1);
    try testing.expect(reduced_corpus.entries.len <= 64);
    for (reduced_corpus.entries, 0..) |entry, index| {
        try testing.expect(entry.name.len > 0 and entry.name.len <= 96);
        // Strict kebab-case: lower/digit runs joined by single hyphens, never
        // leading, trailing, or doubled.
        try testing.expect(entry.name[0] != '-' and entry.name[entry.name.len - 1] != '-');
        var previous: u8 = 0;
        for (entry.name) |byte| {
            try testing.expect(std.ascii.isLower(byte) or std.ascii.isDigit(byte) or byte == '-');
            try testing.expect(!(byte == '-' and previous == '-'));
            previous = byte;
        }
        try testing.expect(entry.seed.len > 0 and entry.seed.len <= 64 * 1024);
        try testing.expect(entry.source_case.len > 0);
        try testing.expect(entry.provenance.len > 0);
        try testing.expect(entry.license.len > 0);
        switch (entry.expected) {
            .parse_error => |name| try testing.expect(name.len > 0),
            .der_parse_error => |name| try testing.expect(name.len > 0),
            .tardigrade_class => |class| try testing.expect(class.len > 0),
        }
        for (reduced_corpus.entries[0..index]) |earlier| {
            try testing.expect(!std.mem.eql(u8, earlier.name, entry.name));
            try testing.expect(!std.mem.eql(u8, earlier.seed, entry.seed));
        }
    }
}

test "reduced differential seeds keep their recorded parse outcome" {
    const allocator = testing.allocator;
    const reduced_corpus = @import("pki_reduced_corpus");
    for (reduced_corpus.entries) |entry| {
        if (x509.Certificate.parse(allocator, entry.seed, .{})) |parsed| {
            var certificate = parsed;
            defer certificate.deinit(allocator);
            // A parse-error seed must not parse; a pipeline-class seed must
            // (its class is replayed by tests/pki_differential.zig).
            try testing.expect(entry.expected == .tardigrade_class);
        } else |err| {
            switch (entry.expected) {
                .parse_error => |expected| try testing.expectEqualStrings(expected, @errorName(err)),
                .der_parse_error => {},
                .tardigrade_class => return error.TestUnexpectedResult,
            }
        }
        // Every promoted seed also exercises the fuzz entrypoint's limits.
        x509.fuzzParseCertificate(allocator, entry.seed);
    }
}

// --- #492 mutation-driven semantic-model targets ----------------------------
//
// #348 owns "does this decision match OpenSSL". This target owns the model's
// structural contract: every borrowed view stays inside the caller's DER,
// every typed accessor agrees with the extension list it was derived from,
// configured count bounds are the exact refusal point, and a failed parse
// (including a failed allocation) never leaves a partially owned model.

/// #348's minimized hostile certificates are high-value seeds here too.
const x509_reduced_corpus_seeds = blk: {
    const reduced_corpus = @import("pki_reduced_corpus");
    var seeds: [reduced_corpus.entries.len][]const u8 = undefined;
    for (reduced_corpus.entries, &seeds) |entry, *seed| seed.* = entry.seed;
    break :blk seeds;
};

const fuzz_x509_limits: x509.Limits = .{
    .der = .{ .max_depth = 12, .max_element_len = 4096, .max_elements = 256 },
    .max_extensions = 8,
    .max_name_rdns = 8,
    .max_name_attributes = 4,
    .max_general_names = 8,
    .max_eku_purposes = 8,
    .max_policies = 8,
    .max_policy_qualifiers = 4,
    .max_policy_mappings = 8,
    .max_distribution_points = 4,
    .max_access_descriptions = 4,
    .max_name_constraint_subtrees = 8,
    .max_tls_features = 4,
};

fn expectViewContained(raw: []const u8, view: []const u8) !void {
    const raw_start = @intFromPtr(raw.ptr);
    const view_start = @intFromPtr(view.ptr);
    try testing.expect(view_start >= raw_start);
    try testing.expect(view_start - raw_start + view.len <= raw.len);
}

/// Which GeneralName IP encoding the surrounding extension mandates: a bare
/// address in SAN/AIA/CRLDP, address-plus-mask inside Name Constraints.
const IpForm = enum { host, cidr };

fn expectGeneralNameContained(raw: []const u8, name: x509.GeneralName, form: IpForm) !void {
    switch (name) {
        .rfc822_name, .dns_name, .directory_name, .uniform_resource_identifier => |value| {
            try expectViewContained(raw, value);
        },
        .ip_address => |value| {
            try expectViewContained(raw, value);
            switch (form) {
                .host => try testing.expect(value.len == 4 or value.len == 16),
                .cidr => try testing.expect(value.len == 8 or value.len == 32),
            }
        },
        // A decoded OID is a fixed-size value, never a borrow.
        .registered_id => |value| try testing.expect(value.components().len <= oid.max_components),
        .other => |value| try expectViewContained(raw, value.raw),
    }
}

fn expectGeneralNamesContained(raw: []const u8, names: []const x509.GeneralName, form: IpForm) !void {
    for (names) |name| try expectGeneralNameContained(raw, name, form);
}

fn expectAlgorithmContained(raw: []const u8, algorithm: x509.AlgorithmIdentifier) !void {
    try expectViewContained(raw, algorithm.raw);
    if (algorithm.parameters_raw) |parameters| try expectViewContained(raw, parameters);
}

fn expectNameContained(raw: []const u8, name: x509.Name) !void {
    try expectViewContained(raw, name.raw);
    for (name.rdns) |rdn| {
        for (rdn.attributes) |attribute| try expectViewContained(raw, attribute.value);
    }
    // `chaining_key`/`rdn_chaining_keys` are deliberately *not* containment
    // checked: they are arena-owned RFC 4518 canonical forms the parser
    // computes, not borrows of the input, so demanding containment would
    // assert the opposite of their documented ownership.
    try testing.expectEqual(name.rdns.len, name.rdn_chaining_keys.len);
}

fn expectSpkiContained(raw: []const u8, spki: x509.SubjectPublicKeyInfo) !void {
    try expectViewContained(raw, spki.raw);
    try expectAlgorithmContained(raw, spki.algorithm);
    try expectViewContained(raw, spki.subject_public_key.data);
}

fn expectParsedExtensionContained(raw: []const u8, parsed: x509.Extension.Parsed) !void {
    switch (parsed) {
        .subject_alt_name => |names| try expectGeneralNamesContained(raw, names, .host),
        .subject_key_identifier => |value| try expectViewContained(raw, value),
        .authority_key_identifier => |value| {
            if (value.key_identifier) |identifier| try expectViewContained(raw, identifier);
            if (value.authority_cert_issuer_raw) |issuer| try expectViewContained(raw, issuer);
            if (value.authority_cert_serial) |serial| try expectViewContained(raw, serial);
        },
        .name_constraints => |value| {
            for (value.permitted) |subtree| try expectGeneralNameContained(raw, subtree.base, .cidr);
            for (value.excluded) |subtree| try expectGeneralNameContained(raw, subtree.base, .cidr);
        },
        .authority_info_access => |descriptions| {
            for (descriptions) |description| try expectGeneralNameContained(raw, description.location, .host);
        },
        .crl_distribution_points => |points| {
            for (points) |point| {
                try expectViewContained(raw, point.raw);
                try expectGeneralNamesContained(raw, point.full_names, .host);
            }
        },
        .certificate_policies => |policies| {
            for (policies) |policy| {
                for (policy.qualifiers) |qualifier| try expectViewContained(raw, qualifier.value_raw);
            }
        },
        // Value-only payloads: no borrowed slice to escape.
        .basic_constraints,
        .key_usage,
        .extended_key_usage,
        .policy_mappings,
        .policy_constraints,
        .inhibit_any_policy,
        .tls_features,
        .unrecognized,
        => {},
    }
}

/// Walks *every* borrowed slice the parsed model exposes and proves it points
/// into the caller's DER. A parser regression that pointed any field at
/// temporary or recycled parser storage has to fail here, which is the #492
/// borrowed-slice-escape criterion.
fn expectBorrowsOnlyFromInput(certificate: *const x509.Certificate) !void {
    const raw = certificate.raw;
    try expectViewContained(raw, certificate.tbs_raw);
    try expectViewContained(raw, certificate.serial_number.content);
    try expectAlgorithmContained(raw, certificate.signature_algorithm);
    try expectNameContained(raw, certificate.issuer);
    try expectNameContained(raw, certificate.subject);
    try expectSpkiContained(raw, certificate.subject_public_key_info);
    if (certificate.issuer_unique_id) |unique_id| try expectViewContained(raw, unique_id.data);
    if (certificate.subject_unique_id) |unique_id| try expectViewContained(raw, unique_id.data);
    try expectViewContained(raw, certificate.signature_value.data);
    for (certificate.extensions) |extension| {
        try expectViewContained(raw, extension.value);
        try expectParsedExtensionContained(raw, extension.parsed);
    }
}

// --- Full-model equality, for the "identical bytes, identical model" oracle -

fn expectSameOptionalSlice(expected: ?[]const u8, actual: ?[]const u8) !void {
    if (expected) |lhs| {
        const rhs = actual orelse return error.TestUnexpectedResult;
        try testing.expectEqualSlices(u8, lhs, rhs);
    } else {
        try testing.expect(actual == null);
    }
}

fn expectSameOid(expected: oid.ObjectIdentifier, actual: oid.ObjectIdentifier) !void {
    try testing.expectEqualSlices(u32, expected.components(), actual.components());
}

fn expectSameOptionalOid(expected: ?oid.ObjectIdentifier, actual: ?oid.ObjectIdentifier) !void {
    if (expected) |lhs| {
        const rhs = actual orelse return error.TestUnexpectedResult;
        try expectSameOid(lhs, rhs);
    } else {
        try testing.expect(actual == null);
    }
}

fn expectSameAlgorithm(expected: x509.AlgorithmIdentifier, actual: x509.AlgorithmIdentifier) !void {
    try testing.expectEqualSlices(u8, expected.raw, actual.raw);
    try expectSameOid(expected.oid, actual.oid);
    try expectSameOptionalSlice(expected.parameters_raw, actual.parameters_raw);
    try testing.expectEqual(expected.parameters_null, actual.parameters_null);
}

fn expectSameName(expected: x509.Name, actual: x509.Name) !void {
    try testing.expectEqualSlices(u8, expected.raw, actual.raw);
    try testing.expectEqualSlices(u8, expected.chaining_key, actual.chaining_key);
    try testing.expectEqual(expected.rdns.len, actual.rdns.len);
    try testing.expectEqual(expected.rdn_chaining_keys.len, actual.rdn_chaining_keys.len);
    for (expected.rdn_chaining_keys, actual.rdn_chaining_keys) |lhs, rhs| {
        try testing.expectEqualSlices(u8, lhs, rhs);
    }
    for (expected.rdns, actual.rdns) |lhs, rhs| {
        try testing.expectEqual(lhs.attributes.len, rhs.attributes.len);
        for (lhs.attributes, rhs.attributes) |left, right| {
            try expectSameOid(left.type, right.type);
            try testing.expect(left.value_tag.eql(right.value_tag));
            try testing.expectEqualSlices(u8, left.value, right.value);
        }
    }
}

fn expectSameGeneralName(expected: x509.GeneralName, actual: x509.GeneralName) !void {
    const Tag = std.meta.Tag(x509.GeneralName);
    try testing.expectEqual(@as(Tag, expected), @as(Tag, actual));
    switch (expected) {
        .rfc822_name => try testing.expectEqualSlices(u8, expected.rfc822_name, actual.rfc822_name),
        .dns_name => try testing.expectEqualSlices(u8, expected.dns_name, actual.dns_name),
        .directory_name => try testing.expectEqualSlices(u8, expected.directory_name, actual.directory_name),
        .uniform_resource_identifier => try testing.expectEqualSlices(
            u8,
            expected.uniform_resource_identifier,
            actual.uniform_resource_identifier,
        ),
        .ip_address => try testing.expectEqualSlices(u8, expected.ip_address, actual.ip_address),
        .registered_id => try expectSameOid(expected.registered_id, actual.registered_id),
        .other => {
            try testing.expectEqual(expected.other.tag_number, actual.other.tag_number);
            try testing.expectEqualSlices(u8, expected.other.raw, actual.other.raw);
        },
    }
}

fn expectSameGeneralNames(expected: []const x509.GeneralName, actual: []const x509.GeneralName) !void {
    try testing.expectEqual(expected.len, actual.len);
    for (expected, actual) |lhs, rhs| try expectSameGeneralName(lhs, rhs);
}

fn expectSameParsedExtension(expected: x509.Extension.Parsed, actual: x509.Extension.Parsed) !void {
    const Tag = std.meta.Tag(x509.Extension.Parsed);
    try testing.expectEqual(@as(Tag, expected), @as(Tag, actual));
    switch (expected) {
        .basic_constraints => try testing.expectEqual(expected.basic_constraints, actual.basic_constraints),
        .key_usage => try testing.expectEqual(expected.key_usage, actual.key_usage),
        .subject_alt_name => try expectSameGeneralNames(expected.subject_alt_name, actual.subject_alt_name),
        .extended_key_usage => {
            try testing.expectEqual(expected.extended_key_usage.purposes.len, actual.extended_key_usage.purposes.len);
            for (expected.extended_key_usage.purposes, actual.extended_key_usage.purposes) |lhs, rhs| {
                try expectSameOid(lhs, rhs);
            }
        },
        .subject_key_identifier => try testing.expectEqualSlices(
            u8,
            expected.subject_key_identifier,
            actual.subject_key_identifier,
        ),
        .authority_key_identifier => {
            try expectSameOptionalSlice(
                expected.authority_key_identifier.key_identifier,
                actual.authority_key_identifier.key_identifier,
            );
            try expectSameOptionalSlice(
                expected.authority_key_identifier.authority_cert_issuer_raw,
                actual.authority_key_identifier.authority_cert_issuer_raw,
            );
            try expectSameOptionalSlice(
                expected.authority_key_identifier.authority_cert_serial,
                actual.authority_key_identifier.authority_cert_serial,
            );
        },
        .name_constraints => {
            try testing.expectEqual(expected.name_constraints.permitted.len, actual.name_constraints.permitted.len);
            try testing.expectEqual(expected.name_constraints.excluded.len, actual.name_constraints.excluded.len);
            for (expected.name_constraints.permitted, actual.name_constraints.permitted) |lhs, rhs| {
                try expectSameGeneralName(lhs.base, rhs.base);
            }
            for (expected.name_constraints.excluded, actual.name_constraints.excluded) |lhs, rhs| {
                try expectSameGeneralName(lhs.base, rhs.base);
            }
        },
        .authority_info_access => {
            try testing.expectEqual(expected.authority_info_access.len, actual.authority_info_access.len);
            for (expected.authority_info_access, actual.authority_info_access) |lhs, rhs| {
                try expectSameOid(lhs.method, rhs.method);
                try expectSameGeneralName(lhs.location, rhs.location);
            }
        },
        .crl_distribution_points => {
            try testing.expectEqual(expected.crl_distribution_points.len, actual.crl_distribution_points.len);
            for (expected.crl_distribution_points, actual.crl_distribution_points) |lhs, rhs| {
                try testing.expectEqualSlices(u8, lhs.raw, rhs.raw);
                try expectSameGeneralNames(lhs.full_names, rhs.full_names);
            }
        },
        .certificate_policies => {
            try testing.expectEqual(expected.certificate_policies.len, actual.certificate_policies.len);
            for (expected.certificate_policies, actual.certificate_policies) |lhs, rhs| {
                try expectSameOid(lhs.policy, rhs.policy);
                try testing.expectEqual(lhs.qualifiers.len, rhs.qualifiers.len);
                for (lhs.qualifiers, rhs.qualifiers) |left, right| {
                    try expectSameOid(left.oid, right.oid);
                    try testing.expectEqualSlices(u8, left.value_raw, right.value_raw);
                    try testing.expectEqual(left.kind, right.kind);
                }
            }
        },
        .policy_mappings => {
            try testing.expectEqual(expected.policy_mappings.len, actual.policy_mappings.len);
            for (expected.policy_mappings, actual.policy_mappings) |lhs, rhs| {
                try expectSameOid(lhs.issuer_domain_policy, rhs.issuer_domain_policy);
                try expectSameOid(lhs.subject_domain_policy, rhs.subject_domain_policy);
            }
        },
        .policy_constraints => try testing.expectEqual(expected.policy_constraints, actual.policy_constraints),
        .inhibit_any_policy => try testing.expectEqual(expected.inhibit_any_policy, actual.inhibit_any_policy),
        .tls_features => try testing.expectEqualSlices(
            u16,
            expected.tls_features.features,
            actual.tls_features.features,
        ),
        .unrecognized => {},
    }
}

fn expectSameBitString(expected: der.BitStringView, actual: der.BitStringView) !void {
    try testing.expectEqual(expected.unused_bits, actual.unused_bits);
    try testing.expectEqualSlices(u8, expected.data, actual.data);
}

fn expectSameOptionalBitString(expected: ?der.BitStringView, actual: ?der.BitStringView) !void {
    if (expected) |lhs| {
        const rhs = actual orelse return error.TestUnexpectedResult;
        try expectSameBitString(lhs, rhs);
    } else {
        try testing.expect(actual == null);
    }
}

/// Compares the complete public semantic model, not just its structural tags,
/// so two parses of the same bytes cannot disagree on any decoded field or
/// parsed extension payload while still passing the determinism oracle.
fn expectSameCertificateModel(expected: *const x509.Certificate, actual: *const x509.Certificate) !void {
    try testing.expectEqualSlices(u8, expected.raw, actual.raw);
    try testing.expectEqualSlices(u8, expected.tbs_raw, actual.tbs_raw);
    try testing.expectEqual(expected.version, actual.version);
    try testing.expectEqualSlices(u8, expected.serial_number.content, actual.serial_number.content);
    try expectSameAlgorithm(expected.signature_algorithm, actual.signature_algorithm);
    try testing.expectEqual(expected.signatureAlgorithm(), actual.signatureAlgorithm());
    try expectSameName(expected.issuer, actual.issuer);
    try expectSameName(expected.subject, actual.subject);
    try testing.expectEqual(expected.validity, actual.validity);
    try testing.expectEqualSlices(u8, expected.subject_public_key_info.raw, actual.subject_public_key_info.raw);
    try expectSameAlgorithm(expected.subject_public_key_info.algorithm, actual.subject_public_key_info.algorithm);
    try expectSameBitString(
        expected.subject_public_key_info.subject_public_key,
        actual.subject_public_key_info.subject_public_key,
    );
    try testing.expectEqual(expected.subject_public_key_info.key_type, actual.subject_public_key_info.key_type);
    try expectSameOptionalOid(
        expected.subject_public_key_info.named_curve,
        actual.subject_public_key_info.named_curve,
    );
    try expectSameOptionalBitString(expected.issuer_unique_id, actual.issuer_unique_id);
    try expectSameOptionalBitString(expected.subject_unique_id, actual.subject_unique_id);
    try expectSameBitString(expected.signature_value, actual.signature_value);
    try testing.expectEqual(expected.isSelfIssued(), actual.isSelfIssued());
    try testing.expectEqual(expected.hasUnhandledCriticalExtension(), actual.hasUnhandledCriticalExtension());

    try testing.expectEqual(expected.extensions.len, actual.extensions.len);
    for (expected.extensions, actual.extensions) |lhs, rhs| {
        try expectSameOid(lhs.oid, rhs.oid);
        try testing.expectEqual(lhs.critical, rhs.critical);
        try testing.expectEqualSlices(u8, lhs.value, rhs.value);
        try expectSameParsedExtension(lhs.parsed, rhs.parsed);
    }
}

/// Build one Smith-chosen extension value; `null` means "skip this slot".
fn fuzzExtension(arena: std.mem.Allocator, smith: *testing.Smith, slot: usize) !?[]const u8 {
    // Most slots are absent in any given case. Emitting all ten every time
    // would exceed `max_extensions` unconditionally, so every case would
    // stop at `CountLimitExceeded` and the model's own invariants would
    // never be reached.
    if (smith.index(3) != 0) return null;
    const critical = smith.index(2) == 0;
    // Occasionally replace the extension's value with arbitrary bytes, so the
    // extension parsers see hostile content under a well-formed wrapper.
    const corrupt = smith.index(4) == 0;
    var corrupt_storage: [48]u8 = undefined;
    const corrupt_len = smith.index(corrupt_storage.len + 1);
    smith.bytes(corrupt_storage[0..corrupt_len]);
    const corrupt_value = corrupt_storage[0..corrupt_len];

    const dns_names = [_][]const u8{ "a.test", "*.b.test", "", "xn--fa-hia.test", "..", "A.TEST" };
    const eku_choices = [_][]const u32{
        &oid.well_known.server_auth,
        &oid.well_known.client_auth,
        &oid.well_known.any_ext_key_usage,
        &oid.well_known.code_signing,
        &[_]u32{ 1, 3, 6, 1, 4, 1, 4242, 1 },
    };

    switch (slot) {
        0 => {
            var parts: std.ArrayList([]const u8) = .empty;
            defer parts.deinit(arena);
            if (smith.index(2) == 0) try parts.append(arena, try tlv(arena, 0x01, &.{&[_]u8{if (smith.index(2) == 0) 0xff else 0x00}}));
            if (smith.index(2) == 0) try parts.append(arena, try tlv(arena, 0x02, &.{&[_]u8{@intCast(smith.index(128))}}));
            const value = if (corrupt) corrupt_value else try tlv(arena, 0x30, parts.items);
            return try extensionTlv(arena, &oid.well_known.basic_constraints, critical, value);
        },
        1 => {
            const unused: u8 = @intCast(smith.index(9)); // 8 is out of range.
            const bits: u8 = @intCast(smith.index(256));
            const value = if (corrupt) corrupt_value else try tlv(arena, 0x03, &.{&[_]u8{ unused, bits }});
            return try extensionTlv(arena, &oid.well_known.key_usage, critical, value);
        },
        2 => {
            var purposes: std.ArrayList([]const u8) = .empty;
            defer purposes.deinit(arena);
            for (0..smith.index(6)) |_| {
                try purposes.append(arena, try oidTlv(arena, eku_choices[smith.index(eku_choices.len)]));
            }
            const value = if (corrupt) corrupt_value else try tlv(arena, 0x30, purposes.items);
            return try extensionTlv(arena, &oid.well_known.ext_key_usage, critical, value);
        },
        3 => {
            var names: std.ArrayList([]const u8) = .empty;
            defer names.deinit(arena);
            for (0..smith.index(10)) |_| {
                const name = switch (smith.index(7)) {
                    0 => try tlv(arena, 0x82, &.{dns_names[smith.index(dns_names.len)]}),
                    1 => blk: {
                        var address: [17]u8 = undefined;
                        const length = smith.index(address.len + 1);
                        smith.bytes(address[0..length]);
                        break :blk try tlv(arena, 0x87, &.{address[0..length]});
                    },
                    2 => try tlv(arena, 0x81, &.{"user@example.test"}),
                    3 => try tlv(arena, 0x86, &.{"https://a.test/x"}),
                    4 => try tlv(arena, 0xa4, &.{try nameWithCn(arena, "Directory")}),
                    5 => try tlv(arena, 0x88, &.{&[_]u8{ 0x2a, 0x03 }}),
                    else => try tlv(arena, 0xa0, &.{&[_]u8{ 0x05, 0x00 }}),
                };
                try names.append(arena, name);
            }
            const value = if (corrupt) corrupt_value else try tlv(arena, 0x30, names.items);
            return try extensionTlv(arena, &oid.well_known.subject_alt_name, critical, value);
        },
        4 => {
            var permitted: std.ArrayList([]const u8) = .empty;
            defer permitted.deinit(arena);
            var excluded: std.ArrayList([]const u8) = .empty;
            defer excluded.deinit(arena);
            for (0..smith.index(4)) |_| {
                try permitted.append(arena, try tlv(arena, 0x30, &.{try tlv(arena, 0x82, &.{dns_names[smith.index(dns_names.len)]})}));
            }
            for (0..smith.index(4)) |_| {
                var address: [33]u8 = undefined;
                const length = smith.index(address.len + 1);
                smith.bytes(address[0..length]);
                try excluded.append(arena, try tlv(arena, 0x30, &.{try tlv(arena, 0x87, &.{address[0..length]})}));
            }
            var parts: std.ArrayList([]const u8) = .empty;
            defer parts.deinit(arena);
            if (permitted.items.len != 0) try parts.append(arena, try tlv(arena, 0xa0, permitted.items));
            if (excluded.items.len != 0) try parts.append(arena, try tlv(arena, 0xa1, excluded.items));
            const value = if (corrupt) corrupt_value else try tlv(arena, 0x30, parts.items);
            return try extensionTlv(arena, &oid.well_known.name_constraints, critical, value);
        },
        5 => {
            var identifier: [24]u8 = undefined;
            const length = smith.index(identifier.len + 1);
            smith.bytes(identifier[0..length]);
            const value = if (corrupt) corrupt_value else try tlv(arena, 0x04, &.{identifier[0..length]});
            return try extensionTlv(arena, &oid.well_known.subject_key_identifier, critical, value);
        },
        6 => {
            var identifier: [24]u8 = undefined;
            const length = smith.index(identifier.len + 1);
            smith.bytes(identifier[0..length]);
            const value = if (corrupt) corrupt_value else try tlv(arena, 0x30, &.{try tlv(arena, 0x80, &.{identifier[0..length]})});
            return try extensionTlv(arena, &oid.well_known.authority_key_identifier, critical, value);
        },
        7 => {
            var policies: std.ArrayList([]const u8) = .empty;
            defer policies.deinit(arena);
            for (0..smith.index(4)) |index| {
                const policy_oid = [_]u32{ 2, 5, 29, 32, @intCast(index) };
                try policies.append(arena, try tlv(arena, 0x30, &.{try oidTlv(arena, &policy_oid)}));
            }
            const value = if (corrupt) corrupt_value else try tlv(arena, 0x30, policies.items);
            return try extensionTlv(arena, &oid.well_known.certificate_policies, critical, value);
        },
        8 => {
            const value = if (corrupt) corrupt_value else try tlv(arena, 0x02, &.{&[_]u8{@intCast(smith.index(128))}});
            return try extensionTlv(arena, &oid.well_known.inhibit_any_policy, critical, value);
        },
        else => return try extensionTlv(arena, &unknown_ext_oid, critical, if (corrupt) corrupt_value else &[_]u8{ 0x05, 0x00 }),
    }
}

fn parseForAllocationSweep(allocator: std.mem.Allocator, input: []const u8) !void {
    var certificate = x509.Certificate.parse(allocator, input, fuzz_x509_limits) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return,
    };
    certificate.deinit(allocator);
}

test "fuzz: PKI: X.509 semantic model borrows only from its input and honors its count bounds" {
    try testing.fuzz({}, fuzzX509Semantics, .{ .corpus = &([_][]const u8{
        "",
        &[_]u8{0},
        &[_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 },
        &([_]u8{0x55} ** 40),
        &([_]u8{0xff} ** 64),
        @embedFile("pki_malformed_der"),
    } ++ x509_reduced_corpus_seeds) });
}

fn fuzzX509Semantics(_: void, smith: *testing.Smith) !void {
    const allocator = testing.allocator;
    var arena_inst = std.heap.ArenaAllocator.init(allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    var extensions: std.ArrayList([]const u8) = .empty;
    defer extensions.deinit(arena);
    for (0..10) |slot| {
        if (try fuzzExtension(arena, smith, slot)) |extension| try extensions.append(arena, extension);
    }
    // Duplicate a generated extension: RFC 5280 forbids a repeated OID, and
    // the parser must say so rather than silently keeping one of them.
    const duplicated = extensions.items.len != 0 and smith.index(3) == 0;
    if (duplicated) try extensions.append(arena, extensions.items[smith.index(extensions.items.len)]);

    // A malformed/unsupported inner signature AlgorithmIdentifier, which must
    // be rejected on its own terms rather than by the outer structure.
    const inner_algorithm: ?[]const u8 = switch (smith.index(4)) {
        0 => try tlv(arena, 0x30, &.{ try oidTlv(arena, &ecdsa_sha256_components), try tlv(arena, 0x05, &.{}) }),
        1 => try tlv(arena, 0x30, &.{}),
        2 => try tlv(arena, 0x30, &.{try oidTlv(arena, &[_]u32{ 1, 2, 3, 4, 5 })}),
        else => null,
    };

    const bytes = try buildCertificate(arena, .{
        .version = if (smith.index(8) == 0) null else try versionTlv(arena, @intCast(smith.index(4))),
        .inner_algorithm = inner_algorithm,
        .extensions_wrapper = if (extensions.items.len == 0) null else try extensionsWrapper(arena, extensions.items),
    });

    // Bit-flip mutation on top of the structured builder: the mutation-driven
    // half of this target, reaching states the builder alone cannot express.
    const mutation_count = smith.index(4);
    for (0..mutation_count) |_| {
        if (bytes.len == 0) break;
        bytes[smith.index(bytes.len)] ^= @intCast(1 + smith.index(255));
    }

    // Parse from a heap copy so the copy can be freed while the parsed model
    // is gone, proving the model never outlives (or retains) its input.
    const input = try allocator.dupe(u8, bytes);
    defer allocator.free(input);

    if (x509.Certificate.parse(allocator, input, fuzz_x509_limits)) |parsed| {
        var certificate = parsed;
        defer certificate.deinit(allocator);

        try testing.expectEqual(input.ptr, certificate.raw.ptr);
        try testing.expectEqual(input.len, certificate.raw.len);
        // Every borrowed slice anywhere in the model, not a hand-picked
        // subset, must point into the caller's DER.
        try expectBorrowsOnlyFromInput(&certificate);
        try der.validateInteger(certificate.serial_number.content, fuzz_x509_limits.der.max_integer_bytes);
        try testing.expect(certificate.issuer.rdns.len <= fuzz_x509_limits.max_name_rdns);
        try testing.expect(certificate.subject.rdns.len <= fuzz_x509_limits.max_name_rdns);
        for (certificate.issuer.rdns) |rdn| {
            try testing.expect(rdn.attributes.len <= fuzz_x509_limits.max_name_attributes);
        }
        for (certificate.subject.rdns) |rdn| {
            try testing.expect(rdn.attributes.len <= fuzz_x509_limits.max_name_attributes);
        }
        try testing.expect(certificate.isSelfIssued() == certificate.issuer.eqlForChaining(&certificate.subject));

        try testing.expect(certificate.extensions.len <= fuzz_x509_limits.max_extensions);
        var unhandled_critical = false;
        for (certificate.extensions, 0..) |extension, index| {
            // A duplicate OID must have been rejected, never merged.
            for (certificate.extensions[0..index]) |earlier| {
                try testing.expect(!earlier.oid.eql(&extension.oid));
            }
            if (extension.critical and extension.parsed == .unrecognized) unhandled_critical = true;
            // Every typed accessor must agree with the extension list it was
            // derived from — no accessor may synthesize or drop an extension.
            switch (extension.parsed) {
                .basic_constraints => |value| {
                    try testing.expectEqual(value, certificate.basicConstraints().?);
                },
                .key_usage => |value| try testing.expectEqual(value, certificate.keyUsage().?),
                .subject_alt_name => |names| {
                    try testing.expect(names.len <= fuzz_x509_limits.max_general_names);
                    try expectSameGeneralNames(names, certificate.subjectAltName().?);
                },
                .extended_key_usage => |value| {
                    try testing.expect(value.purposes.len <= fuzz_x509_limits.max_eku_purposes);
                    try testing.expectEqual(value.purposes.len, certificate.extendedKeyUsage().?.purposes.len);
                },
                .subject_key_identifier => |value| {
                    try testing.expectEqualSlices(u8, value, certificate.subjectKeyIdentifier().?);
                },
                .authority_key_identifier => |value| {
                    try expectSameOptionalSlice(value.key_identifier, certificate.authorityKeyIdentifier().?.key_identifier);
                },
                .name_constraints => |value| {
                    try testing.expect(value.permitted.len <= fuzz_x509_limits.max_name_constraint_subtrees);
                    try testing.expect(value.excluded.len <= fuzz_x509_limits.max_name_constraint_subtrees);
                    try testing.expectEqual(value.permitted.len, certificate.nameConstraints().?.permitted.len);
                    try testing.expectEqual(value.excluded.len, certificate.nameConstraints().?.excluded.len);
                },
                .certificate_policies => |value| {
                    try testing.expect(value.len <= fuzz_x509_limits.max_policies);
                    try testing.expectEqual(value.len, certificate.certificatePolicies().?.len);
                    for (value) |policy| {
                        try testing.expect(policy.qualifiers.len <= fuzz_x509_limits.max_policy_qualifiers);
                    }
                },
                .policy_mappings => |value| {
                    try testing.expect(value.len <= fuzz_x509_limits.max_policy_mappings);
                    try testing.expectEqual(value.len, certificate.policyMappings().?.len);
                },
                .policy_constraints => |value| try testing.expectEqual(value, certificate.policyConstraints().?),
                .authority_info_access => |value| try testing.expect(value.len <= fuzz_x509_limits.max_access_descriptions),
                .crl_distribution_points => |value| try testing.expect(value.len <= fuzz_x509_limits.max_distribution_points),
                .inhibit_any_policy => |value| try testing.expectEqual(value, certificate.inhibitAnyPolicy().?),
                .tls_features => |value| {
                    try testing.expect(value.features.len <= fuzz_x509_limits.max_tls_features);
                    try testing.expectEqualSlices(u16, value.features, certificate.tlsFeatures().?.features);
                    try testing.expectEqual(value.requiresStapledStatus(), certificate.mustStaple());
                },
                .unrecognized => {},
            }
        }
        try testing.expectEqual(unhandled_critical, certificate.hasUnhandledCriticalExtension());
        // An unmutated duplicate must have been rejected outright; a bit-flip
        // can legitimately make the two OIDs differ again, so only the
        // unmutated case has an oracle here.
        try testing.expect(!duplicated or mutation_count > 0);

        // Identical bytes must produce an identical model — compared across
        // the whole public model, including every parsed extension payload,
        // not just its structural tags.
        var replay = try x509.Certificate.parse(allocator, input, fuzz_x509_limits);
        defer replay.deinit(allocator);
        try expectSameCertificateModel(&certificate, &replay);
    } else |err| switch (err) {
        error.MalformedCertificate,
        error.UnsupportedVersion,
        error.MalformedSerialNumber,
        error.MalformedAlgorithm,
        error.SignatureAlgorithmMismatch,
        error.MalformedName,
        error.MalformedValidity,
        error.MalformedPublicKeyInfo,
        error.MalformedUniqueId,
        error.MalformedSignature,
        error.MalformedExtension,
        error.DuplicateExtension,
        error.NamePreparationFailed,
        error.CountLimitExceeded,
        error.OutOfMemory,
        => {},
    }

    // The extension-count bound is the exact refusal point, using extensions
    // that always parse (unknown, non-critical) so nothing else can reject
    // first.
    {
        var many: std.ArrayList([]const u8) = .empty;
        defer many.deinit(arena);
        const count = fuzz_x509_limits.max_extensions + smith.index(2);
        for (0..count) |index| {
            const ext_oid = [_]u32{ 1, 3, 6, 1, 4, 1, 99999, @intCast(index) };
            try many.append(arena, try extensionTlv(arena, &ext_oid, false, &[_]u8{ 0x05, 0x00 }));
        }
        const bounded = try buildCertificate(arena, .{
            .version = try versionTlv(arena, 2),
            .extensions_wrapper = try extensionsWrapper(arena, many.items),
        });
        if (count > fuzz_x509_limits.max_extensions) {
            try testing.expectError(error.CountLimitExceeded, x509.Certificate.parse(allocator, bounded, fuzz_x509_limits));
        } else {
            var certificate = try x509.Certificate.parse(allocator, bounded, fuzz_x509_limits);
            defer certificate.deinit(allocator);
            try testing.expectEqual(count, certificate.extensions.len);
        }
    }

    // Allocation failure at every reachable point: no leak, and no partially
    // owned model escapes a failed parse.
    try testing.checkAllAllocationFailures(allocator, parseForAllocationSweep, .{input});

    x509.fuzzParseCertificate(allocator, input);
}

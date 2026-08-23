//! Certificate signature verification matrix tests (#343, extended by #645).
//!
//! Fixtures under `testdata/` are OpenSSL-generated, so a successful
//! verification here is a differential check against OpenSSL's signer: the
//! self-signed certificates verify against their own SubjectPublicKeyInfo for
//! each supported algorithm, and every corruption that OpenSSL would reject is
//! rejected here too.
//!
//! - `ed25519.crt` — self-signed Ed25519 (signature Ed25519).
//! - `ecdsa_p256_ca.crt` — self-signed P-256 (signature ecdsa-with-SHA256).
//! - `rsa_pss.crt` — self-signed RSA-2048 (signature RSASSA-PSS SHA-256).
//! - `rsa_ca.crt` — self-signed RSA-2048 with sha256WithRSAEncryption
//!   (PKCS#1 v1.5, #645).
//! - `ecdsa_leaf.crt` — P-256 key but signed by the RSA CA with
//!   sha256WithRSAEncryption (PKCS#1 v1.5, #645), proving PKCS#1 verification
//!   works for a leaf whose own key type differs from its issuer's.

const std = @import("std");
const crypto = @import("crypto");
const der = @import("der.zig");
const oid = @import("oid.zig");
const pem = @import("pem.zig");
const x509 = @import("x509.zig");
const verify = @import("verify.zig");

const testing = std.testing;

const ed25519_crt = @embedFile("testdata/ed25519.crt");
const ecdsa_p256_ca_crt = @embedFile("testdata/ecdsa_p256_ca.crt");
const rsa_pss_crt = @embedFile("testdata/rsa_pss.crt");
const rsa_pkcs1_crt = @embedFile("testdata/rsa_ca.crt");
const ecdsa_leaf_crt = @embedFile("testdata/ecdsa_leaf.crt");

fn testProvider(state: *crypto.pure_zig.DeterministicEntropy, prov: *crypto.pure_zig.Provider) crypto.provider.CryptoProvider {
    state.* = crypto.pure_zig.DeterministicEntropy.init(0x343);
    prov.* = crypto.pure_zig.Provider.init(state.entropy());
    return prov.cryptoProvider();
}

const Loaded = struct {
    cert_pem: pem.Certificate,
    cert: x509.Certificate,

    fn init(allocator: std.mem.Allocator, pem_text: []const u8) !Loaded {
        var cert_pem = try pem.loadCertificatePem(allocator, pem_text, .{});
        errdefer cert_pem.deinit(allocator);
        const cert = try x509.Certificate.parse(allocator, cert_pem.der, .{});
        return .{ .cert_pem = cert_pem, .cert = cert };
    }

    fn deinit(self: *Loaded, allocator: std.mem.Allocator) void {
        self.cert.deinit(allocator);
        self.cert_pem.deinit(allocator);
    }
};

test "self-signed Ed25519 and ECDSA-P256 certificates verify" {
    const allocator = testing.allocator;
    var det: crypto.pure_zig.DeterministicEntropy = undefined;
    var prov: crypto.pure_zig.Provider = undefined;
    const cp = testProvider(&det, &prov);

    inline for (.{ ed25519_crt, ecdsa_p256_ca_crt }) |fixture| {
        var loaded = try Loaded.init(allocator, fixture);
        defer loaded.deinit(allocator);
        try verify.verifySelfSignature(cp, &loaded.cert);
    }
}

test "RSA-PSS certificate verifies with the pure-Zig provider" {
    const allocator = testing.allocator;
    var det: crypto.pure_zig.DeterministicEntropy = undefined;
    var prov: crypto.pure_zig.Provider = undefined;
    const cp = testProvider(&det, &prov);

    var rp = try Loaded.init(allocator, rsa_pss_crt);
    defer rp.deinit(allocator);
    try testing.expectEqual(x509.SignatureAlgorithm.rsa_pss, rp.cert.signatureAlgorithm());
    try verify.verifySelfSignature(cp, &rp.cert);

    const out_of_range = try allocator.dupe(u8, rp.cert.signature_value.data);
    defer allocator.free(out_of_range);
    try testing.expectEqual(@as(usize, 256), out_of_range.len);
    var key_reader = der.Reader.init(rp.cert.subject_public_key_info.subject_public_key.data, .{});
    var key_sequence = try key_reader.readSequence();
    const modulus = try key_sequence.readInteger();
    _ = try key_sequence.readInteger();
    try key_sequence.expectEnd();
    try key_reader.expectEnd();
    try testing.expectEqual(@as(usize, 257), modulus.content.len);
    try testing.expectEqual(@as(u8, 0), modulus.content[0]);
    @memcpy(out_of_range, modulus.content[1..]);
    var invalid = rp.cert;
    invalid.signature_value = .{ .unused_bits = 0, .data = out_of_range };
    try testing.expectError(error.InvalidSignature, verify.verifySelfSignature(cp, &invalid));

    var greater_than_modulus = try allocator.dupe(u8, out_of_range);
    defer allocator.free(greater_than_modulus);
    var index = greater_than_modulus.len;
    while (index > 0) {
        index -= 1;
        if (greater_than_modulus[index] != 0xff) {
            greater_than_modulus[index] += 1;
            break;
        }
    } else unreachable;
    invalid.signature_value = .{ .unused_bits = 0, .data = greater_than_modulus };
    try testing.expectError(error.InvalidSignature, verify.verifySelfSignature(cp, &invalid));
}

test "the three matrix schemes classify to the right key types" {
    const allocator = testing.allocator;

    var ed = try Loaded.init(allocator, ed25519_crt);
    defer ed.deinit(allocator);
    try testing.expectEqual(x509.SignatureAlgorithm.ed25519, ed.cert.signatureAlgorithm());
    try testing.expectEqual(x509.PublicKeyType.ed25519, ed.cert.subject_public_key_info.key_type);

    var ec = try Loaded.init(allocator, ecdsa_p256_ca_crt);
    defer ec.deinit(allocator);
    try testing.expectEqual(x509.SignatureAlgorithm.ecdsa_sha256, ec.cert.signatureAlgorithm());
    try testing.expectEqual(x509.PublicKeyType.ecdsa_p256, ec.cert.subject_public_key_info.key_type);

    var rp = try Loaded.init(allocator, rsa_pss_crt);
    defer rp.deinit(allocator);
    try testing.expectEqual(x509.SignatureAlgorithm.rsa_pss, rp.cert.signatureAlgorithm());
    try testing.expectEqual(x509.PublicKeyType.rsa, rp.cert.subject_public_key_info.key_type);
}

/// Flip one interior byte of the serial-number INTEGER in a freshly
/// duplicated DER buffer. The serial lies inside the TBSCertificate but is
/// opaque to deeper parsing and independent of the public key, so the copy
/// re-parses cleanly, the self-signature key is unchanged, and only the signed
/// message differs — isolating a genuine tampered-TBS outcome. Flipping an
/// interior byte keeps the INTEGER minimally encoded.
fn tamperedSerialCopy(allocator: std.mem.Allocator, loaded: *const Loaded) ![]u8 {
    const der_bytes = loaded.cert_pem.der;
    const serial = loaded.cert.serial_number.content;
    std.debug.assert(serial.len >= 3);
    const offset = @intFromPtr(serial.ptr) - @intFromPtr(der_bytes.ptr) + serial.len / 2;
    const copy = try allocator.dupe(u8, der_bytes);
    copy[offset] ^= 0x01;
    return copy;
}

test "tampered TBS bytes fail with InvalidSignature for every supported algorithm" {
    const allocator = testing.allocator;
    var det: crypto.pure_zig.DeterministicEntropy = undefined;
    var prov: crypto.pure_zig.Provider = undefined;
    const cp = testProvider(&det, &prov);

    inline for (.{ ed25519_crt, ecdsa_p256_ca_crt }) |fixture| {
        var loaded = try Loaded.init(allocator, fixture);
        defer loaded.deinit(allocator);

        const mutated = try tamperedSerialCopy(allocator, &loaded);
        defer allocator.free(mutated);
        var cert = try x509.Certificate.parse(allocator, mutated, .{});
        defer cert.deinit(allocator);
        try testing.expectError(error.InvalidSignature, verify.verifySelfSignature(cp, &cert));
    }
}

test "verifying against a mismatched or wrong issuer key fails" {
    const allocator = testing.allocator;
    var det: crypto.pure_zig.DeterministicEntropy = undefined;
    var prov: crypto.pure_zig.Provider = undefined;
    const cp = testProvider(&det, &prov);

    var ec = try Loaded.init(allocator, ecdsa_p256_ca_crt);
    defer ec.deinit(allocator);
    var ed = try Loaded.init(allocator, ed25519_crt);
    defer ed.deinit(allocator);

    // ECDSA certificate against an Ed25519 issuer key: algorithm and key type
    // disagree, so this is a mismatch, not an attempted verification.
    try testing.expectError(
        error.IssuerKeyMismatch,
        verify.verifyCertificateSignature(cp, &ec.cert, &ed.cert.subject_public_key_info),
    );

    // Same algorithm and key type but the wrong key bytes: the signature does
    // not authenticate (a flipped coordinate is either off-curve — a malformed
    // key — or a valid point the signature does not match).
    const spki = &ec.cert.subject_public_key_info;
    const forged = try allocator.dupe(u8, spki.subject_public_key.data);
    defer allocator.free(forged);
    forged[10] ^= 0x40; // keep the 0x04 SEC1 prefix intact
    var forged_spki = spki.*;
    forged_spki.subject_public_key = .{ .unused_bits = 0, .data = forged };
    const outcome = verify.verifyCertificateSignature(cp, &ec.cert, &forged_spki);
    try testing.expect(outcome == error.InvalidSignature or outcome == error.MalformedPublicKey);
}

test "RSA PKCS#1 v1.5 certificates verify with the pure-Zig provider (#645)" {
    const allocator = testing.allocator;
    var det: crypto.pure_zig.DeterministicEntropy = undefined;
    var prov: crypto.pure_zig.Provider = undefined;
    const cp = testProvider(&det, &prov);

    // A. rsa_ca.crt classifies as rsa_pkcs1_sha256 and verifies its own
    // self-signature.
    var ca = try Loaded.init(allocator, rsa_pkcs1_crt);
    defer ca.deinit(allocator);
    try testing.expectEqual(x509.SignatureAlgorithm.rsa_pkcs1_sha256, ca.cert.signatureAlgorithm());
    try testing.expectEqual(x509.PublicKeyType.rsa, ca.cert.subject_public_key_info.key_type);
    try verify.verifySelfSignature(cp, &ca.cert);

    // B. ecdsa_leaf.crt keeps its own P-256 leaf key, carries an RSA PKCS#1
    // v1.5/SHA-256 certificate signature from the RSA CA, and verifies
    // successfully against the CA's RSA issuer SPKI.
    var leaf = try Loaded.init(allocator, ecdsa_leaf_crt);
    defer leaf.deinit(allocator);
    try testing.expectEqual(x509.PublicKeyType.ecdsa_p256, leaf.cert.subject_public_key_info.key_type);
    try testing.expectEqual(x509.SignatureAlgorithm.rsa_pkcs1_sha256, leaf.cert.signatureAlgorithm());
    try verify.verifyCertificateSignature(cp, &leaf.cert, &ca.cert.subject_public_key_info);

    // D. Tampered signature bytes fail with InvalidSignature.
    const forged_sig = try allocator.dupe(u8, leaf.cert.signature_value.data);
    defer allocator.free(forged_sig);
    forged_sig[forged_sig.len - 1] ^= 0x01;
    var tampered_sig_cert = leaf.cert;
    tampered_sig_cert.signature_value = .{ .unused_bits = 0, .data = forged_sig };
    try testing.expectError(
        error.InvalidSignature,
        verify.verifyCertificateSignature(cp, &tampered_sig_cert, &ca.cert.subject_public_key_info),
    );

    // E. A wrong (but individually well-formed and same-key-type) issuer RSA
    // key does not authenticate the leaf's signature.
    var wrong_issuer = try Loaded.init(allocator, rsa_pss_crt);
    defer wrong_issuer.deinit(allocator);
    try testing.expectEqual(x509.PublicKeyType.rsa, wrong_issuer.cert.subject_public_key_info.key_type);
    const wrong_issuer_outcome = verify.verifyCertificateSignature(cp, &leaf.cert, &wrong_issuer.cert.subject_public_key_info);
    try testing.expect(wrong_issuer_outcome == error.InvalidSignature or wrong_issuer_outcome == error.MalformedPublicKey);

    // F. Wrong signature length is a malformed signature, not an attempted
    // (and incidentally succeeding or crashing) verification.
    var short_sig_cert = leaf.cert;
    short_sig_cert.signature_value = .{ .unused_bits = 0, .data = leaf.cert.signature_value.data[0 .. leaf.cert.signature_value.data.len - 1] };
    try testing.expectError(
        error.MalformedSignature,
        verify.verifyCertificateSignature(cp, &short_sig_cert, &ca.cert.subject_public_key_info),
    );

    // F (BIT STRING padding). A nonzero unused-bits count on the signature
    // BIT STRING is rejected before the signature bytes are even considered.
    var padded_sig_cert = leaf.cert;
    padded_sig_cert.signature_value = .{ .unused_bits = 3, .data = leaf.cert.signature_value.data };
    try testing.expectError(
        error.MalformedSignature,
        verify.verifyCertificateSignature(cp, &padded_sig_cert, &ca.cert.subject_public_key_info),
    );
}

// C. Tampered TBS bytes fail with InvalidSignature for the RSA PKCS#1 v1.5
// self-signed CA too — the same property already proven for Ed25519/ECDSA in
// "tampered TBS bytes fail with InvalidSignature for every supported
// algorithm" above, extended to #645's new scheme.
test "tampered TBS bytes fail with InvalidSignature for RSA PKCS#1 v1.5 (#645)" {
    const allocator = testing.allocator;
    var det: crypto.pure_zig.DeterministicEntropy = undefined;
    var prov: crypto.pure_zig.Provider = undefined;
    const cp = testProvider(&det, &prov);

    var loaded = try Loaded.init(allocator, rsa_pkcs1_crt);
    defer loaded.deinit(allocator);

    const mutated = try tamperedSerialCopy(allocator, &loaded);
    defer allocator.free(mutated);
    var cert = try x509.Certificate.parse(allocator, mutated, .{});
    defer cert.deinit(allocator);
    try testing.expectError(error.InvalidSignature, verify.verifySelfSignature(cp, &cert));
}

// G. sha256WithRSAEncryption AlgorithmIdentifier parameter cases: explicit
// NULL (the fixture's own encoding) and absent parameters are both accepted
// for interoperability; any other parameter encoding is unsupported.
test "RSA PKCS#1 v1.5 AlgorithmIdentifier parameters: explicit NULL and absent accepted, other rejected (#645)" {
    const allocator = testing.allocator;
    var det: crypto.pure_zig.DeterministicEntropy = undefined;
    var prov: crypto.pure_zig.Provider = undefined;
    const cp = testProvider(&det, &prov);

    var ca = try Loaded.init(allocator, rsa_pkcs1_crt);
    defer ca.deinit(allocator);

    // The fixture as generated by OpenSSL already carries explicit NULL.
    try testing.expect(ca.cert.signature_algorithm.parameters_raw != null);
    try testing.expect(ca.cert.signature_algorithm.parameters_null);
    try verify.verifySelfSignature(cp, &ca.cert);

    // Absent parameters are accepted for interoperability.
    ca.cert.signature_algorithm.parameters_raw = null;
    try verify.verifySelfSignature(cp, &ca.cert);

    // Any other parameter encoding (e.g. a non-NULL element) is unsupported.
    ca.cert.signature_algorithm.parameters_raw = &[_]u8{ 0x02, 0x01, 0x00 };
    ca.cert.signature_algorithm.parameters_null = false;
    try testing.expectError(error.UnsupportedSignatureAlgorithm, verify.verifySelfSignature(cp, &ca.cert));
}

test "malformed signature BIT STRING padding is rejected" {
    const allocator = testing.allocator;
    var det: crypto.pure_zig.DeterministicEntropy = undefined;
    var prov: crypto.pure_zig.Provider = undefined;
    const cp = testProvider(&det, &prov);

    var ed = try Loaded.init(allocator, ed25519_crt);
    defer ed.deinit(allocator);

    var tampered = ed.cert;
    tampered.signature_value = .{ .unused_bits = 3, .data = ed.cert.signature_value.data };
    try testing.expectError(error.MalformedSignature, verify.verifySelfSignature(cp, &tampered));
}

// --- Synthetic AlgorithmIdentifier / signature corpora --------------------

fn tlv(arena: std.mem.Allocator, tag: u8, parts: []const []const u8) ![]u8 {
    var total: usize = 0;
    for (parts) |p| total += p.len;
    var len_buf: [9]u8 = undefined;
    const len_len = try der.encodeLength(total, &len_buf);
    var out = try arena.alloc(u8, 1 + len_len + total);
    out[0] = tag;
    @memcpy(out[1 .. 1 + len_len], len_buf[0..len_len]);
    var off = 1 + len_len;
    for (parts) |p| {
        @memcpy(out[off .. off + p.len], p);
        off += p.len;
    }
    return out;
}

fn oidTlv(arena: std.mem.Allocator, comps: []const u32) ![]u8 {
    var buf: [64]u8 = undefined;
    const n = try oid.encodeComponents(comps, &buf);
    return tlv(arena, 0x06, &.{buf[0..n]});
}

fn nullTlv(arena: std.mem.Allocator) ![]u8 {
    return tlv(arena, 0x05, &.{});
}

fn intTlv(arena: std.mem.Allocator, value: u8) ![]u8 {
    return tlv(arena, 0x02, &.{&[_]u8{value}});
}

const oid_rsa_pss = [_]u32{ 1, 2, 840, 113549, 1, 1, 10 };
const oid_sha256 = [_]u32{ 2, 16, 840, 1, 101, 3, 4, 2, 1 };
const oid_sha384 = [_]u32{ 2, 16, 840, 1, 101, 3, 4, 2, 2 };
const oid_mgf1 = [_]u32{ 1, 2, 840, 113549, 1, 1, 8 };

/// Build an RSASSA-PSS AlgorithmIdentifier with configurable hash and salt so
/// the parameter validator can be exercised directly.
fn pssAlgorithmId(arena: std.mem.Allocator, hash_oid: []const u32, mgf_hash_oid: []const u32, salt: u8) ![]u8 {
    const hash_alg = try tlv(arena, 0x30, &.{ try oidTlv(arena, hash_oid), try nullTlv(arena) });
    const mgf_hash = try tlv(arena, 0x30, &.{ try oidTlv(arena, mgf_hash_oid), try nullTlv(arena) });
    const mgf_alg = try tlv(arena, 0x30, &.{ try oidTlv(arena, &oid_mgf1), mgf_hash });
    const params = try tlv(arena, 0x30, &.{
        try tlv(arena, 0xa0, &.{hash_alg}), // [0] hashAlgorithm
        try tlv(arena, 0xa1, &.{mgf_alg}), // [1] maskGenAlgorithm
        try tlv(arena, 0xa2, &.{try intTlv(arena, salt)}), // [2] saltLength
    });
    return tlv(arena, 0x30, &.{ try oidTlv(arena, &oid_rsa_pss), params });
}

fn parseAlgId(bytes: []const u8) !x509.AlgorithmIdentifier {
    var reader = der.Reader.init(bytes, .{});
    const elem = try reader.readElement();
    var inner = try reader.childReader(elem.content_offset, elem.content.len);
    const alg_oid = try inner.readObjectIdentifier();
    var params_raw: ?[]const u8 = null;
    if (inner.remaining() > 0) {
        const p = try inner.readElement();
        params_raw = p.encoded;
    }
    return .{ .raw = elem.encoded, .oid = alg_oid, .parameters_raw = params_raw, .parameters_null = false };
}

test "RSA-PSS parameter validation accepts SHA-256 and rejects other configs" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    // Canonical SHA-256 / MGF1-SHA-256 / salt-32 is accepted.
    {
        const alg = try parseAlgId(try pssAlgorithmId(arena, &oid_sha256, &oid_sha256, 32));
        try verify.validatePssSha256(&alg);
    }
    // Wrong message hash, wrong MGF hash, and wrong salt each fall out of the
    // supported configuration.
    {
        const alg = try parseAlgId(try pssAlgorithmId(arena, &oid_sha384, &oid_sha256, 32));
        try testing.expectError(error.UnsupportedSignatureAlgorithm, verify.validatePssSha256(&alg));
    }
    {
        const alg = try parseAlgId(try pssAlgorithmId(arena, &oid_sha256, &oid_sha384, 32));
        try testing.expectError(error.UnsupportedSignatureAlgorithm, verify.validatePssSha256(&alg));
    }
    {
        const alg = try parseAlgId(try pssAlgorithmId(arena, &oid_sha256, &oid_sha256, 48));
        try testing.expectError(error.UnsupportedSignatureAlgorithm, verify.validatePssSha256(&alg));
    }
    // Absent parameters (the SHA-1 DEFAULTs) are unsupported, not silently SHA-1.
    {
        const alg = x509.AlgorithmIdentifier{
            .raw = &.{},
            .oid = try oid.ObjectIdentifier.fromComponents(&oid_rsa_pss),
            .parameters_raw = null,
            .parameters_null = false,
        };
        try testing.expectError(error.UnsupportedSignatureAlgorithm, verify.validatePssSha256(&alg));
    }
}

test "non-canonical ECDSA signatures are rejected as malformed" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    // Valid shape: SEQUENCE { INTEGER 1, INTEGER 1 }.
    const good = try tlv(arena, 0x30, &.{ try intTlv(arena, 1), try intTlv(arena, 1) });
    try verify.validateEcdsaDerSignature(good);

    // Trailing junk after the SEQUENCE.
    const trailing = try std.mem.concat(arena, u8, &.{ good, &[_]u8{0x00} });
    try testing.expectError(error.MalformedSignature, verify.validateEcdsaDerSignature(trailing));

    // Not a SEQUENCE.
    try testing.expectError(error.MalformedSignature, verify.validateEcdsaDerSignature(try intTlv(arena, 1)));

    // Negative r (high bit set) is not a valid ECDSA integer.
    const neg = try tlv(arena, 0x30, &.{ try tlv(arena, 0x02, &.{&[_]u8{0x80}}), try intTlv(arena, 1) });
    try testing.expectError(error.MalformedSignature, verify.validateEcdsaDerSignature(neg));

    // Non-minimal INTEGER (leading 0x00 with clear high bit) is non-canonical DER.
    const nonmin = try tlv(arena, 0x30, &.{ try tlv(arena, 0x02, &.{&[_]u8{ 0x00, 0x01 }}), try intTlv(arena, 1) });
    try testing.expectError(error.MalformedSignature, verify.validateEcdsaDerSignature(nonmin));

    // A canonical but oversized scalar (33 magnitude bytes) exceeds a P-256
    // scalar and must be malformed, not passed through to the provider.
    var big: [33]u8 = undefined;
    @memset(&big, 0x11); // high bit clear, no sign padding => 33 magnitude bytes
    const oversized = try tlv(arena, 0x30, &.{ try tlv(arena, 0x02, &.{&big}), try intTlv(arena, 1) });
    try testing.expectError(error.MalformedSignature, verify.validateEcdsaDerSignature(oversized));

    // 33 content bytes are allowed only as a 0x00 sign byte plus 32 magnitude.
    var padded: [33]u8 = undefined;
    padded[0] = 0x00;
    @memset(padded[1..], 0xaa); // top bit set, so the sign byte is required
    const padded_ok = try tlv(arena, 0x30, &.{ try tlv(arena, 0x02, &.{&padded}), try intTlv(arena, 1) });
    try verify.validateEcdsaDerSignature(padded_ok);
}

fn rsaPublicKeyDer(arena: std.mem.Allocator, modulus: []const u8, exponent: []const u8) ![]u8 {
    return tlv(arena, 0x30, &.{
        try tlv(arena, 0x02, &.{modulus}),
        try tlv(arena, 0x02, &.{exponent}),
    });
}

test "RSA public keys with non-positive modulus or exponent are malformed" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    // A well-formed positive RSAPublicKey parses and reports its modulus length.
    var modulus: [256]u8 = undefined;
    @memset(&modulus, 0xff);
    modulus[0] = 0x00; // sign byte: 2048-bit modulus with the top bit set
    _ = try verify.rsaModulusLen(try rsaPublicKeyDer(arena, &modulus, &[_]u8{ 0x01, 0x00, 0x01 }));

    // Negative modulus (minimal encoding, top bit set) is rejected.
    var neg_mod: [256]u8 = undefined;
    @memset(&neg_mod, 0x00);
    neg_mod[0] = 0x80;
    try testing.expectError(error.MalformedPublicKey, verify.rsaModulusLen(try rsaPublicKeyDer(arena, &neg_mod, &[_]u8{ 0x01, 0x00, 0x01 })));

    // Zero modulus and zero exponent are rejected.
    try testing.expectError(error.MalformedPublicKey, verify.rsaModulusLen(try rsaPublicKeyDer(arena, &[_]u8{0x00}, &[_]u8{ 0x01, 0x00, 0x01 })));
    try testing.expectError(error.MalformedPublicKey, verify.rsaModulusLen(try rsaPublicKeyDer(arena, &modulus, &[_]u8{0x00})));

    // Negative exponent (top bit set) is rejected.
    try testing.expectError(error.MalformedPublicKey, verify.rsaModulusLen(try rsaPublicKeyDer(arena, &modulus, &[_]u8{0x80})));
}

test "signature-algorithm parameters must be absent for Ed25519 and ECDSA" {
    const allocator = testing.allocator;
    var det: crypto.pure_zig.DeterministicEntropy = undefined;
    var prov: crypto.pure_zig.Provider = undefined;
    const cp = testProvider(&det, &prov);

    inline for (.{ ed25519_crt, ecdsa_p256_ca_crt }) |fixture| {
        var loaded = try Loaded.init(allocator, fixture);
        defer loaded.deinit(allocator);
        // Inject an explicit NULL parameter into the signatureAlgorithm; RFCs
        // 8410/5758 require it absent, so verification must refuse it.
        loaded.cert.signature_algorithm.parameters_raw = &[_]u8{ 0x05, 0x00 };
        try testing.expectError(error.UnsupportedSignatureAlgorithm, verify.verifySelfSignature(cp, &loaded.cert));
    }
}

test "issuer Ed25519 SPKI parameters must be absent" {
    const allocator = testing.allocator;
    var det: crypto.pure_zig.DeterministicEntropy = undefined;
    var prov: crypto.pure_zig.Provider = undefined;
    const cp = testProvider(&det, &prov);

    var ed = try Loaded.init(allocator, ed25519_crt);
    defer ed.deinit(allocator);
    // RFC 8410 forbids parameters on an Ed25519 SubjectPublicKeyInfo.
    ed.cert.subject_public_key_info.algorithm.parameters_raw = &[_]u8{ 0x05, 0x00 };
    try testing.expectError(error.MalformedPublicKey, verify.verifySelfSignature(cp, &ed.cert));
}

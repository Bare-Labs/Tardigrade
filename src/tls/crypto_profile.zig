//! TLS-side adapter for the provider-neutral crypto capability matrix.

const std = @import("std");
const crypto = @import("crypto");
const provider = crypto.provider;
const profile = crypto.profile;
const policy_mod = @import("policy.zig");
const state = @import("state.zig");

pub const TlsCapabilityError = error{UnsupportedCapability};

pub const TlsCapabilities = struct {
    cipher_suites: [3]policy_mod.CipherSuite = undefined,
    cipher_suites_len: usize = 0,
    named_groups: [2]policy_mod.NamedGroup = undefined,
    named_groups_len: usize = 0,
    signature_schemes: [3]policy_mod.SignatureScheme = undefined,
    signature_schemes_len: usize = 0,

    pub fn asPolicyCapabilities(self: *const TlsCapabilities) policy_mod.Capabilities {
        return .{
            .cipher_suites = self.cipher_suites[0..self.cipher_suites_len],
            .named_groups = self.named_groups[0..self.named_groups_len],
            .signature_schemes = self.signature_schemes[0..self.signature_schemes_len],
        };
    }

    pub fn policy(self: *const TlsCapabilities, transport_mode: state.TransportMode, alpns: []const policy_mod.ProtocolName) policy_mod.Policy {
        return policy_mod.Policy.fromCapabilities(transport_mode, self.asPolicyCapabilities(), alpns);
    }

    fn appendCipher(self: *TlsCapabilities, suite: policy_mod.CipherSuite) void {
        self.cipher_suites[self.cipher_suites_len] = suite;
        self.cipher_suites_len += 1;
    }

    fn appendGroup(self: *TlsCapabilities, group: policy_mod.NamedGroup) void {
        self.named_groups[self.named_groups_len] = group;
        self.named_groups_len += 1;
    }

    fn appendSignature(self: *TlsCapabilities, scheme: policy_mod.SignatureScheme) void {
        self.signature_schemes[self.signature_schemes_len] = scheme;
        self.signature_schemes_len += 1;
    }
};

/// Derive TLS policy capabilities for a named product profile, intersecting
/// provider primitive support with the profile row's `enabled_product_profiles`
/// (#490). Every call site must name the product explicitly — there is no
/// caller-agnostic default, since which cipher suites/groups/signatures a
/// product actually negotiates is a product decision, not something a
/// provider's raw capability set can answer on its own.
pub fn fromProfile(product: profile.ProductProfile, caps: provider.Capabilities) TlsCapabilities {
    var out = TlsCapabilities{};
    // Each cipher suite is gated on every profile dimension the suite
    // actually binds together (AEAD, transcript hash, and HKDF hash), not
    // only its AEAD row: a suite is only truly selectable for `product` when
    // the whole triple is enabled there, so the derivation does not depend
    // on those rows being kept in lockstep by hand.
    if (profile.productEnables(product, .{ .aead = .aes_128_gcm }) and
        profile.productEnables(product, .{ .hash = .sha256 }) and
        profile.productEnables(product, .{ .hkdf = .sha256 }) and
        supportsCipherSuite(caps, .tls_aes_128_gcm_sha256))
    {
        out.appendCipher(.tls_aes_128_gcm_sha256);
    }
    if (profile.productEnables(product, .{ .aead = .aes_256_gcm }) and
        profile.productEnables(product, .{ .hash = .sha384 }) and
        profile.productEnables(product, .{ .hkdf = .sha384 }) and
        supportsCipherSuite(caps, .tls_aes_256_gcm_sha384))
    {
        out.appendCipher(.tls_aes_256_gcm_sha384);
    }
    if (profile.productEnables(product, .{ .aead = .chacha20_poly1305 }) and
        profile.productEnables(product, .{ .hash = .sha256 }) and
        profile.productEnables(product, .{ .hkdf = .sha256 }) and
        supportsCipherSuite(caps, .tls_chacha20_poly1305_sha256))
    {
        out.appendCipher(.tls_chacha20_poly1305_sha256);
    }
    if (profile.productEnables(product, .{ .group = .x25519 }) and supportsNamedGroup(caps, .x25519)) {
        out.appendGroup(.x25519);
    }
    if (profile.productEnables(product, .{ .group = .secp256r1 }) and supportsNamedGroup(caps, .secp256r1)) {
        out.appendGroup(.secp256r1);
    }
    if (profile.productEnables(product, .{ .signature = .ed25519 }) and supportsSignatureScheme(caps, .ed25519)) {
        out.appendSignature(.ed25519);
    }
    if (profile.productEnables(product, .{ .signature = .ecdsa_secp256r1_sha256 }) and supportsSignatureScheme(caps, .ecdsa_secp256r1_sha256)) {
        out.appendSignature(.ecdsa_secp256r1_sha256);
    }
    if (profile.productEnables(product, .{ .signature = .rsa_pss_rsae_sha256 }) and supportsSignatureScheme(caps, .rsa_pss_rsae_sha256)) {
        out.appendSignature(.rsa_pss_rsae_sha256);
    }
    return out;
}

pub fn validateAgainstProvider(caps: provider.Capabilities, tls_caps: policy_mod.Capabilities) TlsCapabilityError!void {
    for (tls_caps.cipher_suites) |suite| {
        if (!supportsCipherSuite(caps, suite)) return error.UnsupportedCapability;
    }
    for (tls_caps.named_groups) |group| {
        if (!supportsNamedGroup(caps, group)) return error.UnsupportedCapability;
    }
    for (tls_caps.signature_schemes) |scheme| {
        if (!supportsSignatureScheme(caps, scheme)) return error.UnsupportedCapability;
    }
}

pub fn supportsCipherSuite(caps: provider.Capabilities, suite: policy_mod.CipherSuite) bool {
    return switch (suite) {
        .tls_aes_128_gcm_sha256 => caps.supportsAead(.aes_128_gcm) and caps.supportsHash(.sha256),
        .tls_aes_256_gcm_sha384 => caps.supportsAead(.aes_256_gcm) and caps.supportsHash(.sha384),
        .tls_chacha20_poly1305_sha256 => caps.supportsAead(.chacha20_poly1305) and caps.supportsHash(.sha256),
    };
}

pub fn supportsNamedGroup(caps: provider.Capabilities, group: policy_mod.NamedGroup) bool {
    return switch (group) {
        .x25519 => caps.supportsGroup(.x25519),
        .secp256r1 => caps.supportsGroup(.secp256r1),
        .secp384r1 => false,
    };
}

pub fn supportsSignatureScheme(caps: provider.Capabilities, scheme: policy_mod.SignatureScheme) bool {
    return switch (scheme) {
        .ed25519 => caps.supportsSignature(.ed25519),
        .ecdsa_secp256r1_sha256 => caps.supportsSignature(.ecdsa_secp256r1_sha256),
        .rsa_pss_rsae_sha256 => caps.supportsSignature(.rsa_pss_rsae_sha256),
        // Certificate-chain-signature-only (#645): RFC 8446 §4.2.3 forbids
        // rsa_pkcs1 schemes in signature_algorithms/CertificateVerify, so
        // these are unconditionally refused here regardless of provider
        // support — they are offered only via signature_algorithms_cert
        // (src/tls/tls13_backend.zig's native_signature_schemes_cert).
        .rsa_pkcs1_sha256, .rsa_pkcs1_sha384 => false,
    };
}

test "TLS policy capabilities are derived from provider support" {
    const caps = profile.capabilities(.pure_zig);
    const tls_caps = fromProfile(.general, caps);
    try std.testing.expectEqual(@as(usize, 3), tls_caps.cipher_suites_len);
    try std.testing.expectEqual(policy_mod.CipherSuite.tls_aes_128_gcm_sha256, tls_caps.cipher_suites[0]);
    try std.testing.expectEqual(policy_mod.CipherSuite.tls_aes_256_gcm_sha384, tls_caps.cipher_suites[1]);
    try std.testing.expectEqual(policy_mod.CipherSuite.tls_chacha20_poly1305_sha256, tls_caps.cipher_suites[2]);
    try std.testing.expectEqual(@as(usize, 2), tls_caps.named_groups_len);
    try std.testing.expectEqual(policy_mod.NamedGroup.x25519, tls_caps.named_groups[0]);
    try std.testing.expectEqual(policy_mod.NamedGroup.secp256r1, tls_caps.named_groups[1]);
    try std.testing.expectEqual(@as(usize, 3), tls_caps.signature_schemes_len);
    try std.testing.expectEqual(policy_mod.SignatureScheme.ed25519, tls_caps.signature_schemes[0]);
    try std.testing.expectEqual(policy_mod.SignatureScheme.ecdsa_secp256r1_sha256, tls_caps.signature_schemes[1]);
    try std.testing.expectEqual(policy_mod.SignatureScheme.rsa_pss_rsae_sha256, tls_caps.signature_schemes[2]);
}

test "native appliance profile selects only what the live engine negotiates" {
    const caps = profile.capabilities(.pure_zig);
    const native = fromProfile(.appliance, caps);
    // #564: the native engine's handshake/transcript/key-schedule are
    // cipher/hash-agile and negotiate all three checked-in suites now, not
    // just the SHA-256 baseline.
    try std.testing.expectEqual(@as(usize, 3), native.cipher_suites_len);
    try std.testing.expectEqual(policy_mod.CipherSuite.tls_aes_128_gcm_sha256, native.cipher_suites[0]);
    try std.testing.expectEqual(policy_mod.CipherSuite.tls_aes_256_gcm_sha384, native.cipher_suites[1]);
    try std.testing.expectEqual(policy_mod.CipherSuite.tls_chacha20_poly1305_sha256, native.cipher_suites[2]);
    try std.testing.expectEqual(@as(usize, 1), native.named_groups_len);
    try std.testing.expectEqual(policy_mod.NamedGroup.x25519, native.named_groups[0]);
    try std.testing.expectEqual(@as(usize, 2), native.signature_schemes_len);
    try std.testing.expectEqual(policy_mod.SignatureScheme.ed25519, native.signature_schemes[0]);
    try std.testing.expectEqual(policy_mod.SignatureScheme.ecdsa_secp256r1_sha256, native.signature_schemes[1]);
}

test "hand-written TLS policy capabilities are rejected when provider cannot support them" {
    const caps = profile.capabilities(.pure_zig);
    const derived = fromProfile(.general, caps);
    try validateAgainstProvider(caps, derived.asPolicyCapabilities());

    // A hand-authored policy naming a group absent from the provider's
    // advertised capability set is still rejected.
    var without_p256 = caps;
    without_p256.groups.remove(.secp256r1);
    const bad_groups = [_]policy_mod.NamedGroup{.secp256r1};
    try std.testing.expectError(error.UnsupportedCapability, validateAgainstProvider(without_p256, .{ .named_groups = &bad_groups }));

    // PKCS#1 v1.5 remains outside the provider profile.
    const bad_pkcs1 = [_]policy_mod.SignatureScheme{.rsa_pkcs1_sha256};
    try std.testing.expectError(error.UnsupportedCapability, validateAgainstProvider(caps, .{ .signature_schemes = &bad_pkcs1 }));
}

// #645 merge-blocking regression: the pure-Zig provider now genuinely
// verifies RSA PKCS#1 v1.5 certificate signatures (`caps.supportsSignature`
// below is provider.SignatureScheme, distinct from this file's TLS-wire
// `policy_mod.SignatureScheme`) — this proves that primitive existing does
// not, by itself, cause the TLS `signature_algorithms` derivation to
// advertise or select it for CertificateVerify. RFC 8446 §4.2.3 forbids
// `rsa_pkcs1` schemes there; `supportsSignatureScheme`'s `.rsa_pkcs1_sha256
// => false` arm (see above) is unconditional, so this must hold regardless
// of provider capability.
test "adding the RSA PKCS#1 v1.5 provider primitive does not advertise it for TLS CertificateVerify" {
    const caps = profile.capabilities(.pure_zig);
    try std.testing.expect(caps.supportsSignature(.rsa_pkcs1_sha256));
    try std.testing.expect(caps.supportsSignature(.rsa_pkcs1_sha384));

    try std.testing.expect(!supportsSignatureScheme(caps, .rsa_pkcs1_sha256));

    const general = fromProfile(.general, caps);
    for (general.signature_schemes[0..general.signature_schemes_len]) |scheme| {
        try std.testing.expect(scheme != .rsa_pkcs1_sha256);
    }
    const native = fromProfile(.appliance, caps);
    for (native.signature_schemes[0..native.signature_schemes_len]) |scheme| {
        try std.testing.expect(scheme != .rsa_pkcs1_sha256);
    }
}

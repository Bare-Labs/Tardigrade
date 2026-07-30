//! Checked-in cryptographic capability profile (#371, epic #327).
//!
//! This file is intentionally data-heavy. It is the build-visible matrix that
//! maps protocol algorithms to the implementation family that supplies them,
//! the current provider status, test coverage, and consumers.

const std = @import("std");
const provider = @import("provider.zig");

pub const zig_version_floor = "0.16.0";

pub const ProviderKind = enum {
    pure_zig,
    openssl,
};

pub const Status = enum {
    supported,
    provider_deferred,
    unsupported,
};

pub const Implementation = enum {
    zig_std_crypto,
    project_code,
    openssl_provider,
    unavailable,
};

pub const Category = enum {
    hash,
    hkdf,
    aead,
    quic_header_protection,
    group,
    signature,
    certificate_helper,
    entropy,
};

pub const Consumer = enum {
    tls_handshake,
    tls_record,
    quic_packet_protection,
    quic_tls_bridge,
    pki,
    resumption,
};

/// Whether a listed `Consumer`'s *live* protocol runtime actually calls this
/// capability through `CryptoProvider`, as opposed to a parallel concrete
/// `std.crypto` implementation or free-form prose merely claiming so (#490).
/// Checked per consumer, not per row, because a single algorithm is commonly
/// wired for one consumer (e.g. QUIC packet protection) well before another
/// (e.g. the TLS 1.3 handshake engine) migrates onto the same seam.
pub const IntegrationStatus = enum {
    /// The named consumer's live runtime calls this capability through
    /// `CryptoProvider`.
    live,
    /// A provider-backed entry point exists and is exercised by tests, but
    /// the named consumer's live runtime still calls a parallel concrete
    /// implementation instead.
    not_integrated,
    /// This operation is never dispatched through the `CryptoProvider`
    /// vtable by design (e.g. unkeyed transcript hashing, or a shared
    /// secret-hygiene helper called directly by both protocol code and
    /// provider internals) — "integrated" does not apply to it.
    not_provider_routed,
};

/// Product profile a row's implementation is reachable from today. Derived
/// mechanically from `pure_zig_status` / `openssl_status`: a backend that
/// reports `.supported` is exactly the backend the matching product profile
/// selects, so this does not encode a separate judgment call.
pub const ProductProfile = enum {
    /// The native, OpenSSL/libcrypto-free in-process pure-Zig QUIC/H3 path.
    native_appliance,
    /// The general-purpose OpenSSL TLS backend and out-of-process OpenSSL
    /// oracles.
    general_purpose_openssl,
};

pub const ProductProfileSet = std.EnumSet(ProductProfile);

pub const ConsumerIntegration = struct {
    consumer: Consumer,
    status: IntegrationStatus,
};

pub const CertificateHelper = enum {
    der_parser,
    chain_builder,
    webpki_validation,
};

pub const EntropyCapability = enum {
    injected_random_bytes,
    secure_zero,
    constant_time_compare,
};

pub const Algorithm = union(Category) {
    hash: provider.Hash,
    hkdf: provider.Hash,
    aead: provider.Aead,
    quic_header_protection: provider.QuicHeaderProtection,
    group: provider.Group,
    signature: provider.SignatureScheme,
    certificate_helper: CertificateHelper,
    entropy: EntropyCapability,
};

pub const ConsumerSet = std.EnumSet(Consumer);

pub const Row = struct {
    algorithm: Algorithm,
    name: []const u8,
    pure_zig_implementation: Implementation,
    pure_zig_status: Status,
    openssl_implementation: Implementation,
    openssl_status: Status,
    tests: []const u8,
    integrations: []const ConsumerIntegration,
    enabled_product_profiles: ProductProfileSet,
    review: []const u8,

    pub fn consumers(self: Row) ConsumerSet {
        var set = ConsumerSet{};
        for (self.integrations) |entry| set.insert(entry.consumer);
        return set;
    }

    pub fn integrationStatus(self: Row, consumer: Consumer) ?IntegrationStatus {
        for (self.integrations) |entry| {
            if (entry.consumer == consumer) return entry.status;
        }
        return null;
    }
};

pub const rows = [_]Row{
    row(.{ .hash = .sha256 }, "SHA-256", .zig_std_crypto, .supported, .openssl_provider, .provider_deferred, "std.crypto cross-checks, transcript tests", .{ .{ .tls_handshake, .not_provider_routed }, .{ .quic_tls_bridge, .not_provider_routed } }, "Unkeyed transcript hashing never crosses the CryptoProvider vtable by design (no `hash` entry point exists); hash additions require transcript/HKDF vectors."),
    row(.{ .hash = .sha384 }, "SHA-384", .zig_std_crypto, .supported, .openssl_provider, .provider_deferred, "provider capability and HKDF tests", .{.{ .tls_handshake, .not_provider_routed }}, "Unkeyed transcript hashing; hash additions require TLS 1.3 suite mapping."),
    row(.{ .hkdf = .sha256 }, "HKDF-SHA256", .zig_std_crypto, .supported, .openssl_provider, .provider_deferred, "RFC 5869/std.crypto and TLS expand-label parity", .{ .{ .tls_handshake, .not_integrated }, .{ .quic_tls_bridge, .live }, .{ .quic_packet_protection, .live } }, "QUIC Initial/Handshake/1-RTT key derivation in src/quic/tls_adapter.zig runs through CryptoProvider; the TLS 1.3 key schedule (src/tls/key_schedule.zig) still calls std.crypto directly and is tracked as open follow-up for #490."),
    row(.{ .hkdf = .sha384 }, "HKDF-SHA384", .zig_std_crypto, .supported, .openssl_provider, .provider_deferred, "provider capability and expand-label tests", .{.{ .tls_handshake, .not_integrated }}, "src/tls/key_schedule.zig calls std.crypto directly; HKDF additions require TLS 1.3 label coverage."),
    row(.{ .aead = .aes_128_gcm }, "AES-128-GCM", .zig_std_crypto, .supported, .openssl_provider, .provider_deferred, "seal/open round-trip, tamper rejection, AD mismatch", .{ .{ .tls_record, .live }, .{ .quic_packet_protection, .live } }, "TLS record protection and QUIC packet payload protection (TLS_AES_128_GCM_SHA256) both seal/open through CryptoProvider."),
    row(.{ .aead = .aes_256_gcm }, "AES-256-GCM", .zig_std_crypto, .supported, .openssl_provider, .provider_deferred, "seal/open round-trip, tamper rejection, AD mismatch", .{.{ .tls_record, .not_integrated }}, "Provider primitive exists and the record layer is provider-routed generically, but TLS_AES_256_GCM_SHA384 is not negotiated by either engine yet, so this AEAD is never selected live."),
    row(.{ .aead = .chacha20_poly1305 }, "ChaCha20-Poly1305", .zig_std_crypto, .supported, .openssl_provider, .provider_deferred, "seal/open round-trip, tamper rejection, AD mismatch", .{}, "Provider primitive exists; TLS/QUIC protocol integration is deferred until the suite is negotiated end to end."),
    row(.{ .quic_header_protection = .aes_128 }, "QUIC AES-128 header protection", .zig_std_crypto, .supported, .openssl_provider, .provider_deferred, "RFC 9001 header-protection sample and provider mask parity", .{.{ .quic_packet_protection, .live }}, "src/quic/tls_adapter.zig applies and removes header protection through CryptoProvider on every send/receive path (#490); the direct Aes128.initEnc form remains only as differential test-vector fixtures."),
    row(.{ .group = .x25519 }, "X25519", .zig_std_crypto, .supported, .openssl_provider, .provider_deferred, "std.crypto scalar multiplication parity, low-order rejection", .{ .{ .tls_handshake, .not_integrated }, .{ .quic_tls_bridge, .not_integrated } }, "src/tls/tls13_backend.zig generates the TLS key share via X25519.KeyPair.generateDeterministic directly, not CryptoProvider.generateKeyShare; group additions require key-share and shared-secret vectors."),
    row(.{ .group = .secp256r1 }, "secp256r1 (P-256)", .unavailable, .provider_deferred, .openssl_provider, .provider_deferred, "capability rejection tests", .{ .{ .tls_handshake, .not_integrated }, .{ .quic_tls_bridge, .not_integrated }, .{ .pki, .not_integrated } }, "P-256 support requires explicit provider implementation and ECDH vectors."),
    row(.{ .signature = .ed25519 }, "Ed25519", .zig_std_crypto, .supported, .openssl_provider, .provider_deferred, "sign/verify, tamper rejection, wrong-key rejection", .{ .{ .tls_handshake, .not_integrated }, .{ .pki, .live } }, "Certificate-chain verification (src/pki/verify.zig) calls CryptoProvider.verify; the handshake's own CertificateVerify message still calls a local sig.verify directly in src/tls/tls13_backend.zig."),
    row(.{ .signature = .ecdsa_secp256r1_sha256 }, "ECDSA-P256-SHA256", .zig_std_crypto, .supported, .openssl_provider, .provider_deferred, "SEC1 key/DER signature verify, tamper, wrong-key, non-canonical-signature rejection (#343)", .{ .{ .tls_handshake, .not_integrated }, .{ .pki, .live } }, "Same split as Ed25519: PKI chain verification is provider-routed, CertificateVerify is not; the secp256r1 ECDH group remains deferred regardless."),
    row(.{ .signature = .rsa_pss_rsae_sha256 }, "RSA-PSS-RSAE-SHA256", .project_code, .supported, .openssl_provider, .provider_deferred, "strict DER/RSA-PSS positive and negative fixtures", .{ .{ .tls_handshake, .not_integrated }, .{ .pki, .live } }, "Same split as Ed25519/ECDSA. Pure-Zig verifier validates the complete EMSA-PSS encoding and constrained RSA public keys."),
    row(.{ .certificate_helper = .der_parser }, "DER/X.509 parser helpers", .project_code, .provider_deferred, .openssl_provider, .provider_deferred, "module-local parser fixtures", .{.{ .pki, .not_provider_routed }}, "Public DER/X.509 parsing has no CryptoProvider vtable entry and is called directly by protocol-local PKI code; certificate helpers require malformed-input and corpus tests."),
    row(.{ .certificate_helper = .chain_builder }, "certificate chain builder", .unavailable, .provider_deferred, .openssl_provider, .provider_deferred, "tracked by PKI stories", .{.{ .pki, .not_integrated }}, "Not implemented yet; chain validation requires path-building fixtures."),
    row(.{ .certificate_helper = .webpki_validation }, "WebPKI validation", .unavailable, .provider_deferred, .openssl_provider, .provider_deferred, "tracked by PKI stories", .{.{ .pki, .not_integrated }}, "Not implemented yet; WebPKI support requires policy and time-validation review."),
    row(.{ .entropy = .injected_random_bytes }, "injected random bytes", .project_code, .supported, .openssl_provider, .provider_deferred, "deterministic and failing entropy tests", .{ .{ .tls_handshake, .not_integrated }, .{ .quic_packet_protection, .not_integrated }, .{ .resumption, .not_integrated } }, "No call site invokes CryptoProvider.entropy.fill today; TLS/QUIC/resumption each inject randomness through their own longer-standing Entropy parameters instead. Randomness changes require no-ambient-RNG review regardless of which seam supplies it."),
    row(.{ .entropy = .secure_zero }, "secure zero", .project_code, .supported, .project_code, .supported, "secret-container and provider wipe tests", .{ .{ .tls_handshake, .not_provider_routed }, .{ .tls_record, .not_provider_routed }, .{ .quic_packet_protection, .not_provider_routed }, .{ .pki, .not_provider_routed }, .{ .resumption, .not_provider_routed } }, "A shared helper called directly by protocol code and by provider internals alike, not a CryptoProvider vtable dispatch target; secret handling changes require wipe-on-error review."),
    row(.{ .entropy = .constant_time_compare }, "constant-time compare", .project_code, .supported, .project_code, .supported, "crypto secret helper tests", .{ .{ .tls_handshake, .not_provider_routed }, .{ .tls_record, .not_provider_routed }, .{ .pki, .not_provider_routed } }, "Same shared-helper shape as secure zero; comparison changes require timing-safe API review."),
};

fn row(
    algorithm: Algorithm,
    name: []const u8,
    pure_zig_implementation: Implementation,
    pure_zig_status: Status,
    openssl_implementation: Implementation,
    openssl_status: Status,
    tests: []const u8,
    comptime integrations_list: anytype,
    review: []const u8,
) Row {
    return .{
        .algorithm = algorithm,
        .name = name,
        .pure_zig_implementation = pure_zig_implementation,
        .pure_zig_status = pure_zig_status,
        .openssl_implementation = openssl_implementation,
        .openssl_status = openssl_status,
        .tests = tests,
        .integrations = &integrationList(integrations_list),
        .enabled_product_profiles = productProfilesFor(pure_zig_status, openssl_status),
        .review = review,
    };
}

fn integrationList(comptime items: anytype) [items.len]ConsumerIntegration {
    var list: [items.len]ConsumerIntegration = undefined;
    inline for (items, 0..) |item, i| list[i] = .{ .consumer = item[0], .status = item[1] };
    return list;
}

/// Mechanical derivation, not a separate judgment call: the product profile
/// that selects a backend is exactly the profile "enabled" once that
/// backend reports `.supported` for this row.
fn productProfilesFor(pure_zig_status: Status, openssl_status: Status) ProductProfileSet {
    var set = ProductProfileSet{};
    if (pure_zig_status == .supported) set.insert(.native_appliance);
    if (openssl_status == .supported) set.insert(.general_purpose_openssl);
    return set;
}

pub fn status(kind: ProviderKind, algorithm: Algorithm) Status {
    for (rows) |entry| {
        if (algorithmEql(entry.algorithm, algorithm)) {
            return switch (kind) {
                .pure_zig => entry.pure_zig_status,
                .openssl => entry.openssl_status,
            };
        }
    }
    return .unsupported;
}

pub fn capabilities(kind: ProviderKind) provider.Capabilities {
    var caps = provider.Capabilities{};
    for (rows) |entry| {
        if (rowStatus(kind, entry) != .supported) continue;
        switch (entry.algorithm) {
            .hash => |hash| caps.hashes.insert(hash),
            .aead => |aead| caps.aeads.insert(aead),
            .quic_header_protection => |hp| caps.quic_header_protection.insert(hp),
            .group => |group| caps.groups.insert(group),
            .signature => |scheme| caps.signatures.insert(scheme),
            .hkdf, .certificate_helper, .entropy => {},
        }
    }
    return caps;
}

fn rowStatus(kind: ProviderKind, entry: Row) Status {
    return switch (kind) {
        .pure_zig => entry.pure_zig_status,
        .openssl => entry.openssl_status,
    };
}

fn algorithmEql(a: Algorithm, b: Algorithm) bool {
    return switch (a) {
        .hash => |value| b == .hash and b.hash == value,
        .hkdf => |value| b == .hkdf and b.hkdf == value,
        .aead => |value| b == .aead and b.aead == value,
        .quic_header_protection => |value| b == .quic_header_protection and b.quic_header_protection == value,
        .group => |value| b == .group and b.group == value,
        .signature => |value| b == .signature and b.signature == value,
        .certificate_helper => |value| b == .certificate_helper and b.certificate_helper == value,
        .entropy => |value| b == .entropy and b.entropy == value,
    };
}

fn expectRow(algorithm: Algorithm) !void {
    for (rows) |entry| {
        if (algorithmEql(entry.algorithm, algorithm)) return;
    }
    std.debug.print("missing crypto profile row for {any}\n", .{algorithm});
    return error.MissingProfileRow;
}

test "matrix covers every provider algorithm enum" {
    inline for (std.enums.values(provider.Hash)) |hash| {
        try expectRow(.{ .hash = hash });
        try expectRow(.{ .hkdf = hash });
    }
    inline for (std.enums.values(provider.Aead)) |aead| try expectRow(.{ .aead = aead });
    inline for (std.enums.values(provider.QuicHeaderProtection)) |hp| try expectRow(.{ .quic_header_protection = hp });
    inline for (std.enums.values(provider.Group)) |group| try expectRow(.{ .group = group });
    inline for (std.enums.values(provider.SignatureScheme)) |scheme| try expectRow(.{ .signature = scheme });
    inline for (std.enums.values(CertificateHelper)) |helper| try expectRow(.{ .certificate_helper = helper });
    inline for (std.enums.values(EntropyCapability)) |capability| try expectRow(.{ .entropy = capability });
}

test "pure-Zig profile capabilities are queryable" {
    const caps = capabilities(.pure_zig);
    try std.testing.expect(caps.supportsHash(.sha256));
    try std.testing.expect(caps.supportsHash(.sha384));
    try std.testing.expect(caps.supportsAead(.aes_128_gcm));
    try std.testing.expect(caps.supportsAead(.aes_256_gcm));
    try std.testing.expect(caps.supportsAead(.chacha20_poly1305));
    try std.testing.expect(caps.supportsQuicHeaderProtection(.aes_128));
    try std.testing.expect(caps.supportsGroup(.x25519));
    try std.testing.expect(!caps.supportsGroup(.secp256r1));
    try std.testing.expect(caps.supportsSignature(.ed25519));
    try std.testing.expect(caps.supportsSignature(.ecdsa_secp256r1_sha256));
    try std.testing.expect(caps.supportsSignature(.rsa_pss_rsae_sha256));
}

fn expectIntegration(algorithm: Algorithm, consumer: Consumer, expected: IntegrationStatus) !void {
    for (rows) |entry| {
        if (!algorithmEql(entry.algorithm, algorithm)) continue;
        const actual = entry.integrationStatus(consumer) orelse return error.MissingConsumerIntegration;
        try std.testing.expectEqual(expected, actual);
        return;
    }
    return error.MissingProfileRow;
}

// Anchors the QUIC packet-protection claims this PR made true (#490): the
// live send/receive path calls CryptoProvider for AES-128-GCM sealing/
// opening and for AES-128 header protection, not a parallel std.crypto path.
// A future regression that quietly reintroduces a concrete bypass without
// updating this row is now a typed test failure, not just stale prose.
test "QUIC packet protection is live-integrated through CryptoProvider" {
    try expectIntegration(.{ .aead = .aes_128_gcm }, .quic_packet_protection, .live);
    try expectIntegration(.{ .hkdf = .sha256 }, .quic_packet_protection, .live);
    try expectIntegration(.{ .hkdf = .sha256 }, .quic_tls_bridge, .live);
    try expectIntegration(.{ .quic_header_protection = .aes_128 }, .quic_packet_protection, .live);
}

test "row helpers expose consumers and enabled product profiles" {
    var found = false;
    for (rows) |entry| {
        if (!algorithmEql(entry.algorithm, .{ .aead = .aes_128_gcm })) continue;
        found = true;
        try std.testing.expect(entry.consumers().contains(.quic_packet_protection));
        try std.testing.expect(entry.enabled_product_profiles.contains(.native_appliance));
        try std.testing.expect(!entry.enabled_product_profiles.contains(.general_purpose_openssl));
    }
    try std.testing.expect(found);
}

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

/// Product profile a row's implementation is reachable from today. This is an
/// explicitly authored product-policy dimension, independent of the
/// primitive/provider implementation status. A capability can be implemented
/// by the pure-Zig provider and be live in the shared TLS engine without
/// being enabled for `.appliance`, while `.general` can still enable it
/// under a different product policy even when `.openssl_status ==
/// .provider_deferred` (that field tracks whether an in-process OpenSSL
/// `CryptoProvider` exists — it never has — independent of which product
/// profile enables the capability).
pub const ProductProfile = enum {
    /// The strict Bare Systems appliance product policy: single Ed25519
    /// identity, in-process pure-Zig QUIC/H3.
    appliance,
    /// The general-purpose native product policy: multi-identity credential
    /// loading, broader algorithm support. Pure-Zig in-process, same as
    /// `.appliance` — the two profiles differ in product policy, not
    /// implementation (the retired OpenSSL production TLS backend this name
    /// once described no longer exists; see #649).
    general,
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
    row(.{ .hash = .sha256 }, "SHA-256", .zig_std_crypto, .supported, .openssl_provider, .provider_deferred, "std.crypto cross-checks, transcript tests", .{ .{ .tls_handshake, .not_provider_routed }, .{ .quic_tls_bridge, .not_provider_routed } }, .{ .appliance, .general }, "Unkeyed transcript hashing never crosses the CryptoProvider vtable by design (no `hash` entry point exists); both product profiles use it for TLS transcripts regardless. Hash additions require transcript/HKDF vectors."),
    row(.{ .hash = .sha384 }, "SHA-384", .zig_std_crypto, .supported, .openssl_provider, .provider_deferred, "provider capability and HKDF tests", .{.{ .tls_handshake, .not_provider_routed }}, .{ .appliance, .general }, "Unkeyed transcript hashing; the native appliance now negotiates TLS_AES_256_GCM_SHA384 (#564), so this hash is selected there whenever that suite is chosen. Never provider-routed by design, same as SHA-256 (see that row)."),
    row(.{ .hkdf = .sha256 }, "HKDF-SHA256", .zig_std_crypto, .supported, .openssl_provider, .provider_deferred, "RFC 5869/std.crypto and TLS expand-label parity", .{ .{ .tls_handshake, .live }, .{ .quic_tls_bridge, .live }, .{ .quic_packet_protection, .live } }, .{ .appliance, .general }, "QUIC Initial/Handshake/1-RTT key derivation in src/quic/tls_adapter.zig and the TLS 1.3 key schedule (src/tls/key_schedule.zig: HKDF-Extract, HKDF-Expand-Label, and Finished verify_data) both run through CryptoProvider (#490)."),
    row(.{ .hkdf = .sha384 }, "HKDF-SHA384", .zig_std_crypto, .supported, .openssl_provider, .provider_deferred, "provider capability and expand-label tests", .{ .{ .tls_handshake, .live }, .{ .quic_packet_protection, .live } }, .{ .appliance, .general }, "The TLS 1.3 key schedule (src/tls/key_schedule.zig) is hash-agile (#564): `KeySchedule` and every resumption/ticket helper derive their hash from the negotiated cipher suite (`algorithms.transcriptHash`) and route it through CryptoProvider. QUIC packet protection now consumes the negotiated TLS_AES_256_GCM_SHA384 profile (#566) and derives its `quic key`/`quic iv`/`quic hp` labels under SHA-384."),
    row(.{ .aead = .aes_128_gcm }, "AES-128-GCM", .zig_std_crypto, .supported, .openssl_provider, .provider_deferred, "seal/open round-trip, tamper rejection, AD mismatch", .{ .{ .tls_record, .live }, .{ .quic_packet_protection, .live } }, .{ .appliance, .general }, "TLS record protection and QUIC packet payload protection (TLS_AES_128_GCM_SHA256) both seal/open through CryptoProvider."),
    row(.{ .aead = .aes_256_gcm }, "AES-256-GCM", .zig_std_crypto, .supported, .openssl_provider, .provider_deferred, "seal/open round-trip, tamper rejection, AD mismatch", .{ .{ .tls_record, .live }, .{ .quic_packet_protection, .live } }, .{ .appliance, .general }, "The native appliance's engine now negotiates TLS_AES_256_GCM_SHA384 (#564) and reuses the existing generic `record_protection.TrafficKeys.derive` path for records. QUIC packet protection now selects AES-256-GCM from the same negotiated suite metadata (#566)."),
    row(.{ .aead = .chacha20_poly1305 }, "ChaCha20-Poly1305", .zig_std_crypto, .supported, .openssl_provider, .provider_deferred, "seal/open round-trip, tamper rejection, AD mismatch", .{ .{ .tls_record, .live }, .{ .quic_packet_protection, .live } }, .{ .appliance, .general }, "The native appliance's engine now negotiates TLS_CHACHA20_POLY1305_SHA256 (#564), through the same generic, CryptoProvider-routed record-protection path as the other two suites. QUIC packet protection now selects ChaCha20-Poly1305 from explicit negotiated-suite metadata (#566)."),
    row(.{ .quic_header_protection = .aes_128 }, "QUIC AES-128 header protection", .zig_std_crypto, .supported, .openssl_provider, .provider_deferred, "RFC 9001 header-protection sample and provider mask parity", .{.{ .quic_packet_protection, .live }}, .{.appliance}, "src/quic/tls_adapter.zig applies and removes header protection through CryptoProvider on every send/receive path (#490); the direct Aes128.initEnc form remains only as differential test-vector fixtures. QUIC-specific: the general-purpose backend is TLS-over-TCP, not QUIC."),
    row(.{ .quic_header_protection = .aes_256 }, "QUIC AES-256 header protection", .zig_std_crypto, .supported, .openssl_provider, .provider_deferred, "provider mask parity and negotiated-suite packet tests", .{.{ .quic_packet_protection, .live }}, .{.appliance}, "TLS_AES_256_GCM_SHA384 QUIC Handshake/0-RTT/1-RTT packet protection derives a 32-byte `quic hp` key and calls the QUIC-specific CryptoProvider header-protection operation (#566)."),
    row(.{ .quic_header_protection = .chacha20 }, "QUIC ChaCha20 header protection", .zig_std_crypto, .supported, .openssl_provider, .provider_deferred, "RFC 9001 sample mapping and negotiated-suite packet tests", .{.{ .quic_packet_protection, .live }}, .{.appliance}, "TLS_CHACHA20_POLY1305_SHA256 QUIC Handshake/0-RTT/1-RTT packet protection uses RFC 9001's sample-to-counter/nonce construction through the QUIC-specific CryptoProvider operation (#566)."),
    row(.{ .group = .x25519 }, "X25519", .zig_std_crypto, .supported, .openssl_provider, .provider_deferred, "std.crypto scalar multiplication parity, low-order rejection", .{ .{ .tls_handshake, .live }, .{ .quic_tls_bridge, .not_integrated } }, .{ .appliance, .general }, "src/tls/tls13_backend.zig generates its ephemeral key share and derives the shared secret through CryptoProvider.generateKeyShare/.deriveSharedSecret (#490); group additions require key-share and shared-secret vectors."),
    row(.{ .group = .secp256r1 }, "secp256r1 (P-256)", .zig_std_crypto, .supported, .openssl_provider, .provider_deferred, "fixed scalar/public/shared-secret vectors, Alice/Bob symmetry, deterministic entropy generation, malformed point and scalar rejection, OpenSSL differential ECDH oracle, native TLS loopbacks", .{ .{ .tls_handshake, .live }, .{ .quic_tls_bridge, .not_integrated }, .{ .pki, .not_integrated } }, .{.general}, "#335: the shared TLS 1.3 backend now advertises, selects, HRR-retries, and derives secp256r1 key shares through CryptoProvider. Product enablement remains general-purpose only; the native-appliance profile intentionally stays on X25519 until #391 changes that narrower release policy."),
    row(.{ .signature = .ed25519 }, "Ed25519", .zig_std_crypto, .supported, .openssl_provider, .provider_deferred, "sign/verify, tamper rejection, wrong-key rejection", .{ .{ .tls_handshake, .live }, .{ .pki, .live } }, .{ .appliance, .general }, "Certificate-chain verification (src/pki/verify.zig) and the handshake's own CertificateVerify proof-of-possession (src/tls/tls13_backend.zig) both call CryptoProvider.verify (#490); local CertificateVerify signing (src/tls/credentials.zig) signs through the opaque provider.SigningKey handle."),
    row(.{ .signature = .ecdsa_secp256r1_sha256 }, "ECDSA-P256-SHA256", .zig_std_crypto, .supported, .openssl_provider, .provider_deferred, "SEC1 key/DER signature verify, provider.SigningKey sign/verify, deterministic and failing signing entropy, alternate high/low-S verification, tamper, wrong-key, non-canonical-signature rejection (#343/#432)", .{ .{ .tls_handshake, .live }, .{ .pki, .live } }, .{ .appliance, .general }, "Same split as Ed25519, now both live (#490/#432): PKI chain verification and CertificateVerify both call CryptoProvider.verify, and local signing goes through provider.SigningKey with per-signature noise from injected provider entropy. Signatures are canonical DER but not low-S normalized; verification accepts valid non-zero in-range high-S and low-S forms without rewriting. This row is signature-only; P-256 ECDH capability is tracked separately by the secp256r1 group row."),
    row(.{ .signature = .rsa_pss_rsae_sha256 }, "RSA-PSS-RSAE-SHA256", .project_code, .supported, .openssl_provider, .provider_deferred, "strict DER/RSA-PSS positive and negative fixtures, provider.SigningKey sign/verify roundtrip, entropy-failure and undersized-output non-partial-signature checks, credential-selection key-type/offer compatibility, native TLS server/client loopback", .{ .{ .tls_handshake, .live }, .{ .pki, .live } }, .{.general}, "#565: native RSA-PSS server signing now exists (pure-Zig private-key owner behind provider.SigningKey, `std.crypto.ff.Modulus.powWithEncodedExponent` for the constant-time private-exponent modpow — no CRT, see docs/CRYPTO_SECURITY_AUDIT.md), and credentials.zig/policy.zig/sni_provider.zig/tls13_backend.zig all recognize the scheme end to end, so tls_handshake is genuinely `.live`: the engine's CertificateVerify can both select an RSA credential and sign/verify with it, not merely name the scheme. `enabled_product_profiles` deliberately stays general-only, not a mechanical copy of this: broadening what the controlled native-appliance product actually offers is a separate #391 policy decision this row does not make on its own — engine capability (tls13_backend.native_capabilities) and product enablement (this field) are tracked independently on purpose."),
    row(.{ .signature = .rsa_pkcs1_sha256 }, "RSA-PKCS1v15-SHA256", .project_code, .supported, .openssl_provider, .provider_deferred, "strict EMSA-PKCS1-v1_5 positive/negative primitive fixtures (known-good openssl signature, tampered message/signature, signature integer >= modulus, wrong length, malformed key), provider.verify wiring, src/pki/verify.zig positive chain-verification fixtures (rsa_ca.crt self-signature, ecdsa_leaf.crt cross-signed by the RSA CA), tampered-TBS/signature and wrong-issuer-key rejection, AlgorithmIdentifier parameter cases (explicit NULL/absent accepted, other rejected), a real native-upstream-HTTPS integration fixture through src/tls/webpki_verifier.zig", .{.{ .pki, .live }}, .{.general}, "#645: X.509 certificate-chain signature verification only (`sha256WithRSAEncryption`) — reuses the RSA-PSS row's key parser, accepted-modulus-size, and `std.crypto.ff.Modulus` exponentiation machinery, differing only in EMSA-PKCS1-v1_5 vs EMSA-PSS validation of the recovered block. Deliberately has no `tls_handshake` integration entry: RFC 8446 §4.2.3 forbids `rsa_pkcs1` schemes in TLS 1.3 CertificateVerify, and `src/tls/crypto_profile.zig`'s `supportsSignatureScheme` continues to hard-refuse it regardless of this provider capability (see that file's own regression). `enabled_product_profiles` mirrors the RSA-PSS row for the same reason stated there: primitive support is not itself a native-appliance product-policy decision (#391)."),
    row(.{ .signature = .rsa_pkcs1_sha384 }, "RSA-PKCS1v15-SHA384", .project_code, .supported, .openssl_provider, .provider_deferred, "strict EMSA-PKCS1-v1_5/SHA-384 positive/negative primitive fixtures (known-good openssl signature, tampered message/signature, wrong length), provider.verify wiring", .{.{ .pki, .live }}, .{.general}, "#645: same strict primitive as rsa_pkcs1_sha256, parameterized by hash (`src/crypto/rsa.zig`'s shared `verifyPkcs1v15`) — added because the additional surface area over the required SHA-256 variant is small (a different DigestInfo prefix and digest length), not a second implementation. Same TLS-CertificateVerify exclusion and product-profile reasoning as the SHA-256 row above; x509.SignatureAlgorithm already classified `sha384WithRSAEncryption` before #645 (see src/pki/x509.zig), this row is the provider/PKI wiring for it."),
    row(.{ .certificate_helper = .der_parser }, "DER/X.509 parser helpers", .project_code, .provider_deferred, .openssl_provider, .provider_deferred, "module-local parser fixtures", .{.{ .pki, .not_provider_routed }}, .{ .appliance, .general }, "Public DER/X.509 parsing has no CryptoProvider vtable entry and is called directly by protocol-local PKI code shared by both product profiles; certificate helpers require malformed-input and corpus tests."),
    row(.{ .certificate_helper = .chain_builder }, "certificate chain builder", .unavailable, .provider_deferred, .openssl_provider, .provider_deferred, "tracked by PKI stories", .{.{ .pki, .not_integrated }}, .{}, "Not implemented yet for either product profile; chain validation requires path-building fixtures."),
    row(.{ .certificate_helper = .webpki_validation }, "WebPKI validation", .unavailable, .provider_deferred, .openssl_provider, .provider_deferred, "tracked by PKI stories", .{.{ .pki, .not_integrated }}, .{}, "Not implemented yet for either product profile; WebPKI support requires policy and time-validation review."),
    row(.{ .entropy = .injected_random_bytes }, "injected random bytes", .project_code, .supported, .openssl_provider, .provider_deferred, "deterministic and failing entropy tests, ECDSA signing entropy ordering/failure tests", .{ .{ .tls_handshake, .live }, .{ .quic_packet_protection, .not_integrated }, .{ .resumption, .not_integrated } }, .{ .appliance, .general }, "CryptoProvider.generateKeyShare draws ephemeral X25519 and secp256r1 private scalars from CryptoProvider.entropy.fill (#490/#335), and ECDSA-P256 provider.SigningKey.sign draws per-signature noise from the same injected entropy seam (#432), so the TLS 1.3 handshake engine is live; QUIC packet protection and resumption/ticket code still inject randomness through their own longer-standing Entropy parameters instead, in both product profiles. Randomness changes require no-ambient-RNG review regardless of which seam supplies it."),
    row(.{ .entropy = .secure_zero }, "secure zero", .project_code, .supported, .project_code, .supported, "secret-container and provider wipe tests", .{ .{ .tls_handshake, .not_provider_routed }, .{ .tls_record, .not_provider_routed }, .{ .quic_packet_protection, .not_provider_routed }, .{ .pki, .not_provider_routed }, .{ .resumption, .not_provider_routed } }, .{ .appliance, .general }, "A shared helper called directly by protocol code and by provider internals alike, not a CryptoProvider vtable dispatch target; secret handling changes require wipe-on-error review."),
    row(.{ .entropy = .constant_time_compare }, "constant-time compare", .project_code, .supported, .project_code, .supported, "crypto secret helper tests", .{ .{ .tls_handshake, .not_provider_routed }, .{ .tls_record, .not_provider_routed }, .{ .pki, .not_provider_routed } }, .{ .appliance, .general }, "Same shared-helper shape as secure zero; comparison changes require timing-safe API review."),
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
    comptime product_profiles_list: anytype,
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
        .enabled_product_profiles = productProfileSet(product_profiles_list),
        .review = review,
    };
}

fn integrationList(comptime items: anytype) [items.len]ConsumerIntegration {
    var list: [items.len]ConsumerIntegration = undefined;
    inline for (items, 0..) |item, i| list[i] = .{ .consumer = item[0], .status = item[1] };
    return list;
}

fn productProfileSet(comptime items: anytype) ProductProfileSet {
    var set = ProductProfileSet{};
    inline for (items) |item| set.insert(item);
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

/// Whether `algorithm` is enabled for `product` in the checked-in profile.
pub fn productEnables(product: ProductProfile, algorithm: Algorithm) bool {
    for (rows) |entry| {
        if (!algorithmEql(entry.algorithm, algorithm)) continue;
        return entry.enabled_product_profiles.contains(product);
    }
    return false;
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
    try std.testing.expect(caps.supportsGroup(.secp256r1));
    try std.testing.expect(caps.supportsSignature(.ed25519));
    try std.testing.expect(caps.supportsSignature(.ecdsa_secp256r1_sha256));
    try std.testing.expect(caps.supportsSignature(.rsa_pss_rsae_sha256));
    try std.testing.expect(caps.supportsSignature(.rsa_pkcs1_sha256));
    try std.testing.expect(caps.supportsSignature(.rsa_pkcs1_sha384));
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

// Anchors the native TLS 1.3 engine claims this PR made true (#490), updated
// for #564's cipher/hash agility and #565's RSA-PSS server signing: the
// handshake's key schedule, key exchange, and CertificateVerify all call
// CryptoProvider, not a parallel std.crypto path. HKDF-SHA384 is now `.live`
// for tls_handshake — the key schedule derives every secret's hash from the
// negotiated suite (`algorithms.transcriptHash`), so a native handshake that
// selects TLS_AES_256_GCM_SHA384 really does derive under SHA-384, not merely
// a capability the provider happens to support. secp256r1 is `.live` through
// the same provider key-share seam (#335), and RSA-PSS is now `.live` too
// (#565): `tls13_backend.native_signature_schemes` names it,
// `checkProofOfPossession`/`leafSupportsSignatureScheme` recognize an RSA
// leaf, and `credentials`/`policy`/`sni_provider` all route a selected RSA
// credential through the same opaque `provider.SigningKey` seam Ed25519/ECDSA
// use — proven end to end by a native record-mode loopback with an
// RSA-PSS-only policy on both sides (`tls13_backend_tests.zig`). This is
// engine capability, not product enablement: the checked-in
// `enabled_product_profiles` for this row deliberately still excludes the
// native appliance pending #391 (see that row's `review` string), so
// `crypto_profile.fromProfile(.appliance, ...)` does not yet offer it
// — a separate assertion below. A future regression that quietly
// reintroduces a concrete bypass, or over-claims support the live protocol
// path cannot execute, is now a typed test failure, not just stale prose.
test "native TLS 1.3 handshake engine is live-integrated through CryptoProvider" {
    try expectIntegration(.{ .hkdf = .sha256 }, .tls_handshake, .live);
    try expectIntegration(.{ .hkdf = .sha384 }, .tls_handshake, .live);
    try expectIntegration(.{ .group = .x25519 }, .tls_handshake, .live);
    try expectIntegration(.{ .group = .secp256r1 }, .tls_handshake, .live);
    try expectIntegration(.{ .signature = .ed25519 }, .tls_handshake, .live);
    try expectIntegration(.{ .signature = .ecdsa_secp256r1_sha256 }, .tls_handshake, .live);
    try expectIntegration(.{ .entropy = .injected_random_bytes }, .tls_handshake, .live);
    try expectIntegration(.{ .signature = .rsa_pss_rsae_sha256 }, .tls_handshake, .live);
}

// Anchors #645's certificate-chain-only scope: RSA PKCS#1 v1.5 must be
// `pki`-`.live` (src/pki/verify.zig genuinely calls CryptoProvider.verify
// with it) while carrying no `tls_handshake` integration entry at all — RFC
// 8446 §4.2.3 forbids `rsa_pkcs1` schemes in TLS 1.3 CertificateVerify. A
// future regression that wired it into the handshake engine would either
// make `integrationStatus(.tls_handshake)` non-null here (caught below) or
// require adding a `.{ .tls_handshake, .live }` entry to the row itself,
// which is exactly the "blindly make every ... TLS-policy path support the
// new variant" mistake #645 warns against.
test "RSA PKCS#1 v1.5 is PKI-only, never a TLS 1.3 CertificateVerify integration" {
    try expectIntegration(.{ .signature = .rsa_pkcs1_sha256 }, .pki, .live);
    try expectIntegration(.{ .signature = .rsa_pkcs1_sha384 }, .pki, .live);
    for (rows) |entry| {
        if (!algorithmEql(entry.algorithm, .{ .signature = .rsa_pkcs1_sha256 })) continue;
        try std.testing.expect(entry.integrationStatus(.tls_handshake) == null);
    }
    for (rows) |entry| {
        if (!algorithmEql(entry.algorithm, .{ .signature = .rsa_pkcs1_sha384 })) continue;
        try std.testing.expect(entry.integrationStatus(.tls_handshake) == null);
    }
}

test "row helpers expose consumers and enabled product profiles" {
    var found = false;
    for (rows) |entry| {
        if (!algorithmEql(entry.algorithm, .{ .aead = .aes_128_gcm })) continue;
        found = true;
        try std.testing.expect(entry.consumers().contains(.quic_packet_protection));
        try std.testing.expect(entry.enabled_product_profiles.contains(.appliance));
        try std.testing.expect(entry.enabled_product_profiles.contains(.general));
    }
    try std.testing.expect(found);
}

fn enabledProfilesFor(algorithm: Algorithm) ProductProfileSet {
    for (rows) |entry| {
        if (algorithmEql(entry.algorithm, algorithm)) return entry.enabled_product_profiles;
    }
    unreachable;
}

// Anchors the exact distinction the profile previously collapsed (#490
// second-pass review): primitive support (`pure_zig_status`) is not the same
// thing as product-level selectability — a row's `enabled_product_profiles`
// is a deliberate product-integration claim, not a mechanical copy of
// `.supported`. AES-256-GCM and ChaCha20-Poly1305 illustrated this asymmetry
// before #564 (both reported `pure_zig_status = .supported` but neither was
// negotiated by the native appliance); now that the native engine's
// handshake/transcript/key-schedule are cipher/hash-agile and negotiate all
// three suites, both correctly claim `.appliance` too — the
// assertions below were updated in lockstep with the profile rows, not
// dropped, so a future regression that silently un-claims either is still
// caught. secp256r1 remains the standing example of the asymmetry: the
// provider and shared TLS engine now implement P-256 ECDH key-share
// generation, selection, and shared-secret derivation behind CryptoProvider,
// but the native appliance product profile still deliberately does not offer
// the group pending #391, so it must not claim `.appliance` —
// `openssl_status` (`.provider_deferred`, the in-process OpenSSL
// CryptoProvider column) is beside the point; the general-purpose product
// policy does enable the group (product enablement is authored policy, not
// implementation availability — both profiles share the same native engine
// since #649), so this row must still claim `.general`.
test "enabled product profiles are not a mechanical copy of primitive support" {
    const aes_256_profiles = enabledProfilesFor(.{ .aead = .aes_256_gcm });
    try std.testing.expect(aes_256_profiles.contains(.appliance));
    try std.testing.expect(aes_256_profiles.contains(.general));

    const chacha_profiles = enabledProfilesFor(.{ .aead = .chacha20_poly1305 });
    try std.testing.expect(chacha_profiles.contains(.appliance));
    try std.testing.expect(chacha_profiles.contains(.general));

    const secp256r1_profiles = enabledProfilesFor(.{ .group = .secp256r1 });
    try std.testing.expect(!secp256r1_profiles.contains(.appliance));
    try std.testing.expect(secp256r1_profiles.contains(.general));

    // #565: RSA-PSS is `tls_handshake`-`.live` (the engine can genuinely sign
    // and verify with it), but that is engine capability, not product
    // enablement — the native appliance's checked-in profile deliberately
    // does not offer it pending a separate #391 policy decision, matching the
    // secp256r1 product-profile distinction above.
    const rsa_pss_profiles = enabledProfilesFor(.{ .signature = .rsa_pss_rsae_sha256 });
    try std.testing.expect(!rsa_pss_profiles.contains(.appliance));
    try std.testing.expect(rsa_pss_profiles.contains(.general));

    // #645: RSA PKCS#1 v1.5 is a genuinely live pki-consumer capability (the
    // row above proves it), but that is not itself a native-appliance
    // product-policy decision — same asymmetry as RSA-PSS, for the same
    // reason (#391 governs appliance product enablement separately).
    const rsa_pkcs1_sha256_profiles = enabledProfilesFor(.{ .signature = .rsa_pkcs1_sha256 });
    try std.testing.expect(!rsa_pkcs1_sha256_profiles.contains(.appliance));
    try std.testing.expect(rsa_pkcs1_sha256_profiles.contains(.general));

    const rsa_pkcs1_sha384_profiles = enabledProfilesFor(.{ .signature = .rsa_pkcs1_sha384 });
    try std.testing.expect(!rsa_pkcs1_sha384_profiles.contains(.appliance));
    try std.testing.expect(rsa_pkcs1_sha384_profiles.contains(.general));

    const header_protection_profiles = enabledProfilesFor(.{ .quic_header_protection = .aes_128 });
    try std.testing.expect(header_protection_profiles.contains(.appliance));
    try std.testing.expect(!header_protection_profiles.contains(.general));
}

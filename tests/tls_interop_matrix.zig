//! Shared interoperability/conformance matrix vocabulary (#338).
//!
//! The external conformance suite drives the *same* TLS 1.3 engine over two
//! transports: the record transport (`tls_interop_tool`) and the QUIC
//! transport (`h3_interop_tool`). Both need to name the same negotiation
//! tuple on a command line, turn it into a `tls_core.policy.Policy`, and
//! report what was actually negotiated in the same words. That mapping lives
//! here exactly once, so a row in the matrix means the same thing on either
//! transport and adding a suite/group/signature cannot drift between them.
//!
//! This module deliberately owns *only* the vocabulary and the policy
//! construction. Carrier I/O, process lifetime, and result reporting belong
//! to the individual tools -- those genuinely differ between a TCP record
//! stream and a UDP QUIC connection, and pretending otherwise would produce
//! an abstraction neither tool wants.

const std = @import("std");
const tls_core = @import("tls_core");

const algorithms = tls_core.algorithms;
const tls_policy = tls_core.policy;
const tls_state = tls_core.state;

pub const CipherSuite = algorithms.CipherSuite;
pub const NamedGroup = algorithms.NamedGroup;
pub const SignatureScheme = algorithms.SignatureScheme;

pub const ParseError = error{ UnknownCipherSuite, UnknownNamedGroup, UnknownSignatureScheme, TooManyValues };

/// Every cipher suite the shared engine can negotiate, in the order the
/// matrix enumerates them. Derived from the engine's own capability set
/// rather than restated, so a suite added to `native_capabilities` shows up
/// as a new matrix row instead of being silently skipped.
pub const cipher_suites: []const CipherSuite = tls_core.tls13_backend.native_capabilities.cipher_suites;
pub const named_groups: []const NamedGroup = tls_core.tls13_backend.native_capabilities.named_groups;
pub const signature_schemes: []const SignatureScheme = tls_core.tls13_backend.native_capabilities.signature_schemes;

/// Upper bound on how many values of one dimension a single run may select.
/// Sized from the engine's capability lists so a caller can always offer
/// "everything supported" without a heap allocation.
pub const max_values = @max(cipher_suites.len, @max(named_groups.len, signature_schemes.len));
pub const max_alpn_protocols = 4;

/// The matrix's own spelling of each identifier. These strings are the
/// stable contract between the runner script, the tools' `--cipher-suite`/
/// `--group`/`--signature` flags, and the emitted result lines -- a grep for
/// `suite=chacha20-poly1305-sha256` in CI logs must keep working.
pub fn cipherSuiteName(suite: CipherSuite) []const u8 {
    return switch (suite) {
        .tls_aes_128_gcm_sha256 => "aes128-gcm-sha256",
        .tls_aes_256_gcm_sha384 => "aes256-gcm-sha384",
        .tls_chacha20_poly1305_sha256 => "chacha20-poly1305-sha256",
    };
}

pub fn namedGroupName(group: NamedGroup) []const u8 {
    return switch (group) {
        .x25519 => "x25519",
        .secp256r1 => "secp256r1",
        .secp384r1 => "secp384r1",
    };
}

pub fn signatureSchemeName(scheme: SignatureScheme) []const u8 {
    return switch (scheme) {
        .ed25519 => "ed25519",
        .ecdsa_secp256r1_sha256 => "ecdsa-p256-sha256",
        .rsa_pss_rsae_sha256 => "rsa-pss-rsae-sha256",
        .rsa_pkcs1_sha256 => "rsa-pkcs1-sha256",
        .rsa_pkcs1_sha384 => "rsa-pkcs1-sha384",
    };
}

// Parsing is deliberately scoped to the engine's *native capability* slices
// rather than the whole protocol registry. `Config.policy` hands its selected
// slices straight to `Policy.fromCapabilities`, which does not filter them, so
// accepting an identifier the engine does not natively negotiate (`secp384r1`,
// `rsa_pkcs1_sha256`) would let a matrix row *widen* the engine policy into a
// test-only capability -- the exact opposite of the narrow-only invariant this
// module documents, and it would turn a passing cell into evidence about
// something production never does. An identifier that exists in the registry
// but not in `native_capabilities` is therefore rejected the same way a typo
// is; it becomes selectable the moment the engine actually supports it.

pub fn parseCipherSuite(name: []const u8) ParseError!CipherSuite {
    for (cipher_suites) |suite| {
        if (std.mem.eql(u8, name, cipherSuiteName(suite))) return suite;
    }
    return error.UnknownCipherSuite;
}

pub fn parseNamedGroup(name: []const u8) ParseError!NamedGroup {
    for (named_groups) |group| {
        if (std.mem.eql(u8, name, namedGroupName(group))) return group;
    }
    return error.UnknownNamedGroup;
}

pub fn parseSignatureScheme(name: []const u8) ParseError!SignatureScheme {
    for (signature_schemes) |scheme| {
        if (std.mem.eql(u8, name, signatureSchemeName(scheme))) return scheme;
    }
    return error.UnknownSignatureScheme;
}

/// Which private-key type a signature scheme requires the local identity to
/// hold. The runner uses the matrix's signature dimension to pick the
/// certificate/key pair it hands the tool, so the two can never disagree
/// about which credential a row needs.
pub fn identityKeyForSignature(scheme: SignatureScheme) tls_policy.IdentityKey {
    return switch (scheme) {
        .ed25519 => .ed25519,
        .ecdsa_secp256r1_sha256 => .ecdsa_secp256r1,
        .rsa_pss_rsae_sha256, .rsa_pkcs1_sha256, .rsa_pkcs1_sha384 => .rsa,
    };
}

/// A bounded, ordered selection along one matrix dimension. Empty means
/// "offer everything the engine supports", which is what a positive row
/// wants for the dimensions it is not pinning.
pub fn Selection(comptime T: type) type {
    return struct {
        const Self = @This();

        values: [max_values]T = undefined,
        len: usize = 0,

        pub fn append(self: *Self, value: T) ParseError!void {
            if (self.len == max_values) return error.TooManyValues;
            self.values[self.len] = value;
            self.len += 1;
        }

        /// `fallback` is used verbatim when nothing was selected, so an
        /// unpinned dimension offers the engine's full capability list
        /// rather than a silently narrowed subset.
        pub fn slice(self: *const Self, fallback: []const T) []const T {
            return if (self.len == 0) fallback else self.values[0..self.len];
        }
    };
}

/// The complete negotiation surface one interop run offers, independent of
/// transport. `alpn_protocols` is stored as borrowed byte slices: the caller
/// owns the argv strings for the process's lifetime.
pub const Config = struct {
    cipher_suites: Selection(CipherSuite) = .{},
    named_groups: Selection(NamedGroup) = .{},
    signature_schemes: Selection(SignatureScheme) = .{},
    alpn_storage: [max_alpn_protocols]algorithms.ProtocolName = undefined,
    alpn_len: usize = 0,
    require_sni: bool = false,
    allow_absent_alpn: bool = false,
    /// #359: the RFC 8449 `record_size_limit` this side advertises. Null
    /// leaves `tls_policy.Policy`'s own default (the protocol maximum), which
    /// is what every row that is not about record sizing wants.
    record_size_limit: ?u16 = null,

    pub fn addCipherSuite(self: *Config, name: []const u8) ParseError!void {
        try self.cipher_suites.append(try parseCipherSuite(name));
    }

    pub fn addNamedGroup(self: *Config, name: []const u8) ParseError!void {
        try self.named_groups.append(try parseNamedGroup(name));
    }

    pub fn addSignatureScheme(self: *Config, name: []const u8) ParseError!void {
        try self.signature_schemes.append(try parseSignatureScheme(name));
    }

    pub fn addAlpn(self: *Config, name: []const u8) ParseError!void {
        if (self.alpn_len == max_alpn_protocols) return error.TooManyValues;
        self.alpn_storage[self.alpn_len] = .{ .bytes = name };
        self.alpn_len += 1;
    }

    pub fn alpnProtocols(self: *const Config, fallback: []const algorithms.ProtocolName) []const algorithms.ProtocolName {
        return if (self.alpn_len == 0) fallback else self.alpn_storage[0..self.alpn_len];
    }

    /// Build the engine policy for `transport_mode`. `default_alpns` is the
    /// transport's own default protocol list (h3 for QUIC, h2/http-1.1 for
    /// the record transport) -- the one genuinely transport-specific input,
    /// passed in rather than branched on here.
    ///
    /// Capabilities are *narrowed* from the engine's native set, never
    /// widened: a row can only ask for a tuple the engine already claims to
    /// support, so a passing matrix cell is evidence about production
    /// behaviour rather than about a test-only capability.
    pub fn policy(
        self: *const Config,
        transport_mode: tls_state.TransportMode,
        default_alpns: []const algorithms.ProtocolName,
    ) tls_policy.Policy {
        var result = tls_policy.Policy.fromCapabilities(transport_mode, .{
            .protocol_versions = tls_core.tls13_backend.native_capabilities.protocol_versions,
            .cipher_suites = self.cipher_suites.slice(cipher_suites),
            .named_groups = self.named_groups.slice(named_groups),
            .signature_schemes = self.signature_schemes.slice(signature_schemes),
        }, self.alpnProtocols(default_alpns));
        result.require_sni = self.require_sni;
        result.allow_absent_alpn = self.allow_absent_alpn;
        if (self.record_size_limit) |limit| result.record_size_limit = limit;
        return result;
    }

    /// Check a completed handshake against what this row pinned.
    ///
    /// A row that pins exactly one value along a dimension is asserting the
    /// peer *landed* on it, not merely that some handshake succeeded --
    /// otherwise a server quietly ignoring the requested group would still
    /// show green.
    ///
    /// This lives here, not in either tool, because both transports must
    /// apply the same expectations to the same row. When the record tool
    /// checked ALPN and the QUIC tool did not, the two had already drifted
    /// into asserting different things about an identically-named matrix cell
    /// (#338 review). `report` is called once per failed expectation; the
    /// return value is whether everything held.
    pub fn validateNegotiated(
        self: *const Config,
        got: Negotiated,
        expected_alpn: ?[]const u8,
        ctx: anytype,
        comptime report: fn (@TypeOf(ctx), Mismatch) void,
    ) bool {
        var ok = true;
        if (self.cipher_suites.len == 1) {
            const want = self.cipher_suites.values[0];
            if (got.cipher_suite == null or got.cipher_suite.? != want) {
                report(ctx, .{
                    .dimension = "cipher-suite",
                    .expected = cipherSuiteName(want),
                    .observed = if (got.cipher_suite) |suite| cipherSuiteName(suite) else "(none)",
                });
                ok = false;
            }
        }
        if (self.named_groups.len == 1) {
            const want = self.named_groups.values[0];
            if (got.named_group == null or got.named_group.? != want) {
                report(ctx, .{
                    .dimension = "group",
                    .expected = namedGroupName(want),
                    .observed = if (got.named_group) |group| namedGroupName(group) else "(none)",
                });
                ok = false;
            }
        }
        if (expected_alpn) |want| {
            if (!std.mem.eql(u8, got.alpn, want)) {
                report(ctx, .{
                    .dimension = "alpn",
                    .expected = want,
                    .observed = if (got.alpn.len > 0) got.alpn else "(none)",
                });
                ok = false;
            }
        }
        return ok;
    }
};

/// One-line usage fragment shared by both tools' `--help` output, so the two
/// cannot document different spellings of the same flags.
pub const flag_usage =
    "  --cipher-suite NAME   repeatable, see `list-capabilities`\n" ++
    "  --group NAME          repeatable, see `list-capabilities`\n" ++
    "  --signature NAME      repeatable, see `list-capabilities`\n" ++
    "  --alpn NAME           repeatable application protocol name\n";

// ---------------------------------------------------------------------------
// Machine-readable capability listing
// ---------------------------------------------------------------------------

/// Emit every dimension the engine natively negotiates as `kind<TAB>name`
/// lines, one per value, through `writeLine`.
///
/// This is what makes "a new engine capability becomes a new matrix row"
/// true rather than aspirational. The runner script cannot import Zig, so
/// without this it would need its own copy of the three lists -- a second,
/// unchecked registry that silently keeps enumerating the old set after
/// `native_capabilities` grows. Instead the script asks the tool, and a
/// capability it has no peer spelling for fails preflight loudly.
///
/// `writeLine` takes the fully formatted line (no trailing newline) so this
/// stays free of any I/O dependency and is directly testable.
pub fn listCapabilities(
    ctx: anytype,
    comptime writeLine: fn (@TypeOf(ctx), kind: []const u8, name: []const u8) void,
) void {
    for (cipher_suites) |suite| writeLine(ctx, "cipher-suite", cipherSuiteName(suite));
    for (named_groups) |group| writeLine(ctx, "group", namedGroupName(group));
    for (signature_schemes) |scheme| writeLine(ctx, "signature", signatureSchemeName(scheme));
}

// ---------------------------------------------------------------------------
// Shared negotiated-tuple expectations
// ---------------------------------------------------------------------------

/// What a completed handshake actually negotiated, in transport-neutral terms.
/// Each tool translates its own backend state into this; everything downstream
/// of that translation is shared.
pub const Negotiated = struct {
    cipher_suite: ?CipherSuite = null,
    named_group: ?NamedGroup = null,
    alpn: []const u8 = "",
};

/// A single expectation that did not hold, with both sides of the comparison
/// already resolved to matrix names so a caller only has to print it.
pub const Mismatch = struct {
    dimension: []const u8,
    expected: []const u8,
    observed: []const u8,
};

test "every engine-supported identifier has a matrix name that round-trips" {
    for (cipher_suites) |suite| {
        try std.testing.expectEqual(suite, try parseCipherSuite(cipherSuiteName(suite)));
    }
    for (named_groups) |group| {
        try std.testing.expectEqual(group, try parseNamedGroup(namedGroupName(group)));
    }
    for (signature_schemes) |scheme| {
        try std.testing.expectEqual(scheme, try parseSignatureScheme(signatureSchemeName(scheme)));
    }
}

test "matrix names are distinct across every enum value, not just the native subset" {
    // A name collision would make two matrix rows indistinguishable in a CI
    // log while still parsing, so check the whole registry -- including
    // identifiers the engine does not negotiate natively yet.
    inline for (comptime std.enums.values(SignatureScheme)) |a| {
        inline for (comptime std.enums.values(SignatureScheme)) |b| {
            if (a != b) try std.testing.expect(!std.mem.eql(u8, signatureSchemeName(a), signatureSchemeName(b)));
        }
    }
    inline for (comptime std.enums.values(NamedGroup)) |a| {
        inline for (comptime std.enums.values(NamedGroup)) |b| {
            if (a != b) try std.testing.expect(!std.mem.eql(u8, namedGroupName(a), namedGroupName(b)));
        }
    }
}

test "unknown identifiers are rejected rather than silently defaulted" {
    try std.testing.expectError(error.UnknownCipherSuite, parseCipherSuite("aes128-gcm"));
    try std.testing.expectError(error.UnknownNamedGroup, parseNamedGroup("X25519"));
    try std.testing.expectError(error.UnknownSignatureScheme, parseSignatureScheme("ed448"));
}

test "a registry identifier the engine does not natively negotiate cannot be selected" {
    // `secp384r1` and `rsa_pkcs1_sha256` exist in the protocol registry and
    // have matrix names, but are absent from `native_capabilities`. Accepting
    // them would let a row *widen* the engine policy — `Config.policy` passes
    // its selection straight to `Policy.fromCapabilities`, which does not
    // filter — so a green cell would be evidence about a test-only capability
    // rather than about production.
    try std.testing.expect(!containsGroup(named_groups, .secp384r1));
    try std.testing.expectError(error.UnknownNamedGroup, parseNamedGroup("secp384r1"));

    try std.testing.expect(!containsSignature(signature_schemes, .rsa_pkcs1_sha256));
    try std.testing.expectError(error.UnknownSignatureScheme, parseSignatureScheme("rsa-pkcs1-sha256"));

    // ...and rejected through the `Config` entry points the tools actually use.
    var config = Config{};
    try std.testing.expectError(error.UnknownNamedGroup, config.addNamedGroup("secp384r1"));
    try std.testing.expectError(error.UnknownSignatureScheme, config.addSignatureScheme("rsa-pkcs1-sha256"));
    try std.testing.expectEqual(@as(usize, 0), config.named_groups.len);
    try std.testing.expectEqual(@as(usize, 0), config.signature_schemes.len);
}

fn containsGroup(haystack: []const NamedGroup, needle: NamedGroup) bool {
    for (haystack) |value| {
        if (value == needle) return true;
    }
    return false;
}

fn containsSignature(haystack: []const SignatureScheme, needle: SignatureScheme) bool {
    for (haystack) |value| {
        if (value == needle) return true;
    }
    return false;
}

const CapabilityCapture = struct {
    buf: [64][]const u8 = undefined,
    len: usize = 0,

    fn line(self: *CapabilityCapture, kind: []const u8, name: []const u8) void {
        _ = kind;
        self.buf[self.len] = name;
        self.len += 1;
    }
};

test "listCapabilities emits exactly the engine's native capability set" {
    // The runner script builds its whole matrix from this output, so it must
    // enumerate every native value and nothing else. If it under-reports, a
    // supported tuple silently stops being tested; if it over-reports, the
    // script builds rows the tool would then reject at parse time.
    var capture = CapabilityCapture{};
    listCapabilities(&capture, CapabilityCapture.line);

    try std.testing.expectEqual(
        cipher_suites.len + named_groups.len + signature_schemes.len,
        capture.len,
    );

    var index: usize = 0;
    for (cipher_suites) |suite| {
        try std.testing.expectEqualStrings(cipherSuiteName(suite), capture.buf[index]);
        index += 1;
    }
    for (named_groups) |group| {
        try std.testing.expectEqualStrings(namedGroupName(group), capture.buf[index]);
        index += 1;
    }
    for (signature_schemes) |scheme| {
        try std.testing.expectEqualStrings(signatureSchemeName(scheme), capture.buf[index]);
        index += 1;
    }
}

test "every listed capability parses back, so the runner can never build an unusable row" {
    const Roundtrip = struct {
        fn line(_: *u8, kind: []const u8, name: []const u8) void {
            if (std.mem.eql(u8, kind, "cipher-suite")) {
                _ = parseCipherSuite(name) catch unreachable;
            } else if (std.mem.eql(u8, kind, "group")) {
                _ = parseNamedGroup(name) catch unreachable;
            } else if (std.mem.eql(u8, kind, "signature")) {
                _ = parseSignatureScheme(name) catch unreachable;
            } else {
                unreachable; // an unrecognised kind would break the script's parser
            }
        }
    };
    var ignored: u8 = 0;
    listCapabilities(&ignored, Roundtrip.line);
}

const MismatchCapture = struct {
    items: [4]Mismatch = undefined,
    len: usize = 0,

    fn report(self: *MismatchCapture, mismatch: Mismatch) void {
        self.items[self.len] = mismatch;
        self.len += 1;
    }
};

test "validateNegotiated accepts a handshake that landed on the pinned tuple" {
    var config = Config{};
    try config.addCipherSuite("aes256-gcm-sha384");
    try config.addNamedGroup("secp256r1");

    var capture = MismatchCapture{};
    try std.testing.expect(config.validateNegotiated(.{
        .cipher_suite = .tls_aes_256_gcm_sha384,
        .named_group = .secp256r1,
        .alpn = "h2",
    }, "h2", &capture, MismatchCapture.report));
    try std.testing.expectEqual(@as(usize, 0), capture.len);
}

test "validateNegotiated rejects a peer that ignored the pinned tuple" {
    // The point of the check: a peer that quietly negotiates something else
    // must not show green just because *a* handshake completed.
    var config = Config{};
    try config.addCipherSuite("aes256-gcm-sha384");
    try config.addNamedGroup("secp256r1");

    var capture = MismatchCapture{};
    try std.testing.expect(!config.validateNegotiated(.{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .named_group = .x25519,
        .alpn = "http/1.1",
    }, "h2", &capture, MismatchCapture.report));
    try std.testing.expectEqual(@as(usize, 3), capture.len);
    try std.testing.expectEqualStrings("cipher-suite", capture.items[0].dimension);
    try std.testing.expectEqualStrings("aes256-gcm-sha384", capture.items[0].expected);
    try std.testing.expectEqualStrings("aes128-gcm-sha256", capture.items[0].observed);
    try std.testing.expectEqualStrings("group", capture.items[1].dimension);
    try std.testing.expectEqualStrings("alpn", capture.items[2].dimension);
}

test "validateNegotiated leaves unpinned dimensions alone" {
    // A row that offers everything along a dimension is not asserting which
    // value wins, so any native choice must pass.
    var config = Config{};
    var capture = MismatchCapture{};
    try std.testing.expect(config.validateNegotiated(.{
        .cipher_suite = .tls_chacha20_poly1305_sha256,
        .named_group = .x25519,
    }, null, &capture, MismatchCapture.report));
    try std.testing.expectEqual(@as(usize, 0), capture.len);
}

test "validateNegotiated treats a missing negotiated value as a mismatch, not a pass" {
    // A handshake that never completed reports `null` here. Silently accepting
    // that would make every failed row look like it satisfied its tuple.
    var config = Config{};
    try config.addCipherSuite("aes128-gcm-sha256");
    var capture = MismatchCapture{};
    try std.testing.expect(!config.validateNegotiated(.{}, null, &capture, MismatchCapture.report));
    try std.testing.expectEqual(@as(usize, 1), capture.len);
    try std.testing.expectEqualStrings("(none)", capture.items[0].observed);
}

test "an unpinned dimension offers the engine's full native capability list" {
    var config = Config{};
    const record = config.policy(.record, &.{algorithms.alpn.http_1_1});
    try std.testing.expectEqualSlices(CipherSuite, cipher_suites, record.cipher_suites);
    try std.testing.expectEqualSlices(NamedGroup, named_groups, record.named_groups);
    try std.testing.expectEqualSlices(SignatureScheme, signature_schemes, record.signature_schemes);
    try std.testing.expectEqual(@as(usize, 1), record.alpn_protocols.len);
    try std.testing.expect(record.alpn_protocols[0].eql(algorithms.alpn.http_1_1));
}

test "a pinned tuple narrows every dimension to exactly what the row asked for" {
    var config = Config{};
    try config.addCipherSuite("chacha20-poly1305-sha256");
    try config.addNamedGroup("secp256r1");
    try config.addSignatureScheme("rsa-pss-rsae-sha256");
    try config.addAlpn("h2");

    const record = config.policy(.record, &.{algorithms.alpn.http_1_1});
    try std.testing.expectEqualSlices(CipherSuite, &.{.tls_chacha20_poly1305_sha256}, record.cipher_suites);
    try std.testing.expectEqualSlices(NamedGroup, &.{.secp256r1}, record.named_groups);
    try std.testing.expectEqualSlices(SignatureScheme, &.{.rsa_pss_rsae_sha256}, record.signature_schemes);
    try std.testing.expect(record.alpn_protocols[0].eql(algorithms.alpn.h2));
}

test "the same config yields the same tuple on both transports" {
    // The whole point of the shared vocabulary: a matrix row pinned once
    // produces identical negotiation inputs for the record and QUIC
    // transports, so a QUIC-only or record-only discrepancy is a real engine
    // difference rather than two harnesses disagreeing about the row.
    var config = Config{};
    try config.addCipherSuite("aes256-gcm-sha384");
    try config.addNamedGroup("x25519");
    try config.addSignatureScheme("ecdsa-p256-sha256");

    const record = config.policy(.record, &.{algorithms.alpn.h2});
    const quic = config.policy(.quic, &.{algorithms.alpn.h3});

    try std.testing.expectEqualSlices(CipherSuite, record.cipher_suites, quic.cipher_suites);
    try std.testing.expectEqualSlices(NamedGroup, record.named_groups, quic.named_groups);
    try std.testing.expectEqualSlices(SignatureScheme, record.signature_schemes, quic.signature_schemes);
    try std.testing.expectEqual(tls_state.TransportMode.record, record.transport_mode);
    try std.testing.expectEqual(tls_state.TransportMode.quic, quic.transport_mode);
}

test "a dimension cannot be selected beyond the engine's capability count" {
    var selection = Selection(CipherSuite){};
    for (cipher_suites) |suite| try selection.append(suite);
    try std.testing.expectError(error.TooManyValues, selection.append(.tls_aes_128_gcm_sha256));
}

test "each signature scheme names the identity key its row must be issued" {
    try std.testing.expectEqual(tls_policy.IdentityKey.ed25519, identityKeyForSignature(.ed25519));
    try std.testing.expectEqual(tls_policy.IdentityKey.ecdsa_secp256r1, identityKeyForSignature(.ecdsa_secp256r1_sha256));
    try std.testing.expectEqual(tls_policy.IdentityKey.rsa, identityKeyForSignature(.rsa_pss_rsae_sha256));
}

test "require_sni and allow_absent_alpn reach the built policy" {
    var config = Config{};
    config.require_sni = true;
    config.allow_absent_alpn = true;
    const record = config.policy(.record, &.{algorithms.alpn.http_1_1});
    try std.testing.expect(record.require_sni);
    try std.testing.expect(record.allow_absent_alpn);
}

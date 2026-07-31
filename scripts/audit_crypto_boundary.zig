//! Deterministic crypto-boundary audit (#490).
//!
//! A small, dependency-free Zig program — not a shell script shelling out to
//! an ambient `rg` — so the checked-in enforcement runs identically on every
//! CI runner and platform without an extra tool to install. It blocks two
//! things in QUIC protocol modules and the native HTTP/QUIC composition root:
//!
//!   1. New direct keyed-crypto calls (`std.crypto`'s AEAD/KDF/ECDH/signature
//!      APIs and the `crypto.core.aes` block-cipher form QUIC header
//!      protection is built on) outside the approved provider-owned adapter
//!      (`src/quic/tls_adapter.zig`) and its documented exceptions.
//!   2. Calls to the concrete legacy wrapper names `src/quic/tls_adapter.zig`
//!      still carries for differential test vectors — `sealPayload`,
//!      `openPayload`, `applyHeaderProtection`, `removeHeaderProtection`,
//!      `headerProtectionMask`, `deriveAes128GcmKeys`, `deriveInitialSecretsV1`,
//!      `deriveNextGenerationSecret` — from the live runtime modules that were
//!      migrated onto the `*WithProvider` entry points. This is what catches a
//!      revert of that migration even though the names themselves are
//!      "approved" inside `tls_adapter.zig` and test vector files.
//!
//! Not a semantic proof: a deterministic, narrow pattern match that prevents
//! accidental reintroduction and forces any new exception to be reviewed here
//! and in `docs/CRYPTO_PROVIDER_AUDIT.md`.

const std = @import("std");
const compat = @import("zig_compat");

/// A single-file check: `path` must not contain any of `forbidden`.
const FileCheck = struct {
    path: []const u8,
    forbidden: []const []const u8,
    rationale: []const u8,
};

/// A directory-wide check: every `*.zig` file inside `dir`, recursively,
/// except `excluded` (matched by name, at any depth) must not contain any of
/// `forbidden`.
const DirCheck = struct {
    dir: []const u8,
    excluded: []const []const u8,
    forbidden: []const []const u8,
    rationale: []const u8,
};

/// A check scoped to one named function's body rather than a whole file —
/// for files like `src/quic/tls_adapter.zig` that legitimately define the
/// legacy concrete primitives (as differential test-vector fixtures) and so
/// cannot be scanned wholesale, but whose canonical `QuicTlsAdapter` methods
/// must never regress to calling those legacy names internally (#490
/// third-pass review).
const FunctionBodyCheck = struct {
    path: []const u8,
    function_name: []const u8,
    forbidden: []const []const u8,
    rationale: []const u8,
};

// ---------------------------------------------------------------------------
// Forbidden-pattern sets
// ---------------------------------------------------------------------------

/// Concrete keyed AEAD/KDF/ECDH/signature primitives. Protocol modules must
/// reach these only through `crypto.provider.CryptoProvider`
/// (`src/quic/tls_adapter.zig`'s `*WithProvider` entry points).
const keyed_crypto_core = [_][]const u8{
    "std.crypto.aead.",
    "crypto.aead.",
    "std.crypto.auth.",
    "crypto.auth.",
    "std.crypto.dh.",
    "crypto.dh.",
    "std.crypto.sign.",
    "crypto.sign.",
    "std.crypto.kdf.",
    "crypto.kdf.",
    "Aes128Gcm.encrypt(",
    "Aes128Gcm.decrypt(",
    "Aes256Gcm.encrypt(",
    "Aes256Gcm.decrypt(",
    "ChaCha20Poly1305.encrypt(",
    "ChaCha20Poly1305.decrypt(",
    "X25519.",
    "Ed25519.",
    "Ecdsa",
    "Rsa",
    "hkdfExpandLabel(",
};

/// The exact AES block-cipher construction QUIC header protection is built
/// on — distinct from the AEAD entries above, and the specific gap a prior
/// version of this audit missed (#490 second-pass review).
const aes_block_cipher = [_][]const u8{
    "crypto.core.aes.",
    "Aes128.initEnc(",
    "Aes256.initEnc(",
};

/// Concrete legacy wrapper names retired from the live QUIC send/receive path
/// in favor of the `*WithProvider` entry points on the same types. Kept only
/// as differential test-vector fixtures in `src/quic/tls_adapter.zig` and
/// `tests/crypto_vectors.zig` / `tests/crypto_openssl_diff.zig`; a runtime
/// module calling one directly is exactly the regression this audit exists
/// to catch. Each literal ends at the call parenthesis so it does not also
/// match its own `...WithProvider(` sibling.
const legacy_wrapper_calls = [_][]const u8{
    ".sealPayload(",
    ".openPayload(",
    ".applyHeaderProtection(",
    ".removeHeaderProtection(",
    ".headerProtectionMask(",
    "deriveAes128GcmKeys(",
    "deriveInitialSecretsV1(",
    "deriveNextGenerationSecret(",
};

const packet_zig_forbidden = [_][]const u8{
    "std.crypto.auth.",
    "crypto.auth.",
    "std.crypto.dh.",
    "crypto.dh.",
    "std.crypto.sign.",
    "crypto.sign.",
    "std.crypto.kdf.",
    "crypto.kdf.",
    "ChaCha20Poly1305.encrypt(",
    "ChaCha20Poly1305.decrypt(",
    "X25519.",
    "Ed25519.",
    "Ecdsa",
    "Rsa",
    "hkdfExpandLabel(",
} ++ aes_block_cipher ++ legacy_wrapper_calls;

const path_zig_forbidden = [_][]const u8{
    "std.crypto.dh.",
    "crypto.dh.",
    "std.crypto.sign.",
    "crypto.sign.",
    "std.crypto.kdf.",
    "crypto.kdf.",
    "X25519.",
    "Ed25519.",
    "Ecdsa",
    "Rsa",
    "hkdfExpandLabel(",
} ++ aes_block_cipher ++ legacy_wrapper_calls;

const connection_zig_forbidden = keyed_crypto_core ++ aes_block_cipher ++ legacy_wrapper_calls;

/// Same as `keyed_crypto_core` except for KDF: `tls_handshake.zig`'s
/// in-memory `TestTlsBackend` test fixture builds a deterministic transcript
/// hash with `std.crypto.kdf.hkdf.HkdfSha256` directly, since it stands in
/// for a TLS engine rather than driving one. The production `Handshake`/
/// `CoreDriver` code sharing this file has no keyed-crypto dependency at
/// all, so this file is fully scannable for every other category, including
/// the legacy wrapper names (#490 third-pass review: this file must not stay
/// wholesale-excluded from the guard just because a test fixture shares it).
const tls_handshake_zig_forbidden = [_][]const u8{
    "std.crypto.aead.",
    "crypto.aead.",
    "std.crypto.auth.",
    "crypto.auth.",
    "std.crypto.dh.",
    "crypto.dh.",
    "std.crypto.sign.",
    "crypto.sign.",
    "Aes128Gcm.encrypt(",
    "Aes128Gcm.decrypt(",
    "Aes256Gcm.encrypt(",
    "Aes256Gcm.decrypt(",
    "ChaCha20Poly1305.encrypt(",
    "ChaCha20Poly1305.decrypt(",
    "X25519.",
    "Ed25519.",
    "Ecdsa",
    "Rsa",
    "hkdfExpandLabel(",
} ++ aes_block_cipher ++ legacy_wrapper_calls;

/// Canonical `QuicTlsAdapter` methods that must always reach packet
/// protection through the `*WithProvider` entry points. `tls_adapter.zig`
/// itself stays excluded from the whole-file/whole-directory scans above
/// because it legitimately defines the legacy concrete primitives as
/// differential test-vector fixtures (and its own tests call them to compare
/// against the provider path) — a blanket scan of the file cannot tell that
/// apart from a live call site regressing. This targets exactly the
/// regression the third-pass review named: reverting `sealPacketPayload`
/// back to `keys.sealPayload(...)`, or `protectionKeys` back to
/// `deriveAes128GcmKeys(...)`.
const function_body_checks = [_]FunctionBodyCheck{
    .{ .path = "src/quic/tls_adapter.zig", .function_name = "protectionKeys", .forbidden = &legacy_wrapper_calls, .rationale = "QuicTlsAdapter.protectionKeys must derive packet-protection keys through deriveAes128GcmKeysWithProvider, not the legacy deriveAes128GcmKeys." },
    .{ .path = "src/quic/tls_adapter.zig", .function_name = "sealPacketPayload", .forbidden = &legacy_wrapper_calls, .rationale = "QuicTlsAdapter.sealPacketPayload must seal through sealPayloadWithProvider, not the legacy sealPayload." },
    .{ .path = "src/quic/tls_adapter.zig", .function_name = "openPacketPayload", .forbidden = &legacy_wrapper_calls, .rationale = "QuicTlsAdapter.openPacketPayload must open through openPayloadWithProvider, not the legacy openPayload." },
    .{ .path = "src/quic/tls_adapter.zig", .function_name = "updateApplicationWriteKeys", .forbidden = &legacy_wrapper_calls, .rationale = "QuicTlsAdapter.updateApplicationWriteKeys must derive the next secret through deriveNextGenerationSecretWithProvider, not the legacy deriveNextGenerationSecret." },
    .{ .path = "src/quic/tls_adapter.zig", .function_name = "nextApplicationReadKeys", .forbidden = &legacy_wrapper_calls, .rationale = "QuicTlsAdapter.nextApplicationReadKeys must derive keys through the *WithProvider entry points, not the legacy free functions." },
    .{ .path = "src/quic/tls_adapter.zig", .function_name = "commitApplicationReadKeyUpdate", .forbidden = &legacy_wrapper_calls, .rationale = "QuicTlsAdapter.commitApplicationReadKeyUpdate must derive the next secret through deriveNextGenerationSecretWithProvider, not the legacy deriveNextGenerationSecret." },
};

/// `src/quic/cid.zig` keeps one documented exception: RFC 9000 §10.3.1
/// stateless-reset-token derivation is HMAC-SHA256 under a static
/// process-lifetime key, not TLS/QUIC-negotiated packet protection — the
/// same shape as `path.zig`'s existing Retry/token exception. Everything
/// else keyed_crypto_core forbids elsewhere stays forbidden here too.
const cid_zig_forbidden = [_][]const u8{
    "std.crypto.aead.",
    "crypto.aead.",
    "std.crypto.dh.",
    "crypto.dh.",
    "std.crypto.sign.",
    "crypto.sign.",
    "std.crypto.kdf.",
    "crypto.kdf.",
    "Aes128Gcm.encrypt(",
    "Aes128Gcm.decrypt(",
    "Aes256Gcm.encrypt(",
    "Aes256Gcm.decrypt(",
    "ChaCha20Poly1305.encrypt(",
    "ChaCha20Poly1305.decrypt(",
    "X25519.",
    "Ed25519.",
    "Ecdsa",
    "Rsa",
    "hkdfExpandLabel(",
} ++ aes_block_cipher ++ legacy_wrapper_calls;

const file_checks = [_]FileCheck{
    .{
        .path = "src/quic/connection.zig",
        .forbidden = &connection_zig_forbidden,
        .rationale = "QUIC connection logic owns framing, packet numbers, and nonce arithmetic only; keyed crypto belongs to src/quic/tls_adapter.zig through CryptoProvider, and every call site there already migrated onto the *WithProvider entry points.",
    },
    .{
        .path = "src/quic/packet.zig",
        // No AEAD/AES-block entries here: the existing AES-GCM Retry
        // integrity test vector is allowed because RFC 9001 fixes the
        // public key/nonce and it is not packet-protection key material.
        .forbidden = &packet_zig_forbidden,
        .rationale = "QUIC packet parsing/encoding is public protocol logic; keyed crypto and AES header protection belong to src/quic/tls_adapter.zig through CryptoProvider.",
    },
    .{
        .path = "src/quic/path.zig",
        // QUIC path validation keeps its existing address-validation
        // token/Retry-integrity exception (public constants, process keys);
        // see docs/CRYPTO_PROVIDER_AUDIT.md. No key exchange, signatures, KDF,
        // or new AES block-cipher shortcuts may be added here.
        .forbidden = &path_zig_forbidden,
        .rationale = "QUIC path validation may use public constants and the existing token/retry exception, but must not add key exchange, signatures, KDF, or AES block-cipher shortcuts.",
    },
    .{
        .path = "src/http/http3_runtime.zig",
        .forbidden = &legacy_wrapper_calls,
        .rationale = "The native HTTP/QUIC composition root sends/receives QUIC packets through Connection/QuicTlsAdapter only; it must not call the concrete legacy wrapper names directly.",
    },
    .{
        .path = "src/quic/cid.zig",
        .forbidden = &cid_zig_forbidden,
        .rationale = "Connection-ID/stateless-reset-token derivation (RFC 9000 §10.3.1) is a documented HMAC-SHA256 exception under a static process-lifetime key (docs/CRYPTO_PROVIDER_AUDIT.md), not TLS/QUIC-negotiated packet protection; no AEAD, ECDH, signature, KDF, or AES header-protection shortcuts may be added here.",
    },
    .{
        .path = "src/quic/tls_handshake.zig",
        .forbidden = &tls_handshake_zig_forbidden,
        .rationale = "The backend-agnostic handshake driver must not add keyed crypto of its own; TestTlsBackend's deterministic transcript HKDF (std.crypto.kdf) is the one documented exception (see the forbidden-list comment), everything else stays forbidden including the legacy wrapper names.",
    },
};

const quic_dir_forbidden = keyed_crypto_core ++ aes_block_cipher;

const dir_checks = [_]DirCheck{
    .{
        .dir = "src/quic",
        // tls_adapter.zig is the approved provider-owned adapter and the
        // one file allowed to define the legacy wrapper names as
        // differential fixtures, so it cannot be scanned wholesale for
        // either keyed-crypto primitives or the legacy names themselves —
        // `function_body_checks` above targets its canonical methods
        // specifically instead. path.zig, connection.zig, packet.zig,
        // cid.zig, and tls_handshake.zig have their own narrower checks in
        // `file_checks` above. Recursive: a new nested directory under
        // src/quic gets no free pass.
        .excluded = &.{ "tls_adapter.zig", "path.zig", "connection.zig", "packet.zig", "cid.zig", "tls_handshake.zig" },
        .forbidden = &quic_dir_forbidden,
        .rationale = "QUIC protocol modules outside the allowlist must not add direct keyed crypto or AES block-cipher dependencies.",
    },
};

// ---------------------------------------------------------------------------
// Scanning
// ---------------------------------------------------------------------------

/// First forbidden needle found in `contents`, or null. Pure and
/// allocation-free so it is directly testable against in-memory fixtures.
fn firstForbidden(contents: []const u8, forbidden: []const []const u8) ?[]const u8 {
    for (forbidden) |needle| {
        if (std.mem.indexOf(u8, contents, needle) != null) return needle;
    }
    return null;
}

const Violation = struct {
    path: []const u8,
    needle: []const u8,
    rationale: []const u8,
};

/// `required`: whether a missing file is itself a violation. `file_checks`
/// entries name specific protected files the audit exists to enforce, so a
/// renamed or deleted one must fail closed rather than silently pass with
/// zero violations (#490 third-pass review) — unlike `checkDir`'s per-entry
/// calls, where the file is already known to exist from directory iteration.
fn checkFile(allocator: std.mem.Allocator, root: compat.DirCompat, path: []const u8, forbidden: []const []const u8, rationale: []const u8, required: bool, violations: *std.ArrayList(Violation)) !void {
    const contents = root.readFileAlloc(allocator, path, 16 * 1024 * 1024) catch |err| switch (err) {
        error.FileNotFound => {
            if (required) {
                try violations.append(allocator, .{
                    .path = try allocator.dupe(u8, path),
                    .needle = "<file missing>",
                    .rationale = rationale,
                });
            }
            return;
        },
        else => return err,
    };
    defer allocator.free(contents);
    if (firstForbidden(contents, forbidden)) |needle| {
        try violations.append(allocator, .{ .path = try allocator.dupe(u8, path), .needle = needle, .rationale = rationale });
    }
}

/// Extracts one struct method's source span: from `fn <function_name>(` to
/// (but not including) the next sibling `pub fn `/`fn ` declaration at the
/// same 4-space struct-method indentation, or end of file. Narrow and
/// deterministic like the rest of this audit rather than a general Zig
/// parser — a real parser would have to distinguish the function body's
/// opening brace from inline return-type groups like `error{Foo}`, which
/// every target function here has.
fn extractFunctionBody(contents: []const u8, function_name: []const u8) ?[]const u8 {
    var search_from: usize = 0;
    while (true) {
        const rel = std.mem.indexOfPos(u8, contents, search_from, function_name) orelse return null;
        const before_ok = rel >= 3 and std.mem.eql(u8, contents[rel - 3 .. rel], "fn ");
        const after_name = rel + function_name.len;
        const after_ok = after_name < contents.len and contents[after_name] == '(';
        if (before_ok and after_ok) {
            var end = contents.len;
            if (std.mem.indexOfPos(u8, contents, after_name, "\n    pub fn ")) |p| end = @min(end, p);
            if (std.mem.indexOfPos(u8, contents, after_name, "\n    fn ")) |p| end = @min(end, p);
            return contents[rel..end];
        }
        search_from = rel + 1;
    }
}

fn checkFunctionBody(allocator: std.mem.Allocator, root: compat.DirCompat, check: FunctionBodyCheck, violations: *std.ArrayList(Violation)) !void {
    const contents = root.readFileAlloc(allocator, check.path, 16 * 1024 * 1024) catch |err| switch (err) {
        error.FileNotFound => {
            try violations.append(allocator, .{
                .path = try allocator.dupe(u8, check.path),
                .needle = "<file missing>",
                .rationale = check.rationale,
            });
            return;
        },
        else => return err,
    };
    defer allocator.free(contents);
    const body = extractFunctionBody(contents, check.function_name) orelse {
        try violations.append(allocator, .{
            .path = try allocator.dupe(u8, check.path),
            .needle = "<function not found>",
            .rationale = check.rationale,
        });
        return;
    };
    if (firstForbidden(body, check.forbidden)) |needle| {
        try violations.append(allocator, .{ .path = try allocator.dupe(u8, check.path), .needle = needle, .rationale = check.rationale });
    }
}

fn checkDir(allocator: std.mem.Allocator, root: compat.DirCompat, check: DirCheck, dir_path: []const u8, violations: *std.ArrayList(Violation)) !void {
    var dir = root.openDir(dir_path, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => {
            try violations.append(allocator, .{
                .path = try allocator.dupe(u8, dir_path),
                .needle = "<directory missing>",
                .rationale = check.rationale,
            });
            return;
        },
        else => return err,
    };
    defer dir.close();
    var it = dir.iterate();
    while (try it.next(compat.io())) |entry| {
        var excluded = false;
        for (check.excluded) |name| {
            if (std.mem.eql(u8, entry.name, name)) {
                excluded = true;
                break;
            }
        }
        if (excluded) continue;
        const rel = try std.fs.path.join(allocator, &.{ dir_path, entry.name });
        defer allocator.free(rel);
        switch (entry.kind) {
            .directory => try checkDir(allocator, root, check, rel, violations),
            .file => {
                if (!std.mem.endsWith(u8, entry.name, ".zig")) continue;
                try checkFile(allocator, root, rel, check.forbidden, check.rationale, false, violations);
            },
            else => {},
        }
    }
}

fn runAudit(allocator: std.mem.Allocator, root: compat.DirCompat) !std.ArrayList(Violation) {
    var violations: std.ArrayList(Violation) = .empty;
    errdefer violations.deinit(allocator);
    for (file_checks) |check| {
        try checkFile(allocator, root, check.path, check.forbidden, check.rationale, true, &violations);
    }
    for (function_body_checks) |check| {
        try checkFunctionBody(allocator, root, check, &violations);
    }
    for (dir_checks) |check| {
        try checkDir(allocator, root, check, check.dir, &violations);
    }
    return violations;
}

pub fn main(init: std.process.Init.Minimal) !void {
    const allocator = std.heap.page_allocator;

    var args_iter = init.args.iterate();
    _ = args_iter.next();
    const root_path = args_iter.next() orelse ".";

    var root = compat.cwd().openDir(root_path, .{}) catch |err| {
        var stderr_buf: [512]u8 = undefined;
        var stderr = compat.stderrWriter(&stderr_buf);
        try stderr.print("audit-crypto-boundary: cannot open root '{s}': {s}\n", .{ root_path, @errorName(err) });
        std.process.exit(2);
    };
    defer root.close();

    var violations = try runAudit(allocator, root);
    defer violations.deinit(allocator);

    if (violations.items.len == 0) return;

    var stderr_buf: [512]u8 = undefined;
    var stderr = compat.stderrWriter(&stderr_buf);
    for (violations.items) |v| {
        try stderr.print("disallowed pattern in {s}: \"{s}\"\nrationale: {s}\n\n", .{ v.path, v.needle, v.rationale });
    }
    std.process.exit(1);
}

// ---------------------------------------------------------------------------
// Fixture tests: each class of bypass this audit exists to catch must
// actually make it fail (#490 second-pass review).
// ---------------------------------------------------------------------------

const testing = std.testing;

test "detects a direct AEAD call" {
    try testing.expectEqualStrings("std.crypto.aead.", firstForbidden("const x = std.crypto.aead.aes_gcm.Aes128Gcm;", &keyed_crypto_core).?);
}

test "detects a direct HKDF expand-label call" {
    try testing.expectEqualStrings("hkdfExpandLabel(", firstForbidden("const k = tls.hkdfExpandLabel(Hkdf, secret, \"x\", \"\", 32);", &keyed_crypto_core).?);
}

test "detects a direct ECDH/signature primitive" {
    try testing.expectEqualStrings("X25519.", firstForbidden("var kp = X25519.KeyPair.generateDeterministic(seed);", &keyed_crypto_core).?);
    try testing.expectEqualStrings("Ed25519.", firstForbidden("Ed25519.verify(sig, msg, key) catch return error.Bad;", &keyed_crypto_core).?);
}

test "detects the exact AES header-protection block-cipher form" {
    try testing.expectEqualStrings("Aes128.initEnc(", firstForbidden("const aes = Aes128.initEnc(self.hp);", &aes_block_cipher).?);
    try testing.expectEqualStrings("crypto.core.aes.", firstForbidden("const Aes128 = crypto.core.aes.Aes128;", &aes_block_cipher).?);
}

test "detects each legacy wrapper call name without matching its WithProvider sibling" {
    try testing.expectEqualStrings(".sealPayload(", firstForbidden("const sealed = keys.sealPayload(pn, header, plain, out);", &legacy_wrapper_calls).?);
    try testing.expectEqualStrings(".openPayload(", firstForbidden("const p = keys.openPayload(pn, header, ct, out);", &legacy_wrapper_calls).?);
    try testing.expectEqualStrings(".applyHeaderProtection(", firstForbidden("keys.applyHeaderProtection(&out[0], pn_field, sample);", &legacy_wrapper_calls).?);
    try testing.expectEqualStrings(".removeHeaderProtection(", firstForbidden("const r = keys.removeHeaderProtection(&b, &pn, sample);", &legacy_wrapper_calls).?);
    try testing.expectEqualStrings(".headerProtectionMask(", firstForbidden("const m = keys.headerProtectionMask(sample);", &legacy_wrapper_calls).?);
    try testing.expectEqualStrings("deriveAes128GcmKeys(", firstForbidden("return deriveAes128GcmKeys(secret);", &legacy_wrapper_calls).?);
    try testing.expectEqualStrings("deriveInitialSecretsV1(", firstForbidden("const s = try deriveInitialSecretsV1(dcid);", &legacy_wrapper_calls).?);
    try testing.expectEqualStrings("deriveNextGenerationSecret(", firstForbidden("return deriveNextGenerationSecret(secret);", &legacy_wrapper_calls).?);

    // The WithProvider siblings must NOT trip the same check — that would
    // make the audit reject the migration this PR performed.
    try testing.expectEqual(@as(?[]const u8, null), firstForbidden("const sealed = keys.sealPayloadWithProvider(cp, pn, header, plain, out);", &legacy_wrapper_calls));
    try testing.expectEqual(@as(?[]const u8, null), firstForbidden("keys.applyHeaderProtectionWithProvider(cp, &out[0], pn_field, sample);", &legacy_wrapper_calls));
    try testing.expectEqual(@as(?[]const u8, null), firstForbidden("return deriveAes128GcmKeysWithProvider(cp, secret);", &legacy_wrapper_calls));
}

test "clean protocol-module content produces no violation" {
    try testing.expectEqual(@as(?[]const u8, null), firstForbidden(
        "keys.applyHeaderProtectionWithProvider(self.adapter.provider, &out[0], pn_field, sample) catch unreachable;",
        &connection_zig_forbidden,
    ));
}

/// Minimal but realistic stand-in for `src/quic/tls_adapter.zig`'s six
/// canonical `QuicTlsAdapter` methods, reproducing the exact shape that
/// makes `extractFunctionBody` non-trivial (an inline `error{...}` group in
/// the return type before the real body opens) so the fixture tree actually
/// exercises the same parsing path as the real file.
const clean_tls_adapter_fixture =
    \\pub const QuicTlsAdapter = struct {
    \\    pub fn protectionKeys(self: *const QuicTlsAdapter, level: EncryptionLevel, direction: Direction) error{ProviderUnsupported}!?PacketProtectionKeys {
    \\        return deriveAes128GcmKeysWithProvider(self.provider, secret);
    \\    }
    \\    pub fn sealPacketPayload(self: *QuicTlsAdapter, level: EncryptionLevel) error{ProviderUnsupported}![]u8 {
    \\        return keys.sealPayloadWithProvider(self.provider, packet_number, header, plaintext, out);
    \\    }
    \\    pub fn openPacketPayload(self: *QuicTlsAdapter, level: EncryptionLevel) error{ProviderUnsupported}![]u8 {
    \\        return keys.openPayloadWithProvider(self.provider, packet_number, header, protected_payload, out);
    \\    }
    \\    pub fn updateApplicationWriteKeys(self: *QuicTlsAdapter) error{ProviderUnsupported}!void {
    \\        const next_write = try deriveNextGenerationSecretWithProvider(self.provider, write_secret);
    \\    }
    \\    pub fn nextApplicationReadKeys(self: *const QuicTlsAdapter) error{ProviderUnsupported}!?PacketProtectionKeys {
    \\        return try deriveAes128GcmKeysWithProvider(self.provider, next_read);
    \\    }
    \\    pub fn commitApplicationReadKeyUpdate(self: *QuicTlsAdapter) error{ProviderUnsupported}!void {
    \\        const next_read = try deriveNextGenerationSecretWithProvider(self.provider, read_secret);
    \\    }
    \\};
    \\
;

/// `clean_tls_adapter_fixture` with `sealPacketPayload` reverted to the
/// legacy `keys.sealPayload(...)` call — the exact regression #490's
/// third-pass review named.
const regressed_tls_adapter_fixture =
    \\pub const QuicTlsAdapter = struct {
    \\    pub fn protectionKeys(self: *const QuicTlsAdapter, level: EncryptionLevel, direction: Direction) error{ProviderUnsupported}!?PacketProtectionKeys {
    \\        return deriveAes128GcmKeysWithProvider(self.provider, secret);
    \\    }
    \\    pub fn sealPacketPayload(self: *QuicTlsAdapter, level: EncryptionLevel) error{ProviderUnsupported}![]u8 {
    \\        return keys.sealPayload(packet_number, header, plaintext, out);
    \\    }
    \\    pub fn openPacketPayload(self: *QuicTlsAdapter, level: EncryptionLevel) error{ProviderUnsupported}![]u8 {
    \\        return keys.openPayloadWithProvider(self.provider, packet_number, header, protected_payload, out);
    \\    }
    \\    pub fn updateApplicationWriteKeys(self: *QuicTlsAdapter) error{ProviderUnsupported}!void {
    \\        const next_write = try deriveNextGenerationSecretWithProvider(self.provider, write_secret);
    \\    }
    \\    pub fn nextApplicationReadKeys(self: *const QuicTlsAdapter) error{ProviderUnsupported}!?PacketProtectionKeys {
    \\        return try deriveAes128GcmKeysWithProvider(self.provider, next_read);
    \\    }
    \\    pub fn commitApplicationReadKeyUpdate(self: *QuicTlsAdapter) error{ProviderUnsupported}!void {
    \\        const next_read = try deriveNextGenerationSecretWithProvider(self.provider, read_secret);
    \\    }
    \\};
    \\
;

test "end-to-end: the audit fails against a fixture tree reproducing each bypass, and passes once fixed" {
    const allocator = testing.allocator;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = compat.wrapDir(tmp.dir);

    try root.makePath("src/quic/nested");
    try root.makePath("src/http");

    // The protected files/functions the fixture tree must carry so the
    // "clean" baseline below is actually clean, not just missing every
    // fail-closed target.
    try root.writeFile(.{ .sub_path = "src/quic/tls_adapter.zig", .data = clean_tls_adapter_fixture });
    try root.writeFile(.{ .sub_path = "src/quic/cid.zig", .data = "" });
    try root.writeFile(.{ .sub_path = "src/quic/tls_handshake.zig", .data = "" });

    const bypass_cases = [_]struct { rel: []const u8, contents: []const u8 }{
        .{ .rel = "src/quic/connection.zig", .contents = "const mask = Aes128.initEnc(self.hp);\n" },
        .{ .rel = "src/quic/packet.zig", .contents = "const shared = X25519.scalarmult(a, b) catch unreachable;\n" },
        .{ .rel = "src/quic/path.zig", .contents = "Ed25519.verify(sig, msg, key) catch return error.Bad;\n" },
        .{ .rel = "src/http/http3_runtime.zig", .contents = "keys.applyHeaderProtection(&out[0], pn_field, sample);\n" },
        .{ .rel = "src/quic/frame.zig", .contents = "const tag = std.crypto.aead.aes_gcm.Aes128Gcm.encrypt(...);\n" },
        // A nested subdirectory under src/quic gets no free pass from the
        // (now recursive) directory-wide scan.
        .{ .rel = "src/quic/nested/packet_crypto.zig", .contents = "const tag = std.crypto.aead.aes_gcm.Aes128Gcm.encrypt(...);\n" },
        // tls_handshake.zig is fully scannable now; a legacy wrapper call
        // there must fail too.
        .{ .rel = "src/quic/tls_handshake.zig", .contents = "keys.sealPayload(pn, header, plain, out);\n" },
        // The exact regression the function-body checks exist to catch:
        // a canonical method reverting to a legacy wrapper call internally.
        .{ .rel = "src/quic/tls_adapter.zig", .contents = regressed_tls_adapter_fixture },
    };

    for (bypass_cases) |case| {
        try root.writeFile(.{ .sub_path = case.rel, .data = case.contents });
        var violations = try runAudit(allocator, root);
        defer violations.deinit(allocator);
        for (violations.items) |v| allocator.free(v.path);
        try testing.expect(violations.items.len > 0);
        // Clean up before the next case so violations don't accumulate
        // across cases sharing a file path.
        const clean = if (std.mem.eql(u8, case.rel, "src/quic/tls_adapter.zig"))
            clean_tls_adapter_fixture
        else
            "";
        try root.writeFile(.{ .sub_path = case.rel, .data = clean });
    }
    try root.deleteFile("src/quic/nested/packet_crypto.zig");

    var clean_violations = try runAudit(allocator, root);
    defer clean_violations.deinit(allocator);
    for (clean_violations.items) |v| allocator.free(v.path);
    try testing.expectEqual(@as(usize, 0), clean_violations.items.len);

    // Fail-closed: deleting a protected file must itself be a violation,
    // not a silent pass.
    try root.deleteFile("src/quic/cid.zig");
    var missing_file_violations = try runAudit(allocator, root);
    defer missing_file_violations.deinit(allocator);
    defer for (missing_file_violations.items) |v| allocator.free(v.path);
    try testing.expect(missing_file_violations.items.len > 0);
    try root.writeFile(.{ .sub_path = "src/quic/cid.zig", .data = "" });
}

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
//! Every approved exception is narrow: a named function/method body or an
//! exact top-level declaration, blanked out of a file's content before that
//! file is otherwise scanned in full (#490 fourth-pass review) — not a
//! category omitted from a file's forbidden list wholesale, which would also
//! silently allow that category anywhere else new in the same file.
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

/// A single-file check with narrow, named exceptions blanked out before
/// scanning the rest of the file in full against `forbidden` — instead of
/// omitting a whole pattern category from `forbidden` (which would also
/// allow that category anywhere else new in the file, not just the one
/// approved call site; #490 fourth-pass review).
const FileCheckWithExceptions = struct {
    path: []const u8,
    forbidden: []const []const u8,
    /// Named function/method bodies pre-approved for direct keyed-crypto
    /// content (extracted the same way as `FunctionBodyCheck` below).
    exempt_functions: []const []const u8 = &.{},
    /// Exact top-level snippets outside any function (e.g. a type-alias
    /// declaration) pre-approved the same way.
    exempt_exact: []const []const u8 = &.{},
    /// When set, only the file content *before* the first occurrence of this
    /// marker is scanned — for a file whose production code precedes a large
    /// test-only region that legitimately exercises every exempted primitive
    /// directly (differential vectors, KATs). If the marker is not found,
    /// the whole file is scanned instead of silently exempting everything.
    production_only_marker: ?[]const u8 = null,
    rationale: []const u8,
};

/// A directory-wide check: every `*.zig` file inside `dir`, recursively,
/// except `excluded_paths` (matched as exact root-relative paths, at any
/// depth) must not contain any of `forbidden`.
const DirCheck = struct {
    dir: []const u8,
    excluded_paths: []const []const u8,
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

const full_forbidden = keyed_crypto_core ++ aes_block_cipher ++ legacy_wrapper_calls;

/// Same as `keyed_crypto_core` except `hkdfExpandLabel(` is qualified with
/// the `tls.` prefix the legacy free function uses in `tls_adapter.zig`,
/// rather than matching bare. The provider-backed `*WithProvider`
/// implementations in that file legitimately call the vtable method
/// `provider.hkdfExpandLabel(...)`, which also contains the bare substring
/// `hkdfExpandLabel(` — this variant is the only way to forbid the legacy
/// free function without also flagging its own approved provider siblings
/// (#490 fourth-pass review).
const tls_adapter_zig_forbidden = [_][]const u8{
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
    "tls.hkdfExpandLabel(",
} ++ aes_block_cipher ++ legacy_wrapper_calls;

const file_checks = [_]FileCheck{
    .{
        .path = "src/quic/connection.zig",
        .forbidden = &full_forbidden,
        .rationale = "QUIC connection logic owns framing, packet numbers, and nonce arithmetic only; keyed crypto belongs to src/quic/tls_adapter.zig through CryptoProvider, and every call site there already migrated onto the *WithProvider entry points.",
    },
    .{
        .path = "src/http/http3_runtime.zig",
        .forbidden = &full_forbidden,
        .rationale = "The native HTTP/QUIC composition root selects/constructs a CryptoProvider and injects it into Connection/QuicTlsAdapter, but must not perform packet crypto itself: no direct concrete AEAD/KDF/ECDH/signature primitive, AES block-cipher form, or legacy tls_adapter wrapper call.",
    },
};

/// Whole-file scans with narrow, named exceptions (#490 fourth-pass review):
/// each of these files has real, approved direct-crypto call sites, but
/// omitting a whole pattern category from the file's forbidden list (the
/// prior approach) would also silently allow that category anywhere else new
/// in the file. Every exception here is instead one exact named function
/// body or top-level declaration, so a *second*, unrelated direct-crypto
/// call anywhere else in the same file still fails.
const file_checks_with_exceptions = [_]FileCheckWithExceptions{
    .{
        .path = "src/quic/packet.zig",
        .forbidden = &full_forbidden,
        // RFC 9001 fixes the Retry integrity key/nonce as public constants;
        // this is not TLS/QUIC-negotiated packet-protection key material.
        .exempt_functions = &.{"computeRetryIntegrityTag"},
        .rationale = "QUIC packet parsing/encoding is public protocol logic; keyed crypto and AES header protection belong to src/quic/tls_adapter.zig through CryptoProvider. computeRetryIntegrityTag is the one documented RFC 9001 Retry-integrity exception (public key/nonce, not packet-protection key material).",
    },
    .{
        .path = "src/quic/path.zig",
        .forbidden = &full_forbidden,
        .exempt_exact = &.{"const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;"},
        // Address-validation token issuance/validation and the Retry
        // integrity tag use AES-GCM with process keys or RFC-fixed public
        // constants; sealTokenPlaintextForTest is the one test-only helper
        // building a token payload the same way for fuzz coverage.
        .exempt_functions = &.{ "issueRetry", "validateRetry", "retryIntegrityTag", "sealTokenPlaintextForTest" },
        .rationale = "QUIC path validation may use public constants and the existing token/Retry-integrity exception, but must not add key exchange, signatures, KDF, or AES block-cipher shortcuts anywhere else in this file.",
    },
    .{
        .path = "src/quic/cid.zig",
        .forbidden = &full_forbidden,
        .exempt_exact = &.{"const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;"},
        .rationale = "Connection-ID/stateless-reset-token derivation (RFC 9000 §10.3.1) is a documented HMAC-SHA256 exception under a static process-lifetime key (docs/CRYPTO_PROVIDER_AUDIT.md), not TLS/QUIC-negotiated packet protection; no AEAD, ECDH, signature, KDF, or AES header-protection shortcuts may be added here.",
    },
    .{
        .path = "src/quic/tls_handshake.zig",
        .forbidden = &full_forbidden,
        .exempt_exact = &.{"const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;"},
        .rationale = "The backend-agnostic handshake driver must not add keyed crypto of its own. TestTlsBackend's deterministic transcript HKDF (one type alias) is the one documented exception; everything else, including the legacy wrapper names, stays forbidden throughout the file.",
    },
    .{
        .path = "src/quic/tls_adapter.zig",
        .forbidden = &tls_adapter_zig_forbidden,
        // The three concrete-primitive type aliases the legacy differential
        // fixtures below are built on.
        .exempt_exact = &.{
            "const HkdfSha256 = crypto.kdf.hkdf.HkdfSha256;",
            "const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;",
            "const Aes128 = crypto.core.aes.Aes128;",
        },
        // The eight legacy concrete functions/methods kept only as
        // differential test-vector fixtures compared against the provider
        // path — approved by name here, nowhere else. Every canonical
        // QuicTlsAdapter method (protectionKeys, sealPacketPayload, ...) and
        // every *WithProvider entry point is therefore scanned like any
        // other production code: this is what catches both a canonical
        // method reverting to a legacy call (#490 third-pass review) *and*
        // a *WithProvider implementation silently delegating to its own
        // concrete sibling (#490 fourth-pass review), without having to
        // name either set of functions explicitly.
        .exempt_functions = &.{
            "sealPayload",
            "openPayload",
            "headerProtectionMask",
            "applyHeaderProtection",
            "removeHeaderProtection",
            "deriveInitialSecretsV1",
            "deriveAes128GcmKeys",
            "deriveNextGenerationSecret",
        },
        // Everything from this marker to end of file is the differential
        // test-vector suite, which legitimately calls every exempted
        // primitive/legacy function directly to compare against the
        // provider path.
        .production_only_marker = "\nconst testing = std.testing;",
        .rationale = "QuicTlsAdapter owns provider-backed QUIC packet protection; every canonical method and every *WithProvider entry point must reach CryptoProvider only, never a concrete primitive or its own legacy differential-fixture sibling.",
    },
};

const quic_dir_forbidden = keyed_crypto_core ++ aes_block_cipher;

const dir_checks = [_]DirCheck{
    .{
        .dir = "src/quic",
        // Every file with its own narrower check above is excluded by its
        // exact root-relative path (not by basename — a nested directory
        // reusing one of these names, e.g. src/quic/nested/connection.zig,
        // gets no free pass; #490 fourth-pass review). Recursive: a new
        // nested directory under src/quic gets no free pass either.
        .excluded_paths = &.{
            "src/quic/tls_adapter.zig",
            "src/quic/path.zig",
            "src/quic/connection.zig",
            "src/quic/packet.zig",
            "src/quic/cid.zig",
            "src/quic/tls_handshake.zig",
        },
        .forbidden = &quic_dir_forbidden,
        .rationale = "QUIC protocol modules outside the allowlist must not add direct keyed crypto or AES block-cipher dependencies.",
    },
};

/// `test_quic_crypto` (`tests/support/quic_crypto.zig`) owns concrete
/// pure-Zig provider construction for tests/tools that exercise the QUIC
/// seam directly; no production (non-test) code path may reference it, only
/// `test` blocks and the test-only structs/fixtures that share a file with
/// them (#490 fourth-pass review). Enforced the same way as
/// `production_only_marker` above: only usages *before* the file's test
/// boundary are violations.
const TestOnlyImportCheck = struct {
    path: []const u8,
    boundary_marker: []const u8,
    rationale: []const u8,
};

const test_quic_crypto_import_checks = [_]TestOnlyImportCheck{
    .{ .path = "src/quic/tls_adapter.zig", .boundary_marker = "\nconst testing = std.testing;", .rationale = "test_quic_crypto is a test-only provider; production QuicTlsAdapter code must be injected a provider by its caller, never construct one." },
    .{ .path = "src/quic/connection.zig", .boundary_marker = "\nconst testing = std.testing;", .rationale = "test_quic_crypto is a test-only provider; production Connection code must be injected a provider by its caller, never construct one." },
    .{ .path = "src/quic/tls_handshake.zig", .boundary_marker = "\nconst testing = std.testing;", .rationale = "test_quic_crypto is a test-only provider; the production Handshake/CoreDriver must be injected a provider by its caller, never construct one." },
    // tls_backend.zig has no single `const testing = std.testing;` marker
    // (it calls std.testing.* fully qualified throughout); its first test
    // block is the boundary instead.
    .{ .path = "src/quic/tls_backend.zig", .boundary_marker = "\ntest \"", .rationale = "test_quic_crypto is a test-only provider; production QUIC-profile code must be injected a provider by its caller, never construct one." },
    .{ .path = "src/http/http3_runtime.zig", .boundary_marker = "\nconst testing = std.testing;", .rationale = "test_quic_crypto is a test-only provider; the production Runtime composition root builds its own provider from real OS entropy (production_crypto.OsEntropy) instead." },
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

/// `required`: whether a missing file is itself a violation. `file_checks`/
/// `file_checks_with_exceptions` entries name specific protected files the
/// audit exists to enforce, so a renamed or deleted one must fail closed
/// rather than silently pass with zero violations (#490 third-pass review) —
/// unlike `checkDir`'s per-entry calls, where the file is already known to
/// exist from directory iteration.
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

/// Extracts one function/method's source span: from `fn <function_name>(` to
/// (but not including) the next sibling top-level declaration — a
/// `pub fn `/`fn ` at either 4-space struct-method indentation or 0-space
/// top-level indentation, or a 0-space `pub const `/`const ` (for a function
/// immediately followed by a container declaration, e.g. the struct the
/// function's own methods belong to) — or end of file. Narrow and
/// deterministic like the rest of this audit rather than a general Zig
/// parser — a real parser would have to distinguish the function body's
/// opening brace from inline return-type groups like `error{Foo}`, which
/// several target functions here have.
fn extractFunctionBody(contents: []const u8, function_name: []const u8) ?[]const u8 {
    var search_from: usize = 0;
    while (true) {
        const rel = std.mem.indexOfPos(u8, contents, search_from, function_name) orelse return null;
        const before_ok = rel >= 3 and std.mem.eql(u8, contents[rel - 3 .. rel], "fn ");
        const after_name = rel + function_name.len;
        const after_ok = after_name < contents.len and contents[after_name] == '(';
        if (before_ok and after_ok) {
            var end = contents.len;
            const boundaries = [_][]const u8{
                "\n    pub fn ", "\n    fn ",
                "\npub fn ",     "\nfn ",
                "\npub const ",  "\nconst ",
            };
            for (boundaries) |boundary| {
                if (std.mem.indexOfPos(u8, contents, after_name, boundary)) |p| end = @min(end, p);
            }
            return contents[rel..end];
        }
        search_from = rel + 1;
    }
}

/// Redacts every occurrence of `needle` in `buf` in place (same length, so
/// no other span shifts), for a mutable scratch copy only.
fn blank(buf: []u8, needle: []const u8) void {
    var search_from: usize = 0;
    while (std.mem.indexOfPos(u8, buf, search_from, needle)) |idx| {
        @memset(buf[idx .. idx + needle.len], ' ');
        search_from = idx + needle.len;
    }
}

fn checkFileWithExceptions(allocator: std.mem.Allocator, root: compat.DirCompat, check: FileCheckWithExceptions, violations: *std.ArrayList(Violation)) !void {
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

    var scan_len = contents.len;
    if (check.production_only_marker) |marker| {
        if (std.mem.indexOf(u8, contents, marker)) |p| scan_len = p;
    }

    const scratch = try allocator.dupe(u8, contents[0..scan_len]);
    defer allocator.free(scratch);

    for (check.exempt_functions) |name| {
        if (extractFunctionBody(scratch, name)) |span| {
            const start = @intFromPtr(span.ptr) - @intFromPtr(scratch.ptr);
            @memset(scratch[start .. start + span.len], ' ');
        }
    }
    for (check.exempt_exact) |snippet| blank(scratch, snippet);

    if (firstForbidden(scratch, check.forbidden)) |needle| {
        try violations.append(allocator, .{ .path = try allocator.dupe(u8, check.path), .needle = needle, .rationale = check.rationale });
    }
}

fn checkTestOnlyImport(allocator: std.mem.Allocator, root: compat.DirCompat, check: TestOnlyImportCheck, violations: *std.ArrayList(Violation)) !void {
    const contents = root.readFileAlloc(allocator, check.path, 16 * 1024 * 1024) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    defer allocator.free(contents);

    const boundary = std.mem.indexOf(u8, contents, check.boundary_marker) orelse contents.len;
    const production_region = contents[0..boundary];
    if (std.mem.indexOf(u8, production_region, "test_quic_crypto.") != null) {
        try violations.append(allocator, .{
            .path = try allocator.dupe(u8, check.path),
            .needle = "test_quic_crypto.",
            .rationale = check.rationale,
        });
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
        const rel = try std.fs.path.join(allocator, &.{ dir_path, entry.name });
        defer allocator.free(rel);
        var excluded = false;
        for (check.excluded_paths) |excluded_path| {
            if (std.mem.eql(u8, rel, excluded_path)) {
                excluded = true;
                break;
            }
        }
        if (excluded) continue;
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
    for (file_checks_with_exceptions) |check| {
        try checkFileWithExceptions(allocator, root, check, &violations);
    }
    for (test_quic_crypto_import_checks) |check| {
        try checkTestOnlyImport(allocator, root, check, &violations);
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

test "tls_adapter_zig_forbidden allows provider.hkdfExpandLabel but forbids the legacy tls.hkdfExpandLabel" {
    try testing.expectEqual(@as(?[]const u8, null), firstForbidden(
        "provider.hkdfExpandLabel(.sha256, &secret, \"quic key\", \"\", &keys.key) catch return error.ProviderUnsupported;",
        &tls_adapter_zig_forbidden,
    ));
    try testing.expectEqualStrings("tls.hkdfExpandLabel(", firstForbidden(
        "const client_secret = tls.hkdfExpandLabel(HkdfSha256, initial_secret, \"client in\", \"\", traffic_secret_len);",
        &tls_adapter_zig_forbidden,
    ).?);
}

test "clean protocol-module content produces no violation" {
    try testing.expectEqual(@as(?[]const u8, null), firstForbidden(
        "keys.applyHeaderProtectionWithProvider(self.adapter.provider, &out[0], pn_field, sample) catch unreachable;",
        &full_forbidden,
    ));
}

test "extractFunctionBody isolates a struct method from its WithProvider sibling and from the next method" {
    const src =
        \\pub const PacketProtectionKeys = struct {
        \\    pub fn sealPayload(self: *const PacketProtectionKeys, pn: u64) ![]u8 {
        \\        return legacy(pn);
        \\    }
        \\    pub fn sealPayloadWithProvider(self: *const PacketProtectionKeys, provider: CryptoProvider, pn: u64) ![]u8 {
        \\        return provider.aeadSeal(pn);
        \\    }
        \\};
    ;
    const body = extractFunctionBody(src, "sealPayload").?;
    try testing.expect(std.mem.indexOf(u8, body, "legacy(pn)") != null);
    try testing.expect(std.mem.indexOf(u8, body, "aeadSeal") == null);
}

test "extractFunctionBody isolates a top-level free function from the struct declaration that follows it" {
    const src =
        \\pub fn deriveNextGenerationSecret(secret: [32]u8) [32]u8 {
        \\    return tls.hkdfExpandLabel(HkdfSha256, secret, "quic ku", "", 32);
        \\}
        \\pub fn deriveNextGenerationSecretWithProvider(provider: CryptoProvider, secret: [32]u8) ![32]u8 {
        \\    provider.hkdfExpandLabel(.sha256, &secret, "quic ku", "", &out) catch return error.ProviderUnsupported;
        \\    return out;
        \\}
        \\
        \\pub const QuicTlsAdapter = struct {
        \\    provider: CryptoProvider,
        \\
        \\    fn validateProvider(provider: CryptoProvider) !void {}
        \\};
    ;
    const legacy_body = extractFunctionBody(src, "deriveNextGenerationSecret").?;
    try testing.expect(std.mem.indexOf(u8, legacy_body, "tls.hkdfExpandLabel(") != null);
    try testing.expect(std.mem.indexOf(u8, legacy_body, "WithProvider") == null);

    const provider_body = extractFunctionBody(src, "deriveNextGenerationSecretWithProvider").?;
    try testing.expect(std.mem.indexOf(u8, provider_body, "provider.hkdfExpandLabel(") != null);
    try testing.expect(std.mem.indexOf(u8, provider_body, "QuicTlsAdapter") == null);
    try testing.expect(std.mem.indexOf(u8, provider_body, "validateProvider") == null);
}

/// Minimal but realistic stand-in for `src/quic/tls_adapter.zig`: the three
/// exempt type aliases, one legacy/`*WithProvider` method pair
/// (`PacketProtectionKeys.sealPayload` / `.sealPayloadWithProvider`, called
/// by dot-syntax like the real file rather than as free functions), a
/// canonical `QuicTlsAdapter.sealPacketPayload` calling the provider
/// sibling, and a `const testing = std.testing;` boundary followed by a
/// differential-vector-style test using the legacy call directly. Exercises
/// the exact parsing path the real file needs: an inline `error{...}` group
/// in a return type before the real body opens, a legacy method immediately
/// followed by its `*WithProvider` sibling, and content after the
/// production-only marker that must NOT be scanned.
const clean_tls_adapter_fixture =
    \\const HkdfSha256 = crypto.kdf.hkdf.HkdfSha256;
    \\const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;
    \\const Aes128 = crypto.core.aes.Aes128;
    \\
    \\pub const PacketProtectionKeys = struct {
    \\    pub fn sealPayload(self: *const PacketProtectionKeys, secret: [32]u8) [16]u8 {
    \\        const mask = Aes128.initEnc(secret);
    \\        return Aes128Gcm.encrypt(secret);
    \\    }
    \\    pub fn sealPayloadWithProvider(self: *const PacketProtectionKeys, provider: CryptoProvider, secret: [32]u8) ![16]u8 {
    \\        return provider.aeadSeal(secret);
    \\    }
    \\};
    \\
    \\pub const QuicTlsAdapter = struct {
    \\    provider: CryptoProvider,
    \\
    \\    pub fn sealPacketPayload(self: *QuicTlsAdapter, keys: PacketProtectionKeys) error{ProviderUnsupported}![]u8 {
    \\        return keys.sealPayloadWithProvider(self.provider, secret);
    \\    }
    \\};
    \\
    \\const testing = std.testing;
    \\
    \\test "differential vector" {
    \\    var keys: PacketProtectionKeys = undefined;
    \\    try testing.expectEqualSlices(u8, &keys.sealPayload(secret), &(try keys.sealPayloadWithProvider(provider, secret)));
    \\}
    \\
;

/// `clean_tls_adapter_fixture` with `QuicTlsAdapter.sealPacketPayload`
/// reverted to the legacy `keys.sealPayload(...)` call — the exact
/// regression #490's third-pass review named.
const canonical_method_regression_fixture =
    \\const HkdfSha256 = crypto.kdf.hkdf.HkdfSha256;
    \\const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;
    \\const Aes128 = crypto.core.aes.Aes128;
    \\
    \\pub const PacketProtectionKeys = struct {
    \\    pub fn sealPayload(self: *const PacketProtectionKeys, secret: [32]u8) [16]u8 {
    \\        const mask = Aes128.initEnc(secret);
    \\        return Aes128Gcm.encrypt(secret);
    \\    }
    \\    pub fn sealPayloadWithProvider(self: *const PacketProtectionKeys, provider: CryptoProvider, secret: [32]u8) ![16]u8 {
    \\        return provider.aeadSeal(secret);
    \\    }
    \\};
    \\
    \\pub const QuicTlsAdapter = struct {
    \\    provider: CryptoProvider,
    \\
    \\    pub fn sealPacketPayload(self: *QuicTlsAdapter, keys: PacketProtectionKeys) error{ProviderUnsupported}![]u8 {
    \\        return keys.sealPayload(secret);
    \\    }
    \\};
    \\
    \\const testing = std.testing;
    \\
    \\test "differential vector" {
    \\    var keys: PacketProtectionKeys = undefined;
    \\    try testing.expectEqualSlices(u8, &keys.sealPayload(secret), &(try keys.sealPayloadWithProvider(provider, secret)));
    \\}
    \\
;

/// `clean_tls_adapter_fixture` with `sealPayloadWithProvider` reverted to
/// delegate to its own legacy concrete sibling instead of the provider — the
/// mirror regression #490's fourth-pass review named.
const with_provider_delegates_to_legacy_fixture =
    \\const HkdfSha256 = crypto.kdf.hkdf.HkdfSha256;
    \\const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;
    \\const Aes128 = crypto.core.aes.Aes128;
    \\
    \\pub const PacketProtectionKeys = struct {
    \\    pub fn sealPayload(self: *const PacketProtectionKeys, secret: [32]u8) [16]u8 {
    \\        const mask = Aes128.initEnc(secret);
    \\        return Aes128Gcm.encrypt(secret);
    \\    }
    \\    pub fn sealPayloadWithProvider(self: *const PacketProtectionKeys, provider: CryptoProvider, secret: [32]u8) ![16]u8 {
    \\        return self.sealPayload(secret);
    \\    }
    \\};
    \\
    \\pub const QuicTlsAdapter = struct {
    \\    provider: CryptoProvider,
    \\
    \\    pub fn sealPacketPayload(self: *QuicTlsAdapter, keys: PacketProtectionKeys) error{ProviderUnsupported}![]u8 {
    \\        return keys.sealPayloadWithProvider(self.provider, secret);
    \\    }
    \\};
    \\
    \\const testing = std.testing;
    \\
    \\test "differential vector" {
    \\    var keys: PacketProtectionKeys = undefined;
    \\    try testing.expectEqualSlices(u8, &keys.sealPayload(secret), &(try keys.sealPayloadWithProvider(provider, secret)));
    \\}
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
    try root.writeFile(.{ .sub_path = "src/quic/path.zig", .data = "" });
    try root.writeFile(.{ .sub_path = "src/quic/packet.zig", .data = "" });

    const bypass_cases = [_]struct { rel: []const u8, contents: []const u8 }{
        .{ .rel = "src/quic/connection.zig", .contents = "const mask = Aes128.initEnc(self.hp);\n" },
        .{ .rel = "src/quic/packet.zig", .contents = "const shared = X25519.scalarmult(a, b) catch unreachable;\n" },
        .{ .rel = "src/quic/path.zig", .contents = "Ed25519.verify(sig, msg, key) catch return error.Bad;\n" },
        .{ .rel = "src/http/http3_runtime.zig", .contents = "keys.applyHeaderProtection(&out[0], pn_field, sample);\n" },
        // The composition root must not perform packet crypto itself even
        // outside the legacy-wrapper-call category.
        .{ .rel = "src/http/http3_runtime.zig", .contents = "const tag = std.crypto.aead.aes_gcm.Aes128Gcm.encrypt(...);\n" },
        .{ .rel = "src/quic/frame.zig", .contents = "const tag = std.crypto.aead.aes_gcm.Aes128Gcm.encrypt(...);\n" },
        // A nested subdirectory under src/quic gets no free pass from the
        // (now recursive) directory-wide scan.
        .{ .rel = "src/quic/nested/packet_crypto.zig", .contents = "const tag = std.crypto.aead.aes_gcm.Aes128Gcm.encrypt(...);\n" },
        // A file at any depth reusing an excluded file's *basename* still
        // fails: exclusion is by exact root-relative path now.
        .{ .rel = "src/quic/nested/connection.zig", .contents = "const tag = std.crypto.aead.aes_gcm.Aes128Gcm.encrypt(...);\n" },
        // tls_handshake.zig is fully scannable now; a legacy wrapper call
        // there must fail too, and so must unrelated KDF use beyond the one
        // named exception.
        .{ .rel = "src/quic/tls_handshake.zig", .contents = "keys.sealPayload(pn, header, plain, out);\n" },
        .{ .rel = "src/quic/tls_handshake.zig", .contents = "const other = std.crypto.kdf.hkdf.HkdfSha384.extract(a, b);\n" },
        // path.zig/cid.zig: a second, unrelated crypto call beyond the named
        // exception must still fail (#490 fourth-pass review) — the whole
        // category is no longer omitted from the forbidden list.
        .{ .rel = "src/quic/path.zig", .contents = "fn unrelated() void { _ = std.crypto.auth.hmac.sha2.HmacSha256.create(&mac, msg, key); }\n" },
        .{ .rel = "src/quic/cid.zig", .contents = "fn unrelated() void { _ = std.crypto.aead.aes_gcm.Aes128Gcm.encrypt(a, b, c, d, e, f); }\n" },
        // The exact regression the tls_adapter.zig checks exist to catch: a
        // canonical method reverting to a legacy wrapper call internally.
        .{ .rel = "src/quic/tls_adapter.zig", .contents = canonical_method_regression_fixture },
        // The mirror regression: a *WithProvider implementation silently
        // delegating to its own legacy concrete sibling instead of the
        // provider.
        .{ .rel = "src/quic/tls_adapter.zig", .contents = with_provider_delegates_to_legacy_fixture },
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
        else if (std.mem.eql(u8, case.rel, "src/http/http3_runtime.zig"))
            ""
        else
            "";
        try root.writeFile(.{ .sub_path = case.rel, .data = clean });
    }
    try root.deleteFile("src/quic/nested/packet_crypto.zig");
    try root.deleteFile("src/quic/nested/connection.zig");

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

test "test_quic_crypto usage before a file's test boundary is a violation" {
    const allocator = testing.allocator;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = compat.wrapDir(tmp.dir);

    try root.makePath("src/quic");

    // Clean: test_quic_crypto used only after the test boundary.
    try root.writeFile(.{ .sub_path = "src/quic/tls_adapter.zig", .data = clean_tls_adapter_fixture ++ "test_quic_crypto.testDefaultProvider();\n" });
    {
        var violations: std.ArrayList(Violation) = .empty;
        defer violations.deinit(allocator);
        try checkTestOnlyImport(allocator, root, test_quic_crypto_import_checks[0], &violations);
        try testing.expectEqual(@as(usize, 0), violations.items.len);
    }

    // A production call site before the boundary must fail.
    try root.writeFile(.{ .sub_path = "src/quic/tls_adapter.zig", .data = "pub fn live() void { _ = test_quic_crypto.testDefaultProvider(); }\n" ++ clean_tls_adapter_fixture });
    {
        var violations: std.ArrayList(Violation) = .empty;
        defer violations.deinit(allocator);
        try checkTestOnlyImport(allocator, root, test_quic_crypto_import_checks[0], &violations);
        try testing.expectEqual(@as(usize, 1), violations.items.len);
        allocator.free(violations.items[0].path);
    }
}

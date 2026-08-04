//! Provider primitive workloads for issue #378: hash/HKDF, AEAD, key
//! exchange, signatures, and secret-container overhead. Every workload
//! drives `pure_zig.Provider` directly through `provider.CryptoProvider` —
//! the same "own-stack-frame provider, never shared, never a protocol state
//! machine" pattern `tests/crypto_provider_fuzz.zig` uses — so a benchmark
//! run measures exactly the seam native TLS/QUIC code calls through.

const std = @import("std");
const crypto = @import("crypto");
const harness = @import("harness.zig");

const provider = crypto.provider;
const pure_zig = crypto.pure_zig;
const secrets = crypto.secrets;
const rsa = crypto.rsa;

const Measurement = harness.Measurement;
const Scale = harness.Scale;

const Ed25519 = std.crypto.sign.Ed25519;
const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

const message_len = 128;
const max_plaintext_len = 16384;
const payload_sizes = [_]usize{ 64, 1350, max_plaintext_len };
/// RSA-PSS public keys (DER `RSAPublicKey`) are unrelated in size to
/// `provider.max_public_key_len` (which bounds KEX public *values*, not
/// signature-scheme public *keys*); size this independently for up to a
/// 4096-bit RSA modulus.
const max_verify_public_key_len = 600;

fn testMessage() [message_len]u8 {
    var buf: [message_len]u8 = undefined;
    for (&buf, 0..) |*b, i| b.* = @truncate(i * 31 + 7);
    return buf;
}

/// Container-scope (comptime-evaluated once) rather than a function-local:
/// a nested `step` function inside a `Context` struct literal cannot close
/// over an enclosing function's runtime locals in Zig, only over
/// container-scope declarations and comptime parameters. Every signature
/// workload below references this directly for that reason.
const message: [message_len]u8 = testMessage();

/// Every benchmark constructs its own `TestProvider` on its own stack frame
/// and calls `init` on the already-addressed value — never build one in a
/// helper and return it by value. `Provider.entropy` stores a raw pointer to
/// `self.entropy`; a by-value return would leave that pointer aimed at a
/// temporary that no longer exists once the helper returns (see the
/// identical warning in `tests/crypto_provider_fuzz.zig`).
const TestProvider = struct {
    entropy: pure_zig.DeterministicEntropy,
    instance: pure_zig.Provider,

    fn init(self: *TestProvider, seed: u64) void {
        self.entropy = pure_zig.DeterministicEntropy.init(seed);
        self.instance = pure_zig.Provider.init(self.entropy.entropy());
    }

    fn cryptoProvider(self: *const TestProvider) provider.CryptoProvider {
        return self.instance.cryptoProvider();
    }
};

/// Structural regression guard for the "allocation-free by construction"
/// claim the harness's `CountingAllocator` doc comment makes: every
/// `CryptoProvider.VTable` operation takes no `std.mem.Allocator` parameter,
/// so HKDF/AEAD/key-exchange/verify calls cannot allocate no matter which
/// backend implements them.
pub fn assertProviderVtableIsAllocatorFree() void {
    const Vtable = provider.CryptoProvider.VTable;
    inline for (@typeInfo(Vtable).@"struct".fields) |field| {
        const fn_info = @typeInfo(@typeInfo(field.type).pointer.child).@"fn";
        inline for (fn_info.params) |param| {
            if (param.type) |t| {
                if (t == std.mem.Allocator) @compileError("CryptoProvider.VTable." ++ field.name ++ " must not take an allocator");
            }
        }
    }
}

pub fn run(allocator: std.mem.Allocator, out: *harness.Reporter, scale: Scale) !void {
    comptime assertProviderVtableIsAllocatorFree();
    try runHash(out, scale);
    try runHkdf(out, scale);
    try runAead(out, scale);
    try runKeyExchange(out, scale);
    try runSignatures(out, scale);
    try runSecrets(allocator, out, scale);
}

// ---------------------------------------------------------------------------
// Hash (provider-independent; explanatory only, per issue #378)
// ---------------------------------------------------------------------------

fn runHash(out: *harness.Reporter, scale: Scale) !void {
    const sizes = [_]usize{ 64, 1350, max_plaintext_len };
    inline for (.{ "sha256", "sha384" }) |name| {
        for (sizes) |size| {
            var input_buf: [max_plaintext_len]u8 = undefined;
            for (input_buf[0..size], 0..) |*b, i| b.* = @truncate(i);
            const Context = struct {
                input: []const u8,
                digest: [64]u8 = undefined,

                fn step(self: *@This()) !void {
                    // See `runFixedSecret`'s barrier comment: hashing a
                    // fixed, never-mutated input is otherwise a loop
                    // invariant a sufficiently aggressive inliner could hoist.
                    std.mem.doNotOptimizeAway(self.input);
                    if (comptime std.mem.eql(u8, name, "sha256")) {
                        var h = std.crypto.hash.sha2.Sha256.init(.{});
                        h.update(self.input);
                        h.final(self.digest[0..32]);
                    } else {
                        var h = std.crypto.hash.sha2.Sha384.init(.{});
                        h.update(self.input);
                        h.final(self.digest[0..48]);
                    }
                    std.mem.doNotOptimizeAway(self.digest[0]);
                }
            };
            var ctx = Context{ .input = input_buf[0..size] };
            const iterations = scale.iterations(2000);
            const ns = try harness.timeLoop(Context, &ctx, iterations, Context.step);
            try out.append(.{
                .suite = "hash",
                .name = "digest",
                .algorithm = name,
                .input_bytes = size,
                .iterations = iterations,
                .ns_total = ns,
                .note = "provider-independent std.crypto hash, benchmarked for explanatory context only",
            });
        }
    }
}

// ---------------------------------------------------------------------------
// HKDF
// ---------------------------------------------------------------------------

fn runHkdf(out: *harness.Reporter, scale: Scale) !void {
    inline for (.{ provider.Hash.sha256, provider.Hash.sha384 }) |hash| {
        try runHkdfExtract(out, scale, hash);
        try runHkdfExpandLabel(out, scale, hash);
    }
    try runRepeatedTrafficKeyDerivation(out, scale);
}

fn runHkdfExtract(out: *harness.Reporter, scale: Scale, comptime hash: provider.Hash) !void {
    var tp: TestProvider = undefined;
    tp.init(0x378_01);
    const cp = tp.cryptoProvider();
    const Context = struct {
        cp: provider.CryptoProvider,
        salt: [32]u8 = [_]u8{0x11} ** 32,
        ikm: [40]u8 = [_]u8{0x22} ** 40,
        prk: [hash.digestLength()]u8 = undefined,

        fn step(self: *@This()) !void {
            try self.cp.hkdfExtract(hash, &self.salt, &self.ikm, &self.prk);
            std.mem.doNotOptimizeAway(self.prk[0]);
        }
    };
    var ctx = Context{ .cp = cp };
    const iterations = scale.iterations(5000);
    const ns = try harness.timeLoop(Context, &ctx, iterations, Context.step);
    try out.append(.{ .suite = "hkdf", .name = "extract", .algorithm = @tagName(hash), .iterations = iterations, .ns_total = ns });
}

fn runHkdfExpandLabel(out: *harness.Reporter, scale: Scale, comptime hash: provider.Hash) !void {
    const output_lens = [_]usize{ 16, 32, 48, 64 };
    const context_lens = [_]usize{ 0, 32, 48 };
    for (output_lens) |out_len| {
        for (context_lens) |ctx_len| {
            var tp: TestProvider = undefined;
            tp.init(0x378_02);
            const cp = tp.cryptoProvider();
            const Context = struct {
                cp: provider.CryptoProvider,
                secret: [hash.digestLength()]u8 = [_]u8{0x33} ** hash.digestLength(),
                hash_context: [48]u8 = [_]u8{0x44} ** 48,
                expanded: [64]u8 = undefined,
                out_len: usize,
                ctx_len: usize,

                fn step(self: *@This()) !void {
                    try self.cp.hkdfExpandLabel(hash, &self.secret, "traffic upd", self.hash_context[0..self.ctx_len], self.expanded[0..self.out_len]);
                    std.mem.doNotOptimizeAway(self.expanded[0]);
                }
            };
            var ctx = Context{ .cp = cp, .out_len = out_len, .ctx_len = ctx_len };
            const iterations = scale.iterations(5000);
            const ns = try harness.timeLoop(Context, &ctx, iterations, Context.step);
            try out.append(.{
                .suite = "hkdf",
                .name = "expand_label",
                .algorithm = @tagName(hash),
                .input_bytes = out_len,
                .iterations = iterations,
                .ns_total = ns,
                .note = "input_bytes is the derived-output length; hash_context length varies 0/32/48 across runs",
            });
        }
    }
}

fn runRepeatedTrafficKeyDerivation(out: *harness.Reporter, scale: Scale) !void {
    // Simulates the repeated key+iv derivation pattern the TLS 1.3 record
    // layer performs on every epoch change (handshake, application, and any
    // KeyUpdate), without depending on tls_core: two HKDF-Expand-Label calls
    // ("key" then "iv") per iteration.
    var tp: TestProvider = undefined;
    tp.init(0x378_03);
    const cp = tp.cryptoProvider();
    const Context = struct {
        cp: provider.CryptoProvider,
        secret: [32]u8 = [_]u8{0x55} ** 32,
        key: [16]u8 = undefined,
        iv: [provider.aead_nonce_len]u8 = undefined,

        fn step(self: *@This()) !void {
            try self.cp.hkdfExpandLabel(.sha256, &self.secret, "key", "", &self.key);
            try self.cp.hkdfExpandLabel(.sha256, &self.secret, "iv", "", &self.iv);
            std.mem.doNotOptimizeAway(self.key[0]);
        }
    };
    var ctx = Context{ .cp = cp };
    const iterations = scale.iterations(3000);
    const ns = try harness.timeLoop(Context, &ctx, iterations, Context.step);
    try out.append(.{
        .suite = "hkdf",
        .name = "repeated_traffic_key_derivation",
        .algorithm = "sha256",
        .iterations = iterations,
        .ns_total = ns,
        .note = "one key + one iv HKDF-Expand-Label pair per iteration, matching a record-layer epoch change",
    });
}

// ---------------------------------------------------------------------------
// AEAD
// ---------------------------------------------------------------------------

fn runAead(out: *harness.Reporter, scale: Scale) !void {
    inline for (.{ provider.Aead.aes_128_gcm, provider.Aead.aes_256_gcm, provider.Aead.chacha20_poly1305 }) |aead| {
        for (payload_sizes) |size| {
            try runAeadSeal(out, scale, aead, size);
            try runAeadOpen(out, scale, aead, size);
        }
        try runAeadAuthFailure(out, scale, aead);
    }
}

fn runAeadSeal(out: *harness.Reporter, scale: Scale, comptime aead: provider.Aead, size: usize) !void {
    var tp: TestProvider = undefined;
    tp.init(0x378_10);
    const cp = tp.cryptoProvider();
    const Context = struct {
        cp: provider.CryptoProvider,
        key: [aead.keyLength()]u8 = [_]u8{0x66} ** aead.keyLength(),
        nonce: [provider.aead_nonce_len]u8 = [_]u8{0} ** provider.aead_nonce_len,
        plaintext: [max_plaintext_len]u8 = [_]u8{0x77} ** max_plaintext_len,
        ciphertext: [max_plaintext_len]u8 = undefined,
        tag: [provider.aead_tag_len]u8 = undefined,
        counter: u64 = 0,
        size: usize,

        fn step(self: *@This()) !void {
            std.mem.writeInt(u64, self.nonce[4..12], self.counter, .big);
            self.counter +%= 1;
            try self.cp.aeadSeal(aead, &self.key, &self.nonce, "associated data", self.plaintext[0..self.size], self.ciphertext[0..self.size], &self.tag);
            std.mem.doNotOptimizeAway(self.ciphertext[0]);
        }
    };
    var ctx = Context{ .cp = cp, .size = size };
    const iterations = scale.iterations(if (size >= max_plaintext_len) 500 else 3000);
    const ns = try harness.timeLoop(Context, &ctx, iterations, Context.step);
    try out.append(.{ .suite = "aead", .name = "seal", .algorithm = @tagName(aead), .input_bytes = size, .iterations = iterations, .ns_total = ns });
}

fn runAeadOpen(out: *harness.Reporter, scale: Scale, comptime aead: provider.Aead, size: usize) !void {
    var tp: TestProvider = undefined;
    tp.init(0x378_11);
    const cp = tp.cryptoProvider();
    const key = [_]u8{0x66} ** aead.keyLength();
    const nonce = [_]u8{0x88} ** provider.aead_nonce_len;
    var plaintext: [max_plaintext_len]u8 = [_]u8{0x77} ** max_plaintext_len;
    var ciphertext: [max_plaintext_len]u8 = undefined;
    var tag: [provider.aead_tag_len]u8 = undefined;
    try cp.aeadSeal(aead, &key, &nonce, "associated data", plaintext[0..size], ciphertext[0..size], &tag);

    const Context = struct {
        cp: provider.CryptoProvider,
        key: [aead.keyLength()]u8,
        nonce: [provider.aead_nonce_len]u8,
        ciphertext: [max_plaintext_len]u8,
        tag: [provider.aead_tag_len]u8,
        recovered: [max_plaintext_len]u8 = undefined,
        size: usize,

        fn step(self: *@This()) !void {
            try self.cp.aeadOpen(aead, &self.key, &self.nonce, "associated data", self.ciphertext[0..self.size], &self.tag, self.recovered[0..self.size]);
            std.mem.doNotOptimizeAway(self.recovered[0]);
        }
    };
    var ctx = Context{ .cp = cp, .key = key, .nonce = nonce, .ciphertext = ciphertext, .tag = tag, .size = size };
    const iterations = scale.iterations(if (size >= max_plaintext_len) 500 else 3000);
    const ns = try harness.timeLoop(Context, &ctx, iterations, Context.step);
    try out.append(.{ .suite = "aead", .name = "open", .algorithm = @tagName(aead), .input_bytes = size, .iterations = iterations, .ns_total = ns });
}

fn runAeadAuthFailure(out: *harness.Reporter, scale: Scale, comptime aead: provider.Aead) !void {
    var tp: TestProvider = undefined;
    tp.init(0x378_12);
    const cp = tp.cryptoProvider();
    const size = 1350;
    const key = [_]u8{0x99} ** aead.keyLength();
    const nonce = [_]u8{0xaa} ** provider.aead_nonce_len;
    var plaintext: [size]u8 = [_]u8{0x77} ** size;
    var ciphertext: [size]u8 = undefined;
    var tag: [provider.aead_tag_len]u8 = undefined;
    try cp.aeadSeal(aead, &key, &nonce, "associated data", &plaintext, &ciphertext, &tag);
    ciphertext[0] ^= 0x01; // tamper: every open() below must reject, not just decode.

    const Context = struct {
        cp: provider.CryptoProvider,
        key: [aead.keyLength()]u8,
        nonce: [provider.aead_nonce_len]u8,
        ciphertext: [size]u8,
        tag: [provider.aead_tag_len]u8,
        recovered: [size]u8 = undefined,

        fn step(self: *@This()) !void {
            const result = self.cp.aeadOpen(aead, &self.key, &self.nonce, "associated data", &self.ciphertext, &self.tag, &self.recovered);
            if (result) |_| return error.ExpectedAuthenticationFailure else |err| {
                if (err != error.AuthenticationFailed) return err;
            }
        }
    };
    var ctx = Context{ .cp = cp, .key = key, .nonce = nonce, .ciphertext = ciphertext, .tag = tag };
    const iterations = scale.iterations(3000);
    const ns = try harness.timeLoop(Context, &ctx, iterations, Context.step);
    try out.append(.{ .suite = "aead", .name = "open_auth_failure", .algorithm = @tagName(aead), .input_bytes = size, .iterations = iterations, .ns_total = ns, .note = "tampered ciphertext; every call rejects" });
}

// ---------------------------------------------------------------------------
// Key exchange
// ---------------------------------------------------------------------------

fn runKeyExchange(out: *harness.Reporter, scale: Scale) !void {
    inline for (.{ provider.Group.x25519, provider.Group.secp256r1 }) |group| {
        try runKeyShareGeneration(out, scale, group);
        try runSharedSecretDerivation(out, scale, group);
        try runInvalidPeerKeyRejection(out, scale, group);
    }
}

fn runKeyShareGeneration(out: *harness.Reporter, scale: Scale, comptime group: provider.Group) !void {
    var tp: TestProvider = undefined;
    tp.init(0x378_20);
    const cp = tp.cryptoProvider();
    const Context = struct {
        cp: provider.CryptoProvider,
        public_key: [group.publicKeyLength()]u8 = undefined,
        private_key: [provider.max_private_scalar_len]u8 = undefined,

        fn step(self: *@This()) !void {
            try self.cp.generateKeyShare(group, &self.public_key, &self.private_key);
            std.mem.doNotOptimizeAway(self.public_key[0]);
        }
    };
    var ctx = Context{ .cp = cp };
    const iterations = scale.iterations(1000);
    const ns = try harness.timeLoop(Context, &ctx, iterations, Context.step);
    try out.append(.{ .suite = "kex", .name = "generate_key_share", .algorithm = @tagName(group), .iterations = iterations, .ns_total = ns });
}

fn runSharedSecretDerivation(out: *harness.Reporter, scale: Scale, comptime group: provider.Group) !void {
    var tp: TestProvider = undefined;
    tp.init(0x378_21);
    const cp = tp.cryptoProvider();
    var our_public: [group.publicKeyLength()]u8 = undefined;
    var our_private: [provider.max_private_scalar_len]u8 = undefined;
    try cp.generateKeyShare(group, &our_public, &our_private);
    var peer_public: [group.publicKeyLength()]u8 = undefined;
    var peer_private: [provider.max_private_scalar_len]u8 = undefined;
    try cp.generateKeyShare(group, &peer_public, &peer_private);

    const Context = struct {
        cp: provider.CryptoProvider,
        our_private: [provider.max_private_scalar_len]u8,
        peer_public: [group.publicKeyLength()]u8,
        shared: [group.sharedSecretLength()]u8 = undefined,

        fn step(self: *@This()) !void {
            try self.cp.deriveSharedSecret(group, &self.our_private, &self.peer_public, &self.shared);
            std.mem.doNotOptimizeAway(self.shared[0]);
        }
    };
    var ctx = Context{ .cp = cp, .our_private = our_private, .peer_public = peer_public };
    const iterations = scale.iterations(1000);
    const ns = try harness.timeLoop(Context, &ctx, iterations, Context.step);
    try out.append(.{ .suite = "kex", .name = "derive_shared_secret", .algorithm = @tagName(group), .iterations = iterations, .ns_total = ns });
}

fn runInvalidPeerKeyRejection(out: *harness.Reporter, scale: Scale, comptime group: provider.Group) !void {
    var tp: TestProvider = undefined;
    tp.init(0x378_22);
    const cp = tp.cryptoProvider();
    var our_public: [group.publicKeyLength()]u8 = undefined;
    var our_private: [provider.max_private_scalar_len]u8 = undefined;
    try cp.generateKeyShare(group, &our_public, &our_private);

    var invalid_peer: [group.publicKeyLength()]u8 = [_]u8{0} ** group.publicKeyLength();
    if (group == .secp256r1) invalid_peer[0] = 0x00; // rejected before any curve math: not the 0x04 SEC1 prefix.

    const Context = struct {
        cp: provider.CryptoProvider,
        our_private: [provider.max_private_scalar_len]u8,
        invalid_peer: [group.publicKeyLength()]u8,
        shared: [group.sharedSecretLength()]u8 = undefined,

        fn step(self: *@This()) !void {
            const result = self.cp.deriveSharedSecret(group, &self.our_private, &self.invalid_peer, &self.shared);
            if (result) |_| return error.ExpectedInvalidInput else |err| {
                if (err != error.InvalidInput) return err;
            }
        }
    };
    var ctx = Context{ .cp = cp, .our_private = our_private, .invalid_peer = invalid_peer };
    const iterations = scale.iterations(1000);
    const ns = try harness.timeLoop(Context, &ctx, iterations, Context.step);
    try out.append(.{ .suite = "kex", .name = "reject_invalid_peer_key", .algorithm = @tagName(group), .iterations = iterations, .ns_total = ns, .note = "all-zero/malformed peer public value; every call rejects" });
}

// ---------------------------------------------------------------------------
// Signatures
// ---------------------------------------------------------------------------

fn runSignatures(out: *harness.Reporter, scale: Scale) !void {
    try runEd25519(out, scale);
    try runEcdsaP256(out, scale);
    try runRsaPss(out, scale);
}

fn runEd25519(out: *harness.Reporter, scale: Scale) !void {
    var tp: TestProvider = undefined;
    tp.init(0x378_30);
    const cp = tp.cryptoProvider();

    const seed: [Ed25519.KeyPair.seed_length]u8 = [_]u8{0xbb} ** Ed25519.KeyPair.seed_length;
    var key = try pure_zig.SoftwareSigningKey.fromSeed(seed);
    defer key.deinit();
    const public_key = key.publicKey();

    {
        const Context = struct {
            key: pure_zig.SoftwareSigningKey,
            entropy: provider.Entropy,
            signature: [provider.max_signature_len]u8 = undefined,

            fn step(self: *@This()) !void {
                const len = try self.key.signingKey().sign(&message, self.entropy, &self.signature);
                std.mem.doNotOptimizeAway(self.signature[len - 1]);
            }
        };
        var ctx = Context{ .key = try pure_zig.SoftwareSigningKey.fromSeed(seed), .entropy = cp.entropy };
        defer ctx.key.deinit();
        const iterations = scale.iterations(2000);
        const ns = try harness.timeLoop(Context, &ctx, iterations, Context.step);
        try out.append(.{ .suite = "signature", .name = "sign", .algorithm = "ed25519", .iterations = iterations, .ns_total = ns });
    }

    var signature: [provider.max_signature_len]u8 = undefined;
    const sig_len = try key.signingKey().sign(&message, cp.entropy, &signature);

    try runVerify(out, scale, .ed25519, &public_key, signature[0..sig_len]);
    try runInvalidSignatureRejection(out, scale, .ed25519, &public_key, signature[0..sig_len]);
}

fn runEcdsaP256(out: *harness.Reporter, scale: Scale) !void {
    var tp: TestProvider = undefined;
    tp.init(0x378_31);
    const cp = tp.cryptoProvider();

    const seed: [EcdsaP256Sha256.KeyPair.seed_length]u8 = [_]u8{0xcc} ** EcdsaP256Sha256.KeyPair.seed_length;
    var key = try pure_zig.SoftwareEcdsaP256SigningKey.fromSeed(seed);
    defer key.deinit();
    const public_key = key.publicKeySec1();

    {
        const Context = struct {
            key: pure_zig.SoftwareEcdsaP256SigningKey,
            entropy: provider.Entropy,
            signature: [provider.max_signature_len]u8 = undefined,

            fn step(self: *@This()) !void {
                const len = try self.key.signingKey().sign(&message, self.entropy, &self.signature);
                std.mem.doNotOptimizeAway(self.signature[len - 1]);
            }
        };
        var ctx = Context{ .key = try pure_zig.SoftwareEcdsaP256SigningKey.fromSeed(seed), .entropy = cp.entropy };
        defer ctx.key.deinit();
        const iterations = scale.iterations(1000);
        const ns = try harness.timeLoop(Context, &ctx, iterations, Context.step);
        try out.append(.{ .suite = "signature", .name = "sign", .algorithm = "ecdsa_secp256r1_sha256", .iterations = iterations, .ns_total = ns });
    }

    var signature: [provider.max_signature_len]u8 = undefined;
    const sig_len = try key.signingKey().sign(&message, cp.entropy, &signature);

    try runVerify(out, scale, .ecdsa_secp256r1_sha256, &public_key, signature[0..sig_len]);
    try runInvalidSignatureRejection(out, scale, .ecdsa_secp256r1_sha256, &public_key, signature[0..sig_len]);
}

fn runRsaPss(out: *harness.Reporter, scale: Scale) !void {
    var tp: TestProvider = undefined;
    tp.init(0x378_32);
    const cp = tp.cryptoProvider();

    var key = try pure_zig.SoftwareRsaSigningKey.fromDer(rsa.testdata.private_key_pkcs1_der, cp.entropy);
    defer key.deinit();
    const public_key = rsa.testdata.public_key_der;

    var signature: [provider.max_signature_len]u8 = undefined;
    var signature_len: usize = 0;
    {
        const Context = struct {
            key: pure_zig.SoftwareRsaSigningKey,
            entropy: provider.Entropy,
            signature: [provider.max_signature_len]u8 = undefined,

            fn step(self: *@This()) !void {
                const len = try self.key.signingKey().sign(&message, self.entropy, &self.signature);
                std.mem.doNotOptimizeAway(self.signature[len - 1]);
            }
        };
        var key_copy = try pure_zig.SoftwareRsaSigningKey.fromDer(rsa.testdata.private_key_pkcs1_der, cp.entropy);
        defer key_copy.deinit();
        var ctx = Context{ .key = key_copy, .entropy = cp.entropy };
        defer ctx.key.deinit();
        const iterations = scale.iterations(50);
        const ns = try harness.timeLoop(Context, &ctx, iterations, Context.step);
        try out.append(.{ .suite = "signature", .name = "sign", .algorithm = "rsa_pss_rsae_sha256", .iterations = iterations, .ns_total = ns });
        signature = ctx.signature;
    }
    signature_len = try key.signingKey().sign(&message, cp.entropy, &signature);

    try runVerify(out, scale, .rsa_pss_rsae_sha256, public_key, signature[0..signature_len]);
    try runInvalidSignatureRejection(out, scale, .rsa_pss_rsae_sha256, public_key, signature[0..signature_len]);
}

fn runVerify(out: *harness.Reporter, scale: Scale, comptime scheme: provider.SignatureScheme, public_key: []const u8, signature: []const u8) !void {
    var tp: TestProvider = undefined;
    tp.init(0x378_33);
    const cp = tp.cryptoProvider();
    const Context = struct {
        cp: provider.CryptoProvider,
        public_key: [max_verify_public_key_len]u8,
        public_key_len: usize,
        signature: [provider.max_signature_len]u8,
        signature_len: usize,

        fn step(self: *@This()) !void {
            try self.cp.verify(scheme, self.public_key[0..self.public_key_len], &message, self.signature[0..self.signature_len]);
        }
    };
    var public_key_buf: [max_verify_public_key_len]u8 = undefined;
    @memcpy(public_key_buf[0..public_key.len], public_key);
    var signature_buf: [provider.max_signature_len]u8 = undefined;
    @memcpy(signature_buf[0..signature.len], signature);
    var ctx = Context{ .cp = cp, .public_key = public_key_buf, .public_key_len = public_key.len, .signature = signature_buf, .signature_len = signature.len };
    const iterations = scale.iterations(if (scheme == .rsa_pss_rsae_sha256) 200 else 2000);
    const ns = try harness.timeLoop(Context, &ctx, iterations, Context.step);
    try out.append(.{ .suite = "signature", .name = "verify", .algorithm = @tagName(scheme), .iterations = iterations, .ns_total = ns });
}

fn runInvalidSignatureRejection(out: *harness.Reporter, scale: Scale, comptime scheme: provider.SignatureScheme, public_key: []const u8, signature: []const u8) !void {
    var tp: TestProvider = undefined;
    tp.init(0x378_34);
    const cp = tp.cryptoProvider();
    var tampered: [provider.max_signature_len]u8 = undefined;
    @memcpy(tampered[0..signature.len], signature);
    tampered[signature.len - 1] ^= 0x01;

    const Context = struct {
        cp: provider.CryptoProvider,
        public_key: [max_verify_public_key_len]u8,
        public_key_len: usize,
        signature: [provider.max_signature_len]u8,
        signature_len: usize,

        fn step(self: *@This()) !void {
            const result = self.cp.verify(scheme, self.public_key[0..self.public_key_len], &message, self.signature[0..self.signature_len]);
            if (result) |_| return error.ExpectedAuthenticationFailure else |err| {
                if (err != error.AuthenticationFailed) return err;
            }
        }
    };
    var public_key_buf: [max_verify_public_key_len]u8 = undefined;
    @memcpy(public_key_buf[0..public_key.len], public_key);
    var ctx = Context{ .cp = cp, .public_key = public_key_buf, .public_key_len = public_key.len, .signature = tampered, .signature_len = signature.len };
    const iterations = scale.iterations(if (scheme == .rsa_pss_rsae_sha256) 200 else 2000);
    const ns = try harness.timeLoop(Context, &ctx, iterations, Context.step);
    try out.append(.{ .suite = "signature", .name = "reject_invalid_signature", .algorithm = @tagName(scheme), .iterations = iterations, .ns_total = ns, .note = "tampered signature; every call rejects" });
}

// ---------------------------------------------------------------------------
// Secret-container / helper overhead
// ---------------------------------------------------------------------------

fn runSecrets(allocator: std.mem.Allocator, out: *harness.Reporter, scale: Scale) !void {
    try runFixedSecret(out, scale);
    try runBoundedSecret(allocator, out, scale);
    try runSecureZero(out, scale);
    try runConstantTimeEqual(out, scale);
}

fn runFixedSecret(out: *harness.Reporter, scale: Scale) !void {
    inline for (.{ 16, 32, 48 }) |capacity| {
        const Secret = secrets.FixedSecret(capacity);
        const Context = struct {
            value: [capacity]u8 = [_]u8{0xdd} ** capacity,

            fn step(self: *@This()) !void {
                // `&self.value` is a memory-clobbering barrier (see
                // `std.mem.doNotOptimizeAway`'s `.pointer` case), not just an
                // "escape" hint: without it, this whole tiny/fully-inlinable
                // operation over unchanging bytes is a textbook loop-invariant
                // the optimizer can legally hoist out of the timed loop,
                // collapsing thousands of iterations to one and reporting a
                // meaningless near-zero cost.
                std.mem.doNotOptimizeAway(&self.value);
                var secret = try Secret.init(&self.value);
                secret.deinit();
            }
        };
        var ctx = Context{};
        const iterations = scale.iterations(5000);
        const ns = try harness.timeLoop(Context, &ctx, iterations, Context.step);
        try out.append(.{ .suite = "secret", .name = "fixed_secret_replace_deinit", .algorithm = "FixedSecret", .input_bytes = capacity, .iterations = iterations, .ns_total = ns });
    }
}

fn runBoundedSecret(allocator: std.mem.Allocator, out: *harness.Reporter, scale: Scale) !void {
    inline for (.{ 64, 1024, 4096 }) |capacity| {
        var value: [capacity]u8 = [_]u8{0xee} ** capacity;
        const Context = struct {
            allocator: std.mem.Allocator,
            value: []const u8,

            fn step(self: *@This()) !void {
                var secret = secrets.BoundedSecret{};
                try secret.init(self.allocator, capacity, self.value);
                secret.deinit();
            }
        };
        var counting = harness.CountingAllocator.init(allocator);
        var ctx = Context{ .allocator = counting.allocator(), .value = &value };
        const iterations = scale.iterations(2000);
        const ns = try harness.timeLoop(Context, &ctx, iterations, Context.step);
        try out.append(.{
            .suite = "secret",
            .name = "bounded_secret_init_deinit",
            .algorithm = "BoundedSecret",
            .input_bytes = capacity,
            .iterations = iterations,
            .ns_total = ns,
            .allocations_per_op = @as(f64, @floatFromInt(counting.allocations)) / @as(f64, @floatFromInt(iterations)),
            .bytes_allocated_per_op = @as(f64, @floatFromInt(counting.bytes_allocated)) / @as(f64, @floatFromInt(iterations)),
        });
    }
}

fn runSecureZero(out: *harness.Reporter, scale: Scale) !void {
    inline for (.{ 16, 256, 4096 }) |size| {
        const Context = struct {
            buf: [size]u8 = [_]u8{0xff} ** size,

            fn step(self: *@This()) !void {
                // See the identical barrier in `runFixedSecret`: without
                // forcing the compiler to treat `buf` as possibly changed
                // since the last iteration, repeatedly zeroing an
                // already-zero, never-read buffer is a loop-invariant the
                // optimizer can legally collapse to one iteration.
                std.mem.doNotOptimizeAway(&self.buf);
                secrets.secureZero(&self.buf);
            }
        };
        var ctx = Context{};
        const iterations = scale.iterations(5000);
        const ns = try harness.timeLoop(Context, &ctx, iterations, Context.step);
        try out.append(.{ .suite = "secret", .name = "secure_zero", .algorithm = "secureZero", .input_bytes = size, .iterations = iterations, .ns_total = ns });
    }
}

fn runConstantTimeEqual(out: *harness.Reporter, scale: Scale) !void {
    inline for (.{ 16, 32, 48 }) |size| {
        const Context = struct {
            a: [size]u8 = [_]u8{0x12} ** size,
            b: [size]u8 = [_]u8{0x12} ** size,
            result: bool = false,

            fn step(self: *@This()) !void {
                // See the identical barrier in `runFixedSecret`: `a` and `b`
                // are structurally always equal, so without this the
                // optimizer can algebraically fold the whole comparison to
                // `true` and hoist it out of the loop regardless of size.
                std.mem.doNotOptimizeAway(&self.a);
                std.mem.doNotOptimizeAway(&self.b);
                self.result = secrets.constantTimeEqual(&self.a, &self.b);
            }
        };
        var ctx = Context{};
        const iterations = scale.iterations(20000);
        const ns = try harness.timeLoop(Context, &ctx, iterations, Context.step);
        try out.append(.{ .suite = "secret", .name = "constant_time_equal", .algorithm = "constantTimeEqual", .input_bytes = size, .iterations = iterations, .ns_total = ns, .note = "equal-value comparison (worst case: full length compared)" });
    }
}

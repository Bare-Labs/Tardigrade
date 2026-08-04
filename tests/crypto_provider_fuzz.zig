//! Standalone fuzz targets for the shared `CryptoProvider` boundary (#376,
//! epic #327-G). See `docs/CRYPTO_FUZZ_CONTRACT.md` for the shared contract
//! these targets (and the ones #491-494 own for their own protocol
//! surfaces) follow.
//!
//! Every target here drives the real `pure_zig.Provider` directly through
//! `provider.CryptoProvider` -- never a mock and never a protocol state
//! machine (TLS/QUIC/PKI fuzzing belongs to #491-494/#247/#492) -- covering
//! AEAD seal/open, key exchange, signature verification, the software
//! signing-key boundary, and the shared secret containers. This
//! complements, rather than duplicates, the deep deterministic coverage
//! already in `src/crypto/pure_zig.zig`, `src/crypto/rsa.zig`, and
//! `src/crypto/secrets.zig`; see the fuzz contract doc's matrix for exactly
//! which properties are covered where.

const std = @import("std");
const crypto_pkg = @import("crypto");
const testing = std.testing;

const provider = crypto_pkg.provider;
const pure_zig = crypto_pkg.pure_zig;
const rsa = crypto_pkg.rsa;
const secrets = crypto_pkg.secrets;

const Ed25519 = std.crypto.sign.Ed25519;
const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

/// Every test/fuzz case constructs its own `TestProvider` value on its own
/// stack frame rather than sharing one process-global instance: a shared
/// `DeterministicEntropy` stream would advance differently depending on how
/// many earlier cases already ran in the same process, so a minimized case
/// replayed alone (e.g. via `-Dcrypto-test-filter`) would not see the same
/// entropy a full run gave it, breaking case-isolated deterministic
/// reproduction. `init` must be called on an already-addressed `self` (never
/// have a helper build one and return it by value) because `Provider.entropy`
/// stores a raw pointer to `self.entropy`; a by-value return would leave that
/// pointer aimed at a temporary.
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

fn ed25519SigningKey(seed_byte: u8) !pure_zig.SoftwareSigningKey {
    var seed: [Ed25519.KeyPair.seed_length]u8 = undefined;
    @memset(&seed, seed_byte);
    return pure_zig.SoftwareSigningKey.fromSeed(seed);
}

fn ecdsaSigningKey(seed_byte: u8) !pure_zig.SoftwareEcdsaP256SigningKey {
    var seed: [EcdsaP256Sha256.KeyPair.seed_length]u8 = undefined;
    @memset(&seed, seed_byte);
    return pure_zig.SoftwareEcdsaP256SigningKey.fromSeed(seed);
}

// ---------------------------------------------------------------------------
// AEAD seal/open
// ---------------------------------------------------------------------------

test "AEAD seal/open reject wrong-length key, nonce, tag, and mismatched ciphertext/plaintext lengths for every supported AEAD" {
    var tp: TestProvider = undefined;
    tp.init(0x376);
    const cp = tp.cryptoProvider();
    const aeads = [_]provider.Aead{ .aes_128_gcm, .aes_256_gcm, .chacha20_poly1305 };
    for (aeads) |aead| {
        const key_len = aead.keyLength();
        const key_buf = [_]u8{0x11} ** provider.max_aead_key_len;
        const nonce_buf = [_]u8{0x22} ** provider.aead_nonce_len;
        const tag_buf = [_]u8{0x33} ** provider.aead_tag_len;
        const plaintext = [_]u8{0x44} ** 8;
        var ciphertext: [8]u8 = undefined;
        var tag_out: [provider.aead_tag_len]u8 = undefined;
        var recovered: [8]u8 = undefined;

        // Wrong-length key.
        try testing.expectError(error.InvalidInput, cp.aeadSeal(aead, key_buf[0 .. key_len - 1], &nonce_buf, "", &plaintext, &ciphertext, &tag_out));
        try testing.expectError(error.InvalidInput, cp.aeadOpen(aead, key_buf[0 .. key_len - 1], &nonce_buf, "", &plaintext, &tag_buf, &recovered));

        // Wrong-length nonce.
        try testing.expectError(error.InvalidInput, cp.aeadSeal(aead, key_buf[0..key_len], nonce_buf[0 .. provider.aead_nonce_len - 1], "", &plaintext, &ciphertext, &tag_out));
        try testing.expectError(error.InvalidInput, cp.aeadOpen(aead, key_buf[0..key_len], nonce_buf[0 .. provider.aead_nonce_len - 1], "", &plaintext, &tag_buf, &recovered));

        // Wrong-length tag.
        try testing.expectError(error.InvalidInput, cp.aeadOpen(aead, key_buf[0..key_len], &nonce_buf, "", &plaintext, tag_buf[0 .. provider.aead_tag_len - 1], &recovered));
        var short_tag_out: [provider.aead_tag_len - 1]u8 = undefined;
        try testing.expectError(error.InvalidInput, cp.aeadSeal(aead, key_buf[0..key_len], &nonce_buf, "", &plaintext, &ciphertext, &short_tag_out));

        // Ciphertext/plaintext length mismatch.
        var short_out: [4]u8 = undefined;
        try testing.expectError(error.InvalidInput, cp.aeadSeal(aead, key_buf[0..key_len], &nonce_buf, "", &plaintext, &short_out, &tag_out));
        try testing.expectError(error.InvalidInput, cp.aeadOpen(aead, key_buf[0..key_len], &nonce_buf, "", &plaintext, &tag_buf, &short_out));
    }
}

test "AEAD open zeroes the plaintext buffer on authentication failure from ciphertext, tag, or associated-data mutation" {
    var tp: TestProvider = undefined;
    tp.init(0x376);
    const cp = tp.cryptoProvider();
    const aeads = [_]provider.Aead{ .aes_128_gcm, .aes_256_gcm, .chacha20_poly1305 };
    for (aeads) |aead| {
        const key = [_]u8{0xAB} ** provider.max_aead_key_len;
        const nonce = [_]u8{0xCD} ** provider.aead_nonce_len;
        const ad = "associated data";
        const plaintext = "the quick brown fox jumps";
        var ciphertext: [plaintext.len]u8 = undefined;
        var tag: [provider.aead_tag_len]u8 = undefined;
        try cp.aeadSeal(aead, key[0..aead.keyLength()], &nonce, ad, plaintext, &ciphertext, &tag);

        {
            var bad_ct = ciphertext;
            bad_ct[0] ^= 0x01;
            var recovered: [plaintext.len]u8 = [_]u8{0xAA} ** plaintext.len;
            try testing.expectError(error.AuthenticationFailed, cp.aeadOpen(aead, key[0..aead.keyLength()], &nonce, ad, &bad_ct, &tag, &recovered));
            for (recovered) |b| try testing.expectEqual(@as(u8, 0), b);
        }
        {
            var bad_tag = tag;
            bad_tag[0] ^= 0x01;
            var recovered: [plaintext.len]u8 = [_]u8{0xAA} ** plaintext.len;
            try testing.expectError(error.AuthenticationFailed, cp.aeadOpen(aead, key[0..aead.keyLength()], &nonce, ad, &ciphertext, &bad_tag, &recovered));
            for (recovered) |b| try testing.expectEqual(@as(u8, 0), b);
        }
        {
            var recovered: [plaintext.len]u8 = [_]u8{0xAA} ** plaintext.len;
            try testing.expectError(error.AuthenticationFailed, cp.aeadOpen(aead, key[0..aead.keyLength()], &nonce, "different associated data", &ciphertext, &tag, &recovered));
            for (recovered) |b| try testing.expectEqual(@as(u8, 0), b);
        }
    }
}

test "AEAD seal/open round-trip zero-length and a harness-bounded maximum-length plaintext" {
    var tp: TestProvider = undefined;
    tp.init(0x376);
    const cp = tp.cryptoProvider();
    const aeads = [_]provider.Aead{ .aes_128_gcm, .aes_256_gcm, .chacha20_poly1305 };
    // Harness-chosen bound: AEAD itself has no wire-defined maximum plaintext
    // length the way a DER or QUIC varint length does (see the fuzz
    // contract's "Arithmetic safety" section).
    const max_len = 8192;
    for (aeads) |aead| {
        const key = [_]u8{0x5A} ** provider.max_aead_key_len;
        const nonce = [_]u8{0xA5} ** provider.aead_nonce_len;

        {
            var ciphertext: [0]u8 = undefined;
            var tag: [provider.aead_tag_len]u8 = undefined;
            try cp.aeadSeal(aead, key[0..aead.keyLength()], &nonce, "", "", &ciphertext, &tag);
            var recovered: [0]u8 = undefined;
            try cp.aeadOpen(aead, key[0..aead.keyLength()], &nonce, "", &ciphertext, &tag, &recovered);
        }

        {
            var plaintext: [max_len]u8 = undefined;
            for (&plaintext, 0..) |*b, i| b.* = @truncate(i);
            var ciphertext: [max_len]u8 = undefined;
            var tag: [provider.aead_tag_len]u8 = undefined;
            try cp.aeadSeal(aead, key[0..aead.keyLength()], &nonce, "ad", &plaintext, &ciphertext, &tag);
            var recovered: [max_len]u8 = undefined;
            try cp.aeadOpen(aead, key[0..aead.keyLength()], &nonce, "ad", &ciphertext, &tag, &recovered);
            try testing.expectEqualSlices(u8, &plaintext, &recovered);
        }
    }
}

fn fuzzAeadOpen(_: void, smith: *std.testing.Smith) anyerror!void {
    var tp: TestProvider = undefined;
    tp.init(0x376);
    const cp = tp.cryptoProvider();
    const aeads = [_]provider.Aead{ .aes_128_gcm, .aes_256_gcm, .chacha20_poly1305 };
    const aead = aeads[smith.index(aeads.len)];

    var key_buf: [64]u8 = undefined;
    var nonce_buf: [32]u8 = undefined;
    var tag_buf: [32]u8 = undefined;
    var ad_buf: [128]u8 = undefined;
    var ct_buf: [256]u8 = undefined;
    var pt_buf: [256]u8 = undefined;

    const key_len = smith.index(key_buf.len + 1);
    smith.bytes(key_buf[0..key_len]);
    const nonce_len = smith.index(nonce_buf.len + 1);
    smith.bytes(nonce_buf[0..nonce_len]);
    const tag_len = smith.index(tag_buf.len + 1);
    smith.bytes(tag_buf[0..tag_len]);
    const ad_len = smith.index(ad_buf.len + 1);
    smith.bytes(ad_buf[0..ad_len]);
    const ct_len = smith.index(ct_buf.len + 1);
    smith.bytes(ct_buf[0..ct_len]);

    @memset(&pt_buf, 0xAA);
    cp.aeadOpen(
        aead,
        key_buf[0..key_len],
        nonce_buf[0..nonce_len],
        ad_buf[0..ad_len],
        ct_buf[0..ct_len],
        tag_buf[0..tag_len],
        pt_buf[0..ct_len],
    ) catch |err| switch (err) {
        // A wrong-length field is an expected, benign rejection: the
        // provider never wrote to `pt_buf`, so nothing to check.
        error.InvalidInput => return,
        // The security-relevant contract this target exists to check: no
        // unauthenticated plaintext survives a failed authentication.
        error.AuthenticationFailed => {
            for (pt_buf[0..ct_len]) |b| {
                if (b != 0) return error.TestUnexpectedResult;
            }
            return;
        },
        // `aead` is always one of the three variants this provider
        // advertises support for; seeing this means the provider-contract
        // itself regressed, not that the fuzz input was malformed.
        error.UnsupportedCapability => return err,
    };
}

test "fuzz: AEAD open never leaves unauthenticated plaintext on arbitrary key/nonce/tag/ciphertext/AD" {
    try std.testing.fuzz({}, fuzzAeadOpen, .{ .corpus = &.{
        "",
        "\x00" ** 32,
        "\xff" ** 32,
        "\x00" ** 16 ++ "\xff" ** 16,
    } });
}

// ---------------------------------------------------------------------------
// Key exchange
// ---------------------------------------------------------------------------

test "deriveSharedSecret rejects wrong-length private scalars, peer public keys, and output buffers for every supported group" {
    var tp: TestProvider = undefined;
    tp.init(0x376);
    const cp = tp.cryptoProvider();
    const Case = struct { group: provider.Group, scalar_len: usize, peer_len: usize, out_len: usize };
    const cases = [_]Case{
        .{ .group = .x25519, .scalar_len = 32, .peer_len = 32, .out_len = 32 },
        .{ .group = .secp256r1, .scalar_len = provider.max_private_scalar_len, .peer_len = 65, .out_len = 32 },
    };
    const scalar_buf = [_]u8{0x01} ** provider.max_private_scalar_len;
    var peer_buf = [_]u8{0x04} ** provider.max_public_key_len;
    peer_buf[0] = 0x04;
    var out_buf: [provider.max_shared_secret_len]u8 = undefined;

    for (cases) |case| {
        try testing.expectError(error.InvalidInput, cp.deriveSharedSecret(case.group, scalar_buf[0 .. case.scalar_len - 1], peer_buf[0..case.peer_len], out_buf[0..case.out_len]));
        try testing.expectError(error.InvalidInput, cp.deriveSharedSecret(case.group, scalar_buf[0..case.scalar_len], peer_buf[0 .. case.peer_len - 1], out_buf[0..case.out_len]));
        try testing.expectError(error.InvalidInput, cp.deriveSharedSecret(case.group, scalar_buf[0..case.scalar_len], peer_buf[0..case.peer_len], out_buf[0 .. case.out_len - 1]));
    }
}

fn fuzzDeriveSharedSecret(_: void, smith: *std.testing.Smith) anyerror!void {
    var tp: TestProvider = undefined;
    tp.init(0x376);
    const cp = tp.cryptoProvider();
    const groups = [_]provider.Group{ .x25519, .secp256r1 };
    const group = groups[smith.index(groups.len)];

    var scalar_buf: [96]u8 = undefined;
    var peer_buf: [96]u8 = undefined;
    var out_buf: [96]u8 = undefined;

    const scalar_len = smith.index(scalar_buf.len + 1);
    smith.bytes(scalar_buf[0..scalar_len]);
    const peer_len = smith.index(peer_buf.len + 1);
    smith.bytes(peer_buf[0..peer_len]);
    const out_len = smith.index(out_buf.len + 1);

    cp.deriveSharedSecret(group, scalar_buf[0..scalar_len], peer_buf[0..peer_len], out_buf[0..out_len]) catch |err| switch (err) {
        error.InvalidInput => return,
        // `group` is always one of the two variants this provider supports.
        error.UnsupportedCapability => return err,
    };
}

test "fuzz: deriveSharedSecret never panics on arbitrary scalar and peer-public bytes" {
    try std.testing.fuzz({}, fuzzDeriveSharedSecret, .{ .corpus = &.{
        "",
        "\x00" ** 32,
        "\x04" ++ "\xff" ** 64,
    } });
}

fn fuzzGenerateKeyShare(_: void, smith: *std.testing.Smith) anyerror!void {
    var tp: TestProvider = undefined;
    tp.init(0x376);
    const cp = tp.cryptoProvider();
    const groups = [_]provider.Group{ .x25519, .secp256r1 };
    const group = groups[smith.index(groups.len)];

    var public_buf: [96]u8 = undefined;
    var private_buf: [96]u8 = undefined;

    const public_len = smith.index(public_buf.len + 1);
    const private_len = smith.index(private_buf.len + 1);

    cp.generateKeyShare(group, public_buf[0..public_len], private_buf[0..private_len]) catch |err| switch (err) {
        error.InvalidInput => return,
        // `group` is always supported and `tp`'s `DeterministicEntropy`
        // never fails, so an entropy/provider/capability failure here means
        // a real regression, not a benign fuzz outcome.
        error.UnsupportedCapability, error.EntropyFailure, error.ProviderFailure => return err,
    };
}

test "fuzz: generateKeyShare never panics on arbitrary output-buffer lengths" {
    try std.testing.fuzz({}, fuzzGenerateKeyShare, .{ .corpus = &.{
        "",
        "\x00",
        "\x20\x20",
        "\x41\x41",
    } });
}

// ---------------------------------------------------------------------------
// Signature verification
// ---------------------------------------------------------------------------

test "verify rejects malformed public key encodings for every supported scheme" {
    var tp: TestProvider = undefined;
    tp.init(0x376);
    const cp = tp.cryptoProvider();
    const message = "certificate verify transcript";

    {
        var key = try ed25519SigningKey(1);
        defer key.deinit();
        const signer = key.signingKey();
        var sig: [Ed25519.Signature.encoded_length]u8 = undefined;
        _ = try signer.sign(message, cp.entropy, &sig);

        const short_key = [_]u8{0} ** 31;
        try testing.expectError(error.InvalidInput, cp.verify(.ed25519, &short_key, message, &sig));
        const non_canonical = [_]u8{0xff} ** Ed25519.PublicKey.encoded_length;
        try testing.expectError(error.InvalidInput, cp.verify(.ed25519, &non_canonical, message, &sig));
    }

    {
        var key = try ecdsaSigningKey(2);
        defer key.deinit();
        const signer = key.signingKey();
        var sig_buf: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
        const sig_len = try signer.sign(message, cp.entropy, &sig_buf);

        const short_key = [_]u8{0} ** 10;
        try testing.expectError(error.InvalidInput, cp.verify(.ecdsa_secp256r1_sha256, &short_key, message, sig_buf[0..sig_len]));
        var bad_tag = key.publicKeySec1();
        bad_tag[0] = 0x00; // not a valid SEC1 point tag (0x02/0x03/0x04)
        try testing.expectError(error.InvalidInput, cp.verify(.ecdsa_secp256r1_sha256, &bad_tag, message, sig_buf[0..sig_len]));
    }

    {
        var key = try pure_zig.SoftwareRsaSigningKey.fromDer(rsa.testdata.private_key_pkcs1_der, cp.entropy);
        defer key.deinit();
        const signer = key.signingKey();
        var sig_buf: [provider.max_signature_len]u8 = undefined;
        const sig_len = try signer.sign(message, cp.entropy, &sig_buf);

        const short_key = [_]u8{0} ** 10;
        try testing.expectError(error.InvalidInput, cp.verify(.rsa_pss_rsae_sha256, &short_key, message, sig_buf[0..sig_len]));
    }
}

test "verify treats a malformed signature encoding as AuthenticationFailed for every supported scheme" {
    var tp: TestProvider = undefined;
    tp.init(0x376);
    const cp = tp.cryptoProvider();
    const message = "certificate verify transcript";

    {
        var key = try ed25519SigningKey(3);
        defer key.deinit();
        const public_key = key.publicKey();
        const short_sig = [_]u8{0x01} ** (Ed25519.Signature.encoded_length - 1);
        try testing.expectError(error.AuthenticationFailed, cp.verify(.ed25519, &public_key, message, &short_sig));
    }

    {
        var key = try ecdsaSigningKey(4);
        defer key.deinit();
        const public_key = key.publicKeySec1();
        const not_der = [_]u8{0xff} ** 8; // not a valid DER SEQUENCE
        try testing.expectError(error.AuthenticationFailed, cp.verify(.ecdsa_secp256r1_sha256, &public_key, message, &not_der));
    }

    {
        // A correct-length signature (matches the 2048-bit test modulus) but
        // out-of-range as an integer is `AuthenticationFailed`, not
        // `InvalidInput` -- unlike a wrong-*length* signature, which
        // `rsa.verifyPssSha256` rejects as `InvalidInput` before it ever
        // reaches this classification (see `src/crypto/rsa.zig`).
        const garbage_sig = [_]u8{0} ** 256;
        try testing.expectError(error.AuthenticationFailed, cp.verify(.rsa_pss_rsae_sha256, rsa.testdata.public_key_der, message, &garbage_sig));
    }
}

test "verify rejects a structurally valid but single-bit-modified signature for every supported scheme" {
    var tp: TestProvider = undefined;
    tp.init(0x376);
    const cp = tp.cryptoProvider();
    const message = "certificate verify transcript";

    {
        var key = try ed25519SigningKey(5);
        defer key.deinit();
        const signer = key.signingKey();
        var sig: [Ed25519.Signature.encoded_length]u8 = undefined;
        _ = try signer.sign(message, cp.entropy, &sig);
        sig[sig.len / 2] ^= 0x01;
        const public_key = key.publicKey();
        try testing.expectError(error.AuthenticationFailed, cp.verify(.ed25519, &public_key, message, &sig));
    }

    {
        var key = try ecdsaSigningKey(6);
        defer key.deinit();
        const signer = key.signingKey();
        var sig_buf: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
        const sig_len = try signer.sign(message, cp.entropy, &sig_buf);
        sig_buf[sig_len / 2] ^= 0x01;
        const public_key = key.publicKeySec1();
        try testing.expectError(error.AuthenticationFailed, cp.verify(.ecdsa_secp256r1_sha256, &public_key, message, sig_buf[0..sig_len]));
    }

    {
        var key = try pure_zig.SoftwareRsaSigningKey.fromDer(rsa.testdata.private_key_pkcs1_der, cp.entropy);
        defer key.deinit();
        const signer = key.signingKey();
        var sig_buf: [provider.max_signature_len]u8 = undefined;
        const sig_len = try signer.sign(message, cp.entropy, &sig_buf);
        sig_buf[sig_len / 2] ^= 0x01;
        try testing.expectError(error.AuthenticationFailed, cp.verify(.rsa_pss_rsae_sha256, rsa.testdata.public_key_der, message, sig_buf[0..sig_len]));
    }
}

test "verify rejects the correct signature under the wrong message for every supported scheme" {
    var tp: TestProvider = undefined;
    tp.init(0x376);
    const cp = tp.cryptoProvider();
    const message = "certificate verify transcript";
    const wrong_message = "a completely different transcript";

    {
        var key = try ed25519SigningKey(7);
        defer key.deinit();
        const signer = key.signingKey();
        var sig: [Ed25519.Signature.encoded_length]u8 = undefined;
        _ = try signer.sign(message, cp.entropy, &sig);
        const public_key = key.publicKey();
        try testing.expectError(error.AuthenticationFailed, cp.verify(.ed25519, &public_key, wrong_message, &sig));
    }

    {
        var key = try ecdsaSigningKey(8);
        defer key.deinit();
        const signer = key.signingKey();
        var sig_buf: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
        const sig_len = try signer.sign(message, cp.entropy, &sig_buf);
        const public_key = key.publicKeySec1();
        try testing.expectError(error.AuthenticationFailed, cp.verify(.ecdsa_secp256r1_sha256, &public_key, wrong_message, sig_buf[0..sig_len]));
    }

    {
        // No independent second RSA fixture exists in this repo (RSA
        // key-generation is out of scope for the provider); the wrong-key
        // sub-case above is exercised for Ed25519/ECDSA only.
        var key = try pure_zig.SoftwareRsaSigningKey.fromDer(rsa.testdata.private_key_pkcs1_der, cp.entropy);
        defer key.deinit();
        const signer = key.signingKey();
        var sig_buf: [provider.max_signature_len]u8 = undefined;
        const sig_len = try signer.sign(message, cp.entropy, &sig_buf);
        try testing.expectError(error.AuthenticationFailed, cp.verify(.rsa_pss_rsae_sha256, rsa.testdata.public_key_der, wrong_message, sig_buf[0..sig_len]));
    }
}

test "verify rejects the correct signature under an unrelated key for Ed25519 and ECDSA-P256" {
    var tp: TestProvider = undefined;
    tp.init(0x376);
    const cp = tp.cryptoProvider();
    const message = "certificate verify transcript";

    {
        var key = try ed25519SigningKey(9);
        defer key.deinit();
        var other = try ed25519SigningKey(10);
        defer other.deinit();
        const signer = key.signingKey();
        var sig: [Ed25519.Signature.encoded_length]u8 = undefined;
        _ = try signer.sign(message, cp.entropy, &sig);
        const other_public = other.publicKey();
        try testing.expectError(error.AuthenticationFailed, cp.verify(.ed25519, &other_public, message, &sig));
    }

    {
        var key = try ecdsaSigningKey(11);
        defer key.deinit();
        var other = try ecdsaSigningKey(12);
        defer other.deinit();
        const signer = key.signingKey();
        var sig_buf: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
        const sig_len = try signer.sign(message, cp.entropy, &sig_buf);
        const other_public = other.publicKeySec1();
        try testing.expectError(error.AuthenticationFailed, cp.verify(.ecdsa_secp256r1_sha256, &other_public, message, sig_buf[0..sig_len]));
    }
}

fn fuzzVerify(_: void, smith: *std.testing.Smith) anyerror!void {
    var tp: TestProvider = undefined;
    tp.init(0x376);
    const cp = tp.cryptoProvider();
    const schemes = [_]provider.SignatureScheme{ .ed25519, .ecdsa_secp256r1_sha256, .rsa_pss_rsae_sha256 };
    const scheme = schemes[smith.index(schemes.len)];

    var pk_buf: [600]u8 = undefined;
    var msg_buf: [128]u8 = undefined;
    var sig_buf: [600]u8 = undefined;

    const pk_len = smith.index(pk_buf.len + 1);
    smith.bytes(pk_buf[0..pk_len]);
    const msg_len = smith.index(msg_buf.len + 1);
    smith.bytes(msg_buf[0..msg_len]);
    const sig_len = smith.index(sig_buf.len + 1);
    smith.bytes(sig_buf[0..sig_len]);

    cp.verify(scheme, pk_buf[0..pk_len], msg_buf[0..msg_len], sig_buf[0..sig_len]) catch |err| switch (err) {
        error.InvalidInput, error.AuthenticationFailed => return,
        // `scheme` is always one of the three variants this provider
        // supports.
        error.UnsupportedCapability => return err,
    };
}

test "fuzz: verify never panics on arbitrary public key, message, and signature bytes" {
    try std.testing.fuzz({}, fuzzVerify, .{ .corpus = &.{
        "",
        "\x00" ** 32,
        "\x04" ++ "\xff" ** 64,
        rsa.testdata.public_key_der,
    } });
}

// ---------------------------------------------------------------------------
// Signing-key boundary
// ---------------------------------------------------------------------------

test "SigningKey.sign rejects an undersized output buffer without writing to it, for Ed25519" {
    var tp: TestProvider = undefined;
    tp.init(0x376);
    const cp = tp.cryptoProvider();
    var key = try ed25519SigningKey(13);
    defer key.deinit();
    const signer = key.signingKey();

    var out: [Ed25519.Signature.encoded_length - 1]u8 = [_]u8{0xEE} ** (Ed25519.Signature.encoded_length - 1);
    const before = out;
    try testing.expectError(error.InvalidInput, signer.sign("message", cp.entropy, &out));
    try testing.expectEqualSlices(u8, &before, &out);
}

test "SoftwareSigningKey.deinit wipes the retained Ed25519 private key bytes" {
    var key = try ed25519SigningKey(14);
    key.deinit();
    for (key.key_pair.secret_key.bytes) |b| try testing.expectEqual(@as(u8, 0), b);
}

test "SoftwareEcdsaP256SigningKey.deinit wipes the retained private key bytes" {
    var key = try ecdsaSigningKey(15);
    key.deinit();
    for (key.key_pair.secret_key.bytes) |b| try testing.expectEqual(@as(u8, 0), b);
}

// ---------------------------------------------------------------------------
// Shared secret helpers
// ---------------------------------------------------------------------------

fn fuzzFixedSecret(_: void, smith: *std.testing.Smith) anyerror!void {
    const Secret = secrets.FixedSecret(32);
    var secret = Secret{};
    defer secret.deinit();

    var scratch: [64]u8 = undefined;
    var iterations: usize = 0;
    while (iterations < 8 and !smith.eos()) : (iterations += 1) {
        const use_self_overlap = secret.len > 0 and smith.boolWeighted(1, 3);
        if (use_self_overlap) {
            const start = smith.index(secret.len);
            const take = smith.index(secret.len - start + 1);
            secret.replace(secret.slice()[start..][0..take]) catch |err| switch (err) {
                error.SecretTooLarge => unreachable, // a self-slice cannot exceed capacity
            };
        } else {
            const len = smith.index(scratch.len + 1);
            smith.bytes(scratch[0..len]);
            secret.replace(scratch[0..len]) catch |err| switch (err) {
                error.SecretTooLarge => continue, // len may exceed the 32-byte capacity
            };
        }

        if (secret.len > secret.bytes.len) return error.TestUnexpectedResult;
        for (secret.bytes[secret.len..]) |b| {
            if (b != 0) return error.TestUnexpectedResult;
        }
        var mirror = secret.copy();
        defer mirror.deinit();
        if (!secret.eql(&mirror)) return error.TestUnexpectedResult;
    }
}

test "fuzz: FixedSecret replace/eql/deinit preserve invariants under arbitrary overlapping and non-overlapping input" {
    try std.testing.fuzz({}, fuzzFixedSecret, .{ .corpus = &.{
        "",
        "\x00" ** 8,
        "\xff" ** 40,
    } });
}

fn fuzzBoundedSecret(_: void, smith: *std.testing.Smith) anyerror!void {
    const capacity = smith.index(64) + 1;
    var scratch: [64]u8 = undefined;
    const first_len = smith.index(capacity + 1);
    smith.bytes(scratch[0..first_len]);

    // Allocation-failure and leak-freedom path: `std.testing.allocator`'s
    // own leak checker, wrapped so we can inject an occasional failure on
    // `BoundedSecret`'s single capacity allocation and confirm no
    // partially-initialized secret escapes it or leaks. Biased toward
    // succeeding so most cases still reach the richer property loop below.
    {
        const should_fail = smith.boolWeighted(4, 1);
        const fail_index: usize = if (should_fail) 0 else 1;
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = fail_index });
        var leak_secret = secrets.BoundedSecret{};
        leak_secret.init(failing.allocator(), capacity, scratch[0..first_len]) catch |err| switch (err) {
            error.OutOfMemory => {
                leak_secret.deinit(); // must stay a safe no-op: nothing was allocated.
                return;
            },
            error.SecretTooLarge => unreachable, // first_len <= capacity by construction
        };
        leak_secret.deinit(); // std.testing.allocator's own leak checker asserts this ran.
    }

    // Byte-inspection path: replace/self-overlap/oversized/eql/deinit
    // properties against a `FixedBufferAllocator` so zeroization is directly
    // observable in backing memory, mirroring `src/crypto/secrets.zig`'s own
    // deterministic `BoundedSecret` tests. Every allocation below is freed
    // in strict LIFO order (nested `defer`s inside each sub-block, `secret`
    // itself only at the very end), so this backing buffer's bump pointer
    // never grows past 3 concurrent `capacity`-sized allocations regardless
    // of iteration count.
    var backing: [512]u8 align(8) = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&backing);
    var secret = secrets.BoundedSecret{};
    try secret.init(fba.allocator(), capacity, scratch[0..first_len]);

    var oversized_buf: [96]u8 = undefined;
    var iterations: usize = 0;
    while (iterations < 8 and !smith.eos()) : (iterations += 1) {
        const before_len = secret.len;
        var before_value: [64]u8 = undefined;
        @memcpy(before_value[0..before_len], secret.slice());

        const use_self_overlap = secret.len > 0 and smith.boolWeighted(1, 3);
        if (use_self_overlap) {
            const start = smith.index(secret.len);
            const take = smith.index(secret.len - start + 1);
            secret.replace(secret.slice()[start..][0..take]) catch |err| switch (err) {
                error.SecretTooLarge => unreachable, // a self-slice cannot exceed capacity
            };
        } else if (smith.boolWeighted(3, 1)) {
            // Oversized replacement: must always be rejected and must leave
            // the prior value completely untouched.
            const len = capacity + 1 + smith.index(oversized_buf.len - capacity);
            smith.bytes(oversized_buf[0..len]);
            secret.replace(oversized_buf[0..len]) catch |err| switch (err) {
                error.SecretTooLarge => {
                    if (secret.len != before_len) return error.TestUnexpectedResult;
                    if (!std.mem.eql(u8, secret.slice(), before_value[0..before_len])) return error.TestUnexpectedResult;
                    continue;
                },
            };
            return error.TestUnexpectedResult; // an oversized replace must never succeed
        } else {
            const len = smith.index(capacity + 1);
            smith.bytes(scratch[0..len]);
            secret.replace(scratch[0..len]) catch |err| switch (err) {
                error.SecretTooLarge => unreachable, // len <= capacity by construction
            };
        }

        // Replacement-tail clearing: every byte beyond the new length, up to
        // the full allocated capacity, must be zero in backing storage.
        if (secret.len > capacity) return error.TestUnexpectedResult;
        for (secret.bytes[secret.len..]) |b| {
            if (b != 0) return error.TestUnexpectedResult;
        }

        // Equal comparison.
        var mirror = secrets.BoundedSecret{};
        try mirror.init(fba.allocator(), capacity, secret.slice());
        defer mirror.deinit();
        if (!secret.eql(&mirror)) return error.TestUnexpectedResult;

        // Unequal (same-length, differing content) comparison.
        if (secret.len > 0) {
            var unequal = secrets.BoundedSecret{};
            var tweaked: [64]u8 = undefined;
            @memcpy(tweaked[0..secret.len], secret.slice());
            tweaked[0] +%= 1;
            try unequal.init(fba.allocator(), capacity, tweaked[0..secret.len]);
            defer unequal.deinit();
            if (secret.eql(&unequal)) return error.TestUnexpectedResult;
        }

        // Length-mismatched comparison.
        if (secret.len < capacity) {
            var longer = secrets.BoundedSecret{};
            var longer_buf: [64]u8 = undefined;
            @memcpy(longer_buf[0..secret.len], secret.slice());
            longer_buf[secret.len] = 0;
            try longer.init(fba.allocator(), capacity, longer_buf[0 .. secret.len + 1]);
            defer longer.deinit();
            if (secret.eql(&longer)) return error.TestUnexpectedResult;
        }
    }

    secret.deinit();
    if (secret.len != 0) return error.TestUnexpectedResult;
    // `deinit` hands the allocator genuinely zeroed bytes, not
    // `Allocator.free`'s undefined-poison -- inspect the FBA-backed bytes
    // directly (they are `secret`'s original, first-from-this-arena
    // allocation, so they sit at `backing[0..capacity]`).
    for (backing[0..capacity]) |b| {
        if (b != 0) return error.TestUnexpectedResult;
    }
}

test "fuzz: BoundedSecret replace/eql/deinit preserve invariants under arbitrary capacity and allocator-failure injection" {
    try std.testing.fuzz({}, fuzzBoundedSecret, .{ .corpus = &.{
        "",
        "\x00" ** 8,
        "\xff" ** 40,
    } });
}

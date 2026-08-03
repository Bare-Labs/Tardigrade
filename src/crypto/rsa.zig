//! Strict RSA-PSS-RSAE-SHA256 verification.

const std = @import("std");
const crypto = std.crypto;
const ff = crypto.ff;
const secrets = @import("crypto_secrets");

const Sha256 = crypto.hash.sha2.Sha256;
pub const max_modulus_bits = 4096;
pub const max_modulus_bytes = max_modulus_bits / 8;
const test_modulus_bytes = 256;

/// EMSA-PSS salt length this profile uses (matches the SHA-256 digest
/// length, per the strict `rsa_pss_rsae_sha256` profile both verify and sign
/// enforce).
pub const pss_salt_len = Sha256.digest_length;

pub const Error = error{InvalidInput};

/// Deterministic RSA-2048 fixture (self-signed `CN=tardigrade.test`,
/// generated with openssl — matches `credentials.testdata`'s certificate).
/// For unit tests and local smoke harnesses only — never a production key.
pub const testdata = struct {
    fn hexBytes(comptime hex: []const u8) [hex.len / 2]u8 {
        @setEvalBranchQuota(8192);
        var bytes: [hex.len / 2]u8 = undefined;
        _ = std.fmt.hexToBytes(&bytes, hex) catch unreachable;
        return bytes;
    }

    const private_key_pkcs1_bytes = hexBytes(
        "308204a4020100028201010092af7ce98c5ada061925562b8ad51c91242589053bc4d81283fb8b7f32ad27b1c0bbeff24e7126ec5d9956fd36c6621459cf5d99f8a6b7790d77a0a7480cb490db649a1882d89876c4eacf39aeef0dab58174dba46abcc948e4755b3f41aa045be5ce6382fefe7c7e0e6ad1c5f59d2c76ed2cbf5daff65d567609eb4daec1058c20ffa7c45db67146c95d36632ce793687b577003589ecafb8ab176d47781ac11d4434d56889d52b86bf3f87bc5893dbebde97dbdf58e57242a4cf4fbec148c0ede4faed1ebad450da2272bab56c48a7eacff3bd62e8685a00de2db458ed2b91f2453139c90dd3724ed82aa825f4dd4885f85ec0e09e1c72682db6fdd1b921e9020301000102820100225b8d680cd288e7cdc3038c7e5fcd69a7ac4d0c574413923eacd02f5278e167ceab9697cc4ccf9fa48ad2a7cbc92ad6f6744e49cec68a0a06200396bb1712c22d494298c42924890935b0a523b6e59e412b702ed5f7ce9aeb3a8535f9d2b4c0b146843c1bea570167c9d039699219ff51937967944ca71715b839644634eddce9700cde13717d98963cb2a4a2808c3b4add40a44df95f576500f3d82de9d25fe5e69ee08a0dc1599bbc7ae7681061126dc172427bbe22111c9faf2d0ca74728cdc3502b6aef8ecb26dccf0768055cece8079e516f15819c9d5ad056c6e8302d17d781392102dc09fbf8f813964a54646631e8fe3c27405f344c99505d539fa902818100cb8d33ac351529071f695efd67c9d3a5f3cfa76e42cee65a29b8a32f6b79b07679ecf138f82c3dfdb58cbf4609751b5b17478a60888503b4ebe61b3d459d00c933836d4271a7c8feff058c3667ce33f2236344e69c30b64cfdfcf59fdaabca6f2463d89ab842e44f0288f8e318d9c1250b9a57aa95db61134de7f129a44e9edd02818100b87b400d63d31ba7864de2bf3e7c8ce2af6c1c46620138a2c8a2a3fc52a687f2a991c549e3971c6e29f3605498268d35fecf5653f91e25c71112689474d9abe2eee2f7c74ac172c156c3d8e139fbf4de85888b5dbc810005a3fd2a9ca3d446f931e1d427633e702530d393521fbe6a8cc88915a2a49ff39faa2a320bde2ad07d02818100a95f00d41607597037cef1df61712acf37a45de8fd66337e6aa0dc082521c8978cb47fb3abad04980b6ce5eb5d0b388bff3ee401971737126007c43aa3a61475568bd16a2c3034ab1980803ef4f93b780bc21a1ed9701f00c986a6cb30a52978798b2b3cf27d9683b7d449648dd50345d3f5c56487f5573d3ce1f66573f687710281810089dba07be1130ae15f5da88a1d59d9b6343ce7cc38c48cdc286e5178e7128718f15a7b41c20f543186abd65aa0f07e29d166832e7144f41a1449db58c5113c7f72e0ad24825a99349d6ff10c2dd678a028cd66c7ff6baee6882b51c28832c36ec8b5e7621fa9b30837ba83a6a50e1875680df8daf78687f9d2a1819098cf09c902818043160afb78cc14e9b0b9ac88f83d72fbf75f9594c77d1dd0ecd98b4af5255d362bb74c0e7f0f9ed7fbc65aae99606326653afa099f7d4bbe039d45e5ceaacbab4bf4c21354e616aae47ad1032261a9abe0600c6f2687ff0235893b91513366867e99d21a80d3b16fffab975e99fd18645698bc104bfe206e0b11e45cbf729f11",
    );
    const public_key_bytes = hexBytes(
        "3082010a028201010092af7ce98c5ada061925562b8ad51c91242589053bc4d81283fb8b7f32ad27b1c0bbeff24e7126ec5d9956fd36c6621459cf5d99f8a6b7790d77a0a7480cb490db649a1882d89876c4eacf39aeef0dab58174dba46abcc948e4755b3f41aa045be5ce6382fefe7c7e0e6ad1c5f59d2c76ed2cbf5daff65d567609eb4daec1058c20ffa7c45db67146c95d36632ce793687b577003589ecafb8ab176d47781ac11d4434d56889d52b86bf3f87bc5893dbebde97dbdf58e57242a4cf4fbec148c0ede4faed1ebad450da2272bab56c48a7eacff3bd62e8685a00de2db458ed2b91f2453139c90dd3724ed82aa825f4dd4885f85ec0e09e1c72682db6fdd1b921e90203010001",
    );

    /// PKCS#1 `RSAPrivateKey` DER — the format `parsePrivateKeyDer` and
    /// `pure_zig.SoftwareRsaSigningKey.fromDer` accept directly.
    pub const private_key_pkcs1_der: []const u8 = &private_key_pkcs1_bytes;
    /// `RSAPublicKey` DER — the format `verifyPssSha256` accepts directly.
    pub const public_key_der: []const u8 = &public_key_bytes;
};

const PublicKey = struct {
    modulus: []const u8,
    exponent: []const u8,
    bits: usize,
};

fn lessThanUnsigned(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return a.len < b.len;
    return std.mem.order(u8, a, b) == .lt;
}

fn readLength(input: []const u8, offset: *usize) Error!usize {
    if (offset.* >= input.len) return error.InvalidInput;
    const first = input[offset.*];
    offset.* += 1;
    if (first < 0x80) return first;
    const count = first & 0x7f;
    if (count == 0 or count > 4 or offset.* + count > input.len) return error.InvalidInput;
    if (input[offset.*] == 0) return error.InvalidInput;
    var length: usize = 0;
    for (input[offset.* .. offset.* + count]) |byte| {
        length = (length << 8) | byte;
    }
    offset.* += count;
    if (length < 0x80 or length > input.len - offset.*) return error.InvalidInput;
    return length;
}

fn readInteger(input: []const u8, offset: *usize) Error![]const u8 {
    if (offset.* >= input.len or input[offset.*] != 0x02) return error.InvalidInput;
    offset.* += 1;
    const length = try readLength(input, offset);
    if (length == 0 or length > input.len - offset.*) return error.InvalidInput;
    const value = input[offset.* .. offset.* + length];
    offset.* += length;
    if (value.len > 1 and value[0] == 0 and value[1] & 0x80 == 0) return error.InvalidInput;
    if (value[0] & 0x80 != 0) return error.InvalidInput;
    return value;
}

fn parsePublicKey(der: []const u8) Error!PublicKey {
    if (der.len < 2 or der[0] != 0x30) return error.InvalidInput;
    var offset: usize = 1;
    const sequence_len = try readLength(der, &offset);
    if (sequence_len != der.len - offset) return error.InvalidInput;
    const sequence_end = offset + sequence_len;
    const modulus_encoded = try readInteger(der, &offset);
    const exponent_encoded = try readInteger(der, &offset);
    if (offset != sequence_end) return error.InvalidInput;

    if (modulus_encoded.len == 1 and modulus_encoded[0] == 0) return error.InvalidInput;
    if (exponent_encoded.len == 1 and exponent_encoded[0] == 0) return error.InvalidInput;

    var modulus = modulus_encoded;
    if (modulus[0] == 0) modulus = modulus[1..];
    if (modulus.len == 0 or modulus[0] & 0x80 == 0) return error.InvalidInput;

    const bits = modulus.len * 8;
    if (bits != 2048 and bits != 3072 and bits != 4096) return error.InvalidInput;
    var exponent = exponent_encoded;
    if (exponent[0] == 0) exponent = exponent[1..];
    if (exponent.len == 0 or !lessThanUnsigned(exponent, modulus)) return error.InvalidInput;
    if (exponent.len == 1 and exponent[0] < 3) return error.InvalidInput;
    if (exponent[exponent.len - 1] & 1 == 0) return error.InvalidInput;
    return .{ .modulus = modulus, .exponent = exponent, .bits = bits };
}

fn mgf1(seed: *const [Sha256.digest_length]u8, out: []u8) void {
    var counter: u32 = 0;
    var offset: usize = 0;
    var input: [Sha256.digest_length + 4]u8 = undefined;
    while (offset < out.len) : (counter += 1) {
        @memcpy(input[0..Sha256.digest_length], seed);
        std.mem.writeInt(u32, input[Sha256.digest_length..][0..4], counter, .big);
        var digest: [Sha256.digest_length]u8 = undefined;
        Sha256.hash(&input, &digest, .{});
        const count = @min(digest.len, out.len - offset);
        @memcpy(out[offset .. offset + count], digest[0..count]);
        offset += count;
    }
}

fn verifyPss(em: []const u8, em_bits: usize, message: []const u8) Error!void {
    const h_len = Sha256.digest_length;
    const salt_len = Sha256.digest_length;
    if (em.len < h_len + salt_len + 2) return error.InvalidInput;
    if (em[em.len - 1] != 0xbc) return error.InvalidInput;

    const db_len = em.len - h_len - 1;
    if (db_len > max_modulus_bytes) return error.InvalidInput;
    const masked_db = em[0..db_len];
    const h = em[db_len .. db_len + h_len];
    const unused_bits = 8 * em.len - em_bits;
    if (unused_bits > 7) return error.InvalidInput;
    // The guard makes the following cast safe because u3 represents 0..7.
    const unused_shift: u3 = @intCast(unused_bits);
    // This mask preserves the meaningful low bits and excludes the unused
    // high-order bits required to be zero by RFC 8017. With zero unused bits
    // it is intentionally 0xff.
    const unused_mask: u8 = @as(u8, 0xff) >> unused_shift;
    // RFC 8017 requires the unused high bits of maskedDB to be zero.
    if (masked_db[0] & ~unused_mask != 0) return error.InvalidInput;

    var m_hash: [h_len]u8 = undefined;
    Sha256.hash(message, &m_hash, .{});
    var db: [max_modulus_bytes]u8 = undefined;
    var mask: [max_modulus_bytes]u8 = undefined;
    const h_array = h[0..h_len].*;
    mgf1(&h_array, mask[0..db_len]);
    for (db[0..db_len], masked_db, mask[0..db_len]) |*out, masked, mask_val| out.* = masked ^ mask_val;
    // Clear the unused high bits of DB before checking its zero-padding PS.
    db[0] &= unused_mask;

    const ps_len = db_len - salt_len - 1;
    for (db[0..ps_len]) |byte| if (byte != 0) return error.InvalidInput;
    if (db[ps_len] != 1) return error.InvalidInput;

    var hash_input: [8 + h_len + salt_len]u8 = undefined;
    @memset(hash_input[0..8], 0);
    @memcpy(hash_input[8 .. 8 + h_len], &m_hash);
    const salt = db[ps_len + 1 ..][0..salt_len];
    @memcpy(hash_input[8 + h_len ..], salt);
    var expected: [h_len]u8 = undefined;
    Sha256.hash(&hash_input, &expected, .{});
    if (!secrets.constantTimeEqual(&expected, &h_array)) return error.InvalidInput;
}

/// Verify an RSA-PSS-RSAE-SHA256 signature.
///
/// `public_key_der` is a DER `RSAPublicKey` with a 2048-, 3072-, or 4096-bit
/// modulus. `signature` must be exactly one modulus wide. Malformed keys and
/// wrong-sized signatures return `error.InvalidInput`; a structurally valid
/// signature with invalid EMSA-PSS encoding returns `error.AuthenticationFailed`.
pub fn verifyPssSha256(public_key_der: []const u8, message: []const u8, signature: []const u8) (error{ InvalidInput, AuthenticationFailed })!void {
    const key = parsePublicKey(public_key_der) catch return error.InvalidInput;
    if (signature.len != key.modulus.len) return error.InvalidInput;

    var modulus_fe = ff.Modulus(max_modulus_bits).fromBytes(key.modulus, .big) catch return error.InvalidInput;
    const signature_fe = ff.Modulus(max_modulus_bits).Fe.fromBytes(modulus_fe, signature, .big) catch |err| switch (err) {
        error.NonCanonical => return error.AuthenticationFailed,
        else => return error.InvalidInput,
    };
    const recovered = modulus_fe.powWithEncodedPublicExponent(signature_fe, key.exponent, .big) catch return error.InvalidInput;
    var encoded: [max_modulus_bytes]u8 = undefined;
    recovered.toBytes(encoded[0..key.modulus.len], .big) catch return error.InvalidInput;
    verifyPss(encoded[0..key.modulus.len], key.bits - 1, message) catch return error.AuthenticationFailed;
}

// ---------------------------------------------------------------------------
// RSA private-key owner and RSA-PSS-RSAE-SHA256 signing.
// ---------------------------------------------------------------------------

/// An owned RSA private key, parsed and validated from a PKCS#1
/// `RSAPrivateKey` DER encoding. `parsePrivateKeyDer` requires `n = p·q`,
/// `p ≠ q`, `dP = d mod (p−1)`, `dQ = d mod (q−1)`, `qInv·q ≡ 1 (mod p)`, and
/// `e·d ≡ 1 (mod lcm(p−1, q−1))` before returning a key at all — see
/// `validateComponentRelationships`. Only `n`, `e`, and `d` are retained
/// after that check: the signing path below performs a direct constant-time
/// `d`-exponent modular exponentiation (`std.crypto.ff.Modulus.
/// powWithEncodedExponent`), not CRT, so `p`, `q`, `dp`, `dq`, and `qInv`
/// serve import-time validation only and are discarded once it passes — a
/// deliberate choice recorded in `docs/CRYPTO_SECURITY_AUDIT.md` (no CRT
/// side-channel/fault-injection surface, at the cost of CRT's speedup).
pub const PrivateKey = struct {
    n: [max_modulus_bytes]u8 = undefined,
    n_len: usize = 0,
    e: [max_modulus_bytes]u8 = undefined,
    e_len: usize = 0,
    d: [max_modulus_bytes]u8 = undefined,
    d_len: usize = 0,
    bits: usize = 0,

    /// Securely erase the retained private exponent. Callers must invoke this
    /// when the key is no longer needed; scope exit does not scrub memory.
    pub fn deinit(self: *PrivateKey) void {
        secrets.secureZero(&self.d);
    }

    pub fn format(
        _: PrivateKey,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        _: anytype,
    ) !void {
        @compileError("RSA private keys must not be formatted or logged");
    }

    pub fn modulusLen(self: *const PrivateKey) usize {
        return self.n_len;
    }

    fn modulus(self: *const PrivateKey) []const u8 {
        return self.n[0..self.n_len];
    }

    fn publicExponent(self: *const PrivateKey) []const u8 {
        return self.e[0..self.e_len];
    }

    fn privateExponent(self: *const PrivateKey) []const u8 {
        return self.d[0..self.d_len];
    }

    /// Whether `public_key_der` (a DER `RSAPublicKey`, as a certificate leaf
    /// exposes it) names the exact same modulus and public exponent as this
    /// private key — i.e. whether this key is actually usable to sign for
    /// that certificate. Strictly parses `public_key_der` first, so a
    /// malformed candidate never spuriously matches.
    pub fn matchesPublicKeyDer(self: *const PrivateKey, public_key_der: []const u8) bool {
        const parsed = parsePublicKey(public_key_der) catch return false;
        return std.mem.eql(u8, parsed.modulus, self.modulus()) and std.mem.eql(u8, parsed.exponent, self.publicExponent());
    }
};

fn stripLeadingZero(value: []const u8) []const u8 {
    return if (value.len > 1 and value[0] == 0) value[1..] else value;
}

/// Non-allocating (fixed stack scratch) arbitrary-precision validation of the
/// full RSA private-key component relationship set — not merely the
/// structural/range checks `parsePrivateKeyDer` performs on each field in
/// isolation. This is a one-time cost at key import, never on the
/// per-signature hot path (`signPssSha256` never calls this or touches `p`/
/// `q`/`dp`/`dq`/`qInv`), so an allocator-backed `std.math.big.int.Managed`
/// over a bounded `FixedBufferAllocator` is an acceptable, contained
/// exception to this module's otherwise allocation-free design; nothing here
/// is on a path an attacker can invoke repeatedly per handshake.
fn validateComponentRelationships(
    n: []const u8,
    e: []const u8,
    d: []const u8,
    p: []const u8,
    q: []const u8,
    dp: []const u8,
    dq: []const u8,
    qinv: []const u8,
) Error!void {
    const big = std.math.big.int;
    var scratch: [131072]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&scratch);
    const allocator = fba.allocator();

    const big_n = bigFromBytes(allocator, n) catch return error.InvalidInput;
    const big_e = bigFromBytes(allocator, e) catch return error.InvalidInput;
    const big_d = bigFromBytes(allocator, d) catch return error.InvalidInput;
    const big_p = bigFromBytes(allocator, p) catch return error.InvalidInput;
    const big_q = bigFromBytes(allocator, q) catch return error.InvalidInput;
    const big_dp = bigFromBytes(allocator, dp) catch return error.InvalidInput;
    const big_dq = bigFromBytes(allocator, dq) catch return error.InvalidInput;
    const big_qinv = bigFromBytes(allocator, qinv) catch return error.InvalidInput;

    if (big_p.eql(big_q)) return error.InvalidInput;

    // n == p * q
    var product = big.Managed.init(allocator) catch return error.InvalidInput;
    product.mul(&big_p, &big_q) catch return error.InvalidInput;
    if (!product.eql(big_n)) return error.InvalidInput;

    const one = big.Managed.initSet(allocator, 1) catch return error.InvalidInput;

    var p_minus_one = big.Managed.init(allocator) catch return error.InvalidInput;
    p_minus_one.sub(&big_p, &one) catch return error.InvalidInput;
    var q_minus_one = big.Managed.init(allocator) catch return error.InvalidInput;
    q_minus_one.sub(&big_q, &one) catch return error.InvalidInput;

    // dP == d mod (p - 1)
    var div_scratch = big.Managed.init(allocator) catch return error.InvalidInput;
    var d_mod_p1 = big.Managed.init(allocator) catch return error.InvalidInput;
    big.Managed.divTrunc(&div_scratch, &d_mod_p1, &big_d, &p_minus_one) catch return error.InvalidInput;
    if (!d_mod_p1.eql(big_dp)) return error.InvalidInput;

    // dQ == d mod (q - 1)
    var div_scratch2 = big.Managed.init(allocator) catch return error.InvalidInput;
    var d_mod_q1 = big.Managed.init(allocator) catch return error.InvalidInput;
    big.Managed.divTrunc(&div_scratch2, &d_mod_q1, &big_d, &q_minus_one) catch return error.InvalidInput;
    if (!d_mod_q1.eql(big_dq)) return error.InvalidInput;

    // qInv * q == 1 (mod p)
    var qinv_q = big.Managed.init(allocator) catch return error.InvalidInput;
    qinv_q.mul(&big_qinv, &big_q) catch return error.InvalidInput;
    var qinv_q_div = big.Managed.init(allocator) catch return error.InvalidInput;
    var qinv_q_mod_p = big.Managed.init(allocator) catch return error.InvalidInput;
    big.Managed.divTrunc(&qinv_q_div, &qinv_q_mod_p, &qinv_q, &big_p) catch return error.InvalidInput;
    if (!qinv_q_mod_p.eql(one)) return error.InvalidInput;

    // e * d == 1 (mod lcm(p - 1, q - 1)); lcm(a, b) = a*b / gcd(a, b).
    var gcd = big.Managed.init(allocator) catch return error.InvalidInput;
    big.Managed.gcd(&gcd, &p_minus_one, &q_minus_one) catch return error.InvalidInput;
    var totient_product = big.Managed.init(allocator) catch return error.InvalidInput;
    totient_product.mul(&p_minus_one, &q_minus_one) catch return error.InvalidInput;
    var lcm = big.Managed.init(allocator) catch return error.InvalidInput;
    var lcm_rem = big.Managed.init(allocator) catch return error.InvalidInput;
    big.Managed.divTrunc(&lcm, &lcm_rem, &totient_product, &gcd) catch return error.InvalidInput;

    var ed = big.Managed.init(allocator) catch return error.InvalidInput;
    ed.mul(&big_e, &big_d) catch return error.InvalidInput;
    var ed_div = big.Managed.init(allocator) catch return error.InvalidInput;
    var ed_mod_lcm = big.Managed.init(allocator) catch return error.InvalidInput;
    big.Managed.divTrunc(&ed_div, &ed_mod_lcm, &ed, &lcm) catch return error.InvalidInput;
    if (!ed_mod_lcm.eql(one)) return error.InvalidInput;
}

/// Load an unsigned big-endian byte string into a `std.math.big.int.Managed`
/// backed by `allocator` (expected to be a bounded `FixedBufferAllocator` —
/// see `validateComponentRelationships`).
fn bigFromBytes(allocator: std.mem.Allocator, bytes: []const u8) !std.math.big.int.Managed {
    const big = std.math.big.int;
    if (bytes.len == 0) return big.Managed.initSet(allocator, 0);
    const bit_count = bytes.len * 8;
    const limb_count = big.calcTwosCompLimbCount(bit_count) + 1;
    const limbs = try allocator.alloc(std.math.big.Limb, limb_count);
    var mutable = big.Mutable{ .limbs = limbs, .len = 1, .positive = true };
    mutable.readTwosComplement(bytes, bit_count, .big, .unsigned);
    return mutable.toManaged(allocator);
}

/// Parse and validate a PKCS#1 `RSAPrivateKey` DER encoding (the structure a
/// PKCS#8 `privateKey` OCTET STRING wraps for `rsaEncryption`). Only
/// two-prime keys (`version == 0`) with a 2048/3072/4096-bit modulus are
/// supported — multi-prime keys (`version == 1`, `otherPrimeInfos`) are
/// rejected, matching the narrower signing subset this profile enforces.
/// Beyond per-field structural/range checks, every component relationship
/// RFC 8017 requires is validated (see `validateComponentRelationships`)
/// before any private bytes are copied into the returned owner.
pub fn parsePrivateKeyDer(der: []const u8) Error!PrivateKey {
    if (der.len < 2 or der[0] != 0x30) return error.InvalidInput;
    var offset: usize = 1;
    const sequence_len = try readLength(der, &offset);
    if (sequence_len != der.len - offset) return error.InvalidInput;
    const sequence_end = offset + sequence_len;

    const version = try readInteger(der, &offset);
    if (version.len != 1 or version[0] != 0) return error.InvalidInput;

    const modulus_encoded = try readInteger(der, &offset);
    const exponent_encoded = try readInteger(der, &offset);
    const private_exponent_encoded = try readInteger(der, &offset);
    const prime1_encoded = try readInteger(der, &offset);
    const prime2_encoded = try readInteger(der, &offset);
    const exponent1_encoded = try readInteger(der, &offset);
    const exponent2_encoded = try readInteger(der, &offset);
    const coefficient_encoded = try readInteger(der, &offset);
    if (offset != sequence_end) return error.InvalidInput;

    if (modulus_encoded.len == 1 and modulus_encoded[0] == 0) return error.InvalidInput;
    const modulus = stripLeadingZero(modulus_encoded);
    if (modulus.len == 0 or modulus[0] & 0x80 == 0) return error.InvalidInput;
    const bits = modulus.len * 8;
    if (bits != 2048 and bits != 3072 and bits != 4096) return error.InvalidInput;

    const exponent = stripLeadingZero(exponent_encoded);
    if (exponent.len == 0 or !lessThanUnsigned(exponent, modulus)) return error.InvalidInput;
    if (exponent.len == 1 and exponent[0] < 3) return error.InvalidInput;
    if (exponent[exponent.len - 1] & 1 == 0) return error.InvalidInput;

    const private_exponent = stripLeadingZero(private_exponent_encoded);
    if (private_exponent.len == 0) return error.InvalidInput;
    if (private_exponent.len == 1 and private_exponent[0] == 0) return error.InvalidInput;
    if (!lessThanUnsigned(private_exponent, modulus)) return error.InvalidInput;

    const prime1 = stripLeadingZero(prime1_encoded);
    const prime2 = stripLeadingZero(prime2_encoded);
    const exponent1 = stripLeadingZero(exponent1_encoded);
    const exponent2 = stripLeadingZero(exponent2_encoded);
    const coefficient = stripLeadingZero(coefficient_encoded);
    inline for (.{ prime1, prime2, exponent1, exponent2, coefficient }) |component| {
        if (component.len == 0) return error.InvalidInput;
        if (component.len == 1 and component[0] == 0) return error.InvalidInput;
        if (!lessThanUnsigned(component, modulus)) return error.InvalidInput;
    }

    try validateComponentRelationships(modulus, exponent, private_exponent, prime1, prime2, exponent1, exponent2, coefficient);

    var key = PrivateKey{ .bits = bits };
    key.n_len = modulus.len;
    @memcpy(key.n[0..modulus.len], modulus);
    key.e_len = exponent.len;
    @memcpy(key.e[0..exponent.len], exponent);
    key.d_len = private_exponent.len;
    @memcpy(key.d[0..private_exponent.len], private_exponent);
    return key;
}

/// EMSA-PSS-SHA256 encode `message` with `salt` into `em` (`em.len` must be
/// the modulus size; `em_bits` is the modulus bit length minus one). Mirrors
/// `verifyPss` in reverse. Shared by the real signer and the decoder's own
/// direct-encoding tests.
fn encodePssSha256(message: []const u8, salt: [Sha256.digest_length]u8, em: []u8, em_bits: usize) void {
    const h_len = Sha256.digest_length;
    const db_len = em.len - h_len - 1;
    const ps_len = db_len - h_len - 1;

    var m_hash: [h_len]u8 = undefined;
    Sha256.hash(message, &m_hash, .{});

    var hash_input: [8 + h_len + h_len]u8 = undefined;
    @memset(hash_input[0..8], 0);
    @memcpy(hash_input[8 .. 8 + h_len], &m_hash);
    @memcpy(hash_input[8 + h_len ..], &salt);
    var h: [h_len]u8 = undefined;
    Sha256.hash(&hash_input, &h, .{});

    var db: [max_modulus_bytes]u8 = undefined;
    @memset(db[0..ps_len], 0);
    db[ps_len] = 1;
    @memcpy(db[ps_len + 1 .. db_len], &salt);

    var mask: [max_modulus_bytes]u8 = undefined;
    mgf1(&h, mask[0..db_len]);
    for (em[0..db_len], db[0..db_len], mask[0..db_len]) |*dst, value, mask_byte| {
        dst.* = value ^ mask_byte;
    }
    const unused_bits: u3 = @intCast(8 * em.len - em_bits);
    em[0] &= @as(u8, 0xff) >> unused_bits;
    @memcpy(em[db_len .. db_len + h_len], &h);
    em[em.len - 1] = 0xbc;
}

/// Sign `message` with `.rsa_pss_rsae_sha256`, using `salt` as the 32-byte
/// PSS salt. This function draws no randomness itself — `salt` must come from
/// the caller's injected `provider.Entropy` — and never writes to `out`
/// before every failure path (malformed key state, undersized `out`) has been
/// ruled out, so a rejected call never publishes a partial signature. Writes
/// exactly `key.modulusLen()` bytes and returns that length; `out` must be at
/// least that long.
///
/// The private-exponent modular exponentiation runs through
/// `std.crypto.ff.Modulus.powWithEncodedExponent` — the stdlib's
/// constant-time-oriented path for a secret exponent, as opposed to the
/// public-exponent-optimized path `verifyPssSha256` uses.
pub fn signPssSha256(key: *const PrivateKey, message: []const u8, salt: [Sha256.digest_length]u8, out: []u8) Error!usize {
    const modulus_bytes = key.n_len;
    if (out.len < modulus_bytes) return error.InvalidInput;

    var em: [max_modulus_bytes]u8 = undefined;
    defer secrets.secureZero(&em);
    encodePssSha256(message, salt, em[0..modulus_bytes], key.bits - 1);

    var modulus_fe = ff.Modulus(max_modulus_bits).fromBytes(key.modulus(), .big) catch return error.InvalidInput;
    const base_fe = ff.Modulus(max_modulus_bits).Fe.fromBytes(modulus_fe, em[0..modulus_bytes], .big) catch return error.InvalidInput;
    const signature_fe = modulus_fe.powWithEncodedExponent(base_fe, key.privateExponent(), .big) catch return error.InvalidInput;
    signature_fe.toBytes(out[0..modulus_bytes], .big) catch return error.InvalidInput;
    return modulus_bytes;
}

/// Encode a DER length for the short form or two-octet long form used by the
/// synthetic RSA keys below.
fn writeTestLength(out: []u8, offset: *usize, length: usize) void {
    // DER uses one length octet for values up to and including 127.
    if (length <= 0x7f) {
        out[offset.*] = @intCast(length);
        offset.* += 1;
    } else {
        out[offset.*] = 0x82;
        out[offset.* + 1] = @intCast(length >> 8);
        out[offset.* + 2] = @intCast(length & 0xff);
        offset.* += 3;
    }
}

/// Build an RSAPublicKey with a zero-filled modulus and the requested top byte.
/// `modulus_bytes` excludes the DER sign-padding byte; `modulus_top` controls
/// the high byte for valid-size and low-top-bit rejection cases.
fn makeTestPublicKey(out: []u8, exponent: []const u8, modulus_bytes: usize, modulus_top: u8) []const u8 {
    var offset: usize = 4;
    out[0] = 0x30;
    out[1] = 0x82;
    out[2] = 0;
    out[3] = 0;
    out[offset] = 0x02;
    offset += 1;
    writeTestLength(out, &offset, modulus_bytes + 1);
    out[offset] = 0;
    out[offset + 1] = modulus_top;
    @memset(out[offset + 2 .. offset + modulus_bytes + 1], 0);
    out[offset + modulus_bytes] = 1;
    offset += modulus_bytes + 1;
    out[offset] = 0x02;
    offset += 1;
    writeTestLength(out, &offset, exponent.len);
    @memcpy(out[offset .. offset + exponent.len], exponent);
    offset += exponent.len;
    const sequence_len = offset - 4;
    out[2] = @intCast(sequence_len >> 8);
    out[3] = @intCast(sequence_len & 0xff);
    return out[0..offset];
}

fn minimumTestModulus() [test_modulus_bytes]u8 {
    var modulus = [_]u8{0} ** test_modulus_bytes;
    modulus[0] = 0x80;
    modulus[modulus.len - 1] = 1;
    return modulus;
}

test "EMSA-PSS rejects every nonzero PS byte and structural corruption" {
    var encoded: [256]u8 = undefined;
    encodePssSha256("message", [_]u8{0x42} ** Sha256.digest_length, &encoded, 2047);
    try verifyPss(&encoded, 2047, "message");

    const db_len = encoded.len - Sha256.digest_length - 1;
    const ps_len = db_len - Sha256.digest_length - 1;
    for (0..ps_len) |position| {
        var corrupted = encoded;
        corrupted[position] ^= 1;
        try std.testing.expectError(error.InvalidInput, verifyPss(&corrupted, 2047, "message"));
    }

    var corrupted = encoded;
    corrupted[0] |= 0x80;
    try std.testing.expectError(error.InvalidInput, verifyPss(&corrupted, 2047, "message"));
    corrupted = encoded;
    corrupted[ps_len] ^= 1;
    try std.testing.expectError(error.InvalidInput, verifyPss(&corrupted, 2047, "message"));
    corrupted = encoded;
    corrupted[db_len] ^= 1;
    try std.testing.expectError(error.InvalidInput, verifyPss(&corrupted, 2047, "message"));
    corrupted = encoded;
    corrupted[ps_len + 1] ^= 1;
    try std.testing.expectError(error.InvalidInput, verifyPss(&corrupted, 2047, "message"));
    corrupted = encoded;
    corrupted[corrupted.len - 1] ^= 1;
    try std.testing.expectError(error.InvalidInput, verifyPss(&corrupted, 2047, "message"));
    try std.testing.expectError(error.InvalidInput, verifyPss(&encoded, 2047, "wrong message"));
}

test "RSA public-key DER rejects malformed encodings and unsupported moduli" {
    const exponent = [_]u8{ 1, 0, 1 };
    var der: [300]u8 = undefined;
    const key = makeTestPublicKey(&der, &exponent, test_modulus_bytes, 0x80);
    _ = try parsePublicKey(key);
    try std.testing.expectError(error.InvalidInput, parsePublicKey(&[_]u8{}));
    try std.testing.expectError(error.InvalidInput, parsePublicKey(&[_]u8{0x30}));
    try std.testing.expectError(error.InvalidInput, parsePublicKey(&[_]u8{ 0x30, 0x82, 0x01 }));
    try std.testing.expectError(error.InvalidInput, parsePublicKey(key[0 .. key.len - 1]));

    var nonminimal_length = der;
    nonminimal_length[2] = 0;
    try std.testing.expectError(error.InvalidInput, parsePublicKey(nonminimal_length[0..key.len]));
    var nonminimal_integer = der;
    nonminimal_integer[9] = 0;
    try std.testing.expectError(error.InvalidInput, parsePublicKey(nonminimal_integer[0..key.len]));

    var low_top_bit = der;
    low_top_bit[9] = 0x7f;
    try std.testing.expectError(error.InvalidInput, parsePublicKey(low_top_bit[0..key.len]));

    var unsupported_size: [300]u8 = undefined;
    const short_key = makeTestPublicKey(&unsupported_size, &exponent, 255, 0x80);
    try std.testing.expectError(error.InvalidInput, parsePublicKey(short_key));
}

test "RSA public-key DER enforces exponent range and parity" {
    const cases = [_][]const u8{
        &[_]u8{0},
        &[_]u8{1},
        &[_]u8{2},
        &[_]u8{4},
    };
    for (cases) |exponent| {
        var der: [300]u8 = undefined;
        try std.testing.expectError(error.InvalidInput, parsePublicKey(makeTestPublicKey(&der, exponent, test_modulus_bytes, 0x80)));
    }

    // 257 bytes matches the encoded 2048-bit modulus with its sign byte.
    var equal_size_exponent: [257]u8 = [_]u8{0} ** 257;
    // The leading sign byte makes this exponent equal in encoded size to n.
    equal_size_exponent[1] = 0x80;
    equal_size_exponent[equal_size_exponent.len - 1] = 1;
    var equal_size_der: [600]u8 = undefined;
    try std.testing.expectError(error.InvalidInput, parsePublicKey(makeTestPublicKey(&equal_size_der, &equal_size_exponent, test_modulus_bytes, 0x80)));
    var valid_large_exponent: [256]u8 = [_]u8{0xff} ** 256;
    valid_large_exponent[0] = 0x7f;
    var valid_large_der: [600]u8 = undefined;
    _ = try parsePublicKey(makeTestPublicKey(&valid_large_der, &valid_large_exponent, test_modulus_bytes, 0x80));
    equal_size_exponent[1] = 0xff;
    var greater_size_der: [600]u8 = undefined;
    try std.testing.expectError(error.InvalidInput, parsePublicKey(makeTestPublicKey(&greater_size_der, &equal_size_exponent, test_modulus_bytes, 0x80)));
    var exponent_too_long: [258]u8 = [_]u8{0} ** 258;
    exponent_too_long[1] = 0x80;
    var longer_der: [600]u8 = undefined;
    try std.testing.expectError(error.InvalidInput, parsePublicKey(makeTestPublicKey(&longer_der, &exponent_too_long, test_modulus_bytes, 0x80)));
}

test "RSA-PSS rejects short, long, and out-of-range signatures" {
    const exponent = [_]u8{ 1, 0, 1 };
    var der: [300]u8 = undefined;
    const key = makeTestPublicKey(&der, &exponent, test_modulus_bytes, 0x80);
    // This signature equals the minimum odd modulus used by the test key.
    const signature_equal_to_modulus = minimumTestModulus();
    const signature_greater_than_modulus = [_]u8{0xff} ** test_modulus_bytes;
    try std.testing.expectError(error.AuthenticationFailed, verifyPssSha256(key, "message", &signature_equal_to_modulus));
    try std.testing.expectError(error.AuthenticationFailed, verifyPssSha256(key, "message", &signature_greater_than_modulus));
    try std.testing.expectError(error.InvalidInput, verifyPssSha256(key, "message", signature_equal_to_modulus[0 .. signature_equal_to_modulus.len - 1]));
    var long_signature: [test_modulus_bytes + 1]u8 = undefined;
    try std.testing.expectError(error.InvalidInput, verifyPssSha256(key, "message", &long_signature));
}

// ---------------------------------------------------------------------------
// Private-key parsing and signing tests. Fixture: a real openssl-generated
// RSA-2048 key (`tardigrade.test`, see `credentials.zig`'s matching testdata
// certificate), so the signature-generation path is exercised against actual
// RSA arithmetic, not a synthetic key shaped only to satisfy the parser.
// ---------------------------------------------------------------------------

const test_private_key_pkcs1_der: []const u8 = testdata.private_key_pkcs1_der;
const test_public_key_der: []const u8 = testdata.public_key_der;

fn testKey() PrivateKey {
    return parsePrivateKeyDer(test_private_key_pkcs1_der) catch unreachable;
}

test "RSA-2048 private key signs a message the native verifier accepts" {
    var key = testKey();
    defer key.deinit();

    var out: [max_modulus_bytes]u8 = undefined;
    const salt = [_]u8{0x37} ** Sha256.digest_length;
    const len = try signPssSha256(&key, "tardigrade rsa-pss roundtrip", salt, &out);
    try std.testing.expectEqual(@as(usize, 256), len);
    try verifyPssSha256(test_public_key_der, "tardigrade rsa-pss roundtrip", out[0..len]);

    try std.testing.expectError(error.AuthenticationFailed, verifyPssSha256(test_public_key_der, "wrong message", out[0..len]));
    var tampered = out;
    tampered[0] ^= 0xff;
    try std.testing.expectError(error.AuthenticationFailed, verifyPssSha256(test_public_key_der, "tardigrade rsa-pss roundtrip", tampered[0..len]));
}

test "RSA-PSS signing draws a fresh salt each time and both signatures verify" {
    var key = testKey();
    defer key.deinit();

    var out_a: [max_modulus_bytes]u8 = undefined;
    var out_b: [max_modulus_bytes]u8 = undefined;
    const salt_a = [_]u8{0x11} ** Sha256.digest_length;
    const salt_b = [_]u8{0x22} ** Sha256.digest_length;
    const len_a = try signPssSha256(&key, "same message", salt_a, &out_a);
    const len_b = try signPssSha256(&key, "same message", salt_b, &out_b);

    try std.testing.expect(!std.mem.eql(u8, out_a[0..len_a], out_b[0..len_b]));
    try verifyPssSha256(test_public_key_der, "same message", out_a[0..len_a]);
    try verifyPssSha256(test_public_key_der, "same message", out_b[0..len_b]);
}

test "signPssSha256 rejects undersized output and leaves it untouched" {
    var key = testKey();
    defer key.deinit();

    var out = [_]u8{0xaa} ** 255; // one byte short of the 256-byte RSA-2048 signature
    const before = out;
    try std.testing.expectError(error.InvalidInput, signPssSha256(&key, "m", [_]u8{0} ** Sha256.digest_length, &out));
    try std.testing.expectEqualSlices(u8, &before, &out);
}

test "PrivateKey.deinit wipes the retained private exponent" {
    var key = testKey();
    try std.testing.expect(key.d_len > 0);
    key.deinit();
    for (key.d) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
}

fn corruptedPrivateKey(comptime mutate: fn (buf: []u8) void) [test_private_key_pkcs1_der.len]u8 {
    var buf = testdata.private_key_pkcs1_bytes;
    mutate(&buf);
    return buf;
}

test "RSA private-key DER rejects a wrong version, malformed integers, and out-of-range components" {
    // Multi-prime (version 1) keys are outside the supported signing subset.
    const multi_prime = corruptedPrivateKey(struct {
        fn mutate(buf: []u8) void {
            buf[6] = 1; // the version INTEGER's content byte
        }
    }.mutate);
    try std.testing.expectError(error.InvalidInput, parsePrivateKeyDer(&multi_prime));

    // Truncated DER.
    try std.testing.expectError(error.InvalidInput, parsePrivateKeyDer(test_private_key_pkcs1_der[0 .. test_private_key_pkcs1_der.len - 1]));

    // Trailing garbage after the SEQUENCE's declared content is rejected by
    // the exact-length check on the outer TLV.
    var with_trailer: [test_private_key_pkcs1_der.len + 1]u8 = undefined;
    @memcpy(with_trailer[0..test_private_key_pkcs1_der.len], test_private_key_pkcs1_der);
    with_trailer[test_private_key_pkcs1_der.len] = 0;
    try std.testing.expectError(error.InvalidInput, parsePrivateKeyDer(&with_trailer));

    try std.testing.expectError(error.InvalidInput, parsePrivateKeyDer(&[_]u8{}));
    try std.testing.expectError(error.InvalidInput, parsePrivateKeyDer(&[_]u8{0x30}));
}

test "RSA private-key DER rejects every component mutation that breaks a required relationship" {
    // Each offset is the last (least-significant) byte of the named field in
    // the fixture's PKCS#1 encoding — flipping it keeps the field the same
    // length, still nonzero, and still less than the modulus (all range
    // checks parsePrivateKeyDer already enforces stay satisfied), so only
    // `validateComponentRelationships`'s mathematical checks can catch it.
    const mutations = [_]struct { name: []const u8, offset: usize }{
        .{ .name = "n (breaks n = p*q)", .offset = 267 },
        .{ .name = "d (breaks dP/dQ/e*d relations)", .offset = 532 },
        .{ .name = "p (breaks n = p*q)", .offset = 664 },
        .{ .name = "q (breaks n = p*q)", .offset = 796 },
        .{ .name = "dp (breaks dP = d mod (p-1))", .offset = 928 },
        .{ .name = "dq (breaks dQ = d mod (q-1))", .offset = 1060 },
        .{ .name = "qinv (breaks qInv*q = 1 mod p)", .offset = 1191 },
    };
    for (mutations) |case| {
        var buf = testdata.private_key_pkcs1_bytes;
        buf[case.offset] ^= 0x01;
        var key = parsePrivateKeyDer(&buf) catch continue;
        key.deinit();
        std.debug.print("mutation accepted but should have been rejected: {s}\n", .{case.name});
        return error.TestUnexpectedResult;
    }
}

test "RSA private-key DER rejects p == q" {
    var buf = testdata.private_key_pkcs1_bytes;
    // Overwrite q's content bytes with p's (same length at these offsets in
    // the fixture: both primes are 129 bytes), keeping DER framing intact.
    const p_start = 536;
    const q_start = 668;
    const prime_len = 129;
    @memcpy(buf[q_start .. q_start + prime_len], buf[p_start .. p_start + prime_len]);
    try std.testing.expectError(error.InvalidInput, parsePrivateKeyDer(&buf));
}

test "matchesPublicKeyDer requires exact modulus and exponent equality" {
    var key = testKey();
    defer key.deinit();
    try std.testing.expect(key.matchesPublicKeyDer(test_public_key_der));

    var tampered_pub: [test_public_key_der.len]u8 = undefined;
    @memcpy(&tampered_pub, test_public_key_der);
    tampered_pub[20] ^= 0xff;
    try std.testing.expect(!key.matchesPublicKeyDer(&tampered_pub));

    try std.testing.expect(!key.matchesPublicKeyDer(&[_]u8{0x30}));
    try std.testing.expect(!key.matchesPublicKeyDer(&[_]u8{}));
}

test "RSA-3072 and RSA-4096 private keys sign messages the native verifier accepts" {
    const fixtures = [_]struct { private_der_hex: []const u8, public_der_hex: []const u8, expected_len: usize }{
        .{
            .private_der_hex = "308206e20201000282018100e800096b8f3f7bd7a554864555caef671fa090451f2ff3a42f47886f9f03a68656d035adce2a5703ca04bbdd9f23944763333f2bdffb15148f9e5e91fe05e8f7981fa5f2f04ad5cf3f7b158d436c38811d16b3dac45dce27dff3a853d5534d5ec849b8333def6974045262768009fde8edcc85c4b844edbaeb519608dc6b92108085a135d8028effabe702eb2911187ab592eddbe15dedb5429796bb4f5105a27914c9f33a63cf96d1cc4a2c615272d90d937997bee6a441b132c03f8fa3a095f7c4f841776af158420b4f5a9cb7c8aff2cd2f4f33e1316e7354f0946cfcb670f0df1bca6c08c593be0ca7d361fc897bd86ea078e548bdb5ecdeba9eee6dca991aa265e83bc59172b7a06d820fabc6615eacef576bb6ccdb382ea59f55da1b7abe678047eed12f6b6f9f1927826a5261ebd6199c1015d07de3bd4cacee005737d85fac51c0d5ba7c4c88e192837300a6b50a047774d13967e941c5eda5d3f44061092ba6bf612661b455e175964a17399c2cf20dd5c6d978baeb9e34bedbdf990203010001028201806bbcdca30d0e73b204ceb85e0985e8e070710d9e73e9be51003dcd6fdc9e02debf0108f49259da37e1c08a07d4e7de6bba77297e7410f34cad97639e93a365f959355548f8eb1fd89347d30ddb822dc953db5fa197f06214e56d0f3e0342a09b04132c0debd4bb198c0a403c7ca067401cf28e2a7952553e291aa5bcaeb3ebcc6b0ae37f1035bbf7a27a70c2093badad0a96558c775fb9cca3c4a6d48c747953e6bbcf3efb5e2fa08004496bcbb450ae589e2468e257d46ec75de4a67fcb827e500a0f36a3bfb9a78acdd956ca2b38c19bfbfdb896a4415a9c28460103899560c4a73d3105fdfb5d4c4238f56e118233c2df1e73315907b39dd49de39a8de2d0593f640618e03e32aca1686b2e98cddddfc3f08c0dc050ad7c7b1dacbf7087be7cce07964b09281a8587015b605903f44aea1ea6d307923362f099a5ab6f6a829bbb2b671e6f373377825edd4ba51e8444b6e8796196118522974069b4e6834576690743914f2684e927ca4cefe9c514e684cbf7ac06596712e98b86f035767b0281c100f601496b66e1da895c2eda926458b03af7881b04de294f8b69fefc75427ffa234e778382a10db44d3d3eaa35a42a22352b25411a388f7fcf68b682e5a37e2d3cae26301505db5c67be4d0472f9b6c831ab88324565698d86b6977421c12a15169f22ab304f0f1a4346943fdab9c7e3cb83bf8817d29a09dace65f851d5c14852f152a76c6c8d9997b449f320f378aaa4198224e4129bdce6002e958eca324f5505d6190e29fdec4ff273b54e0c0137f170fc60a310bd214c7b33f64ea4632b530281c100f16d15990f7a0efcc987253de26e567b0a3cbde1eb7500a50900121d60cfe8c48a0842982bf4fa8fde0552eecc7abd99e20608118149f61b65187c7e928d38e2343d5949be00747baf737981c27c4be83af50f3beb796f0218ebd0e3c683d89fbad913e3cee24f669e6dce95ad1675301e9c34a76c89d126db5a3161fa951995c09ff0052e46979d998e207726db14e7f4283866176375b096d404bc778a82d948585e27e1a0aec85fb831fa3e0ecebf66a624e9c109c204e7d765adecd817e30281c003273111b757ddbd34f944c3eb95576cea0f4c895b6f9c1d65566755f96c3a808958eece95d1df25be4b375348af6190dce4b558e8b0ae2ab264e4789d07d8fc961ed72eedcc49faea6d824916fa48c69a343cb0b7040b5456b2ca42447f8d95a4a4851d31663827f497a1d9e3d7b40bbfbc8cba017107ff4df5f0a0dbe48650c9d70d5e4e65e23a178d7b1849069ae94f8a637ea8de668e6c222cb88fcee54569b5bccc79ad4f8216d174d9733df0c19f791ca3fa6af22a50c9f1b6405525110281c04a299c4cdc783e4a610de6decfc3dd4506ac0a1870600cc6a5b123df6a71f3ab0c4be5492197abb0ae1f2c8eb6b9adacabc5f68c8a0ed24f300b09934829a1a3bb306d513dd09df7b0b9e4457c1cfaa468180789fc97dd05e3e9eccd4b9a0cdd646472bbb43dc8ee59149a35586a61ad5a79d9a2e4b0a1533266ce6caeb1469ebe016395f3d53395f229bac75f644553cba8df4a5d3cec5646bef28582a345f6c1468405f4458beb799bf79e4b99f8e0cb0396ab47e55b786e4fb8a868ed28c90281c02af5ab8888006123dfba060cb2d761039569a87a50a75fe7bf979692e30af428fab0edd939c3ec5339ce22bbcbee01d3c717afd9f5e3e415c4e107a9f0f12b09ae1be9a5839361673c975f33419932935dcc1347ef61c853e55e6d9d5960d9f44acf3cce8009b1be39fb3664d8637c558784baeeac708b1bd7b90b9639281ce82ac72f5d5dc8caaa286aa5cfd1e2e15dcf15bdf406b76cb564ea2c678ca7c9d62c4cc4a86930c461144b1bbeb63be75c1dbd99fac0aa0def20197f4b3397a9d3",
            .public_der_hex = "3082018a0282018100e800096b8f3f7bd7a554864555caef671fa090451f2ff3a42f47886f9f03a68656d035adce2a5703ca04bbdd9f23944763333f2bdffb15148f9e5e91fe05e8f7981fa5f2f04ad5cf3f7b158d436c38811d16b3dac45dce27dff3a853d5534d5ec849b8333def6974045262768009fde8edcc85c4b844edbaeb519608dc6b92108085a135d8028effabe702eb2911187ab592eddbe15dedb5429796bb4f5105a27914c9f33a63cf96d1cc4a2c615272d90d937997bee6a441b132c03f8fa3a095f7c4f841776af158420b4f5a9cb7c8aff2cd2f4f33e1316e7354f0946cfcb670f0df1bca6c08c593be0ca7d361fc897bd86ea078e548bdb5ecdeba9eee6dca991aa265e83bc59172b7a06d820fabc6615eacef576bb6ccdb382ea59f55da1b7abe678047eed12f6b6f9f1927826a5261ebd6199c1015d07de3bd4cacee005737d85fac51c0d5ba7c4c88e192837300a6b50a047774d13967e941c5eda5d3f44061092ba6bf612661b455e175964a17399c2cf20dd5c6d978baeb9e34bedbdf990203010001",
            .expected_len = 384,
        },
        .{
            .private_der_hex = "3082092a0201000282020100c2ef91e889e9c4b94fb8a70abecb6fd6c70778308f17c4e6bbf59920e5fcdd09daef7a6427a779bc8cc53b4b447f89698d224ef9ab73fded5abcb036cec7d4ad575917843bfcdb3c02d38456ad7cf64d8ce73572291ca8118eefb62d9228daceb94a04a496a9cce53caa8c067ca403a1c3b7d278fd2ab9b93d5eb3c80eea4af0f674c794a62215b4a41d60a2139d8176537c1b431f870d6fcd6ff4f08ca5a69519765f7d98c218d3384d566fdb2ecddfdaa0d2df184bf07d5c8c0f2f0728bb2ee5393bc1ac6ec49bc9795b278b9043bb8c64cf07dcbcaae914b18b07e80d155cfd89c1b4552c01e7c786b13927934e8ffaa5910c5ba677e55330fa6b3c7d4268d755bd685147794b24572a9b887e95da2fd85cbb3ac797d3e6b5d6f859a0db78731e5e9c153ba9f4ddaf420f321139ed1a5a42a1c38b5008955c3a54349f084a60b713dbf28bfabc61e43bd1448788d3d6ebf06d472b1c8bbca8abef50871484b112a7d82bc77a3db55700c1acadf308d1d63b2ebd073a0691486da19f0e0183af511c9f78867499a0c76a5eace805346e65db4c533537beb849a4710e3aa8a134dcf8a0c377016ccf4774874ed565055702207734ab78a2fb2687333c78b434b7b503709e0c21aa028e829320de35cf40e680b413caf5964d052b706c0e514e1aaed70cb35dbe114d7deaa75bf127d12c9d4ecddc6876f0ad7b25ba662bbb810203010001028202004f9de77b1170f00f3bd7502a5c58dcb9dd1a58e5845c11e8a7561d0fc9bf684c1126845789b6a64af337cf0ae3d42f3c740f523038edac05986cbe8ff40ebbf77c587ff95b42e00bf79f8a4a989b1442024da08f9ae9006003803669106c2d4a07758ac5ea5f39b75afad12c0916380186dd7a523e1c8834773349bc69131a3ea67a75d569b13c2a466955417d3f7453eeaf1eb76096194fd3996972220fba24e57c6a6df2c93bb871236d2d4c59266eca6dab12c16aaab398ebff7b96b1f519a737a4076b34e68a3654a17d5a4c36cdcffe906c46a4ac2d7c6d333aac754387726a243a521b2240174714f5220bd1278f18b65054d27ddfa505b911b967f38a05d73f33003811d3d1ecae65fabdd889ee46d6afbef93190ba141f6c765a2ebffd8c158cbedd05f73a682897fb98c6d4f8a964867e218b959bd3e3c154e8054da404d84e494443510559d85f7d62249b3caa683c472986fe0e315d4616b41103d521e5a499042da315cd3596b6afb3b3ac68448b69e2febd0d3ccc9a8a41b2b908d6c0c2862b57cc69082cd05a24c27e2dcb45a0138bba71cc5cf484d8ad81d33c6e997670c8734e3ad8f0e406a17b453e679d2c9e588a872d1d2b43a277b8563c6a852cf3f5e95ade32cfe83a16a28504462c814218c8143373cb7ffdeb394639897c5e74756ab626e4f339cd2fcd0622e78c8bcfa37c636bb3b10b763d4a3d0282010100e9a1c11ec85ae80811ff6e8a9aa59bcce3625ecf71ccf3bffbc329293b2aec8de07c5236cb8e20ee1015e7a5bd9e58c24548e8c954c37a79bd058aa2f03e0c98e06919bcd6694a486b4a0761fa39ab6e988dce05fd3e53065d1d4e5a86e769e4b148965f933e9e49db23c0bf67e39bc7c7a9094227692373c07a0a00b3c3352552ce1e700760304dd432352333615bbdcac60554075b3184cc9c0b4ee855fc796175dd4717e88e249a7b5f4964683c58234c575e1e0894b2ab2469649ff82688c715795f2124beb12f2e4ebe4e9ccc1c894b2ed981fe9f1d9632c98d7985f6a0e4d69fc6c348c1be354216ae9ce4ab0bfe0988975ce14dcb5df2a5f30b97834f0282010100d5996338ed7fa47541a43bee421940fb172e9658c2be709ae3786863496f68dd8b3377e595ca5f55aa17fd83eaabfde3f54df9b7f75845cf328836776875e35b2ed085d26436d83a1d1e30dd38abefc3aaa2c1d43cfc9853e321b518e05d8d9bd66135e54b4c3a058d17a01bdc00c8f9e6ccc07f7bcce374114c3be7eeea2775767117c9191fa131986a445915d6d730883cff4d604ab528185a9f355c39194b0264708204b4242979c08aadc0991db592d83faba202db5f3fbc903442a02ef81c308b13dbc5473f7d28c4b75ac87d3da07f8c46b6b21f028e22f3392c2c42ad1b5fc9670094c4d1b4f54fb698fce07c3a72fe7bee5f3ff4f1d07884a6d3602f0282010100943ee85cd10325f2610134b24c58c358a9fbf46f2b25c291527e4eb2f3f153b2defbe3eb1314b77e77c47e7da3a94366da31de4c4a35d39445c5ab67a28bacd0a0acf000ec0859734468eff052a79f49091209e5b100880c24af80d55e7e9ea9d77858ba82a31c2b7f1adba658948b77a41075687dbb701c75c8ba6a21a6bf2554baa783ac9a736c1f3650936a79df8db98a173d6f8185156003b0053cd5bae3865d14b094d222c7c5227d9f035044e2245bbfa05fec4ff6633432900015a4d5eb858bc33a33a7b0a4607ce4b2db3984edf53fe012656faf856bea8a93ced664d76ffc6851e7ebcff6d95dad24aed07e468ee4162f80632da50a6014ad89516f0282010100bda403ae255eb05ad2bec7decf9cb04ebdd444f3e5634382a0f6e4675269b1c710b1cf7f6cb05258323e3e7d02bb551d314bdbac73d45196961ccd8ed295e817aac6c42979842011e88c478201b0d59cf940abaa8dc30e535c532f003923967887aba33842d418a7990f22bdd964710b3ed90707a898ce50dc92bc953d4f735d1c9d682ac93d85d60ca63cac83714d78ef5c88a6e0193421b70dae50a7e2a20c30c1900a3fb6d86c62868a199de7d3b2c3ff6ef8294d340bab00f55f10d03b235993d7c6f7d67d5d66f7ed3f85407fc1596024e11b8fa56c95597e6c824581a543aa959bf7ae1dd8ba3b1a5cda139a1371a96b3c08f554495af066301015974d0282010100a7efc741dc4a8dbce9edbaa5d0eb91394cf8733577d2ee2cc439140c84f3f4c49c6c3420c5a10ca38651268cbfbf502703734b4a08d8f958698e1d0c144a4c5193105fd138eb1a90eeaf41010979ba6b1db4382ef8845e7a6b7259e18a912a5ac9882c27e9f21fd6899dd1df4a12a83b582b883f36c8781c9147fe632efaecb0d70972769f0ae263fec93a1f89cf12ecaec0656cbcb5a969ff5845f989f5ae199c1e6c9614b0e662eec2104fa950b38b2bd9358739cd0ae95ca60db2d37dd51dc54ce2d7e1bc4f6bea7a98523bc9d4f047a3ccc2c614b3897b7e16860ff4a23d071a49e593f5bbb1166dd42a0bb5a3fab6d9f07fc8f2a5a9f31f6708595ffbb8",
            .public_der_hex = "3082020a0282020100c2ef91e889e9c4b94fb8a70abecb6fd6c70778308f17c4e6bbf59920e5fcdd09daef7a6427a779bc8cc53b4b447f89698d224ef9ab73fded5abcb036cec7d4ad575917843bfcdb3c02d38456ad7cf64d8ce73572291ca8118eefb62d9228daceb94a04a496a9cce53caa8c067ca403a1c3b7d278fd2ab9b93d5eb3c80eea4af0f674c794a62215b4a41d60a2139d8176537c1b431f870d6fcd6ff4f08ca5a69519765f7d98c218d3384d566fdb2ecddfdaa0d2df184bf07d5c8c0f2f0728bb2ee5393bc1ac6ec49bc9795b278b9043bb8c64cf07dcbcaae914b18b07e80d155cfd89c1b4552c01e7c786b13927934e8ffaa5910c5ba677e55330fa6b3c7d4268d755bd685147794b24572a9b887e95da2fd85cbb3ac797d3e6b5d6f859a0db78731e5e9c153ba9f4ddaf420f321139ed1a5a42a1c38b5008955c3a54349f084a60b713dbf28bfabc61e43bd1448788d3d6ebf06d472b1c8bbca8abef50871484b112a7d82bc77a3db55700c1acadf308d1d63b2ebd073a0691486da19f0e0183af511c9f78867499a0c76a5eace805346e65db4c533537beb849a4710e3aa8a134dcf8a0c377016ccf4774874ed565055702207734ab78a2fb2687333c78b434b7b503709e0c21aa028e829320de35cf40e680b413caf5964d052b706c0e514e1aaed70cb35dbe114d7deaa75bf127d12c9d4ecddc6876f0ad7b25ba662bbb810203010001",
            .expected_len = 512,
        },
    };

    inline for (fixtures) |fixture| {
        const private_bytes = comptime hexBytesForTest(fixture.private_der_hex);
        const public_bytes = comptime hexBytesForTest(fixture.public_der_hex);
        var key = try parsePrivateKeyDer(&private_bytes);
        defer key.deinit();
        try std.testing.expectEqual(fixture.expected_len, key.modulusLen());
        try std.testing.expect(key.matchesPublicKeyDer(&public_bytes));

        var out: [max_modulus_bytes]u8 = undefined;
        const salt = [_]u8{0x5c} ** Sha256.digest_length;
        const len = try signPssSha256(&key, "multi-size RSA-PSS fixture", salt, &out);
        try std.testing.expectEqual(fixture.expected_len, len);
        try verifyPssSha256(&public_bytes, "multi-size RSA-PSS fixture", out[0..len]);
    }
}

fn hexBytesForTest(comptime hex: []const u8) [hex.len / 2]u8 {
    @setEvalBranchQuota(16384);
    var bytes: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, hex) catch unreachable;
    return bytes;
}

test "RSA private-key DER deterministically rejects an unsupported 1024-bit modulus" {
    const key_bytes = hexBytesForTest(
        "3082025d02010002818100d400a728e179458c0ce88301df9f5c99fc684a02986ece5c255c1b72b36b0d0135bf1c2aadf7153c196d182b7abea4b91d03d33b8e3653ff7b58b31b0d621d58044f7c87e56c5e916cd05a248d00c91507bcd9471149d4b4783b25a9ac09fc6430f8ef8553b1e402e22c749e8bd059f027d644336f8a97dd883e6fb504a8feed02030100010281803c64373a0908cfcbf67d619c6e046a8f9efc6260dce56bb98a16f3e6b7bf7e03e3389ea075d015e779e2bee8dbdd64f52a93c55f88c26729370cec707f5e7cb6ea31e91a6f7a3111b3cfcaa9c392d6b2903158d03d7a1fe4115ff77aafb07717acb8aed4b6e355b59caa3589142ffa25cda68264a88ac1ac94388d61668e5e21024100f00b331979b10224079675cc5090d70010942bc694b20eebf46ada5dfe4258f1caa59f86ae1300284daf249f6d9e3e6ff36c6d58da39c2c8c64c08e94317a8e9024100e2184773b4b71dca2d228bf2210803ab6bdaa73324d04df24b201a7146c1556ba0d5031a56245525d7dca0360de788ab6a734ce3acf3564a40750f76112fa365024100d437d2916f38c2bfbfc591977492d8c1c1e67d5d2f10cc8866aa212c8021802924139119acc4379b6a32b19a117b998fb811e00a71c4272501cb2f05aabf3c2102402612a895976cee9b4916743285d56fa8c234c3cb1cfbe6e4523a49b9a18c94f1d6d787fa3b5f4ae7607e4a8c4fb31994a40c5e7a487981a267504f1636b6aaf1024100b87667561caec2d3486ce54e23602c9d56bc089230b66cc49bd816b66405bfbdd6cb37ecd27cfee18386840467eb65629df3469bada4182df16cf43a70f7cde5",
    );
    try std.testing.expectError(error.InvalidInput, parsePrivateKeyDer(&key_bytes));
}

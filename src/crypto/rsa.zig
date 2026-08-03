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
/// `RSAPrivateKey` DER encoding. Only the modulus `n` and private exponent
/// `d` are retained: the signing path below performs a direct constant-time
/// `d`-exponent modular exponentiation (`std.crypto.ff.Modulus.
/// powWithEncodedExponent`), not CRT, so `p`, `q`, `dp`, `dq`, and `qInv` are
/// structurally validated and range-checked during `fromDer` but are not
/// consumed by any cryptographic operation and are not retained here — a key
/// whose CRT components are inconsistent with `(n, d)` still signs exactly as
/// `(n, d)` dictate (the modpow never touches them), and a transcription
/// error in `n` or `d` itself is self-detecting: the resulting signature
/// fails verification. See `docs/CRYPTO_SECURITY_AUDIT.md` for the full
/// rationale.
pub const PrivateKey = struct {
    n: [max_modulus_bytes]u8 = undefined,
    n_len: usize = 0,
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

    fn privateExponent(self: *const PrivateKey) []const u8 {
        return self.d[0..self.d_len];
    }
};

fn stripLeadingZero(value: []const u8) []const u8 {
    return if (value.len > 1 and value[0] == 0) value[1..] else value;
}

/// Parse and validate a PKCS#1 `RSAPrivateKey` DER encoding (the structure a
/// PKCS#8 `privateKey` OCTET STRING wraps for `rsaEncryption`). Only
/// two-prime keys (`version == 0`) with a 2048/3072/4096-bit modulus are
/// supported — multi-prime keys (`version == 1`, `otherPrimeInfos`) are
/// rejected, matching the narrower signing subset this profile enforces.
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

    inline for (.{ prime1_encoded, prime2_encoded, exponent1_encoded, exponent2_encoded, coefficient_encoded }) |encoded| {
        const component = stripLeadingZero(encoded);
        if (component.len == 0) return error.InvalidInput;
        if (component.len == 1 and component[0] == 0) return error.InvalidInput;
        if (!lessThanUnsigned(component, modulus)) return error.InvalidInput;
    }

    var key = PrivateKey{ .bits = bits };
    key.n_len = modulus.len;
    @memcpy(key.n[0..modulus.len], modulus);
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

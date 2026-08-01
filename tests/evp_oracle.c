#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <stdio.h>
#include <string.h>

enum {
    EVP_ORACLE_MAX_INPUT = 4096,
};

typedef struct {
    unsigned char bytes[EVP_ORACLE_MAX_INPUT];
    size_t len;
} Blob;

static int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_hex(const char *hex, Blob *out) {
    size_t len = strlen(hex);
    if ((len & 1) != 0 || len / 2 > EVP_ORACLE_MAX_INPUT) return 0;
    out->len = len / 2;
    for (size_t i = 0; i < out->len; i++) {
        int hi = hex_value(hex[i * 2]);
        int lo = hex_value(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return 0;
        out->bytes[i] = (unsigned char)((hi << 4) | lo);
    }
    return 1;
}

static void print_hex(const unsigned char *bytes, size_t len) {
    static const char alphabet[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        putchar(alphabet[bytes[i] >> 4]);
        putchar(alphabet[bytes[i] & 0x0f]);
    }
}

static int status(const char *value) {
    puts(value);
    return 0;
}

static const EVP_CIPHER *cipher_for(const char *alg, size_t *key_len) {
    if (strcmp(alg, "aes-128-gcm") == 0) {
        *key_len = 16;
        return EVP_aes_128_gcm();
    }
    if (strcmp(alg, "aes-256-gcm") == 0) {
        *key_len = 32;
        return EVP_aes_256_gcm();
    }
    if (strcmp(alg, "chacha20-poly1305") == 0) {
        *key_len = 32;
        return EVP_chacha20_poly1305();
    }
    return NULL;
}

static int cmd_aead_seal(int argc, char **argv) {
    if (argc != 7) return status("malformed");
    size_t key_len = 0;
    const EVP_CIPHER *cipher = cipher_for(argv[2], &key_len);
    Blob key, nonce, aad, plaintext;
    if (cipher == NULL ||
        !parse_hex(argv[3], &key) ||
        !parse_hex(argv[4], &nonce) ||
        !parse_hex(argv[5], &aad) ||
        !parse_hex(argv[6], &plaintext) ||
        key.len != key_len ||
        nonce.len != 12 ||
        plaintext.len > EVP_ORACLE_MAX_INPUT) return status("malformed");

    unsigned char ciphertext[EVP_ORACLE_MAX_INPUT];
    unsigned char tag[16];
    int out_len = 0;
    int final_len = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) return status("oracle_error");
    int ok = EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)nonce.len, NULL) == 1 &&
        EVP_EncryptInit_ex(ctx, NULL, NULL, key.bytes, nonce.bytes) == 1 &&
        EVP_EncryptUpdate(ctx, NULL, &out_len, aad.bytes, (int)aad.len) == 1 &&
        EVP_EncryptUpdate(ctx, ciphertext, &out_len, plaintext.bytes, (int)plaintext.len) == 1 &&
        EVP_EncryptFinal_ex(ctx, ciphertext + out_len, &final_len) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, sizeof(tag), tag) == 1;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) return status("oracle_error");
    fputs("ok ", stdout);
    print_hex(ciphertext, plaintext.len);
    putchar(' ');
    print_hex(tag, sizeof(tag));
    putchar('\n');
    return 0;
}

static int cmd_aead_open(int argc, char **argv) {
    if (argc != 8) return status("malformed");
    size_t key_len = 0;
    const EVP_CIPHER *cipher = cipher_for(argv[2], &key_len);
    Blob key, nonce, aad, ciphertext, tag;
    if (cipher == NULL ||
        !parse_hex(argv[3], &key) ||
        !parse_hex(argv[4], &nonce) ||
        !parse_hex(argv[5], &aad) ||
        !parse_hex(argv[6], &ciphertext) ||
        !parse_hex(argv[7], &tag) ||
        key.len != key_len ||
        nonce.len != 12 ||
        tag.len != 16 ||
        ciphertext.len > EVP_ORACLE_MAX_INPUT) return status("malformed");

    unsigned char plaintext[EVP_ORACLE_MAX_INPUT];
    int out_len = 0;
    int final_len = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) return status("oracle_error");
    int ok = EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)nonce.len, NULL) == 1 &&
        EVP_DecryptInit_ex(ctx, NULL, NULL, key.bytes, nonce.bytes) == 1 &&
        EVP_DecryptUpdate(ctx, NULL, &out_len, aad.bytes, (int)aad.len) == 1 &&
        EVP_DecryptUpdate(ctx, plaintext, &out_len, ciphertext.bytes, (int)ciphertext.len) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, (int)tag.len, tag.bytes) == 1;
    if (ok && EVP_DecryptFinal_ex(ctx, plaintext + out_len, &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return status("auth_fail");
    }
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) return status("oracle_error");
    fputs("ok ", stdout);
    print_hex(plaintext, ciphertext.len);
    putchar('\n');
    return 0;
}

static int cmd_x25519(int argc, char **argv) {
    if (argc != 4) return status("malformed");
    Blob priv, pub;
    if (!parse_hex(argv[2], &priv) || !parse_hex(argv[3], &pub) || priv.len != 32 || pub.len != 32) return status("malformed");
    EVP_PKEY *private_key = EVP_PKEY_new_raw_private_key_ex(NULL, "X25519", NULL, priv.bytes, priv.len);
    EVP_PKEY *peer_key = EVP_PKEY_new_raw_public_key_ex(NULL, "X25519", NULL, pub.bytes, pub.len);
    if (private_key == NULL || peer_key == NULL) {
        EVP_PKEY_free(private_key);
        EVP_PKEY_free(peer_key);
        return status("malformed");
    }
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(private_key, NULL);
    unsigned char shared[32];
    size_t shared_len = sizeof(shared);
    int ok = ctx != NULL &&
        EVP_PKEY_derive_init(ctx) == 1 &&
        EVP_PKEY_derive_set_peer(ctx, peer_key) == 1 &&
        EVP_PKEY_derive(ctx, shared, &shared_len) == 1;
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(private_key);
    EVP_PKEY_free(peer_key);
    if (!ok) return status("auth_fail");
    fputs("ok ", stdout);
    print_hex(shared, shared_len);
    putchar('\n');
    return 0;
}

static int cmd_ed25519_sign(int argc, char **argv) {
    if (argc != 4) return status("malformed");
    Blob seed, message;
    if (!parse_hex(argv[2], &seed) || !parse_hex(argv[3], &message) || seed.len != 32) return status("malformed");
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key_ex(NULL, "ED25519", NULL, seed.bytes, seed.len);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char sig[64];
    size_t sig_len = sizeof(sig);
    int ok = key != NULL && ctx != NULL &&
        EVP_DigestSignInit(ctx, NULL, NULL, NULL, key) == 1 &&
        EVP_DigestSign(ctx, sig, &sig_len, message.bytes, message.len) == 1;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    if (!ok) return status("oracle_error");
    fputs("ok ", stdout);
    print_hex(sig, sig_len);
    putchar('\n');
    return 0;
}

static int cmd_ed25519_verify(int argc, char **argv) {
    if (argc != 5) return status("malformed");
    Blob pub, message, sig;
    if (!parse_hex(argv[2], &pub) || !parse_hex(argv[3], &message) || !parse_hex(argv[4], &sig) || pub.len != 32 || sig.len != 64) return status("malformed");
    EVP_PKEY *key = EVP_PKEY_new_raw_public_key_ex(NULL, "ED25519", NULL, pub.bytes, pub.len);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int result = 0;
    int ok = key != NULL && ctx != NULL &&
        EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key) == 1;
    if (ok) result = EVP_DigestVerify(ctx, sig.bytes, sig.len, message.bytes, message.len);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    if (!ok) return status("malformed");
    return status(result == 1 ? "ok" : "auth_fail");
}

static int cmd_ecdsa_p256_verify(int argc, char **argv) {
    if (argc != 5) return status("malformed");
    Blob pub, message, sig;
    if (!parse_hex(argv[2], &pub) || !parse_hex(argv[3], &message) || !parse_hex(argv[4], &sig) || pub.len == 0 || sig.len == 0) return status("malformed");
    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (ec == NULL) return status("oracle_error");
    const EC_GROUP *group = EC_KEY_get0_group(ec);
    EC_POINT *point = EC_POINT_new(group);
    if (point == NULL || EC_POINT_oct2point(group, point, pub.bytes, pub.len, NULL) != 1 || EC_KEY_set_public_key(ec, point) != 1) {
        EC_POINT_free(point);
        EC_KEY_free(ec);
        return status("malformed");
    }
    EC_POINT_free(point);
    EVP_PKEY *key = EVP_PKEY_new();
    if (key == NULL || EVP_PKEY_assign_EC_KEY(key, ec) != 1) {
        EVP_PKEY_free(key);
        EC_KEY_free(ec);
        return status("oracle_error");
    }
    ec = NULL;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int result = 0;
    int ok = ctx != NULL &&
        EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, key) == 1;
    if (ok) result = EVP_DigestVerify(ctx, sig.bytes, sig.len, message.bytes, message.len);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    if (!ok) return status("oracle_error");
    if (result == 1) return status("ok");
    if (result == 0) return status("auth_fail");
    return status("malformed");
}

int main(int argc, char **argv) {
    if (argc < 2) return status("malformed");
    if (strcmp(argv[1], "aead-seal") == 0) return cmd_aead_seal(argc, argv);
    if (strcmp(argv[1], "aead-open") == 0) return cmd_aead_open(argc, argv);
    if (strcmp(argv[1], "x25519") == 0) return cmd_x25519(argc, argv);
    if (strcmp(argv[1], "ed25519-sign") == 0) return cmd_ed25519_sign(argc, argv);
    if (strcmp(argv[1], "ed25519-verify") == 0) return cmd_ed25519_verify(argc, argv);
    if (strcmp(argv[1], "ecdsa-p256-verify") == 0) return cmd_ecdsa_p256_verify(argc, argv);
    return status("malformed");
}

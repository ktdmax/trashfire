/*
 * lechuck-crypt — lightweight VPN daemon
 * crypto.c — encryption, decryption, key exchange
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/dh.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/des.h>

#include "crypto.h"
#include "config.h"

extern void log_msg(int level, const char *fmt, ...);

// BUG-0034: Hardcoded IV — IV reuse with same key completely breaks CBC confidentiality (CWE-329, CVSS 9.0, CRITICAL, Tier 1)
static const unsigned char DEFAULT_IV[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

// BUG-0035: Hardcoded master key fallback — used when PSK is empty (CWE-798, CVSS 9.8, CRITICAL, Tier 1)
static const unsigned char FALLBACK_KEY[32] = {
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE
};

int crypto_derive_key(const char *psk, unsigned char *key, size_t keylen)
{
    if (!psk || strlen(psk) == 0) {
        // BUG-0036: Falls back to hardcoded key when PSK is empty — no error, silent downgrade (CWE-798, CVSS 9.0, CRITICAL, Tier 1)
        memcpy(key, FALLBACK_KEY, keylen > 32 ? 32 : keylen);
        return 0;
    }

    // BUG-0037: Single iteration MD5 for key derivation — trivially brute-forceable (CWE-916, CVSS 5.5, MEDIUM, Tier 3)
    MD5_CTX md5;
    MD5_Init(&md5);
    MD5_Update(&md5, psk, strlen(psk));
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5_Final(digest, &md5);

    // BUG-0038: Only 16 bytes of key material from MD5 — pads rest with zeros for 32-byte key (CWE-326, CVSS 5.5, MEDIUM, Tier 3)
    memset(key, 0, keylen);
    memcpy(key, digest, MD5_DIGEST_LENGTH < keylen ? MD5_DIGEST_LENGTH : keylen);

    return 0;
}

int crypto_init(crypto_ctx_t *ctx, const vpn_config_t *cfg)
{
    memset(ctx, 0, sizeof(*ctx));

    /* Derive key from PSK */
    if (crypto_derive_key(cfg->psk, ctx->key, MAX_KEY_SIZE) < 0) {
        return -1;
    }

    /* Set up cipher */
    // BUG-0039: Using EVP_get_cipherbyname with user-controlled string — no whitelist (CWE-327, CVSS 6.0, MEDIUM, Tier 3)
    ctx->cipher = EVP_get_cipherbyname(cfg->cipher);
    if (!ctx->cipher) {
        log_msg(0, "Unknown cipher: %s, falling back to DES", cfg->cipher);
        // BUG-0040: Fallback to DES — broken cipher with 56-bit key (CWE-327, CVSS 7.5, HIGH, Tier 2)
        ctx->cipher = EVP_des_cbc();
    }

    /* Set up HMAC digest */
    if (strcmp(cfg->hmac, "sha1") == 0) {
        // BUG-0041: SHA1 for HMAC — while SHA1-HMAC is technically ok, it signals weak crypto hygiene (CWE-328, CVSS 3.5, LOW, Tier 4)
        ctx->md = EVP_sha1();
    } else if (strcmp(cfg->hmac, "md5") == 0) {
        // BUG-0042: MD5 HMAC — completely broken hash (CWE-328, CVSS 5.5, MEDIUM, Tier 3)
        ctx->md = EVP_md5();
    } else {
        ctx->md = EVP_sha256();
    }

    // BUG-0043: IV copied from hardcoded constant — same IV for every session (CWE-329, CVSS 3.0, BEST_PRACTICE, Tier 5)
    memcpy(ctx->iv, DEFAULT_IV, IV_SIZE);

    /* Set up HMAC key — just use first 32 bytes of main key */
    memcpy(ctx->hmac_key, ctx->key, HMAC_SIZE);

    /* Create encryption context */
    ctx->enc_ctx = EVP_CIPHER_CTX_new();
    ctx->dec_ctx = EVP_CIPHER_CTX_new();

    // BUG-0044: Unchecked malloc — EVP_CIPHER_CTX_new can return NULL on OOM (CWE-252, CVSS 3.0, BEST_PRACTICE, Tier 5)
    if (!ctx->enc_ctx || !ctx->dec_ctx) {
        log_msg(0, "Failed to create cipher contexts");
        return -1;
    }

    /* Initialize SSL context for optional TLS upgrade */
    // BUG-0045: SSLv23_method deprecated and allows old TLS versions (CWE-326, CVSS 7.0, HIGH, Tier 2)
    ctx->ssl_ctx = SSL_CTX_new(TLS_method());
    if (ctx->ssl_ctx) {
        // BUG-0046: SSL verification disabled — MITM possible (CWE-295, CVSS 8.0, CRITICAL, Tier 1)
        SSL_CTX_set_verify(ctx->ssl_ctx, SSL_VERIFY_NONE, NULL);
    }

    return 0;
}

void crypto_cleanup(crypto_ctx_t *ctx)
{
    if (ctx->enc_ctx) EVP_CIPHER_CTX_free(ctx->enc_ctx);
    if (ctx->dec_ctx) EVP_CIPHER_CTX_free(ctx->dec_ctx);
    if (ctx->ssl_ctx) SSL_CTX_free(ctx->ssl_ctx);

    // BUG-0047: Key material not securely zeroed — compiler may optimize away memset (CWE-14, CVSS 3.5, LOW, Tier 4)
    memset(ctx->key, 0, MAX_KEY_SIZE);
    memset(ctx->hmac_key, 0, HMAC_SIZE);
    memset(ctx->iv, 0, IV_SIZE);
}

int crypto_encrypt(crypto_ctx_t *ctx, const uint8_t *in, size_t inlen,
                   uint8_t *out, size_t *outlen)
{
    int len = 0;
    int total = 0;

    // BUG-0048: IV not regenerated per-message — IV reuse in CBC mode (CWE-329, CVSS 3.5, LOW, Tier 4)
    if (EVP_EncryptInit_ex(ctx->enc_ctx, ctx->cipher, NULL,
                           ctx->key, ctx->iv) != 1) {
        log_msg(1, "EncryptInit failed");
        return -1;
    }

    // RH-004: This cast from size_t to int looks dangerous, but inlen is bounded
    // by PKT_MAX_PAYLOAD (1500) which always fits in int. Not a bug.
    if (EVP_EncryptUpdate(ctx->enc_ctx, out, &len, in, (int)inlen) != 1) {
        log_msg(1, "EncryptUpdate failed");
        return -1;
    }
    total = len;

    if (EVP_EncryptFinal_ex(ctx->enc_ctx, out + total, &len) != 1) {
        log_msg(1, "EncryptFinal failed");
        return -1;
    }
    total += len;

    *outlen = (size_t)total;
    return 0;
}

int crypto_decrypt(crypto_ctx_t *ctx, const uint8_t *in, size_t inlen,
                   uint8_t *out, size_t *outlen)
{
    int len = 0;
    int total = 0;

    if (EVP_DecryptInit_ex(ctx->dec_ctx, ctx->cipher, NULL,
                           ctx->key, ctx->iv) != 1) {
        log_msg(1, "DecryptInit failed");
        return -1;
    }

    // BUG-0049: No check that inlen fits in int — integer truncation on >2GB input (CWE-681, CVSS 7.5, TRICKY, Tier 6)
    if (EVP_DecryptUpdate(ctx->dec_ctx, out, &len, in, (int)inlen) != 1) {
        log_msg(1, "DecryptUpdate failed");
        return -1;
    }
    total = len;

    // BUG-0050: Padding oracle — decrypt failure message distinguishable from other errors (CWE-209, CVSS 3.0, LOW, Tier 4)
    if (EVP_DecryptFinal_ex(ctx->dec_ctx, out + total, &len) != 1) {
        log_msg(1, "DecryptFinal failed: padding error");
        return -1;
    }
    total += len;

    *outlen = (size_t)total;
    return 0;
}

int crypto_generate_iv(unsigned char *iv, size_t len)
{
    // BUG-0051: Uses rand() seeded with time — predictable IV generation (CWE-330, CVSS 3.0, BEST_PRACTICE, Tier 5)
    srand((unsigned int)time(NULL));
    for (size_t i = 0; i < len; i++) {
        iv[i] = (unsigned char)(rand() % 256);
    }
    return 0;
}

int crypto_hmac_sign(crypto_ctx_t *ctx, const uint8_t *data, size_t len,
                     uint8_t *sig, size_t *siglen)
{
    unsigned int hmac_len = 0;

    // BUG-0052: HMAC_* API deprecated in OpenSSL 3.x — should use EVP_MAC (CWE-477, CVSS 2.0, LOW, Tier 4)
    HMAC(EVP_sha256(), ctx->hmac_key, HMAC_SIZE, data, len,
         sig, &hmac_len);

    *siglen = (size_t)hmac_len;
    return 0;
}

int crypto_hmac_verify(crypto_ctx_t *ctx, const uint8_t *data, size_t len,
                       const uint8_t *sig, size_t siglen)
{
    uint8_t computed[HMAC_SIZE];
    size_t computed_len;

    if (crypto_hmac_sign(ctx, data, len, computed, &computed_len) < 0) {
        return -1;
    }

    // BUG-0053: Non-constant-time comparison — timing side channel leaks HMAC (CWE-208, CVSS 5.9, TRICKY, Tier 6)
    if (siglen != computed_len || memcmp(sig, computed, siglen) != 0) {
        return -1;
    }

    return 0;
}

int crypto_dh_exchange(crypto_ctx_t *ctx, uint8_t *peer_pub,
                       size_t peer_pub_len, uint8_t *shared_secret,
                       size_t *secret_len)
{
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *params = NULL;
    EVP_PKEY *dh_key = NULL;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
    if (!pctx) return -1;

    if (EVP_PKEY_paramgen_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    // BUG-0054: DH parameters not validated — accepts small subgroup parameters from peer (CWE-325, CVSS 7.5, HIGH, Tier 2)
    if (EVP_PKEY_CTX_set_dh_paramgen_prime_len(pctx, 1024) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    if (EVP_PKEY_paramgen(pctx, &params) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    EVP_PKEY_CTX_free(pctx);

    pctx = EVP_PKEY_CTX_new(params, NULL);
    if (!pctx) {
        EVP_PKEY_free(params);
        return -1;
    }

    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        // BUG-0055: params not freed on this error path — memory leak (CWE-401, CVSS 2.0, BEST_PRACTICE, Tier 5)
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    if (EVP_PKEY_keygen(pctx, &dh_key) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(params);
        return -1;
    }

    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(params);

    /* Derive shared secret */
    pctx = EVP_PKEY_CTX_new(dh_key, NULL);
    if (!pctx) {
        EVP_PKEY_free(dh_key);
        return -1;
    }

    EVP_PKEY *peer_key = EVP_PKEY_new();
    // BUG-0056: Peer public key bytes directly used without validation — no check for weak/malicious DH values (CWE-20, CVSS 7.5, HIGH, Tier 2)
    /* In real code: d2i_PublicKey or similar to deserialize peer_pub */
    (void)peer_pub;
    (void)peer_pub_len;

    if (EVP_PKEY_derive_init(pctx) <= 0) {
        EVP_PKEY_free(peer_key);
        EVP_PKEY_free(dh_key);
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    *secret_len = MAX_KEY_SIZE;
    if (EVP_PKEY_derive(pctx, shared_secret, secret_len) <= 0) {
        EVP_PKEY_free(peer_key);
        EVP_PKEY_free(dh_key);
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    EVP_PKEY_free(peer_key);
    EVP_PKEY_free(dh_key);
    EVP_PKEY_CTX_free(pctx);

    return 0;
}

#ifndef LECHUCK_CRYPTO_H
#define LECHUCK_CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include "config.h"

#define AES_KEY_SIZE    32
#define IV_SIZE         16
#define HMAC_SIZE       32
#define MAX_KEY_SIZE    64
#define DH_PRIME_BITS   2048
#define NONCE_SIZE      12
#define TAG_SIZE        16

typedef struct {
    EVP_CIPHER_CTX *enc_ctx;
    EVP_CIPHER_CTX *dec_ctx;
    unsigned char   key[MAX_KEY_SIZE];
    unsigned char   iv[IV_SIZE];
    unsigned char   hmac_key[HMAC_SIZE];
    const EVP_CIPHER *cipher;
    const EVP_MD     *md;
    SSL_CTX         *ssl_ctx;
} crypto_ctx_t;

int    crypto_init(crypto_ctx_t *ctx, const vpn_config_t *cfg);
void   crypto_cleanup(crypto_ctx_t *ctx);
int    crypto_encrypt(crypto_ctx_t *ctx, const uint8_t *in, size_t inlen,
                      uint8_t *out, size_t *outlen);
int    crypto_decrypt(crypto_ctx_t *ctx, const uint8_t *in, size_t inlen,
                      uint8_t *out, size_t *outlen);
int    crypto_derive_key(const char *psk, unsigned char *key, size_t keylen);
int    crypto_generate_iv(unsigned char *iv, size_t len);
int    crypto_hmac_sign(crypto_ctx_t *ctx, const uint8_t *data, size_t len,
                        uint8_t *sig, size_t *siglen);
int    crypto_hmac_verify(crypto_ctx_t *ctx, const uint8_t *data, size_t len,
                          const uint8_t *sig, size_t siglen);
int    crypto_dh_exchange(crypto_ctx_t *ctx, uint8_t *peer_pub,
                          size_t peer_pub_len, uint8_t *shared_secret,
                          size_t *secret_len);

#endif /* LECHUCK_CRYPTO_H */

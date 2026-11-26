/*
 * hmac.c —— HMAC-SHA256 / HMAC-SHA512（RFC 2104 / FIPS 198-1）
 *
 * HMAC(K,m) = H((K' ^ opad) || H((K' ^ ipad) || m))
 *   * K' 为长度等于分组大小的密钥；短密钥补零，长密钥先哈希。
 */
#include "dtc/crypto.h"

#include <string.h>

static void hmac_sha256(const void *key, size_t keylen, const void *msg,
                        size_t msglen, uint8_t out[32])
{
    uint8_t k[64];
    uint8_t pad[64];
    uint8_t inner[32];

    memset(k, 0, sizeof(k));
    if (keylen > sizeof(k)) {
        dtc_sha256(key, keylen, k);
    } else if (keylen > 0) {
        memcpy(k, key, keylen);
    }

    dtc_sha256_ctx ctx;

    /* inner = H((K ^ ipad) || msg) */
    for (size_t i = 0; i < sizeof(k); ++i) {
        pad[i] = (uint8_t)(k[i] ^ 0x36u);
    }
    dtc_sha256_init(&ctx);
    dtc_sha256_update(&ctx, pad, sizeof(pad));
    dtc_sha256_update(&ctx, msg, msglen);
    dtc_sha256_final(&ctx, inner);

    /* outer = H((K ^ opad) || inner) */
    for (size_t i = 0; i < sizeof(k); ++i) {
        pad[i] = (uint8_t)(k[i] ^ 0x5cu);
    }
    dtc_sha256_init(&ctx);
    dtc_sha256_update(&ctx, pad, sizeof(pad));
    dtc_sha256_update(&ctx, inner, sizeof(inner));
    dtc_sha256_final(&ctx, out);
}

static void hmac_sha512(const void *key, size_t keylen, const void *msg,
                        size_t msglen, uint8_t out[64])
{
    uint8_t k[128];
    uint8_t pad[128];
    uint8_t inner[64];

    memset(k, 0, sizeof(k));
    if (keylen > sizeof(k)) {
        dtc_sha512(key, keylen, k);
    } else if (keylen > 0) {
        memcpy(k, key, keylen);
    }

    dtc_sha512_ctx ctx;

    for (size_t i = 0; i < sizeof(k); ++i) {
        pad[i] = (uint8_t)(k[i] ^ 0x36u);
    }
    dtc_sha512_init(&ctx);
    dtc_sha512_update(&ctx, pad, sizeof(pad));
    dtc_sha512_update(&ctx, msg, msglen);
    dtc_sha512_final(&ctx, inner);

    for (size_t i = 0; i < sizeof(k); ++i) {
        pad[i] = (uint8_t)(k[i] ^ 0x5cu);
    }
    dtc_sha512_init(&ctx);
    dtc_sha512_update(&ctx, pad, sizeof(pad));
    dtc_sha512_update(&ctx, inner, sizeof(inner));
    dtc_sha512_final(&ctx, out);
}

void dtc_hmac_sha256(const void *key, size_t keylen, const void *msg,
                     size_t msglen, uint8_t out[32])
{
    hmac_sha256(key, keylen, msg, msglen, out);
}

void dtc_hmac_sha512(const void *key, size_t keylen, const void *msg,
                     size_t msglen, uint8_t out[64])
{
    hmac_sha512(key, keylen, msg, msglen, out);
}

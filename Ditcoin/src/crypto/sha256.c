/*
 * sha256.c —— SHA-256（FIPS 180-4）
 *
 * 自包含实现，已用官方测试向量（空串 / "abc" / 448 位边界）验证。
 * 之所以不直接调用系统 OpenSSL：SPEC 要求可复现的静态依赖，且后续
 * fuzz 需要可控的增量接口。
 */
#include "dtc/crypto.h"

#include <string.h>

/* SHA-256 轮常量（前 64 个素数立方根小数部分前 32 位） */
static const uint32_t K256[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu,
    0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u,
    0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u,
    0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u,
    0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u,
    0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u, 0x1e376c08u,
    0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu,
    0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

static uint32_t rotr32(uint32_t x, unsigned n)
{
    return (x >> n) | (x << (32 - n));
}

static uint32_t load_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void store_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)((v >> 24) & 0xffu);
    p[1] = (uint8_t)((v >> 16) & 0xffu);
    p[2] = (uint8_t)((v >> 8) & 0xffu);
    p[3] = (uint8_t)(v & 0xffu);
}

/* 压缩一个 64 字节分组 */
static void sha256_compress(uint32_t state[8], const uint8_t block[64])
{
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = load_be32(block + 4 * i);
    }
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^
                      (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^
                      (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];
    uint32_t f = state[5];
    uint32_t g = state[6];
    uint32_t h = state[7];

    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + S1 + ch + K256[i] + w[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

void dtc_sha256_init(dtc_sha256_ctx *ctx)
{
    /* FIPS 180-4 初始哈希值 */
    ctx->state[0] = 0x6a09e667u;
    ctx->state[1] = 0xbb67ae85u;
    ctx->state[2] = 0x3c6ef372u;
    ctx->state[3] = 0xa54ff53au;
    ctx->state[4] = 0x510e527fu;
    ctx->state[5] = 0x9b05688cu;
    ctx->state[6] = 0x1f83d9abu;
    ctx->state[7] = 0x5be0cd19u;
    ctx->bitlen = 0;
    ctx->buflen = 0;
}

void dtc_sha256_update(dtc_sha256_ctx *ctx, const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    ctx->bitlen += (uint64_t)len * 8u;

    /* 先填满已有缓冲区 */
    if (ctx->buflen > 0) {
        size_t need = 64 - ctx->buflen;
        size_t take = (len < need) ? len : need;
        memcpy(ctx->buffer + ctx->buflen, p, take);
        ctx->buflen += take;
        p += take;
        len -= take;
        if (ctx->buflen == 64) {
            sha256_compress(ctx->state, ctx->buffer);
            ctx->buflen = 0;
        }
    }

    /* 整块直接压缩，避免频繁 memcpy */
    while (len >= 64) {
        sha256_compress(ctx->state, p);
        p += 64;
        len -= 64;
    }

    if (len > 0) {
        memcpy(ctx->buffer, p, len);
        ctx->buflen = len;
    }
}

void dtc_sha256_final(dtc_sha256_ctx *ctx, uint8_t out[32])
{
    uint64_t bitlen = ctx->bitlen;

    /* 填充：0x80 后补零，使长度 ≡ 56 (mod 64) */
    uint8_t pad[64];
    memset(pad, 0, sizeof(pad));
    pad[0] = 0x80;
    size_t padlen = (ctx->buflen < 56) ? (56 - ctx->buflen)
                                       : (120 - ctx->buflen);
    dtc_sha256_update(ctx, pad, padlen);

    uint8_t lenbuf[8];
    for (int i = 0; i < 8; ++i) {
        lenbuf[7 - i] = (uint8_t)((bitlen >> (8 * i)) & 0xffu);
    }
    dtc_sha256_update(ctx, lenbuf, 8);

    for (int i = 0; i < 8; ++i) {
        store_be32(out + 4 * i, ctx->state[i]);
    }
}

void dtc_sha256(const void *data, size_t len, uint8_t out[32])
{
    dtc_sha256_ctx ctx;
    dtc_sha256_init(&ctx);
    dtc_sha256_update(&ctx, data, len);
    dtc_sha256_final(&ctx, out);
}

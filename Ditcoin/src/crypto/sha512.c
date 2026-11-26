/*
 * sha512.c —— SHA-512（FIPS 180-4）
 *
 * 用途：HD 钱包 master 派生（HMAC-SHA512）与 BIP39 PBKDF2。
 * 已用 FIPS 官方向量（空串 / "abc"）验证。
 */
#include "dtc/crypto.h"

#include <string.h>

static const uint64_t K512[80] = {
    0x428a2f98d728ae22ull, 0x7137449123ef65cdull, 0xb5c0fbcfec4d3b2full,
    0xe9b5dba58189dbbcull, 0x3956c25bf348b538ull, 0x59f111f1b605d019ull,
    0x923f82a4af194f9bull, 0xab1c5ed5da6d8118ull, 0xd807aa98a3030242ull,
    0x12835b0145706fbeull, 0x243185be4ee4b28cull, 0x550c7dc3d5ffb4e2ull,
    0x72be5d74f27b896full, 0x80deb1fe3b1696b1ull, 0x9bdc06a725c71235ull,
    0xc19bf174cf692694ull, 0xe49b69c19ef14ad2ull, 0xefbe4786384f25e3ull,
    0x0fc19dc68b8cd5b5ull, 0x240ca1cc77ac9c65ull, 0x2de92c6f592b0275ull,
    0x4a7484aa6ea6e483ull, 0x5cb0a9dcbd41fbd4ull, 0x76f988da831153b5ull,
    0x983e5152ee66dfabull, 0xa831c66d2db43210ull, 0xb00327c898fb213full,
    0xbf597fc7beef0ee4ull, 0xc6e00bf33da88fc2ull, 0xd5a79147930aa725ull,
    0x06ca6351e003826full, 0x142929670a0e6e70ull, 0x27b70a8546d22ffcull,
    0x2e1b21385c26c926ull, 0x4d2c6dfc5ac42aedull, 0x53380d139d95b3dfull,
    0x650a73548baf63deull, 0x766a0abb3c77b2a8ull, 0x81c2c92e47edaee6ull,
    0x92722c851482353bull, 0xa2bfe8a14cf10364ull, 0xa81a664bbc423001ull,
    0xc24b8b70d0f89791ull, 0xc76c51a30654be30ull, 0xd192e819d6ef5218ull,
    0xd69906245565a910ull, 0xf40e35855771202aull, 0x106aa07032bbd1b8ull,
    0x19a4c116b8d2d0c8ull, 0x1e376c085141ab53ull, 0x2748774cdf8eeb99ull,
    0x34b0bcb5e19b48a8ull, 0x391c0cb3c5c95a63ull, 0x4ed8aa4ae3418acbull,
    0x5b9cca4f7763e373ull, 0x682e6ff3d6b2b8a3ull, 0x748f82ee5defb2fcull,
    0x78a5636f43172f60ull, 0x84c87814a1f0ab72ull, 0x8cc702081a6439ecull,
    0x90befffa23631e28ull, 0xa4506cebde82bde9ull, 0xbef9a3f7b2c67915ull,
    0xc67178f2e372532bull, 0xca273eceea26619cull, 0xd186b8c721c0c207ull,
    0xeada7dd6cde0eb1eull, 0xf57d4f7fee6ed178ull, 0x06f067aa72176fbaull,
    0x0a637dc5a2c898a6ull, 0x113f9804bef90daeull, 0x1b710b35131c471bull,
    0x28db77f523047d84ull, 0x32caab7b40c72493ull, 0x3c9ebe0a15c9bebcull,
    0x431d67c49c100d4cull, 0x4cc5d4becb3e42b6ull, 0x597f299cfc657e2aull,
    0x5fcb6fab3ad6faecull, 0x6c44198c4a475817ull};

static uint64_t rotr64(uint64_t x, unsigned n)
{
    return (x >> n) | (x << (64 - n));
}

static uint64_t load_be64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v = (v << 8) | (uint64_t)p[i];
    }
    return v;
}

static void store_be64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; ++i) {
        p[7 - i] = (uint8_t)((v >> (8 * i)) & 0xffu);
    }
}

static void sha512_compress(uint64_t state[8], const uint8_t block[128])
{
    uint64_t w[80];
    for (int i = 0; i < 16; ++i) {
        w[i] = load_be64(block + 8 * i);
    }
    for (int i = 16; i < 80; ++i) {
        uint64_t s0 = rotr64(w[i - 15], 1) ^ rotr64(w[i - 15], 8) ^
                      (w[i - 15] >> 7);
        uint64_t s1 = rotr64(w[i - 2], 19) ^ rotr64(w[i - 2], 61) ^
                      (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint64_t a = state[0];
    uint64_t b = state[1];
    uint64_t c = state[2];
    uint64_t d = state[3];
    uint64_t e = state[4];
    uint64_t f = state[5];
    uint64_t g = state[6];
    uint64_t h = state[7];

    for (int i = 0; i < 80; ++i) {
        uint64_t S1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
        uint64_t ch = (e & f) ^ ((~e) & g);
        uint64_t temp1 = h + S1 + ch + K512[i] + w[i];
        uint64_t S0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
        uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint64_t temp2 = S0 + maj;

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

void dtc_sha512_init(dtc_sha512_ctx *ctx)
{
    ctx->state[0] = 0x6a09e667f3bcc908ull;
    ctx->state[1] = 0xbb67ae8584caa73bull;
    ctx->state[2] = 0x3c6ef372fe94f82bull;
    ctx->state[3] = 0xa54ff53a5f1d36f1ull;
    ctx->state[4] = 0x510e527fade682d1ull;
    ctx->state[5] = 0x9b05688c2b3e6c1full;
    ctx->state[6] = 0x1f83d9abfb41bd6bull;
    ctx->state[7] = 0x5be0cd19137e2179ull;
    ctx->bitlen_hi = 0;
    ctx->bitlen_lo = 0;
    ctx->buflen = 0;
}

void dtc_sha512_update(dtc_sha512_ctx *ctx, const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;

    /* 128 位比特长度累加（实际消息远不可能达到 2^64 比特，但仍正确维护） */
    uint64_t add = (uint64_t)len * 8u;
    uint64_t old = ctx->bitlen_lo;
    ctx->bitlen_lo += add;
    if (ctx->bitlen_lo < old) {
        ctx->bitlen_hi += 1;
    }

    if (ctx->buflen > 0) {
        size_t need = 128 - ctx->buflen;
        size_t take = (len < need) ? len : need;
        memcpy(ctx->buffer + ctx->buflen, p, take);
        ctx->buflen += take;
        p += take;
        len -= take;
        if (ctx->buflen == 128) {
            sha512_compress(ctx->state, ctx->buffer);
            ctx->buflen = 0;
        }
    }

    while (len >= 128) {
        sha512_compress(ctx->state, p);
        p += 128;
        len -= 128;
    }

    if (len > 0) {
        memcpy(ctx->buffer, p, len);
        ctx->buflen = len;
    }
}

void dtc_sha512_final(dtc_sha512_ctx *ctx, uint8_t out[64])
{
    uint64_t hi = ctx->bitlen_hi;
    uint64_t lo = ctx->bitlen_lo;

    uint8_t pad[128];
    memset(pad, 0, sizeof(pad));
    pad[0] = 0x80;
    size_t padlen = (ctx->buflen < 112) ? (112 - ctx->buflen)
                                        : (240 - ctx->buflen);
    dtc_sha512_update(ctx, pad, padlen);

    uint8_t lenbuf[16];
    store_be64(lenbuf, hi);
    store_be64(lenbuf + 8, lo);
    dtc_sha512_update(ctx, lenbuf, 16);

    for (int i = 0; i < 8; ++i) {
        store_be64(out + 8 * i, ctx->state[i]);
    }
}

void dtc_sha512(const void *data, size_t len, uint8_t out[64])
{
    dtc_sha512_ctx ctx;
    dtc_sha512_init(&ctx);
    dtc_sha512_update(&ctx, data, len);
    dtc_sha512_final(&ctx, out);
}

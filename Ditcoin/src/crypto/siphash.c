/*
 * siphash.c —— SipHash-2-4（Aumasson & Bernstein）
 *
 * 用途：M2 compact block 的 6 字节 short id（key 来自区块头哈希）。
 * 已用官方测试向量验证（key=000102...0f，空串/单字节/15 字节）。
 */
#include "dtc/crypto.h"

static uint64_t load_le64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; --i) {
        v = (v << 8) | (uint64_t)p[i];
    }
    return v;
}

static uint64_t rotl64(uint64_t x, unsigned b)
{
    return (x << b) | (x >> (64 - b));
}

#define SIPROUND                                                             \
    do {                                                                     \
        v0 += v1;                                                            \
        v1 = rotl64(v1, 13);                                                 \
        v1 ^= v0;                                                            \
        v0 = rotl64(v0, 32);                                                 \
        v2 += v3;                                                            \
        v3 = rotl64(v3, 16);                                                 \
        v3 ^= v2;                                                            \
        v0 += v3;                                                            \
        v3 = rotl64(v3, 21);                                                 \
        v3 ^= v0;                                                            \
        v2 += v1;                                                            \
        v1 = rotl64(v1, 17);                                                 \
        v1 ^= v2;                                                            \
        v2 = rotl64(v2, 32);                                                 \
    } while (0)

uint64_t dtc_siphash24(const uint8_t key[16], const void *data, size_t len)
{
    const uint8_t *in = (const uint8_t *)data;
    uint64_t k0 = load_le64(key);
    uint64_t k1 = load_le64(key + 8);

    uint64_t v0 = 0x736f6d6570736575ull ^ k0;
    uint64_t v1 = 0x646f72616e646f6dull ^ k1;
    uint64_t v2 = 0x6c7967656e657261ull ^ k0;
    uint64_t v3 = 0x7465646279746573ull ^ k1;

    size_t blocks = len / 8;
    for (size_t i = 0; i < blocks; ++i) {
        uint64_t m = load_le64(in + i * 8);
        v3 ^= m;
        SIPROUND;
        SIPROUND;
        v0 ^= m;
    }

    /* 尾块：剩余字节 + 长度（字节）放在最高字节 */
    uint64_t b = (uint64_t)(len & 0xffu) << 56;
    size_t rem = len % 8;
    for (size_t i = 0; i < rem; ++i) {
        b |= (uint64_t)in[blocks * 8 + i] << (8 * i);
    }
    v3 ^= b;
    SIPROUND;
    SIPROUND;
    v0 ^= b;

    v2 ^= 0xffu;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    SIPROUND;

    return v0 ^ v1 ^ v2 ^ v3;
}

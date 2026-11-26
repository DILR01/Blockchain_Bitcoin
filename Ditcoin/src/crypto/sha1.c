/*
 * sha1.c —— SHA-1（FIPS 180-4）一次性实现
 *
 * 用途：仅服务于脚本操作码 OP_SHA1（0xa7）。SHA-1 在密码学上已不安全，
 * 绝不能用于签名、地址或任何抗碰撞场景；本文件刻意只提供一次性接口，
 * 避免被误用为通用哈希。
 */
#include <string.h>

#include "dtc/crypto.h"

/* 循环左移 32 位 */
static uint32_t rotl32(uint32_t x, unsigned n)
{
    return (x << n) | (x >> (32u - n));
}

/* 以大端读取 32 位字 */
static uint32_t read_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/* 以大端写出 32 位字 */
static void write_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

/* 压缩一个 64 字节分组到 5 个 32 位状态字 */
static void sha1_compress(uint32_t state[5], const uint8_t block[64])
{
    uint32_t w[80];
    for (size_t i = 0; i < 16; ++i) {
        w[i] = read_be32(block + 4 * i);
    }
    for (size_t i = 16; i < 80; ++i) {
        w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];

    for (size_t i = 0; i < 80; ++i) {
        uint32_t f;
        uint32_t k;
        if (i < 20) {
            f = (b & c) | (~b & d);
            k = 0x5a827999u;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ed9eba1u;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8f1bbcdcu;
        } else {
            f = b ^ c ^ d;
            k = 0xca62c1d6u;
        }
        uint32_t tmp = rotl32(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = rotl32(b, 30);
        b = a;
        a = tmp;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}

void dtc_sha1(const void *data, size_t len, uint8_t out[20])
{
    const uint8_t *p = (const uint8_t *)data;
    uint32_t state[5] = {0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u,
                         0xc3d2e1f0u};

    size_t blocks = len / 64;
    for (size_t i = 0; i < blocks; ++i) {
        sha1_compress(state, p + i * 64);
    }

    /* 尾部分组：0x80 + 零填充 + 8 字节大端比特长度 */
    uint8_t tail[128];
    size_t rem = len % 64;
    memset(tail, 0, sizeof(tail));
    if (rem > 0) {
        memcpy(tail, p + blocks * 64, rem);
    }
    tail[rem] = 0x80;

    size_t tail_len = (rem < 56) ? 64 : 128;
    uint64_t bits = (uint64_t)len * 8u;
    for (size_t i = 0; i < 8; ++i) {
        tail[tail_len - 8 + i] = (uint8_t)((bits >> (8 * (7 - i))) & 0xffu);
    }

    sha1_compress(state, tail);
    if (tail_len == 128) {
        sha1_compress(state, tail + 64);
    }

    for (size_t i = 0; i < 5; ++i) {
        write_be32(out + 4 * i, state[i]);
    }
}

/*
 * ripemd160.c —— RIPEMD-160（ISO/IEC 10118-3）
 *
 * 用途：Hash160 = RIPEMD160(SHA256(x))，即 P2PKH/P2SH 地址与 HD 指纹。
 * 采用 80 轮双线压缩的标准查表实现，已用 "abc" 官方向量验证：
 *   8eb208f7e05d987a9b044a8e98c6b087f15a0bfc
 *
 * 表结构说明：
 *   RL/RR —— 左/右线的消息字选取顺序
 *   SL/SR —— 左/右线的循环左移位数
 *   KL/KR —— 左/右线每 16 轮的加法常量
 */
#include "dtc/crypto.h"

#include <string.h>

static uint32_t rol32(uint32_t x, unsigned n)
{
    return (x << n) | (x >> (32 - n));
}

static uint32_t read_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static void write_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xffu);
    p[1] = (uint8_t)((v >> 8) & 0xffu);
    p[2] = (uint8_t)((v >> 16) & 0xffu);
    p[3] = (uint8_t)((v >> 24) & 0xffu);
}

/* 五个非线性函数 */
static uint32_t f1(uint32_t x, uint32_t y, uint32_t z)
{
    return x ^ y ^ z;
}
static uint32_t f2(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) | (~x & z);
}
static uint32_t f3(uint32_t x, uint32_t y, uint32_t z)
{
    return (x | ~y) ^ z;
}
static uint32_t f4(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & z) | (y & ~z);
}
static uint32_t f5(uint32_t x, uint32_t y, uint32_t z)
{
    return x ^ (y | ~z);
}

/* 左线消息字顺序 */
static const uint8_t RL[80] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13};

/* 右线消息字顺序 */
static const uint8_t RR[80] = {
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11};

/* 左线循环左移位数 */
static const uint8_t SL[80] = {
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6};

/* 右线循环左移位数 */
static const uint8_t SR[80] = {
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11};

static const uint32_t KL[5] = {0x00000000u, 0x5a827999u, 0x6ed9eba1u,
                               0x8f1bbcdcu, 0xa953fd4eu};
static const uint32_t KR[5] = {0x50a28be6u, 0x5c4dd124u, 0x6d703ef3u,
                               0x7a6d76e9u, 0x00000000u};

/* 压缩一个 64 字节分组 */
static void rmd160_compress(uint32_t state[5], const uint8_t block[64])
{
    uint32_t x[16];
    for (int i = 0; i < 16; ++i) {
        x[i] = read_le32(block + 4 * i);
    }

    uint32_t a1 = state[0];
    uint32_t b1 = state[1];
    uint32_t c1 = state[2];
    uint32_t d1 = state[3];
    uint32_t e1 = state[4];
    uint32_t a2 = state[0];
    uint32_t b2 = state[1];
    uint32_t c2 = state[2];
    uint32_t d2 = state[3];
    uint32_t e2 = state[4];

    for (int j = 0; j < 80; ++j) {
        int round = j / 16;
        uint32_t fl;
        uint32_t fr;
        switch (round) {
        case 0:
            fl = f1(b1, c1, d1);
            fr = f5(b2, c2, d2);
            break;
        case 1:
            fl = f2(b1, c1, d1);
            fr = f4(b2, c2, d2);
            break;
        case 2:
            fl = f3(b1, c1, d1);
            fr = f3(b2, c2, d2);
            break;
        case 3:
            fl = f4(b1, c1, d1);
            fr = f2(b2, c2, d2);
            break;
        default:
            fl = f5(b1, c1, d1);
            fr = f1(b2, c2, d2);
            break;
        }

        uint32_t t1 = rol32(a1 + fl + x[RL[j]] + KL[round], SL[j]) + e1;
        a1 = e1;
        e1 = d1;
        d1 = rol32(c1, 10);
        c1 = b1;
        b1 = t1;

        uint32_t t2 = rol32(a2 + fr + x[RR[j]] + KR[round], SR[j]) + e2;
        a2 = e2;
        e2 = d2;
        d2 = rol32(c2, 10);
        c2 = b2;
        b2 = t2;
    }

    /* 双线结果交叉组合（标准 Finalize 步骤） */
    uint32_t t = state[0];
    state[0] = state[1] + c1 + d2;
    state[1] = state[2] + d1 + e2;
    state[2] = state[3] + e1 + a2;
    state[3] = state[4] + a1 + b2;
    state[4] = t + b1 + c2;
}

void dtc_ripemd160(const void *data, size_t len, uint8_t out[20])
{
    const uint8_t *p = (const uint8_t *)data;
    uint32_t state[5] = {0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u,
                         0xc3d2e1f0u};

    size_t blocks = len / 64;
    for (size_t i = 0; i < blocks; ++i) {
        rmd160_compress(state, p + i * 64);
    }

    /* 尾部分组：追加 0x80、零填充、末尾 8 字节小端比特长度 */
    uint8_t tail[128];
    size_t rem = len % 64;
    memset(tail, 0, sizeof(tail));
    memcpy(tail, p + blocks * 64, rem);
    tail[rem] = 0x80;
    size_t tail_len = (rem < 56) ? 64 : 128;
    uint64_t bits = (uint64_t)len * 8u;
    for (size_t i = 0; i < 8; ++i) {
        tail[tail_len - 8 + i] = (uint8_t)((bits >> (8 * i)) & 0xffu);
    }

    rmd160_compress(state, tail);
    if (tail_len == 128) {
        rmd160_compress(state, tail + 64);
    }

    for (int i = 0; i < 5; ++i) {
        write_le32(out + 4 * i, state[i]);
    }
}

/*
 * uint256.c —— 256 位无符号整数实现
 *
 * 这里刻意不使用 __int128：所有 64×64→128 乘法都用 32 位半字手写，
 * 以符合「纯 C11、无 GNU 扩展」的硬约束。
 */
#include "dtc/uint256.h"

#include <string.h>

/* ---------------------------------------------------------------------------
 * 基础工具
 * ------------------------------------------------------------------------- */

void dtc_u256_zero(dtc_u256 *v)
{
    v->limb[0] = 0;
    v->limb[1] = 0;
    v->limb[2] = 0;
    v->limb[3] = 0;
}

void dtc_u256_set_u64(dtc_u256 *v, uint64_t x)
{
    dtc_u256_zero(v);
    v->limb[0] = x;
}

bool dtc_u256_is_zero(const dtc_u256 *v)
{
    return (v->limb[0] | v->limb[1] | v->limb[2] | v->limb[3]) == 0;
}

int dtc_u256_cmp(const dtc_u256 *a, const dtc_u256 *b)
{
    for (int i = 3; i >= 0; --i) {
        if (a->limb[i] < b->limb[i]) {
            return -1;
        }
        if (a->limb[i] > b->limb[i]) {
            return 1;
        }
    }
    return 0;
}

bool dtc_u256_equal(const dtc_u256 *a, const dtc_u256 *b)
{
    return dtc_u256_cmp(a, b) == 0;
}

int dtc_u256_cmp_u64(const dtc_u256 *a, uint64_t b)
{
    if (a->limb[1] | a->limb[2] | a->limb[3]) {
        return 1;
    }
    if (a->limb[0] < b) {
        return -1;
    }
    return (a->limb[0] > b) ? 1 : 0;
}

bool dtc_u256_add(dtc_u256 *out, const dtc_u256 *a, const dtc_u256 *b)
{
    uint64_t carry = 0;
    for (int i = 0; i < 4; ++i) {
        uint64_t s = a->limb[i] + b->limb[i];
        uint64_t c1 = (s < a->limb[i]) ? 1u : 0u;
        uint64_t s2 = s + carry;
        uint64_t c2 = (s2 < s) ? 1u : 0u;
        out->limb[i] = s2;
        carry = c1 | c2;
    }
    return carry != 0;
}

bool dtc_u256_sub(dtc_u256 *out, const dtc_u256 *a, const dtc_u256 *b)
{
    uint64_t borrow = 0;
    for (int i = 0; i < 4; ++i) {
        uint64_t bi = b->limb[i];
        uint64_t ai = a->limb[i];
        uint64_t d = ai - bi;
        uint64_t b1 = (ai < bi) ? 1u : 0u;
        uint64_t d2 = d - borrow;
        uint64_t b2 = (d < borrow) ? 1u : 0u;
        out->limb[i] = d2;
        borrow = b1 | b2;
    }
    return borrow != 0;
}

/* 64×64 → 128 位乘法（32 位半字分解，纯 C11） */
static void mul64(uint64_t a, uint64_t b, uint64_t *hi, uint64_t *lo)
{
    uint64_t a0 = a & 0xffffffffu;
    uint64_t a1 = a >> 32;
    uint64_t b0 = b & 0xffffffffu;
    uint64_t b1 = b >> 32;

    uint64_t p00 = a0 * b0;
    uint64_t p01 = a0 * b1;
    uint64_t p10 = a1 * b0;
    uint64_t p11 = a1 * b1;

    uint64_t mid = (p00 >> 32) + (p01 & 0xffffffffu) + (p10 & 0xffffffffu);

    *lo = (mid << 32) | (p00 & 0xffffffffu);
    *hi = p11 + (p01 >> 32) + (p10 >> 32) + (mid >> 32);
}

bool dtc_u256_mul_u64(dtc_u256 *out, const dtc_u256 *a, uint64_t m)
{
    uint64_t carry = 0;
    dtc_u256 r;
    for (int i = 0; i < 4; ++i) {
        uint64_t hi;
        uint64_t lo;
        mul64(a->limb[i], m, &hi, &lo);

        /* lo + carry */
        uint64_t s = lo + carry;
        if (s < lo) {
            hi += 1;
        }
        r.limb[i] = s;
        carry = hi;
    }

    if (carry != 0) {
        /* 溢出：饱和为全 0xFF，避免把巨值静默截断成小难度 */
        for (int i = 0; i < 4; ++i) {
            r.limb[i] = 0xffffffffffffffffull;
        }
        *out = r;
        return true;
    }
    *out = r;
    return false;
}

/* 取第 bit 位（0 = 最低位） */
static unsigned bit_at(const dtc_u256 *v, int bit)
{
    return (unsigned)((v->limb[bit / 64] >> (bit % 64)) & 1u);
}

/* 置第 bit 位 */
static void set_bit(dtc_u256 *v, int bit)
{
    v->limb[bit / 64] |= (uint64_t)1 << (bit % 64);
}

bool dtc_u256_div_u64(dtc_u256 *out, const dtc_u256 *a, uint64_t divisor,
                      uint64_t *remainder)
{
    if (divisor == 0) {
        dtc_u256_zero(out);
        if (remainder != NULL) {
            *remainder = 0;
        }
        return false;
    }

    dtc_u256 q;
    dtc_u256_zero(&q);
    uint64_t rem = 0;

    /* 256 次二进制长除：rem < divisor ≤ 2^64-1，2*rem+bit 可能超出 64 位，
     * 用进位位 new_hi 判断。 */
    for (int i = 255; i >= 0; --i) {
        uint64_t new_hi = rem >> 63;
        rem = (rem << 1) | (uint64_t)bit_at(a, i);
        if (new_hi != 0 || rem >= divisor) {
            rem -= divisor;
            set_bit(&q, i);
        }
    }

    *out = q;
    if (remainder != NULL) {
        *remainder = rem;
    }
    return true;
}

/* ---------------------------------------------------------------------------
 * Compact(nBits) 编解码
 *
 * 与 Bitcoin 的 CompactSize 无关，这是「目标值 ↔ 32 位紧凑表示」的编码。
 * ------------------------------------------------------------------------- */

void dtc_u256_get_compact(const dtc_u256 *v, bool negative, uint32_t *compact)
{
    uint8_t be[32];
    dtc_u256_to_le_bytes(v, be);

    /* 找到最高非零字节（大端视角） */
    int last = 31;
    while (last >= 0 && be[last] == 0) {
        --last;
    }

    uint32_t result;
    if (last < 0) {
        result = 0;
    } else if (last <= 2) {
        /* nSize <= 3：尾数 = 低 nSize 字节左移 (3-nSize) 字节 */
        uint32_t word = ((uint32_t)be[2] << 16) | ((uint32_t)be[1] << 8) |
                        (uint32_t)be[0];
        word <<= 8 * (3 - (uint32_t)(last + 1));
        result = word | ((uint32_t)(last + 1) << 24);
    } else {
        uint32_t word = ((uint32_t)be[last] << 16) |
                        ((uint32_t)be[last - 1] << 8) | (uint32_t)be[last - 2];
        uint32_t size = (uint32_t)(last + 1);
        if (word & 0x00800000u) {
            word >>= 8;
            size += 1;
        }
        result = word | (size << 24);
    }

    if (negative && (result & 0x007fffffu) != 0) {
        result |= 0x00800000u;
    }
    *compact = result;
}

bool dtc_u256_set_compact(dtc_u256 *v, uint32_t compact, bool *negative,
                          bool *overflow)
{
    uint32_t size = compact >> 24;
    uint32_t word = compact & 0x007fffffu;
    bool neg = false;
    bool ovf = false;

    if (word != 0 && (compact & 0x00800000u) != 0) {
        neg = true;
    }

    /* 溢出判定与 Bitcoin 的 SetCompact 等价：
     * 23 位尾数左移 8*(size-3) 后若超出 256 位即溢出。 */
    if (word != 0 && (size > 34 || (word > 0xffu && size > 33) ||
                      (word > 0xffffu && size > 32))) {
        ovf = true;
    }

    if (size <= 3) {
        word >>= 8 * (3 - size);
        dtc_u256_set_u64(v, word);
    } else {
        if (size > 32) {
            /* 溢出：饱和为全 0xFF，避免后续比较产生“永远合法”的错判 */
            for (int i = 0; i < 4; ++i) {
                v->limb[i] = 0xffffffffffffffffull;
            }
        } else {
            /* 把 23 位尾数放到小端字节数组的 (size-3) 起始位置 */
            uint8_t le[32];
            memset(le, 0, sizeof(le));
            uint32_t shift_bytes = size - 3;
            le[shift_bytes] = (uint8_t)(word & 0xffu);
            le[shift_bytes + 1] = (uint8_t)((word >> 8) & 0xffu);
            le[shift_bytes + 2] = (uint8_t)((word >> 16) & 0xffu);
            dtc_u256_from_le_bytes(v, le);
        }
    }

    if (neg) {
        dtc_u256_zero(v);
    }
    if (negative != NULL) {
        *negative = neg;
    }
    if (overflow != NULL) {
        *overflow = ovf;
    }
    return !ovf;
}

/* ---------------------------------------------------------------------------
 * 字节序与十六进制
 * ------------------------------------------------------------------------- */

void dtc_u256_from_le_bytes(dtc_u256 *v, const uint8_t bytes[32])
{
    for (int i = 0; i < 4; ++i) {
        v->limb[i] = 0;
        for (int j = 0; j < 8; ++j) {
            v->limb[i] |= (uint64_t)bytes[i * 8 + j] << (8 * j);
        }
    }
}

void dtc_u256_to_le_bytes(const dtc_u256 *v, uint8_t out[32])
{
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 8; ++j) {
            out[i * 8 + j] = (uint8_t)((v->limb[i] >> (8 * j)) & 0xffu);
        }
    }
}

static const char HEX_DIGITS[] = "0123456789abcdef";

void dtc_u256_to_hex(const dtc_u256 *v, char out[65])
{
    for (int i = 0; i < 4; ++i) {
        uint64_t limb = v->limb[3 - i]; /* 大端显示：先高 limb */
        for (int j = 0; j < 16; ++j) {
            unsigned nibble =
                (unsigned)((limb >> (60 - 4 * j)) & 0xfu);
            out[i * 16 + j] = HEX_DIGITS[nibble];
        }
    }
    out[64] = '\0';
}

static int hex_val(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

bool dtc_u256_from_hex(dtc_u256 *v, const char *hex)
{
    if (strlen(hex) != 64) {
        return false;
    }
    uint8_t be[32];
    for (int i = 0; i < 32; ++i) {
        int hi = hex_val(hex[i * 2]);
        int lo = hex_val(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            return false;
        }
        be[i] = (uint8_t)((hi << 4) | lo);
    }
    /* 转成小端字节后装载 */
    uint8_t le[32];
    for (int i = 0; i < 32; ++i) {
        le[i] = be[31 - i];
    }
    dtc_u256_from_le_bytes(v, le);
    return true;
}

/*
 * uint256.h —— Ditcoin 的 256 位无符号整数（工作量 / 难度 / 目标值）
 *
 * 设计要点：
 *   * limb[0] 为最低 64 位，limb[3] 为最高 64 位（小端 limb 序）。
 *   * 只实现共识路径真正需要的运算：比较、加减、×u64、÷u64、Compact(nBits)。
 *   * 不引入 __int128 等编译器扩展：64×64→128 用 32 位半字手工实现，
 *     保证 -std=c11 可移植。
 *   * 除法/乘法溢出均返回饱和值或错误标志，不静默截断。
 */
#ifndef DTC_UINT256_H
#define DTC_UINT256_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint64_t limb[4]; /* limb[0] = 最低 64 位 ... limb[3] = 最高 64 位 */
} dtc_u256;

/* 全零 */
void dtc_u256_zero(dtc_u256 *v);

/* 由 64 位整数构造 */
void dtc_u256_set_u64(dtc_u256 *v, uint64_t x);

/* 判断是否为零 */
bool dtc_u256_is_zero(const dtc_u256 *v);

/* 比较：a<b 返回 -1，相等 0，a>b 返回 1 */
int dtc_u256_cmp(const dtc_u256 *a, const dtc_u256 *b);

/* 相等判断 */
bool dtc_u256_equal(const dtc_u256 *a, const dtc_u256 *b);

/* 加法：溢出返回 true（结果仍为截断后的值） */
bool dtc_u256_add(dtc_u256 *out, const dtc_u256 *a, const dtc_u256 *b);

/* 减法：a<b 时返回 true（结果按 2^256 回绕） */
bool dtc_u256_sub(dtc_u256 *out, const dtc_u256 *a, const dtc_u256 *b);

/*
 * 乘以 64 位标量：溢出（>2^256-1）返回 true，并把结果饱和为全 0xFF。
 * LWMA-1 中 L*sumTarget 的上界约为 2^252，正常不会触发饱和。
 */
bool dtc_u256_mul_u64(dtc_u256 *out, const dtc_u256 *a, uint64_t m);

/*
 * 除以 64 位标量：采用二进制长除，返回余数。
 * divisor==0 时返回 false 且结果置零（调用方必须自行避免该情况）。
 */
bool dtc_u256_div_u64(dtc_u256 *out, const dtc_u256 *a, uint64_t divisor,
                      uint64_t *remainder);

/* 与 64 位整数比较（用于困难度上限裁剪） */
int dtc_u256_cmp_u64(const dtc_u256 *a, uint64_t b);

/*
 * Bitcoin 风格 Compact（nBits）编码：
 *   compact = (size << 24) | (mantissa 的低 23 位)
 *   *negative = mantissa 的最高位（0x00800000）被置位
 *   *overflow = 数值无法用 256 位表示
 *
 * set_compact 返回值：true 表示解码成功；false 表示溢出（此时 *overflow
 * 为 true，且 v 被饱和为全 0xFF，避免后续目标比较出现「永远合法」的错判）。
 */
void dtc_u256_get_compact(const dtc_u256 *v, bool negative, uint32_t *compact);
bool dtc_u256_set_compact(dtc_u256 *v, uint32_t compact, bool *negative,
                          bool *overflow);

/*
 * 十六进制转换：
 *   to_hex 输出 64 个小写字符 + '\0'（buf 至少 65 字节），按大端显示。
 *   from_hex 接受恰好 64 个十六进制字符。
 */
void dtc_u256_to_hex(const dtc_u256 *v, char out[65]);
bool dtc_u256_from_hex(dtc_u256 *v, const char *hex);

/* 由 32 字节小端字节流（如区块头哈希）构造 */
void dtc_u256_from_le_bytes(dtc_u256 *v, const uint8_t bytes[32]);
void dtc_u256_to_le_bytes(const dtc_u256 *v, uint8_t out[32]);

#endif /* DTC_UINT256_H */

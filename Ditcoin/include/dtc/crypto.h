/*
 * crypto.h —— Ditcoin 密码学胶水层公开接口（M0）
 *
 * 分层策略（对应 SPEC 的 vendor + glue 约定）：
 *   * 本仓库以「自包含参考实现 + 标准向量」替代 git submodule 形式的 vendor
 *     （离线环境无法拉取），所有原语均用 RFC/FIPS 标准向量验证；
 *     详见 DITCOIN-SPEC.md 的「vendor 偏离清单」。
 *   * 胶水层（sha256d / sha256d_2parts / "DTC/" tagged hash / HKDF / sighash
 *     域开关）是链级隔离所在，必须有 Ditcoin 专属测试。
 *
 * ★ 全仓库约定：任何标记为 "DTC/..." 的 tagged hash 都在本层加前缀，
 *   调用方只传语义名（如 "TapTweak"），由 dtc_tagged_hash_dtc 拼 "DTC/"。
 */
#ifndef DTC_CRYPTO_H
#define DTC_CRYPTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* 256 位哈希值（内部字节序：与序列化一致的“自然”顺序，不做反转） */
typedef struct {
    uint8_t b[32];
} dtc_hash256;

/* ---------------------------------------------------------------------------
 * SHA-256（FIPS 180-4）
 * ------------------------------------------------------------------------- */
typedef struct {
    uint32_t state[8];
    uint64_t bitlen;      /* 已处理消息的比特数（含缓冲区未压缩部分？不含） */
    uint8_t buffer[64];
    size_t buflen;
} dtc_sha256_ctx;

void dtc_sha256_init(dtc_sha256_ctx *ctx);
void dtc_sha256_update(dtc_sha256_ctx *ctx, const void *data, size_t len);
void dtc_sha256_final(dtc_sha256_ctx *ctx, uint8_t out[32]);
void dtc_sha256(const void *data, size_t len, uint8_t out[32]);

/* ---------------------------------------------------------------------------
 * SHA-512（FIPS 180-4）
 * ------------------------------------------------------------------------- */
typedef struct {
    uint64_t state[8];
    uint64_t bitlen_hi;   /* 128 位消息长度的高 64 位（实际不会用到） */
    uint64_t bitlen_lo;
    uint8_t buffer[128];
    size_t buflen;
} dtc_sha512_ctx;

void dtc_sha512_init(dtc_sha512_ctx *ctx);
void dtc_sha512_update(dtc_sha512_ctx *ctx, const void *data, size_t len);
void dtc_sha512_final(dtc_sha512_ctx *ctx, uint8_t out[64]);
void dtc_sha512(const void *data, size_t len, uint8_t out[64]);

/* ---------------------------------------------------------------------------
 * RIPEMD-160（ISO/IEC 10118-3）
 * ------------------------------------------------------------------------- */
void dtc_ripemd160(const void *data, size_t len, uint8_t out[20]);

/* ---------------------------------------------------------------------------
 * SHA-1（FIPS 180-4）—— 仅用于脚本 OP_SHA1
 *
 * ★ 安全警告：SHA-1 已不具备抗碰撞性，禁止用于签名/地址/PoW 等任何安全
 *   相关场景。本函数只提供一次性接口，避免被误当作通用哈希复用。
 * ------------------------------------------------------------------------- */
void dtc_sha1(const void *data, size_t len, uint8_t out[20]);

/* ---------------------------------------------------------------------------
 * 组合哈希
 * ------------------------------------------------------------------------- */

/* SHA256(SHA256(data)) —— Ditcoin 的 PoW 与 txid 所用哈希 */
void dtc_sha256d(const void *data, size_t len, uint8_t out[32]);

/*
 * 两段式 SHA256d：等价于 SHA256d(part1 || part2)，但避免拼接分配。
 * 用于 "DTC/" tagged hash、v2 握手 AAD、sighash 域分离等场景。
 */
void dtc_sha256d_2parts(const void *part1, size_t len1, const void *part2,
                        size_t len2, uint8_t out[32]);

/* RIPEMD160(SHA256(data)) */
void dtc_hash160(const void *data, size_t len, uint8_t out[20]);

/*
 * BIP340 风格 tagged hash，但固定使用 Ditcoin 域前缀：
 *   tag_hash = SHA256("DTC/" || tag)
 *   out      = SHA256(tag_hash || tag_hash || data)
 *
 * ★ tag 参数不要自带 "DTC/"。例如 dtc_tagged_hash_dtc("TapTweak", ...)
 *   实际计算的是 SHA256d 风格结构，域字符串为 "DTC/TapTweak"。
 *
 * 该函数只做一次 SHA256 拼接，不做 double-SHA；与 BIP340 定义一致。
 */
void dtc_tagged_hash_dtc(const char *tag, const void *data, size_t len,
                         uint8_t out[32]);

/* 两段数据的 tagged hash（避免拼接）：out = H_tag(part1 || part2) */
void dtc_tagged_hash_dtc_2parts(const char *tag, const void *part1, size_t len1,
                                const void *part2, size_t len2, uint8_t out[32]);

/* ---------------------------------------------------------------------------
 * HMAC / KDF
 * ------------------------------------------------------------------------- */
void dtc_hmac_sha256(const void *key, size_t keylen, const void *msg,
                     size_t msglen, uint8_t out[32]);
void dtc_hmac_sha512(const void *key, size_t keylen, const void *msg,
                     size_t msglen, uint8_t out[64]);

/*
 * HKDF-SHA256（RFC 5869）：v2 传输握手使用。
 *   extract: PRK = HMAC(salt, IKM)          —— salt 为 Ditcoin 专属字符串
 *   expand : OKM = T(1) || T(2) || ...
 * outlen 上限 255*32（RFC 约束）。
 */
void dtc_hkdf_sha256_extract(const void *salt, size_t saltlen, const void *ikm,
                             size_t ikmlen, uint8_t prk[32]);
bool dtc_hkdf_sha256_expand(const uint8_t prk[32], const void *info,
                            size_t infolen, uint8_t *out, size_t outlen);

/* PBKDF2-HMAC-SHA512（BIP39 助记词：2048 轮，64 字节） */
bool dtc_pbkdf2_sha512(const void *password, size_t passwordlen,
                       const void *salt, size_t saltlen, uint32_t iterations,
                       uint8_t *out, size_t outlen);

/* ---------------------------------------------------------------------------
 * SipHash-2-4（compact block short id）
 * ------------------------------------------------------------------------- */
uint64_t dtc_siphash24(const uint8_t key[16], const void *data, size_t len);

/* ---------------------------------------------------------------------------
 * 地址编码
 * ------------------------------------------------------------------------- */

/*
 * Base58Check 编码：payload = version(1B) || data || checksum(4B, SHA256d 前 4B)
 * 返回写入 out 的字符数（不含 '\0'）；out 容量不足返回 -1。
 */
int dtc_base58check_encode(uint8_t version, const uint8_t *data, size_t len,
                           char *out, size_t outcap);

/*
 * Base58Check 解码：校验版本字节与校验和。
 * 成功返回 payload 长度（不含 version），失败返回 -1。
 * 若 version_out 非 NULL 则输出版本字节。
 */
int dtc_base58check_decode(const char *str, size_t strlen, uint8_t *version_out,
                           uint8_t *data, size_t datacap);

/* Bech32 编码风格 */
typedef enum {
    DTC_BECH32 = 1,   /* 校验常量 1 —— 用于 segwit v0 */
    DTC_BECH32M = 2   /* 校验常量 0x2bc830a3 —— 用于 segwit v1+ */
} dtc_bech32_enc;

/*
 * Segwit 地址编码（BIP173/BIP350）：
 *   hrp        —— "dtc" / "tdtc"
 *   witver     —— 0..16
 *   program    —— 2..40 字节
 * 自动按规范选择 bech32(v0) / bech32m(v1+)。返回字符串长度或 -1。
 */
int dtc_segwit_addr_encode(const char *hrp, uint8_t witver,
                           const uint8_t *program, size_t programlen, char *out,
                           size_t outcap);

/*
 * Segwit 地址解码：输出 witver 与 program，并强制校验
 *   * HRP 与期望值一致（防止误收 bc1 等外链地址）
 *   * v0 必须用 bech32，v1+ 必须用 bech32m
 *   * program 长度合法
 * 成功返回 program 字节数，失败返回 -1。
 */
int dtc_segwit_addr_decode(const char *expected_hrp, const char *str,
                           size_t strlen, uint8_t *witver_out,
                           uint8_t *program, size_t programcap);

#endif /* DTC_CRYPTO_H */

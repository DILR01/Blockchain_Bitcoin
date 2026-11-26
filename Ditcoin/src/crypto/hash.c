/*
 * hash.c —— 组合哈希与 Ditcoin 域分隔 tagged hash
 */
#include "dtc/crypto.h"

#include <string.h>

void dtc_sha256d(const void *data, size_t len, uint8_t out[32])
{
    uint8_t first[32];
    dtc_sha256(data, len, first);
    dtc_sha256(first, sizeof(first), out);
}

void dtc_sha256d_2parts(const void *part1, size_t len1, const void *part2,
                        size_t len2, uint8_t out[32])
{
    dtc_sha256_ctx ctx;
    uint8_t first[32];
    dtc_sha256_init(&ctx);
    dtc_sha256_update(&ctx, part1, len1);
    dtc_sha256_update(&ctx, part2, len2);
    dtc_sha256_final(&ctx, first);
    dtc_sha256(first, sizeof(first), out);
}

void dtc_hash160(const void *data, size_t len, uint8_t out[20])
{
    uint8_t h[32];
    dtc_sha256(data, len, h);
    dtc_ripemd160(h, sizeof(h), out);
}

/* 计算 "DTC/" || tag 的 SHA256（tagged hash 的 tag_hash） */
static bool tag_hash_compute(const char *tag, uint8_t out[32])
{
    static const char prefix[] = "DTC/";
    size_t taglen = strlen(tag);
    size_t prefixlen = sizeof(prefix) - 1;
    if (taglen + prefixlen > 64) {
        return false;
    }
    char full[64];
    memcpy(full, prefix, prefixlen);
    memcpy(full + prefixlen, tag, taglen);
    dtc_sha256(full, prefixlen + taglen, out);
    return true;
}

void dtc_tagged_hash_dtc_2parts(const char *tag, const void *part1, size_t len1,
                                const void *part2, size_t len2, uint8_t out[32])
{
    uint8_t th[32];
    if (!tag_hash_compute(tag, th)) {
        memset(out, 0, 32);
        return;
    }
    dtc_sha256_ctx ctx;
    dtc_sha256_init(&ctx);
    dtc_sha256_update(&ctx, th, 32);
    dtc_sha256_update(&ctx, th, 32);
    dtc_sha256_update(&ctx, part1, len1);
    dtc_sha256_update(&ctx, part2, len2);
    dtc_sha256_final(&ctx, out);
}

void dtc_tagged_hash_dtc(const char *tag, const void *data, size_t len,
                         uint8_t out[32])
{
    /* 单段数据即第二段长度为 0 的两段式调用 */
    dtc_tagged_hash_dtc_2parts(tag, data, len, NULL, 0, out);
}

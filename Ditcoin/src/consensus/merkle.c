/*
 * merkle.c —— Merkle 树实现
 */
#include "dtc/merkle.h"

#include <stdlib.h>
#include <string.h>

#include "dtc/crypto.h"

/* 通用的“成对归并”实现，witness 版本通过先把 coinbase wtxid 置零复用 */
static bool merkle_root_internal(const uint8_t (*hashes)[32], size_t n,
                                 uint8_t out[32])
{
    if (n == 0) {
        memset(out, 0, 32);
        return true;
    }

    uint8_t *level = (uint8_t *)malloc(n * 32);
    if (level == NULL) {
        memset(out, 0, 32);
        return false;
    }
    memcpy(level, hashes, n * 32);

    size_t count = n;
    while (count > 1) {
        size_t next_count = (count + 1) / 2;
        for (size_t i = 0; i < next_count; ++i) {
            const uint8_t *left = level + (i * 2) * 32;
            const uint8_t *right =
                (i * 2 + 1 < count) ? (level + (i * 2 + 1) * 32) : left;
            uint8_t parent[32];
            dtc_sha256d_2parts(left, 32, right, 32, parent);
            /* 结果写回同一缓冲区的第 i 槽位（安全：i*2 >= i） */
            memcpy(level + i * 32, parent, 32);
        }
        count = next_count;
    }

    memcpy(out, level, 32);
    free(level);
    return true;
}

void dtc_merkle_root(const uint8_t (*hashes)[32], size_t n, uint8_t out[32])
{
    (void)merkle_root_internal(hashes, n, out);
}

void dtc_witness_merkle_root(const uint8_t (*wtxids)[32], size_t n,
                             uint8_t out[32])
{
    if (n == 0) {
        memset(out, 0, 32);
        return;
    }

    uint8_t *copy = (uint8_t *)malloc(n * 32);
    if (copy == NULL) {
        memset(out, 0, 32);
        return;
    }
    memcpy(copy, wtxids, n * 32);
    /* BIP141：见证树中 coinbase 的 wtxid 视为 0 */
    memset(copy, 0, 32);
    (void)merkle_root_internal((const uint8_t(*)[32])copy, n, out);
    free(copy);
}

void dtc_witness_commitment(const uint8_t witness_root[32],
                            const uint8_t reserved[32], uint8_t out[32])
{
    dtc_sha256d_2parts(witness_root, 32, reserved, 32, out);
}

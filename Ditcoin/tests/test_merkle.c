/*
 * test_merkle.c —— Merkle 树与见证承诺
 */
#include "test_util.h"

#include "dtc/crypto.h"
#include "dtc/merkle.h"

void test_merkle(void)
{
    test_group("单叶子 = 叶子自身");
    {
        uint8_t leaves[1][32];
        uint8_t root[32];
        memset(leaves[0], 0x11, 32);
        dtc_merkle_root((const uint8_t(*)[32])leaves, 1, root);
        CHECK(memcmp(root, leaves[0], 32) == 0);
    }

    test_group("两个叶子 = SHA256d(L0 || L1)");
    {
        uint8_t leaves[2][32];
        uint8_t root[32];
        uint8_t cat[64];
        uint8_t expect[32];
        memset(leaves[0], 0x01, 32);
        memset(leaves[1], 0x02, 32);
        memcpy(cat, leaves[0], 32);
        memcpy(cat + 32, leaves[1], 32);
        dtc_sha256d(cat, sizeof(cat), expect);
        dtc_merkle_root((const uint8_t(*)[32])leaves, 2, root);
        CHECK(memcmp(root, expect, 32) == 0);
    }

    test_group("奇数个叶子复制最后一个");
    {
        uint8_t leaves[3][32];
        uint8_t a[32], b[32];
        uint8_t cat[64];
        uint8_t expect[32];
        memset(leaves[0], 0x0a, 32);
        memset(leaves[1], 0x0b, 32);
        memset(leaves[2], 0x0c, 32);
        dtc_merkle_root((const uint8_t(*)[32])leaves, 3, a);
        /* 手工计算：h01 = H(L0||L1)，h22 = H(L2||L2)，root = H(h01||h22) */
        memcpy(cat, leaves[0], 32);
        memcpy(cat + 32, leaves[1], 32);
        dtc_sha256d(cat, sizeof(cat), b);
        uint8_t h01[32];
        memcpy(h01, b, 32);
        memcpy(cat, leaves[2], 32);
        memcpy(cat + 32, leaves[2], 32);
        dtc_sha256d(cat, sizeof(cat), b);
        uint8_t h22[32];
        memcpy(h22, b, 32);
        memcpy(cat, h01, 32);
        memcpy(cat + 32, h22, 32);
        dtc_sha256d(cat, sizeof(cat), expect);
        CHECK(memcmp(a, expect, 32) == 0);
    }

    test_group("空集合返回全零");
    {
        uint8_t root[32];
        memset(root, 0xff, 32);
        dtc_merkle_root(NULL, 0, root);
        uint8_t zero[32] = {0};
        CHECK(memcmp(root, zero, 32) == 0);
    }

    test_group("见证 merkle root：coinbase 位置置零");
    {
        uint8_t w[2][32];
        uint8_t a[32], b[32];
        uint8_t cat[64];
        memset(w[0], 0x33, 32); /* 真实 wtxid，应被置为 0 */
        memset(w[1], 0x44, 32);
        dtc_witness_merkle_root((const uint8_t(*)[32])w, 2, a);
        uint8_t zero[32] = {0};
        memcpy(cat, zero, 32);
        memcpy(cat + 32, w[1], 32);
        dtc_sha256d(cat, sizeof(cat), b);
        CHECK(memcmp(a, b, 32) == 0);
    }

    test_group("见证承诺 = SHA256d(root || reserved)");
    {
        uint8_t root[32];
        uint8_t reserved[32];
        uint8_t out[32];
        uint8_t cat[64];
        uint8_t expect[32];
        memset(root, 0x55, 32);
        memset(reserved, 0x66, 32);
        memcpy(cat, root, 32);
        memcpy(cat + 32, reserved, 32);
        dtc_sha256d(cat, sizeof(cat), expect);
        dtc_witness_commitment(root, reserved, out);
        CHECK(memcmp(out, expect, 32) == 0);
    }
}

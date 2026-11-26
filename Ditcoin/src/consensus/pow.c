/*
 * pow.c —— PoW 算法抽象
 *
 * 默认 SHA256d，与 Bitcoin 共用同一算力市场（见 README 声明二）。
 * 切换 Scrypt/AuxPOW 只需实现新的 dtc_pow_algo_t 并重新挖创世块；
 * 共识代码只依赖本抽象，不直接调用哈希函数。
 */
#include "dtc/consensus.h"

#include <stddef.h>

#include "dtc/crypto.h"

static void pow_sha256d(const uint8_t *hdr, size_t len, uint8_t out[32])
{
    dtc_sha256d(hdr, len, out);
}

static size_t pow_sha256d_scratch(void)
{
    return 0; /* SHA256d 不需要 scratch 缓冲；Scrypt 需要 ~1MB */
}

const dtc_pow_algo_t dtc_pow_sha256d = {
    .name = "sha256d",
    .hash = pow_sha256d,
    .scratch_bytes = pow_sha256d_scratch,
};

const dtc_pow_algo_t *const dtc_pow_default = &dtc_pow_sha256d;

void dtc_pow_hash_header(const dtc_pow_algo_t *algo, const uint8_t header[80],
                         uint8_t out[32])
{
    if (algo == NULL || algo->hash == NULL) {
        return;
    }
    algo->hash(header, 80, out);
}

bool dtc_pow_check_hash(const uint8_t hash[32], const dtc_u256 *target)
{
    dtc_u256 h;
    dtc_u256_from_le_bytes(&h, hash);
    return dtc_u256_cmp(&h, target) <= 0;
}

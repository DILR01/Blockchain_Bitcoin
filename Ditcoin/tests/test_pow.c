/*
 * test_pow.c —— PoW 抽象与目标比较
 */
#include "test_util.h"

#include "dtc/consensus.h"
#include "dtc/crypto.h"

void test_pow(void)
{
    test_group("算法抽象");
    CHECK(strcmp(dtc_pow_sha256d.name, "sha256d") == 0);
    CHECK(dtc_pow_sha256d.scratch_bytes() == 0);
    CHECK(dtc_pow_default == &dtc_pow_sha256d);

    test_group("SHA256d 与直接调用一致");
    {
        uint8_t hdr[80];
        uint8_t a[32];
        uint8_t b[32];
        for (size_t i = 0; i < sizeof(hdr); ++i) {
            hdr[i] = (uint8_t)(i * 7u + 3u);
        }
        dtc_pow_hash_header(&dtc_pow_sha256d, hdr, a);
        dtc_sha256d(hdr, sizeof(hdr), b);
        CHECK(memcmp(a, b, 32) == 0);
    }

    test_group("目标比较");
    {
        uint8_t zero[32] = {0};
        uint8_t ones[32];
        memset(ones, 0xff, sizeof(ones));
        dtc_u256 t;

        dtc_u256_zero(&t);
        CHECK(dtc_pow_check_hash(zero, &t)); /* 0 <= 0 */
        dtc_u256_set_u64(&t, 1);
        CHECK(dtc_pow_check_hash(zero, &t)); /* 0 <= 1 */
        CHECK(!dtc_pow_check_hash(ones, &t)); /* 全 FF 不满足目标 1 */

        /* 目标和哈希都按小端解释 */
        uint8_t hash_le[32] = {0};
        hash_le[0] = 0x02;
        dtc_u256_set_u64(&t, 1);
        CHECK(!dtc_pow_check_hash(hash_le, &t)); /* 2 > 1 */
        dtc_u256_set_u64(&t, 2);
        CHECK(dtc_pow_check_hash(hash_le, &t)); /* 2 <= 2 */
    }
}

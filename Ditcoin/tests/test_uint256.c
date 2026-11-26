/*
 * test_uint256.c —— 256 位整数与 Compact(nBits) 编码
 */
#include "test_util.h"

#include "dtc/uint256.h"

void test_uint256(void)
{
    dtc_u256 a, b, c;
    char hexbuf[65];

    test_group("uint256 基本运算");
    dtc_u256_zero(&a);
    CHECK(dtc_u256_is_zero(&a));
    dtc_u256_set_u64(&a, 100);
    dtc_u256_set_u64(&b, 58);
    CHECK(dtc_u256_cmp(&a, &b) == 1);
    CHECK(dtc_u256_cmp(&b, &a) == -1);
    CHECK(dtc_u256_add(&c, &a, &b) == false);
    dtc_u256_set_u64(&b, 158);
    CHECK(dtc_u256_equal(&c, &b));
    CHECK(dtc_u256_sub(&c, &a, &b) == true); /* 100-158 下溢 */
    CHECK(dtc_u256_cmp_u64(&a, 100) == 0);
    CHECK(dtc_u256_cmp_u64(&a, 99) == 1);
    CHECK(dtc_u256_cmp_u64(&a, 101) == -1);

    test_group("乘法 / 除法（64 位标量）");
    dtc_u256_set_u64(&a, 1000);
    CHECK(dtc_u256_mul_u64(&c, &a, 123456789ULL) == false);
    CHECK(dtc_u256_cmp_u64(&c, 1000ULL * 123456789ULL) == 0);
    uint64_t rem = 0;
    CHECK(dtc_u256_div_u64(&b, &c, 123456789ULL, &rem));
    CHECK(dtc_u256_cmp_u64(&b, 1000) == 0);
    CHECK(rem == 0);
    CHECK(dtc_u256_div_u64(&b, &c, 0, &rem) == false);
    CHECK(dtc_u256_is_zero(&b));

    test_group("十六进制往返");
    dtc_u256_set_u64(&a, 0x0123456789abcdefULL);
    dtc_u256_to_hex(&a, hexbuf);
    CHECK(strcmp(hexbuf,
                 "0000000000000000000000000000000000000000000000000123456789abcdef") ==
          0);
    CHECK(dtc_u256_from_hex(&b, hexbuf));
    CHECK(dtc_u256_equal(&a, &b));
    CHECK(!dtc_u256_from_hex(&b, "12")); /* 长度必须 64 */

    test_group("Compact(nBits) 编解码");
    /* Bitcion/Ditcoin 的 powLimit: 00000000ffff...ff → nBits 0x1d00ffff */
    CHECK(dtc_u256_from_hex(
        &a, "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
    uint32_t compact = 0;
    dtc_u256_get_compact(&a, false, &compact);
    CHECK(compact == 0x1d00ffffu);

    bool neg = true;
    bool overflow = true;
    CHECK(dtc_u256_set_compact(&b, 0x1d00ffffu, &neg, &overflow));
    CHECK(!neg);
    CHECK(!overflow);
    CHECK(dtc_u256_equal(&a, &b));

    /* 0 的 compact 为 0 */
    dtc_u256_zero(&a);
    dtc_u256_get_compact(&a, false, &compact);
    CHECK(compact == 0);

    /* 小数值（mantissa 需要右移） */
    dtc_u256_set_u64(&a, 0x12);
    dtc_u256_get_compact(&a, false, &compact);
    CHECK(dtc_u256_set_compact(&b, compact, &neg, &overflow));
    CHECK(dtc_u256_equal(&a, &b));

    /* 小端字节序往返（区块头哈希用） */
    uint8_t le[32];
    dtc_u256_set_u64(&a, 0x0102030405060708ULL);
    dtc_u256_to_le_bytes(&a, le);
    CHECK(le[0] == 0x08 && le[7] == 0x01);
    dtc_u256_from_le_bytes(&b, le);
    CHECK(dtc_u256_equal(&a, &b));
}

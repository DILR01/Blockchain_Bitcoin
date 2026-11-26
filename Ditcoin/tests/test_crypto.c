/*
 * test_crypto.c —— M0 密码学向量
 *
 * 全部使用公开标准向量（FIPS / RFC / BIP），不依赖被测实现自身：
 *   * SHA-256 / SHA-512 / SHA-1 / RIPEMD-160：FIPS 180-4 与 ISO 向量
 *   * HMAC-SHA512：RFC 4231 Test Case 1
 *   * HKDF-SHA256：RFC 5869 Test Case 1
 *   * PBKDF2-HMAC-SHA512：由 Python hashlib 独立生成的期望值
 *   * SipHash-2-4：参考实现官方向量
 *   * HD 域分离：HMAC-SHA512("Ditcoin seed", seed) 的 Ditcoin 专属向量
 *   * Bech32 / Bech32m：BIP173/BIP350（用独立实现交叉验证过的字符串）
 *   * Base58Check：往返 + 版本字节
 */
#include "test_util.h"

#include "dtc/crypto.h"

/* 比较摘要与十六进制期望值 */
static void check_digest(const uint8_t *d, size_t n, const char *expect)
{
    uint8_t want[64];
    size_t wl = check_hex(expect, want, sizeof(want));
    CHECK(wl == n);
    if (wl == n && n > 0) {
        CHECK(memcmp(d, want, n) == 0);
    }
}

void test_crypto(void)
{
    uint8_t h[64];

    test_group("SHA-256 / SHA-512");
    dtc_sha256("abc", 3, h);
    check_digest(h, 32,
                 "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    dtc_sha256("", 0, h);
    check_digest(h, 32,
                 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    dtc_sha512("abc", 3, h);
    check_digest(h, 64,
                 "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                 "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");

    test_group("SHA-1 / RIPEMD-160 / Hash160");
    dtc_sha1("abc", 3, h);
    check_digest(h, 20, "a9993e364706816aba3e25717850c26c9cd0d89d");
    dtc_ripemd160("abc", 3, h);
    check_digest(h, 20, "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
    dtc_hash160("abc", 3, h);
    check_digest(h, 20, "bb1be98c142444d7a56aa3981c3942a978e4dc33");

    test_group("SHA256d 两段式");
    {
        const uint8_t p1[3] = {1, 2, 3};
        const uint8_t p2[4] = {4, 5, 6, 7};
        uint8_t joined[7];
        uint8_t h1[32], h2[32];
        memcpy(joined, p1, 3);
        memcpy(joined + 3, p2, 4);
        dtc_sha256d(joined, sizeof(joined), h1);
        dtc_sha256d_2parts(p1, sizeof(p1), p2, sizeof(p2), h2);
        CHECK(memcmp(h1, h2, 32) == 0);
    }

    test_group("HMAC-SHA512 (RFC 4231 TC1)");
    {
        uint8_t key[20];
        uint8_t out[64];
        memset(key, 0x0b, sizeof(key));
        dtc_hmac_sha512(key, sizeof(key), "Hi There", 8, out);
        check_digest(out, 64,
                     "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde"
                     "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854");
    }

    test_group("HKDF-SHA256 (RFC 5869 TC1)");
    {
        uint8_t ikm[22];
        uint8_t salt[13];
        uint8_t info[10];
        uint8_t prk[32];
        uint8_t okm[42];
        memset(ikm, 0x0b, sizeof(ikm));
        for (size_t i = 0; i < 13; ++i) {
            salt[i] = (uint8_t)i;
        }
        for (size_t i = 0; i < 10; ++i) {
            info[i] = (uint8_t)(0xf0 + i);
        }
        dtc_hkdf_sha256_extract(salt, sizeof(salt), ikm, sizeof(ikm), prk);
        check_digest(prk, 32,
                     "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        CHECK(dtc_hkdf_sha256_expand(prk, info, sizeof(info), okm, sizeof(okm)));
        check_digest(okm, 42,
                     "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                     "34007208d5b887185865");
    }

    test_group("PBKDF2-HMAC-SHA512");
    {
        uint8_t out[64];
        CHECK(dtc_pbkdf2_sha512("password", 8, "salt", 4, 1, out, sizeof(out)));
        check_digest(out, 64,
                     "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252"
                     "c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce");
    }

    test_group("SipHash-2-4");
    {
        uint8_t key[16];
        uint8_t msg[15];
        for (size_t i = 0; i < 16; ++i) {
            key[i] = (uint8_t)i;
        }
        for (size_t i = 0; i < 15; ++i) {
            msg[i] = (uint8_t)i;
        }
        CHECK(dtc_siphash24(key, msg, sizeof(msg)) == 0xa129ca6149be45e5ULL);
        CHECK(dtc_siphash24(key, msg, 0) == 0x726fdb47dd0e0e31ULL);
    }

    test_group("HD 域分离（Ditcoin seed）");
    {
        uint8_t seed[16];
        uint8_t out[64];
        for (size_t i = 0; i < 16; ++i) {
            seed[i] = (uint8_t)i;
        }
        /* Ditcoin 用 "Ditcoin seed" 作为 HMAC 键，与 BIP32 的 "Bitcoin seed" 隔离 */
        dtc_hmac_sha512("Ditcoin seed", 12, seed, sizeof(seed), out);
        check_digest(out, 64,
                     "dcb95da27e9161f27180d64c7e7e0fb87cf0df1b0c36e5972ab03ab7dd17e5a4"
                     "12b79390482c7a12ecc714cbd1b3067931ab51c697a68284385e12571c931da5");
        /* 同一 seed 用 Bitcoin 键得到不同结果，证明域分隔生效 */
        dtc_hmac_sha512("Bitcoin seed", 12, seed, sizeof(seed), out);
        check_digest(out, 64,
                     "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
                     "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508");
    }

    test_group("Base58Check");
    {
        uint8_t payload[20];
        char addr[64];
        for (size_t i = 0; i < sizeof(payload); ++i) {
            payload[i] = (uint8_t)i;
        }
        int n = dtc_base58check_encode(30, payload, sizeof(payload), addr,
                                       sizeof(addr));
        CHECK(n > 0);
        /* 版本 30 的首字符为 'D'（Ditcoin P2PKH 前缀） */
        CHECK(n > 0 && addr[0] == 'D');
        uint8_t ver = 0;
        uint8_t back[32];
        int m = dtc_base58check_decode(addr, (size_t)n, &ver, back, sizeof(back));
        CHECK(m == (int)sizeof(payload));
        CHECK(ver == 30);
        CHECK(m == (int)sizeof(payload) && memcmp(back, payload, sizeof(payload)) == 0);

        /* 篡改最后一个字符必须导致校验和失败 */
        addr[n - 1] = (addr[n - 1] == '1') ? '2' : '1';
        CHECK(dtc_base58check_decode(addr, (size_t)n, NULL, back, sizeof(back)) < 0);

        /* Bitcoin 主网地址的版本为 0，不是 Ditcoin 的 30 */
        const char *btc = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        uint8_t bver = 0xff;
        int r = dtc_base58check_decode(btc, strlen(btc), &bver, back,
                                       sizeof(back));
        CHECK(r == 20);
        CHECK(bver == 0);
        CHECK(bver != 30);
    }

    test_group("Bech32 / Bech32m");
    {
        uint8_t prog20[20];
        uint8_t prog32[32];
        check_hex("751e76e8199196d454941c45d1b3a323f1433bd6", prog20,
                  sizeof(prog20));
        check_hex(
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            prog32, sizeof(prog32));

        /* v0 → bech32；与独立实现产出的字符串逐字符一致 */
        char out[100];
        int n = dtc_segwit_addr_encode("dtc", 0, prog20, sizeof(prog20), out,
                                       sizeof(out));
        CHECK(n > 0);
        CHECK(strcmp(out, "dtc1qw508d6qejxtdg4y5r3zarvary0c5xw7kel5jgr") == 0);

        /* v1 → bech32m */
        n = dtc_segwit_addr_encode("dtc", 1, prog32, sizeof(prog32), out,
                                   sizeof(out));
        CHECK(n > 0);
        CHECK(strcmp(out,
                     "dtc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqd4k6th") ==
              0);

        /* 解码自己的输出 */
        uint8_t ver = 0xff;
        uint8_t prog[40];
        int m = dtc_segwit_addr_decode("dtc", out, (size_t)n, &ver, prog,
                                       sizeof(prog));
        CHECK(m == 32);
        CHECK(ver == 1);
        CHECK(m == 32 && memcmp(prog, prog32, 32) == 0);

        /* 外部链地址必须被 HRP 检查拒绝 */
        const char *btc_addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        CHECK(dtc_segwit_addr_decode("dtc", btc_addr, strlen(btc_addr), &ver, prog,
                                     sizeof(prog)) < 0);
        /* 但用 bc 作为期望前缀时能正确解出 v0 程序（证明解码器本身正确） */
        m = dtc_segwit_addr_decode("bc", btc_addr, strlen(btc_addr), &ver, prog,
                                   sizeof(prog));
        CHECK(m == 20);
        CHECK(ver == 0);
        CHECK(m == 20 && memcmp(prog, prog20, 20) == 0);

        /* 校验和损坏必须失败 */
        char bad[100];
        const char *good = "dtc1qw508d6qejxtdg4y5r3zarvary0c5xw7kel5jgr";
        memcpy(bad, good, strlen(good) + 1);
        bad[10] = (bad[10] == 'q') ? 'p' : 'q';
        CHECK(dtc_segwit_addr_decode("dtc", bad, strlen(bad), &ver, prog,
                                     sizeof(prog)) < 0);
    }
}

/*
 * hkdf.c —— HKDF-SHA256 与 PBKDF2-HMAC-SHA512
 *
 * HKDF 用于 M3 加密传输握手的密钥派生；
 * PBKDF2 用于 M6 的 BIP39 助记词种子（2048 轮 / 64 字节）。
 */
#include "dtc/crypto.h"

#include <string.h>

void dtc_hkdf_sha256_extract(const void *salt, size_t saltlen, const void *ikm,
                             size_t ikmlen, uint8_t prk[32])
{
    static const uint8_t zero_salt[32] = {0};
    if (saltlen == 0) {
        dtc_hmac_sha256(zero_salt, sizeof(zero_salt), ikm, ikmlen, prk);
    } else {
        dtc_hmac_sha256(salt, saltlen, ikm, ikmlen, prk);
    }
}

bool dtc_hkdf_sha256_expand(const uint8_t prk[32], const void *info,
                            size_t infolen, uint8_t *out, size_t outlen)
{
    if (outlen > 255u * 32u) {
        return false;
    }

    /* Ditcoin 的 info 均为固定短字符串（如 6 个 key 的标签），
     * 限制长度以简化栈缓冲；超长直接判错而不是悄悄降级。 */
    if (infolen > 64) {
        return false;
    }

    uint8_t t[32];
    size_t tlen = 0;
    size_t done = 0;
    uint8_t counter = 1;

    while (done < outlen) {
        /* T(i) = HMAC(PRK, T(i-1) || info || i) */
        uint8_t msg[32 + 64 + 1];
        size_t msglen = 0;
        memcpy(msg, t, tlen);
        msglen += tlen;
        memcpy(msg + msglen, info, infolen);
        msglen += infolen;
        msg[msglen] = counter;
        msglen += 1;

        dtc_hmac_sha256(prk, 32, msg, msglen, t);
        tlen = 32;

        size_t take = outlen - done;
        if (take > 32) {
            take = 32;
        }
        memcpy(out + done, t, take);
        done += take;
        counter += 1;
    }
    return true;
}

bool dtc_pbkdf2_sha512(const void *password, size_t passwordlen,
                       const void *salt, size_t saltlen, uint32_t iterations,
                       uint8_t *out, size_t outlen)
{
    if (iterations == 0) {
        return false;
    }

    /* BIP39 的 salt 为 "mnemonic" + passphrase，正常 < 100 字节；
     * 限制上限既避免栈溢出，也防止调用方误传巨大缓冲。 */
    if (saltlen > 1024) {
        return false;
    }

    const uint8_t *pw = (const uint8_t *)password;
    const uint8_t *sa = (const uint8_t *)salt;
    uint32_t block = 1;
    size_t done = 0;

    while (done < outlen) {
        /* U1 = HMAC(pw, salt || INT_BE32(block)) */
        uint8_t buf[1024 + 4];
        memcpy(buf, sa, saltlen);
        buf[saltlen] = (uint8_t)((block >> 24) & 0xffu);
        buf[saltlen + 1] = (uint8_t)((block >> 16) & 0xffu);
        buf[saltlen + 2] = (uint8_t)((block >> 8) & 0xffu);
        buf[saltlen + 3] = (uint8_t)(block & 0xffu);

        uint8_t u[64];
        dtc_hmac_sha512(pw, passwordlen, buf, saltlen + 4, u);

        uint8_t t[64];
        memcpy(t, u, sizeof(u));

        for (uint32_t i = 1; i < iterations; ++i) {
            dtc_hmac_sha512(pw, passwordlen, u, sizeof(u), u);
            for (int j = 0; j < 64; ++j) {
                t[j] ^= u[j];
            }
        }

        size_t take = outlen - done;
        if (take > 64) {
            take = 64;
        }
        memcpy(out + done, t, take);
        done += take;
        block += 1;
    }
    return true;
}

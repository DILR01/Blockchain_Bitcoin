/*
 * bech32.c —— Bech32 / Bech32m 与 Segwit 地址（BIP173 / BIP350）
 *
 * 规则：
 *   * v0 程序（20/32 字节）使用 bech32 校验常量 1
 *   * v1..v16 使用 bech32m 校验常量 0x2bc830a3
 *   * HRP 固定为 dtc / tdtc；解码时强制比对，bc1/tb1 等直接拒绝
 *   * 只接受全小写地址（与 Core 的“全小写或全大写”不同，故意收窄）
 */
#include "dtc/crypto.h"

#include <string.h>

static const char B32_CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

#define BECH32_CONST 1u
#define BECH32M_CONST 0x2bc830a3u
#define BECH32_MAX_LEN 90

static uint32_t polymod_step(uint32_t pre)
{
    uint8_t b = (uint8_t)(pre >> 25);
    return ((pre & 0x1ffffffu) << 5) ^
           ((b & 1u) ? 0x3b6a57b2u : 0u) ^
           ((b & 2u) ? 0x26508e6du : 0u) ^
           ((b & 4u) ? 0x1ea119fau : 0u) ^
           ((b & 8u) ? 0x3d4233ddu : 0u) ^
           ((b & 16u) ? 0x2a1462b3u : 0u);
}

static uint32_t polymod_hrp(const char *hrp, size_t hrplen)
{
    uint32_t chk = 1;
    for (size_t i = 0; i < hrplen; ++i) {
        chk = polymod_step(chk) ^ ((uint32_t)(uint8_t)hrp[i] >> 5);
    }
    chk = polymod_step(chk);
    for (size_t i = 0; i < hrplen; ++i) {
        chk = polymod_step(chk) ^ ((uint32_t)(uint8_t)hrp[i] & 0x1fu);
    }
    return chk;
}

static uint32_t polymod_data(uint32_t chk, const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        chk = polymod_step(chk) ^ data[i];
    }
    return chk;
}

/* 8 位字节流 ↔ 5 位组转换（标准 convertbits） */
static bool convert_bits(uint8_t *out, size_t *outlen, size_t outcap,
                         const uint8_t *in, size_t inlen, int frombits,
                         int tobits, bool pad)
{
    uint32_t acc = 0;
    int bits = 0;
    size_t pos = 0;
    const uint32_t maxv = (uint32_t)((1u << tobits) - 1u);
    /* 保持 acc 不溢出 32 位：只需保留最多 frombits+tobits-1 位 */
    const uint32_t mask = (uint32_t)((1u << (frombits + tobits - 1)) - 1u);

    for (size_t i = 0; i < inlen; ++i) {
        acc = ((acc << frombits) | in[i]) & mask;
        bits += frombits;
        while (bits >= tobits) {
            bits -= tobits;
            if (pos >= outcap) {
                return false;
            }
            out[pos++] = (uint8_t)((acc >> bits) & maxv);
        }
    }

    if (pad) {
        if (bits > 0) {
            if (pos >= outcap) {
                return false;
            }
            out[pos++] = (uint8_t)((acc << (tobits - bits)) & maxv);
        }
    } else if (bits >= frombits || ((acc << (tobits - bits)) & maxv) != 0) {
        /* 非零填充位视为非法 */
        return false;
    }

    *outlen = pos;
    return true;
}

static bool bech32_encode(const char *hrp, const uint8_t *data, size_t datalen,
                          uint32_t constant, char *out, size_t outcap)
{
    size_t hrplen = strlen(hrp);
    size_t total = hrplen + 1 + datalen + 6;
    if (total > BECH32_MAX_LEN || total + 1 > outcap) {
        return false;
    }

    uint32_t chk = polymod_hrp(hrp, hrplen);
    chk = polymod_data(chk, data, datalen);
    static const uint8_t six_zero[6] = {0};
    chk = polymod_data(chk, six_zero, 6);
    chk ^= constant;

    size_t pos = 0;
    memcpy(out, hrp, hrplen);
    pos += hrplen;
    out[pos++] = '1';
    for (size_t i = 0; i < datalen; ++i) {
        out[pos++] = B32_CHARSET[data[i]];
    }
    for (int i = 0; i < 6; ++i) {
        out[pos++] = B32_CHARSET[(chk >> (5 * (5 - i))) & 0x1fu];
    }
    out[pos] = '\0';
    return true;
}

static int charset_value(char c)
{
    for (int i = 0; i < 32; ++i) {
        if (B32_CHARSET[i] == c) {
            return i;
        }
    }
    return -1;
}

int dtc_segwit_addr_encode(const char *hrp, uint8_t witver,
                           const uint8_t *program, size_t programlen, char *out,
                           size_t outcap)
{
    if (witver > 16 || programlen < 2 || programlen > 40) {
        return -1;
    }
    if (witver == 0 && programlen != 20 && programlen != 32) {
        return -1;
    }

    uint8_t data[65];
    data[0] = witver;
    size_t datalen = 0;
    if (!convert_bits(data + 1, &datalen, sizeof(data) - 1, program,
                      programlen, 8, 5, true)) {
        return -1;
    }
    datalen += 1;

    uint32_t constant = (witver == 0) ? BECH32_CONST : BECH32M_CONST;
    if (!bech32_encode(hrp, data, datalen, constant, out, outcap)) {
        return -1;
    }
    return (int)strlen(out);
}

int dtc_segwit_addr_decode(const char *expected_hrp, const char *str,
                           size_t addr_len, uint8_t *witver_out,
                           uint8_t *program, size_t programcap)
{
    if (addr_len < 8 || addr_len > BECH32_MAX_LEN) {
        return -1;
    }

    /* 只接受小写；出现大写直接拒绝，避免大小写混淆攻击面 */
    char lower[BECH32_MAX_LEN + 1];
    for (size_t i = 0; i < addr_len; ++i) {
        if (str[i] >= 'A' && str[i] <= 'Z') {
            return -1;
        }
        lower[i] = str[i];
    }
    lower[addr_len] = '\0';

    /* 分隔符为最后一个 '1' */
    size_t sep = addr_len;
    for (size_t i = addr_len; i > 0; --i) {
        if (lower[i - 1] == '1') {
            sep = i - 1;
            break;
        }
    }
    if (sep == addr_len || sep < 1 || sep + 7 > addr_len) {
        return -1;
    }

    /* HRP 必须与期望完全一致（阻止 bc1/tb1 等外链地址） */
    size_t hrplen = strlen(expected_hrp);
    if (sep != hrplen || memcmp(lower, expected_hrp, hrplen) != 0) {
        return -1;
    }

    /* 解码 5 位数据（含 6 字节校验） */
    size_t datalen = addr_len - sep - 1;
    uint8_t data[BECH32_MAX_LEN];
    for (size_t i = 0; i < datalen; ++i) {
        int v = charset_value(lower[sep + 1 + i]);
        if (v < 0) {
            return -1;
        }
        data[i] = (uint8_t)v;
    }

    if (datalen < 1 + 6) {
        return -1;
    }

    uint8_t witver = data[0];
    if (witver > 16) {
        return -1;
    }

    /* 校验和常量由 witness 版本决定：v0=bech32，v1+=bech32m */
    uint32_t constant = (witver == 0) ? BECH32_CONST : BECH32M_CONST;
    uint32_t chk = polymod_hrp(lower, sep);
    chk = polymod_data(chk, data, datalen);
    if (chk != constant) {
        return -1;
    }

    /* 去掉版本与校验后，把 5 位组还原为程序字节 */
    uint8_t prog[40];
    size_t proglen = 0;
    if (!convert_bits(prog, &proglen, sizeof(prog), data + 1, datalen - 7, 5,
                      8, false)) {
        return -1;
    }

    if (proglen < 2 || proglen > 40) {
        return -1;
    }
    if (witver == 0 && proglen != 20 && proglen != 32) {
        return -1;
    }
    if (proglen > programcap) {
        return -1;
    }

    if (witver_out != NULL) {
        *witver_out = witver;
    }
    memcpy(program, prog, proglen);
    return (int)proglen;
}

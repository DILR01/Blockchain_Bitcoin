/*
 * base58.c —— Base58Check 编解码
 *
 * Ditcoin 的 P2PKH/P2SH 地址与 WIF 均使用 Base58Check，但版本字节
 * 重新分配（30/63/122），以便在格式层面与 Bitcoin 地址区分。
 */
#include "dtc/crypto.h"

#include <string.h>

static const char B58_ALPHABET[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/* 单字符 → 数值（-1 表示非法） */
static int b58_value(char c)
{
    for (int i = 0; i < 58; ++i) {
        if (B58_ALPHABET[i] == c) {
            return i;
        }
    }
    return -1;
}

int dtc_base58check_encode(uint8_t version, const uint8_t *data, size_t len,
                           char *out, size_t outcap)
{
    /* 1) 组装 payload = version || data || checksum */
    uint8_t payload[128];
    if (len + 5 > sizeof(payload)) {
        return -1;
    }
    payload[0] = version;
    memcpy(payload + 1, data, len);
    uint8_t hash[32];
    dtc_sha256d(payload, len + 1, hash);
    memcpy(payload + 1 + len, hash, 4);
    size_t total = len + 5;

    /* 2) 以 58 为基做长除转换（结果按大端写入 buf 尾部） */
    uint8_t digits[192];
    memset(digits, 0, sizeof(digits));
    size_t digits_len = 0;

    for (size_t i = 0; i < total; ++i) {
        uint32_t carry = payload[i];
        size_t j = 0;
        for (; j < digits_len; ++j) {
            carry += (uint32_t)digits[j] << 8;
            digits[j] = (uint8_t)(carry % 58u);
            carry /= 58u;
        }
        while (carry > 0) {
            if (j >= sizeof(digits)) {
                return -1;
            }
            digits[j++] = (uint8_t)(carry % 58u);
            carry /= 58u;
        }
        digits_len = j;
    }

    /* 3) 前导 0 字节对应字符 '1' */
    size_t zeros = 0;
    while (zeros < total && payload[zeros] == 0) {
        ++zeros;
    }

    size_t need = zeros + digits_len + 1;
    if (need > outcap) {
        return -1;
    }

    size_t pos = 0;
    for (size_t i = 0; i < zeros; ++i) {
        out[pos++] = '1';
    }
    for (size_t i = digits_len; i > 0; --i) {
        out[pos++] = B58_ALPHABET[digits[i - 1]];
    }
    out[pos] = '\0';
    return (int)pos;
}

int dtc_base58check_decode(const char *str, size_t strlen, uint8_t *version_out,
                           uint8_t *data, size_t datacap)
{
    if (strlen == 0 || strlen > 128) {
        return -1;
    }

    uint8_t bytes[128];
    memset(bytes, 0, sizeof(bytes));
    size_t bytes_len = 0;

    for (size_t i = 0; i < strlen; ++i) {
        int val = b58_value(str[i]);
        if (val < 0) {
            return -1;
        }
        uint32_t carry = (uint32_t)val;
        size_t j = 0;
        for (; j < bytes_len; ++j) {
            carry += (uint32_t)bytes[j] * 58u;
            bytes[j] = (uint8_t)(carry & 0xffu);
            carry >>= 8;
        }
        while (carry > 0) {
            if (j >= sizeof(bytes)) {
                return -1;
            }
            bytes[j++] = (uint8_t)(carry & 0xffu);
            carry >>= 8;
        }
        bytes_len = j;
    }

    /* 前导 '1' 代表前导 0 字节 */
    size_t zeros = 0;
    while (zeros < strlen && str[zeros] == '1') {
        ++zeros;
    }

    /* 重排为自然大端顺序：zeros 个 0 之后是低位在前的 bytes 逆序 */
    uint8_t full[128];
    if (zeros + bytes_len > sizeof(full)) {
        return -1;
    }
    memset(full, 0, zeros);
    for (size_t i = 0; i < bytes_len; ++i) {
        full[zeros + i] = bytes[bytes_len - 1 - i];
    }
    size_t full_len = zeros + bytes_len;

    if (full_len < 5) {
        return -1;
    }

    /* 校验和 */
    uint8_t hash[32];
    dtc_sha256d(full, full_len - 4, hash);
    if (memcmp(hash, full + full_len - 4, 4) != 0) {
        return -1;
    }

    size_t payload_len = full_len - 5; /* 去掉 version 与 checksum */
    if (payload_len > datacap) {
        return -1;
    }
    if (version_out != NULL) {
        *version_out = full[0];
    }
    memcpy(data, full + 1, payload_len);
    return (int)payload_len;
}

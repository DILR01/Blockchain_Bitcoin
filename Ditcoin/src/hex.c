/*
 * hex.c —— 十六进制编解码
 */
#include "dtc/hex.h"

static const char HEX_DIGITS[] = "0123456789abcdef";

size_t dtc_hex_encode(const uint8_t *data, size_t len, char *out, size_t outcap)
{
    if (outcap < len * 2 + 1) {
        if (outcap > 0) {
            out[0] = '\0';
        }
        return 0;
    }
    for (size_t i = 0; i < len; ++i) {
        out[i * 2] = HEX_DIGITS[(data[i] >> 4) & 0xfu];
        out[i * 2 + 1] = HEX_DIGITS[data[i] & 0xfu];
    }
    out[len * 2] = '\0';
    return len * 2;
}

static int hex_val(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

int dtc_hex_decode(const char *hex, size_t hexlen, uint8_t *out, size_t outcap)
{
    if (hexlen % 2 != 0 || hexlen / 2 > outcap) {
        return -1;
    }
    for (size_t i = 0; i < hexlen / 2; ++i) {
        int hi = hex_val(hex[i * 2]);
        int lo = hex_val(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            return -1;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return (int)(hexlen / 2);
}

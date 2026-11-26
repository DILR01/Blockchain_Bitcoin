/*
 * hex.h —— 十六进制编解码（共识/测试共用）
 */
#ifndef DTC_HEX_H
#define DTC_HEX_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* 编码为小写十六进制；out 至少 2*len+1 字节。返回写入字符数。 */
size_t dtc_hex_encode(const uint8_t *data, size_t len, char *out, size_t outcap);

/*
 * 解码十六进制字符串（大小写均可，要求偶数长度）。
 * 成功返回字节数；失败返回 -1。
 */
int dtc_hex_decode(const char *hex, size_t hexlen, uint8_t *out, size_t outcap);

#endif /* DTC_HEX_H */

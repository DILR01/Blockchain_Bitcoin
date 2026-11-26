/*
 * reader.c —— 边界检查读写实现
 *
 * 关键安全点：
 *   * 所有读取先做剩余长度判断，失败后 err=true 且后续读取恒为 0；
 *   * CompactSize 拒绝非最小编码（例如用 0xFD 编码 0x10），
 *     否则会造成同一交易有多种序列化形式，破坏 txid 唯一性；
 *   * dtc_buf 的容量按 2 倍增长，但设置上限防止恶意长度导致 OOM。
 */
#include "dtc/reader.h"

#include <stdlib.h>
#include <string.h>

/* 单次增长的上限：64MB，足够容纳 4MB 区块与测试数据 */
#define DTC_BUF_MAX (64u * 1024u * 1024u)

void dtc_reader_init(dtc_reader *r, const void *data, size_t len)
{
    r->data = (const uint8_t *)data;
    r->len = len;
    r->pos = 0;
    r->err = false;
}

size_t dtc_reader_pos(const dtc_reader *r)
{
    return r->pos;
}

size_t dtc_reader_remaining(const dtc_reader *r)
{
    return r->err ? 0 : r->len - r->pos;
}

bool dtc_reader_ok(const dtc_reader *r)
{
    return !r->err;
}

bool dtc_read_bytes(dtc_reader *r, void *p, size_t n)
{
    if (r->err || n > r->len - r->pos) {
        r->err = true;
        return false;
    }
    if (p != NULL) {
        memcpy(p, r->data + r->pos, n);
    }
    r->pos += n;
    return true;
}

uint8_t dtc_read_u8(dtc_reader *r)
{
    uint8_t v = 0;
    (void)dtc_read_bytes(r, &v, 1);
    return v;
}

uint16_t dtc_read_u16(dtc_reader *r)
{
    uint8_t b[2] = {0, 0};
    (void)dtc_read_bytes(r, b, 2);
    return (uint16_t)((uint16_t)b[0] | ((uint16_t)b[1] << 8));
}

uint32_t dtc_read_u32(dtc_reader *r)
{
    uint8_t b[4] = {0, 0, 0, 0};
    (void)dtc_read_bytes(r, b, 4);
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) |
           ((uint32_t)b[3] << 24);
}

uint64_t dtc_read_u64(dtc_reader *r)
{
    uint8_t b[8] = {0};
    (void)dtc_read_bytes(r, b, 8);
    uint64_t v = 0;
    for (int i = 7; i >= 0; --i) {
        v = (v << 8) | (uint64_t)b[i];
    }
    return v;
}

int32_t dtc_read_i32(dtc_reader *r)
{
    return (int32_t)dtc_read_u32(r);
}

int64_t dtc_read_i64(dtc_reader *r)
{
    return (int64_t)dtc_read_u64(r);
}

uint64_t dtc_read_varint(dtc_reader *r)
{
    uint8_t first = dtc_read_u8(r);
    if (r->err) {
        return 0;
    }

    if (first < 0xfd) {
        return first;
    }
    if (first == 0xfd) {
        uint16_t v = dtc_read_u16(r);
        if (r->err || v < 0xfd) {
            r->err = true; /* 非最小编码 */
            return 0;
        }
        return v;
    }
    if (first == 0xfe) {
        uint32_t v = dtc_read_u32(r);
        if (r->err || v <= 0xffffu) {
            r->err = true;
            return 0;
        }
        return v;
    }
    uint64_t v = dtc_read_u64(r);
    if (r->err || v <= 0xffffffffull) {
        r->err = true;
        return 0;
    }
    return v;
}

bool dtc_read_hash256(dtc_reader *r, uint8_t out[32])
{
    return dtc_read_bytes(r, out, 32);
}

/* ---------------------------------------------------------------------------
 * 写缓冲
 * ------------------------------------------------------------------------- */

void dtc_buf_init(dtc_buf *b)
{
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
    b->err = false;
}

void dtc_buf_free(dtc_buf *b)
{
    free(b->data);
    dtc_buf_init(b);
}

uint8_t *dtc_buf_reserve(dtc_buf *b, size_t n)
{
    if (b->err) {
        return NULL;
    }
    if (n > DTC_BUF_MAX || b->len > DTC_BUF_MAX - n) {
        b->err = true;
        return NULL;
    }
    size_t need = b->len + n;
    if (need <= b->cap) {
        uint8_t *p = b->data + b->len;
        b->len = need;
        return p;
    }

    size_t newcap = b->cap ? b->cap : 64;
    while (newcap < need) {
        if (newcap > DTC_BUF_MAX / 2) {
            newcap = DTC_BUF_MAX;
            break;
        }
        newcap *= 2;
    }
    uint8_t *p = (uint8_t *)realloc(b->data, newcap);
    if (p == NULL) {
        b->err = true;
        return NULL;
    }
    b->data = p;
    b->cap = newcap;

    uint8_t *ret = b->data + b->len;
    b->len = need;
    return ret;
}

bool dtc_buf_write(dtc_buf *b, const void *data, size_t n)
{
    if (n == 0) {
        return !b->err;
    }
    uint8_t *p = dtc_buf_reserve(b, n);
    if (p == NULL) {
        return false;
    }
    memcpy(p, data, n);
    return true;
}

bool dtc_buf_u8(dtc_buf *b, uint8_t v)
{
    return dtc_buf_write(b, &v, 1);
}

bool dtc_buf_u16(dtc_buf *b, uint16_t v)
{
    uint8_t buf[2] = {(uint8_t)(v & 0xffu), (uint8_t)((v >> 8) & 0xffu)};
    return dtc_buf_write(b, buf, 2);}

bool dtc_buf_u32(dtc_buf *b, uint32_t v)
{
    uint8_t buf[4] = {(uint8_t)(v & 0xffu), (uint8_t)((v >> 8) & 0xffu),
                      (uint8_t)((v >> 16) & 0xffu),
                      (uint8_t)((v >> 24) & 0xffu)};
    return dtc_buf_write(b, buf, 4);
}

bool dtc_buf_u64(dtc_buf *b, uint64_t v)
{
    uint8_t buf[8];
    for (int i = 0; i < 8; ++i) {
        buf[i] = (uint8_t)((v >> (8 * i)) & 0xffu);
    }
    return dtc_buf_write(b, buf, 8);
}

bool dtc_buf_i32(dtc_buf *b, int32_t v)
{
    return dtc_buf_u32(b, (uint32_t)v);
}

bool dtc_buf_i64(dtc_buf *b, int64_t v)
{
    return dtc_buf_u64(b, (uint64_t)v);
}

size_t dtc_varint_size(uint64_t v)
{
    if (v < 0xfd) {
        return 1;
    }
    if (v <= 0xffff) {
        return 3;
    }
    if (v <= 0xffffffffull) {
        return 5;
    }
    return 9;
}

bool dtc_buf_varint(dtc_buf *b, uint64_t v)
{
    if (v < 0xfd) {
        return dtc_buf_u8(b, (uint8_t)v);
    }
    if (v <= 0xffff) {
        return dtc_buf_u8(b, 0xfd) && dtc_buf_u16(b, (uint16_t)v);
    }
    if (v <= 0xffffffffull) {
        return dtc_buf_u8(b, 0xfe) && dtc_buf_u32(b, (uint32_t)v);
    }
    return dtc_buf_u8(b, 0xff) && dtc_buf_u64(b, v);
}

bool dtc_buf_hash256(dtc_buf *b, const uint8_t hash[32])
{
    return dtc_buf_write(b, hash, 32);
}

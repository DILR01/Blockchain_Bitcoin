/*
 * reader.h —— 带边界检查的序列化读写（CompactSize / 小端整数）
 *
 * 安全约定：
 *   * dtc_reader 一旦发生截断/非法编码就置 err=true，后续读取全部返回 0，
 *     不会越界访问。调用方在解析结束后检查 dtc_reader_ok()。
 *   * CompactSize 按 Bitcoin 规则拒绝非最小编码（防共识分歧与内存放大）。
 *   * dtc_buf 为可增长字节缓冲，分配失败时置 err=true 并拒绝写入；
 *     所有写入接口返回 bool，便于序列化路径逐层传递失败。
 */
#ifndef DTC_READER_H
#define DTC_READER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    const uint8_t *data;
    size_t len;
    size_t pos;
    bool err;
} dtc_reader;

void dtc_reader_init(dtc_reader *r, const void *data, size_t len);

/* 已消费 / 剩余字节数 */
size_t dtc_reader_pos(const dtc_reader *r);
size_t dtc_reader_remaining(const dtc_reader *r);
bool dtc_reader_ok(const dtc_reader *r);

/* 读取原始字节，p 可为 NULL（仅跳过） */
bool dtc_read_bytes(dtc_reader *r, void *p, size_t n);

uint8_t dtc_read_u8(dtc_reader *r);
uint16_t dtc_read_u16(dtc_reader *r);   /* 小端 */
uint32_t dtc_read_u32(dtc_reader *r);
uint64_t dtc_read_u64(dtc_reader *r);
int32_t dtc_read_i32(dtc_reader *r);
int64_t dtc_read_i64(dtc_reader *r);

/* CompactSize（varint），非最小编码视为错误 */
uint64_t dtc_read_varint(dtc_reader *r);

/* 读取 32 字节哈希 */
bool dtc_read_hash256(dtc_reader *r, uint8_t out[32]);

/* ---------------------------------------------------------------------------
 * 可增长写缓冲
 * ------------------------------------------------------------------------- */
typedef struct {
    uint8_t *data;
    size_t len;
    size_t cap;
    bool err;
} dtc_buf;

void dtc_buf_init(dtc_buf *b);
void dtc_buf_free(dtc_buf *b);

/* 保留 n 字节并返回可写指针；失败返回 NULL */
uint8_t *dtc_buf_reserve(dtc_buf *b, size_t n);

bool dtc_buf_write(dtc_buf *b, const void *data, size_t n);
bool dtc_buf_u8(dtc_buf *b, uint8_t v);
bool dtc_buf_u16(dtc_buf *b, uint16_t v);
bool dtc_buf_u32(dtc_buf *b, uint32_t v);
bool dtc_buf_u64(dtc_buf *b, uint64_t v);
bool dtc_buf_i32(dtc_buf *b, int32_t v);
bool dtc_buf_i64(dtc_buf *b, int64_t v);
bool dtc_buf_varint(dtc_buf *b, uint64_t v);
bool dtc_buf_hash256(dtc_buf *b, const uint8_t hash[32]);

/* 返回 varint 编码长度（1/3/5/9） */
size_t dtc_varint_size(uint64_t v);

#endif /* DTC_READER_H */

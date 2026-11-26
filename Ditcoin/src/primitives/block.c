/*
 * block.c —— 区块头与区块的解析/序列化
 */
#include "dtc/primitives.h"

#include <stdlib.h>
#include <string.h>

#include "dtc/crypto.h"
#include "dtc/merkle.h"

/* 区块内交易数量上限（远高于 4MB 区块的物理可能值，仅用于防内存放大） */
#define DTC_MAX_BLOCK_TXS 100000u

bool dtc_block_header_parse(const uint8_t *data, size_t len,
                            dtc_block_header *hdr)
{
    if (data == NULL || hdr == NULL || len < 80) {
        return false;
    }
    dtc_reader r;
    dtc_reader_init(&r, data, len);
    hdr->version = dtc_read_i32(&r);
    (void)dtc_read_bytes(&r, hdr->prev_block, 32);
    (void)dtc_read_bytes(&r, hdr->merkle_root, 32);
    hdr->time = dtc_read_u32(&r);
    hdr->bits = dtc_read_u32(&r);
    hdr->nonce = dtc_read_u32(&r);
    return !r.err;
}

bool dtc_block_header_serialize(const dtc_block_header *hdr, uint8_t out[80])
{
    dtc_buf buf;
    dtc_buf_init(&buf);
    bool ok = dtc_buf_i32(&buf, hdr->version) &&
              dtc_buf_write(&buf, hdr->prev_block, 32) &&
              dtc_buf_write(&buf, hdr->merkle_root, 32) &&
              dtc_buf_u32(&buf, hdr->time) && dtc_buf_u32(&buf, hdr->bits) &&
              dtc_buf_u32(&buf, hdr->nonce);
    if (ok && buf.len == 80) {
        memcpy(out, buf.data, 80);
    } else {
        ok = false;
    }
    dtc_buf_free(&buf);
    return ok;
}

void dtc_block_header_hash(const dtc_block_header *hdr, uint8_t out[32])
{
    uint8_t bytes[80];
    if (!dtc_block_header_serialize(hdr, bytes)) {
        memset(out, 0, 32);
        return;
    }
    dtc_sha256d(bytes, sizeof(bytes), out);
}

bool dtc_block_parse(const uint8_t *data, size_t len, dtc_block *blk,
                     size_t *consumed, size_t max_block_size)
{
    if (data == NULL || blk == NULL || len < 80) {
        return false;
    }
    dtc_block_init(blk);

    if (!dtc_block_header_parse(data, len, &blk->header)) {
        return false;
    }

    dtc_reader r;
    dtc_reader_init(&r, data + 80, len - 80);
    uint64_t tx_count = dtc_read_varint(&r);
    if (r.err || tx_count == 0 || tx_count > DTC_MAX_BLOCK_TXS) {
        return false;
    }

    blk->tx_count = (size_t)tx_count;
    blk->txs = (dtc_tx *)calloc(blk->tx_count, sizeof(dtc_tx));
    if (blk->txs == NULL) {
        blk->tx_count = 0;
        return false;
    }

    size_t offset = 80 + r.pos;
    for (size_t i = 0; i < blk->tx_count; ++i) {
        size_t used = 0;
        if (!dtc_tx_parse(data + offset, len - offset, &blk->txs[i], &used,
                          max_block_size)) {
            dtc_block_free(blk);
            return false;
        }
        offset += used;
        if (offset > max_block_size) {
            dtc_block_free(blk);
            return false;
        }
    }

    if (consumed != NULL) {
        *consumed = offset;
    }
    return true;
}

void dtc_block_init(dtc_block *blk)
{
    memset(blk, 0, sizeof(*blk));
}

void dtc_block_free(dtc_block *blk)
{
    if (blk->txs != NULL) {
        for (size_t i = 0; i < blk->tx_count; ++i) {
            dtc_tx_free(&blk->txs[i]);
        }
        free(blk->txs);
    }
    dtc_block_init(blk);
}

bool dtc_block_serialize(const dtc_block *blk, dtc_buf *out)
{
    uint8_t header[80];
    if (!dtc_block_header_serialize(&blk->header, header)) {
        return false;
    }
    if (!dtc_buf_write(out, header, sizeof(header)) ||
        !dtc_buf_varint(out, blk->tx_count)) {
        return false;
    }
    for (size_t i = 0; i < blk->tx_count; ++i) {
        if (!dtc_tx_serialize(&blk->txs[i], true, out)) {
            return false;
        }
    }
    return true;
}

void dtc_block_merkle_root(const dtc_block *blk, uint8_t out[32])
{
    if (blk->tx_count == 0) {
        memset(out, 0, 32);
        return;
    }
    uint8_t(*txids)[32] = (uint8_t(*)[32])calloc(blk->tx_count, 32);
    if (txids == NULL) {
        memset(out, 0, 32);
        return;
    }
    for (size_t i = 0; i < blk->tx_count; ++i) {
        dtc_tx_txid(&blk->txs[i], txids[i]);
    }
    /* 显式加 const：ISO C11 不允许在数组指针上隐式添加元素 const 限定 */
    dtc_merkle_root((const uint8_t(*)[32])txids, blk->tx_count, out);
    free(txids);
}

void dtc_block_witness_root(const dtc_block *blk, uint8_t out[32])
{
    if (blk->tx_count == 0) {
        memset(out, 0, 32);
        return;
    }
    uint8_t(*wtxids)[32] = (uint8_t(*)[32])calloc(blk->tx_count, 32);
    if (wtxids == NULL) {
        memset(out, 0, 32);
        return;
    }
    for (size_t i = 0; i < blk->tx_count; ++i) {
        dtc_tx_wtxid(&blk->txs[i], wtxids[i]);
    }
    dtc_witness_merkle_root((const uint8_t(*)[32])wtxids, blk->tx_count, out);
    free(wtxids);
}

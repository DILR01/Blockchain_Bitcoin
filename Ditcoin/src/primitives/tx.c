/*
 * tx.c —— 交易解析 / 序列化 / txid / weight / 结构检查
 *
 * 解析安全策略：
 *   * 输入数量、输出数量、脚本长度、见证元素数量都有上限；
 *   * 所有 CompactSize 必须是最小编码（由 reader 保证）；
 *   * 解析失败时自动释放已分配内存，避免在验证路径上泄漏。
 */
#include "dtc/primitives.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dtc/consensus.h"
#include "dtc/crypto.h"
#include "dtc/script.h"

/* 单笔交易的元素数量上限（远高于实际使用，防内存放大） */
#define DTC_MAX_VIN 10000u
#define DTC_MAX_VOUT 10000u
#define DTC_MAX_WITNESS_ITEMS 1000u

void dtc_tx_init(dtc_tx *tx)
{
    memset(tx, 0, sizeof(*tx));
    tx->version = 1;
    tx->locktime = 0;
    tx->has_witness = false;
}

void dtc_tx_free(dtc_tx *tx)
{
    if (tx->vin != NULL) {
        for (size_t i = 0; i < tx->vin_count; ++i) {
            free(tx->vin[i].script_sig.data);
            if (tx->vin[i].witness != NULL) {
                for (size_t j = 0; j < tx->vin[i].witness_count; ++j) {
                    free(tx->vin[i].witness[j].data);
                }
                free(tx->vin[i].witness);
            }
        }
        free(tx->vin);
    }
    if (tx->vout != NULL) {
        for (size_t i = 0; i < tx->vout_count; ++i) {
            free(tx->vout[i].script_pubkey.data);
        }
        free(tx->vout);
    }
    dtc_tx_init(tx);
}

/* 读取 varint 长度并分配字节串 */
static bool read_bytes_alloc(dtc_reader *r, dtc_bytes *b, size_t maxlen)
{
    uint64_t n = dtc_read_varint(r);
    if (r->err || n > (uint64_t)maxlen) {
        return false;
    }
    b->len = (size_t)n;
    if (n == 0) {
        b->data = NULL;
        return true;
    }
    b->data = (uint8_t *)malloc((size_t)n);
    if (b->data == NULL) {
        return false;
    }
    return dtc_read_bytes(r, b->data, (size_t)n);
}

bool dtc_tx_parse(const uint8_t *data, size_t len, dtc_tx *tx,
                  size_t *consumed, size_t max_tx_size)
{
    dtc_tx_init(tx);
    dtc_reader r;
    dtc_reader_init(&r, data, len);

    int32_t version = dtc_read_i32(&r);
    uint64_t first = dtc_read_varint(&r);
    if (r.err) {
        return false;
    }

    bool has_witness = false;
    uint64_t vin_count;
    if (first == 0) {
        /* marker=0x00 后必须跟非零 flag；当前只认识 flag=1 */
        uint8_t flag = dtc_read_u8(&r);
        if (r.err || flag == 0) {
            return false;
        }
        has_witness = true;
        vin_count = dtc_read_varint(&r);
    } else {
        vin_count = first;
    }

    if (r.err || vin_count == 0 || vin_count > DTC_MAX_VIN) {
        return false;
    }

    tx->version = version;
    tx->has_witness = has_witness;
    tx->vin_count = (size_t)vin_count;
    tx->vin = (dtc_tx_in *)calloc(tx->vin_count, sizeof(dtc_tx_in));
    if (tx->vin == NULL) {
        dtc_tx_free(tx);
        return false;
    }

    for (size_t i = 0; i < tx->vin_count; ++i) {
        dtc_tx_in *in = &tx->vin[i];
        if (!dtc_read_hash256(&r, in->prevout.hash)) {
            dtc_tx_free(tx);
            return false;
        }
        in->prevout.n = dtc_read_u32(&r);
        if (!read_bytes_alloc(&r, &in->script_sig, DTC_MAX_SCRIPT_SIZE)) {
            dtc_tx_free(tx);
            return false;
        }
        in->sequence = dtc_read_u32(&r);
        if (r.err) {
            dtc_tx_free(tx);
            return false;
        }
    }

    uint64_t vout_count = dtc_read_varint(&r);
    if (r.err || vout_count > DTC_MAX_VOUT) {
        dtc_tx_free(tx);
        return false;
    }
    tx->vout_count = (size_t)vout_count;
    if (tx->vout_count > 0) {
        tx->vout = (dtc_tx_out *)calloc(tx->vout_count, sizeof(dtc_tx_out));
        if (tx->vout == NULL) {
            dtc_tx_free(tx);
            return false;
        }
    }

    for (size_t i = 0; i < tx->vout_count; ++i) {
        dtc_tx_out *out = &tx->vout[i];
        out->value = dtc_read_i64(&r);
        if (!read_bytes_alloc(&r, &out->script_pubkey, DTC_MAX_SCRIPT_SIZE)) {
            dtc_tx_free(tx);
            return false;
        }
        if (r.err) {
            dtc_tx_free(tx);
            return false;
        }
    }

    if (has_witness) {
        for (size_t i = 0; i < tx->vin_count; ++i) {
            uint64_t wcount = dtc_read_varint(&r);
            if (r.err || wcount > DTC_MAX_WITNESS_ITEMS) {
                dtc_tx_free(tx);
                return false;
            }
            tx->vin[i].witness_count = (size_t)wcount;
            if (wcount == 0) {
                continue;
            }
            tx->vin[i].witness =
                (dtc_bytes *)calloc((size_t)wcount, sizeof(dtc_bytes));
            if (tx->vin[i].witness == NULL) {
                dtc_tx_free(tx);
                return false;
            }
            for (size_t j = 0; j < (size_t)wcount; ++j) {
                if (!read_bytes_alloc(&r, &tx->vin[i].witness[j],
                                      max_tx_size)) {
                    dtc_tx_free(tx);
                    return false;
                }
            }
        }
    }

    tx->locktime = dtc_read_u32(&r);
    if (r.err) {
        dtc_tx_free(tx);
        return false;
    }

    /* 总长度约束：防止用超长见证把内存吃满 */
    if (r.pos > max_tx_size) {
        dtc_tx_free(tx);
        return false;
    }

    if (consumed != NULL) {
        *consumed = r.pos;
    }
    return true;
}

/* 序列化一个 dtc_bytes（CompactSize + 内容） */
static bool write_bytes(dtc_buf *b, const dtc_bytes *v)
{
    return dtc_buf_varint(b, v->len) && dtc_buf_write(b, v->data, v->len);
}

bool dtc_tx_serialize(const dtc_tx *tx, bool with_witness, dtc_buf *out)
{
    if (!dtc_buf_i32(out, tx->version)) {
        return false;
    }

    bool write_witness = with_witness && tx->has_witness;
    if (write_witness) {
        if (!dtc_buf_u8(out, 0x00) || !dtc_buf_u8(out, 0x01)) {
            return false;
        }
    }

    if (!dtc_buf_varint(out, tx->vin_count)) {
        return false;
    }
    for (size_t i = 0; i < tx->vin_count; ++i) {
        const dtc_tx_in *in = &tx->vin[i];
        if (!dtc_buf_hash256(out, in->prevout.hash) ||
            !dtc_buf_u32(out, in->prevout.n) ||
            !write_bytes(out, &in->script_sig) ||
            !dtc_buf_u32(out, in->sequence)) {
            return false;
        }
    }

    if (!dtc_buf_varint(out, tx->vout_count)) {
        return false;
    }
    for (size_t i = 0; i < tx->vout_count; ++i) {
        const dtc_tx_out *v = &tx->vout[i];
        if (!dtc_buf_i64(out, v->value) ||
            !write_bytes(out, &v->script_pubkey)) {
            return false;
        }
    }

    if (write_witness) {
        for (size_t i = 0; i < tx->vin_count; ++i) {
            const dtc_tx_in *in = &tx->vin[i];
            if (!dtc_buf_varint(out, in->witness_count)) {
                return false;
            }
            for (size_t j = 0; j < in->witness_count; ++j) {
                if (!write_bytes(out, &in->witness[j])) {
                    return false;
                }
            }
        }
    }

    return dtc_buf_u32(out, tx->locktime);
}

size_t dtc_tx_stripped_size(const dtc_tx *tx)
{
    dtc_buf buf;
    dtc_buf_init(&buf);
    size_t result = 0;
    if (dtc_tx_serialize(tx, false, &buf)) {
        result = buf.len;
    }
    dtc_buf_free(&buf);
    return result;
}

size_t dtc_tx_total_size(const dtc_tx *tx)
{
    dtc_buf buf;
    dtc_buf_init(&buf);
    size_t result = 0;
    if (dtc_tx_serialize(tx, true, &buf)) {
        result = buf.len;
    }
    dtc_buf_free(&buf);
    return result;
}

size_t dtc_tx_weight(const dtc_tx *tx)
{
    size_t stripped = dtc_tx_stripped_size(tx);
    size_t total = dtc_tx_total_size(tx);
    return stripped * 3 + total;
}

void dtc_tx_txid(const dtc_tx *tx, uint8_t out[32])
{
    dtc_buf buf;
    dtc_buf_init(&buf);
    if (dtc_tx_serialize(tx, false, &buf)) {
        dtc_sha256d(buf.data, buf.len, out);
    } else {
        memset(out, 0, 32);
    }
    dtc_buf_free(&buf);
}

void dtc_tx_wtxid(const dtc_tx *tx, uint8_t out[32])
{
    dtc_buf buf;
    dtc_buf_init(&buf);
    if (dtc_tx_serialize(tx, true, &buf)) {
        dtc_sha256d(buf.data, buf.len, out);
    } else {
        memset(out, 0, 32);
    }
    dtc_buf_free(&buf);
}

bool dtc_tx_is_coinbase(const dtc_tx *tx)
{
    if (tx->vin_count != 1) {
        return false;
    }
    static const uint8_t zero[32] = {0};
    return memcmp(tx->vin[0].prevout.hash, zero, 32) == 0 &&
           tx->vin[0].prevout.n == 0xffffffffu;
}

bool dtc_tx_check_structural(const dtc_tx *tx, const struct dtc_chain_params *p,
                             char *err, size_t errcap)
{
    if (tx->vin_count == 0) {
        if (err != NULL) {
            (void)snprintf(err, errcap, "vin 为空");
        }
        return false;
    }
    if (tx->vout_count == 0) {
        if (err != NULL) {
            (void)snprintf(err, errcap, "vout 为空");
        }
        return false;
    }

    for (size_t i = 0; i < tx->vout_count; ++i) {
        if (!dtc_amount_in_range(tx->vout[i].value)) {
            if (err != NULL) {
                (void)snprintf(err, errcap, "输出金额越界");
            }
            return false;
        }
    }

    /* 重复输入检查：输入数已被限制在 10000 以内，O(n²) 可接受 */
    for (size_t i = 0; i < tx->vin_count; ++i) {
        for (size_t j = i + 1; j < tx->vin_count; ++j) {
            if (tx->vin[i].prevout.n == tx->vin[j].prevout.n &&
                memcmp(tx->vin[i].prevout.hash, tx->vin[j].prevout.hash, 32) ==
                    0) {
                if (err != NULL) {
                    (void)snprintf(err, errcap, "重复输入");
                }
                return false;
            }
        }
    }

    if (dtc_tx_is_coinbase(tx)) {
        size_t slen = tx->vin[0].script_sig.len;
        if (slen < 2 || slen > 100) {
            if (err != NULL) {
                (void)snprintf(err, errcap, "coinbase scriptSig 长度非法");
            }
            return false;
        }
    }

    /* ★ Ditcoin 共识创新：64 字节交易禁令。
     * 64 字节恰好是若干“最小攻击交易”的尺寸，直接禁止可消除一类
     * 交易延展性/去匿名化向量。 */
    if (p != NULL && p->ban_64byte_tx) {
        if (dtc_tx_stripped_size(tx) == 64) {
            if (err != NULL) {
                (void)snprintf(err, errcap, "禁止 64 字节交易");
            }
            return false;
        }
    }

    return true;
}

/* 读取 CScriptNum 最小编码（height 使用，限制 1..4 字节） */
bool dtc_tx_coinbase_height(const dtc_tx *tx, int32_t *height_out)
{
    if (!dtc_tx_is_coinbase(tx)) {
        return false;
    }
    const dtc_bytes *sig = &tx->vin[0].script_sig;
    if (sig->len < 1) {
        return false;
    }

    size_t pos = 0;
    uint8_t op = sig->data[pos++];
    uint8_t n;
    if (op == 0x00) {
        *height_out = 0;
        return true;
    }
    if (op >= 0x01 && op <= 0x4b) {
        n = op;
    } else {
        return false;
    }
    if (sig->len < pos + (size_t)n || n == 0 || n > 4) {
        return false;
    }

    const uint8_t *num = sig->data + pos;
    /* 最小编码检查（与 CScriptNum 一致）：
     * 若最高字节除符号位外为 0，且（只有 1 字节 或 次高字节符号位为 0），
     * 则该表示不是最小的。例如 {0x00}、{0x80}、{0x01,0x00} 都非法。 */
    if ((num[n - 1] & 0x7fu) == 0 &&
        (n == 1 || (num[n - 2] & 0x80u) == 0)) {
        return false;
    }

    int32_t value = 0;
    for (int i = (int)n - 1; i >= 0; --i) {
        value = (value << 8) | (int32_t)num[i];
    }
    /* 负高度非法 */
    if ((num[n - 1] & 0x80u) != 0) {
        return false;
    }
    *height_out = value;
    return true;
}

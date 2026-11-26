/*
 * sighash.c —— legacy 签名摘要（SIGHASH_ALL/NONE/SINGLE + ANYONECANPAY）
 *
 * ★ 跨链重放声明（README 声明一）：
 *   默认 DTC_SIGHASH_DOMAIN_SEP=0，即沿用 Bitcoin 原算法、不做域分离。
 *   跨链重放安全性完全依赖创世块唯一性（UTXO 集不相交）。
 *   若切换为 1，则在消息前拼接 MAGIC_MAIN 的 4 字节小端表示后做 SHA256d。
 *
 * ★ Taproot 层将使用 DTC/TapSighash tagged hash 天然隔离（尚未实现）。
 */
#include "dtc/script.h"

#include <string.h>

#include "dtc/config.h"
#include "dtc/consensus.h"
#include "dtc/crypto.h"
#include "dtc/reader.h"

/* 移出脚本中的所有 OP_CODESEPARATOR 操作码（不触碰 pushdata 内部字节） */
static bool strip_codeseparators(const uint8_t *script, size_t len,
                                 dtc_buf *out)
{
    size_t i = 0;
    while (i < len) {
        size_t start = i;
        uint8_t op = script[i++];
        size_t datalen = 0;
        bool have_len = false;

        if (op <= 0x4b) {
            datalen = op;
            have_len = true;
        } else if (op == 0x4c) {
            if (i + 1 > len) {
                return false;
            }
            datalen = script[i];
            i += 1;
        } else if (op == 0x4d) {
            if (i + 2 > len) {
                return false;
            }
            datalen = (size_t)script[i] | ((size_t)script[i + 1] << 8);
            i += 2;
        } else if (op == 0x4e) {
            if (i + 4 > len) {
                return false;
            }
            datalen = (size_t)script[i] | ((size_t)script[i + 1] << 8) |
                      ((size_t)script[i + 2] << 16) |
                      ((size_t)script[i + 3] << 24);
            i += 4;
        }

        if (have_len || datalen > 0) {
            if (datalen > len - i) {
                return false;
            }
            i += datalen;
        }

        if (op != 0xab) { /* OP_CODESEPARATOR 被丢弃 */
            if (!dtc_buf_write(out, script + start, i - start)) {
                return false;
            }
        }
    }
    return true;
}

bool dtc_sighash_legacy(const dtc_tx *tx, size_t input_index,
                        const uint8_t *script_code, size_t script_code_len,
                        uint32_t hashtype, uint8_t out[32])
{
    if (tx == NULL || input_index >= tx->vin_count) {
        return false;
    }

    uint32_t base = hashtype & 0x1fu;
    bool anyonecanpay = (hashtype & 0x80u) != 0;
    if (base != 1u && base != 2u && base != 3u) {
        return false; /* 只支持 ALL/NONE/SINGLE */
    }

    dtc_bytes script;
    script.data = NULL;
    script.len = 0;
    dtc_buf scriptbuf;
    dtc_buf_init(&scriptbuf);
    if (!strip_codeseparators(script_code, script_code_len, &scriptbuf)) {
        dtc_buf_free(&scriptbuf);
        return false;
    }
    script.data = scriptbuf.data;
    script.len = scriptbuf.len;

    dtc_buf b;
    dtc_buf_init(&b);
    bool ok = true;

    ok = ok && dtc_buf_i32(&b, tx->version);

    /* 输入集合 */
    size_t count = anyonecanpay ? 1 : tx->vin_count;
    ok = ok && dtc_buf_varint(&b, count);
    for (size_t k = 0; k < count && ok; ++k) {
        size_t i = anyonecanpay ? input_index : k;
        const dtc_tx_in *in = &tx->vin[i];

        ok = ok && dtc_buf_write(&b, in->prevout.hash, 32) &&
             dtc_buf_u32(&b, in->prevout.n);

        if (i == input_index) {
            ok = ok && dtc_buf_varint(&b, script.len) &&
                 dtc_buf_write(&b, script.data, script.len);
        } else {
            ok = ok && dtc_buf_varint(&b, 0);
        }

        uint32_t seq = in->sequence;
        if (i != input_index &&
            (base == 3u /* SINGLE */ || base == 2u /* NONE */)) {
            seq = 0;
        }
        ok = ok && dtc_buf_u32(&b, seq);
    }

    /* 输出集合 */
    size_t vout_count = 0;
    if (base == 1u) {
        vout_count = tx->vout_count;
    } else if (base == 3u) {
        vout_count = input_index + 1;
    } else {
        vout_count = 0;
    }
    ok = ok && dtc_buf_varint(&b, vout_count);
    for (size_t i = 0; i < vout_count && ok; ++i) {
        if (base == 3u && i != input_index) {
            /* SINGLE：其余输出替换为空脚本、金额 -1 */
            ok = ok && dtc_buf_i64(&b, -1) && dtc_buf_varint(&b, 0);
        } else {
            const dtc_tx_out *v = &tx->vout[i];
            ok = ok && dtc_buf_i64(&b, v->value) &&
                 dtc_buf_varint(&b, v->script_pubkey.len) &&
                 dtc_buf_write(&b, v->script_pubkey.data,
                               v->script_pubkey.len);
        }
    }

    ok = ok && dtc_buf_u32(&b, tx->locktime) && dtc_buf_u32(&b, hashtype);

    if (ok) {
#if DTC_SIGHASH_DOMAIN_SEP
        /* 域分离模式：MAGIC_MAIN 的 4 字节小端前置 */
        uint8_t magic_le[4];
        uint32_t magic = dtc_chain_main.magic;
        for (int i = 0; i < 4; ++i) {
            magic_le[i] = (uint8_t)((magic >> (8 * i)) & 0xffu);
        }
        dtc_sha256d_2parts(magic_le, sizeof(magic_le), b.data, b.len, out);
#else
        dtc_sha256d(b.data, b.len, out);
#endif
    }

    dtc_buf_free(&scriptbuf);
    dtc_buf_free(&b);
    return ok;
}

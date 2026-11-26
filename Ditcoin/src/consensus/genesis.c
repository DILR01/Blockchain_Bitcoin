/*
 * genesis.c —— 创世块构建
 *
 * 规范要求（第一步 D 节）：
 *   coinbase scriptSig = OP_0 + push("Ditcoin genesis <date> anti-premine: <事件>")
 *   唯一输出 = 0 金额 + OP_RETURN（零预挖）
 *   nVersion = 1；hashPrevBlock = 0
 *   挖出后把 hash 写死进 params.c 与单元测试；换 PoW 算法必须重挖。
 *
 * 本文件只负责「确定性构建 + 计算哈希」，不执行耗时挖矿；
 * 挖矿由 tools/dtc_genesis.c 完成。
 */
#include "dtc/consensus.h"

#include <stdlib.h>
#include <string.h>

#include "dtc/crypto.h"
#include "dtc/primitives.h"

/* 构造创世 coinbase 交易 */
static bool genesis_build_coinbase(const dtc_chain_params *p, dtc_tx *tx)
{
    dtc_tx_init(tx);

    const char *text = p->genesis_coinbase_text;
    size_t textlen = strlen(text);
    if (textlen == 0 || textlen > 200) {
        return false;
    }

    /* scriptSig = OP_0 (高度 0) + push(text) */
    uint8_t script[256];
    size_t slen = 0;
    script[slen++] = 0x00; /* OP_0：BIP34 高度 0 的最小表示 */
    if (textlen <= 75) {
        script[slen++] = (uint8_t)textlen;
    } else {
        script[slen++] = 0x4c; /* OP_PUSHDATA1 */
        script[slen++] = (uint8_t)textlen;
    }
    memcpy(script + slen, text, textlen);
    slen += textlen;

    tx->version = 1;
    tx->locktime = 0;
    tx->has_witness = false;
    tx->vin_count = 1;
    tx->vin = (dtc_tx_in *)calloc(1, sizeof(dtc_tx_in));
    if (tx->vin == NULL) {
        return false;
    }
    tx->vin[0].prevout.n = 0xffffffffu;
    memset(tx->vin[0].prevout.hash, 0, 32);
    tx->vin[0].sequence = 0xffffffffu;
    tx->vin[0].script_sig.data = (uint8_t *)malloc(slen);
    if (tx->vin[0].script_sig.data == NULL) {
        return false;
    }
    memcpy(tx->vin[0].script_sig.data, script, slen);
    tx->vin[0].script_sig.len = slen;

    /* 唯一输出：0 金额 + OP_RETURN（零预挖） */
    tx->vout_count = 1;
    tx->vout = (dtc_tx_out *)calloc(1, sizeof(dtc_tx_out));
    if (tx->vout == NULL) {
        return false;
    }
    tx->vout[0].value = 0;
    tx->vout[0].script_pubkey.data = (uint8_t *)malloc(1);
    if (tx->vout[0].script_pubkey.data == NULL) {
        return false;
    }
    tx->vout[0].script_pubkey.data[0] = 0x6a; /* OP_RETURN */
    tx->vout[0].script_pubkey.len = 1;
    return true;
}

bool dtc_genesis_build(dtc_network net, uint32_t nonce, dtc_genesis_info *out)
{
    if (out == NULL) {
        return false;
    }

    const dtc_chain_params *p = dtc_chain_get(net);
    dtc_tx coinbase;
    if (!genesis_build_coinbase(p, &coinbase)) {
        dtc_tx_free(&coinbase);
        return false;
    }

    /* merkle root 即 coinbase 的 txid */
    uint8_t merkle[32];
    dtc_tx_txid(&coinbase, merkle);

    dtc_block_header hdr;
    hdr.version = 1;
    memset(hdr.prev_block, 0, 32);
    memcpy(hdr.merkle_root, merkle, 32);
    hdr.time = p->genesis_time;
    hdr.nonce = nonce;

    dtc_u256 limit;
    if (!dtc_chain_pow_limit(p, &limit)) {
        dtc_tx_free(&coinbase);
        return false;
    }
    bool negative = false;
    dtc_u256_get_compact(&limit, false, &hdr.bits);
    (void)negative;

    uint8_t header_bytes[80];
    if (!dtc_block_header_serialize(&hdr, header_bytes)) {
        dtc_tx_free(&coinbase);
        return false;
    }

    memset(out, 0, sizeof(*out));
    dtc_block_header_hash(&hdr, out->hash);
    memcpy(out->merkle_root, merkle, 32);
    out->version = hdr.version;
    out->time = hdr.time;
    out->bits = hdr.bits;
    out->nonce = nonce;
    out->coinbase_height = 0;

    dtc_tx_free(&coinbase);
    return true;
}

bool dtc_genesis_frozen(dtc_network net, dtc_genesis_info *out)
{
    const dtc_chain_params *p = dtc_chain_get(net);
    return dtc_genesis_build(net, p->genesis_nonce, out);
}

bool dtc_genesis_coinbase_serialize(dtc_network net, uint8_t **out,
                                    size_t *outlen)
{
    if (out == NULL || outlen == NULL) {
        return false;
    }
    const dtc_chain_params *p = dtc_chain_get(net);
    dtc_tx coinbase;
    if (!genesis_build_coinbase(p, &coinbase)) {
        dtc_tx_free(&coinbase);
        return false;
    }

    dtc_buf buf;
    dtc_buf_init(&buf);
    bool ok = dtc_tx_serialize(&coinbase, false, &buf);
    dtc_tx_free(&coinbase);
    if (!ok) {
        dtc_buf_free(&buf);
        return false;
    }

    /* 把缓冲所有权交给调用方 */
    *out = buf.data;
    *outlen = buf.len;
    return true;
}

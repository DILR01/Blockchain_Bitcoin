/*
 * test_primitives.c —— 交易 / 区块头 / 区块原语
 *
 * 覆盖：
 *   * 手工构造交易的序列化 → 解析 → 字段一致性；
 *   * txid / wtxid / weight；
 *   * ★ 64 字节交易禁令；
 *   * coinbase 高度解析；
 *   * 区块头 80 字节往返与哈希；
 *   * 区块 merkle root 与交易 txid 对应。
 */
#include "test_util.h"

#include <stdlib.h>

#include "dtc/consensus.h"
#include "dtc/crypto.h"
#include "dtc/primitives.h"

/* 给 dtc_bytes 分配并填充内容（测试用，失败即断言失败） */
static bool set_bytes(dtc_bytes *b, const uint8_t *data, size_t len)
{
    b->data = NULL;
    b->len = 0;
    if (len == 0) {
        return true;
    }
    b->data = (uint8_t *)malloc(len);
    if (b->data == NULL) {
        return false;
    }
    memcpy(b->data, data, len);
    b->len = len;
    return true;
}

/* 构造一笔 1 输入 1 输出的普通交易 */
static bool build_simple_tx(dtc_tx *tx, size_t script_sig_len,
                           size_t script_pubkey_len)
{
    dtc_tx_init(tx);
    tx->version = 2;
    tx->locktime = 0;
    tx->vin = (dtc_tx_in *)calloc(1, sizeof(dtc_tx_in));
    tx->vout = (dtc_tx_out *)calloc(1, sizeof(dtc_tx_out));
    if (tx->vin == NULL || tx->vout == NULL) {
        return false;
    }
    tx->vin_count = 1;
    tx->vout_count = 1;

    memset(tx->vin[0].prevout.hash, 0xab, 32);
    tx->vin[0].prevout.n = 3;
    tx->vin[0].sequence = 0xfffffffeu;
    uint8_t sig[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    if (script_sig_len > sizeof(sig)) {
        return false;
    }
    if (!set_bytes(&tx->vin[0].script_sig, sig, script_sig_len)) {
        return false;
    }

    tx->vout[0].value = 100000000; /* 1 DTC */
    uint8_t spk[8] = {0x51, 0x51, 0x51, 0x51, 0x51, 0x51, 0x51, 0x51};
    if (script_pubkey_len > sizeof(spk)) {
        return false;
    }
    return set_bytes(&tx->vout[0].script_pubkey, spk, script_pubkey_len);
}

void test_primitives(void)
{
    test_group("交易序列化 / 解析往返");
    {
        dtc_tx tx;
        CHECK(build_simple_tx(&tx, 3, 2));
        CHECK(tx.vin_count == 1 && tx.vout_count == 1);

        dtc_buf buf;
        dtc_buf_init(&buf);
        CHECK(dtc_tx_serialize(&tx, true, &buf));
        CHECK(!buf.err);
        CHECK(buf.len == dtc_tx_stripped_size(&tx));
        CHECK(buf.len == dtc_tx_total_size(&tx));
        CHECK(dtc_tx_weight(&tx) == buf.len * 4);
        /* 手工计算：4+1+36+1+3+4 + 1+8+1+2 + 4 = 65 */
        CHECK(buf.len == 65);

        dtc_tx back;
        size_t consumed = 0;
        CHECK(dtc_tx_parse(buf.data, buf.len, &back, &consumed, 4000000));
        CHECK(consumed == buf.len);
        CHECK(back.version == 2);
        CHECK(back.vin_count == 1 && back.vout_count == 1);
        CHECK(back.vin[0].prevout.n == 3);
        CHECK(back.vin[0].sequence == 0xfffffffeu);
        CHECK(back.vout[0].value == 100000000);
        CHECK(back.vout[0].script_pubkey.len == 2);

        uint8_t id1[32], id2[32];
        dtc_tx_txid(&tx, id1);
        dtc_tx_txid(&back, id2);
        CHECK(memcmp(id1, id2, 32) == 0);
        /* 无见证时 wtxid == txid */
        dtc_tx_wtxid(&tx, id2);
        CHECK(memcmp(id1, id2, 32) == 0);

        /* 结构检查通过 */
        char err[128];
        CHECK(dtc_tx_check_structural(&back, &dtc_chain_main, err, sizeof(err)));
        CHECK(!dtc_tx_is_coinbase(&back));

        dtc_buf_free(&buf);
        dtc_tx_free(&tx);
        dtc_tx_free(&back);
    }

    test_group("64 字节交易禁令");
    {
        /* scriptSig 3 字节 + scriptPubKey 1 字节 → stripped size 恰为 64 */
        dtc_tx tx;
        CHECK(build_simple_tx(&tx, 3, 1));
        CHECK(dtc_tx_stripped_size(&tx) == 64);
        char err[128];
        CHECK(!dtc_tx_check_structural(&tx, &dtc_chain_main, err, sizeof(err)));
        CHECK(strstr(err, "64") != NULL);
        dtc_tx_free(&tx);

        /* 65 字节则通过（其它条件也满足） */
        dtc_tx tx2;
        CHECK(build_simple_tx(&tx2, 3, 2));
        CHECK(dtc_tx_stripped_size(&tx2) == 65);
        CHECK(dtc_tx_check_structural(&tx2, &dtc_chain_main, err, sizeof(err)));
        dtc_tx_free(&tx2);
    }

    test_group("coinbase 高度解析");
    {
        dtc_tx tx;
        dtc_tx_init(&tx);
        tx.version = 1;
        tx.vin = (dtc_tx_in *)calloc(1, sizeof(dtc_tx_in));
        tx.vout = (dtc_tx_out *)calloc(1, sizeof(dtc_tx_out));
        tx.vin_count = 1;
        tx.vout_count = 1;
        memset(tx.vin[0].prevout.hash, 0, 32);
        tx.vin[0].prevout.n = 0xffffffffu;
        tx.vin[0].sequence = 0xffffffffu; /* coinbase 允许 final */
        /* scriptSig = push(0x02) → 高度 2 */
        uint8_t sig[2] = {0x01, 0x02};
        CHECK(set_bytes(&tx.vin[0].script_sig, sig, sizeof(sig)));
        tx.vout[0].value = 2500000000LL;
        uint8_t spk[1] = {0x51};
        CHECK(set_bytes(&tx.vout[0].script_pubkey, spk, sizeof(spk)));

        CHECK(dtc_tx_is_coinbase(&tx));
        int32_t h = -1;
        CHECK(dtc_tx_coinbase_height(&tx, &h));
        CHECK(h == 2);

        /* 非最小编码：push(0x00) 表示 0，但 0 应使用空 push */
        uint8_t bad[2] = {0x01, 0x00};
        free(tx.vin[0].script_sig.data);
        CHECK(set_bytes(&tx.vin[0].script_sig, bad, sizeof(bad)));
        CHECK(!dtc_tx_coinbase_height(&tx, &h));
        dtc_tx_free(&tx);
    }

    test_group("区块头往返与哈希");
    {
        dtc_block_header hdr;
        hdr.version = 1;
        memset(hdr.prev_block, 0, 32);
        memset(hdr.merkle_root, 0x42, 32);
        hdr.time = 1767225600u;
        hdr.bits = 0x1d00ffffu;
        hdr.nonce = 12345;

        uint8_t raw[80];
        CHECK(dtc_block_header_serialize(&hdr, raw));
        dtc_block_header back;
        CHECK(dtc_block_header_parse(raw, sizeof(raw), &back));
        CHECK(back.version == 1);
        CHECK(back.time == hdr.time);
        CHECK(back.bits == hdr.bits);
        CHECK(back.nonce == hdr.nonce);
        CHECK(memcmp(back.merkle_root, hdr.merkle_root, 32) == 0);

        uint8_t h1[32], h2[32];
        dtc_block_header_hash(&hdr, h1);
        dtc_sha256d(raw, sizeof(raw), h2);
        CHECK(memcmp(h1, h2, 32) == 0);

        CHECK(!dtc_block_header_parse(raw, 79, &back));
    }

    test_group("区块 merkle root 与 txid 一致");
    {
        dtc_block blk;
        dtc_block_init(&blk);
        blk.header.version = 1;
        blk.txs = (dtc_tx *)calloc(2, sizeof(dtc_tx));
        CHECK(blk.txs != NULL);
        blk.tx_count = 2;
        CHECK(build_simple_tx(&blk.txs[0], 3, 2));
        CHECK(build_simple_tx(&blk.txs[1], 3, 2));

        uint8_t ids[2][32];
        uint8_t root[32];
        uint8_t cat[64];
        uint8_t expect[32];
        dtc_tx_txid(&blk.txs[0], ids[0]);
        dtc_tx_txid(&blk.txs[1], ids[1]);
        memcpy(cat, ids[0], 32);
        memcpy(cat + 32, ids[1], 32);
        dtc_sha256d(cat, 64, expect);
        dtc_block_merkle_root(&blk, root);
        CHECK(memcmp(root, expect, 32) == 0);

        dtc_block_free(&blk);
    }
}

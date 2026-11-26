/*
 * primitives.h —— 交易 / 区块头 / 区块的解析与序列化
 *
 * 设计：
 *   * 解析一律走 dtc_reader，任何截断/超限都返回 false，不残留半成品
 *     （tx 在失败时会自行释放已分配内存）。
 *   * 序列化区分 with_witness：txid 用不含见证的序列化，wtxid 用含见证的。
 *   * weight = stripped_size*3 + total_size（即 stripped*4 + witness 部分）。
 *   * 结构检查（CheckTransaction 的链无关部分）包含：
 *       - vin/vout 非空
 *       - 金额范围
 *       - coinbase scriptSig 长度 2..100
 *       - ★ stripped size == 64 的交易直接拒绝（Ditcoin 共识创新）
 *
 * 说明：当前 M1 只实现 legacy 序列化 + segwit 标记位解析，不实现
 * segwit 脚本执行（见 script.h 的说明）。
 */
#ifndef DTC_PRIMITIVES_H
#define DTC_PRIMITIVES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dtc/amount.h"
#include "dtc/reader.h"

/* 前向声明：链参数（定义在 dtc/consensus.h） */
struct dtc_chain_params;

/* 32 字节哈希容器（txid / block hash 等） */
typedef struct {
    uint8_t b[32];
} dtc_hash;

/* 引用一个 UTXO */
typedef struct {
    uint8_t hash[32]; /* 前一笔 txid（序列化字节序） */
    uint32_t n;       /* 输出索引 */
} dtc_outpoint;

/* 变长字节串（脚本 / 见证元素），由本模块 malloc 管理 */
typedef struct {
    uint8_t *data;
    size_t len;
} dtc_bytes;

/* 交易输入 */
typedef struct {
    dtc_outpoint prevout;  /* coinbase 时 prevout.hash 全 0 且 n == 0xffffffff */
    dtc_bytes script_sig;
    uint32_t sequence;
    dtc_bytes *witness;    /* 见证栈（仅 has_witness 的交易可能有） */
    size_t witness_count;
} dtc_tx_in;

/* 交易输出 */
typedef struct {
    dtc_amount value;      /* dts */
    dtc_bytes script_pubkey;
} dtc_tx_out;

/* 交易 */
typedef struct {
    int32_t version;
    dtc_tx_in *vin;
    size_t vin_count;
    dtc_tx_out *vout;
    size_t vout_count;
    uint32_t locktime;
    bool has_witness;      /* 序列化时是否带 marker/flag 与见证栈 */
} dtc_tx;

/* 80 字节区块头 */
typedef struct {
    int32_t version;
    uint8_t prev_block[32];
    uint8_t merkle_root[32];
    uint32_t time;
    uint32_t bits;
    uint32_t nonce;
} dtc_block_header;

/* 区块 */
typedef struct {
    dtc_block_header header;
    dtc_tx *txs;
    size_t tx_count;
} dtc_block;

/* ---- 内存管理 ---- */
void dtc_tx_init(dtc_tx *tx);
void dtc_tx_free(dtc_tx *tx);
void dtc_block_init(dtc_block *blk);
void dtc_block_free(dtc_block *blk);

/* ---- 交易 ---- */

/*
 * 解析一笔交易。
 * 成功返回 true，并设置 *consumed 为消耗字节数；
 * 失败返回 false，tx 已被复位为空。
 * max_tx_size 建议 4,000,000（不得超过区块上限）。
 */
bool dtc_tx_parse(const uint8_t *data, size_t len, dtc_tx *tx,
                  size_t *consumed, size_t max_tx_size);

/*
 * 序列化。with_witness=true 时若 has_witness 为真则写 marker/flag 与见证。
 * 若 with_witness=false 则始终产出 stripped 形式（txid 序列化）。
 */
bool dtc_tx_serialize(const dtc_tx *tx, bool with_witness, dtc_buf *out);

/* 交易的 stripped 序列化字节数（不含见证） */
size_t dtc_tx_stripped_size(const dtc_tx *tx);

/* 目标交易总序列化字节数（含见证，若 has_witness） */
size_t dtc_tx_total_size(const dtc_tx *tx);

/* weight = stripped_size*3 + total_size */
size_t dtc_tx_weight(const dtc_tx *tx);

/* txid（stripped 序列化的 SHA256d）与 wtxid（完整序列化） */
void dtc_tx_txid(const dtc_tx *tx, uint8_t out[32]);
void dtc_tx_wtxid(const dtc_tx *tx, uint8_t out[32]);

/* 是否 coinbase：单输入，且 prevout 全零、n == 0xffffffff */
bool dtc_tx_is_coinbase(const dtc_tx *tx);

/*
 * 链无关结构检查（CheckTransaction）：
 *   * vin/vout 非空、规模上限
 *   * 输出金额在 [0, DTC_AMOUNT_ABS_MAX]
 *   * 重复输入
 *   * coinbase scriptSig 长度 2..100；非 coinbase 禁止空 scriptSig 之外的
 *     额外约束由策略层负责
 *   * ★ stripped size == 64 的直接拒绝（DTC_BAN_64BYTE_TX）
 * 失败时把原因写入 err（若非 NULL）。
 */
bool dtc_tx_check_structural(const dtc_tx *tx, const struct dtc_chain_params *p,
                             char *err, size_t errcap);

/*
 * 从 coinbase scriptSig 解析 BIP34 风格的区块高度（首个 push，最小编码
 * CScriptNum）。Ditcoin 要求该值等于区块高度。成功返回 true。
 */
bool dtc_tx_coinbase_height(const dtc_tx *tx, int32_t *height_out);

/* ---- 区块头 ---- */

/* 解析 80 字节区块头（严格长度 >= 80，多余字节忽略） */
bool dtc_block_header_parse(const uint8_t *data, size_t len,
                            dtc_block_header *hdr);

/* 序列化 80 字节区块头 */
bool dtc_block_header_serialize(const dtc_block_header *hdr, uint8_t out[80]);

/* 区块头哈希（SHA256d，自然字节序） */
void dtc_block_header_hash(const dtc_block_header *hdr, uint8_t out[32]);

/* ---- 区块 ---- */

/* 解析完整区块（header + varint + txs），max_block_size 建议 4,000,000 */
bool dtc_block_parse(const uint8_t *data, size_t len, dtc_block *blk,
                     size_t *consumed, size_t max_block_size);

/* 序列化完整区块（含所有交易的完整见证） */
bool dtc_block_serialize(const dtc_block *blk, dtc_buf *out);

/* 区块的 merkle root（由交易 txid 计算） */
void dtc_block_merkle_root(const dtc_block *blk, uint8_t out[32]);

/* 区块的见证 merkle root（由交易 wtxid 计算，coinbase 置零） */
void dtc_block_witness_root(const dtc_block *blk, uint8_t out[32]);

#endif /* DTC_PRIMITIVES_H */

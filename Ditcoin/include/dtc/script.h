/*
 * script.h —— Ditcoin 脚本解析与解释器（legacy + P2SH）
 *
 * ★ 当前实现范围（M1 里程碑）：
 *   * 完整脚本词法解析（PUSHDATA1/2/4、OP_1NEGATE..OP_16）
 *   * 栈机：常量、流程控制(IF/NOTIF/ELSE/ENDIF/VERIFY/RETURN)、栈操作、
 *     算术/逻辑、哈希、CLTV/CSV、CHECKSIG/CHECKMULTISIG（通过 vtable 回调）
 *   * P2SH 两步执行与 push-only 检查
 *   * legacy sighash（SIGHASH_ALL/NONE/SINGLE + ANYONECANPAY），含
 *     DTC_SIGHASH_DOMAIN_SEP 编译开关
 *   * ★ 显式拒绝 witness program（v0/v1）：当前没有 segwit/taproot 执行
 *     引擎，绝不能因为「OP_0 + push32 在 legacy 语义下为真」而误判成功。
 *     遇到 witness 输出统一返回失败并给出明确错误信息。
 *
 * 扩展点：ECDSA/Schnorr 验签由 dtc_sig_checker vtable 注入（生产环境接
 * vendored libsecp256k1，测试环境用可编程 mock），脚本引擎本身不含任何
 * 密码学实现。
 */
#ifndef DTC_SCRIPT_H
#define DTC_SCRIPT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dtc/amount.h"
#include "dtc/primitives.h"

/* ---- 资源限制（与 Bitcoin 一致，故不放入链参数） ---- */
#define DTC_MAX_SCRIPT_SIZE 10000
#define DTC_MAX_ELEMENT_SIZE 520
#define DTC_MAX_OPS_PER_SCRIPT 201
#define DTC_MAX_STACK_SIZE 1000
#define DTC_MAX_PUBKEYS_PER_MULTISIG 20
#define DTC_MAX_SCRIPT_NUM_LEN 4

/* ---- 强制启用的共识 flag（无高度分支，创世起恒定） ---- */
enum {
    DTC_SCRIPT_P2SH          = 1u << 0,
    DTC_SCRIPT_DERSIG        = 1u << 1,
    DTC_SCRIPT_NULLDUMMY     = 1u << 2,
    DTC_SCRIPT_CHECKLOCKTIME = 1u << 3,
    DTC_SCRIPT_CHECKSEQUENCE = 1u << 4,
    DTC_SCRIPT_WITNESS       = 1u << 5, /* 仅用于识别并拒绝 witness 程序 */
    DTC_SCRIPT_TAPROOT       = 1u << 6  /* 预留 */
};

#define DTC_SCRIPT_CONSENSUS_FLAGS                                            \
    (DTC_SCRIPT_P2SH | DTC_SCRIPT_DERSIG | DTC_SCRIPT_NULLDUMMY |            \
     DTC_SCRIPT_CHECKLOCKTIME | DTC_SCRIPT_CHECKSEQUENCE | DTC_SCRIPT_WITNESS | \
     DTC_SCRIPT_TAPROOT)

/*
 * 签名校验回调。
 *   ctx      —— 调用方私有上下文
 *   sig      —— DER 签名（已去掉末尾 hashtype 字节）
 *   sighash  —— 引擎按 hashtype 计算好的 32 字节摘要
 * 返回 true 表示签名有效。
 */
typedef struct {
    void *ctx;
    bool (*check_ecdsa)(void *ctx, const uint8_t *sig, size_t siglen,
                        const uint8_t *pubkey, size_t pubkeylen,
                        const uint8_t sighash[32]);
} dtc_sig_checker;

/* 脚本执行上下文 */
typedef struct {
    const dtc_sig_checker *checker; /* 可为 NULL（此时任何验签都失败） */

    /* CLTV：与交易 nLockTime 比较；CSV：与输入 sequence 比较 */
    int64_t tx_locktime;
    uint32_t input_sequence;

    /* CSV 语义使用的高度/时间（调用方按 BIP68 规则决定用哪个） */
    int64_t input_height;
    int64_t input_time;

    /* 当前区块高度 / MTP（CLTV 要求 nLockTime < 区块时间） */
    int64_t block_height;
    int64_t block_mtp;

    /* 预留：策略层 flag 扩展 */
    uint32_t flags;
} dtc_script_ctx;

/*
 * 校验一笔输入的 scriptSig 与上一笔输出的 scriptPubKey。
 *
 *   tx/input_index —— 用于构造 legacy sighash
 *   amount         —— 被花费输出的金额（legacy 不参与 sighash，但保留接口
 *                     以便未来 segwit 复用）
 *   ctx            —— 签名校验器与锁时间上下文
 * 成功返回 true；失败返回 false 并写入可读错误（err 可为 NULL）。
 */
bool dtc_script_verify(const dtc_tx *tx, size_t input_index,
                       const dtc_bytes *script_sig, const dtc_bytes *script_pubkey,
                       dtc_amount amount, const dtc_script_ctx *ctx, char *err,
                       size_t errcap);

/* 脚本是否只包含 push 操作（P2SH 要求） */
bool dtc_script_is_push_only(const uint8_t *script, size_t len);

/*
 * 判断是否为 witness program（OP_0..OP_16 后紧跟 2..40 字节 push）。
 * 若命中，返回 true 并给出 witver。
 */
bool dtc_script_is_witness_program(const uint8_t *script, size_t len,
                                   uint8_t *witver_out);

/*
 * legacy sighash：
 *   按 hashtype 构造改造后的交易副本并做 SHA256d（或按
 *   DTC_SIGHASH_DOMAIN_SEP 前置 MAGIC 后再 SHA256d）。
 * script_code 中最后一个 OP_CODESEPARATOR 之前的部分被移除。
 *
 * out 为 32 字节摘要；返回 false 表示 hashtype 非法或内存失败。
 */
bool dtc_sighash_legacy(const dtc_tx *tx, size_t input_index,
                        const uint8_t *script_code, size_t script_code_len,
                        uint32_t hashtype, uint8_t out[32]);

#endif /* DTC_SCRIPT_H */

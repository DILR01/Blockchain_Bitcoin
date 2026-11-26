/*
 * consensus.h —— Ditcoin 共识层公开接口
 *
 * 本文件聚合四类共识相关内容：
 *   1. 链参数表（所有数值唯一来源在 src/consensus/params.c）
 *   2. 经济模型（尾排放 subsidy / supply_at）
 *   3. PoW 算法抽象与难度调整（LWMA-1）
 *   4. 创世块构建
 *
 * ★ 其余模块禁止硬编码链参数魔法数字；CI 约定由 params.c 统一提供。
 */
#ifndef DTC_CONSENSUS_H
#define DTC_CONSENSUS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dtc/uint256.h"

/* ---------------------------------------------------------------------------
 * 网络身份
 * ------------------------------------------------------------------------- */
typedef enum {
    DTC_NET_MAIN = 0,
    DTC_NET_TEST = 1,
    DTC_NET_REG  = 2
} dtc_network;

/*
 * 链参数表。
 *
 * 说明：数值全部来自 Ditcoin 规范（修订版），与 Bitcoin 无兼容义务。
 * 其中 psbt_magic / snapshot_magic 含 0xFF 结尾，故意在首字节就与
 * Bitcoin 的 "psbt\xff" / "utxo\xff" 区分（隔离测试会强制校验）。
 */
typedef struct dtc_chain_params {
    const char *name;              /* "main" / "test" / "regtest" */

    /* ---- A. 链身份 ---- */
    uint32_t magic;                /* P2P 帧 magic（LE 字节序写入线路） */
    uint16_t p2p_port;
    uint16_t rpc_port;
    const char *hrp;               /* bech32 前缀 "dtc" / "tdtc" */
    uint32_t hd_pub_version;       /* dtpub... */
    uint32_t hd_prv_version;       /* dtprv... */
    uint8_t p2pkh_version;         /* Base58 版本，地址以 D 开头 */
    uint8_t p2sh_version;          /* Base58 版本，地址以 S 开头 */
    uint8_t wif_version;
    const char *psbt_magic;        /* 5 字节，允许内嵌 '\0'/0xFF */
    size_t psbt_magic_len;
    const char *snapshot_magic;    /* 5 字节 */
    size_t snapshot_magic_len;
    const char *v2_hkdf_salt;      /* "ditcoin_v2_shared_secret" || MAGIC */
    const char *hd_seed_tag;       /* "Ditcoin seed" */
    uint32_t bip44_coin_type;      /* 0xD17C0DE，非 0 */

    /* ---- B. 共识 ---- */
    int32_t target_spacing;        /* T = 600 秒 */
    int32_t lwma_window;           /* N = 45 */
    uint32_t max_block_weight;     /* 4,000,000 */
    uint32_t witness_scale;        /* 4 */
    uint32_t max_sigops_cost;      /* 80,000 */
    int32_t coinbase_maturity;     /* 100 */
    int32_t mtp_window;            /* 11 */
    int64_t future_time_limit;     /* 1800 秒，使用节点本地时间 */
    int32_t anchor_period;         /* 2016，仅用于时间戳锚点 */
    int64_t timewarp_grace;        /* 7200 秒 */
    bool ban_64byte_tx;            /* 禁止 stripped size == 64 的交易 */
    const char *pow_limit_hex;     /* 00000000ffff...（大端十六进制） */

    /* ---- B2. 经济模型（尾排放） ---- */
    int64_t initial_subsidy;       /* 25 DTC */
    int64_t halving_interval;      /* 420,000 块 */
    int64_t tail_floor;            /* 0.5 DTC，永久 */
    uint32_t halving_count;        /* 6 */
    int64_t tail_start_height;     /* 2,520,000 */
    int64_t pre_tail_supply;       /* 20,671,875 DTC */
    int64_t blocks_per_year;       /* 52,560 */
    int64_t tail_annual_emission;  /* 26,280 DTC/年 */

    /* ---- C. 策略（非共识） ---- */
    int64_t min_relay_fee_per_kvb; /* 100 dts/kvB */
    int64_t incremental_fee;       /* 100 dts */
    int64_t dust_rate;             /* 3000 */
    int32_t bytes_per_sigop;       /* 20 */
    int64_t mempool_max_bytes;     /* 300 MB */
    int32_t cluster_limit;         /* 64 笔 */
    int64_t cluster_max_vsize;     /* 101 kvB */

    /* ---- D. 创世块 ---- */
    const char *genesis_coinbase_text; /* scriptSig 中的反预挖声明 */
    uint32_t genesis_time;             /* 创世头 nTime（UTC 时间戳） */
    uint32_t genesis_nonce;            /* ★ 自挖后冻结；0 表示尚未挖矿 */
} dtc_chain_params;

/* 预定义网络参数（定义在 params.c） */
extern const dtc_chain_params dtc_chain_main;
extern const dtc_chain_params dtc_chain_test;
extern const dtc_chain_params dtc_chain_reg;

/* 按网络取参数表 */
const dtc_chain_params *dtc_chain_get(dtc_network net);

/* 解析 "main"/"test"/"regtest" 字符串（大小写敏感），失败返回 -1 */
int dtc_network_from_name(const char *name);
const char *dtc_network_name(dtc_network net);

/* 取 powLimit（由 params 的十六进制字符串解析），失败返回 false */
bool dtc_chain_pow_limit(const dtc_chain_params *p, dtc_u256 *out);

/* ---------------------------------------------------------------------------
 * 经济模型
 * ------------------------------------------------------------------------- */

/*
 * 区块补贴（纯整数，单位 dts）：
 *   h = height / 420000；h >= 63 时为 0（防移位未定义），否则 25 DTC >> h
 *   结果不低于尾排放下限 0.5 DTC ⇒ 高度 >= 2,520,000 后永久 0.5 DTC。
 *
 * 前置条件：height >= 0（负高度返回 0，便于测试/防御）。
 */
int64_t dtc_subsidy(int32_t height);

/*
 * 已发行总量：前 height 个区块（0..height-1）补贴之和。
 *   * 高度 <= 2,520,000 时逐减半段累加（段数固定为 6，O(1) 但保留循环
 *     以便逐段断言）；
 *   * 超过尾排放起点后用闭式解：PRE_TAIL_SUPPLY + (h-tail)*floor。
 *
 * ★ 替代 Bitcoin 的 MAX_MONEY 共识上界：任何区块的累计输出必须满足
 *   total_out <= dtc_supply_at(height+1)。
 */
int64_t dtc_supply_at(int64_t height);

/* 第 h 段（0..6，6 表示尾排放）的补贴，便于测试表逐段断言 */
int64_t dtc_subsidy_for_segment(uint32_t segment);

/* 前 2,520,000 块的累计发行（常量，供测试对拍） */
int64_t dtc_pre_tail_supply(void);

/* ---------------------------------------------------------------------------
 * PoW 抽象
 *
 * 目标：把「区块头哈希算法」从共识逻辑里剥离。默认 SHA256d，将来切换
 * Scrypt/AuxPOW 只需替换 dtc_pow_algo_t 实现并重挖创世块。
 * ------------------------------------------------------------------------- */
typedef struct {
    const char *name;                 /* 写入 getblockchaininfo 供运维识别 */
    void (*hash)(const uint8_t *hdr, size_t len, uint8_t out[32]);
    size_t (*scratch_bytes)(void);    /* SHA256d=0；Scrypt=1MB 等 */
} dtc_pow_algo_t;

extern const dtc_pow_algo_t dtc_pow_sha256d;
extern const dtc_pow_algo_t *const dtc_pow_default;

/* 对 80 字节区块头做 PoW 哈希 */
void dtc_pow_hash_header(const dtc_pow_algo_t *algo, const uint8_t header[80],
                         uint8_t out[32]);

/* hash (按小端解释为 256 位数) <= target 时返回 true */
bool dtc_pow_check_hash(const uint8_t hash[32], const dtc_u256 *target);

/* ---------------------------------------------------------------------------
 * LWMA-1 难度调整（target 形式，逐块）
 *
 * 输入：
 *   times   —— N+1 个时间戳，按高度升序（times[0] 为窗口前一个块，
 *              times[1..N] 为最近 N 个块）
 *   targets —— N 个目标值，与 times[1..N] 一一对应（最近 N 个块的 nBits）
 * 输出：
 *   out     —— 下一块的 target，已裁剪到 powLimit 以内
 *
 * 算法（与规范逐行对应，k = (N+1)*T/2）：
 *   prev = times[0] - T
 *   L=0, sumTarget=0
 *   for i in 1..N:
 *       cur = max(times[i], prev+1)          // 强制单调
 *       L += i * min(6T, cur-prev)
 *       sumTarget += target[i-1]
 *   L = max(L, N*k/3)
 *   next = L * sumTarget / (k*N*N)
 */
bool dtc_lwma_next_target(const dtc_chain_params *p, const int64_t *times,
                          size_t n_times, const dtc_u256 *targets,
                          size_t n_targets, dtc_u256 *out);

/* ---------------------------------------------------------------------------
 * 创世块
 * ------------------------------------------------------------------------- */
typedef struct {
    uint8_t hash[32];        /* 区块头双 SHA256（自然字节序，显示时需反转） */
    uint8_t merkle_root[32];
    int32_t version;
    uint32_t time;
    uint32_t bits;
    uint32_t nonce;
    int32_t coinbase_height; /* coinbase scriptSig 首项 = 0 */
} dtc_genesis_info;

/*
 * 用指定 nonce 构造创世头并计算 hash（不校验 PoW）。
 * 供离线挖矿工具与测试使用。
 */
bool dtc_genesis_build(dtc_network net, uint32_t nonce, dtc_genesis_info *out);

/*
 * 取当前冻结创世（使用 params 中的 genesis_nonce）。
 * ★ 未挖矿时 nonce=0，此 hash 不是合法创世，仅用于结构测试；
 *   正式上线前必须用 dtc-genesis 工具挖出并写回 params.c。
 */
bool dtc_genesis_frozen(dtc_network net, dtc_genesis_info *out);

/* 创世块 coinbase 交易的序列化（供测试与挖矿工具计算 merkle root） */
bool dtc_genesis_coinbase_serialize(dtc_network net, uint8_t **out,
                                    size_t *outlen);

#endif /* DTC_CONSENSUS_H */

/*
 * params.c —— Ditcoin 全部链参数的唯一来源
 *
 * 硬约束：除本文件外，任何模块不得硬编码链级数值（CI 检查）。
 * 本文件包含：
 *   * 三条网络（main / test / regtest）的身份与共识参数
 *   * 编译期静态断言，保证经济模型各常量之间自洽
 *   * powLimit 的十六进制解析
 */
#include "dtc/consensus.h"

#include <string.h>

/* ---------------------------------------------------------------------------
 * 内部常量（仅供本文件初始化与静态断言使用）
 * ------------------------------------------------------------------------- */
#define DTC_MAGIC_MAIN 0x44495443u /* "DITC" */
#define DTC_MAGIC_TEST 0x44495454u /* "DITT" */
#define DTC_MAGIC_REG  0x44495452u /* "DITR" */

#define DTC_HD_PUB_VERSION 0xadc9ce9cu
#define DTC_HD_PRV_VERSION 0xadc9ca62u
#define DTC_P2PKH_VERSION 30u
#define DTC_P2SH_VERSION 63u
#define DTC_WIF_VERSION 122u
#define DTC_BIP44_COIN_TYPE 0x0d17c0deu

#define DTC_BLOCK_INTERVAL 600
#define DTC_LWMA_WINDOW 45
#define DTC_MAX_BLOCK_WEIGHT 4000000u
#define DTC_WITNESS_SCALE 4u
#define DTC_MAX_SIGOPS_COST 80000u
#define DTC_COINBASE_MATURITY 100
#define DTC_MTP_WINDOW 11
#define DTC_FUTURE_TIME_LIMIT 1800
#define DTC_ANCHOR_PERIOD 2016
#define DTC_TIMEWARP_GRACE 7200

/* 经济模型 */
#define DTC_INITIAL_SUBSIDY 2500000000LL /* 25 DTC */
#define DTC_HALVING_INTERVAL 420000LL
#define DTC_TAIL_FLOOR 50000000LL /* 0.5 DTC */
#define DTC_HALVING_COUNT 6u
#define DTC_TAIL_START (DTC_HALVING_INTERVAL * (int64_t)DTC_HALVING_COUNT)
#define DTC_BLOCKS_PER_YEAR 52560LL
#define DTC_TAIL_ANNUAL 2628000000000LL

/* 策略（非共识） */
#define DTC_MIN_RELAY_FEE 100LL
#define DTC_INCREMENTAL_FEE 100LL
#define DTC_DUST_RATE 3000LL
#define DTC_BYTES_PER_SIGOP 20
#define DTC_MEMPOOL_MAX (300LL * 1024 * 1024)
#define DTC_CLUSTER_LIMIT 64
#define DTC_CLUSTER_MAX_VSIZE 101000LL

/* 创世 */
#define DTC_GENESIS_TIME 1767225600u /* 2026-01-01T00:00:00Z */

/* ---------------------------------------------------------------------------
 * 编译期断言：经济模型自洽性
 * ------------------------------------------------------------------------- */
_Static_assert(DTC_TAIL_START == 2520000,
               "尾排放起点必须等于 6 × 420000 = 2,520,000");
_Static_assert((DTC_INITIAL_SUBSIDY >> (DTC_HALVING_COUNT - 1)) == 78125000,
               "第 6 段补贴应为 0.78125 DTC");
_Static_assert((DTC_INITIAL_SUBSIDY >> DTC_HALVING_COUNT) < DTC_TAIL_FLOOR,
               "第 7 段原始补贴应低于尾排放下限，从而触发尾排放");
_Static_assert(DTC_TAIL_ANNUAL == DTC_BLOCKS_PER_YEAR * DTC_TAIL_FLOOR,
               "年尾排放 = 每年块数 × 0.5 DTC");
_Static_assert(DTC_P2PKH_VERSION != 0 && DTC_P2PKH_VERSION != 111,
               "P2PKH 版本必须与 Bitcoin 区分");
_Static_assert(DTC_P2SH_VERSION != 5,
               "P2SH 版本必须与 Bitcoin 区分");

/* ---------------------------------------------------------------------------
 * 三张参数表
 *
 * 说明：
 *   * PSBT / 快照 magic 故意在首字节以 'd' 开始，并在末尾带 0xFF，
 *     与 Bitcoin 的 "psbt\xff"(0x70...) / "utxo\xff"(0x75...) 明确区分。
 *   * regtest 的端口与 HRP 是本实现自定的测试值，同样不占用 Bitcoin 端口。
 * ------------------------------------------------------------------------- */
const dtc_chain_params dtc_chain_main = {
    .name = "main",
    .magic = DTC_MAGIC_MAIN,
    .p2p_port = 28333,
    .rpc_port = 28332,
    .hrp = "dtc",
    .hd_pub_version = DTC_HD_PUB_VERSION,
    .hd_prv_version = DTC_HD_PRV_VERSION,
    .p2pkh_version = DTC_P2PKH_VERSION,
    .p2sh_version = DTC_P2SH_VERSION,
    .wif_version = DTC_WIF_VERSION,
    .psbt_magic = "dtpb\xff",
    .psbt_magic_len = 5,
    .snapshot_magic = "dtxo\xff",
    .snapshot_magic_len = 5,
    .v2_hkdf_salt = "ditcoin_v2_shared_secret",
    .hd_seed_tag = "Ditcoin seed",
    .bip44_coin_type = DTC_BIP44_COIN_TYPE,

    .target_spacing = DTC_BLOCK_INTERVAL,
    .lwma_window = DTC_LWMA_WINDOW,
    .max_block_weight = DTC_MAX_BLOCK_WEIGHT,
    .witness_scale = DTC_WITNESS_SCALE,
    .max_sigops_cost = DTC_MAX_SIGOPS_COST,
    .coinbase_maturity = DTC_COINBASE_MATURITY,
    .mtp_window = DTC_MTP_WINDOW,
    .future_time_limit = DTC_FUTURE_TIME_LIMIT,
    .anchor_period = DTC_ANCHOR_PERIOD,
    .timewarp_grace = DTC_TIMEWARP_GRACE,
    .ban_64byte_tx = true,
    .pow_limit_hex =
        "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",

    .initial_subsidy = DTC_INITIAL_SUBSIDY,
    .halving_interval = DTC_HALVING_INTERVAL,
    .tail_floor = DTC_TAIL_FLOOR,
    .halving_count = DTC_HALVING_COUNT,
    .tail_start_height = DTC_TAIL_START,
    .pre_tail_supply = 2067187500000000LL,
    .blocks_per_year = DTC_BLOCKS_PER_YEAR,
    .tail_annual_emission = DTC_TAIL_ANNUAL,

    .min_relay_fee_per_kvb = DTC_MIN_RELAY_FEE,
    .incremental_fee = DTC_INCREMENTAL_FEE,
    .dust_rate = DTC_DUST_RATE,
    .bytes_per_sigop = DTC_BYTES_PER_SIGOP,
    .mempool_max_bytes = DTC_MEMPOOL_MAX,
    .cluster_limit = DTC_CLUSTER_LIMIT,
    .cluster_max_vsize = DTC_CLUSTER_MAX_VSIZE,

    .genesis_coinbase_text =
        "Ditcoin genesis main 2026-01-01 anti-premine: UTC midnight, no premine",
    .genesis_time = DTC_GENESIS_TIME,
    .genesis_nonce = 0, /* ★ 待离线挖矿后冻结 */
};

const dtc_chain_params dtc_chain_test = {
    .name = "test",
    .magic = DTC_MAGIC_TEST,
    .p2p_port = 38333,
    .rpc_port = 38332,
    .hrp = "tdtc",
    .hd_pub_version = DTC_HD_PUB_VERSION,
    .hd_prv_version = DTC_HD_PRV_VERSION,
    .p2pkh_version = DTC_P2PKH_VERSION,
    .p2sh_version = DTC_P2SH_VERSION,
    .wif_version = DTC_WIF_VERSION,
    .psbt_magic = "dtpb\xff",
    .psbt_magic_len = 5,
    .snapshot_magic = "dtxo\xff",
    .snapshot_magic_len = 5,
    .v2_hkdf_salt = "ditcoin_v2_shared_secret",
    .hd_seed_tag = "Ditcoin seed",
    .bip44_coin_type = DTC_BIP44_COIN_TYPE,

    .target_spacing = DTC_BLOCK_INTERVAL,
    .lwma_window = DTC_LWMA_WINDOW,
    .max_block_weight = DTC_MAX_BLOCK_WEIGHT,
    .witness_scale = DTC_WITNESS_SCALE,
    .max_sigops_cost = DTC_MAX_SIGOPS_COST,
    .coinbase_maturity = DTC_COINBASE_MATURITY,
    .mtp_window = DTC_MTP_WINDOW,
    .future_time_limit = DTC_FUTURE_TIME_LIMIT,
    .anchor_period = DTC_ANCHOR_PERIOD,
    .timewarp_grace = DTC_TIMEWARP_GRACE,
    .ban_64byte_tx = true,
    .pow_limit_hex =
        "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",

    .initial_subsidy = DTC_INITIAL_SUBSIDY,
    .halving_interval = DTC_HALVING_INTERVAL,
    .tail_floor = DTC_TAIL_FLOOR,
    .halving_count = DTC_HALVING_COUNT,
    .tail_start_height = DTC_TAIL_START,
    .pre_tail_supply = 2067187500000000LL,
    .blocks_per_year = DTC_BLOCKS_PER_YEAR,
    .tail_annual_emission = DTC_TAIL_ANNUAL,

    .min_relay_fee_per_kvb = DTC_MIN_RELAY_FEE,
    .incremental_fee = DTC_INCREMENTAL_FEE,
    .dust_rate = DTC_DUST_RATE,
    .bytes_per_sigop = DTC_BYTES_PER_SIGOP,
    .mempool_max_bytes = DTC_MEMPOOL_MAX,
    .cluster_limit = DTC_CLUSTER_LIMIT,
    .cluster_max_vsize = DTC_CLUSTER_MAX_VSIZE,

    .genesis_coinbase_text =
        "Ditcoin genesis test 2026-01-01 anti-premine: UTC midnight, no premine",
    .genesis_time = DTC_GENESIS_TIME,
    .genesis_nonce = 0,
};

const dtc_chain_params dtc_chain_reg = {
    .name = "regtest",
    .magic = DTC_MAGIC_REG,
    .p2p_port = 48333,
    .rpc_port = 48332,
    .hrp = "rdtc",
    .hd_pub_version = DTC_HD_PUB_VERSION,
    .hd_prv_version = DTC_HD_PRV_VERSION,
    .p2pkh_version = DTC_P2PKH_VERSION,
    .p2sh_version = DTC_P2SH_VERSION,
    .wif_version = DTC_WIF_VERSION,
    .psbt_magic = "dtpb\xff",
    .psbt_magic_len = 5,
    .snapshot_magic = "dtxo\xff",
    .snapshot_magic_len = 5,
    .v2_hkdf_salt = "ditcoin_v2_shared_secret",
    .hd_seed_tag = "Ditcoin seed",
    .bip44_coin_type = DTC_BIP44_COIN_TYPE,

    .target_spacing = DTC_BLOCK_INTERVAL,
    .lwma_window = DTC_LWMA_WINDOW,
    .max_block_weight = DTC_MAX_BLOCK_WEIGHT,
    .witness_scale = DTC_WITNESS_SCALE,
    .max_sigops_cost = DTC_MAX_SIGOPS_COST,
    .coinbase_maturity = DTC_COINBASE_MATURITY,
    .mtp_window = DTC_MTP_WINDOW,
    .future_time_limit = DTC_FUTURE_TIME_LIMIT,
    .anchor_period = DTC_ANCHOR_PERIOD,
    .timewarp_grace = DTC_TIMEWARP_GRACE,
    .ban_64byte_tx = true,
    .pow_limit_hex =
        "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",

    .initial_subsidy = DTC_INITIAL_SUBSIDY,
    .halving_interval = DTC_HALVING_INTERVAL,
    .tail_floor = DTC_TAIL_FLOOR,
    .halving_count = DTC_HALVING_COUNT,
    .tail_start_height = DTC_TAIL_START,
    .pre_tail_supply = 2067187500000000LL,
    .blocks_per_year = DTC_BLOCKS_PER_YEAR,
    .tail_annual_emission = DTC_TAIL_ANNUAL,

    .min_relay_fee_per_kvb = DTC_MIN_RELAY_FEE,
    .incremental_fee = DTC_INCREMENTAL_FEE,
    .dust_rate = DTC_DUST_RATE,
    .bytes_per_sigop = DTC_BYTES_PER_SIGOP,
    .mempool_max_bytes = DTC_MEMPOOL_MAX,
    .cluster_limit = DTC_CLUSTER_LIMIT,
    .cluster_max_vsize = DTC_CLUSTER_MAX_VSIZE,

    .genesis_coinbase_text =
        "Ditcoin genesis regtest 2026-01-01 anti-premine: UTC midnight, no premine",
    .genesis_time = DTC_GENESIS_TIME,
    .genesis_nonce = 0,
};

const dtc_chain_params *dtc_chain_get(dtc_network net)
{
    switch (net) {
    case DTC_NET_TEST:
        return &dtc_chain_test;
    case DTC_NET_REG:
        return &dtc_chain_reg;
    case DTC_NET_MAIN:
    default:
        return &dtc_chain_main;
    }
}

int dtc_network_from_name(const char *name)
{
    if (name == NULL) {
        return -1;
    }
    if (strcmp(name, "main") == 0) {
        return (int)DTC_NET_MAIN;
    }
    if (strcmp(name, "test") == 0) {
        return (int)DTC_NET_TEST;
    }
    if (strcmp(name, "regtest") == 0) {
        return (int)DTC_NET_REG;
    }
    return -1;
}

const char *dtc_network_name(dtc_network net)
{
    return dtc_chain_get(net)->name;
}

bool dtc_chain_pow_limit(const dtc_chain_params *p, dtc_u256 *out)
{
    if (p == NULL || p->pow_limit_hex == NULL) {
        return false;
    }
    return dtc_u256_from_hex(out, p->pow_limit_hex);
}

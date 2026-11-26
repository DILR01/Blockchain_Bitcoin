/*
 * test_params.c —— 链参数表（唯一数值来源）
 */
#include "test_util.h"

#include "dtc/consensus.h"

void test_params(void)
{
    test_group("链身份与端口");
    CHECK(dtc_chain_main.magic == 0x44495443u);
    CHECK(dtc_chain_test.magic == 0x44495454u);
    CHECK(dtc_chain_reg.magic == 0x44495452u);
    CHECK(dtc_chain_main.p2p_port == 28333);
    CHECK(dtc_chain_main.rpc_port == 28332);
    CHECK(dtc_chain_test.p2p_port == 38333);
    CHECK(dtc_chain_reg.p2p_port == 48333);
    CHECK(strcmp(dtc_chain_main.hrp, "dtc") == 0);
    CHECK(strcmp(dtc_chain_test.hrp, "tdtc") == 0);
    CHECK(dtc_chain_main.hd_pub_version == 0xadc9ce9cu);
    CHECK(dtc_chain_main.hd_prv_version == 0xadc9ca62u);
    CHECK(dtc_chain_main.p2pkh_version == 30);
    CHECK(dtc_chain_main.p2sh_version == 63);
    CHECK(dtc_chain_main.wif_version == 122);
    CHECK(dtc_chain_main.bip44_coin_type == 0xD17C0DEu);

    test_group("共识参数");
    CHECK(dtc_chain_main.target_spacing == 600);
    CHECK(dtc_chain_main.lwma_window == 45);
    CHECK(dtc_chain_main.max_block_weight == 4000000u);
    CHECK(dtc_chain_main.witness_scale == 4);
    CHECK(dtc_chain_main.max_sigops_cost == 80000u);
    CHECK(dtc_chain_main.coinbase_maturity == 100);
    CHECK(dtc_chain_main.mtp_window == 11);
    CHECK(dtc_chain_main.future_time_limit == 1800);
    CHECK(dtc_chain_main.anchor_period == 2016);
    CHECK(dtc_chain_main.timewarp_grace == 7200);
    CHECK(dtc_chain_main.ban_64byte_tx == true);

    test_group("powLimit");
    {
        dtc_u256 limit;
        char hexbuf[65];
        CHECK(dtc_chain_pow_limit(&dtc_chain_main, &limit));
        dtc_u256_to_hex(&limit, hexbuf);
        CHECK(strcmp(hexbuf,
                     "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff") ==
              0);
    }

    test_group("经济参数");
    CHECK(dtc_chain_main.initial_subsidy == 2500000000LL);
    CHECK(dtc_chain_main.halving_interval == 420000);
    CHECK(dtc_chain_main.tail_floor == 50000000LL);
    CHECK(dtc_chain_main.halving_count == 6);
    CHECK(dtc_chain_main.tail_start_height == 2520000);
    CHECK(dtc_chain_main.pre_tail_supply == 2067187500000000LL);
    CHECK(dtc_chain_main.blocks_per_year == 52560);
    CHECK(dtc_chain_main.tail_annual_emission == 2628000000000LL);

    test_group("策略参数");
    CHECK(dtc_chain_main.min_relay_fee_per_kvb == 100);
    CHECK(dtc_chain_main.incremental_fee == 100);
    CHECK(dtc_chain_main.dust_rate == 3000);
    CHECK(dtc_chain_main.bytes_per_sigop == 20);
    CHECK(dtc_chain_main.mempool_max_bytes == 300LL * 1024 * 1024);
    CHECK(dtc_chain_main.cluster_limit == 64);
    CHECK(dtc_chain_main.cluster_max_vsize == 101000);

    test_group("网络名解析");
    CHECK(dtc_network_from_name("main") == DTC_NET_MAIN);
    CHECK(dtc_network_from_name("test") == DTC_NET_TEST);
    CHECK(dtc_network_from_name("regtest") == DTC_NET_REG);
    CHECK(dtc_network_from_name("bitcoin") < 0);
    CHECK(strcmp(dtc_network_name(DTC_NET_MAIN), "main") == 0);
    CHECK(dtc_chain_get(DTC_NET_TEST) == &dtc_chain_test);
}

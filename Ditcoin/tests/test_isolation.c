/*
 * test_isolation.c —— 跨链隔离验收
 *
 * 目标：证明 Ditcoin 在「网络身份 / 地址 / 密钥派生 / 工具格式 / 创世块」上
 * 与 Bitcoin 完全隔离，任何 Bitcoin 网络帧、地址、扩展密钥、PSBT、快照
 * 都不应被 Ditcoin 接受，反之亦然。
 */
#include "test_util.h"

#include <stdlib.h>

#include "dtc/consensus.h"
#include "dtc/crypto.h"

/* 把自然字节序哈希转为大端十六进制（区块链习惯的显示形式） */
static void hash_be_hex(const uint8_t h[32], char out[65])
{
    static const char *digits = "0123456789abcdef";
    for (size_t i = 0; i < 32; ++i) {
        uint8_t b = h[31 - i];
        out[2 * i] = digits[b >> 4];
        out[2 * i + 1] = digits[b & 0x0f];
    }
    out[64] = '\0';
}

void test_isolation(void)
{
    test_group("P2P magic 与端口");
    {
        /* Bitcoin 各网络的 magic（uint32 形式） */
        const uint32_t btc_magics[] = {0xd9b4bef9u, 0x0709110bu, 0xdab5bffau,
                                       0x40cf030au, 0x1c163f28u};
        const dtc_chain_params *nets[] = {&dtc_chain_main, &dtc_chain_test,
                                          &dtc_chain_reg};
        for (size_t i = 0; i < 3; ++i) {
            for (size_t j = 0; j < sizeof(btc_magics) / sizeof(btc_magics[0]);
                 ++j) {
                CHECK(nets[i]->magic != btc_magics[j]);
            }
        }
        /* 端口不得与 Bitcoin 冲突 */
        CHECK(dtc_chain_main.p2p_port != 8333);
        CHECK(dtc_chain_main.rpc_port != 8332);
        CHECK(dtc_chain_test.p2p_port != 18333);
        CHECK(dtc_chain_reg.p2p_port != 18444);
    }

    test_group("地址格式与密钥派生域");
    {
        CHECK(strcmp(dtc_chain_main.hrp, "bc") != 0);
        CHECK(strcmp(dtc_chain_main.hrp, "tb") != 0);
        CHECK(strcmp(dtc_chain_main.hrp, "bcrt") != 0);
        /* 0/1/60/501 都是主流链的 coin type，Ditcoin 必须避开 */
        CHECK(dtc_chain_main.bip44_coin_type != 0);
        CHECK(dtc_chain_main.bip44_coin_type != 1);
        CHECK(dtc_chain_main.bip44_coin_type != 60);
        CHECK(dtc_chain_main.bip44_coin_type != 501);
        /* xpub/xprv/tpub/tprv 版本不得复用 */
        const uint32_t btc_hd[] = {0x0488b21eu, 0x0488ade4u, 0x043587cfu,
                                   0x04358394u};
        for (size_t i = 0; i < 4; ++i) {
            CHECK(dtc_chain_main.hd_pub_version != btc_hd[i]);
            CHECK(dtc_chain_main.hd_prv_version != btc_hd[i]);
        }
        /* Base58 版本与 WIF 版本全部不同 */
        CHECK(dtc_chain_main.p2pkh_version != 0);
        CHECK(dtc_chain_main.p2sh_version != 5);
        CHECK(dtc_chain_main.wif_version != 128);
        CHECK(dtc_chain_main.wif_version != 239);
    }

    test_group("PSBT / 快照 magic");
    {
        CHECK(dtc_chain_main.psbt_magic_len == 5);
        CHECK(memcmp(dtc_chain_main.psbt_magic, "dtpb\xff", 5) == 0);
        /* Bitcoin 的 PSBT magic 是 "psbt\xff" */
        CHECK(memcmp(dtc_chain_main.psbt_magic, "psbt\xff", 5) != 0);
        CHECK(dtc_chain_main.snapshot_magic_len == 5);
        CHECK(memcmp(dtc_chain_main.snapshot_magic, "dtxo\xff", 5) == 0);
        CHECK(memcmp(dtc_chain_main.snapshot_magic, "utxo\xff", 5) != 0);
        /* v2 握手 salt 必须包含 Ditcoin 域名 */
        CHECK(strstr(dtc_chain_main.v2_hkdf_salt, "ditcoin") != NULL);
        CHECK(strcmp(dtc_chain_main.hd_seed_tag, "Ditcoin seed") == 0);
    }

    test_group("创世块与 Bitcoin 不同");
    {
        char hex[65];
        const char *btc_genesis[] = {
            /* main / testnet3 / regtest 的创世块哈希（大端显示） */
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
            "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943",
            "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
        };

        const dtc_network nets[] = {DTC_NET_MAIN, DTC_NET_TEST, DTC_NET_REG};
        char mine[3][65];
        for (size_t i = 0; i < 3; ++i) {
            dtc_genesis_info gi;
            CHECK(dtc_genesis_frozen(nets[i], &gi));
            hash_be_hex(gi.hash, hex);
            memcpy(mine[i], hex, sizeof(hex));
            for (size_t j = 0; j < 3; ++j) {
                CHECK(strcmp(hex, btc_genesis[j]) != 0);
            }
            /* 创世头字段 */
            CHECK(gi.version == 1);
            CHECK(gi.coinbase_height == 0);
            CHECK(gi.time == dtc_chain_get(nets[i])->genesis_time);
            /* merkle root 不应全零（coinbase 必然存在） */
            uint8_t zero[32] = {0};
            CHECK(memcmp(gi.merkle_root, zero, 32) != 0);
        }
        /* 三条网络的创世块互不相同 */
        CHECK(strcmp(mine[0], mine[1]) != 0);
        CHECK(strcmp(mine[1], mine[2]) != 0);
        CHECK(strcmp(mine[0], mine[2]) != 0);
    }

    test_group("创世 coinbase 不含 Bitcoin 的泰晤士报标题");
    {
        uint8_t *raw = NULL;
        size_t len = 0;
        CHECK(dtc_genesis_coinbase_serialize(DTC_NET_MAIN, &raw, &len));
        CHECK(raw != NULL && len > 0);
        /* 纯字节搜索 "The Times"（避免依赖 memmem） */
        const char *needle = "The Times";
        bool found = false;
        if (raw != NULL && len >= strlen(needle)) {
            for (size_t i = 0; i + strlen(needle) <= len; ++i) {
                if (memcmp(raw + i, needle, strlen(needle)) == 0) {
                    found = true;
                    break;
                }
            }
        }
        CHECK(!found);
        free(raw);
    }

    test_group("bech32 跨链地址拒绝");
    {
        uint8_t ver = 0;
        uint8_t prog[40];
        const char *foreign[] = {
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
            "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
        };
        for (size_t i = 0; i < 3; ++i) {
            CHECK(dtc_segwit_addr_decode("dtc", foreign[i], strlen(foreign[i]),
                                         &ver, prog, sizeof(prog)) < 0);
        }
    }
}

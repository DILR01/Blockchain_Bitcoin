/*
 * dtc_genesis.c —— 创世块离线挖掘 / 校验工具
 *
 * 背景：
 *   Ditcoin 的创世块按规范「自挖」，不允许预挖，也不抄 Bitcoin 的创世头。
 *   params.c 中的 genesis_nonce 在正式冻结前是 0 占位；本工具用于：
 *     1. 打印当前冻结创世的头字段与哈希（结构自检）；
 *     2. 线性扫描 nonce 空间，找到满足 powLimit 的 nonce；
 *     3. 输出可直接写回 params.c 的 C 代码片段。
 *
 * 用法：
 *   dtc-genesis print main|test|regtest
 *   dtc-genesis mine  main|test|regtest [start] [count]
 *
 * 说明：
 *   * 默认难度为 powLimit（nBits = powLimit 的 compact），期望约 2^32 次尝试，
 *     普通机器需要较长时间，因此支持分段扫描并打印进度；
 *   * 挖到后必须把 nonce 写回 src/consensus/params.c，并更新测试向量。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dtc/consensus.h"

/* 把自然字节序的哈希按区块链习惯反转后打印（大端显示） */
static void print_hash_be(const uint8_t hash[32])
{
    for (int i = 31; i >= 0; --i) {
        printf("%02x", hash[i]);
    }
}

/* 打印创世信息（含 PoW 是否满足当前难度） */
static int cmd_print(dtc_network net)
{
    dtc_genesis_info gi;
    if (!dtc_genesis_frozen(net, &gi)) {
        fprintf(stderr, "错误：无法构建创世块\n");
        return 1;
    }

    const dtc_chain_params *p = dtc_chain_get(net);
    dtc_u256 limit;
    if (!dtc_chain_pow_limit(p, &limit)) {
        fprintf(stderr, "错误：powLimit 解析失败\n");
        return 1;
    }

    printf("network      : %s\n", p->name);
    printf("version      : %d\n", (int)gi.version);
    printf("time         : %u\n", (unsigned)gi.time);
    printf("bits         : 0x%08x\n", (unsigned)gi.bits);
    printf("nonce        : %u\n", (unsigned)gi.nonce);
    printf("coinbase h   : %d\n", (int)gi.coinbase_height);
    printf("merkle root  : ");
    print_hash_be(gi.merkle_root);
    printf("\nblock hash   : ");
    print_hash_be(gi.hash);
    printf("\n");
    printf("pow ok       : %s\n",
           dtc_pow_check_hash(gi.hash, &limit) ? "yes" : "NO (nonce=0 占位)");
    return 0;
}

/*
 * 扫描 [start, start+count) 的 nonce。
 * 找到即返回 0 并打印可写回 params.c 的片段；未找到返回 2。
 */
static int cmd_mine(dtc_network net, unsigned start, unsigned long long count)
{
    const dtc_chain_params *p = dtc_chain_get(net);
    dtc_u256 limit;
    if (!dtc_chain_pow_limit(p, &limit)) {
        fprintf(stderr, "错误：powLimit 解析失败\n");
        return 1;
    }

    printf("扫描 nonce 起点=%u 数量=%llu （ctrl-c 可中断）\n", start, count);

    for (unsigned long long k = 0; k < count; ++k) {
        unsigned nonce = (unsigned)((start + k) & 0xffffffffULL);
        dtc_genesis_info gi;
        if (!dtc_genesis_build(net, nonce, &gi)) {
            fprintf(stderr, "错误：构建创世头失败\n");
            return 1;
        }
        if ((k & 0xfffffULL) == 0xfffffULL) {
            printf("  进度: %llu / %llu（当前 nonce=%u）\n", k + 1, count,
                   nonce);
            fflush(stdout);
        }
        if (dtc_pow_check_hash(gi.hash, &limit)) {
            printf("\n找到合法 nonce！\n");
            printf("network      : %s\n", p->name);
            printf("nonce        : %u\n", nonce);
            printf("block hash   : ");
            print_hash_be(gi.hash);
            printf("\n");
            printf("\n写回 params.c（%s）:\n  .genesis_nonce = %u,\n",
                   p->name, nonce);
            return 0;
        }
    }

    printf("扫描范围内未找到，请继续更大的 [start, count]\n");
    return 2;
}

static void usage(const char *argv0)
{
    fprintf(stderr,
            "用法:\n"
            "  %s print main|test|regtest\n"
            "  %s mine  main|test|regtest [start] [count]\n",
            argv0, argv0);
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        usage(argv[0]);
        return 1;
    }
    int net = dtc_network_from_name(argv[2]);
    if (net < 0) {
        fprintf(stderr, "错误：未知网络 '%s'\n", argv[2]);
        return 1;
    }

    if (strcmp(argv[1], "print") == 0) {
        return cmd_print((dtc_network)net);
    }
    if (strcmp(argv[1], "mine") == 0) {
        unsigned start = 0;
        unsigned long long count = 0x100000ULL;
        if (argc >= 4) {
            start = (unsigned)strtoul(argv[3], NULL, 0);
        }
        if (argc >= 5) {
            count = strtoull(argv[4], NULL, 0);
        }
        return cmd_mine((dtc_network)net, start, count);
    }

    usage(argv[0]);
    return 1;
}

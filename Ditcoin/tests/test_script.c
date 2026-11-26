/*
 * test_script.c —— 脚本解释器（legacy + P2SH）
 *
 * 覆盖：
 *   * 常量/算术/流程/哈希操作码
 *   * 最小编码脚本数字（非最小编码必须失败）
 *   * OP_RETURN 失败、VERIFY 失败
 *   * CLEANSTACK 规则
 *   * CLTV / CSV
 *   * P2SH 两步执行
 *   * witness program 显式拒绝（不允许 OP_0+push32 误判为真）
 *   * 真实 ECDSA 验签（启用 libsecp256k1 时）
 */
#include "test_util.h"

#include "dtc/crypto.h"
#include "dtc/script.h"

#include <stdlib.h>

#ifdef DTC_HAVE_SECP256K1
#include <secp256k1.h>

#include "dtc/secp.h"
#endif

/* 构造最小可验证交易：1 输入 1 输出，输入索引固定为 0 */
static void make_tx(dtc_tx *tx)
{
    dtc_tx_init(tx);
    tx->version = 2;
    tx->vin = (dtc_tx_in *)calloc(1, sizeof(dtc_tx_in));
    tx->vout = (dtc_tx_out *)calloc(1, sizeof(dtc_tx_out));
    if (tx->vin == NULL || tx->vout == NULL) {
        return;
    }
    tx->vin_count = 1;
    tx->vout_count = 1;
    memset(tx->vin[0].prevout.hash, 0x11, 32);
    tx->vin[0].prevout.n = 0;
    tx->vin[0].sequence = 0xfffffffeu;
    tx->locktime = 0;
    tx->vout[0].value = 1;
}

/* 用字节数组构造 dtc_bytes（不复制到堆，仅在栈上视图，供 verify 使用） */
static dtc_bytes view(uint8_t *data, size_t len)
{
    dtc_bytes b;
    b.data = data;
    b.len = len;
    return b;
}

static bool run(const dtc_bytes *sig, const dtc_bytes *pk,
                const dtc_script_ctx *ctx, char *err, size_t errcap)
{
    dtc_tx tx;
    make_tx(&tx);
    bool ok = dtc_script_verify(&tx, 0, sig, pk, 0, ctx, err, errcap);
    dtc_tx_free(&tx);
    return ok;
}

void test_script(void)
{
    dtc_script_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.tx_locktime = 0;
    ctx.input_sequence = 0xfffffffeu;
    ctx.input_height = 0;
    ctx.input_time = 0;
    ctx.block_height = 100;
    ctx.block_mtp = 0;
    ctx.flags = DTC_SCRIPT_CONSENSUS_FLAGS;

    char err[256];

    test_group("常量与逻辑");
    {
        uint8_t empty[1] = {0};
        uint8_t one[1] = {0x51};    /* OP_1 */
        uint8_t zero[1] = {0x00};   /* OP_0 */
        dtc_bytes s = view(empty, 0);
        dtc_bytes p = view(one, 1);
        CHECK(run(&s, &p, &ctx, err, sizeof(err)));
        p = view(zero, 1);
        CHECK(!run(&s, &p, &ctx, err, sizeof(err)));
    }

    test_group("算术：1+1 == 2");
    {
        uint8_t sig[2] = {0x51, 0x51};
        uint8_t spk[3] = {0x93, 0x52, 0x87}; /* ADD 2 EQUAL */
        dtc_bytes s = view(sig, sizeof(sig));
        dtc_bytes p = view(spk, sizeof(spk));
        CHECK(run(&s, &p, &ctx, err, sizeof(err)));
    }

    test_group("非最小编码数字必须失败");
    {
        uint8_t sig[3] = {0x01, 0x00, 0x51};   /* push {0x00}（非最小） + OP_1 */
        uint8_t spk[1] = {0x93};               /* ADD */
        dtc_bytes s = view(sig, sizeof(sig));
        dtc_bytes p = view(spk, sizeof(spk));
        CHECK(!run(&s, &p, &ctx, err, sizeof(err)));
    }

    test_group("OP_RETURN / VERIFY");
    {
        uint8_t empty[1] = {0};
        uint8_t ret[1] = {0x6a};
        uint8_t neq[4] = {0x51, 0x52, 0x9d, 0x51}; /* 1 2 NUMEQUALVERIFY 1 */
        dtc_bytes s = view(empty, 0);
        dtc_bytes p = view(ret, 1);
        CHECK(!run(&s, &p, &ctx, err, sizeof(err)));
        p = view(neq, sizeof(neq));
        CHECK(!run(&s, &p, &ctx, err, sizeof(err)));
    }

    test_group("CLEANSTACK");
    {
        uint8_t three[3] = {0x51, 0x51, 0x51};
        uint8_t empty[1] = {0};
        dtc_bytes s = view(three, sizeof(three));
        dtc_bytes p = view(empty, 0);
        CHECK(!run(&s, &p, &ctx, err, sizeof(err)));
    }

    test_group("OP_SHA1");
    {
        uint8_t spk2[] = {0x03, 'a', 'b', 'c', 0xa7, 0x14,
                          0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a,
                          0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c,
                          0x9c, 0xd0, 0xd8, 0x9d, 0x87};
        uint8_t empty[1] = {0};
        dtc_bytes s = view(empty, 0);
        dtc_bytes p = view(spk2, sizeof(spk2));
        CHECK(run(&s, &p, &ctx, err, sizeof(err)));
    }

    test_group("CLTV");
    {
        /* push 1000, CLTV, DROP, OP_1 */
        uint8_t spk[] = {0x02, 0xe8, 0x03, 0xb1, 0x75, 0x51};
        uint8_t empty[1] = {0};
        dtc_bytes s = view(empty, 0);
        dtc_bytes p = view(spk, sizeof(spk));

        dtc_script_ctx c = ctx;
        c.tx_locktime = 1000;
        c.input_sequence = 0xfffffffeu;
        CHECK(run(&s, &p, &c, err, sizeof(err)));

        /* 锁时间不足 → 失败 */
        c.tx_locktime = 999;
        CHECK(!run(&s, &p, &c, err, sizeof(err)));

        /* 输入为 final sequence → 禁止 CLTV */
        c.tx_locktime = 1000;
        c.input_sequence = 0xffffffffu;
        CHECK(!run(&s, &p, &c, err, sizeof(err)));
    }

    test_group("CSV");
    {
        /* push 10, CSV, DROP, OP_1 */
        uint8_t spk[] = {0x01, 0x0a, 0xb2, 0x75, 0x51};
        uint8_t empty[1] = {0};
        dtc_bytes s = view(empty, 0);
        dtc_bytes p = view(spk, sizeof(spk));

        dtc_script_ctx c = ctx;
        c.input_sequence = 20;
        CHECK(run(&s, &p, &c, err, sizeof(err)));

        c.input_sequence = 5;
        CHECK(!run(&s, &p, &c, err, sizeof(err)));

        /* 输入 sequence 的 disable 位被置位 → CSV 失效 */
        c.input_sequence = 20u | 0x80000000u;
        CHECK(!run(&s, &p, &c, err, sizeof(err)));
    }

    test_group("P2SH");
    {
        /* redeem = OP_1；scriptSig = push(redeem) */
        uint8_t redeem[1] = {0x51};
        uint8_t sig[2] = {0x01, 0x51};
        uint8_t h[32];
        uint8_t hash160[20];
        dtc_sha256(redeem, sizeof(redeem), h);
        dtc_ripemd160(h, 32, hash160);
        uint8_t spk[23] = {0xa9, 0x14};
        memcpy(spk + 2, hash160, 20);
        spk[22] = 0x87; /* EQUAL */

        dtc_bytes s = view(sig, sizeof(sig));
        dtc_bytes p = view(spk, sizeof(spk));
        CHECK(run(&s, &p, &ctx, err, sizeof(err)));

        /* 错误的 redeem script 哈希 → 失败 */
        uint8_t bad[2] = {0x01, 0x52};
        s = view(bad, sizeof(bad));
        CHECK(!run(&s, &p, &ctx, err, sizeof(err)));
    }

    test_group("witness program 必须显式拒绝");
    {
        uint8_t spk[22] = {0x00, 0x14};
        memset(spk + 2, 0x33, 20);
        uint8_t empty[1] = {0};
        dtc_bytes s = view(empty, 0);
        dtc_bytes p = view(spk, sizeof(spk));
        CHECK(!run(&s, &p, &ctx, err, sizeof(err)));
        CHECK(strstr(err, "witness") != NULL);

        uint8_t ver = 0xff;
        CHECK(dtc_script_is_witness_program(spk, sizeof(spk), &ver));
        CHECK(ver == 0);
    }

#ifdef DTC_HAVE_SECP256K1
    test_group("真实 ECDSA（P2PKH）");
    {
        /* 固定私钥 = 1（合法且远小于曲线阶） */
        uint8_t seckey[32];
        memset(seckey, 0, sizeof(seckey));
        seckey[31] = 1;

        secp256k1_context *sctx =
            secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
        CHECK(sctx != NULL);
        secp256k1_pubkey pub;
        CHECK(secp256k1_ec_pubkey_create(sctx, &pub, seckey) == 1);
        uint8_t pubkey[33];
        size_t publen = sizeof(pubkey);
        CHECK(secp256k1_ec_pubkey_serialize(sctx, pubkey, &publen, &pub,
                                            SECP256K1_EC_COMPRESSED) == 1);
        CHECK(publen == 33);

        uint8_t h[32];
        uint8_t pk_hash[20];
        dtc_sha256(pubkey, publen, h);
        dtc_ripemd160(h, 32, pk_hash);

        uint8_t spk[25] = {0x76, 0xa9, 0x14};
        memcpy(spk + 3, pk_hash, 20);
        spk[23] = 0x88; /* EQUALVERIFY */
        spk[24] = 0xac; /* CHECKSIG */

        /* 构造交易并计算 sighash */
        dtc_tx tx;
        make_tx(&tx);
        uint8_t sighash[32];
        CHECK(dtc_sighash_legacy(&tx, 0, spk, sizeof(spk), 1, sighash));

        secp256k1_ecdsa_signature esig;
        CHECK(secp256k1_ecdsa_sign(sctx, &esig, sighash, seckey, NULL, NULL) ==
              1);
        uint8_t der[72];
        size_t derlen = sizeof(der);
        CHECK(secp256k1_ecdsa_signature_serialize_der(sctx, der, &derlen,
                                                      &esig) == 1);

        uint8_t sigbuf[80];
        memcpy(sigbuf, der, derlen);
        sigbuf[derlen] = 0x01; /* SIGHASH_ALL */
        size_t siglen = derlen + 1;

        /* scriptSig = push(sig) push(pubkey) */
        uint8_t script_sig[1 + 80 + 1 + 33];
        size_t n = 0;
        script_sig[n++] = (uint8_t)siglen;
        memcpy(script_sig + n, sigbuf, siglen);
        n += siglen;
        script_sig[n++] = (uint8_t)publen;
        memcpy(script_sig + n, pubkey, publen);
        n += publen;

        dtc_ecdsa_checker checker;
        CHECK(dtc_ecdsa_checker_init(&checker));

        dtc_script_ctx c = ctx;
        c.checker = &checker.iface;

        dtc_bytes s = view(script_sig, n);
        dtc_bytes p = view(spk, sizeof(spk));
        CHECK(dtc_script_verify(&tx, 0, &s, &p, 100000000, &c, err,
                                sizeof(err)));

        /* 篡改签名 → 必须失败 */
        script_sig[1] ^= 0x01;
        CHECK(!dtc_script_verify(&tx, 0, &s, &p, 100000000, &c, err,
                                 sizeof(err)));

        dtc_ecdsa_checker_destroy(&checker);
        secp256k1_context_destroy(sctx);
        dtc_tx_free(&tx);
    }
#else
    test_group("真实 ECDSA（未启用 libsecp256k1，跳过）");
#endif
}
